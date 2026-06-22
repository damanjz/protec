use crate::ipc::framing::{read_frame, write_frame};
use crate::ipc::handler::process;
use crate::ipc::protocol::{Request, Response};
use crate::state::AppState;
use tauri::{AppHandle, Emitter, Manager};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::oneshot;

/// Spawn the IPC server. One request per connection (the host opens a fresh
/// connection per request). Transport is platform-specific; per-connection
/// handling is shared.
pub fn spawn(app: AppHandle) {
    #[cfg(windows)]
    {
        spawn_windows(app);
    }
    #[cfg(target_os = "macos")]
    {
        spawn_macos(app);
    }
}

#[cfg(windows)]
fn spawn_windows(app: AppHandle) {
    use crate::ipc::protocol::PIPE_NAME;
    use tokio::net::windows::named_pipe::ServerOptions;
    tauri::async_runtime::spawn(async move {
        loop {
            let server = match ServerOptions::new()
                .reject_remote_clients(true)
                .create(PIPE_NAME)
            {
                Ok(s) => s,
                Err(_) => {
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                    continue;
                }
            };
            if server.connect().await.is_err() {
                continue;
            }
            let app2 = app.clone();
            tauri::async_runtime::spawn(async move {
                let _ = handle_conn(app2, server).await;
            });
        }
    });
}

#[cfg(target_os = "macos")]
fn spawn_macos(app: AppHandle) {
    use crate::ipc::protocol::endpoint;
    use std::os::unix::fs::PermissionsExt;
    use tokio::net::UnixListener;
    tauri::async_runtime::spawn(async move {
        let path = endpoint();
        if let Some(parent) = std::path::Path::new(&path).parent() {
            let _ = std::fs::create_dir_all(parent);
            let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
        }
        loop {
            // Remove any stale socket before binding.
            let _ = std::fs::remove_file(&path);
            let listener = match UnixListener::bind(&path) {
                Ok(l) => l,
                Err(_) => {
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                    continue;
                }
            };
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
            loop {
                match listener.accept().await {
                    Ok((stream, _addr)) => {
                        let app2 = app.clone();
                        tauri::async_runtime::spawn(async move {
                            let _ = handle_conn(app2, stream).await;
                        });
                    }
                    Err(_) => break, // re-bind on accept failure
                }
            }
        }
    });
}

async fn handle_conn<S>(app: AppHandle, mut stream: S) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let body = match read_frame(&mut stream).await {
        Ok(b) => b,
        Err(_) => {
            write_response(
                &mut stream,
                &Response::Error {
                    message: "Request too large or malformed".into(),
                },
            )
            .await?;
            return Ok(());
        }
    };

    let req: Request = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(_) => {
            write_response(
                &mut stream,
                &Response::Error {
                    message: "Malformed request".into(),
                },
            )
            .await?;
            return Ok(());
        }
    };

    // Abuse protection: rate-limit per origin before doing anything else.
    let origin = match &req {
        Request::Find { origin } | Request::Submit { origin, .. } => Some(origin.clone()),
        Request::Status => None,
    };
    if let Some(origin) = origin {
        let now = now_ms();
        let limiter = app.state::<RateLimitState>();
        let allowed = limiter
            .0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .check(&origin, now);
        if !allowed {
            write_response(&mut stream, &Response::Denied).await?;
            return Ok(());
        }
    }

    let state = app.state::<AppState>();
    let app_for_confirm = app.clone();
    let resp = process(state.inner(), req, move |prompt: String| {
        let app = app_for_confirm.clone();
        async move { request_confirmation(app, prompt).await }
    })
    .await;

    write_response(&mut stream, &resp).await
}

async fn write_response<S>(stream: &mut S, resp: &Response) -> std::io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    // Every Response variant is a simple enum of String/bool, so this is infallible.
    let body = serde_json::to_vec(resp).expect("Response serialization is infallible");
    write_frame(stream, &body).await
}

/// Raise the desktop confirmation prompt and await Allow/Deny. Emits an event
/// the frontend listens for; the frontend replies via answer_confirm.
async fn request_confirmation(app: AppHandle, prompt: String) -> bool {
    use rand_core::RngCore;
    let nonce = rand_core::OsRng.next_u64();
    let (tx, rx) = oneshot::channel::<bool>();
    let pending = app.state::<PendingConfirm>();
    {
        let mut guard = pending.0.lock().unwrap_or_else(|p| p.into_inner());
        if guard.is_some() {
            // A confirmation is already awaiting the user; deny the new one
            // rather than silently invalidating the in-flight prompt.
            return false;
        }
        *guard = Some((nonce, tx));
    }
    if let Some(win) = app.get_webview_window("main") {
        let _ = win.set_focus();
    }
    // Send the nonce as a STRING to avoid JS number-precision loss on a u64;
    // the frontend echoes the same string back in answer_confirm.
    #[derive(serde::Serialize, Clone)]
    struct ConfirmPayload {
        prompt: String,
        nonce: String,
    }
    let _ = app.emit(
        "protec://confirm",
        ConfirmPayload {
            prompt,
            nonce: nonce.to_string(),
        },
    );
    rx.await.unwrap_or(false)
}

/// Holds the in-flight confirmation responder along with the correlation nonce
/// the frontend must echo back. Registered as managed state.
pub struct PendingConfirm(pub std::sync::Mutex<Option<(u64, oneshot::Sender<bool>)>>);

impl Default for PendingConfirm {
    fn default() -> Self {
        Self(std::sync::Mutex::new(None))
    }
}

/// The per-origin rate limiter, registered as managed state.
pub struct RateLimitState(pub std::sync::Mutex<crate::ipc::ratelimit::RateLimiter>);

impl Default for RateLimitState {
    fn default() -> Self {
        // Allow up to 5 autofill requests per origin per 10 seconds.
        Self(std::sync::Mutex::new(
            crate::ipc::ratelimit::RateLimiter::new(10_000, 5),
        ))
    }
}

fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Called by the frontend to answer the current confirmation prompt. The nonce
/// must match the one emitted with `protec://confirm`, so a forged
/// `answer_confirm` cannot resolve a prompt the user never saw.
#[tauri::command]
pub fn answer_confirm(allow: bool, nonce: String, pending: tauri::State<PendingConfirm>) {
    let mut guard = pending.0.lock().unwrap_or_else(|p| p.into_inner());
    if let Some((expected, _)) = guard.as_ref() {
        if expected.to_string() != nonce {
            return; // wrong/forged nonce — ignore
        }
    } else {
        return;
    }
    if let Some((_, tx)) = guard.take() {
        let _ = tx.send(allow);
    }
}
