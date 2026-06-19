use crate::ipc::handler::process;
use crate::ipc::protocol::{Request, Response, PIPE_NAME};
use crate::state::AppState;
use tauri::{AppHandle, Emitter, Manager};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use tokio::sync::oneshot;

/// Spawn the named-pipe server. Each client connection is handled, one request
/// per connection (the extension opens a fresh connection per request).
pub fn spawn(app: AppHandle) {
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

async fn handle_conn(app: AppHandle, mut server: NamedPipeServer) -> std::io::Result<()> {
    let mut len = [0u8; 4];
    server.read_exact(&mut len).await?;
    let n = u32::from_le_bytes(len) as usize;
    if n > 16 * 1024 * 1024 {
        return Ok(());
    }
    let mut body = vec![0u8; n];
    server.read_exact(&mut body).await?;

    let req: Request = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            write_response(
                &mut server,
                &Response::Error {
                    message: e.to_string(),
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
            write_response(&mut server, &Response::Denied).await?;
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

    write_response(&mut server, &resp).await
}

async fn write_response(server: &mut NamedPipeServer, resp: &Response) -> std::io::Result<()> {
    let body = serde_json::to_vec(resp).unwrap_or_default();
    server.write_all(&(body.len() as u32).to_le_bytes()).await?;
    server.write_all(&body).await?;
    server.flush().await
}

/// Raise the desktop confirmation prompt and await Allow/Deny. Emits an event
/// the frontend listens for; the frontend replies via answer_confirm.
async fn request_confirmation(app: AppHandle, prompt: String) -> bool {
    let (tx, rx) = oneshot::channel::<bool>();
    let pending = app.state::<PendingConfirm>();
    {
        let mut guard = pending.0.lock().unwrap_or_else(|p| p.into_inner());
        if guard.is_some() {
            // A confirmation is already awaiting the user; deny the new one
            // rather than silently invalidating the in-flight prompt.
            return false;
        }
        *guard = Some(tx);
    }
    if let Some(win) = app.get_webview_window("main") {
        let _ = win.set_focus();
    }
    let _ = app.emit("protec://confirm", prompt);
    rx.await.unwrap_or(false)
}

/// Holds the in-flight confirmation responder. Registered as managed state.
pub struct PendingConfirm(pub std::sync::Mutex<Option<oneshot::Sender<bool>>>);

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

/// Called by the frontend to answer the current confirmation prompt.
#[tauri::command]
pub fn answer_confirm(allow: bool, pending: tauri::State<PendingConfirm>) {
    if let Some(tx) = pending.0.lock().unwrap_or_else(|p| p.into_inner()).take() {
        let _ = tx.send(allow);
    }
}
