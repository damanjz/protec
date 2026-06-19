use arboard::Clipboard;
use std::thread;
use std::time::Duration;

/// Copy `text` to the clipboard. If `clear_secs` > 0, spawn a thread that clears
/// the clipboard after the delay (best-effort; only clears if it still matches).
#[tauri::command]
pub fn copy_secret(text: String, clear_secs: u64) -> Result<(), String> {
    // Defensive cap: never sleep longer than 1 hour (the config UI clamps too,
    // but a direct invoke could pass anything).
    let clear_secs = clear_secs.min(3_600);
    let mut cb = Clipboard::new().map_err(|e| e.to_string())?;
    cb.set_text(text.clone()).map_err(|e| e.to_string())?;
    if clear_secs > 0 {
        thread::spawn(move || {
            thread::sleep(Duration::from_secs(clear_secs));
            if let Ok(mut cb) = Clipboard::new() {
                if let Ok(current) = cb.get_text() {
                    if current == text {
                        let _ = cb.set_text(String::new());
                    }
                }
            }
        });
    }
    Ok(())
}
