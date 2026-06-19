use protec_core::{generate_passphrase, generate_password, CharsetOptions, PassphraseOptions};
use serde::Deserialize;

#[derive(Deserialize)]
pub struct GenRequest {
    pub mode: String, // "chars" | "passphrase"
    pub length: usize,
    pub lowercase: bool,
    pub uppercase: bool,
    pub digits: bool,
    pub symbols: bool,
    pub exclude_ambiguous: bool,
    pub words: usize,
    pub separator: String,
    pub capitalize: bool,
}

#[tauri::command]
pub fn generate(req: GenRequest) -> Result<String, String> {
    match req.mode.as_str() {
        "passphrase" => {
            let opts = PassphraseOptions {
                words: req.words,
                separator: req.separator,
                capitalize: req.capitalize,
            };
            generate_passphrase(&opts).ok_or_else(|| "Word count must be at least 1".into())
        }
        "chars" => {
            let opts = CharsetOptions {
                length: req.length,
                lowercase: req.lowercase,
                uppercase: req.uppercase,
                digits: req.digits,
                symbols: req.symbols,
                exclude_ambiguous: req.exclude_ambiguous,
            };
            generate_password(&opts)
                .ok_or_else(|| "Enable at least one character set and a non-zero length".into())
        }
        other => Err(format!("Unknown generator mode: {other}")),
    }
}
