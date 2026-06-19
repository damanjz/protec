use serde::{Deserialize, Serialize};
use std::path::Path;

/// User preferences. Holds NO secrets. Persisted as TOML.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct AppConfig {
    pub auto_lock_secs: u64, // 0 = never
    pub lock_on_blur: bool,
    pub clipboard_clear_secs: u64, // 0 = never
    pub auto_save: bool,
    pub theme: String, // "slate" | "terminal-green"
    pub reveal_on_select: bool,
    pub gen_length: usize,
    pub gen_lowercase: bool,
    pub gen_uppercase: bool,
    pub gen_digits: bool,
    pub gen_symbols: bool,
    pub gen_exclude_ambiguous: bool,
    pub vault_path: Option<String>, // None = default location
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            auto_lock_secs: 600,
            lock_on_blur: false,
            clipboard_clear_secs: 20,
            auto_save: true,
            theme: "slate".to_string(),
            reveal_on_select: false,
            gen_length: 20,
            gen_lowercase: true,
            gen_uppercase: true,
            gen_digits: true,
            gen_symbols: true,
            gen_exclude_ambiguous: true,
            vault_path: None,
        }
    }
}

impl AppConfig {
    /// Clamp/repair out-of-range values to safe defaults.
    pub fn sanitized(mut self) -> Self {
        let d = AppConfig::default();
        if self.theme != "slate" && self.theme != "terminal-green" {
            self.theme = d.theme.clone();
        }
        if self.gen_length == 0 || self.gen_length > 256 {
            self.gen_length = d.gen_length;
        }
        // At least one character class must be on.
        if !(self.gen_lowercase || self.gen_uppercase || self.gen_digits || self.gen_symbols) {
            self.gen_lowercase = true;
            self.gen_uppercase = true;
            self.gen_digits = true;
            self.gen_symbols = true;
        }
        // Reject dangerous vault paths (UNC, device namespace, relative). A None
        // here falls back to the safe default location.
        if let Some(p) = &self.vault_path {
            let bad = p.starts_with(r"\\")          // UNC or device (\\.\, \\?\)
                || p.trim().is_empty()
                || !std::path::Path::new(p).is_absolute();
            if bad {
                self.vault_path = None;
            }
        }
        // Clamp time-based security settings to sane maximums.
        if self.auto_lock_secs > 86_400 {
            self.auto_lock_secs = 86_400; // 24h ceiling
        }
        if self.clipboard_clear_secs > 3_600 {
            self.clipboard_clear_secs = 3_600; // 1h ceiling
        }
        self
    }

    /// Parse from TOML text; malformed input falls back to defaults (never errors).
    pub fn from_toml_or_default(text: &str) -> Self {
        toml::from_str::<AppConfig>(text)
            .unwrap_or_default()
            .sanitized()
    }

    pub fn to_toml(&self) -> String {
        toml::to_string_pretty(self).unwrap_or_default()
    }
}

impl AppConfig {
    /// Load config from `path`. Missing or malformed file => defaults (never errors).
    pub fn load(path: &Path) -> Self {
        match std::fs::read_to_string(path) {
            Ok(text) => AppConfig::from_toml_or_default(&text),
            Err(_) => AppConfig::default(),
        }
    }

    /// Save config to `path`, creating parent dirs. Returns Err on IO failure.
    pub fn save(&self, path: &Path) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        std::fs::write(path, self.to_toml()).map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_sane() {
        let c = AppConfig::default();
        assert_eq!(c.auto_lock_secs, 600);
        assert!(c.auto_save);
        assert_eq!(c.theme, "slate");
    }

    #[test]
    fn malformed_toml_falls_back_to_defaults() {
        let c = AppConfig::from_toml_or_default("this is not valid toml =====");
        assert_eq!(c, AppConfig::default());
    }

    #[test]
    fn partial_toml_fills_missing_with_defaults() {
        let c = AppConfig::from_toml_or_default("auto_lock_secs = 60");
        assert_eq!(c.auto_lock_secs, 60);
        assert!(c.auto_save); // default preserved
    }

    #[test]
    fn invalid_theme_is_repaired() {
        let c = AppConfig::from_toml_or_default("theme = \"neon-rave\"");
        assert_eq!(c.theme, "slate");
    }

    #[test]
    fn no_charset_enabled_is_repaired() {
        let text =
            "gen_lowercase = false\ngen_uppercase = false\ngen_digits = false\ngen_symbols = false";
        let c = AppConfig::from_toml_or_default(text);
        assert!(c.gen_lowercase || c.gen_uppercase || c.gen_digits || c.gen_symbols);
    }

    #[test]
    fn rejects_unc_vault_path() {
        let c =
            AppConfig::from_toml_or_default("vault_path = \"\\\\\\\\attacker\\\\share\\\\v.dat\"");
        assert_eq!(c.vault_path, None);
    }

    #[test]
    fn rejects_relative_vault_path() {
        let c = AppConfig::from_toml_or_default("vault_path = \"vault.dat\"");
        assert_eq!(c.vault_path, None);
    }

    #[test]
    fn keeps_absolute_vault_path() {
        let c = AppConfig::from_toml_or_default("vault_path = \"C:\\\\Users\\\\me\\\\v.dat\"");
        assert_eq!(c.vault_path.as_deref(), Some("C:\\Users\\me\\v.dat"));
    }

    #[test]
    fn clamps_absurd_timeouts() {
        let c = AppConfig::from_toml_or_default(
            "auto_lock_secs = 999999999\nclipboard_clear_secs = 999999999",
        );
        assert_eq!(c.auto_lock_secs, 86_400);
        assert_eq!(c.clipboard_clear_secs, 3_600);
    }

    #[test]
    fn toml_round_trips() {
        let c = AppConfig {
            auto_lock_secs: 300,
            theme: "terminal-green".into(),
            ..Default::default()
        };
        let back = AppConfig::from_toml_or_default(&c.to_toml());
        assert_eq!(c, back);
    }

    #[test]
    fn load_missing_file_returns_defaults() {
        let dir = std::env::temp_dir().join("protec_cfg_missing_test");
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("config.toml");
        assert_eq!(AppConfig::load(&path), AppConfig::default());
    }

    #[test]
    fn save_then_load_round_trips() {
        let dir = std::env::temp_dir().join("protec_cfg_rt_test");
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("config.toml");
        let c = AppConfig {
            theme: "terminal-green".into(),
            clipboard_clear_secs: 30,
            ..Default::default()
        };
        c.save(&path).unwrap();
        assert_eq!(AppConfig::load(&path), c);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
