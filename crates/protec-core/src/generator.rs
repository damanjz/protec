use rand_core::{OsRng, RngCore};

/// Which character classes a generated password may draw from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CharsetOptions {
    pub length: usize,
    pub lowercase: bool,
    pub uppercase: bool,
    pub digits: bool,
    pub symbols: bool,
    pub exclude_ambiguous: bool,
}

impl Default for CharsetOptions {
    fn default() -> Self {
        Self {
            length: 20,
            lowercase: true,
            uppercase: true,
            digits: true,
            symbols: true,
            exclude_ambiguous: true,
        }
    }
}

const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &str = "0123456789";
const SYMBOLS: &str = "!@#$%^&*()-_=+[]{};:,.<>?";
// Ambiguous glyphs that are easy to misread.
const AMBIGUOUS: &str = "O0oIl1|S5B8";

/// Build the allowed character pool from the options.
fn pool(opts: &CharsetOptions) -> Vec<char> {
    let mut s = String::new();
    if opts.lowercase {
        s.push_str(LOWER);
    }
    if opts.uppercase {
        s.push_str(UPPER);
    }
    if opts.digits {
        s.push_str(DIGITS);
    }
    if opts.symbols {
        s.push_str(SYMBOLS);
    }
    if opts.exclude_ambiguous {
        s.retain(|c| !AMBIGUOUS.contains(c));
    }
    s.chars().collect()
}

/// Generate a random password. Returns None if no character class is enabled
/// or length is zero (caller should validate/report).
pub fn generate_password(opts: &CharsetOptions) -> Option<String> {
    let chars = pool(opts);
    if chars.is_empty() || opts.length == 0 {
        return None;
    }
    let mut out = String::with_capacity(opts.length);
    for _ in 0..opts.length {
        // Unbiased index via rejection sampling.
        let n = chars.len() as u32;
        let limit = u32::MAX - (u32::MAX % n);
        let idx = loop {
            let r = OsRng.next_u32();
            if r < limit {
                break (r % n) as usize;
            }
        };
        out.push(chars[idx]);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_requested_length() {
        let opts = CharsetOptions { length: 32, ..Default::default() };
        let pw = generate_password(&opts).unwrap();
        assert_eq!(pw.chars().count(), 32);
    }

    #[test]
    fn respects_disabled_classes() {
        let opts = CharsetOptions {
            length: 200,
            lowercase: true,
            uppercase: false,
            digits: false,
            symbols: false,
            exclude_ambiguous: false,
        };
        let pw = generate_password(&opts).unwrap();
        assert!(pw.chars().all(|c| c.is_ascii_lowercase()));
    }

    #[test]
    fn exclude_ambiguous_removes_those_chars() {
        let opts = CharsetOptions { length: 500, exclude_ambiguous: true, ..Default::default() };
        let pw = generate_password(&opts).unwrap();
        assert!(pw.chars().all(|c| !AMBIGUOUS.contains(c)));
    }

    #[test]
    fn no_classes_enabled_returns_none() {
        let opts = CharsetOptions {
            length: 10,
            lowercase: false,
            uppercase: false,
            digits: false,
            symbols: false,
            exclude_ambiguous: false,
        };
        assert!(generate_password(&opts).is_none());
    }

    #[test]
    fn zero_length_returns_none() {
        let opts = CharsetOptions { length: 0, ..Default::default() };
        assert!(generate_password(&opts).is_none());
    }
}
