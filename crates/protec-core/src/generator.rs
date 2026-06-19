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

/// Options for word-based passphrases (e.g. "correct-horse-battery-staple").
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PassphraseOptions {
    pub words: usize,
    pub separator: String,
    pub capitalize: bool,
}

impl Default for PassphraseOptions {
    fn default() -> Self {
        Self {
            words: 4,
            separator: "-".to_string(),
            capitalize: false,
        }
    }
}

/// Embedded passphrase wordlist of 264 distinct, short, common English words.
/// 264 words ≈ 8 bits/word, so a 4-word phrase ≈ 32 bits and the UI's max of
/// 8 words ≈ 64 bits. Entropy is word count × log2(list size). Words are concrete
/// nouns/adjectives (animals, colors, objects, nature, food), 3–8 letters, all
/// lowercase, with no duplicates.
const WORDS: &[&str] = &[
    "able", "acid", "acorn", "actor", "amber", "anchor", "angle", "ankle", "apple", "apron",
    "arch", "arrow", "ash", "aspen", "atom", "autumn", "axe", "azure", "bacon", "badge", "bagel",
    "baker", "bamboo", "banana", "banjo", "barley", "basil", "basin", "basket", "beach", "beacon",
    "bean", "bear", "beaver", "beetle", "berry", "birch", "bird", "bison", "black", "blade",
    "blanket", "block", "bloom", "blue", "boat", "bolt", "bone", "bonus", "book", "boot", "bottle",
    "boulder", "bowl", "branch", "brass", "bread", "brick", "bridge", "broom", "brown", "brush",
    "bubble", "bucket", "buffalo", "bugle", "bunny", "burrow", "button", "cabin", "cable",
    "cactus", "camel", "candle", "canoe", "canyon", "carbon", "cargo", "carrot", "castle", "cedar",
    "celery", "chain", "chalk", "cheese", "cherry", "chest", "chili", "cider", "clay", "clever",
    "cliff", "clock", "cloud", "clover", "coal", "coast", "cobalt", "cocoa", "coffee", "comet",
    "copper", "coral", "corn", "cotton", "cougar", "cousin", "cover", "crab", "crane", "crater",
    "cream", "crow", "crystal", "cube", "daisy", "dawn", "deer", "delta", "desert", "diamond",
    "dimple", "dolphin", "donut", "dove", "dragon", "drum", "duck", "dune", "dusk", "eagle",
    "earth", "ember", "emerald", "engine", "fable", "falcon", "fawn", "fern", "field", "finch",
    "flame", "flint", "flower", "flute", "forest", "fossil", "fountain", "fox", "frog", "frost",
    "garden", "garnet", "ginger", "glacier", "globe", "goat", "gold", "goose", "granite", "grape",
    "grass", "green", "grove", "guava", "hammer", "harbor", "hazel", "heron", "hickory", "honey",
    "hornet", "horse", "ivory", "jade", "jaguar", "jasmine", "jelly", "jungle", "kettle", "kitten",
    "koala", "lagoon", "lake", "lantern", "lava", "leaf", "lemon", "lentil", "lilac", "lily",
    "lime", "lion", "lizard", "llama", "lotus", "lumber", "mango", "maple", "marble", "marsh",
    "meadow", "melon", "mint", "mirror", "moose", "moss", "mountain", "mouse", "muffin", "needle",
    "nickel", "noodle", "oak", "ocean", "olive", "onion", "onyx", "orange", "orchid", "otter",
    "owl", "oyster", "paddle", "panda", "pansy", "paper", "parrot", "peach", "peanut", "pearl",
    "pebble", "pecan", "pelican", "penguin", "pepper", "pewter", "pigeon", "pillow", "pine",
    "pizza", "planet", "plum", "pond", "poppy", "potato", "prairie", "pumpkin", "quartz", "rabbit",
    "radish", "raisin", "raven", "ribbon", "river", "robin", "rose", "ruby", "saddle", "salmon",
    "sapphire", "scarf", "seal", "silver", "sparrow", "spruce", "tiger", "tulip", "violet",
    "walnut", "willow", "zebra",
];

/// Generate a passphrase. Returns None if words == 0.
pub fn generate_passphrase(opts: &PassphraseOptions) -> Option<String> {
    if opts.words == 0 {
        return None;
    }
    let n = WORDS.len() as u32;
    let limit = u32::MAX - (u32::MAX % n);
    let mut parts: Vec<String> = Vec::with_capacity(opts.words);
    for _ in 0..opts.words {
        let idx = loop {
            let r = OsRng.next_u32();
            if r < limit {
                break (r % n) as usize;
            }
        };
        let mut w = WORDS[idx].to_string();
        if opts.capitalize {
            let mut c = w.chars();
            if let Some(first) = c.next() {
                w = first.to_uppercase().collect::<String>() + c.as_str();
            }
        }
        parts.push(w);
    }
    Some(parts.join(&opts.separator))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_requested_length() {
        let opts = CharsetOptions {
            length: 32,
            ..Default::default()
        };
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
        let opts = CharsetOptions {
            length: 500,
            exclude_ambiguous: true,
            ..Default::default()
        };
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
        let opts = CharsetOptions {
            length: 0,
            ..Default::default()
        };
        assert!(generate_password(&opts).is_none());
    }

    #[test]
    fn passphrase_has_requested_word_count() {
        let opts = PassphraseOptions {
            words: 5,
            separator: "-".into(),
            capitalize: false,
        };
        let phrase = generate_passphrase(&opts).unwrap();
        assert_eq!(phrase.split('-').count(), 5);
    }

    #[test]
    fn passphrase_capitalizes_when_requested() {
        let opts = PassphraseOptions {
            words: 3,
            separator: " ".into(),
            capitalize: true,
        };
        let phrase = generate_passphrase(&opts).unwrap();
        assert!(phrase
            .split(' ')
            .all(|w| w.chars().next().unwrap().is_uppercase()));
    }

    #[test]
    fn passphrase_zero_words_is_none() {
        let opts = PassphraseOptions {
            words: 0,
            ..Default::default()
        };
        assert!(generate_passphrase(&opts).is_none());
    }

    #[test]
    fn wordlist_is_large_and_unique() {
        use std::collections::HashSet;
        assert!(WORDS.len() >= 256, "wordlist too small: {}", WORDS.len());
        let set: HashSet<&&str> = WORDS.iter().collect();
        assert_eq!(set.len(), WORDS.len(), "wordlist has duplicates");
    }
}
