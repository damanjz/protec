use std::collections::HashMap;

/// Sliding-window rate limiter keyed by origin. Not time-aware on its own —
/// the caller passes a monotonic "now" in milliseconds so it stays testable.
pub struct RateLimiter {
    window_ms: u64,
    max_in_window: usize,
    hits: HashMap<String, Vec<u64>>,
}

impl RateLimiter {
    pub fn new(window_ms: u64, max_in_window: usize) -> Self {
        Self { window_ms, max_in_window, hits: HashMap::new() }
    }

    /// Record a request for `origin` at time `now_ms`. Returns true if allowed,
    /// false if the origin has exceeded `max_in_window` within the window.
    pub fn check(&mut self, origin: &str, now_ms: u64) -> bool {
        let cutoff = now_ms.saturating_sub(self.window_ms);
        let v = self.hits.entry(origin.to_string()).or_default();
        v.retain(|&t| t >= cutoff);
        if v.len() >= self.max_in_window {
            return false;
        }
        v.push(now_ms);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_up_to_the_limit() {
        let mut rl = RateLimiter::new(1000, 3);
        assert!(rl.check("a", 0));
        assert!(rl.check("a", 10));
        assert!(rl.check("a", 20));
        assert!(!rl.check("a", 30)); // 4th within window → blocked
    }

    #[test]
    fn window_slides() {
        let mut rl = RateLimiter::new(1000, 2);
        assert!(rl.check("a", 0));
        assert!(rl.check("a", 500));
        assert!(!rl.check("a", 600));     // blocked
        assert!(rl.check("a", 1600));     // first hit aged out → allowed again
    }

    #[test]
    fn origins_are_independent() {
        let mut rl = RateLimiter::new(1000, 1);
        assert!(rl.check("a", 0));
        assert!(!rl.check("a", 1));
        assert!(rl.check("b", 1)); // different origin unaffected
    }
}
