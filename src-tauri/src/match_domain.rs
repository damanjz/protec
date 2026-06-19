//! Strict registrable-domain matching for anti-phishing autofill.
//! The page origin is supplied by the browser, never by page content.

/// Extract the registrable domain (eTLD+1) from a URL or origin string.
/// e.g. "https://www.github.com/login" -> "github.com",
///      "https://a.b.example.co.uk" -> "example.co.uk".
/// Returns None if there is no host or no registrable domain.
pub fn registrable_domain(url_or_origin: &str) -> Option<String> {
    // Accept bare hosts too (e.g. "github.com") by trying to parse, then
    // falling back to treating the input as a host.
    let host = match url::Url::parse(url_or_origin) {
        Ok(u) => u.host_str().map(|h| h.to_string()),
        Err(_) => Some(url_or_origin.trim().to_string()),
    }?;
    let host = host.trim_end_matches('.').to_lowercase();
    if host.is_empty() {
        return None;
    }
    let domain = psl::domain_str(&host)?;
    Some(domain.to_string())
}

/// True if a saved entry URL should be offered for the given page origin.
/// Both are reduced to their registrable domain and compared exactly — so
/// `github.com` matches `www.github.com` but NOT `github.com.evil.com`.
pub fn origin_matches(saved_url: &str, page_origin: &str) -> bool {
    match (registrable_domain(saved_url), registrable_domain(page_origin)) {
        (Some(a), Some(b)) => a == b,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_simple_domain() {
        assert_eq!(registrable_domain("https://github.com/login").as_deref(), Some("github.com"));
    }

    #[test]
    fn extracts_from_subdomain() {
        assert_eq!(registrable_domain("https://www.github.com").as_deref(), Some("github.com"));
        assert_eq!(registrable_domain("https://accounts.github.com").as_deref(), Some("github.com"));
    }

    #[test]
    fn handles_multi_part_suffix() {
        assert_eq!(registrable_domain("https://a.b.example.co.uk").as_deref(), Some("example.co.uk"));
    }

    #[test]
    fn accepts_bare_host() {
        assert_eq!(registrable_domain("github.com").as_deref(), Some("github.com"));
    }

    #[test]
    fn rejects_empty() {
        assert_eq!(registrable_domain(""), None);
    }

    #[test]
    fn matches_same_registrable_domain() {
        assert!(origin_matches("https://github.com", "https://www.github.com/login"));
        assert!(origin_matches("https://accounts.github.com", "https://github.com"));
    }

    #[test]
    fn rejects_lookalike_suffix_attack() {
        // The classic phishing vector — must NOT match.
        assert!(!origin_matches("https://github.com", "https://github.com.evil.com"));
    }

    #[test]
    fn rejects_typosquat() {
        assert!(!origin_matches("https://github.com", "https://g1thub.com"));
    }

    #[test]
    fn rejects_unrelated_domain() {
        assert!(!origin_matches("https://github.com", "https://paypal.com"));
    }

    #[test]
    fn rejects_when_either_side_unparseable() {
        assert!(!origin_matches("", "https://github.com"));
        assert!(!origin_matches("https://github.com", ""));
    }
}
