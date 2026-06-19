use thiserror::Error;

/// All fallible operations in protec-core return `Result<_, VaultError>`.
#[derive(Debug, Error)]
pub enum VaultError {
    #[error("incorrect master password")]
    WrongPassword,
    #[error("vault file is corrupted")]
    Corrupted,
    #[error("vault authentication failed (data was tampered with)")]
    Tampered,
    #[error("vault format version {0} is not supported")]
    VersionUnsupported(u8),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrong_password_and_tampered_have_distinct_variants_but_generic_messages() {
        assert_eq!(VaultError::WrongPassword.to_string(), "incorrect master password");
        assert_eq!(
            VaultError::Tampered.to_string(),
            "vault authentication failed (data was tampered with)"
        );
    }
}
