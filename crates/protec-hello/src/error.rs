/// Errors from Windows Hello operations. All map to friendly, non-leaky messages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HelloError {
    /// No TPM / Hello not configured on this device.
    Unavailable,
    /// The user cancelled or failed the Hello prompt.
    UserCancelled,
    /// The TPM key Protec created is missing (e.g. Hello/TPM was reset).
    KeyMissing,
    /// Any other failure (TPM busy, OS error). The String is a short, safe label.
    Backend(String),
}

impl std::fmt::Display for HelloError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HelloError::Unavailable => write!(f, "Windows Hello is not available on this device"),
            HelloError::UserCancelled => write!(f, "Windows Hello was cancelled"),
            HelloError::KeyMissing => write!(
                f,
                "The Windows Hello key is missing — use your master password"
            ),
            HelloError::Backend(_) => write!(
                f,
                "Windows Hello could not be used — use your master password"
            ),
        }
    }
}

impl std::error::Error for HelloError {}
