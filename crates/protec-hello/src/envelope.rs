use crate::error::HelloError;
use zeroize::Zeroizing;

/// Abstracts the source of the 32-byte wrapping key. The real implementation
/// (tpm.rs) derives it from a TPM-bound, Hello-gated credential. Tests use a
/// fake provider so the envelope logic is verifiable without hardware.
pub trait KeyProvider {
    /// Produce the 32-byte wrapping key, prompting Hello if needed.
    /// Called for both enable (to wrap) and unlock (to unwrap).
    fn wrapping_key(&self) -> Result<Zeroizing<[u8; 32]>, HelloError>;
}

/// The data persisted alongside a Hello wrap that the provider needs to
/// reproduce the same wrapping key later. For the TPM provider this is empty
/// (the key lives in the TPM, addressed by a fixed container name), but the
/// type leaves room for per-vault salt if a future provider needs it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HelloWrapData;

/// Compute the wrapping key for enabling Hello on a vault. Returns the 32-byte
/// key the caller passes to `KeyWrap::seal(WrapKind::WindowsHello, key, vault_key)`.
pub fn wrapping_key_for_enable(
    provider: &impl KeyProvider,
) -> Result<Zeroizing<[u8; 32]>, HelloError> {
    provider.wrapping_key()
}

/// Compute the wrapping key for unlocking via Hello. Same key the enable step
/// produced (the provider is deterministic for a given device + credential).
pub fn wrapping_key_for_unlock(
    provider: &impl KeyProvider,
) -> Result<Zeroizing<[u8; 32]>, HelloError> {
    provider.wrapping_key()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A deterministic fake provider — returns a fixed key. Stands in for the TPM.
    struct FakeProvider {
        key: [u8; 32],
        fail: Option<HelloError>,
    }
    impl KeyProvider for FakeProvider {
        fn wrapping_key(&self) -> Result<Zeroizing<[u8; 32]>, HelloError> {
            if let Some(e) = &self.fail {
                return Err(e.clone());
            }
            Ok(Zeroizing::new(self.key))
        }
    }

    #[test]
    fn enable_and_unlock_produce_the_same_key() {
        let p = FakeProvider {
            key: [3u8; 32],
            fail: None,
        };
        let a = wrapping_key_for_enable(&p).unwrap();
        let b = wrapping_key_for_unlock(&p).unwrap();
        assert_eq!(a.as_ref(), b.as_ref());
    }

    #[test]
    fn provider_failure_propagates() {
        let p = FakeProvider {
            key: [0u8; 32],
            fail: Some(HelloError::UserCancelled),
        };
        assert_eq!(wrapping_key_for_unlock(&p), Err(HelloError::UserCancelled));
    }

    /// End-to-end envelope check using protec-core's KeyWrap with the fake key:
    /// wrap a vault key with the provider's key, then unwrap it. This proves the
    /// Hello wrap integrates with the core envelope without any TPM.
    #[test]
    fn envelope_round_trip_via_core_keywrap() {
        let p = FakeProvider {
            key: [5u8; 32],
            fail: None,
        };
        let vault_key = [8u8; 32];
        let wk = wrapping_key_for_enable(&p).unwrap();
        let wrap = protec_core::KeyWrap::seal(protec_core::WrapKind::WindowsHello, &wk, &vault_key)
            .unwrap();
        let wk2 = wrapping_key_for_unlock(&p).unwrap();
        let recovered = wrap.open(&wk2).unwrap();
        assert_eq!(recovered.as_ref(), &vault_key);
    }
}
