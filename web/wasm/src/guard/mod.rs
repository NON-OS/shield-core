//! The keystore of the browser build: the wallet's file key wrapped under a secret the user's
//! passkey derives through the WebAuthn PRF extension, after the user is verified. The page asks
//! the authenticator for that secret and hands it here just before the wallet needs it, and it is
//! used once and wiped. Unlike a Secure Enclave key it passes through the page's memory, which
//! docs/web.md says plainly.

use nonos_seal::{open, seal, NONCE_LEN, TAG_LEN};
use nox_shield_core::custody::HardwareGuard;
use nox_shield_core::error::CustodyError;
use std::sync::Mutex;
use zeroize::Zeroizing;

/// Bound into every wrap, so a blob from another use of the same passkey secret never opens here.
const AAD: &[u8] = b"nox-shield/web/guard/v1";
const KEY_LEN: usize = 32;

#[derive(Default)]
pub struct PasskeyGuard {
    secret: Mutex<Option<Zeroizing<[u8; KEY_LEN]>>>,
}

impl PasskeyGuard {
    /// The passkey's PRF output for the next wrap or unwrap. Anything but 32 bytes is refused.
    pub fn hold(&self, secret: &[u8]) -> bool {
        let Ok(bytes) = <[u8; KEY_LEN]>::try_from(secret) else { return false };
        let Ok(mut slot) = self.secret.lock() else { return false };
        *slot = Some(Zeroizing::new(bytes));
        true
    }

    /// The held secret, taken so it cannot be used a second time.
    fn take(&self) -> Result<Zeroizing<[u8; KEY_LEN]>, CustodyError> {
        self.secret.lock().map_err(|_| CustodyError::Guard)?.take().ok_or(CustodyError::Guard)
    }
}

impl HardwareGuard for PasskeyGuard {
    fn wrap(&self, key: Vec<u8>) -> Result<Vec<u8>, CustodyError> {
        let key = Zeroizing::new(key);
        let secret = self.take()?;
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::getrandom(&mut nonce).map_err(|_| CustodyError::Entropy)?;
        let mut out = vec![0u8; NONCE_LEN + key.len() + TAG_LEN];
        let (head, body) = out.split_at_mut(NONCE_LEN);
        head.copy_from_slice(&nonce);
        seal(&secret, &nonce, AAD, &key, body).map_err(|_| CustodyError::Guard)?;
        Ok(out)
    }

    fn unwrap_key(&self, blob: Vec<u8>) -> Result<Vec<u8>, CustodyError> {
        let secret = self.take()?;
        let (nonce, sealed) = blob.split_at_checked(NONCE_LEN).ok_or(CustodyError::Guard)?;
        let nonce: [u8; NONCE_LEN] = nonce.try_into().map_err(|_| CustodyError::Guard)?;
        let length = sealed.len().checked_sub(TAG_LEN).ok_or(CustodyError::Guard)?;
        let mut key = vec![0u8; length];
        open(&secret, &nonce, AAD, sealed, &mut key).map_err(|_| CustodyError::SealAuth)?;
        Ok(key)
    }
}
