use argon2::{Config as Argon2Config, ThreadMode, Variant, Version};
use aws_lc_rs::aead::{AES_128_GCM, Aad, LessSafeKey, Nonce, UnboundKey};

pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;

#[derive(Debug)]
pub struct AeadError;

impl std::fmt::Display for AeadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AEAD authentication failure")
    }
}

impl std::error::Error for AeadError {}

pub struct Aead(LessSafeKey);

impl Aead {
    pub fn aes_128_gcm(key: &[u8]) -> Self {
        let unbound = UnboundKey::new(&AES_128_GCM, key)
            .expect("AEAD key length matches the algorithm");
        Self(LessSafeKey::new(unbound))
    }

    pub fn seal_detached(
        &self,
        nonce: &[u8; NONCE_LEN],
        ad: &[u8],
        data: &mut [u8],
        tag: &mut [u8],
    ) -> Result<(), AeadError> {
        debug_assert_eq!(tag.len(), TAG_LEN);
        let n = Nonce::try_assume_unique_for_key(nonce).map_err(|_| AeadError)?;
        let t = self
            .0
            .seal_in_place_separate_tag(n, Aad::from(ad), data)
            .map_err(|_| AeadError)?;
        tag.copy_from_slice(t.as_ref());
        Ok(())
    }

    pub fn open_detached(
        &self,
        nonce: &[u8; NONCE_LEN],
        ad: &[u8],
        data: &mut [u8],
        tag: &[u8],
    ) -> Result<(), AeadError> {
        let n = Nonce::try_assume_unique_for_key(nonce).map_err(|_| AeadError)?;
        self.0
            .open_in_place_separate_tag(n, Aad::from(ad), tag, data)
            .map_err(|_| AeadError)?;
        Ok(())
    }

    pub fn seal_append(
        &self,
        nonce: &[u8; NONCE_LEN],
        ad: &[u8],
        buf: &mut Vec<u8>,
    ) -> Result<(), AeadError> {
        let len = buf.len();
        buf.resize(len + TAG_LEN, 0);
        let (data, tag) = buf.split_at_mut(len);
        self.seal_detached(nonce, ad, data, tag)
    }

    pub fn open_trailing(
        &self,
        nonce: &[u8; NONCE_LEN],
        ad: &[u8],
        buf: &mut Vec<u8>,
    ) -> Result<(), AeadError> {
        let len = buf.len().checked_sub(TAG_LEN).ok_or(AeadError)?;
        let (data, tag) = buf.split_at_mut(len);
        self.open_detached(nonce, ad, data, tag)?;
        buf.truncate(len);
        Ok(())
    }
}

pub const SNELL_ARGON2_CONFIG: Argon2Config<'static> = Argon2Config {
    variant: Variant::Argon2id,
    version: Version::Version13,
    mem_cost: 8,  // 8 KB
    time_cost: 3, // 3 iterations
    lanes: 1,     // parallelism = 1
    thread_mode: ThreadMode::Sequential,
    secret: &[],
    ad: &[],
    hash_length: 32,
};

/// Snell KDF — Argon2id(t=3, m=8 KiB, p=1) → 32 bytes; first `key_size` bytes are used as the AEAD key.
pub fn snell_kdf(psk: &[u8], salt: &[u8], key_size: usize) -> Vec<u8> {
    debug_assert!(key_size <= 32, "snell KDF caller asked for >32 B");
    let mut out = argon2::hash_raw(psk, salt, &SNELL_ARGON2_CONFIG)
        .expect("argon2 hash_raw never fails with valid params");
    out.truncate(key_size);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kdf_is_deterministic_for_same_inputs() {
        let psk = b"shared-secret";
        let salt = [7u8; 16];
        let a = snell_kdf(psk, &salt, 16);
        let b = snell_kdf(psk, &salt, 16);
        assert_eq!(a, b);
        assert_eq!(a.len(), 16);
    }

    #[test]
    fn kdf_differs_on_different_salt() {
        let psk = b"shared-secret";
        let a = snell_kdf(psk, &[0u8; 16], 16);
        let b = snell_kdf(psk, &[1u8; 16], 16);
        assert_ne!(a, b);
    }

    #[test]
    fn open_rejects_tampering_and_short_input() {
        let aead = Aead::aes_128_gcm(&[7; 16]);
        let nonce = [1; NONCE_LEN];
        let mut buf = b"record".to_vec();
        aead.seal_append(&nonce, b"ad", &mut buf).unwrap();

        let mut flipped = buf.clone();
        flipped[0] ^= 1;
        assert!(aead.open_trailing(&nonce, b"ad", &mut flipped).is_err());
        assert!(aead
            .open_trailing(&[2; NONCE_LEN], b"ad", &mut buf.clone())
            .is_err());
        assert!(aead
            .open_trailing(&nonce, b"other ad", &mut buf.clone())
            .is_err());
        assert!(aead
            .open_trailing(&nonce, b"", &mut vec![0; TAG_LEN - 1])
            .is_err());
        aead.open_trailing(&nonce, b"ad", &mut buf).unwrap();
        assert_eq!(buf, b"record");
    }
}
