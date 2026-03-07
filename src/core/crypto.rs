/// Cryptographic primitives for the Kryptis blockchain.
///
/// Provides SHA-256 hashing, ed25519 keypairs, and the KRS1-prefixed
/// address format. All hex encoding uses lowercase.
use std::path::Path;

use ed25519_dalek::{Signer, Verifier};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

use crate::core::error::{KryptisError, KryptisResult};

/// A hex-encoded SHA-256 hash (64 lowercase hex characters).
pub type Hash = String;

/// A KRS1-prefixed address string (44 characters total).
///
/// Format: `"KRS1"` + hex(first 20 bytes of SHA-256(public key bytes))
pub type Address = String;

/// Compute a single SHA-256 hash of the given bytes, returned as lowercase hex.
pub fn sha256(data: &[u8]) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Compute SHA-256(SHA-256(data)) — double hash used for block headers.
pub fn double_sha256(data: &[u8]) -> Hash {
    let first = Sha256::digest(data);
    let second = Sha256::digest(first);
    hex::encode(second)
}

/// An ed25519 keypair for signing and verifying data.
///
/// The `signing_key` holds both secret and public halves.
/// Serialised to disk as a JSON object containing the 32-byte secret key in hex.
pub struct Keypair {
    /// The ed25519 signing key (contains the secret scalar).
    pub signing_key: ed25519_dalek::SigningKey,
    /// The corresponding verifying (public) key, derived from `signing_key`.
    pub verifying_key: ed25519_dalek::VerifyingKey,
}

impl Keypair {
    /// Generate a fresh random keypair using the OS RNG.
    pub fn generate() -> Self {
        let signing_key = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        Self {
            signing_key,
            verifying_key,
        }
    }

    /// Sign `message` and return the signature as lowercase hex (128 chars).
    pub fn sign(&self, message: &[u8]) -> String {
        let sig: ed25519_dalek::Signature = self.signing_key.sign(message);
        hex::encode(sig.to_bytes())
    }

    /// Return the verifying key as lowercase hex (64 chars).
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.verifying_key.as_bytes())
    }

    /// Derive the KRS1 address from the public key.
    ///
    /// Address = `"KRS1"` + hex(SHA-256(pubkey_bytes)[..20])
    /// Total length: 4 + 40 = 44 characters.
    pub fn address(&self) -> Address {
        let pubkey_bytes = self.verifying_key.as_bytes();
        let hash = Sha256::digest(pubkey_bytes);
        format!("KRS1{}", hex::encode(&hash[..20]))
    }

    /// Persist the keypair to `path` as a JSON file.
    ///
    /// Only the 32-byte secret key is stored; the public key is always
    /// re-derived on load so there is no risk of inconsistency.
    pub fn save_to_file(&self, path: &Path) -> KryptisResult<()> {
        let secret_hex = hex::encode(self.signing_key.to_bytes());
        let json = serde_json::json!({ "secret_key": secret_hex });
        let content = serde_json::to_string_pretty(&json)
            .map_err(|e| KryptisError::SerializationError(e.to_string()))?;
        std::fs::write(path, content)
            .map_err(|e| KryptisError::StorageError(e.to_string()))
    }

    /// Load a keypair from a JSON file previously written by [`save_to_file`].
    pub fn load_from_file(path: &Path) -> KryptisResult<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| KryptisError::StorageError(e.to_string()))?;
        let json: serde_json::Value = serde_json::from_str(&content)
            .map_err(|e| KryptisError::SerializationError(e.to_string()))?;
        let secret_hex = json["secret_key"]
            .as_str()
            .ok_or_else(|| KryptisError::KeyGenerationFailed("missing secret_key field".into()))?;
        let secret_bytes = hex::decode(secret_hex)
            .map_err(|e| KryptisError::KeyGenerationFailed(e.to_string()))?;
        let bytes: [u8; 32] = secret_bytes
            .try_into()
            .map_err(|_| KryptisError::KeyGenerationFailed("secret key must be 32 bytes".into()))?;
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&bytes);
        let verifying_key = signing_key.verifying_key();
        Ok(Self {
            signing_key,
            verifying_key,
        })
    }
}

/// Verify an ed25519 signature produced by the owner of `pubkey_hex`.
///
/// Returns `Ok(())` if the signature is valid, otherwise `Err(InvalidSignature)`.
pub fn verify_signature(
    pubkey_hex: &str,
    message: &[u8],
    sig_hex: &str,
) -> KryptisResult<()> {
    let pubkey_bytes = hex::decode(pubkey_hex).map_err(|_| KryptisError::InvalidPublicKey)?;
    let pubkey_arr: [u8; 32] = pubkey_bytes
        .try_into()
        .map_err(|_| KryptisError::InvalidPublicKey)?;
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&pubkey_arr)
        .map_err(|_| KryptisError::InvalidPublicKey)?;

    let sig_bytes = hex::decode(sig_hex).map_err(|_| KryptisError::InvalidSignature)?;
    let sig_arr: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| KryptisError::InvalidSignature)?;
    let signature = ed25519_dalek::Signature::from_bytes(&sig_arr);

    verifying_key
        .verify(message, &signature)
        .map_err(|_| KryptisError::InvalidSignature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn sha256_deterministic() {
        let a = sha256(b"hello kryptis");
        let b = sha256(b"hello kryptis");
        assert_eq!(a, b);
    }

    #[test]
    fn sha256_different_inputs_differ() {
        let a = sha256(b"foo");
        let b = sha256(b"bar");
        assert_ne!(a, b);
    }

    #[test]
    fn double_sha256_differs_from_single() {
        let data = b"kryptis";
        assert_ne!(sha256(data), double_sha256(data));
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let kp = Keypair::generate();
        let msg = b"test message";
        let sig = kp.sign(msg);
        assert!(verify_signature(&kp.public_key_hex(), msg, &sig).is_ok());
    }

    #[test]
    fn tampered_message_fails_verification() {
        let kp = Keypair::generate();
        let msg = b"original message";
        let sig = kp.sign(msg);
        let tampered = b"tampered message";
        assert!(verify_signature(&kp.public_key_hex(), tampered, &sig).is_err());
    }

    #[test]
    fn address_format_starts_krs1() {
        let kp = Keypair::generate();
        let addr = kp.address();
        assert!(addr.starts_with("KRS1"), "Address must start with KRS1: {}", addr);
    }

    #[test]
    fn address_length_is_44() {
        let kp = Keypair::generate();
        let addr = kp.address();
        assert_eq!(addr.len(), 44, "Address must be 44 chars, got {}", addr.len());
    }

    #[test]
    fn address_is_deterministic() {
        let kp = Keypair::generate();
        assert_eq!(kp.address(), kp.address());
    }

    #[test]
    fn save_and_load_keypair_roundtrip() {
        let kp = Keypair::generate();
        let original_addr = kp.address();
        let original_pubkey = kp.public_key_hex();

        let tmp = NamedTempFile::new().expect("tempfile");
        kp.save_to_file(tmp.path()).expect("save");

        let loaded = Keypair::load_from_file(tmp.path()).expect("load");
        assert_eq!(loaded.address(), original_addr);
        assert_eq!(loaded.public_key_hex(), original_pubkey);
    }

    #[test]
    fn loaded_keypair_can_sign() {
        let kp = Keypair::generate();
        let tmp = NamedTempFile::new().expect("tempfile");
        kp.save_to_file(tmp.path()).expect("save");
        let loaded = Keypair::load_from_file(tmp.path()).expect("load");

        let msg = b"signed after reload";
        let sig = loaded.sign(msg);
        assert!(verify_signature(&loaded.public_key_hex(), msg, &sig).is_ok());
    }
}
