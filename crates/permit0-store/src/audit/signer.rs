#![forbid(unsafe_code)]

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};

/// Trait for signing and verifying audit entry hashes.
pub trait AuditSigner: Send + Sync {
    /// Sign an entry hash. Returns the hex-encoded signature.
    fn sign(&self, entry_hash: &str) -> String;
    /// Verify a signature over an entry hash.
    fn verify(&self, entry_hash: &str, signature: &str) -> bool;
    /// Get the public key as hex.
    fn public_key_hex(&self) -> String;
}

/// ed25519 signer using ed25519-dalek.
pub struct Ed25519Signer {
    signing_key: SigningKey,
}

impl Ed25519Signer {
    /// Create a new signer from a 32-byte seed.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(seed);
        Self { signing_key }
    }

    /// Generate a new random signer.
    pub fn generate() -> Self {
        use rand::rngs::OsRng;
        let signing_key = SigningKey::generate(&mut OsRng);
        Self { signing_key }
    }

    fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }
}

impl AuditSigner for Ed25519Signer {
    fn sign(&self, entry_hash: &str) -> String {
        let signature = self.signing_key.sign(entry_hash.as_bytes());
        hex::encode(signature.to_bytes())
    }

    fn verify(&self, entry_hash: &str, signature: &str) -> bool {
        let sig_bytes = match hex::decode(signature) {
            Ok(b) => b,
            Err(_) => return false,
        };
        let sig = match ed25519_dalek::Signature::from_slice(&sig_bytes) {
            Ok(s) => s,
            Err(_) => return false,
        };
        self.verifying_key()
            .verify(entry_hash.as_bytes(), &sig)
            .is_ok()
    }

    fn public_key_hex(&self) -> String {
        hex::encode(self.verifying_key().as_bytes())
    }
}

/// Verifier-only (no signing key). For verification on air-gapped machines.
pub struct Ed25519Verifier {
    verifying_key: VerifyingKey,
}

impl Ed25519Verifier {
    /// Create from a hex-encoded public key.
    pub fn from_hex(public_key_hex: &str) -> Result<Self, String> {
        let bytes = hex::decode(public_key_hex)
            .map_err(|e| format!("invalid hex: {e}"))?;
        let key_bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| "public key must be 32 bytes".to_string())?;
        let verifying_key = VerifyingKey::from_bytes(&key_bytes)
            .map_err(|e| format!("invalid ed25519 key: {e}"))?;
        Ok(Self { verifying_key })
    }

    /// Verify a signature over an entry hash.
    pub fn verify(&self, entry_hash: &str, signature: &str) -> bool {
        let sig_bytes = match hex::decode(signature) {
            Ok(b) => b,
            Err(_) => return false,
        };
        let sig = match ed25519_dalek::Signature::from_slice(&sig_bytes) {
            Ok(s) => s,
            Err(_) => return false,
        };
        self.verifying_key
            .verify(entry_hash.as_bytes(), &sig)
            .is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify() {
        let signer = Ed25519Signer::generate();
        let hash = "abc123def456";
        let sig = signer.sign(hash);
        assert!(signer.verify(hash, &sig));
    }

    #[test]
    fn verify_rejects_wrong_hash() {
        let signer = Ed25519Signer::generate();
        let sig = signer.sign("correct_hash");
        assert!(!signer.verify("wrong_hash", &sig));
    }

    #[test]
    fn verify_rejects_invalid_signature() {
        let signer = Ed25519Signer::generate();
        assert!(!signer.verify("some_hash", "not_hex_at_all"));
        assert!(!signer.verify("some_hash", "deadbeef"));
    }

    #[test]
    fn verifier_from_public_key() {
        let signer = Ed25519Signer::generate();
        let pubkey_hex = signer.public_key_hex();
        let verifier = Ed25519Verifier::from_hex(&pubkey_hex).unwrap();

        let hash = "test_entry_hash";
        let sig = signer.sign(hash);
        assert!(verifier.verify(hash, &sig));
        assert!(!verifier.verify("tampered", &sig));
    }

    #[test]
    fn from_seed_deterministic() {
        let seed = [42u8; 32];
        let s1 = Ed25519Signer::from_seed(&seed);
        let s2 = Ed25519Signer::from_seed(&seed);
        assert_eq!(s1.public_key_hex(), s2.public_key_hex());

        let hash = "test";
        assert_eq!(s1.sign(hash), s2.sign(hash));
    }
}
