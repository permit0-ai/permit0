#![forbid(unsafe_code)]

use std::fs;
use std::io::Write;
use std::path::Path;

use crate::audit::signer::Ed25519Signer;

/// Errors from key store operations.
#[derive(Debug, thiserror::Error)]
pub enum KeyStoreError {
    #[error("key store I/O error: {0}")]
    Io(String),
    #[error("invalid key file contents: {0}")]
    InvalidKey(String),
}

/// Loads an audit signing key from disk, generating one on first run.
///
/// Format: a single line containing the 32-byte ed25519 seed as hex
/// (64 hex characters). The file is created with mode `0600` on Unix
/// so the seed is not world-readable. A trailing newline is written
/// for ergonomics; readers tolerate any surrounding whitespace.
///
/// Why hex over PEM: the seed is fixed-size (32 bytes), `Ed25519Signer`
/// already exposes hex-encoded public keys, and the audit verifier
/// flow stays uniform.
pub struct FileKeyStore;

impl FileKeyStore {
    /// Load the key at `path` if it exists, otherwise generate, save, and return it.
    pub fn load_or_generate(path: impl AsRef<Path>) -> Result<Ed25519Signer, KeyStoreError> {
        let path = path.as_ref();
        if path.exists() {
            return Self::load(path);
        }
        Self::generate_and_save(path)
    }

    fn load(path: &Path) -> Result<Ed25519Signer, KeyStoreError> {
        let raw = fs::read_to_string(path).map_err(|e| KeyStoreError::Io(e.to_string()))?;
        let trimmed = raw.trim();
        let bytes =
            hex::decode(trimmed).map_err(|e| KeyStoreError::InvalidKey(format!("not hex: {e}")))?;
        let seed: [u8; 32] = bytes.try_into().map_err(|_| {
            KeyStoreError::InvalidKey("seed must be 32 bytes (64 hex chars)".into())
        })?;
        Ok(Ed25519Signer::from_seed(&seed))
    }

    fn generate_and_save(path: &Path) -> Result<Ed25519Signer, KeyStoreError> {
        use rand::RngCore;
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|e| KeyStoreError::Io(e.to_string()))?;
            }
        }

        let mut seed = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut seed);
        let signer = Ed25519Signer::from_seed(&seed);

        write_seed_secure(path, &seed)?;
        Ok(signer)
    }
}

#[cfg(unix)]
fn write_seed_secure(path: &Path, seed: &[u8; 32]) -> Result<(), KeyStoreError> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| KeyStoreError::Io(format!("create key file {}: {e}", path.display())))?;
    let line = hex::encode(seed) + "\n";
    f.write_all(line.as_bytes())
        .map_err(|e| KeyStoreError::Io(e.to_string()))?;
    Ok(())
}

#[cfg(not(unix))]
fn write_seed_secure(path: &Path, seed: &[u8; 32]) -> Result<(), KeyStoreError> {
    let mut f = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|e| KeyStoreError::Io(format!("create key file {}: {e}", path.display())))?;
    let line = hex::encode(seed) + "\n";
    f.write_all(line.as_bytes())
        .map_err(|e| KeyStoreError::Io(e.to_string()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::signer::AuditSigner;

    #[test]
    fn generates_then_reuses_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit_signing.key");

        let signer1 = FileKeyStore::load_or_generate(&path).unwrap();
        let pub1 = signer1.public_key_hex();
        assert!(path.exists());

        let signer2 = FileKeyStore::load_or_generate(&path).unwrap();
        let pub2 = signer2.public_key_hex();
        assert_eq!(pub1, pub2, "second load must return the same key");
    }

    #[test]
    fn rejects_invalid_key_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit_signing.key");
        std::fs::write(&path, "not valid hex").unwrap();
        match FileKeyStore::load_or_generate(&path) {
            Err(KeyStoreError::InvalidKey(_)) => {}
            Ok(_) => panic!("expected InvalidKey error, got Ok"),
            Err(e) => panic!("expected InvalidKey error, got {e:?}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn key_file_is_mode_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit_signing.key");
        FileKeyStore::load_or_generate(&path).unwrap();
        let perms = std::fs::metadata(&path).unwrap().permissions();
        assert_eq!(perms.mode() & 0o777, 0o600);
    }
}
