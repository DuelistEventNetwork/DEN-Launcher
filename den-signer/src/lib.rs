mod signer_error;
pub use signer_error::SignerError;

use std::collections::HashSet;
use std::path::{Path, PathBuf};

pub use ed25519_dalek::VerifyingKey;
use ed25519_dalek::{Signature, Verifier};

pub type Result<T> = std::result::Result<T, SignerError>;

#[derive(bitcode::Encode, bitcode::Decode)]
pub struct ManifestFile {
    pub name: String,
    pub install_path: String,
    pub sig: [u8; 64],
}

#[derive(bitcode::Encode, bitcode::Decode)]
pub struct ManifestV1 {
    pub version: String,
    pub files: Vec<ManifestFile>,
}

pub type ManifestInner = ManifestV1;

#[derive(bitcode::Encode, bitcode::Decode)]
pub struct OpaquePayload(Vec<u8>);

impl OpaquePayload {
    pub fn encode_from<T: bitcode::Encode>(val: &T) -> Self {
        Self(bitcode::encode(val))
    }

    pub fn decode_as<T: for<'a> bitcode::Decode<'a>>(&self) -> Result<T> {
        bitcode::decode(&self.0).map_err(|e| SignerError::Bitcode(e.to_string()))
    }

    pub fn bytes(&self) -> &[u8] {
        &self.0
    }
}

#[derive(bitcode::Encode, bitcode::Decode)]
pub struct ReleaseManifest {
    pub format_version: u32,
    pub payload: OpaquePayload,
    pub sig: [u8; 64],
}

impl ManifestFile {
    pub fn verify(&self, data: &[u8], key: &VerifyingKey) -> Result<()> {
        let sig = Signature::from_bytes(&self.sig);
        key.verify(data, &sig).map_err(|_| {
            SignerError::Signature(format!(
                "File signature verification failed for {}",
                self.name
            ))
        })
    }
}

impl ReleaseManifest {
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        bitcode::decode(bytes).map_err(|e| SignerError::Bitcode(e.to_string()))
    }

    pub fn verify(&self, key: &VerifyingKey) -> Result<()> {
        let sig = Signature::from_bytes(&self.sig);
        key.verify(self.payload.bytes(), &sig).map_err(|_| {
            SignerError::Signature("Manifest signature verification failed".to_string())
        })
    }

    pub fn decode_inner(&self) -> Result<ManifestInner> {
        match self.format_version {
            1 => self.payload.decode_as::<ManifestInner>(),
            v => Err(SignerError::Validation(format!(
                "Unsupported manifest format version v{v}. Please update your launcher."
            ))),
        }
    }

    pub fn validate(&self) -> Result<()> {
        let inner = self.decode_inner()?;
        inner.validate()
    }

    pub fn safe_join(base: &Path, relative: &str) -> Option<PathBuf> {
        let rel = Path::new(relative);
        if rel.is_absolute() {
            return None;
        }

        let mut result = base.to_path_buf();
        for component in rel.components() {
            match component {
                std::path::Component::ParentDir => return None,
                std::path::Component::RootDir | std::path::Component::Prefix(_) => return None,
                std::path::Component::CurDir => continue,
                std::path::Component::Normal(part) => result.push(part),
            }
        }
        Some(result)
    }

    pub fn is_safe_asset_name(name: &str) -> bool {
        let path = Path::new(name);
        let file_name = match path.file_name() {
            Some(n) => n.to_string_lossy(),
            None => return false,
        };
        if path.components().count() != 1 {
            return false;
        }
        Self::is_safe_path_component(&file_name)
    }

    pub fn is_safe_install_path(name: &str) -> bool {
        let rel = Path::new(name);
        if rel.is_absolute() {
            return false;
        }

        let mut has_component = false;
        for component in rel.components() {
            match component {
                std::path::Component::CurDir | std::path::Component::ParentDir => return false,
                std::path::Component::RootDir | std::path::Component::Prefix(_) => return false,
                std::path::Component::Normal(part) => {
                    has_component = true;
                    if !Self::is_safe_path_component(&part.to_string_lossy()) {
                        return false;
                    }
                }
            }
        }
        has_component
    }

    fn is_safe_path_component(name: &str) -> bool {
        if name.is_empty() || name.ends_with(' ') || name.ends_with('.') {
            return false;
        }

        // Windows reserved device names
        let lower = name.to_lowercase();
        let stem = lower.split('.').next().unwrap_or(&lower);
        const RESERVED: &[&str] = &[
            "con", "prn", "aux", "nul", "clock$", "com1", "com2", "com3", "com4", "com5", "com6",
            "com7", "com8", "com9", "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8",
            "lpt9",
        ];
        if RESERVED.contains(&stem) {
            return false;
        }

        // ASCII-only allowlist. Unicode filenames are intentionally not supported.
        name.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    }
}

impl ManifestInner {
    pub fn validate(&self) -> Result<()> {
        let mut install_path_set = HashSet::new();
        let mut asset_name_set = HashSet::new();

        for mf in &self.files {
            if !ReleaseManifest::is_safe_asset_name(&mf.name) {
                return Err(SignerError::Validation(format!(
                    "Unsafe asset name in manifest: {}",
                    mf.name
                )));
            }

            if !ReleaseManifest::is_safe_install_path(&mf.install_path) {
                return Err(SignerError::Validation(format!(
                    "Unsafe install path in manifest: {}",
                    mf.install_path
                )));
            }

            if !install_path_set.insert(&mf.install_path) {
                return Err(SignerError::Validation(format!(
                    "Duplicate install path in manifest: {}",
                    mf.install_path
                )));
            }

            if !asset_name_set.insert(&mf.name) {
                return Err(SignerError::Validation(format!(
                    "Duplicate asset name in manifest: {}",
                    mf.name
                )));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;

    fn build_manifest(key: &SigningKey, version: &str, files: &[(&str, &[u8])]) -> ReleaseManifest {
        let manifest_files = files
            .iter()
            .map(|(name, data)| {
                let sig = key.sign(data);
                ManifestFile {
                    name: name.to_string(),
                    install_path: name.to_string(),
                    sig: sig.to_bytes(),
                }
            })
            .collect();

        let inner = ManifestInner {
            version: version.to_string(),
            files: manifest_files,
        };

        let payload = OpaquePayload::encode_from(&inner);
        let sig = key.sign(payload.bytes());

        ReleaseManifest {
            format_version: 1,
            payload,
            sig: sig.to_bytes(),
        }
    }

    #[test]
    fn test_roundtrip_encode_decode() {
        let key = SigningKey::generate(&mut OsRng);
        let manifest = build_manifest(&key, "1.2.3", &[("foo.dll", b"fake dll bytes")]);
        let decoded = ReleaseManifest::decode(&bitcode::encode(&manifest)).unwrap();
        let inner = decoded.decode_inner().unwrap();
        assert_eq!(inner.version, "1.2.3");
        assert_eq!(inner.files.len(), 1);
        assert_eq!(inner.files[0].name, "foo.dll");
    }

    #[test]
    fn test_decode_rejects_garbage() {
        assert!(ReleaseManifest::decode(b"not valid bitcode").is_err());
    }

    #[test]
    fn test_verify_manifest_ok() {
        let key = SigningKey::generate(&mut OsRng);
        let manifest = build_manifest(&key, "1.0.0", &[("a.dll", b"data")]);
        manifest.verify(&key.verifying_key()).unwrap();
    }

    #[test]
    fn test_verify_manifest_tampered_version() {
        let key = SigningKey::generate(&mut OsRng);
        let mut manifest = build_manifest(&key, "1.0.0", &[("a.dll", b"data")]);
        let mut inner = manifest.decode_inner().unwrap();
        inner.version = "9.9.9".to_string();
        manifest.payload = OpaquePayload::encode_from(&inner);
        assert!(manifest.verify(&key.verifying_key()).is_err());
    }

    #[test]
    fn test_verify_manifest_wrong_key() {
        let key = SigningKey::generate(&mut OsRng);
        let manifest = build_manifest(&key, "1.0.0", &[("a.dll", b"data")]);
        assert!(
            manifest
                .verify(&SigningKey::generate(&mut OsRng).verifying_key())
                .is_err()
        );
    }

    #[test]
    fn test_verify_file_ok() {
        let key = SigningKey::generate(&mut OsRng);
        let data = b"file contents";
        let manifest = build_manifest(&key, "1.0.0", &[("f.dll", data)]);
        let inner = manifest.decode_inner().unwrap();
        inner.files[0].verify(data, &key.verifying_key()).unwrap();
    }

    #[test]
    fn test_verify_file_tampered_data() {
        let key = SigningKey::generate(&mut OsRng);
        let manifest = build_manifest(&key, "1.0.0", &[("f.dll", b"original")]);
        let inner = manifest.decode_inner().unwrap();
        assert!(
            inner.files[0]
                .verify(b"tampered", &key.verifying_key())
                .is_err()
        );
    }

    #[test]
    fn test_verify_file_wrong_key() {
        let key = SigningKey::generate(&mut OsRng);
        let data = b"file contents";
        let manifest = build_manifest(&key, "1.0.0", &[("f.dll", data)]);
        let inner = manifest.decode_inner().unwrap();
        assert!(
            inner.files[0]
                .verify(data, &SigningKey::generate(&mut OsRng).verifying_key())
                .is_err()
        );
    }

    #[test]
    fn test_validate_ok() {
        let key = SigningKey::generate(&mut OsRng);
        build_manifest(&key, "1.0.0", &[("a.dll", b"data")])
            .validate()
            .unwrap();
    }

    #[test]
    fn test_validate_rejects_path_traversal() {
        let key = SigningKey::generate(&mut OsRng);
        let mut manifest = build_manifest(&key, "1.0.0", &[("a.dll", b"data")]);
        let mut inner = manifest.decode_inner().unwrap();
        inner.files[0].install_path = "../evil.dll".into();
        manifest.payload = OpaquePayload::encode_from(&inner);
        assert!(manifest.validate().is_err());
    }

    #[test]
    fn test_validate_rejects_duplicate_install_paths() {
        let key = SigningKey::generate(&mut OsRng);
        let mut manifest = build_manifest(&key, "1.0.0", &[("a.dll", b"data"), ("b.dll", b"data")]);
        let mut inner = manifest.decode_inner().unwrap();
        inner.files[1].install_path = "a.dll".into();
        manifest.payload = OpaquePayload::encode_from(&inner);
        assert!(manifest.validate().is_err());
    }

    #[test]
    fn test_validate_rejects_duplicate_asset_names() {
        let key = SigningKey::generate(&mut OsRng);
        assert!(
            build_manifest(&key, "1.0.0", &[("a.dll", b"data"), ("a.dll", b"data")])
                .validate()
                .is_err()
        );
    }

    #[test]
    fn test_is_safe_path_component_rejects_reserved_names() {
        for name in &["con", "NUL", "COM1", "lpt9", "AUX", "prn"] {
            assert!(
                !ReleaseManifest::is_safe_path_component(name),
                "{name} should be rejected"
            );
            let with_ext = format!("{name}.dll");
            assert!(
                !ReleaseManifest::is_safe_path_component(&with_ext),
                "{with_ext} should be rejected"
            );
        }
    }

    #[test]
    fn test_is_safe_path_component_rejects_trailing_dot_and_space() {
        assert!(!ReleaseManifest::is_safe_path_component("file."));
        assert!(!ReleaseManifest::is_safe_path_component("file "));
    }

    #[test]
    fn test_is_safe_path_component_allows_valid_names() {
        for name in &["foo.dll", "my-mod_v2.bin", "data.pak"] {
            assert!(
                ReleaseManifest::is_safe_path_component(name),
                "{name} should be allowed"
            );
        }
    }
}
