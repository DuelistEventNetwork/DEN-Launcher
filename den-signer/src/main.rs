use clap::{Parser, Subcommand};
use den_signer::{ManifestFile, ManifestInner, OpaquePayload, ReleaseManifest, SignerError};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};

#[derive(Parser)]
#[command(name = "den-signer")]
struct Args {
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a new ed25519 keypair
    GenerateKeys {
        #[arg(long, default_value = "release_private_key.bin")]
        private_key: PathBuf,
        #[arg(long, default_value = "release_public_key.bin")]
        public_key: PathBuf,
    },
    /// Sign files and produce a manifest.bin
    Sign {
        #[arg(long)]
        private_key: PathBuf,
        #[arg(long)]
        version: String,
        #[arg(long, default_value = "manifest.bin")]
        output: PathBuf,
        /// Files to sign, each as `source_path:install_path`
        #[arg(required = true)]
        files: Vec<String>,
    },
    /// Verify a manifest.bin and all referenced files
    Verify {
        #[arg(long)]
        public_key: PathBuf,
        manifest: PathBuf,
        /// Paths to the signed DLLs referenced by the manifest.
        #[arg(required = true)]
        files: Vec<PathBuf>,
    },
}

fn load_signing_key(path: &Path) -> Result<SigningKey, SignerError> {
    let bytes = std::fs::read(path)?;
    match bytes.len() {
        32 => Ok(SigningKey::from_bytes(&bytes.try_into().unwrap())),
        64 => SigningKey::from_keypair_bytes(&bytes.try_into().unwrap())
            .map_err(|e| SignerError::InvalidKey(format!("Invalid keypair bytes: {e}"))),
        n => Err(SignerError::InvalidKey(format!(
            "Unexpected private key length: {n} bytes (expected 32 or 64)"
        ))),
    }
}

fn load_verifying_key(path: &Path) -> Result<VerifyingKey, SignerError> {
    let bytes = std::fs::read(path)?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| SignerError::InvalidKey("Public key must be exactly 32 bytes".into()))?;
    VerifyingKey::from_bytes(&arr)
        .map_err(|e| SignerError::InvalidKey(format!("Invalid public key: {e}")))
}

fn cmd_generate_keys(private_key: &Path, public_key: &Path) -> Result<(), SignerError> {
    let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
    let verifying_key = signing_key.verifying_key();
    std::fs::write(private_key, signing_key.to_keypair_bytes())?;
    std::fs::write(public_key, verifying_key.to_bytes())?;
    println!("Generated keypair:");
    println!("  Private key : {}", private_key.display());
    println!("  Public  key : {}", public_key.display());
    Ok(())
}

fn cmd_sign(
    private_key: &Path,
    version: String,
    output: &Path,
    files: &[String],
) -> Result<(), SignerError> {
    let signing_key = load_signing_key(private_key)?;
    let mut manifest_files: Vec<ManifestFile> = Vec::new();

    for spec in files {
        let (name, install_path) = spec.split_once(':').ok_or_else(|| {
            SignerError::Other(format!(
                "Invalid file spec {spec:?}: expected 'asset_name:install_path'"
            ))
        })?;

        let data = std::fs::read(install_path).map_err(SignerError::Io)?;
        let sig: Signature = signing_key.sign(&data);

        manifest_files.push(ManifestFile {
            name: name.to_string(),
            install_path: install_path.to_string(),
            sig: sig.to_bytes(),
        });

        println!("  signed  {name}");
    }

    let inner = ManifestInner {
        version,
        files: manifest_files,
    };
    let payload = OpaquePayload::encode_from(&inner);
    let manifest_sig: Signature = signing_key.sign(payload.bytes());
    let manifest = ReleaseManifest {
        format_version: 1,
        payload,
        sig: manifest_sig.to_bytes(),
    };

    manifest.validate()?;
    std::fs::write(output, bitcode::encode(&manifest))?;
    println!("Manifest written -> {}", output.display());
    Ok(())
}

fn cmd_verify(
    public_key: &Path,
    manifest_path: &Path,
    files: &[PathBuf],
) -> Result<(), SignerError> {
    let verifying_key = load_verifying_key(public_key)?;
    let raw = std::fs::read(manifest_path)?;
    let manifest = ReleaseManifest::decode(&raw)?;

    manifest.validate()?;
    manifest.verify(&verifying_key)?;
    println!("Manifest signature OK");

    let mut provided_files: HashMap<String, &PathBuf> = HashMap::new();
    for path in files {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| {
                SignerError::InvalidKey(format!("Invalid file path: {}", path.display()))
            })?
            .to_string();

        if provided_files.insert(name.clone(), path).is_some() {
            return Err(SignerError::Other(format!(
                "Duplicate file basename provided for verification: {}",
                name
            )));
        }
    }

    let inner = manifest.decode_inner()?;

    for mf in &inner.files {
        let file_path = provided_files.get(&mf.name).ok_or_else(|| {
            SignerError::Other(format!(
                "Missing file for manifest asset {}: provide the path to {}",
                mf.name, mf.name
            ))
        })?;

        let data = std::fs::read(file_path)?;
        mf.verify(&data, &verifying_key)?;
        println!("  {} OK ({})", mf.name, file_path.display());
    }

    println!("All files verified successfully");
    Ok(())
}

fn run() -> Result<(), SignerError> {
    match Args::parse().cmd {
        Command::GenerateKeys {
            private_key,
            public_key,
        } => cmd_generate_keys(&private_key, &public_key),
        Command::Sign {
            private_key,
            version,
            output,
            files,
        } => cmd_sign(&private_key, version, &output, &files),
        Command::Verify {
            public_key,
            manifest,
            files,
        } => cmd_verify(&public_key, &manifest, &files),
    }
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
