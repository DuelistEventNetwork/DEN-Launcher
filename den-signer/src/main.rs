use clap::{Parser, Subcommand};
use den_signer::{ManifestFile, ManifestInner, ReleaseManifest};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use std::path::{Path, PathBuf};

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
        /// Files to sign, each as `asset_name:install_path`
        #[arg(required = true)]
        files: Vec<String>,
    },
    /// Verify a manifest.bin and all referenced files
    Verify {
        #[arg(long)]
        public_key: PathBuf,
        manifest: PathBuf,
    },
}

fn load_signing_key(path: &Path) -> Result<SigningKey, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("Failed to read private key: {e}"))?;
    match bytes.len() {
        32 => Ok(SigningKey::from_bytes(&bytes.try_into().unwrap())),
        64 => SigningKey::from_keypair_bytes(&bytes.try_into().unwrap())
            .map_err(|e| format!("Invalid keypair bytes: {e}")),
        n => Err(format!(
            "Unexpected private key length: {n} bytes (expected 32 or 64)"
        )),
    }
}

fn load_verifying_key(path: &Path) -> Result<VerifyingKey, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("Failed to read public key: {e}"))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "Public key must be exactly 32 bytes".to_string())?;
    VerifyingKey::from_bytes(&arr).map_err(|e| format!("Invalid public key: {e}"))
}

fn cmd_generate_keys(private_key: &Path, public_key: &Path) -> Result<(), String> {
    let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
    let verifying_key = signing_key.verifying_key();
    std::fs::write(private_key, signing_key.to_keypair_bytes())
        .map_err(|e| format!("Failed to write private key: {e}"))?;
    std::fs::write(public_key, verifying_key.to_bytes())
        .map_err(|e| format!("Failed to write public key: {e}"))?;
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
) -> Result<(), String> {
    let signing_key = load_signing_key(private_key)?;
    let mut manifest_files: Vec<ManifestFile> = Vec::new();

    for spec in files {
        let (name, install_path) = spec.split_once(':').ok_or_else(|| {
            format!("Invalid file spec {spec:?}: expected 'asset_name:install_path'")
        })?;

        let data = std::fs::read(name).map_err(|e| format!("Failed to read {name}: {e}"))?;
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
    let manifest_sig: Signature = signing_key.sign(&bitcode::encode(&inner));
    let manifest = ReleaseManifest {
        inner,
        sig: manifest_sig.to_bytes(),
    };

    manifest.validate()?;
    std::fs::write(output, bitcode::encode(&manifest))
        .map_err(|e| format!("Failed to write manifest: {e}"))?;
    println!("Manifest written -> {}", output.display());
    Ok(())
}

fn cmd_verify(public_key: &Path, manifest_path: &Path) -> Result<(), String> {
    let verifying_key = load_verifying_key(public_key)?;
    let raw = std::fs::read(manifest_path).map_err(|e| format!("Failed to read manifest: {e}"))?;
    let manifest = ReleaseManifest::decode(&raw)?;

    manifest.validate()?;
    manifest.verify(&verifying_key)?;
    println!("Manifest signature OK");

    for mf in &manifest.inner.files {
        let data =
            std::fs::read(&mf.name).map_err(|e| format!("Failed to read {}: {e}", mf.name))?;
        mf.verify(&data, &verifying_key)?;
        println!("  {} OK", mf.name);
    }

    println!("All files verified successfully");
    Ok(())
}

fn run() -> Result<(), String> {
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
        } => cmd_verify(&public_key, &manifest),
    }
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
