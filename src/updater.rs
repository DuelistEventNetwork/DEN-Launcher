use std::{io::Read, path::Path};

use crate::{
    constants::ELDENRING_EXE,
    injector::{get_pids_by_name, kill_process},
};

use den_signer::{ReleaseManifest, VerifyingKey};
use serde::Deserialize;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const RELEASE_PUBLIC_KEY: &[u8] = include_bytes!("../release_public_key.bin");

#[derive(Deserialize)]
struct ReleaseAsset {
    pub url: String,
    pub name: String,
}

#[derive(Deserialize)]
struct Release {
    pub tag_name: String,
    pub assets: Vec<ReleaseAsset>,
}

fn get_verifying_key() -> VerifyingKey {
    let arr: [u8; 32] = RELEASE_PUBLIC_KEY
        .try_into()
        .expect("release_public_key.bin must be exactly 32 bytes");
    VerifyingKey::from_bytes(&arr).expect("release_public_key.bin is not a valid ed25519 key")
}

fn make_request(url: &str, token: Option<&str>) -> ureq::Request {
    let mut req = ureq::get(url).set("User-Agent", &format!("denlauncher/{VERSION}"));
    if let Some(t) = token {
        req = req.set("Authorization", &format!("token {t}"));
    }
    req
}

fn download_bytes(url: &str, token: Option<&str>) -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();
    make_request(url, token)
        .set("Accept", "application/octet-stream")
        .call()
        .map_err(|e| format!("Failed to download {url}: {e}"))?
        .into_reader()
        .read_to_end(&mut buf)
        .map_err(|e| format!("Failed to read download for {url}: {e}"))?;
    Ok(buf)
}

fn get_latest_release(repo_owner: &str, repo_name: &str, token: Option<&str>) -> Option<Release> {
    make_request(
        &format!("https://api.github.com/repos/{repo_owner}/{repo_name}/releases/latest"),
        token,
    )
    .set("Accept", "application/vnd.github+json")
    .call()
    .map_err(|e| tracing::error!("Failed to fetch release: {e}"))
    .ok()?
    .into_json::<Release>()
    .map_err(|e| tracing::error!("Failed to parse release JSON: {e}"))
    .ok()
}

fn apply_manifest(
    manifest: &ReleaseManifest,
    release: &Release,
    exe_dir: &Path,
    token: Option<&str>,
    key: &VerifyingKey,
) -> Result<(), String> {
    let current_exe =
        std::env::current_exe().map_err(|e| format!("Failed to get current exe path: {e}"))?;

    // Collect files that need (re-)downloading.
    let to_update: Vec<&den_signer::ManifestFile> = manifest
        .inner
        .files
        .iter()
        .filter(|mf| {
            let target = exe_dir.join(&mf.install_path);
            match std::fs::read(&target) {
                Ok(data) if mf.verify(&data, key).is_ok() => {
                    tracing::info!("{} is up to date", mf.name);
                    false
                }
                Ok(_) => {
                    tracing::info!("{} signature mismatch; queuing for update", mf.name);
                    true
                }
                Err(_) => {
                    tracing::info!("{} not found locally; queuing for download", mf.name);
                    true
                }
            }
        })
        .collect();

    if to_update.is_empty() {
        tracing::info!("All files are already up to date");
        return Ok(());
    }

    let mut pending = Vec::new();
    for mf in to_update {
        let asset = release
            .assets
            .iter()
            .find(|a| a.name == mf.name)
            .ok_or_else(|| format!("Asset '{}' not found in release", mf.name))?;

        tracing::info!("Downloading {}", mf.name);
        let data = download_bytes(&asset.url, token)?;
        mf.verify(&data, key)?;
        tracing::info!("{} signature OK", mf.name);

        let target = ReleaseManifest::safe_join(exe_dir, &mf.install_path)
            .ok_or_else(|| format!("Unsafe install_path in manifest: {}", mf.install_path))?;

        pending.push((mf, data, target));
    }

    for pid in get_pids_by_name(ELDENRING_EXE) {
        kill_process(pid);
    }

    let mut self_replaced = false;
    for (mf, data, target) in pending {
        if target == current_exe {
            let tmp_path = exe_dir.join(format!("_update_{}.tmp", mf.name));
            std::fs::write(&tmp_path, &data)
                .map_err(|e| format!("Failed to write launcher update temp file: {e}"))?;
            self_replace::self_replace(&tmp_path)
                .map_err(|e| format!("Failed to self-replace launcher: {e}"))?;
            let _ = std::fs::remove_file(&tmp_path);
            tracing::info!("Launcher queued for replacement");
            self_replaced = true;
        } else {
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    format!(
                        "Failed to create target directory {}: {e}",
                        parent.display()
                    )
                })?;
            }
            std::fs::write(&target, &data)
                .map_err(|e| format!("Failed to write updated file {}: {e}", target.display()))?;
            tracing::info!("Updated {}", target.display());
        }
    }

    if self_replaced {
        tracing::warn!("Launcher was updated; please restart to apply changes");
        std::thread::sleep(std::time::Duration::from_secs(5));
        std::process::exit(0);
    }

    tracing::info!("Update complete");
    Ok(())
}

pub fn start_updater(repo_owner: &str, repo_name: &str, token: Option<&str>) {
    let Some(release) = get_latest_release(repo_owner, repo_name, token) else {
        tracing::warn!("Failed to fetch latest release info");
        return;
    };

    let Some(manifest_asset) = release.assets.iter().find(|a| a.name == "manifest.bin") else {
        tracing::warn!("No manifest.bin in release assets; skipping update");
        return;
    };

    tracing::info!(
        "Checking release {} for updates",
        release.tag_name.trim_start_matches('v')
    );
    let manifest_bytes = match download_bytes(&manifest_asset.url, token) {
        Ok(bytes) => bytes,
        Err(err) => {
            tracing::error!("Failed to download manifest.bin: {}", err);
            return;
        }
    };
    let manifest = match ReleaseManifest::decode(&manifest_bytes) {
        Ok(m) => m,
        Err(e) => {
            tracing::error!("Failed to decode manifest: {e}");
            return;
        }
    };

    let verifying_key = get_verifying_key();

    if let Err(e) = manifest.validate() {
        tracing::error!("Manifest validation failed: {e}");
        return;
    }

    if let Err(e) = manifest.verify(&verifying_key) {
        tracing::error!("Manifest signature invalid: {e}");
        return;
    }

    let current_exe = match std::env::current_exe() {
        Ok(path) => path,
        Err(err) => {
            tracing::error!("Failed to get current exe: {}", err);
            return;
        }
    };
    let exe_dir = match current_exe.parent() {
        Some(dir) => dir,
        None => {
            tracing::error!("Failed to get exe dir");
            return;
        }
    };

    if let Err(err) = apply_manifest(&manifest, &release, exe_dir, token, &verifying_key) {
        tracing::error!("Update failed: {}", err);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fetch_and_verify_real_manifest() {
        let _ = dotenvy::dotenv_override(); // ignore error when .env is absent

        let owner = match std::env::var("DEN_REPO_OWNER") {
            Ok(v) => v,
            Err(_) => {
                eprintln!("DEN_REPO_OWNER not set, skipping online manifest test");
                return;
            }
        };
        let name = match std::env::var("DEN_REPO_NAME") {
            Ok(v) => v,
            Err(_) => {
                eprintln!("DEN_REPO_NAME not set skipping online manifest test");
                return;
            }
        };
        let token = std::env::var("DEN_REPO_TOKEN").ok();
        assert!(
            !owner.is_empty() && !name.is_empty(),
            "DEN_REPO_OWNER and DEN_REPO_NAME must be set for this test"
        );

        let release = match get_latest_release(&owner, &name, token.as_deref()) {
            Some(r) => r,
            None => {
                eprintln!("Failed to fetch release - skipping online manifest test");
                return;
            }
        };

        let manifest_asset = release
            .assets
            .iter()
            .find(|a| a.name == "manifest.bin")
            .expect("manifest.bin not found in release assets");

        let bytes = download_bytes(&manifest_asset.url, token.as_deref())
            .expect("failed to download manifest.bin");
        let manifest = ReleaseManifest::decode(&bytes).expect("failed to decode manifest");

        let key = get_verifying_key();
        manifest.validate().expect("manifest validation failed");
        manifest.verify(&key).expect("manifest signature invalid");

        assert!(
            !manifest.inner.version.is_empty(),
            "version must not be empty"
        );
        assert!(
            !manifest.inner.files.is_empty(),
            "manifest must list at least one file"
        );
        for mf in &manifest.inner.files {
            assert!(!mf.name.is_empty(), "file name must not be empty");
            assert!(
                !mf.install_path.is_empty(),
                "install_path must not be empty"
            );
        }

        eprintln!(
            "OK  manifest v{}  ({} file(s))",
            manifest.inner.version,
            manifest.inner.files.len()
        );
    }
}
