use std::{
    convert::TryInto,
    io::{Read, Seek, Write},
};

use crate::{
    constants::ELDENRING_EXE,
    injector::{get_pids_by_name, kill_process},
};

use semver::Version;
use serde::Deserialize;
use walkdir::WalkDir;
use zip::ZipArchive;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const RELEASE_PUBLIC_KEY: &[u8] = include_bytes!("../release_public_key.bin");

#[derive(Deserialize, Clone)]
struct ReleaseAsset {
    pub url: String,
    pub name: String,
}

#[derive(Deserialize, Clone)]
struct Release {
    pub tag_name: String,
    pub assets: Vec<ReleaseAsset>,
}

pub fn bump_is_greater(current: &str, other: &str) -> Option<bool> {
    Some(Version::parse(other).ok()? > Version::parse(current).ok()?)
}

fn get_update(
    repo_owner: &str,
    repo_name: &str,
    repo_private_key: Option<&str>,
) -> Option<Release> {
    let mut request = ureq::get(&format!(
        "https://api.github.com/repos/{}/{}/releases",
        repo_owner, repo_name
    ))
    .set("User-Agent", &format!("denlauncher/{}", VERSION))
    .query("per_page", "20");

    if let Some(token) = repo_private_key {
        request = request.set("Authorization", &format!("token {}", token));
    }

    let response = request
        .call()
        .map_err(|e| {
            tracing::error!("Failed to fetch releases: {}", e);
            e
        })
        .ok()?
        .into_json::<Vec<Release>>()
        .map_err(|e| {
            tracing::error!("Failed to parse JSON: {}", e);
            e
        })
        .ok()?;

    response
        .into_iter()
        .find(|r| bump_is_greater(VERSION, r.tag_name.trim_start_matches("v")).unwrap_or(false))
}

// #[cfg(not(debug_assertions))]
fn verify_signature(
    archive: &mut std::fs::File,
    context: &[u8],
    keys: &[[u8; zipsign_api::PUBLIC_KEY_LENGTH]],
) -> Result<(), zipsign_api::ZipsignError> {
    if keys.is_empty() {
        return Ok(());
    }

    tracing::info!("Verifying signature of update archive");

    let keys = keys.iter().copied().map(Ok);
    let keys = zipsign_api::verify::collect_keys(keys).map_err(zipsign_api::ZipsignError::from)?;

    zipsign_api::verify::verify_zip(archive, &keys, Some(context))
        .map_err(zipsign_api::ZipsignError::from)?;
    Ok(())
}

fn update_from_asset(
    asset: &ReleaseAsset,
    content_dir: &str,
    dll_name: &str,
    repo_private_key: Option<&str>,
) {
    for pid in get_pids_by_name(ELDENRING_EXE) {
        kill_process(pid);
    }

    let (exe_dir, content_dir, dll_path) = get_paths(content_dir, dll_name);
    let (mut tmp_archive, tmp_dir) = download_asset(asset, repo_private_key);
    remove_old_content(&content_dir, &dll_path);
    extract_archive(&mut tmp_archive, &tmp_dir);
    perform_binary_replacement(&tmp_dir, exe_dir);
}

fn get_paths(
    content_dir: &str,
    dll_name: &str,
) -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
    let current_exe = std::env::current_exe().unwrap();
    let exe_dir = current_exe.parent().unwrap().to_path_buf();
    let content_dir = exe_dir.join(content_dir);
    let dll_path = content_dir.join(dll_name);
    (exe_dir, content_dir, dll_path)
}

fn download_asset(
    asset: &ReleaseAsset,
    repo_private_key: Option<&str>,
) -> (std::fs::File, tempfile::TempDir) {
    let tmp_archive_dir = tempfile::TempDir::new().expect("Failed to create temp dir");
    let mut tmp_archive_file = tempfile::tempfile().expect("Failed to create temp file");

    tracing::info!("Downloading archive: {}", asset.url);

    let mut request = ureq::get(&asset.url)
        .set(
            "User-Agent",
            &format!("denlauncher/{}", env!("CARGO_PKG_VERSION")),
        )
        .set("Accept", "application/octet-stream");
    if let Some(token) = repo_private_key {
        request = request.set("Authorization", &format!("token {}", token));
    }
    let mut buf = Vec::new();
    let response = request.call().expect("Failed to download archive");

    if response.status() != 200 {
        panic!("Failed to download archive: HTTP {}", response.status());
    }

    response
        .into_reader()
        .read_to_end(&mut buf)
        .expect("Failed to read archive content");

    tmp_archive_file
        .write_all(&buf)
        .expect("Failed to write to temp file");

    // Rewind the file cursor to the beginning before verifying the signature
    tmp_archive_file
        .seek(std::io::SeekFrom::Start(0))
        .expect("Failed to seek to start of temp file");

    tracing::info!("Downloaded archive: {:?}", tmp_archive_file);

    let mut public_keys: Vec<[u8; zipsign_api::PUBLIC_KEY_LENGTH]> = Vec::new();
    match RELEASE_PUBLIC_KEY.try_into() {
        Ok(key) => public_keys.push(key),
        Err(_) =>
        {
            #[allow(clippy::const_is_empty)]
            if !RELEASE_PUBLIC_KEY.is_empty() {
                tracing::warn!(
                    "release_public_key.bin has unexpected size ({} bytes); signature verification disabled",
                    RELEASE_PUBLIC_KEY.len()
                );
            }
        }
    }

    verify_signature(&mut tmp_archive_file, asset.name.as_bytes(), &public_keys)
        .expect("Failed to verify update archive signature");

    tmp_archive_file
        .seek(std::io::SeekFrom::Start(0))
        .expect("Failed to seek to start of verified temp file");

    (tmp_archive_file, tmp_archive_dir)
}

fn extract_archive(tmp_archive: &mut std::fs::File, temp_dir: &tempfile::TempDir) {
    tracing::debug!("Extracting archive to: {:?}", tmp_archive);

    tmp_archive
        .seek(std::io::SeekFrom::Start(0))
        .expect("Failed to seek to start of archive before extraction");

    ZipArchive::new(tmp_archive)
        .expect("Failed to open archive")
        .extract(temp_dir)
        .expect("Failed to extract archive");
}

fn remove_old_content(content_dir: &std::path::Path, dll_path: &std::path::Path) {
    tracing::info!("Removing old content");

    std::fs::remove_file(dll_path)
        .map_err(|e| tracing::warn!("Failed to remove old DLL at {:?}: {}", dll_path, e))
        .ok();

    let content_is_empty = std::fs::read_dir(content_dir)
        .map(|mut dir| dir.next().is_none())
        .unwrap_or(false);
    if content_is_empty {
        std::fs::remove_dir(content_dir)
            .map_err(|e| {
                tracing::warn!(
                    "Failed to remove old content dir at {:?}: {}",
                    content_dir,
                    e
                )
            })
            .ok();
    }
}

fn perform_binary_replacement(tmp_dir: &tempfile::TempDir, exe_dir: std::path::PathBuf) {
    let mut new_exe_path: Option<std::path::PathBuf> = None;

    for entry in WalkDir::new(tmp_dir).into_iter().filter_map(Result::ok) {
        let path = entry.path();
        let relative_path = path.strip_prefix(tmp_dir).expect("Failed to strip prefix");
        let target_path = exe_dir.join(relative_path);

        if entry.file_type().is_file() {
            if let Some(path) = handle_file_entry(entry, &target_path) {
                new_exe_path = Some(path);
            }
        } else if entry.file_type().is_dir() {
            std::fs::create_dir_all(&target_path).expect("Failed to create directory");
        }
    }

    if let Some(new_exe_path) = new_exe_path {
        tracing::info!("Replacing binary with new version");
        self_replace::self_replace(new_exe_path).expect("Failed to replace binary");
    } else {
        self_replace::self_delete().expect("Failed to delete updater");
    }
}

fn handle_file_entry(
    entry: walkdir::DirEntry,
    target_path: &std::path::PathBuf,
) -> Option<std::path::PathBuf> {
    // returns path if it's the current exe, otherwise copies the file
    if entry.file_name()
        == std::env::current_exe()
            .expect("Failed to get current exe name")
            .file_name()
            .unwrap()
    {
        Some(entry.path().to_path_buf())
    } else {
        std::fs::copy(entry.path(), target_path).expect("Failed to copy file");
        None
    }
}

pub fn start_updater(
    repo_owner: &str,
    repo_name: &str,
    repo_private_key: Option<&str>,
    content_dir: &str,
    dll_name: &str,
) {
    if let Some(release) = get_update(repo_owner, repo_name, repo_private_key) {
        tracing::info!(
            "Found new release: {}",
            release.tag_name.trim_start_matches("v")
        );

        if let Some(asset) = release
            .assets
            .iter()
            .find(|asset| asset.name.ends_with(".zip"))
        {
            update_from_asset(asset, content_dir, dll_name, repo_private_key);
        }
        tracing::info!("Update complete, please restart the launcher");
        std::thread::sleep(std::time::Duration::from_secs(5));
        std::process::exit(0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bump_is_greater() {
        assert_eq!(bump_is_greater("1.0.0", "1.0.1"), Some(true));
        assert_eq!(bump_is_greater("1.0.1", "1.0.0"), Some(false));
        assert_eq!(bump_is_greater("1.0.0", "1.0.0"), Some(false));
        assert_eq!(bump_is_greater("1.0.0", "invalid"), None);
        assert_eq!(bump_is_greater("invalid", "1.0.0"), None);
        assert_eq!(
            bump_is_greater("2.0.0-beta.10", "2.0.0-beta.9"),
            Some(false)
        );
        assert_eq!(bump_is_greater("2.0.0-beta9", "2.0.0-beta.10"), Some(false));
        assert_eq!(
            bump_is_greater("2.0.0-rc.1", "2.0.0-rc.1+patch.1"),
            Some(true)
        );
    }
}
