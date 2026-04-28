use std::path::PathBuf;

use windows::{Win32::System::Registry::HKEY_LOCAL_MACHINE, core::PCWSTR};

use crate::constants::ELDENRING_ID;
use crate::launcher_error::LauncherError;

pub fn locate_steam_game(game_executable: &str) -> Result<PathBuf, LauncherError> {
    let steam_path = reg_read_sz(
        HKEY_LOCAL_MACHINE,
        "SOFTWARE\\WOW6432Node\\Valve\\Steam",
        "InstallPath",
    )?;

    let vdf_path = PathBuf::from(&steam_path)
        .join("steamapps")
        .join("libraryfolders.vdf");

    let vdf = std::fs::read_to_string(&vdf_path)?;

    for library in parse_library_paths(&vdf) {
        let manifest = library
            .join("steamapps")
            .join(format!("appmanifest_{ELDENRING_ID}.acf"));

        if manifest.exists() {
            let game = library
                .join("steamapps")
                .join("common")
                .join("ELDEN RING")
                .join("Game")
                .join(game_executable);

            if game.exists() {
                return Ok(game);
            }
        }
    }

    Err(LauncherError::GameNotFound(
        "Elden Ring was not found in your Steam library. Please verify the game is installed and Steam has the correct library path.".into(),
    ))
}

fn parse_library_paths(vdf: &str) -> Vec<PathBuf> {
    vdf.lines()
        .filter_map(|line| {
            let line = line.trim();
            if !line.starts_with(r#""path""#) {
                return None;
            }
            let after = line[6..].trim().trim_matches('"');
            Some(PathBuf::from(after.replace("\\\\", "\\")))
        })
        .collect()
}

fn reg_read_sz(
    root: windows::Win32::System::Registry::HKEY,
    subkey: &str,
    value: &str,
) -> Result<String, LauncherError> {
    use windows::Win32::System::Registry::*;
    unsafe {
        let subkey_wide: Vec<u16> = subkey.encode_utf16().chain(std::iter::once(0)).collect();
        let value_wide: Vec<u16> = value.encode_utf16().chain(std::iter::once(0)).collect();
        let mut hkey = HKEY::default();
        RegOpenKeyExW(
            root,
            PCWSTR(subkey_wide.as_ptr()),
            None,
            KEY_READ,
            &mut hkey,
        )
        .ok()
        .map_err(|e| LauncherError::SteamNotFound(format!("Registry open failed: {e}")))?;
        let mut size = 0u32;
        let mut kind = REG_SZ;
        RegQueryValueExW(
            hkey,
            PCWSTR(value_wide.as_ptr()),
            None,
            Some(&mut kind),
            None,
            Some(&mut size),
        )
        .ok()
        .map_err(|e| LauncherError::SteamNotFound(format!("Registry query size failed: {e}")))?;
        let mut buf = vec![0u16; size as usize / 2];
        RegQueryValueExW(
            hkey,
            PCWSTR(value_wide.as_ptr()),
            None,
            Some(&mut kind),
            Some(buf.as_mut_ptr() as *mut u8),
            Some(&mut size),
        )
        .ok()
        .map_err(|e| LauncherError::SteamNotFound(format!("Registry query value failed: {e}")))?;
        buf.truncate(buf.iter().position(|&c| c == 0).unwrap_or(buf.len()));
        Ok(String::from_utf16_lossy(&buf))
    }
}
