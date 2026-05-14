use std::path::PathBuf;

use windows::Win32::System::Registry::HKEY_LOCAL_MACHINE;

use crate::constants::ELDENRING_ID;
use crate::launcher_error::LauncherError;
use crate::util::reg_read;

pub fn locate_steam_game(game_executable: &str) -> Result<PathBuf, LauncherError> {
    let steam_path = reg_read(
        HKEY_LOCAL_MACHINE,
        "SOFTWARE\\WOW6432Node\\Valve\\Steam",
        "InstallPath",
    )
    .map_err(|e| LauncherError::SteamNotFound(e.to_string()))?;

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
