use std::path::Path;

#[cfg(feature = "migrations")]
pub fn run(exe_dir: &Path) {
    legacy_cleanup(exe_dir);
}

#[cfg(not(feature = "migrations"))]
pub fn run(_exe_dir: &Path) {}

#[cfg(feature = "migrations")]
fn legacy_cleanup(exe_dir: &Path) {
    let current_exe = std::env::current_exe().ok();

    let legacy_exe = exe_dir.join("DEN-Launcher.exe");
    if legacy_exe.exists()
        && current_exe
            .as_ref()
            .map(|p| p.as_path() != legacy_exe.as_path())
            .unwrap_or(true)
    {
        std::fs::remove_file(&legacy_exe)
            .map_err(|e| tracing::warn!("Failed to remove legacy exe at {:?}: {}", legacy_exe, e))
            .ok();
    }

    let legacy_data_dir = exe_dir.join("DENData");
    if legacy_data_dir.exists() {
        std::fs::remove_dir_all(&legacy_data_dir)
            .map_err(|e| {
                tracing::warn!(
                    "Failed to remove legacy data dir at {:?}: {}",
                    legacy_data_dir,
                    e
                )
            })
            .ok();
    }
}
