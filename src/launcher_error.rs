use thiserror::Error;

use den_signer::SignerError;
use windows::core::Error as WindowsError;

#[derive(Error, Debug)]
pub enum LauncherError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("HTTP request failed for {url}: {source}")]
    Download {
        url: String,
        #[source]
        source: Box<ureq::Error>,
    },

    #[error("failed to parse release JSON: {0}")]
    ReleaseJson(#[from] serde_json::Error),

    #[error("asset not found in release: {0}")]
    ReleaseAssetMissing(String),

    #[error("unsafe install path in manifest: {0}")]
    UnsafeInstallPath(String),

    #[error("manifest error: {0}")]
    Manifest(#[from] SignerError),

    #[error("windows API error: {0}")]
    Windows(#[from] WindowsError),

    #[error("invalid string: {0}")]
    InvalidString(#[from] std::ffi::NulError),

    #[error("invalid path: {0}")]
    InvalidPath(String),

    #[error("{0}")]
    Other(String),

    #[error("Steam not found: {0}")]
    SteamNotFound(String),

    #[error("game not found: {0}")]
    GameNotFound(String),

    #[error("content directory not found: {0}")]
    ContentDirMissing(String),

    #[error("DLL not found: {0}")]
    DllNotFound(String),

    #[error("unsupported launch path: {0}")]
    UnsupportedLaunchPath(String),

    #[error("suspicious DLL files found in game folder")]
    ModsDetected,

    #[error("DLL injection failed: {0}")]
    InjectionFailed(String),

    #[error("self-update failed: {0}")]
    SelfReplaceFailed(String),

    #[error("restart required to complete update")]
    RestartRequired,
}

impl From<String> for LauncherError {
    fn from(value: String) -> Self {
        LauncherError::Other(value)
    }
}

impl From<&str> for LauncherError {
    fn from(value: &str) -> Self {
        LauncherError::Other(value.to_string())
    }
}
