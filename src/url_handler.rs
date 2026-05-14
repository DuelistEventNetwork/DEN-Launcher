use windows::{
    Win32::{
        Foundation::{CloseHandle, GENERIC_WRITE},
        Storage::FileSystem::{
            CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_NONE, OPEN_EXISTING, WriteFile,
        },
        System::Registry::HKEY_CURRENT_USER,
    },
    core::PCWSTR,
};

use crate::{
    constants::{IPC_PIPE_NAME, LAUNCHER_NAME, URL_SCHEME},
    launcher_error::LauncherError,
    util::{reg_read, reg_write, wstr},
};

pub fn set_payload_env(url: &str) {
    unsafe { std::env::set_var("BMP_URL", url) };
}

pub fn try_send_to_running_game(payload: &str) -> Result<bool, LauncherError> {
    let pipe_name = wstr(IPC_PIPE_NAME);

    let handle = match unsafe {
        CreateFileW(
            PCWSTR(pipe_name.as_ptr()),
            GENERIC_WRITE.0,
            FILE_SHARE_NONE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
    } {
        Ok(handle) => handle,
        Err(_) => return Ok(false),
    };

    let payload_bytes = payload.as_bytes();
    let mut written = 0;

    let result = unsafe { WriteFile(handle, Some(payload_bytes), Some(&mut written), None) };

    unsafe {
        CloseHandle(handle)?;
    }

    result.map_err(LauncherError::Windows)?;

    tracing::debug!("Sent {written} bytes to running game via IPC pipe");
    Ok(true)
}

pub fn try_register_url_scheme(launcher_exe: &str) -> Result<(), LauncherError> {
    let base_key = format!(r"Software\Classes\{URL_SCHEME}");
    let command_key = format!(r"{base_key}\shell\open\command");
    let expected_command = format!("\"{launcher_exe}\" \"%1\"");

    if reg_read(HKEY_CURRENT_USER, &base_key, "").is_ok_and(|en| en == LAUNCHER_NAME)
        && reg_read(HKEY_CURRENT_USER, &command_key, "").is_ok_and(|ec| ec == expected_command)
    {
        tracing::debug!("URL scheme registration is up to date");
        return Ok(());
    }

    reg_write(HKEY_CURRENT_USER, &base_key, "", LAUNCHER_NAME)?;
    reg_write(HKEY_CURRENT_USER, &base_key, "URL Protocol", "")?;
    reg_write(HKEY_CURRENT_USER, &command_key, "", &expected_command)?;

    tracing::debug!(
        "Registered {}:// URL scheme to {}",
        URL_SCHEME,
        launcher_exe
    );

    Ok(())
}
