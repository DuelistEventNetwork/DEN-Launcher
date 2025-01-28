use windows::Win32::Foundation::{CloseHandle, HANDLE};

use std::ffi::c_void;
use std::path::{Path, PathBuf};
use steamlocate::SteamDir;
use windows::core::{PCSTR, PCWSTR, PSTR};
use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use windows::Win32::System::Memory::{
    VirtualAllocEx, VirtualFreeEx, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE,
};
use windows::Win32::System::Threading::{
    CreateProcessA, CreateRemoteThread, GetExitCodeThread, OpenProcess, TerminateProcess,
    WaitForSingleObject, CREATE_NEW_PROCESS_GROUP, CREATE_SUSPENDED, INFINITE, PROCESS_INFORMATION,
    STARTUPINFOA,
};

use crate::constants::{
    CONTENT_DIR, DLL_NAME, ELDENRING_EXE, ELDENRING_ID, PROCESS_INJECTION_ACCESS,
};

fn locate_executable() -> PathBuf {
    let steam_dir = SteamDir::locate().expect("Failed to locate Steam directory");
    let (app, lib) = steam_dir
        .find_app(ELDENRING_ID)
        .ok()
        .flatten()
        .expect("Failed to locate Elden Ring");
    lib.resolve_app_dir(&app).join("Game").join(ELDENRING_EXE)
}

fn open_process_by_pid(pid: u32) -> Option<HANDLE> {
    unsafe {
        OpenProcess(
            // access required for performing dll injection
            *PROCESS_INJECTION_ACCESS,
            false,
            pid,
        )
    }
    .ok()
}

fn kill_process(pid: u32) {
    open_process_by_pid(pid).and_then(|handle| {
        unsafe { TerminateProcess(handle, 1) }
            .map_err(|err| tracing::error!("Failed to terminate process: {:?}", err))
            .ok()
    });
}

fn get_pids_by_name(name: &str) -> Vec<u32> {
    let mut system = sysinfo::System::new();
    system.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
    system
        .processes()
        .values()
        .filter(move |process| process.name().to_str().is_some_and(|n| n.contains(name)))
        .map(|process| process.pid().as_u32())
        .collect()
}

pub fn start_game() -> Result<(), Box<dyn std::error::Error>> {
    // Kill existing processes
    for pid in get_pids_by_name(ELDENRING_EXE) {
        kill_process(pid);
    }

    // Setup paths
    let executable_path = locate_executable();
    let current_exe = std::env::current_exe()?;
    let parent_dir = current_exe
        .parent()
        .ok_or("Failed to get current executable dir path")?;
    let dll_path = parent_dir.join(&*CONTENT_DIR).join(&*DLL_NAME);

    tracing::info!("Injecting DLL: {:?}", dll_path);

    if !dll_path.exists() {
        return Err("DLL not found".into());
    }

    // Set Steam App ID
    std::env::set_var("SteamAppId", ELDENRING_ID.to_string());
    // Set Content Dir
    std::env::set_var("DEN_CONTENT_DIR", parent_dir.join(&*CONTENT_DIR));

    // Create process
    let process_info = create_suspended_process(&executable_path)?;

    // Inject DLL
    inject_dll(&process_info, &dll_path)?;

    // Resume process
    unsafe { windows::Win32::System::Threading::ResumeThread(process_info.hThread) };

    Ok(())
}

fn create_suspended_process(
    executable_path: &Path,
) -> Result<PROCESS_INFORMATION, Box<dyn std::error::Error>> {
    let exe_path_cstr = std::ffi::CString::new(executable_path.to_str().ok_or("Invalid path")?)?;

    let mut startup_info = STARTUPINFOA::default();
    let mut process_info = PROCESS_INFORMATION::default();

    let cwd = executable_path.parent().ok_or("Invalid executable path")?;
    std::env::set_current_dir(cwd)?;

    unsafe {
        CreateProcessA(
            PCSTR(exe_path_cstr.as_ptr() as *const u8),
            PSTR::null(),
            None,
            None,
            false,
            CREATE_SUSPENDED | CREATE_NEW_PROCESS_GROUP,
            None,
            None,
            &mut startup_info,
            &mut process_info,
        )
    }?;

    Ok(process_info)
}

fn inject_dll(
    process_info: &PROCESS_INFORMATION,
    dll_path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let dll_path_str = dll_path.to_str().ok_or("Invalid path")?;
    let wide_path: Vec<u16> = dll_path_str
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let pcwstr = PCWSTR::from_raw(wide_path.as_ptr());
    let buffer_size = (wide_path.len()) * std::mem::size_of::<u16>();

    let str_addr = unsafe {
        VirtualAllocEx(
            process_info.hProcess,
            None,
            buffer_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    };

    if str_addr.is_null() {
        return Err("Failed to allocate memory in target process".into());
    }

    let mut bytes_written: usize = 0;
    unsafe {
        WriteProcessMemory(
            process_info.hProcess,
            str_addr,
            pcwstr.as_ptr() as *const c_void,
            buffer_size,
            Some(&mut bytes_written as *mut usize),
        )?;
    }

    tracing::info!(
        "Wrote DLL path to target process memory, bytes written: {}",
        bytes_written
    );

    let kernel32 = unsafe { GetModuleHandleA(PCSTR("kernel32.dll\0".as_ptr()))? };
    let load_library = unsafe {
        GetProcAddress(kernel32, PCSTR("LoadLibraryW\0".as_ptr()))
            .ok_or("Failed to get LoadLibraryW address")
    }? as *const ();

    unsafe {
        let thread_handle = CreateRemoteThread(
            process_info.hProcess,
            None,
            0,
            Some(std::mem::transmute(load_library)),
            Some(str_addr),
            0,
            None,
        )?;

        tracing::info!("DLL injected, waiting for thread completion");
        WaitForSingleObject(thread_handle, INFINITE);

        VirtualFreeEx(process_info.hProcess, str_addr, 0, MEM_RELEASE)?;

        let mut base_address: u32 = 0;
        GetExitCodeThread(thread_handle, &mut base_address as *mut u32)?;

        if base_address == 0 {
            return Err("DLL injection failed - LoadLibraryW returned NULL".into());
        }

        tracing::info!("DLL successfully loaded at: {:#016x}", base_address);
        CloseHandle(thread_handle)?;
    }

    Ok(())
}
