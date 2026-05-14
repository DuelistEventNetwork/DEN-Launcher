use std::{ffi::c_void, mem, ptr};

use windows::{
    Win32::{
        Foundation::GetLastError,
        Networking::WinHttp::{
            URL_COMPONENTS, WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_FLAG_SECURE,
            WINHTTP_INTERNET_SCHEME_HTTPS, WINHTTP_OPEN_REQUEST_FLAGS, WINHTTP_QUERY_FLAG_NUMBER,
            WINHTTP_QUERY_STATUS_CODE, WinHttpCloseHandle, WinHttpConnect, WinHttpCrackUrl,
            WinHttpOpen, WinHttpOpenRequest, WinHttpQueryHeaders, WinHttpReadData,
            WinHttpReceiveResponse, WinHttpSendRequest,
        },
    },
    core::PCWSTR,
};

use crate::{constants::VERSION, launcher_error::LauncherError, util::wstr};

fn last_os_err(context: &str) -> LauncherError {
    LauncherError::Http(format!("{context}: {:?}", unsafe { GetLastError() }))
}

struct Handle(*mut c_void);

impl Handle {
    /// Wraps a raw WinHTTP handle, returning an error if it is null.
    fn new(raw: *mut c_void, context: &str) -> Result<Self, LauncherError> {
        if raw.is_null() {
            Err(last_os_err(context))
        } else {
            Ok(Self(raw))
        }
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                let _ = WinHttpCloseHandle(self.0);
            }
        }
    }
}

struct ParsedUrl {
    host: Vec<u16>,
    path: Vec<u16>,
    port: u16,
    is_https: bool,
}

fn parse_url(url: &str) -> Result<ParsedUrl, LauncherError> {
    let url_wide = wstr(url);

    let mut c: URL_COMPONENTS = unsafe { mem::zeroed() };
    c.dwStructSize = mem::size_of::<URL_COMPONENTS>() as u32;
    c.dwHostNameLength = 1;
    c.dwUrlPathLength = 1;

    unsafe { WinHttpCrackUrl(&url_wide, 0, &mut c) }
        .map_err(|e| LauncherError::Http(format!("Failed to parse URL \"{url}\": {e}")))?;

    if c.lpszHostName.is_null() || c.dwHostNameLength == 0 {
        return Err(LauncherError::Http(format!("No hostname in URL \"{url}\"")));
    }

    let host = unsafe { std::slice::from_raw_parts(c.lpszHostName.0, c.dwHostNameLength as usize) }
        .iter()
        .copied()
        .chain(std::iter::once(0))
        .collect();

    let path = if c.lpszUrlPath.is_null() || c.dwUrlPathLength == 0 {
        wstr("/")
    } else {
        unsafe { std::slice::from_raw_parts(c.lpszUrlPath.0, c.dwUrlPathLength as usize) }
            .iter()
            .copied()
            .chain(std::iter::once(0))
            .collect()
    };

    Ok(ParsedUrl {
        host,
        path,
        port: c.nPort,
        is_https: c.nScheme == WINHTTP_INTERNET_SCHEME_HTTPS,
    })
}

pub fn get(url: &str, headers: &[(&str, &str)]) -> Result<(u32, Vec<u8>), LauncherError> {
    let parsed = parse_url(url)?;

    let agent = wstr(&format!("denlauncher/{VERSION}"));
    let session = Handle::new(
        unsafe {
            WinHttpOpen(
                PCWSTR(agent.as_ptr()),
                WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                PCWSTR::null(),
                PCWSTR::null(),
                0,
            )
        },
        "WinHttpOpen",
    )?;

    let connect = Handle::new(
        unsafe { WinHttpConnect(session.0, PCWSTR(parsed.host.as_ptr()), parsed.port, 0) },
        "WinHttpConnect",
    )?;

    let flags = if parsed.is_https {
        WINHTTP_FLAG_SECURE
    } else {
        WINHTTP_OPEN_REQUEST_FLAGS(0)
    };
    let method = wstr("GET");
    let request = Handle::new(
        unsafe {
            WinHttpOpenRequest(
                connect.0,
                PCWSTR(method.as_ptr()),
                PCWSTR(parsed.path.as_ptr()),
                None,
                None,
                ptr::null_mut(),
                flags,
            )
        },
        "WinHttpOpenRequest",
    )?;

    let header_block: Vec<u16> = headers
        .iter()
        .flat_map(|(k, v)| format!("{k}: {v}\r\n").encode_utf16().collect::<Vec<_>>())
        .collect();
    let header_slice = (!header_block.is_empty()).then_some(header_block.as_slice());

    unsafe { WinHttpSendRequest(request.0, header_slice, None, 0, 0, 0) }
        .map_err(|e| LauncherError::Http(format!("WinHttpSendRequest: {e}")))?;

    unsafe { WinHttpReceiveResponse(request.0, ptr::null_mut()) }
        .map_err(|_| last_os_err("WinHttpReceiveResponse"))?;

    let status = read_status(request.0)?;
    let body = read_body(request.0)?;

    Ok((status, body))
}

fn read_status(request: *mut c_void) -> Result<u32, LauncherError> {
    let mut status: u32 = 0;
    let mut size = mem::size_of::<u32>() as u32;
    unsafe {
        WinHttpQueryHeaders(
            request,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            None,
            Some(&mut status as *mut _ as *mut c_void),
            &mut size,
            ptr::null_mut(),
        )
    }
    .map_err(|_| last_os_err("WinHttpQueryHeaders"))?;
    Ok(status)
}

fn read_body(request: *mut c_void) -> Result<Vec<u8>, LauncherError> {
    let mut body = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        let mut bytes_read: u32 = 0;
        unsafe {
            WinHttpReadData(
                request,
                buf.as_mut_ptr() as *mut c_void,
                buf.len() as u32,
                &mut bytes_read,
            )
        }
        .map_err(|_| last_os_err("WinHttpReadData"))?;
        if bytes_read == 0 {
            break;
        }
        body.extend_from_slice(&buf[..bytes_read as usize]);
    }
    Ok(body)
}
