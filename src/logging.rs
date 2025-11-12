use tracing_panic::panic_hook;
use tracing_subscriber::{self, layer::SubscriberExt, util::SubscriberInitExt, Layer};
use windows::core::Result;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Console::GetConsoleMode;
use windows::Win32::System::Console::GetStdHandle;
use windows::Win32::System::Console::SetConsoleMode;
use windows::Win32::System::Console::ENABLE_VIRTUAL_TERMINAL_PROCESSING;
use windows::Win32::System::Console::STD_OUTPUT_HANDLE;

pub fn enable_ansi_support() -> Result<()> {
    unsafe {
        let handle = GetStdHandle(STD_OUTPUT_HANDLE)?;
        if handle == HANDLE::default() {
            return Err(windows::core::Error::from_win32());
        }

        let mut mode = std::mem::zeroed();
        GetConsoleMode(handle, &mut mode)?;
        SetConsoleMode(handle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING)?;
        Ok(())
    }
}

pub fn den_panic_hook(panic_info: &std::panic::PanicHookInfo) {
    let message;
    let title = "Den-Launcher Error";
    let reason = if let Some(s) = panic_info.payload().downcast_ref::<&str>() {
        *s
    } else if let Some(s) = panic_info.payload().downcast_ref::<String>() {
        s.as_str()
    } else {
        "Unknown"
    };
    if let Some(location) = panic_info.location() {
        message = format!(
            "A panic occurred at {}:{}\nReason: {}",
            location.file(),
            location.line(),
            reason
        );
    } else {
        message = format!("A panic occurred\nReason: {reason}");
    }

    let mut message_utf16: Vec<u16> = message.encode_utf16().collect();
    message_utf16.push(0);
    let mut title_utf16: Vec<u16> = title.encode_utf16().collect();
    title_utf16.push(0);

    unsafe {
        windows::Win32::UI::WindowsAndMessaging::MessageBoxW(
            None,
            windows::core::PCWSTR(message_utf16.as_ptr()),
            windows::core::PCWSTR(title_utf16.as_ptr()),
            windows::Win32::UI::WindowsAndMessaging::MB_ICONERROR,
        );
    }
    panic_hook(panic_info);
    std::thread::sleep(std::time::Duration::from_secs(10));
}

pub fn setup_logging(debug: bool) {
    let stdout_log = tracing_subscriber::fmt::layer()
        .pretty()
        .without_time()
        .with_file(false)
        .with_line_number(false)
        // disable module path
        .with_target(false);

    let filter =
        tracing_subscriber::filter::EnvFilter::from_default_env().add_directive(if debug {
            tracing_subscriber::filter::LevelFilter::DEBUG.into()
        } else {
            tracing_subscriber::filter::LevelFilter::INFO.into()
        });
    let registry = tracing_subscriber::registry().with(stdout_log.with_filter(filter));
    if debug {
        let appender = tracing_appender::rolling::never("./", "denlauncher.log");
        let file_log = tracing_subscriber::fmt::layer()
            .with_writer(appender)
            .with_ansi(false);
        registry.with(file_log).init();
    } else {
        registry.init();
    }
}
