use tracing_subscriber::fmt::FmtContext;
use tracing_subscriber::fmt::format::{self, FormatEvent, FormatFields};
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::{self, Layer, layer::SubscriberExt, util::SubscriberInitExt};

use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Console::ENABLE_VIRTUAL_TERMINAL_PROCESSING;
use windows::Win32::System::Console::GetConsoleMode;
use windows::Win32::System::Console::GetStdHandle;
use windows::Win32::System::Console::STD_OUTPUT_HANDLE;
use windows::Win32::System::Console::SetConsoleMode;
use windows::core::Result;

use crate::util::wstr;

pub fn enable_ansi_support() -> Result<()> {
    unsafe {
        let handle = GetStdHandle(STD_OUTPUT_HANDLE)?;
        if handle == HANDLE::default() {
            return Err(windows::core::Error::from_thread());
        }

        let mut mode = std::mem::zeroed();
        GetConsoleMode(handle, &mut mode)?;
        SetConsoleMode(handle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING)?;
        Ok(())
    }
}

pub fn den_panic_hook(panic_info: &std::panic::PanicHookInfo) {
    let message;
    let title = "Better Multiplayer Error";
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

    unsafe {
        windows::Win32::UI::WindowsAndMessaging::MessageBoxW(
            None,
            windows::core::PCWSTR(wstr(&message).as_ptr()),
            windows::core::PCWSTR(wstr(title).as_ptr()),
            windows::Win32::UI::WindowsAndMessaging::MB_ICONERROR,
        );
    }
    std::thread::sleep(std::time::Duration::from_secs(10));
}

pub fn setup_logging(debug: bool) {
    let stdout_log = tracing_subscriber::fmt::layer()
        // disable module path
        .with_target(false)
        .event_format(ColoredCompact);

    let filter = if debug {
        tracing_subscriber::filter::LevelFilter::DEBUG
    } else {
        tracing_subscriber::filter::LevelFilter::INFO
    };
    let registry = tracing_subscriber::registry().with(stdout_log.with_filter(filter));
    registry.init();
}

struct ColoredCompact;

impl<S, N> FormatEvent<S, N> for ColoredCompact
where
    S: tracing::Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, N>,
        mut writer: format::Writer<'_>,
        event: &tracing::Event<'_>,
    ) -> std::fmt::Result {
        let level = *event.metadata().level();

        let (level_str, color) = match level {
            tracing::Level::ERROR => ("ERROR", "\x1b[31m"), // red
            tracing::Level::WARN => ("WARN ", "\x1b[33m"),  // yellow
            tracing::Level::INFO => ("INFO ", "\x1b[32m"),  // green
            tracing::Level::DEBUG => ("DEBUG", "\x1b[34m"), // blue
            tracing::Level::TRACE => ("TRACE", "\x1b[35m"), // magenta
        };

        let reset = "\x1b[0m";
        let bold = "\x1b[1m";

        write!(writer, "{color}{bold}{level_str}{reset} {color}")?;
        ctx.field_format().format_fields(writer.by_ref(), event)?;
        writeln!(writer, "{reset}")
    }
}
