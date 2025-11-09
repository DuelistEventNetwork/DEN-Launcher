mod constants;
mod injector;
mod logging;
mod updater;

use clap::Parser;
use dotenvy_macro::dotenv;
use injector::start_game;
use logging::{den_panic_hook, enable_ansi_support, setup_logging};
use updater::start_updater;

#[derive(Parser)]
#[command(name = "DenLauncher")]
#[command(version = env!("CARGO_PKG_VERSION"))]
struct Args {
    #[arg(long, env("DEN_SKIP_UPDATES"), default_value_t = false)]
    skip_updates: bool,
    #[arg(long, env("DEN_REPO_OWNER"), default_value = dotenv!("DEN_REPO_OWNER"))]
    updater_repo_owner: String,
    #[arg(long, env("DEN_REPO_NAME"), default_value = dotenv!("DEN_REPO_NAME"))]
    updater_repo_name: String,
    #[arg(long, env("DEN_REPO_PRIVATE_KEY"))]
    updater_repo_private_key: Option<String>,
    #[arg(long, env("DEN_CONTENT_DIR"), default_value = dotenv!("DEN_CONTENT_DIR"))]
    content_dir: String,
    #[arg(long, env("DEN_DLL_NAME"), default_value = dotenv!("DEN_DLL_NAME"))]
    dll_name: String,
}

fn main() {
    dotenvy::dotenv().ok();

    enable_ansi_support().ok();

    setup_logging();

    std::panic::set_hook(Box::new(den_panic_hook));

    let args = Args::parse();

    tracing::info!("Starting DenLauncher v{}", env!("CARGO_PKG_VERSION"));
    tracing::info!(
        " value of DEN_PRIVATE_KEY: {:?}",
        args.updater_repo_private_key
    );
    if args.skip_updates {
        tracing::info!("--skip-updates flag passed, skipping update check.");
    } else {
        tracing::info!("Checking for updates...");
        start_updater(
            &args.updater_repo_owner,
            &args.updater_repo_name,
            args.updater_repo_private_key.as_deref(),
            &args.content_dir,
            &args.dll_name,
        )
    }

    tracing::info!("Starting Elden Ring...");

    if let Err(err) = start_game(&args.content_dir, &args.dll_name) {
        tracing::error!("Failed to start Elden Ring: {:?}", err);
        std::thread::sleep(std::time::Duration::from_secs(5));
        std::process::exit(1);
    } else {
        tracing::info!("Elden Ring started successfully!");
        std::thread::sleep(std::time::Duration::from_secs(5));
    }
}
