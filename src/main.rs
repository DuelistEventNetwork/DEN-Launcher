mod constants;
mod injector;
mod launcher_error;
mod logging;
mod migrations;
mod updater;

use std::path::PathBuf;

use clap::Parser;
use constants::ELDENRING_EXE;
use den_signer::VerifyingKey;
use dotenvy_macro::dotenv;
use injector::start_game;
use logging::{den_panic_hook, enable_ansi_support, setup_logging};
use updater::start_updater;

use crate::{constants::RELEASE_PUBLIC_KEY, launcher_error::LauncherError};

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
    #[arg(long)]
    updater_repo_private_key: Option<String>,
    #[arg(long, env("DEN_CONTENT_DIR"), default_value = dotenv!("DEN_CONTENT_DIR"))]
    content_dir: PathBuf,
    #[arg(long, env("DEN_DLL_NAME"), default_value = dotenv!("DEN_DLL_NAME"))]
    dll_name: String,
    #[arg(long, env("DEN_GAME_EXECUTABLE"), default_value = ELDENRING_EXE)]
    game_executable: String,
    #[arg(long, env("DEN_DEBUG"), default_value_t = false)]
    debug: bool,
}

fn get_verifying_key(bytes: &[u8; 32]) -> VerifyingKey {
    VerifyingKey::from_bytes(bytes).expect("release_public_key.bin is not a valid ed25519 key")
}

fn main() {
    let args = Args::parse();

    enable_ansi_support().ok();

    setup_logging(args.debug);

    std::panic::set_hook(Box::new(den_panic_hook));

    tracing::info!(
        "Starting Better Multiplayer Launcher v{}",
        env!("CARGO_PKG_VERSION")
    );

    let current_exe = std::env::current_exe().expect("Failed to get current exe path");
    let exe_dir = current_exe
        .parent()
        .expect("Failed to get current exe dir")
        .to_path_buf();

    tracing::debug!("Running migrations in {}", exe_dir.display());
    migrations::run(&exe_dir);

    let _ = if args.skip_updates {
        tracing::info!("--skip-updates flag passed, skipping update check.");
        None
    } else {
        tracing::info!("Checking for updates...");
        match start_updater(
            &args.updater_repo_owner,
            &args.updater_repo_name,
            args.updater_repo_private_key.as_deref(),
            &get_verifying_key(RELEASE_PUBLIC_KEY),
        ) {
            Ok(opt) => opt,
            Err(LauncherError::RestartRequired) => {
                wait_for_exit();
                None
            }
            Err(err) => {
                tracing::error!("Updater failed: {err}");
                wait_for_exit();
                None
            }
        }
    };

    tracing::info!("Starting Elden Ring...");

    if let Err(err) = start_game(
        &args.content_dir,
        &args.dll_name,
        &args.game_executable,
        args.debug,
    ) {
        tracing::error!("Failed to start Elden Ring: {}", err);
        wait_for_exit();
    } else {
        tracing::info!("Elden Ring started successfully!");
        std::thread::sleep(std::time::Duration::from_secs(5));
    }
}

fn wait_for_exit() {
    use std::io::Read;

    let mut stdin = std::io::stdin();

    tracing::info!("Press any key to exit...");

    let _ = stdin.read(&mut [0u8]).unwrap();
    std::process::exit(1);
}
