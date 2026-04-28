mod constants;
mod injector;
mod launcher_error;
mod logging;
mod migrations;
mod steamlocate;
mod updater;
mod winhttp_client;

use std::{env, path::PathBuf};

use constants::ELDENRING_EXE;
use den_signer::VerifyingKey;
use dotenvy_macro::dotenv;
use injector::start_game;
use logging::{den_panic_hook, enable_ansi_support, setup_logging};
use updater::start_updater;

use crate::{constants::RELEASE_PUBLIC_KEY, launcher_error::LauncherError};

struct Args {
    skip_updates: bool,
    updater_repo_owner: String,
    updater_repo_name: String,
    updater_repo_private_key: Option<String>,
    content_dir: PathBuf,
    dll_name: String,
    game_executable: String,
    debug: bool,
}

impl Args {
    fn parse() -> Result<Self, pico_args::Error> {
        let mut pargs = pico_args::Arguments::from_env();
        Ok(Args {
            skip_updates: pargs.contains("--skip-updates")
                || std::env::var("DEN_SKIP_UPDATES").is_ok(),
            updater_repo_owner: pargs
                .opt_value_from_str("--updater-repo-owner")?
                .or_else(|| std::env::var("DEN_REPO_OWNER").ok())
                .unwrap_or_else(|| dotenv!("DEN_REPO_OWNER").into()),
            updater_repo_name: pargs
                .opt_value_from_str("--updater-repo-name")?
                .or_else(|| std::env::var("DEN_REPO_NAME").ok())
                .unwrap_or_else(|| dotenv!("DEN_REPO_NAME").into()),
            updater_repo_private_key: pargs.opt_value_from_str("--updater-repo-private-key")?,
            content_dir: pargs
                .opt_value_from_str("--content-dir")?
                .or_else(|| std::env::var("DEN_CONTENT_DIR").ok().map(Into::into))
                .unwrap_or_else(|| dotenv!("DEN_CONTENT_DIR").into()),
            dll_name: pargs
                .opt_value_from_str("--dll-name")?
                .or_else(|| std::env::var("DEN_DLL_NAME").ok())
                .unwrap_or_else(|| dotenv!("DEN_DLL_NAME").into()),
            game_executable: pargs
                .opt_value_from_str("--game-executable")?
                .or_else(|| std::env::var("DEN_GAME_EXECUTABLE").ok())
                .unwrap_or_else(|| ELDENRING_EXE.to_owned()),
            debug: pargs.contains("--debug") || std::env::var("DEN_DEBUG").is_ok(),
        })
    }
}

fn get_verifying_key(bytes: &[u8; 32]) -> VerifyingKey {
    VerifyingKey::from_bytes(bytes).expect("release_public_key.bin is not a valid ed25519 key")
}

fn main() {
    let args = Args::parse().unwrap_or_else(|e| {
        eprintln!("Error parsing arguments: {e}");
        wait_for_exit();
        unreachable!()
    });

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
                unreachable!()
            }
            Err(err) => {
                tracing::error!("Updater failed: {err}");
                wait_for_exit();
                unreachable!()
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
        unreachable!()
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
