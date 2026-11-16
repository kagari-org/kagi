use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

use kagi::config::{self, Config, LogFormat};
use kagi::policy::Policy;

#[derive(Debug, Parser)]
#[command(name = "kagi", version, about = "SSH forwarding and stream server")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the SSH server.
    Serve {
        #[arg(short, long, default_value = "/etc/kagi/kagi.toml")]
        config: PathBuf,
        #[arg(long)]
        listen: Option<String>,
        #[arg(long)]
        log_level: Option<String>,
    },
    /// Validate configuration and print a summary without starting the server.
    Check {
        #[arg(short, long, default_value = "/etc/kagi/kagi.toml")]
        config: PathBuf,
    },
    /// Generate an Ed25519 host key.
    GenHostKey {
        #[arg(short, long)]
        path: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command.unwrap_or(Command::Serve {
        config: PathBuf::from("/etc/kagi/kagi.toml"),
        listen: None,
        log_level: None,
    }) {
        Command::Serve {
            config,
            listen,
            log_level,
        } => serve(config, listen, log_level).await,
        Command::Check { config } => check(config),
        Command::GenHostKey { path } => config::generate_host_key(&path),
    }
}

async fn serve(
    config_path: PathBuf,
    listen: Option<String>,
    log_level: Option<String>,
) -> Result<()> {
    let mut config = config::load(&config_path)?;
    if let Some(listen) = listen {
        config.server.listen = listen;
    }
    init_tracing(
        log_level.as_deref().unwrap_or(&config.log.level),
        config.log.format,
    )?;

    let host_key =
        config::load_or_generate_host_key(&config_path, config.server.host_key.as_deref())
            .context("failed to load or generate host key")?;
    if host_key.generated {
        tracing::info!("host key generated automatically");
    }

    kagi::server::run(config_path, config, host_key.key).await
}

fn check(config_path: PathBuf) -> Result<()> {
    let config: Config = config::load(&config_path)?;
    let policy = Policy::build(config.clone(), 1)?;
    let rules: usize = config.users.values().map(|u| u.rules.len()).sum::<usize>()
        + config.groups.values().map(|g| g.rules.len()).sum::<usize>();

    println!("config:            {}", config_path.display());
    println!("listen:            {}", config.server.listen);
    println!("default policy:    {:?}", config.server.default_policy);
    println!(
        "global -R:         {}",
        if config.server.allow_remote_forward {
            "enabled"
        } else {
            "disabled"
        }
    );
    println!("users:             {}", policy.users.len());
    println!(
        "keys:              {}",
        policy
            .users
            .values()
            .map(|user| user.fingerprints.len())
            .sum::<usize>()
    );
    println!("groups:            {}", policy.groups.len());
    println!("rules:             {rules}");
    println!(
        "host key:          {}",
        config::host_key_summary(&config_path, config.server.host_key.as_deref())
    );
    for warning in policy.warning_list() {
        println!("warning:           {warning}");
    }
    println!("ok");
    Ok(())
}

fn init_tracing(level: &str, format: LogFormat) -> Result<()> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));
    match format {
        LogFormat::Text => {
            tracing_subscriber::fmt()
                .with_env_filter(filter)
                .with_target(false)
                .init();
        }
        LogFormat::Json => {
            tracing_subscriber::fmt()
                .with_env_filter(filter)
                .with_target(false)
                .json()
                .init();
        }
    }
    Ok(())
}
