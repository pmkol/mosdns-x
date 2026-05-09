use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tracing::info;

mod config;
mod core;
mod server;
mod upstream;
mod plugin;
mod query_context;
mod utils;
mod cache;
mod matcher;

use config::Config;
use core::Mosdns;

#[derive(Parser)]
#[command(name = "mosdns")]
#[command(about = "A DNS forwarder written in Rust")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    #[command(about = "Start mosdns main program")]
    Start {
        #[arg(short, long, help = "Config file")]
        config: Option<PathBuf>,
        #[arg(short, long, help = "Working directory")]
        dir: Option<PathBuf>,
        #[arg(long, help = "Set max CPU cores")]
        cpu: Option<usize>,
    },
    #[command(about = "Print out version info and exit")]
    Version,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Start { config, dir, cpu } => {
            if let Some(c) = cpu {
                info!("CPU limit hint: {}", c);
            }

            if let Some(d) = dir {
                std::env::set_current_dir(&d)?;
                info!("working directory changed to {:?}", d);
            }

            let config_path = config.unwrap_or_else(|| {
                PathBuf::from("config.yaml")
            });

            let cfg = Config::load(&config_path)?;
            Mosdns::run(cfg).await?;
        }
        Commands::Version => {
            println!("version: v{}", env!("CARGO_PKG_VERSION"));
        }
    }

    Ok(())
}
