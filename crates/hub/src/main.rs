use clap::{Parser, Subcommand};
use hostlink_hub::{HubConfig, HubService};
use std::{path::PathBuf, process::ExitCode};

#[derive(Parser)]
#[command(
    name = "hostlink-hub",
    about = "HostLink fleet management server",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    Check {
        #[arg(long)]
        config: PathBuf,
    },
    Serve {
        #[arg(long)]
        config: PathBuf,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    match run(Cli::parse()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("hostlink-hub: {error}");
            ExitCode::FAILURE
        }
    }
}
async fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    match cli.command {
        Command::Check { config } => {
            let config = HubConfig::load(&config)?;
            HubService::new(config)?;
            println!("Hub configuration: valid");
            Ok(())
        }
        Command::Serve { config } => {
            let config = HubConfig::load(&config)?;
            HubService::new(config)?.serve().await?;
            Ok(())
        }
    }
}
