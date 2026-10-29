//! HostLink Agent executable entrypoint.

mod cli;
mod commands;
mod shared;

#[tokio::main]
async fn main() {
    if let Err(error) = cli::run().await {
        eprintln!("hostlink-agent: {error}");
        std::process::exit(1);
    }
}
