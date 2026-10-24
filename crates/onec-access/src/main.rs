//! hostlink controller CLI.

use clap::Parser;
use std::io;

mod cli;

use cli::Cli;
pub(crate) use hostlink_access::{invalid_config, not_found_error, process_failed_error};

#[tokio::main]
async fn main() {
    match run().await {
        Ok(Some(code)) => std::process::exit(code),
        Ok(None) => {}
        Err(error) => {
            eprintln!("hostlink: {error}");
            std::process::exit(1);
        }
    }
}

async fn run() -> io::Result<Option<i32>> {
    let cli = Cli::parse();
    Box::pin(cli::run(cli.command))
        .await
        .map_err(io::Error::other)
}

#[cfg(test)]
mod tests {
    use super::run;

    #[test]
    fn cli_runtime_future_keeps_dispatch_state_off_the_main_stack() {
        let future_size = std::mem::size_of_val(&run());
        assert!(
            future_size <= 4096,
            "CLI runtime future is {future_size} bytes; command dispatch must stay heap-boxed"
        );
    }
}
