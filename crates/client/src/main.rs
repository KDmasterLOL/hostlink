//! CLI binary entrypoint.

mod cli;

#[tokio::main]
async fn main() {
    let result = cli::run().await;
    match result {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("hostlink: {error}");
            std::process::exit(1);
        }
    }
}
