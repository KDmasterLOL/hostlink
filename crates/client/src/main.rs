//! CLI for the pinned, pure-russh HostLink controller.

use clap::{Parser, Subcommand};
use hostlink::{HostSpec, connect::HostConnection};
use std::error::Error;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

const MAX_CONFIG_BYTES: u64 = 64 * 1024;
const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Parser)]
#[command(name = "hostlink", version, about = "Pinned managed-host SSH client")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Establish and close a pinned authenticated SSH connection.
    Check {
        #[arg(long)]
        config: PathBuf,
    },
    /// Execute a single remote shell command with binary stdin/out and exact exit status.
    Exec {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        command: String,
        /// Path to a bounded binary stdin payload; "-" reads controller stdin.
        #[arg(long)]
        stdin_file: Option<String>,
    },
    /// Create a new remote file using authenticated SFTP (never overwrite).
    Upload {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        local: PathBuf,
        #[arg(long)]
        remote: String,
    },
    /// Download an SFTP file to a new local file (never overwrite).
    Download {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        remote: String,
        #[arg(long)]
        local: PathBuf,
    },
}

#[tokio::main]
async fn main() {
    let result = run(Cli::parse()).await;
    match result {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("hostlink: {error}");
            std::process::exit(1);
        }
    }
}

async fn run(cli: Cli) -> Result<i32, Box<dyn Error>> {
    let config_path = match &cli.command {
        Command::Check { config }
        | Command::Exec { config, .. }
        | Command::Upload { config, .. }
        | Command::Download { config, .. } => config,
    };
    let spec = load_host_spec(config_path)?;
    let mut client = HostConnection::connect(&spec).await?;
    // All errors must still close both the target and optional gateway SSH sessions.
    let operation: Result<i32, Box<dyn Error>> = async {
        match cli.command {
            Command::Check { .. } => Ok(0_i32),
            Command::Exec {
                command,
                stdin_file,
                ..
            } => {
                let payload = match stdin_file {
                    Some(path) if path == "-" => read_limited(io::stdin().lock(), MAX_FILE_BYTES)?,
                    Some(path) => read_existing_file(Path::new(&path), MAX_FILE_BYTES)?,
                    None => Vec::new(),
                };
                let response = client.exec(&command, &payload).await?;
                // No HostLink protocol diagnostics on stdout: Cargo/libtest needs exact raw bytes.
                io::stdout().lock().write_all(&response.stdout)?;
                io::stderr().lock().write_all(&response.stderr)?;
                let code = i32::try_from(response.exit_code).map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "SSH exit status exceeds process exit range",
                    )
                })?;
                Ok(code)
            }
            Command::Upload { local, remote, .. } => {
                let bytes = read_existing_file(&local, MAX_FILE_BYTES)?;
                client.sftp_upload(&remote, &bytes).await?;
                Ok(0)
            }
            Command::Download { remote, local, .. } => {
                let bytes = client.sftp_download(&remote).await?;
                create_new_output(&local, &bytes)?;
                Ok(0)
            }
        }
    }
    .await;
    let cleanup = client.close().await;
    match (operation, cleanup) {
        (Ok(code), Ok(())) => Ok(code),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(Box::new(error)),
        (Err(primary), Err(cleanup)) => {
            Err(format!("operation failed: {primary}; SSH cleanup also failed: {cleanup}").into())
        }
    }
}

fn load_host_spec(path: &Path) -> io::Result<HostSpec> {
    let bytes = read_existing_file(path, MAX_CONFIG_BYTES)?;
    let mut config: HostSpec = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
    let base = path.parent().unwrap_or_else(|| Path::new("."));
    if config.identity.is_relative() {
        config.identity = base.join(config.identity);
    }
    if let Some(gateway) = &mut config.gateway
        && gateway.identity.is_relative()
    {
        gateway.identity = base.join(&gateway.identity);
    }
    Ok(config)
}

fn read_existing_file(path: &Path, max_bytes: u64) -> io::Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "source must be a bounded regular file, not a symlink",
        ));
    }
    read_limited(File::open(path)?, max_bytes)
}

fn read_limited(mut reader: impl Read, max_bytes: u64) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader
        .by_ref()
        .take(max_bytes + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "input exceeds size limit",
        ));
    }
    Ok(bytes)
}

fn create_new_output(path: &Path, data: &[u8]) -> io::Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    let result = file.write_all(data).and_then(|_| file.sync_all());
    drop(file);
    if let Err(error) = result {
        if let Err(cleanup) = fs::remove_file(path) {
            return Err(io::Error::other(format!(
                "SFTP local output write failed: {error}; owned partial file cleanup failed: {cleanup}",
            )));
        }
        return Err(error);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_config_rejects_unknown_fields_and_symlinks() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("host.json");
        fs::write(&path, br#"{"endpoint":"127.0.0.1:27322","user":"hostlink","identity":"key","host_public_key":"pin","gateway":null,"unknown":true}"#).unwrap();
        assert!(load_host_spec(&path).is_err());
        #[cfg(unix)]
        {
            let symlink = root.path().join("link.json");
            std::os::unix::fs::symlink(path, &symlink).unwrap();
            assert!(load_host_spec(&symlink).is_err());
        }
    }

    #[test]
    fn new_output_never_overwrites_existing_data() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("out");
        create_new_output(&path, b"old").unwrap();
        assert!(create_new_output(&path, b"new").is_err());
        assert_eq!(fs::read(&path).unwrap(), b"old");
    }
}
