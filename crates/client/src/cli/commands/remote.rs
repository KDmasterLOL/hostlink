use crate::cli::{
    MAX_FILE_BYTES, args::HostTarget, commands::hosts::connect_target, create_new_output,
    read_existing_file, read_limited,
};
use hostlink::connect::{HostConnection, SshClientError};
use std::{
    error::Error,
    io::{self, Write},
    net::SocketAddr,
    path::Path,
    time::Duration,
};

pub(super) async fn check(target: &HostTarget) -> Result<i32, Box<dyn Error>> {
    execute(target, async |_| Ok(0)).await
}

pub(super) async fn probe(
    host_target: &HostTarget,
    target: SocketAddr,
    timeout_ms: u64,
) -> Result<i32, Box<dyn Error>> {
    if target.port() == 0 || timeout_ms == 0 {
        return Err("probe target port and timeout must be nonzero".into());
    }
    execute(host_target, async |client| {
        let opened = tokio::time::timeout(
            Duration::from_millis(timeout_ms),
            client.open_forward(target),
        )
        .await
        .map_err(|_| SshClientError::Timeout)??;
        drop(opened);
        eprintln!("hostlink: TCP probe succeeded for {target}");
        Ok(0)
    })
    .await
}

pub(super) async fn exec(
    target: &HostTarget,
    command: &str,
    stdin_file: Option<&str>,
) -> Result<i32, Box<dyn Error>> {
    execute(target, async |client| {
        let payload = match stdin_file {
            Some("-") => read_limited(io::stdin().lock(), MAX_FILE_BYTES)?,
            Some(path) => read_existing_file(Path::new(path), MAX_FILE_BYTES)?,
            None => Vec::new(),
        };
        let response = client.exec(command, &payload).await?;
        io::stdout().lock().write_all(&response.stdout)?;
        io::stderr().lock().write_all(&response.stderr)?;
        let code = i32::try_from(response.exit_code).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "SSH exit status exceeds process exit range",
            )
        })?;
        Ok(code)
    })
    .await
}

pub(super) async fn upload(
    target: &HostTarget,
    local: &Path,
    remote: &str,
) -> Result<i32, Box<dyn Error>> {
    execute(target, async |client| {
        let bytes = read_existing_file(local, MAX_FILE_BYTES)?;
        client.sftp_upload(remote, &bytes).await?;
        Ok(0)
    })
    .await
}

pub(super) async fn download(
    target: &HostTarget,
    remote: &str,
    local: &Path,
) -> Result<i32, Box<dyn Error>> {
    execute(target, async |client| {
        let bytes = client.sftp_download(remote).await?;
        create_new_output(local, &bytes)?;
        Ok(0)
    })
    .await
}

async fn execute(
    target: &HostTarget,
    operation: impl AsyncFnOnce(&mut HostConnection) -> Result<i32, Box<dyn Error>>,
) -> Result<i32, Box<dyn Error>> {
    let mut client = connect_target(target).await?;
    let operation = operation(&mut client).await;
    // Keep cleanup errors visible alongside any command failure, including local I/O errors.
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
