use crate::cli::{
    MAX_FILE_BYTES, args::Command, create_new_output, read_existing_file, read_limited,
};
use hostlink::connect::{HostConnection, SshClientError};
use std::{
    error::Error,
    io::{self, Write},
    path::Path,
    time::Duration,
};

pub(super) async fn execute(
    client: &mut HostConnection,
    command: &Command,
) -> Result<Option<i32>, Box<dyn Error>> {
    match command {
        Command::Check { .. } => Ok(Some(0)),
        Command::Probe {
            target, timeout_ms, ..
        } => {
            if target.port() == 0 || *timeout_ms == 0 {
                return Err("probe target port and timeout must be nonzero".into());
            }
            let opened = tokio::time::timeout(
                Duration::from_millis(*timeout_ms),
                client.open_forward(*target),
            )
            .await
            .map_err(|_| SshClientError::Timeout)??;
            drop(opened);
            eprintln!("hostlink: TCP probe succeeded for {target}");
            Ok(Some(0))
        }
        Command::Exec {
            command,
            stdin_file,
            ..
        } => {
            let payload = match stdin_file.as_deref() {
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
            Ok(Some(code))
        }
        Command::Upload { local, remote, .. } => {
            let bytes = read_existing_file(local, MAX_FILE_BYTES)?;
            client.sftp_upload(remote, &bytes).await?;
            Ok(Some(0))
        }
        Command::Download { remote, local, .. } => {
            let bytes = client.sftp_download(remote).await?;
            create_new_output(local, &bytes)?;
            Ok(Some(0))
        }
        _ => Ok(None),
    }
}
