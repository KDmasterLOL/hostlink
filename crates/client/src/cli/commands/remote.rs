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
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const BOARD_TIMEOUT: Duration = Duration::from_secs(10);
const BOARD_MAX_RESPONSE: usize = 64 * 1024;

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

pub(super) async fn exec_detached(
    target: &HostTarget,
    port: u16,
    command: &str,
    target_os: &str,
) -> Result<i32, Box<dyn Error>> {
    let (program, args) = shell_command(command, target_os)?;
    // Apalis uses ULIDs as its native task identifiers.
    let id = ulid::Ulid::generate().to_string();
    let payload = serde_json::json!({"program": program, "args": args, "cwd": null});
    execute(target, async |client| {
        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        let mut stream = client.open_forward(addr).await?;
        let body = serde_json::to_vec(&payload)?;
        let request = format!("PUT /api/v1/queues/commands/tasks HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\nx-task-id: {id}\r\n\r\n", body.len());
        tokio::time::timeout(BOARD_TIMEOUT, async {
            stream.write_all(request.as_bytes()).await?;
            stream.write_all(&body).await?;
            let response = read_board_response(&mut stream).await?;
            let status = response_status(&response)?;
            if !(200..300).contains(&status) { return Err(io::Error::other(format!("Apalis Board rejected job submission (HTTP {status}); outcome may be ambiguous; do not retry blindly"))); }
            Ok::<(), io::Error>(())
        }).await.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Apalis Board request timed out; submission outcome is unknown; do not retry blindly"))??;
        println!("{id}");
        Ok(0)
    }).await
}

pub(super) async fn job_status(
    target: &HostTarget,
    port: u16,
    id: &str,
) -> Result<i32, Box<dyn Error>> {
    id.parse::<ulid::Ulid>()
        .map_err(|_| "job ID must be a 26-character Apalis ULID")?;
    execute(target, async |client| {
        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        let mut stream = client.open_forward(addr).await?;
        let request = format!("GET /api/v1/queues/commands/tasks/{id} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
        let response = tokio::time::timeout(BOARD_TIMEOUT, async {
            stream.write_all(request.as_bytes()).await?;
            read_board_response(&mut stream).await
        }).await.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Apalis Board status request timed out"))??;
        let status = response_status(&response)?;
        if status == 404 { return Err(io::Error::new(io::ErrorKind::NotFound, "Apalis job ID not found").into()); }
        if status != 200 { return Err(io::Error::other(format!("Apalis Board status failed (HTTP {status})")).into()); }
        let (_, body) = split_response(&response)?;
        let task: serde_json::Value = serde_json::from_slice(body)?;
        let ctx = task.get("ctx").ok_or("Apalis response missing task context")?;
        let native_id = ctx.get("task_id").and_then(serde_json::Value::as_str).ok_or("Apalis response missing task ID")?;
        let state = ctx.get("status").and_then(serde_json::Value::as_str).ok_or("Apalis response missing task status")?;
        if native_id != id { return Err("Apalis response task ID mismatch".into()); }
        println!("id: {native_id}\nstatus: {state}\nexit code: unavailable (not exposed by the upstream Board task response)\noutput: unavailable (use the Board UI or have the command write its own result file)");
        Ok(0)
    }).await
}

fn shell_command(command: &str, target_os: &str) -> Result<(String, Vec<String>), Box<dyn Error>> {
    match target_os {
        "linux" => Ok(("sh".into(), vec!["-c".into(), command.into()])),
        "windows" => Ok((
            "powershell.exe".into(),
            vec![
                "-NoProfile".into(),
                "-NonInteractive".into(),
                "-InputFormat".into(),
                "None".into(),
                "-Command".into(),
                command.into(),
            ],
        )),
        other => Err(format!("unsupported or unknown target OS: {other}").into()),
    }
}

async fn read_board_response(
    stream: &mut (impl tokio::io::AsyncRead + Unpin),
) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        if out.len() + n > BOARD_MAX_RESPONSE {
            return Err(io::Error::other("Apalis Board response exceeds 64 KiB"));
        }
        out.extend_from_slice(&buf[..n]);
    }
    Ok(out)
}

fn split_response(response: &[u8]) -> io::Result<(&str, &[u8])> {
    let split = response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| io::Error::other("invalid HTTP response from Apalis Board"))?;
    let head = std::str::from_utf8(&response[..split]).map_err(io::Error::other)?;
    let body = &response[split + 4..];
    if head
        .to_ascii_lowercase()
        .contains("transfer-encoding: chunked")
    {
        return Err(io::Error::other(
            "chunked Apalis Board response unsupported",
        ));
    }
    if let Some(line) = head
        .lines()
        .find(|line| line.to_ascii_lowercase().starts_with("content-length:"))
    {
        let length: usize = line
            .split_once(':')
            .and_then(|(_, v)| v.trim().parse().ok())
            .ok_or_else(|| io::Error::other("invalid Board Content-Length"))?;
        if length != body.len() {
            return Err(io::Error::other("incomplete Apalis Board response"));
        }
    }
    Ok((head, body))
}
fn response_status(response: &[u8]) -> io::Result<u16> {
    let (head, _) = split_response(response)?;
    head.lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| io::Error::other("invalid Board HTTP status"))
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

#[cfg(test)]
mod board_http_tests {
    use super::*;

    #[test]
    fn parses_upstream_empty_ack_and_task_response() {
        let ack = b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n";
        assert_eq!(response_status(ack).unwrap(), 200);
        let body = br#"{"ctx":{"task_id":"abc","status":"Done"}}"#;
        let status = format!(
            "HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n{}",
            body.len(),
            std::str::from_utf8(body).unwrap()
        );
        assert_eq!(response_status(status.as_bytes()).unwrap(), 200);
        assert_eq!(split_response(status.as_bytes()).unwrap().1, body);
    }

    #[test]
    fn rejects_chunked_and_incomplete_board_responses() {
        assert!(
            split_response(b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n0\r\n\r\n")
                .is_err()
        );
        assert!(split_response(b"HTTP/1.1 200 OK\r\ncontent-length: 4\r\n\r\n{}").is_err());
    }

    #[test]
    fn generated_task_ids_are_upstream_ulids() {
        let id = ulid::Ulid::generate().to_string();
        assert_eq!(id.len(), 26);
        assert!(id.parse::<ulid::Ulid>().is_ok());
    }

    #[test]
    fn detached_shell_matches_platform_shell_contract() {
        let (program, args) = shell_command("echo hi", "linux").unwrap();
        assert_eq!(program, "sh");
        assert_eq!(args, ["-c", "echo hi"]);
        let (program, args) = shell_command("echo hi", "windows").unwrap();
        assert_eq!(program, "powershell.exe");
        assert_eq!(args.last().unwrap(), "echo hi");
        assert!(shell_command("echo hi", "unknown").is_err());
    }
}
