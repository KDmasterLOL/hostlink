use crate::cli::{
    MAX_FILE_BYTES, args::HostTarget, commands::hosts::connect_target, create_new_output,
    read_existing_file, read_limited,
};
use hostlink::connect::{HostConnection, SshClientError};
use std::{
    error::Error,
    future::Future,
    io::{self, Write},
    net::SocketAddr,
    path::Path,
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const BOARD_TIMEOUT: Duration = Duration::from_secs(10);
const BOARD_MAX_RESPONSE: usize = 64 * 1024;
const COMMAND_TIMEOUT_HEADER: &str = "x-hostlink-command-timeout-max";
const COMMAND_TIMEOUT_MAX: u64 = 14_400;

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
    timeout_seconds: Option<u64>,
    allow_child_breakaway: bool,
) -> Result<i32, Box<dyn Error>> {
    execute(target, async |client| {
        let payload = match stdin_file {
            Some("-") => read_limited(io::stdin().lock(), MAX_FILE_BYTES)?,
            Some(path) => read_existing_file(Path::new(path), MAX_FILE_BYTES)?,
            None => Vec::new(),
        };
        let response = if allow_child_breakaway {
            client
                .exec_with_child_breakaway(
                    command,
                    &payload,
                    Duration::from_secs(timeout_seconds.unwrap_or(60)),
                )
                .await?
        } else {
            match timeout_seconds {
                Some(seconds) => {
                    client
                        .exec_with_timeout(command, &payload, Duration::from_secs(seconds))
                        .await?
                }
                None => client.exec(command, &payload).await?,
            }
        };
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
    timeout_seconds: Option<u64>,
) -> Result<i32, Box<dyn Error>> {
    let (program, args) = shell_command(command, target_os)?;
    // Apalis uses ULIDs as its native task identifiers.
    let id = ulid::Ulid::generate().to_string();
    let payload = command_job_payload(program, args, timeout_seconds);
    execute(target, async |client| {
        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        if let Some(requested) = timeout_seconds {
            let mut stream = client.open_forward(addr).await?;
            let request = board_timeout_capability_request(addr);
            let response = tokio::time::timeout(BOARD_TIMEOUT, async {
                stream.write_all(request.as_bytes()).await?;
                read_board_response(&mut stream).await
            })
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "Apalis Board timeout capability preflight timed out; job was not submitted",
                )
            })??;
            submit_after_timeout_preflight(
                &response,
                requested,
                submit_detached_job(client, addr, &id, &payload),
            )
            .await?;
        } else {
            submit_detached_job(client, addr, &id, &payload).await?;
        }
        println!("{id}");
        Ok(0)
    })
    .await
}

async fn submit_detached_job(
    client: &mut HostConnection,
    addr: SocketAddr,
    id: &str,
    payload: &serde_json::Value,
) -> io::Result<()> {
    let mut stream = client.open_forward(addr).await.map_err(io::Error::other)?;
    let body = serde_json::to_vec(payload).map_err(io::Error::other)?;
    let request = board_submit_request(addr, id, body.len());
    tokio::time::timeout(BOARD_TIMEOUT, async {
        stream.write_all(request.as_bytes()).await?;
        stream.write_all(&body).await?;
        let response = read_board_response(&mut stream).await?;
        let status = response_status(&response)?;
        if !(200..300).contains(&status) {
            return Err(io::Error::other(format!(
                "Apalis Board rejected job submission (HTTP {status}); outcome may be ambiguous; do not retry blindly"
            )));
        }
        Ok(())
    })
    .await
    .map_err(|_| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            "Apalis Board request timed out; submission outcome is unknown; do not retry blindly",
        )
    })?
}

fn board_timeout_capability_request(address: SocketAddr) -> String {
    format!("GET /new HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n")
}

async fn submit_after_timeout_preflight<T>(
    response: &[u8],
    requested: u64,
    submit: impl Future<Output = io::Result<T>>,
) -> io::Result<T> {
    validate_timeout_capability(response, requested)?;
    submit.await
}

fn validate_timeout_capability(response: &[u8], requested: u64) -> io::Result<()> {
    let status = response_status(response)?;
    if status != 200 {
        return Err(io::Error::other(format!(
            "Apalis Board timeout capability preflight failed (HTTP {status}); job was not submitted"
        )));
    }
    let (head, _) = split_response(response)?;
    let mut capabilities = head.lines().skip(1).filter_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case(COMMAND_TIMEOUT_HEADER)
            .then_some(value.trim())
    });
    let value = capabilities.next().ok_or_else(|| {
        io::Error::other("Agent does not advertise custom command timeouts; job was not submitted")
    })?;
    if capabilities.next().is_some() {
        return Err(io::Error::other(
            "Agent returned an ambiguous command timeout capability; job was not submitted",
        ));
    }
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(io::Error::other(
            "Agent returned an invalid command timeout capability; job was not submitted",
        ));
    }
    let maximum = value.parse::<u64>().map_err(|_| {
        io::Error::other(
            "Agent returned an invalid command timeout capability; job was not submitted",
        )
    })?;
    if maximum == 0 || maximum > COMMAND_TIMEOUT_MAX {
        return Err(io::Error::other(
            "Agent returned an out-of-range command timeout capability; job was not submitted",
        ));
    }
    if maximum < requested {
        return Err(io::Error::other(format!(
            "Agent supports command timeouts up to {maximum} seconds, below the requested {requested}; job was not submitted"
        )));
    }
    Ok(())
}

fn command_job_payload(
    program: String,
    args: Vec<String>,
    timeout_seconds: Option<u64>,
) -> serde_json::Value {
    let mut payload = serde_json::json!({"program": program, "args": args, "cwd": null});
    if let Some(timeout_seconds) = timeout_seconds {
        payload["timeout_seconds"] = serde_json::json!(timeout_seconds);
    }
    payload
}

fn board_submit_request(address: SocketAddr, id: &str, content_length: usize) -> String {
    // A command may have mutated external state before returning a nonzero
    // exit code. Do not let Apalis automatically repeat that side effect.
    format!(
        "PUT /api/v1/queues/commands/tasks HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {content_length}\r\nx-task-id: {id}\r\nx-task-max-attempts: 1\r\n\r\n"
    )
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
        let status_exit_code = job_status_cli_exit_code(state)?;
        let result = upstream_run_result(ctx);
        let result_line = result.map_or_else(
            || "result: unavailable (not present in the upstream Board task response)".to_owned(),
            |value| format!("upstream result: {}", value),
        );
        println!("id: {native_id}\nstatus: {state}\nexit code: unavailable (the upstream run result is not defined as a process exit code)\n{result_line}\noutput: unavailable (have the command write its own result file)");
        Ok(status_exit_code)
    }).await
}

// CLI status reports query success/failure, not the original process exit code.
fn job_status_cli_exit_code(state: &str) -> io::Result<i32> {
    match state {
        "Pending" | "Queued" | "Running" | "Done" => Ok(0),
        "Failed" | "Killed" => Ok(1),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported Apalis task status: {state}"),
        )),
    }
}

fn upstream_run_result(ctx: &serde_json::Value) -> Option<String> {
    let runs = ctx.get("runs")?.as_array()?;
    runs.iter()
        .rev()
        .find_map(|run| run.get("result").filter(|result| !result.is_null()))
        .map(ToString::to_string)
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
    fn detached_jobs_request_exactly_one_upstream_attempt() {
        let address = SocketAddr::from(([127, 0, 0, 1], 23584));
        let request = board_submit_request(address, "01ARZ3NDEKTSV4RRFFQ69G5FAV", 42);
        assert!(request.starts_with("PUT /api/v1/queues/commands/tasks HTTP/1.1\r\n"));
        assert!(request.contains("\r\nHost: 127.0.0.1:23584\r\n"));
        assert!(request.contains("\r\nContent-Length: 42\r\n"));
        assert!(request.contains("\r\nx-task-max-attempts: 1\r\n"));
        assert!(request.ends_with("\r\n\r\n"));
        assert!(
            !request
                .to_ascii_lowercase()
                .contains(COMMAND_TIMEOUT_HEADER)
        );
    }

    #[test]
    fn timeout_preflight_uses_the_existing_board_form_with_exact_host() {
        let address = SocketAddr::from(([127, 0, 0, 1], 23584));
        assert_eq!(
            board_timeout_capability_request(address),
            "GET /new HTTP/1.1\r\nHost: 127.0.0.1:23584\r\nConnection: close\r\n\r\n"
        );
    }

    #[test]
    fn accepts_one_valid_timeout_capability_at_or_above_request() {
        let response = b"HTTP/1.1 200 OK\r\nx-hostlink-command-timeout-max: 14400\r\ncontent-length: 0\r\n\r\n";
        assert!(validate_timeout_capability(response, 14_400).is_ok());
        let exact =
            b"HTTP/1.1 200 OK\r\nX-HostLink-Command-Timeout-Max: 901\r\ncontent-length: 0\r\n\r\n";
        assert!(validate_timeout_capability(exact, 901).is_ok());
    }

    #[test]
    fn rejects_missing_duplicate_corrupt_and_insufficient_capabilities() {
        let missing = b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n";
        let duplicate = b"HTTP/1.1 200 OK\r\nx-hostlink-command-timeout-max: 14400\r\nX-HostLink-Command-Timeout-Max: 14400\r\ncontent-length: 0\r\n\r\n";
        let corrupt = b"HTTP/1.1 200 OK\r\nx-hostlink-command-timeout-max: 14seconds\r\ncontent-length: 0\r\n\r\n";
        let zero =
            b"HTTP/1.1 200 OK\r\nx-hostlink-command-timeout-max: 0\r\ncontent-length: 0\r\n\r\n";
        let over_cap = b"HTTP/1.1 200 OK\r\nx-hostlink-command-timeout-max: 14401\r\ncontent-length: 0\r\n\r\n";
        let under_limit =
            b"HTTP/1.1 200 OK\r\nx-hostlink-command-timeout-max: 900\r\ncontent-length: 0\r\n\r\n";
        let non_200 = b"HTTP/1.1 404 Not Found\r\nx-hostlink-command-timeout-max: 14400\r\ncontent-length: 0\r\n\r\n";
        let responses: [&[u8]; 7] = [
            missing,
            duplicate,
            corrupt,
            zero,
            over_cap,
            under_limit,
            non_200,
        ];
        for response in responses {
            assert!(validate_timeout_capability(response, 901).is_err());
        }
    }

    #[tokio::test]
    async fn invalid_timeout_preflight_short_circuits_before_enqueue() {
        let response = b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n";
        let submitted = std::cell::Cell::new(false);
        let result = submit_after_timeout_preflight(response, 901, async {
            submitted.set(true);
            Ok(())
        })
        .await;
        assert!(result.is_err());
        assert!(!submitted.get());
    }

    #[test]
    fn command_job_timeout_is_optional_for_legacy_agents() {
        let old = command_job_payload("sh".into(), vec!["-c".into(), "true".into()], None);
        assert_eq!(
            old,
            serde_json::json!({"program":"sh", "args":["-c", "true"], "cwd":null})
        );
        assert!(old.get("timeout_seconds").is_none());

        let new = command_job_payload("sh".into(), vec!["-c".into(), "true".into()], Some(901));
        assert_eq!(new["timeout_seconds"], 901);
    }

    #[test]
    fn job_status_cli_distinguishes_terminal_failure_from_query_success() {
        for state in ["Pending", "Queued", "Running", "Done"] {
            assert_eq!(job_status_cli_exit_code(state).unwrap(), 0, "{state}");
        }
        for state in ["Failed", "Killed"] {
            assert_eq!(job_status_cli_exit_code(state).unwrap(), 1, "{state}");
        }
        assert_eq!(
            job_status_cli_exit_code("Unexpected").unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert!(job_status_cli_exit_code("").is_err());
    }

    #[test]
    fn status_reads_only_a_present_official_upstream_run_result() {
        let response = serde_json::json!({"ctx":{"runs":[{"result":null},{"result":{"Ok":7}}]}});
        assert_eq!(
            upstream_run_result(&response["ctx"]).as_deref(),
            Some("{\"Ok\":7}")
        );

        let unavailable = serde_json::json!({"ctx":{"runs":[]}});
        assert_eq!(upstream_run_result(&unavailable["ctx"]), None);
    }

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
