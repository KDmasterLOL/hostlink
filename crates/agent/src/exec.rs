use processkit::{Command, OutputBufferPolicy};
use std::io;
use std::time::Duration;
use tokio::io::AsyncReadExt;

#[cfg(not(test))]
const EXEC_TIMEOUT: Duration = Duration::from_secs(15 * 60);
#[cfg(test)]
const EXEC_TIMEOUT: Duration = Duration::from_secs(3);
const EXEC_TIMEOUT_GRACE: Duration = Duration::from_secs(2);

pub(super) fn validate_command(data: &[u8], max_bytes: usize) -> io::Result<String> {
    if data.is_empty() {
        return Err(invalid_command("SSH exec command must not be empty"));
    }
    if data.len() > max_bytes {
        return Err(invalid_command(
            "SSH exec command exceeds the configured limit",
        ));
    }
    if data.contains(&0) {
        return Err(invalid_command(
            "SSH exec command must not contain NUL bytes",
        ));
    }
    let command = std::str::from_utf8(data)
        .map_err(|_| invalid_command("SSH exec command must be valid UTF-8"))?;
    if command.trim().is_empty() {
        return Err(invalid_command("SSH exec command must not be empty"));
    }
    Ok(command.to_owned())
}

pub(super) fn prepare_command(command: &str) -> io::Result<Command> {
    #[cfg(unix)]
    let child = Command::new("sh").arg("-c").arg(command);

    #[cfg(windows)]
    let child = {
        // Keep PowerShell from consuming redirected stdin before the command starts.
        Command::new("powershell.exe").args([
            "-NoProfile",
            "-NonInteractive",
            "-InputFormat",
            "None",
            "-Command",
            command,
        ])
    };

    #[cfg(not(any(unix, windows)))]
    let child: Command = {
        let _ = command;
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "SSH exec is unsupported on this operating system",
        ));
    };

    let child = child;
    Ok(child
        .keep_stdin_open()
        .output_buffer(OutputBufferPolicy::bounded(256).with_max_bytes(1024 * 1024))
        .timeout(EXEC_TIMEOUT)
        .timeout_grace(EXEC_TIMEOUT_GRACE))
}

#[cfg(not(target_vendor = "win7"))]
pub(super) fn prepare_shell(term: &str, cols: u16, rows: u16) -> io::Result<Command> {
    #[cfg(unix)]
    let mut child = {
        let shell = std::env::var_os("SHELL")
            .filter(|value| !value.is_empty() && value.len() <= 4096)
            .map(std::path::PathBuf::from)
            .filter(|path| valid_login_shell(path))
            .unwrap_or_else(|| std::path::PathBuf::from("/bin/sh"));
        Command::new(shell).arg("-i")
    };

    #[cfg(windows)]
    let mut child = Command::new("powershell.exe").args(["-NoLogo", "-NoProfile"]);

    #[cfg(not(any(unix, windows)))]
    let child: Command = {
        let _ = (term, cols, rows);
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "interactive SSH shell is unsupported on this operating system",
        ));
    };

    #[cfg(any(unix, windows))]
    {
        child = child
            .env("TERM", term)
            .use_pty()
            .pty_size(cols, rows)
            .keep_stdin_open()
            // Interactive sessions can outlive any fixed exec timeout. Retain
            // no transcript; SSH itself applies bounded channel backpressure.
            .output_buffer(OutputBufferPolicy::bounded(0));
        Ok(child)
    }
}

#[cfg(target_vendor = "win7")]
pub(super) fn prepare_shell(_term: &str, _cols: u16, _rows: u16) -> io::Result<Command> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "interactive SSH PTY is unsupported on Windows 7 targets",
    ))
}

#[cfg(all(test, target_vendor = "win7"))]
mod win7_pty_tests {
    #[test]
    fn interactive_shell_is_unsupported() {
        let error = match super::prepare_shell("xterm", 80, 24) {
            Err(error) => error,
            Ok(_) => panic!("Win7 PTY unexpectedly accepted"),
        };
        assert_eq!(error.kind(), std::io::ErrorKind::Unsupported);
        assert!(error.to_string().contains("Windows 7"));
    }
}

#[cfg(unix)]
fn valid_login_shell(path: &std::path::Path) -> bool {
    use std::os::unix::fs::PermissionsExt;

    if !path.is_absolute()
        || path
            .as_os_str()
            .as_encoded_bytes()
            .iter()
            .any(|byte| *byte < 0x20 || *byte == 0x7f)
    {
        return false;
    }
    std::fs::metadata(path)
        .is_ok_and(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
}

pub(super) async fn run(
    channel: russh::Channel<russh::server::Msg>,
    command: Command,
    cancellation: processkit::CancellationToken,
    allow_child_breakaway: bool,
) {
    run_with_start_error(
        channel,
        command,
        cancellation,
        "SSH exec failed to start\n",
        allow_child_breakaway,
    )
    .await;
}

pub(super) async fn run_shell(
    channel: russh::Channel<russh::server::Msg>,
    command: Command,
    cancellation: processkit::CancellationToken,
) {
    #[cfg(windows)]
    let message = "SSH PTY shell failed to start; Windows requires ConPTY support (Windows 10 version 1809 or later)\n";
    #[cfg(not(windows))]
    let message = "SSH PTY shell failed to start\n";
    run_with_start_error(channel, command, cancellation, message, false).await;
}

async fn run_with_start_error(
    channel: russh::Channel<russh::server::Msg>,
    command: Command,
    cancellation: processkit::CancellationToken,
    start_error: &'static str,
    allow_child_breakaway: bool,
) {
    let (mut remote_input, channel_output) = channel.split();
    let mut command = command.cancel_on(cancellation);
    command = command
        .stdout_raw_tee(channel_output.make_writer())
        .stderr_raw_tee(channel_output.make_writer_ext(Some(1)));

    #[cfg(windows)]
    let result = if allow_child_breakaway {
        processkit::JobRunner::new()
            .start_with_options(
                &command,
                processkit::ProcessGroupOptions::default().windows_allow_breakaway(true),
            )
            .await
    } else {
        command.start().await
    };
    #[cfg(not(windows))]
    let result = if allow_child_breakaway {
        // The SSH layer rejects this mode on unsupported platforms.
        return;
    } else {
        command.start().await
    };
    let mut child = match result {
        Ok(child) => child,
        Err(_) => {
            let _ = channel_output
                .extended_data_bytes(1, start_error.as_bytes())
                .await;
            let _ = channel_output.exit_status(127).await;
            let _ = channel_output.eof().await;
            let _ = channel_output.close().await;
            return;
        }
    };
    let Some(mut child_stdin) = child.take_stdin() else {
        let _ = channel_output.exit_status(127).await;
        let _ = channel_output.eof().await;
        let _ = channel_output.close().await;
        return;
    };

    let stdin = tokio::spawn(async move {
        let mut ssh_input = remote_input.make_reader();
        let mut buffer = [0_u8; 16 * 1024];
        loop {
            match ssh_input.read(&mut buffer).await {
                Ok(0) => return child_stdin.finish().await,
                Ok(count) => {
                    child_stdin.write(&buffer[..count]).await?;
                }
                Err(error) => return Err(error),
            }
        }
    });
    let outcome = child.drain().await;
    stdin.abort();

    if let Ok(outcome) = outcome
        && let Some(code) = outcome.code()
    {
        let _ = channel_output.exit_status(code as u32).await;
    }
    let _ = channel_output.eof().await;
    let _ = channel_output.close().await;
}

fn invalid_command(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

#[cfg(all(test, windows))]
mod windows_process_tests {
    use super::*;
    use processkit::Outcome;
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn powershell_processkit_pipe_preserves_binary_stdin_and_exit_status() {
        let command = r#"$inputStream=[Console]::OpenStandardInput();$outputStream=[Console]::OpenStandardOutput();$buffer=New-Object byte[] 8192;while(($count=$inputStream.Read($buffer,0,$buffer.Length))-gt 0){$outputStream.Write($buffer,0,$count)};$outputStream.Flush();$errorStream=[Console]::OpenStandardError();$errorBytes=[byte[]](0,255,69,82,82,13,10);$errorStream.Write($errorBytes,0,$errorBytes.Length);$errorStream.Flush();exit 7"#;
        let prepared = prepare_command(command);

        // The published processkit 3.3.4 API exposes raw byte tees, not
        // RawOutputSink. Draining both pipes concurrently avoids blocking
        // on the test's bounded duplex buffers.
        let (stdout_writer, mut stdout_reader) = tokio::io::duplex(16 * 1024);
        let (stderr_writer, mut stderr_reader) = tokio::io::duplex(4 * 1024);
        let mut process = prepared
            .expect("PowerShell command")
            .stdout_raw_tee(stdout_writer)
            .stderr_raw_tee(stderr_writer)
            .timeout(Duration::from_secs(15))
            .start()
            .await
            .expect("start PowerShell subprocess");

        let payload: Vec<u8> = (0..4096).map(|index| (index * 37) as u8).collect();
        let mut child_stdin = process.take_stdin().expect("piped child stdin");
        child_stdin
            .write(&payload)
            .await
            .expect("write exact binary stdin");
        child_stdin.finish().await.expect("close child stdin");

        let (outcome, stdout, stderr) = tokio::time::timeout(Duration::from_secs(20), async {
            tokio::try_join!(
                async { process.drain().await.map_err(io::Error::other) },
                async {
                    let mut bytes = Vec::new();
                    stdout_reader.read_to_end(&mut bytes).await?;
                    Ok::<_, io::Error>(bytes)
                },
                async {
                    let mut bytes = Vec::new();
                    stderr_reader.read_to_end(&mut bytes).await?;
                    Ok::<_, io::Error>(bytes)
                }
            )
        })
        .await
        .expect("PowerShell subprocess deadline")
        .expect("drain PowerShell subprocess and raw pipes");

        assert_eq!(outcome, Outcome::Exited(7));
        assert_eq!(stdout, payload);
        assert_eq!(stderr, [0_u8, 255, b'E', b'R', b'R', b'\r', b'\n']);
    }
}

#[cfg(test)]
mod tests {
    use super::validate_command;

    #[test]
    fn command_validation_rejects_empty_nul_invalid_utf8_and_oversized_input() {
        assert!(validate_command(b"", 8).is_err());
        assert!(validate_command(b" \t", 8).is_err());
        assert!(validate_command(b"echo\0no", 8).is_err());
        assert!(validate_command(&[0xff], 8).is_err());
        assert!(validate_command(b"123456789", 8).is_err());
        assert_eq!(
            validate_command(b"echo ok", 8).expect("valid command"),
            "echo ok"
        );
    }
}

#[cfg(all(test, unix))]
mod pty_tests {
    use super::prepare_shell;
    use processkit::Outcome;
    use std::io;
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn processkit_pty_forwards_interactive_input_and_raw_output() {
        let (writer, mut reader) = tokio::io::duplex(16 * 1024);
        let mut process = prepare_shell("xterm", 80, 24)
            .expect("prepare interactive shell")
            .stdout_raw_tee(writer)
            .start()
            .await
            .expect("start real PTY shell");
        let mut input = process.take_stdin().expect("PTY input handle");
        input
            .write(b"printf 'HOSTLINK_PTY_UNIT_MARKER'; exit 7\n")
            .await
            .expect("write command to PTY");
        drop(input);

        let (outcome, output) = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            tokio::try_join!(
                async { process.drain().await.map_err(io::Error::other) },
                async {
                    let mut output = Vec::new();
                    reader.read_to_end(&mut output).await?;
                    Ok::<_, io::Error>(output)
                }
            )
        })
        .await
        .expect("PTY shell deadline")
        .expect("drain real PTY shell");

        assert_eq!(outcome, Outcome::Exited(7));
        assert!(
            output
                .windows(b"HOSTLINK_PTY_UNIT_MARKER".len())
                .any(|window| window == b"HOSTLINK_PTY_UNIT_MARKER")
        );
    }
}
