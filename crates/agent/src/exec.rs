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
        if !safe_windows_user_context()? {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "SSH exec requires a verified non-elevated, non-LocalSystem Windows user context",
            ));
        }
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

pub(super) async fn run(
    channel: russh::Channel<russh::server::Msg>,
    command: Command,
    cancellation: processkit::CancellationToken,
) {
    let (mut remote_input, channel_output) = channel.split();
    let mut command = command.cancel_on(cancellation);
    command = command
        .stdout_raw_tee(channel_output.make_writer())
        .stderr_raw_tee(channel_output.make_writer_ext(Some(1)));

    let mut child = match command.start().await {
        Ok(child) => child,
        Err(_) => {
            let _ = channel_output
                .extended_data_bytes(1, b"SSH exec failed to start\n".as_slice())
                .await;
            let _ = channel_output.exit_status(127).await;
            let _ = channel_output.eof().await;
            let _ = channel_output.close().await;
            return;
        }
    };
    let Some(mut child_stdin) = child.take_stdin() else {
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
        let safe_context = safe_windows_user_context().expect("inspect Windows user context");
        let prepared = prepare_command(command);
        if !safe_context {
            assert!(matches!(
                prepared,
                Err(ref error) if error.kind() == io::ErrorKind::PermissionDenied
            ));
            return;
        }

        // The published processkit 3.3.4 API exposes raw byte tees, not
        // RawOutputSink. Draining both pipes concurrently avoids blocking
        // on the test's bounded duplex buffers.
        let (stdout_writer, mut stdout_reader) = tokio::io::duplex(16 * 1024);
        let (stderr_writer, mut stderr_reader) = tokio::io::duplex(4 * 1024);
        let mut process = prepared
            .expect("verified Windows user context and PowerShell command")
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

#[cfg(windows)]
pub(super) fn safe_windows_user_context() -> io::Result<bool> {
    use std::mem::{size_of, zeroed};
    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE};
    use windows_sys::Win32::Security::{
        CreateWellKnownSid, EqualSid, GetLengthSid, GetTokenInformation, SID, TOKEN_ELEVATION,
        TOKEN_QUERY, TokenElevation, TokenUser, WELL_KNOWN_SID_TYPE, WinLocalSystemSid,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    // SAFETY: GetCurrentProcess returns a pseudo-handle owned by the current process.
    let process = unsafe { GetCurrentProcess() };
    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: token is a valid out pointer and the process pseudo-handle is valid.
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    struct TokenHandle(HANDLE);
    impl Drop for TokenHandle {
        fn drop(&mut self) {
            // SAFETY: OpenProcessToken initialized this owned handle and Drop runs once.
            unsafe { CloseHandle(self.0) };
        }
    }
    let token = TokenHandle(token);

    // SAFETY: TOKEN_ELEVATION is a plain integer struct and all-zero is a valid output buffer.
    let mut elevation: TOKEN_ELEVATION = unsafe { zeroed() };
    let mut returned = 0;
    // SAFETY: elevation and returned are writable buffers of the documented sizes.
    if unsafe {
        GetTokenInformation(
            token.0,
            TokenElevation,
            (&mut elevation as *mut TOKEN_ELEVATION).cast(),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if elevation.TokenIsElevated != 0 {
        return Ok(false);
    }

    let user_storage_bytes: usize = 16 * 1024;
    let user_storage_words = user_storage_bytes.div_ceil(size_of::<usize>());
    let mut user_storage = vec![0_usize; user_storage_words];
    let user_buffer_bytes = user_storage.len() * size_of::<usize>();
    // SAFETY: usize storage provides TOKEN_USER alignment and enough writable bytes for its
    // variable-size data; the allocation remains alive through all SID validation below.
    if unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            user_storage.as_mut_ptr().cast(),
            user_buffer_bytes as u32,
            &mut returned,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if returned as usize > user_buffer_bytes
        || (returned as usize) < size_of::<windows_sys::Win32::Security::TOKEN_USER>()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows returned an invalid token user buffer length",
        ));
    }
    // SAFETY: GetTokenInformation succeeded and returned at least a complete, aligned TOKEN_USER.
    let user = unsafe {
        &*user_storage
            .as_ptr()
            .cast::<windows_sys::Win32::Security::TOKEN_USER>()
    };
    let user_buffer_start = user_storage.as_ptr() as usize;
    let user_buffer_end = user_buffer_start
        .checked_add(returned as usize)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "token user buffer overflow"))?;
    let sid_start = user.User.Sid as usize;
    let sid_header_end = sid_start
        .checked_add(size_of::<SID>())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "token SID pointer overflow"))?;
    if sid_start < user_buffer_start || sid_header_end > user_buffer_end {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows returned a token SID outside its user buffer",
        ));
    }
    // SAFETY: the pointer is within the live TokenUser buffer and includes a complete SID header.
    let sid_bytes = unsafe { GetLengthSid(user.User.Sid) } as usize;
    if sid_bytes < size_of::<SID>()
        || sid_start
            .checked_add(sid_bytes)
            .is_none_or(|end| end > user_buffer_end)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows returned a truncated token SID",
        ));
    }
    let mut system_sid = [0_u8; 68];
    let mut sid_size = system_sid.len() as u32;
    // SAFETY: system_sid is writable storage for a well-known SID and sid_size is its capacity.
    if unsafe {
        CreateWellKnownSid(
            WinLocalSystemSid as WELL_KNOWN_SID_TYPE,
            std::ptr::null_mut(),
            system_sid.as_mut_ptr().cast(),
            &mut sid_size,
        )
    } == 0
    {
        // SAFETY: GetLastError reads the calling thread's last OS error value.
        let error = unsafe { GetLastError() };
        return Err(io::Error::from_raw_os_error(error as i32));
    }
    // SAFETY: both pointers reference valid SID structures returned/contained by the OS.
    Ok(unsafe { EqualSid(user.User.Sid.cast(), system_sid.as_mut_ptr().cast()) } == 0)
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
