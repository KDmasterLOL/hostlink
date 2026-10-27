use super::*;

pub(super) struct OwnedProcess {
    pub(super) handle: HANDLE,
    pub(super) pid: u32,
}

impl Drop for OwnedProcess {
    fn drop(&mut self) {
        // SAFETY: this type uniquely owns a valid process handle.
        unsafe { CloseHandle(self.handle) };
    }
}

pub(super) fn spawn(
    record: &InstallRecord,
    maintenance_start: bool,
    capability: Option<&str>,
) -> io::Result<OwnedProcess> {
    use std::os::windows::process::CommandExt;
    let mut command = Command::new(&record.executable);
    command
        .arg("run")
        .arg(format!("--config={}", record.config.display()))
        .arg("--managed-service")
        .args(if maintenance_start {
            Some("--maintenance-start")
        } else {
            None
        });
    command
        .stdin(if maintenance_start {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(windows_sys::Win32::System::Threading::CREATE_NO_WINDOW);
    let mut child = command.spawn()?;
    if let Some(capability) = capability {
        let mut input = child.stdin.take().ok_or_else(|| {
            invalid("maintenance candidate stdin capability pipe was not created")
        })?;
        input.write_all(capability.as_bytes())?;
        input.flush()?;
    }
    let process = open_owned_process(child.id(), record)?;
    drop(child); // Detach without terminating; keep the synchronized handle.
    Ok(process)
}
pub(super) fn launch_and_wait(record: &InstallRecord) -> io::Result<()> {
    let process = spawn(record, false, None)?;
    for _ in 0..40 {
        match pipe_request(record, "STATUS") {
            Ok(reply) if running_pid(&reply) == Some(process.pid) => return Ok(()),
            Ok(_) => {
                return Err(invalid(
                    "lifecycle endpoint exists but did not authenticate this Agent root",
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        "Agent did not establish its authenticated lifecycle control pipe",
    ))
}
pub(super) fn render_command(record: &InstallRecord) -> String {
    format!(
        "{} //B //NoLogo {}",
        windows_quote(&record.launcher_executable.to_string_lossy()),
        windows_quote(&record.startup_script.to_string_lossy())
    )
}
pub(super) fn render_script(record: &InstallRecord) -> String {
    let command = format!(
        "{} run --config={} --managed-service",
        windows_quote(&record.executable.to_string_lossy()),
        windows_quote(&record.config.to_string_lossy())
    );
    format!(
        "CreateObject(\"WScript.Shell\").Run \"{}\", 0, False\r\n",
        command.replace('"', "\"\"")
    )
}
pub(super) fn system_wscript() -> io::Result<PathBuf> {
    let mut buffer = vec![0u16; 32_768];
    // SAFETY: GetSystemDirectoryW writes at most the supplied UTF-16 buffer length.
    let length = unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) } as usize;
    if length == 0 || length >= buffer.len() {
        return Err(io::Error::last_os_error());
    }
    let directory = String::from_utf16_lossy(&buffer[..length]);
    Ok(PathBuf::from(directory).join("wscript.exe"))
}
pub(super) fn pipe_request(record: &InstallRecord, action: &str) -> io::Result<String> {
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::windows::named_pipe::ClientOptions,
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let mut pipe = ClientOptions::new().open(&record.pipe_name)?;
        pipe.write_all(format!("{action} {}", record.control_token).as_bytes())
            .await?;
        let mut bytes = Vec::with_capacity(64);
        let mut chunk = [0u8; 64];
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let count = pipe.read(&mut chunk).await?;
                if count == 0 {
                    break;
                }
                if bytes.len() + count > MAX_PIPE_MESSAGE {
                    return Err(invalid("Agent lifecycle response exceeds size limit"));
                }
                bytes.extend_from_slice(&chunk[..count]);
                if bytes.contains(&b'\n') {
                    break;
                }
            }
            Ok::<(), io::Error>(())
        })
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "Agent lifecycle pipe response timed out",
            )
        })??;
        String::from_utf8(bytes)
            .map(|value| value.trim().to_owned())
            .map_err(io::Error::other)
    })
}
pub(super) fn running_pid(reply: &str) -> Option<u32> {
    reply
        .strip_prefix("RUNNING ")
        .and_then(|value| value.parse::<u32>().ok())
        .filter(|pid| *pid != 0)
}
pub(super) fn stopping_pid(reply: &str) -> Option<u32> {
    reply
        .strip_prefix("STOPPING ")
        .and_then(|value| value.parse::<u32>().ok())
        .filter(|pid| *pid != 0)
}
pub(super) fn process_pid(reply: &str) -> Option<u32> {
    running_pid(reply).or_else(|| stopping_pid(reply))
}
pub(super) fn open_owned_process(pid: u32, record: &InstallRecord) -> io::Result<OwnedProcess> {
    // SAFETY: OpenProcess receives a PID obtained from the authenticated private pipe.
    let handle = unsafe { OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if handle.is_null() {
        return Err(io::Error::other(format!(
            "cannot open authenticated Agent PID {pid} for identity verification and synchronized wait: {}",
            io::Error::last_os_error()
        )));
    }
    let process = OwnedProcess { handle, pid };
    let mut token = std::ptr::null_mut();
    // SAFETY: handle is valid and token is an initialized writable output pointer.
    if unsafe { OpenProcessToken(handle, TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::other(format!(
            "cannot open authenticated Agent process token: {}",
            io::Error::last_os_error()
        )));
    }
    struct OwnedToken(HANDLE);
    impl Drop for OwnedToken {
        fn drop(&mut self) {
            // SAFETY: this type uniquely owns a valid token handle.
            unsafe { CloseHandle(self.0) };
        }
    }
    let token = OwnedToken(token);
    let mut buffer = vec![0usize; 512];
    let mut returned = 0u32;
    // SAFETY: the aligned buffer is writable and large enough for a TOKEN_USER.
    if unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            std::mem::size_of_val(&buffer) as u32,
            &mut returned,
        )
    } == 0
    {
        return Err(io::Error::other(format!(
            "cannot read authenticated Agent process owner SID: {}",
            io::Error::last_os_error()
        )));
    }
    let process_user = buffer.as_ptr().cast::<TOKEN_USER>();
    let current =
        windows_permissions::utilities::current_process_sid().map_err(io::Error::other)?;
    // SAFETY: GetTokenInformation populated a TOKEN_USER in the aligned buffer.
    if unsafe { EqualSid((*process_user).User.Sid, current.as_ptr().cast()) } == 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "authenticated lifecycle PID belongs to a different Windows user",
        ));
    }
    let mut image = vec![0u16; 32_768];
    let mut image_len = image.len() as u32;
    // SAFETY: image is writable and image_len contains its UTF-16 capacity.
    if unsafe { QueryFullProcessImageNameW(handle, 0, image.as_mut_ptr(), &mut image_len) } == 0 {
        return Err(io::Error::other(format!(
            "cannot verify authenticated Agent process image path: {}",
            io::Error::last_os_error()
        )));
    }
    use std::os::windows::ffi::OsStringExt;
    let image_path = PathBuf::from(std::ffi::OsString::from_wide(&image[..image_len as usize]))
        .canonicalize()?;
    if image_path != record.executable || sha256_file(&image_path)? != record.executable_sha256 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "authenticated lifecycle PID image does not match the owned Agent path and SHA-256",
        ));
    }
    Ok(process)
}
