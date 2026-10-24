//! Platform-specific detached-process configuration, cancellation, and liveness probes.

use super::*;

/// Versioned OS-maintained process creation token persisted beside a PID.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct ProcessIdentity {
    /// Identity encoding version.
    pub(super) version: u32,
    /// PID the token was captured for.
    pub(super) pid: u32,
    /// Kernel-maintained process creation token.
    pub(super) start: String,
}

/// Result of checking whether a persisted process identity still owns its PID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ProcessStatus {
    /// PID and creation token still identify the same process.
    Alive,
    /// The process is absent or its PID now belongs to a different process.
    Dead,
    /// The OS could not prove identity or the persisted record is inconsistent.
    Unverifiable,
}

impl ProcessIdentity {
    /// Reads the OS-maintained creation token for `pid`.
    pub(super) fn capture(pid: u32) -> Option<Self> {
        let start = match process_start_identity(pid) {
            Some(start) => start,
            None if process_absent(pid) => "absent-at-capture".to_owned(),
            None => return None,
        };
        Some(Self {
            version: 1,
            pid,
            start,
        })
    }

    /// Checks both the PID and the captured creation token against the operating system.
    pub(super) fn status(&self) -> ProcessStatus {
        if self.version != 1 {
            return ProcessStatus::Unverifiable;
        }
        let Some(current) = process_start_identity(self.pid) else {
            return if process_absent(self.pid) {
                ProcessStatus::Dead
            } else {
                ProcessStatus::Unverifiable
            };
        };
        compare_process_start(&self.start, Some(&current))
    }
}

fn compare_process_start(captured: &str, current: Option<&str>) -> ProcessStatus {
    match current {
        Some(current) if current.starts_with("exited:") => ProcessStatus::Dead,
        Some(current) if current == captured => ProcessStatus::Alive,
        Some(_) => ProcessStatus::Dead,
        None => ProcessStatus::Unverifiable,
    }
}

#[cfg(target_os = "linux")]
fn process_start_identity(pid: u32) -> Option<String> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    linux_process_start_identity_from_stat(&stat)
}

#[cfg(target_os = "linux")]
fn linux_process_start_identity_from_stat(stat: &str) -> Option<String> {
    // comm is parenthesized but may itself contain spaces and ')'; split after its final delimiter.
    let fields = stat
        .rsplit_once(") ")?
        .1
        .split_whitespace()
        .collect::<Vec<_>>();
    // The first value after comm is field 3; starttime is field 22 (index 19 here).
    let state = fields.first()?;
    let start = fields.get(19)?;
    start.parse::<u64>().ok()?;
    Some(if matches!(*state, "Z" | "X") {
        format!("exited:{start}")
    } else {
        (*start).to_owned()
    })
}

#[cfg(windows)]
fn process_start_identity(pid: u32) -> Option<String> {
    use windows_sys::Win32::Foundation::{CloseHandle, FILETIME, WAIT_OBJECT_0, WAIT_TIMEOUT};
    use windows_sys::Win32::System::Threading::{
        GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
        WaitForSingleObject,
    };

    // Query-only creation identity plus SYNCHRONIZE permits a zero-timeout termination probe.
    // A terminated process can still be opened while another handle to it exists; treating
    // that state as unverifiable would leave its durable job falsely Running.
    let handle = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
            0,
            pid,
        )
    };
    if handle.is_null() {
        return None;
    }
    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    // SAFETY: all FILETIME pointers are valid writable locals and the handle is open.
    let read = unsafe { GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user) };
    // SAFETY: the handle has SYNCHRONIZE access; zero timeout observes state without blocking.
    let wait = unsafe { WaitForSingleObject(handle, 0) };
    // SAFETY: this function owns the handle returned by OpenProcess.
    unsafe { CloseHandle(handle) };
    if read == 0 {
        return None;
    }
    let start = format!("{}:{}", creation.dwHighDateTime, creation.dwLowDateTime);
    match wait {
        WAIT_TIMEOUT => Some(start),
        WAIT_OBJECT_0 => Some(format!("exited:{start}")),
        _ => None,
    }
}

#[cfg(not(any(target_os = "linux", windows)))]
fn process_start_identity(_pid: u32) -> Option<String> {
    None
}

#[cfg(unix)]
pub(super) fn process_absent(pid: u32) -> bool {
    if pid == 0 || pid > i32::MAX as u32 {
        return true;
    }
    // SAFETY: signal 0 performs existence/permission check without delivering a signal.
    if unsafe { libc::kill(pid as i32, 0) } == 0 {
        return false;
    }
    io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
}

#[cfg(windows)]
pub(super) fn process_absent(pid: u32) -> bool {
    if pid == 0 {
        return true;
    }
    use windows_sys::Win32::Foundation::ERROR_INVALID_PARAMETER;
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};
    // SAFETY: query-only handle is closed immediately when OpenProcess succeeds.
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if handle.is_null() {
        return io::Error::last_os_error().raw_os_error() == Some(ERROR_INVALID_PARAMETER as i32);
    }
    // SAFETY: the handle was returned by OpenProcess and is closed exactly once.
    unsafe { windows_sys::Win32::Foundation::CloseHandle(handle) };
    false
}

#[cfg(not(any(unix, windows)))]
pub(super) fn process_absent(_pid: u32) -> bool {
    false
}

#[cfg(unix)]
pub(super) fn configure_detached_process(command: &mut Command) {
    use std::os::unix::process::CommandExt;
    command.process_group(0);
}

#[cfg(windows)]
pub(super) fn configure_detached_process(command: &mut Command) {
    use windows_sys::Win32::System::Threading::CREATE_NEW_PROCESS_GROUP;
    configure_background_process_with_flags(command, CREATE_NEW_PROCESS_GROUP);
}

#[cfg(test)]
mod identity_tests {
    use super::*;

    #[test]
    fn reused_pid_with_a_different_creation_token_is_dead() {
        assert_eq!(
            compare_process_start("original-start", Some("reused-pid-start")),
            ProcessStatus::Dead
        );
        assert_eq!(
            compare_process_start("original-start", Some("original-start")),
            ProcessStatus::Alive
        );
        assert_eq!(
            compare_process_start("exited:123", Some("exited:123")),
            ProcessStatus::Dead
        );
        assert_eq!(
            compare_process_start("original-start", None),
            ProcessStatus::Unverifiable
        );
    }

    #[cfg(windows)]
    struct OwnedChild(Option<std::process::Child>);

    #[cfg(windows)]
    impl OwnedChild {
        fn wait(mut self) -> std::io::Result<std::process::ExitStatus> {
            let status = self.0.as_mut().expect("child is present").wait()?;
            self.0.take();
            Ok(status)
        }
    }

    #[cfg(windows)]
    impl Drop for OwnedChild {
        fn drop(&mut self) {
            if let Some(mut child) = self.0.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_get_process_times_tracks_owned_process_until_exit() {
        use std::process::{Command, Stdio};

        let current_pid = std::process::id();
        let current_identity = ProcessIdentity::capture(current_pid)
            .expect("GetProcessTimes should capture the current test process");
        assert_eq!(current_identity.version, 1);
        assert_eq!(current_identity.pid, current_pid);
        assert!(!current_identity.start.is_empty());
        assert_eq!(current_identity.status(), ProcessStatus::Alive);

        let child = Command::new("powershell.exe")
            .args([
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Start-Sleep -Seconds 2",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("start bounded owned PowerShell child");
        let child = OwnedChild(Some(child));
        let child_pid = child.0.as_ref().expect("child is present").id();
        let child_identity = ProcessIdentity::capture(child_pid)
            .expect("GetProcessTimes should capture the owned child");

        assert_eq!(child_identity.version, 1);
        assert_eq!(child_identity.pid, child_pid);
        assert!(!child_identity.start.is_empty());
        assert_eq!(child_identity.status(), ProcessStatus::Alive);

        let mut mismatched_identity = child_identity.clone();
        mismatched_identity.start.push_str(":reused");
        assert_eq!(mismatched_identity.status(), ProcessStatus::Dead);

        let exit_status = child.wait().expect("wait for owned bounded child");
        assert!(exit_status.success(), "child exited with {exit_status}");
        assert_eq!(child_identity.status(), ProcessStatus::Dead);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_stat_parser_uses_field_22_after_a_parenthesized_command() {
        let stat =
            "42 (worker ) with spaces) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 987654";
        assert_eq!(
            linux_process_start_identity_from_stat(stat),
            Some("987654".into())
        );
    }
}
