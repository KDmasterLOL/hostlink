//! Target-side sshd process spawning and readiness checks.

#[cfg(windows)]
use super::sshd_host::StartGate;
use super::*;
use crate::environment::AgentEnvironmentPolicy;

#[cfg(windows)]
pub(super) fn spawn_ssh_server(
    config: &SshServerConfig,
    environment: &AgentEnvironmentPolicy,
) -> io::Result<TunnelChild> {
    let gate = StartGate::create()?;
    let agent = env::current_exe()?;
    let mut command = background_command(agent);
    command
        .arg("__sshd-host")
        .arg("--program")
        .arg(&config.program)
        .arg("--config")
        .arg(&config.config)
        .arg("--start-event")
        .arg(gate.name())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());
    let mut managed = managed_child(command, "user-mode sshd host", environment)?;
    if let Err(error) = gate.signal() {
        let _ = managed.terminate();
        return Err(io::Error::new(
            error.kind(),
            format!("failed to release user-mode sshd start gate: {error}"),
        ));
    }
    managed._sshd_start_gate = Some(gate);
    Ok(managed)
}

#[cfg(not(windows))]
pub(super) fn spawn_ssh_server(
    config: &SshServerConfig,
    environment: &AgentEnvironmentPolicy,
) -> io::Result<TunnelChild> {
    let mut command = background_command(&config.program);
    command
        .arg("-D")
        .arg("-e")
        .arg("-f")
        .arg(&config.config)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());
    managed_child(command, "user-mode sshd", environment)
}

pub(super) async fn wait_for_ssh_server(
    config: &SshServerConfig,
    child: &mut TunnelChild,
) -> io::Result<()> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while tokio::time::Instant::now() < deadline {
        if let Some(status) = child.try_wait()? {
            return Err(io::Error::other(format!(
                "user-mode sshd exited before becoming ready: {status}"
            )));
        }
        if matches!(
            tokio::time::timeout(
                Duration::from_millis(100),
                tokio::net::TcpStream::connect(("127.0.0.1", config.port)),
            )
            .await,
            Ok(Ok(_))
        ) {
            return Ok(());
        }
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if !remaining.is_zero() {
            tokio::time::sleep(Duration::from_millis(100).min(remaining)).await;
        }
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        format!("user-mode sshd did not listen on 127.0.0.1:{}", config.port),
    ))
}

fn managed_child(
    mut command: std::process::Command,
    description: &str,
    environment: &AgentEnvironmentPolicy,
) -> io::Result<TunnelChild> {
    environment.apply_safe_base(&mut command);
    let child = OwnedProcess::spawn(command).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("failed to spawn owned {description} process tree: {error}"),
        )
    })?;
    Ok(TunnelChild {
        child,
        #[cfg(windows)]
        _sshd_start_gate: None,
    })
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader};
    use windows_sys::Win32::{
        Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0},
        System::Threading::{OpenProcess, PROCESS_SYNCHRONIZE, WaitForSingleObject},
    };

    struct TestHandle(HANDLE);

    impl TestHandle {
        fn open(pid: u32) -> io::Result<Self> {
            // SAFETY: pid comes from a process spawned by this test; only synchronization access
            // is requested and the returned handle is owned by this guard.
            let handle = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, pid) };
            if handle.is_null() {
                return Err(io::Error::last_os_error());
            }
            Ok(Self(handle))
        }

        fn is_signaled(&self, timeout_ms: u32) -> bool {
            // SAFETY: the handle is live for the duration of this guard.
            (unsafe { WaitForSingleObject(self.0, timeout_ms) }) == WAIT_OBJECT_0
        }
    }

    impl Drop for TestHandle {
        fn drop(&mut self) {
            // SAFETY: this guard owns the handle and closes it exactly once.
            let _ = unsafe { CloseHandle(self.0) };
        }
    }

    #[test]
    fn tunnel_owner_tracks_and_terminates_launcher_descendants() {
        let script = "$p=Start-Process powershell.exe -ArgumentList '-NoLogo','-NoProfile','-NonInteractive','-Command','Start-Sleep -Seconds 30' -PassThru; Write-Output $p.Id; exit 0";
        let mut command = background_command("powershell.exe");
        command
            .args([
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                script,
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());

        let mut child = managed_child(
            command,
            "tunnel ownership fixture",
            &AgentEnvironmentPolicy::default(),
        )
        .expect("spawn fixture");
        let launcher = TestHandle::open(child.child.id()).expect("open launcher");
        let stdout = child
            .child
            .take_stdout()
            .expect("fixture stdout must be piped");
        let mut line = String::new();
        BufReader::new(stdout)
            .read_line(&mut line)
            .expect("read descendant pid");
        let descendant_pid = line.trim().parse::<u32>().expect("descendant pid");
        let descendant = TestHandle::open(descendant_pid).expect("open descendant");

        assert!(
            launcher.is_signaled(5_000),
            "launcher must exit while its descendant remains alive"
        );
        assert!(
            !descendant.is_signaled(0),
            "descendant must still be alive before explicit tunnel termination"
        );
        assert_eq!(
            child.try_wait().expect("whole-tree try_wait"),
            None,
            "launcher exit is not whole-tree completion"
        );

        child.terminate().expect("terminate tunnel tree");
        assert!(
            descendant.is_signaled(5_000),
            "tunnel termination must terminate the descendant tree"
        );
    }
}

#[cfg(test)]
mod environment_tests {
    use super::*;
    use std::io::Read;

    fn environment_listing_command() -> std::process::Command {
        #[cfg(windows)]
        {
            let mut command = background_command("cmd.exe");
            command.args(["/d", "/c", "set"]);
            command
        }
        #[cfg(not(windows))]
        {
            background_command("env")
        }
    }

    fn environment_contains(output: &str, name: &str) -> bool {
        output.lines().any(|line| {
            let Some((candidate, _)) = line.split_once('=') else {
                return false;
            };
            if cfg!(windows) {
                candidate.eq_ignore_ascii_case(name)
            } else {
                candidate == name
            }
        })
    }

    #[test]
    fn managed_children_receive_only_safe_base_environment() {
        let mut command = environment_listing_command();
        command
            .env("CUSTOM_AGENT_CONTROL_SECRET", "must-not-leak")
            .env("UNRELATED_SERVICE_CONFIG", "must-not-leak")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());

        let policy = AgentEnvironmentPolicy::new("CUSTOM_AGENT_CONTROL_SECRET");
        let mut child = managed_child(command, "environment isolation fixture", &policy)
            .expect("spawn fixture");
        let mut output = String::new();
        child
            .child
            .take_stdout()
            .expect("fixture stdout")
            .read_to_string(&mut output)
            .expect("read child environment");
        let status = child.wait().expect("wait fixture");
        assert!(status.success(), "environment fixture failed: {status}");

        assert!(
            environment_contains(&output, "PATH"),
            "safe-base PATH must remain available"
        );
        assert!(
            !environment_contains(&output, "CUSTOM_AGENT_CONTROL_SECRET"),
            "configured control-secret environment must not reach managed children"
        );
        assert!(
            !environment_contains(&output, "UNRELATED_SERVICE_CONFIG"),
            "unrelated ambient environment must not reach managed children"
        );
    }
}
