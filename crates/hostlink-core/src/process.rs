#[cfg(unix)]
use process_wrap::std::ProcessGroup;
use process_wrap::std::{ChildWrapper, CommandWrap, KillOnDrop};
use std::ffi::OsStr;
use std::process::{ChildStderr, ChildStdin, ChildStdout, Command, ExitStatus};

#[cfg(any(windows, test))]
const WINDOWS_CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// Default byte ceiling used by toolkit run-to-completion process capture.
///
/// Domain crates may select a stricter or larger bound when their protocol requires it.
pub const DEFAULT_PROCESS_CAPTURE_BYTES: usize = 256 * 1024;

/// Runtime-neutral RAII owner for one spawned process tree.
///
/// The wrapper owns only OS lifecycle mechanics. Product crates remain responsible for timeout
/// policy, diagnostics, tracing, operation labels and domain-specific error classification.
#[derive(Debug)]
pub struct OwnedProcess {
    child: Box<dyn ChildWrapper>,
}

impl OwnedProcess {
    /// Spawn one child as the leader of an owned process tree.
    pub fn spawn(command: Command) -> std::io::Result<Self> {
        let mut command = CommandWrap::from(command);
        configure_owned_process(&mut command);
        let child = command.spawn()?;
        Ok(Self { child })
    }

    /// Returns the root child process identifier.
    pub fn id(&self) -> u32 {
        self.child.id()
    }

    /// Takes ownership of the child's piped stdin, if one was configured.
    pub fn take_stdin(&mut self) -> Option<ChildStdin> {
        self.child.stdin().take()
    }

    /// Takes ownership of the child's piped stdout, if one was configured.
    pub fn take_stdout(&mut self) -> Option<ChildStdout> {
        self.child.stdout().take()
    }

    /// Takes ownership of the child's piped stderr, if one was configured.
    pub fn take_stderr(&mut self) -> Option<ChildStderr> {
        self.child.stderr().take()
    }

    /// Polls for completion of the entire owned process tree without blocking.
    ///
    /// The wrapped process-group/Job-Object implementation owns whole-tree completion semantics.
    pub fn try_wait(&mut self) -> std::io::Result<Option<ExitStatus>> {
        self.child.try_wait()
    }

    /// Wait until the launcher and every process still attached to its owned tree are gone.
    pub fn wait(&mut self) -> std::io::Result<ExitStatus> {
        self.child.wait()
    }

    /// Terminate the owned tree and synchronously reap it.
    pub fn terminate(&mut self) -> std::io::Result<()> {
        self.child.start_kill()?;
        self.wait().map(|_| ())
    }
}

fn configure_owned_process(command: &mut CommandWrap) {
    #[cfg(unix)]
    command.wrap(ProcessGroup::leader());
    #[cfg(windows)]
    {
        use process_wrap::std::{CreationFlags, JobObject};
        use windows::Win32::System::Threading::PROCESS_CREATION_FLAGS;

        command.wrap(CreationFlags(PROCESS_CREATION_FLAGS(
            WINDOWS_CREATE_NO_WINDOW,
        )));
        command.wrap(JobObject);
    }
    command.wrap(KillOnDrop);
}

/// Build a command intended for toolkit-owned background/non-interactive execution.
///
/// Use this raw Command constructor only when the caller owns the child lifecycle, stdio,
/// terminal attachment, or process group. Ordinary run-to-completion commands use
/// ordinary_command instead.
///
/// On Windows, console-subsystem children are created without allocating or showing a console
/// window. Other platforms retain the standard `Command` behavior.
pub fn background_command<S: AsRef<OsStr>>(program: S) -> Command {
    let mut command = Command::new(program);
    configure_background_process(&mut command);
    command
}

/// Apply the toolkit background-process policy to an existing command.
pub fn configure_background_process(command: &mut Command) {
    configure_background_process_with_flags(command, 0);
}

/// Apply the background-process policy while preserving caller-owned Windows creation flags.
///
/// This is used by process-tree owners that also need flags such as `CREATE_SUSPENDED` or
/// `CREATE_NEW_PROCESS_GROUP`.
pub fn configure_background_process_with_flags(command: &mut Command, extra_flags: u32) {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(windows_background_creation_flags(extra_flags));
    }
    #[cfg(not(windows))]
    {
        let _ = (command, extra_flags);
    }
}

/// Serialize UTF-8 arguments with the Microsoft C runtime quoting convention used by
/// `CreateProcessW` consumers. Callers choose whether the program name is part of `arguments`.
pub fn windows_command_line<I, S>(arguments: I) -> String
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    arguments
        .into_iter()
        .map(|argument| quote_windows_argument(argument.as_ref()))
        .collect::<Vec<_>>()
        .join(" ")
}

fn quote_windows_argument(argument: &str) -> String {
    if !argument.is_empty()
        && !argument
            .chars()
            .any(|character| character.is_whitespace() || character == '"')
    {
        return argument.to_owned();
    }

    let mut quoted = String::with_capacity(argument.len() + 2);
    quoted.push('"');
    let mut backslashes = 0usize;
    for character in argument.chars() {
        if character == '\\' {
            backslashes += 1;
            continue;
        }
        if character == '"' {
            quoted.extend(std::iter::repeat_n('\\', backslashes * 2 + 1));
            quoted.push('"');
            backslashes = 0;
            continue;
        }
        quoted.extend(std::iter::repeat_n('\\', backslashes));
        backslashes = 0;
        quoted.push(character);
    }
    quoted.extend(std::iter::repeat_n('\\', backslashes * 2));
    quoted.push('"');
    quoted
}

#[cfg(any(windows, test))]
fn windows_background_creation_flags(extra_flags: u32) -> u32 {
    WINDOWS_CREATE_NO_WINDOW | extra_flags
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn regression_inv_077_windows_background_flags_preserve_extra_flags_and_hide_console() {
        const CREATE_SUSPENDED: u32 = 0x0000_0004;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        let flags = windows_background_creation_flags(CREATE_SUSPENDED | CREATE_NEW_PROCESS_GROUP);
        assert_eq!(flags & WINDOWS_CREATE_NO_WINDOW, WINDOWS_CREATE_NO_WINDOW);
        assert_eq!(flags & CREATE_SUSPENDED, CREATE_SUSPENDED);
        assert_eq!(flags & CREATE_NEW_PROCESS_GROUP, CREATE_NEW_PROCESS_GROUP);
    }

    #[cfg(unix)]
    #[test]
    fn owned_process_try_wait_requires_process_group_drain() {
        let mut command = background_command("sh");
        command.args(["-c", "sleep 30 & exit 0"]);
        command
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        let mut process = OwnedProcess::spawn(command).expect("spawn process group fixture");
        std::thread::sleep(std::time::Duration::from_millis(100));
        assert_eq!(
            process.try_wait().expect("poll owned process"),
            None,
            "launcher exit must not report whole-tree completion while a descendant remains"
        );
        process
            .terminate()
            .expect("terminate process group fixture");
    }

    #[test]
    fn windows_command_line_quotes_empty_spaces_quotes_and_trailing_backslashes() {
        assert_eq!(
            windows_command_line([
                "plain",
                "",
                "a b",
                r#"Srvr="websrv";Ref="test 2";"#,
                r"C:\path with space\",
            ]),
            r#"plain "" "a b" "Srvr=\"websrv\";Ref=\"test 2\";" "C:\path with space\\""#
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_owned_process_drop_terminates_descendant_tree() {
        use std::io::{BufRead, BufReader};

        let directory = tempfile::tempdir().expect("tempdir");
        let marker = directory.path().join("descendant-survived.txt");
        let script = "$p=Start-Process powershell.exe -ArgumentList '-NoLogo','-NoProfile','-NonInteractive','-Command','Start-Sleep -Milliseconds 1200; Set-Content -LiteralPath $env:ONEC_DROP_MARKER -Value survived' -PassThru; Write-Output $p.Id; exit 0";
        let mut command = background_command("powershell.exe");
        command
            .args([
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                script,
            ])
            .env("ONEC_DROP_MARKER", &marker)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null());

        let mut process = OwnedProcess::spawn(command).expect("spawn owned launcher");
        let stdout = process
            .take_stdout()
            .expect("launcher stdout must be piped");
        let mut line = String::new();
        BufReader::new(stdout)
            .read_line(&mut line)
            .expect("read descendant pid");
        assert!(
            line.trim().parse::<u32>().is_ok(),
            "launcher must report a descendant pid, got {line:?}"
        );

        drop(process);
        std::thread::sleep(std::time::Duration::from_millis(1600));
        assert!(
            !marker.exists(),
            "dropping OwnedProcess must terminate the descendant tree before it writes the marker"
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_owned_process_preserves_hidden_console_and_captures_stdout() {
        use std::io::Read;

        let script = r#"Add-Type -TypeDefinition 'using System; using System.Runtime.InteropServices; public static class ConsoleProbe { [DllImport("kernel32.dll")] public static extern IntPtr GetConsoleWindow(); }'; if ([ConsoleProbe]::GetConsoleWindow() -eq [IntPtr]::Zero) { Write-Output 'none' } else { Write-Output 'present' }"#;
        let mut command = std::process::Command::new("powershell.exe");
        command
            .args([
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                script,
            ])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        let mut process =
            OwnedProcess::spawn(command).expect("spawn owned hidden PowerShell probe");
        let mut stdout = Vec::new();
        process
            .take_stdout()
            .expect("probe stdout")
            .read_to_end(&mut stdout)
            .expect("read probe stdout");
        let status = process
            .wait()
            .expect("wait for owned hidden PowerShell probe");
        assert!(status.success(), "hidden PowerShell probe failed: {status}");
        assert_eq!(String::from_utf8_lossy(&stdout).trim(), "none");
    }

    #[cfg(windows)]
    #[test]
    fn regression_inv_077_windows_background_command_has_no_console_window_and_captures_stdout() {
        let script = r#"Add-Type -TypeDefinition 'using System; using System.Runtime.InteropServices; public static class ConsoleProbe { [DllImport("kernel32.dll")] public static extern IntPtr GetConsoleWindow(); }'; if ([ConsoleProbe]::GetConsoleWindow() -eq [IntPtr]::Zero) { Write-Output 'none' } else { Write-Output 'present' }"#;
        let output = background_command("powershell.exe")
            .args([
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                script,
            ])
            .output()
            .expect("run hidden PowerShell probe");
        assert!(
            output.status.success(),
            "stderr={}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "none");
    }
}
