use crate::AppResult;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};

/// Encodes an argv vector into one shell-safe command string for an interactive OpenSSH command.
///
/// Windows and POSIX targets use different quoting/argv-reconstruction strategies because OpenSSH
/// serializes its remote command into one string rather than preserving local argv boundaries.
///
/// # Errors
///
/// Returns [`crate::AppError`] when the remote operating system is unsupported or an argument
/// cannot be represented safely by the maintained quoting contract.
pub fn encode_remote_command(argv: &[String], remote_os: &str) -> AppResult<String> {
    // OpenSSH does not transmit a remote argv vector: it flattens the remote command back into a
    // shell string. Reconstruct one deliberately for the target OS instead of relying on local
    // `Command::args()` boundaries that disappear at the SSH protocol boundary.
    if argv.is_empty() {
        return Ok(String::new());
    }
    if argv.iter().any(|argument| argument.contains('\0')) {
        return Err(crate::invalid_config(
            "SSH command arguments cannot contain NUL".to_owned(),
        ));
    }

    let os = remote_os.trim().to_ascii_lowercase();
    if os.contains("windows") || os.starts_with("win") {
        return Ok(encode_windows_powershell_argv(argv));
    }
    if os.contains("linux")
        || os.contains("darwin")
        || os.contains("macos")
        || os.contains("freebsd")
        || os.contains("unix")
    {
        return Ok(encode_posix_argv(argv));
    }

    Err(crate::invalid_config(format!(
        "cannot safely encode SSH argv for remote OS {remote_os:?}"
    )))
}

fn encode_windows_powershell_argv(argv: &[String]) -> String {
    // Windows PowerShell 5.1 re-serializes native argv for `& $program @args` and can drop
    // literal quotes embedded in an argument. Serialize the native Windows command line here
    // and launch it through ProcessStartInfo so arbitrary caller arguments remain byte-for-byte intact.
    let program = BASE64_STANDARD.encode(argv[0].as_bytes());
    let arguments = hostlink_core::windows_command_line(&argv[1..]);
    let arguments = BASE64_STANDARD.encode(arguments.as_bytes());
    let script = format!(
        "$ErrorActionPreference='Stop';$e=New-Object System.Text.UTF8Encoding($false);\
$p=$e.GetString([Convert]::FromBase64String('{program}'));\
$a=$e.GetString([Convert]::FromBase64String('{arguments}'));\
$s=New-Object System.Diagnostics.ProcessStartInfo;$s.FileName=$p;$s.Arguments=$a;\
$s.UseShellExecute=$false;$x=[System.Diagnostics.Process]::Start($s);$x.WaitForExit();exit $x.ExitCode"
    );
    let mut utf16le = Vec::with_capacity(script.len() * 2);
    for unit in script.encode_utf16() {
        utf16le.extend_from_slice(&unit.to_le_bytes());
    }
    format!(
        "powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand {}",
        BASE64_STANDARD.encode(utf16le)
    )
}

fn encode_posix_argv(argv: &[String]) -> String {
    shlex::try_join(argv.iter().map(String::as_str))
        .expect("validated SSH arguments do not contain NUL")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_remote_command_preserves_argv_without_shell_interpolation() {
        let argv = vec![
            r"C:\Program Files\HostLink Tools\caller.exe".to_owned(),
            "profile".to_owned(),
            "add".to_owned(),
            r#"server="websrv";path="test 2";"#.to_owned(),
            "snapshot: fixture test 2".to_owned(),
            "it's a commit".to_owned(),
        ];
        let command = encode_remote_command(&argv, "windows").expect("windows command");
        assert!(command.starts_with("powershell.exe -NoLogo -NoProfile -NonInteractive"));
        for raw in &argv {
            assert!(
                !command.contains(raw),
                "raw argument leaked into shell command: {raw:?}"
            );
        }

        let encoded_script = command.split_whitespace().last().expect("encoded script");
        let bytes = BASE64_STANDARD
            .decode(encoded_script)
            .expect("base64 script");
        assert_eq!(bytes.len() % 2, 0);
        let utf16 = bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u16::from_le_bytes(*pair))
            .collect::<Vec<_>>();
        let script = String::from_utf16(&utf16).expect("UTF-16LE script");
        let serialized_arguments = hostlink_core::windows_command_line(&argv[1..]);
        assert!(script.contains(&BASE64_STANDARD.encode(argv[0].as_bytes())));
        assert!(script.contains(&BASE64_STANDARD.encode(serialized_arguments.as_bytes())));
        assert!(script.contains("System.Diagnostics.ProcessStartInfo"));
        assert!(script.contains("$s.UseShellExecute=$false"));
        assert!(!script.contains("& $p @r"));
    }

    #[test]
    fn windows_native_argument_quoting_matches_crt_rules() {
        let args = [
            "plain",
            "",
            "a b",
            r#"server="websrv";path="test 2";"#,
            r"C:\path with space\",
        ];
        assert_eq!(
            hostlink_core::windows_command_line(args),
            r#"plain "" "a b" "server=\"websrv\";path=\"test 2\";" "C:\path with space\\""#
        );
    }

    #[test]
    fn posix_remote_command_quotes_spaces_semicolons_and_single_quotes() {
        let argv = vec![
            "/opt/1c tools/onec".to_owned(),
            "Srvr=server;Ref=base;".to_owned(),
            "it's a commit".to_owned(),
        ];
        let encoded = encode_remote_command(&argv, "linux").expect("posix command");
        assert_eq!(shlex::split(&encoded).expect("split encoded argv"), argv);
    }

    #[test]
    fn posix_remote_command_round_trips_harmless_complex_argv() {
        let argv = complex_echo_argv();
        let encoded = encode_remote_command(&argv, "linux").expect("POSIX command");
        assert_eq!(shlex::split(&encoded).expect("decode POSIX argv"), argv);
    }

    #[test]
    fn windows_remote_command_carries_exact_crt_argument_vector() {
        let argv = complex_echo_argv();
        let command = encode_remote_command(&argv, "windows").expect("Windows command");
        let script = decode_powershell_encoded_command(&command);
        let program = script
            .split("$p=$e.GetString([Convert]::FromBase64String('")
            .nth(1)
            .and_then(|value| value.split("'));").next())
            .expect("encoded program");
        assert_eq!(
            BASE64_STANDARD.decode(program).expect("program bytes"),
            argv[0].as_bytes()
        );
        let encoded_args = script
            .split("$a=$e.GetString([Convert]::FromBase64String('")
            .nth(1)
            .and_then(|value| value.split("'));").next())
            .expect("encoded native command line");
        let native_line = String::from_utf8(
            BASE64_STANDARD
                .decode(encoded_args)
                .expect("native argument bytes"),
        )
        .expect("native command line UTF-8");
        assert_eq!(decode_windows_command_line(&native_line), argv[1..]);
    }

    fn complex_echo_argv() -> Vec<String> {
        vec![
            "argv-echo-fixture".to_owned(),
            String::new(),
            "two words".to_owned(),
            "雪だるま ☃".to_owned(),
            "literal \"double\" and 'single' quotes".to_owned(),
            r"trailing slash\".to_owned(),
            r"C:\Program Files\HostLink Tools\bin".to_owned(),
            "semi;colon".to_owned(),
            "ampersand & value".to_owned(),
            "line one\nline two".to_owned(),
            "Srvr=server;Ref=database;Usr=Example;Pwd=DATA".to_owned(),
            "last argument".to_owned(),
        ]
    }

    fn decode_powershell_encoded_command(command: &str) -> String {
        let encoded = command.split_whitespace().last().expect("encoded command");
        let bytes = BASE64_STANDARD.decode(encoded).expect("UTF-16LE bytes");
        let units = bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u16::from_le_bytes(*pair))
            .collect::<Vec<_>>();
        String::from_utf16(&units).expect("PowerShell script UTF-16")
    }

    // Test decoder for the Microsoft CRT quoting rules used by hostlink_core::windows_command_line.
    fn decode_windows_command_line(command_line: &str) -> Vec<String> {
        let mut args = Vec::new();
        let mut chars = command_line.chars().peekable();
        while chars.peek().is_some() {
            while chars.peek().is_some_and(|ch| ch.is_ascii_whitespace()) {
                chars.next();
            }
            if chars.peek().is_none() {
                break;
            }
            let mut arg = String::new();
            let mut quoted = false;
            while let Some(ch) = chars.peek().copied() {
                if ch == '\\' {
                    let mut slashes = 0;
                    while chars.peek() == Some(&'\\') {
                        chars.next();
                        slashes += 1;
                    }
                    if chars.peek() == Some(&'"') {
                        arg.extend(std::iter::repeat_n('\\', slashes / 2));
                        chars.next();
                        if slashes % 2 == 1 {
                            arg.push('"');
                        } else {
                            quoted = !quoted;
                        }
                    } else {
                        arg.extend(std::iter::repeat_n('\\', slashes));
                    }
                } else if ch == '"' {
                    chars.next();
                    quoted = !quoted;
                } else if ch.is_ascii_whitespace() && !quoted {
                    break;
                } else {
                    arg.push(ch);
                    chars.next();
                }
            }
            args.push(arg);
        }
        args
    }

    #[test]
    fn remote_command_rejects_unknown_os_and_nul() {
        assert!(encode_remote_command(&["echo".into()], "plan9").is_err());
        assert!(encode_remote_command(&["bad\0arg".into()], "windows").is_err());
    }
}
