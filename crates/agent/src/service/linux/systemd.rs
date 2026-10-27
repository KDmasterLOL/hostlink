use super::*;
use std::os::unix::fs::MetadataExt;
use std::{net::TcpStream, time::Duration};

pub(super) fn unit_dir() -> io::Result<PathBuf> {
    Ok(user_config_base()?.join("systemd/user"))
}
pub(super) fn user_config_base() -> io::Result<PathBuf> {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .ok_or_else(|| invalid("HOME or XDG_CONFIG_HOME is required"))?;
    Ok(base)
}
pub(super) fn validate_unit_dirs(path: &Path, uid: u32) -> io::Result<()> {
    let base = user_config_base()?;
    let base_metadata = fs::symlink_metadata(&base)?;
    if !base_metadata.is_dir()
        || base_metadata.file_type().is_symlink()
        || base_metadata.uid() != uid
        || base_metadata.mode() & 0o022 != 0
    {
        return Err(invalid(
            "XDG config directory must be current-user-owned and have no symlink or group/world write access",
        ));
    }
    let relative = path
        .strip_prefix(&base)
        .map_err(|_| invalid("systemd unit path escapes the user's config directory"))?;
    let mut current = base;
    for component in relative.components() {
        current.push(component);
        let metadata = fs::symlink_metadata(&current)?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.uid() != uid
            || metadata.mode() & 0o022 != 0
        {
            return Err(invalid(
                "systemd user service path contains an unsafe directory",
            ));
        }
    }
    Ok(())
}
pub(super) fn has_enrollment(root: &Path) -> bool {
    let path = root.join("state/machine.json");
    fs::symlink_metadata(path).is_ok_and(|m| m.is_file() && !m.file_type().is_symlink())
}
pub(super) fn ensure_user_scope() -> io::Result<()> {
    if unsafe { libc::geteuid() } == 0 {
        return Err(invalid("user service management must not run as root"));
    }
    if std::env::var_os("XDG_RUNTIME_DIR").is_none() {
        return Err(invalid(
            "no user session runtime; systemd --user is unavailable (login linger is not enabled automatically)",
        ));
    }
    let version = systemctl_output(&["--version"])?;
    let first = String::from_utf8_lossy(&version.stdout);
    let major = first
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse::<u32>().ok());
    if !version.status.success() || major.is_none_or(|value| value < 254) {
        return Err(invalid(
            "HostLink Agent lifecycle requires systemd 254 or later for bounded exponential restart delay",
        ));
    }
    Ok(())
}
pub(super) fn systemctl(args: &[&str]) -> io::Result<()> {
    let out = systemctl_output(args)?;
    if !out.status.success() {
        return Err(io::Error::other(format!(
            "systemctl --user {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(())
}
pub(super) fn systemctl_output(args: &[&str]) -> io::Result<Output> {
    Command::new("systemctl")
        .arg("--user")
        .args(args)
        .stdin(std::process::Stdio::null())
        .output()
}
pub(super) fn ssh_banner(addr: std::net::SocketAddr) -> io::Result<bool> {
    let mut stream = match TcpStream::connect_timeout(&addr, Duration::from_millis(750)) {
        Ok(s) => s,
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::ConnectionRefused
                    | io::ErrorKind::TimedOut
                    | io::ErrorKind::NotFound
            ) =>
        {
            return Ok(false);
        }
        Err(e) => return Err(e),
    };
    stream.set_read_timeout(Some(Duration::from_millis(750)))?;
    let mut banner = [0; 256];
    match stream.read(&mut banner) {
        Ok(n) => Ok(String::from_utf8_lossy(&banner[..n]).starts_with("SSH-2.0-")),
        Err(e) if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut => {
            Ok(false)
        }
        Err(e) => Err(e),
    }
}
pub(super) fn render_unit(r: &InstallRecord) -> String {
    format!(
        "[Unit]\nDescription=HostLink Agent ({})\nStartLimitIntervalSec=300\nStartLimitBurst=5\n\n[Service]\nType=simple\nExecStart={} run --config={}\nRestart=on-failure\nRestartSec=15s\nRestartSteps=4\nRestartMaxDelaySec=240s\n\n[Install]\nWantedBy=default.target\n",
        r.unit_name,
        systemd_arg(&r.executable),
        systemd_arg(&r.config)
    )
}
pub(super) fn systemd_arg(path: &Path) -> String {
    let value = path.to_string_lossy();
    let mut out = String::from("\"");
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '%' => out.push_str("%%"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            _ => out.push(c),
        }
    }
    out.push('"');
    out
}
pub(super) fn unit_name(root: &Path) -> String {
    let suffix = hex(&Sha256::digest(root.as_os_str().as_encoded_bytes())[..10]);
    format!("hostlink-agent-{suffix}.service")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn systemd_argument_escaping_cannot_expand_specifiers_or_split_arguments() {
        assert_eq!(
            systemd_arg(Path::new("/tmp/a b%\"c\\d")),
            "\"/tmp/a b%%\\\"c\\\\d\""
        );
        assert_eq!(systemd_arg(Path::new("/tmp/x%h")), "\"/tmp/x%%h\"");
    }
}
