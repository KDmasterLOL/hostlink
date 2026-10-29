use service_manager::{ServiceLabel, systemd_user_dir_path};
use sha2::{Digest as _, Sha256};
use std::{
    fs, io,
    net::TcpStream,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::Duration,
};

pub(super) struct Unit {
    pub root: PathBuf,
    pub executable: PathBuf,
    pub config: PathBuf,
    pub label: ServiceLabel,
    pub path: PathBuf,
}

impl Unit {
    pub fn new(root: &Path) -> io::Result<Self> {
        if unsafe { libc::geteuid() } == 0 {
            return Err(io::Error::other("user service cannot run as root"));
        }
        if std::env::var_os("XDG_RUNTIME_DIR").is_none() {
            return Err(io::Error::other("user systemd session is unavailable"));
        }
        let meta = fs::symlink_metadata(root)?;
        if !meta.is_dir()
            || meta.file_type().is_symlink()
            || meta.uid() != unsafe { libc::geteuid() }
            || meta.permissions().mode() & 0o077 != 0
        {
            return Err(io::Error::other(
                "install root must be a private current-user directory without symlinks",
            ));
        }
        let root = root.canonicalize()?;
        let suffix = Sha256::digest(root.as_os_str().as_encoded_bytes())[..10]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let label = ServiceLabel {
            qualifier: None,
            organization: None,
            application: format!("hostlink-agent-{suffix}"),
        };
        let path = systemd_user_dir_path()?.join(format!("{}.service", label.application));
        Ok(Self {
            executable: root.join("bin/hostlink-agent"),
            config: root.join("state/agent.json"),
            root,
            label,
            path,
        })
    }

    pub fn name(&self) -> String {
        format!("{}.service", self.label.application)
    }

    pub fn reject_legacy_marker(&self) -> io::Result<()> {
        if fs::symlink_metadata(self.root.join(".hostlink-user-service.json")).is_ok() {
            return Err(io::Error::other(
                "legacy HostLink service marker exists; migrate or unregister the old service explicitly before installing the new one",
            ));
        }
        Ok(())
    }

    pub fn verify_source(&self, config: &Path) -> io::Result<()> {
        if config.canonicalize()? != self.config {
            return Err(io::Error::other(
                "service config must be ROOT/state/agent.json",
            ));
        }
        if std::env::current_exe()?.canonicalize()? != self.executable {
            return Err(io::Error::other(
                "service install must execute ROOT/bin/hostlink-agent",
            ));
        }
        let meta = fs::symlink_metadata(&self.executable)?;
        if !meta.is_file()
            || meta.file_type().is_symlink()
            || meta.uid() != unsafe { libc::geteuid() }
            || meta.mode() & 0o022 != 0
        {
            return Err(io::Error::other(
                "Agent executable must be a current-user-owned regular file",
            ));
        }
        crate::private_fs::validate_private_path(&self.config, false)
    }

    pub fn contents(&self) -> String {
        format!(
            "[Unit]\nDescription=HostLink Agent ({})\nStartLimitIntervalSec=300\nStartLimitBurst=5\n\
             \n[Service]\nType=simple\nExecStart={} run --config={}\n\
             Restart=on-failure\nRestartSec=15s\n\
             \n[Install]\nWantedBy=default.target\n",
            self.name(),
            systemd_arg(&self.executable),
            systemd_arg(&self.config)
        )
    }

    pub fn verify_unit_dir(&self) -> io::Result<()> {
        let dir = self
            .path
            .parent()
            .ok_or_else(|| io::Error::other("unit has no parent"))?;
        if !dir.exists() {
            return Ok(());
        }
        let m = fs::symlink_metadata(dir)?;
        if !m.is_dir()
            || m.file_type().is_symlink()
            || m.uid() != unsafe { libc::geteuid() }
            || m.mode() & 0o022 != 0
        {
            return Err(io::Error::other("user systemd unit directory is unsafe"));
        }
        Ok(())
    }

    pub fn verify_contents(&self) -> io::Result<()> {
        self.reject_legacy_marker()?;
        self.verify_unit_dir()?;
        let meta = fs::symlink_metadata(&self.path)?;
        if !meta.is_file()
            || meta.file_type().is_symlink()
            || meta.uid() != unsafe { libc::geteuid() }
        {
            return Err(io::Error::other("user service unit is unsafe"));
        }
        if fs::read_to_string(&self.path)? != self.contents() {
            return Err(io::Error::other(
                "user service unit belongs to another configuration",
            ));
        }
        Ok(())
    }

    pub fn reload(&self) -> io::Result<()> {
        let out = Command::new("systemctl")
            .args(["--user", "daemon-reload"])
            .stdin(Stdio::null())
            .output()?;
        if !out.status.success() {
            return Err(io::Error::other(
                String::from_utf8_lossy(&out.stderr).to_string(),
            ));
        }
        Ok(())
    }

    pub fn ssh_banner(&self) -> io::Result<bool> {
        let config = fs::read(&self.config)?;
        let config: crate::AgentConfig =
            serde_json::from_slice(&config).map_err(io::Error::other)?;
        let mut stream =
            match TcpStream::connect_timeout(&config.listen, Duration::from_millis(750)) {
                Ok(stream) => stream,
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::ConnectionRefused | io::ErrorKind::TimedOut
                    ) =>
                {
                    return Ok(false);
                }
                Err(error) => return Err(error),
            };
        stream.set_read_timeout(Some(Duration::from_millis(750)))?;
        let mut buf = [0u8; 256];
        use io::Read;
        match stream.read(&mut buf) {
            Ok(n) => Ok(buf[..n].starts_with(b"SSH-2.0-")),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) =>
            {
                Ok(false)
            }
            Err(error) => Err(error),
        }
    }
}

fn systemd_arg(path: &Path) -> String {
    let mut out = String::from("\"");
    for c in path.to_string_lossy().chars() {
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
