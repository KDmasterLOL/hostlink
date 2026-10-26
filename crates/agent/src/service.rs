//! User-scoped Agent lifecycle integration.
//!
//! Linux uses only `systemctl --user`; this module never contacts the system
//! manager or changes login lingering. The service record binds a unit to the
//! exact private install root, executable digest, config and current uid.

use std::{io, path::Path};

#[cfg(target_os = "linux")]
use crate::jobs;
#[cfg(target_os = "linux")]
use sha2::{Digest, Sha256};
#[cfg(target_os = "linux")]
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::PathBuf,
    process::{Command, Output},
};

#[cfg(target_os = "linux")]
const MARKER: &str = ".hostlink-user-service.json";
#[cfg(target_os = "linux")]
const MARKER_FORMAT: u32 = 1;

#[cfg(target_os = "linux")]
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct InstallRecord {
    format: u32,
    uid: u32,
    root: PathBuf,
    executable: PathBuf,
    executable_sha256: String,
    config: PathBuf,
    unit_name: String,
}

#[cfg(target_os = "linux")]
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct EnrollmentManifest {
    format: u32,
    machine_id: String,
    files: std::collections::BTreeMap<String, EnrollmentFile>,
}

#[cfg(target_os = "linux")]
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct EnrollmentFile {
    size: u64,
    sha256: String,
}

#[derive(Debug)]
pub struct ServiceStatus {
    pub installed: bool,
    pub active: bool,
    pub owner_uid: Option<u32>,
    pub pid: Option<u32>,
    pub executable_sha256: Option<String>,
    pub ssh_banner: bool,
    pub local_enrollment: bool,
    pub detail: String,
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::{
        net::TcpStream,
        os::unix::fs::{MetadataExt, OpenOptionsExt},
        time::Duration,
    };

    pub fn install(root: &Path, config: &Path) -> io::Result<()> {
        ensure_user_scope()?;
        let record = prepare_record(root, config)?;
        let dir = unit_dir()?;
        fs::create_dir_all(&dir)?;
        validate_unit_dirs(&dir, record.uid)?;
        let dir_meta = fs::symlink_metadata(&dir)?;
        if !dir_meta.is_dir()
            || dir_meta.file_type().is_symlink()
            || dir_meta.uid() != record.uid
            || dir_meta.mode() & 0o022 != 0
        {
            return Err(invalid(
                "systemd user unit directory must be a private current-user-owned directory",
            ));
        }
        let unit = dir.join(&record.unit_name);
        let marker_exists = record.root.join(MARKER).exists();
        if marker_exists {
            let existing = read_record(&record.root)?;
            verify_record(&existing)?;
            if existing.unit_name != record.unit_name
                || existing.root != record.root
                || existing.config != record.config
                || existing.executable_sha256 != record.executable_sha256
            {
                return Err(invalid(
                    "this root is already registered with a different binary or config; remove its owned service before replacing it",
                ));
            }
        } else if unit.exists() {
            if unit.is_file() {
                return Err(invalid(
                    "systemd unit already exists and is not owned by this Agent root",
                ));
            }
            return Err(invalid("systemd unit path is occupied by a non-file entry"));
        }
        write_private(&unit, render_unit(&record).as_bytes())?;
        if let Err(error) = write_private(
            &record.root.join(MARKER),
            &serde_json::to_vec(&record).map_err(io::Error::other)?,
        ) {
            let cleanup = fs::remove_file(&unit).and_then(|()| systemctl(&["daemon-reload"]));
            return Err(io::Error::other(format!(
                "cannot write private service marker: {error}; unit cleanup: {cleanup:?}"
            )));
        }
        if let Err(error) =
            systemctl(&["daemon-reload"]).and_then(|()| systemctl(&["enable", &record.unit_name]))
        {
            if !marker_exists {
                fs::remove_file(&unit)?;
                fs::remove_file(record.root.join(MARKER))?;
                systemctl(&["daemon-reload"])?;
            }
            return Err(error);
        }
        println!(
            "Installed user service {} (enabled for this user's login; not started)",
            record.unit_name
        );
        Ok(())
    }

    pub fn start(root: &Path) -> io::Result<()> {
        let record = owned_record(root)?;
        verify_record(&record)?;
        systemctl(&["start", &record.unit_name])?;
        println!("Started {}", record.unit_name);
        Ok(())
    }

    pub fn stop(root: &Path) -> io::Result<()> {
        let record = owned_record(root)?;
        verify_record(&record)?;
        let active = jobs::active_ids(&load_config(&record.config)?.jobs_root)?;
        if !active.is_empty() {
            return Err(busy(&active));
        }
        systemctl(&["stop", &record.unit_name])?;
        // Close the check/stop race: if a request was admitted while systemd
        // was stopping the listener, preserve its durable record and restore
        // the service so the owner can inspect the interrupted outcome.
        let active = jobs::active_ids(&load_config(&record.config)?.jobs_root)?;
        if !active.is_empty() {
            systemctl(&["start", &record.unit_name])?;
            return Err(busy(&active));
        }
        println!("Stopped {}", record.unit_name);
        Ok(())
    }

    pub fn remove(root: &Path) -> io::Result<()> {
        let record = owned_record(root)?;
        verify_record(&record)?;
        let active = jobs::active_ids(&load_config(&record.config)?.jobs_root)?;
        if !active.is_empty() {
            return Err(busy(&active));
        }
        let unit = unit_dir()?.join(&record.unit_name);
        verify_unit_file(&record, &unit)?;
        systemctl(&["stop", &record.unit_name])?;
        let active = jobs::active_ids(&load_config(&record.config)?.jobs_root)?;
        if !active.is_empty() {
            systemctl(&["start", &record.unit_name])?;
            return Err(busy(&active));
        }
        systemctl(&["disable", &record.unit_name])?;
        let staged_binary = record.root.join(".hostlink-agent-uninstall.pending");
        if fs::symlink_metadata(&staged_binary).is_ok() {
            return Err(invalid(
                "uninstall staging path already exists; inspect it before retrying",
            ));
        }
        fs::rename(&record.executable, &staged_binary)?;
        if let Err(error) = fs::remove_file(&unit) {
            return rollback_uninstall(&record, &staged_binary, false, false, &error.to_string());
        }
        if let Err(error) = fs::remove_file(record.root.join(MARKER)) {
            return rollback_uninstall(&record, &staged_binary, true, false, &error.to_string());
        }
        if let Err(error) = systemctl(&["daemon-reload"]) {
            return rollback_uninstall(&record, &staged_binary, true, true, &error.to_string());
        }
        fs::remove_file(&staged_binary)?;
        println!(
            "Uninstalled Agent {}. Enrollment data, keys and jobs remain at {}",
            record.unit_name,
            record.root.display()
        );
        Ok(())
    }

    fn rollback_uninstall(
        record: &InstallRecord,
        staged: &Path,
        restore_unit: bool,
        restore_marker: bool,
        cause: &str,
    ) -> io::Result<()> {
        let mut failures = Vec::new();
        if restore_unit
            && let Err(e) = write_private(
                &unit_dir()?.join(&record.unit_name),
                render_unit(record).as_bytes(),
            )
        {
            failures.push(format!("unit: {e}"));
        }
        if restore_marker
            && let Err(e) = write_private(
                &record.root.join(MARKER),
                &serde_json::to_vec(record).map_err(io::Error::other)?,
            )
        {
            failures.push(format!("marker: {e}"));
        }
        if let Err(e) = fs::rename(staged, &record.executable) {
            failures.push(format!("executable: {e}"));
        }
        if let Err(e) = systemctl(&["daemon-reload"]) {
            failures.push(format!("systemctl daemon-reload: {e}"));
        }
        if let Err(e) = systemctl(&["enable", &record.unit_name]) {
            failures.push(format!("systemctl enable: {e}"));
        }
        if let Err(e) = systemctl(&["start", &record.unit_name]) {
            failures.push(format!("systemctl start: {e}"));
        }
        if failures.is_empty() {
            Err(io::Error::other(format!(
                "uninstall failed: {cause}; original service restored and started"
            )))
        } else {
            Err(io::Error::other(format!(
                "uninstall failed: {cause}; rollback incomplete: {}",
                failures.join("; ")
            )))
        }
    }

    pub fn status(root: &Path) -> io::Result<ServiceStatus> {
        ensure_user_scope()?;
        canonical_private_dir(root, unsafe { libc::geteuid() })?;
        let record = match owned_record(root) {
            Ok(r) => r,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Ok(ServiceStatus {
                    installed: false,
                    active: false,
                    owner_uid: None,
                    pid: None,
                    executable_sha256: None,
                    ssh_banner: false,
                    local_enrollment: false,
                    detail: "unmanaged: no HostLink service marker exists for this root".into(),
                });
            }
            Err(e) => return Err(e),
        };
        verify_record(&record)?;
        let out = systemctl_output(&[
            "show",
            &record.unit_name,
            "--property=ActiveState",
            "--property=MainPID",
        ])?;
        if !out.status.success() {
            return Ok(ServiceStatus {
                installed: true,
                active: false,
                owner_uid: Some(record.uid),
                pid: None,
                executable_sha256: Some(record.executable_sha256),
                ssh_banner: false,
                local_enrollment: has_enrollment(&record.root),
                detail: "installed but systemd --user has no loaded unit".into(),
            });
        }
        let text = String::from_utf8_lossy(&out.stdout);
        let active = text.lines().any(|l| l == "ActiveState=active");
        let pid = text
            .lines()
            .find_map(|l| l.strip_prefix("MainPID=")?.parse::<u32>().ok())
            .filter(|p| *p != 0);
        if !active {
            return Ok(ServiceStatus {
                installed: true,
                active: false,
                owner_uid: Some(record.uid),
                pid,
                executable_sha256: Some(record.executable_sha256),
                ssh_banner: false,
                local_enrollment: has_enrollment(&record.root),
                detail: "installed but service is not active".into(),
            });
        }
        let pid =
            pid.ok_or_else(|| invalid("systemd reports active Agent service without a main PID"))?;
        verify_pid_owner(pid, &record)?;
        let cfg = load_config(&record.config)?;
        let ssh_banner = ssh_banner(cfg.listen)?;
        let enrolled = has_enrollment(&record.root);
        let detail = if ssh_banner {
            "service active; owned process and loopback SSH banner verified; Hub reachability not queried"
        } else {
            "service active; owned process verified but loopback SSH endpoint is unreachable; Hub reachability not queried"
        };
        Ok(ServiceStatus {
            installed: true,
            active,
            owner_uid: Some(record.uid),
            pid: Some(pid),
            executable_sha256: Some(record.executable_sha256),
            ssh_banner,
            local_enrollment: enrolled,
            detail: detail.into(),
        })
    }

    fn prepare_record(root: &Path, config: &Path) -> io::Result<InstallRecord> {
        let uid = unsafe { libc::geteuid() };
        let root = canonical_private_dir(root, uid)?;
        let config = canonical_regular(config, uid)?;
        if config != root.join("state/agent.json") {
            return Err(invalid(
                "service install requires the fresh enrollment config at ROOT/state/agent.json; it never adopts an arbitrary or legacy Agent config",
            ));
        }
        verify_enrollment_root(&root, uid)?;
        let executable = std::env::current_exe()?.canonicalize()?;
        if executable != root.join("bin/hostlink-agent") {
            return Err(invalid(
                "hostlink-agent executable must be the packaged ROOT/bin/hostlink-agent for this fresh install root",
            ));
        }
        let metadata = fs::symlink_metadata(&executable)?;
        if !metadata.is_file() || metadata.uid() != uid || metadata.mode() & 0o022 != 0 {
            return Err(invalid(
                "Agent executable must be a regular file owned by this user and not group/world writable",
            ));
        }
        let executable_sha256 = sha256_file(&executable)?;
        let suffix = hex(&Sha256::digest(root.as_os_str().as_encoded_bytes())[..10]);
        let unit_name = format!("hostlink-agent-{suffix}.service");
        Ok(InstallRecord {
            format: MARKER_FORMAT,
            uid,
            root,
            executable,
            executable_sha256,
            config,
            unit_name,
        })
    }

    fn owned_record(root: &Path) -> io::Result<InstallRecord> {
        ensure_user_scope()?;
        let uid = unsafe { libc::geteuid() };
        let root = canonical_private_dir(root, uid)?;
        let path = root.join(MARKER);
        let meta = fs::symlink_metadata(&path)?;
        if !meta.is_file()
            || meta.file_type().is_symlink()
            || meta.uid() != uid
            || meta.mode() & 0o077 != 0
        {
            return Err(invalid(
                "service marker is not a private regular file owned by this user",
            ));
        }
        let mut bytes = Vec::new();
        File::open(path)?.take(16 * 1024).read_to_end(&mut bytes)?;
        let record: InstallRecord =
            serde_json::from_slice(&bytes).map_err(|_| invalid("service marker is invalid"))?;
        if record.format != MARKER_FORMAT || record.uid != uid || record.root != root {
            return Err(invalid("service marker owner or root does not match"));
        }
        Ok(record)
    }

    fn read_record(root: &Path) -> io::Result<InstallRecord> {
        owned_record(root)
    }

    fn verify_record(r: &InstallRecord) -> io::Result<()> {
        if r.unit_name != unit_name(&r.root)
            || r.executable != r.root.join("bin/hostlink-agent")
            || r.config != r.root.join("state/agent.json")
        {
            return Err(invalid(
                "service marker paths or service identity are inconsistent",
            ));
        }
        canonical_regular(&r.executable, r.uid)?;
        canonical_regular(&r.config, r.uid)?;
        verify_enrollment_root(&r.root, r.uid)?;
        if sha256_file(&r.executable)? != r.executable_sha256 {
            return Err(invalid(
                "installed Agent executable SHA-256 changed; service will not be controlled",
            ));
        }
        let dir = unit_dir()?;
        validate_unit_dirs(&dir, r.uid)?;
        verify_unit_file(r, &dir.join(&r.unit_name))?;
        Ok(())
    }

    fn verify_unit_file(r: &InstallRecord, path: &Path) -> io::Result<()> {
        let m = fs::symlink_metadata(path)?;
        let uid = unsafe { libc::geteuid() };
        if !m.is_file() || m.file_type().is_symlink() || m.uid() != uid || m.mode() & 0o077 != 0 {
            return Err(invalid(
                "systemd unit is not a private regular file owned by this user",
            ));
        }
        if fs::read(path)? != render_unit(r).as_bytes() {
            return Err(invalid(
                "systemd unit contents differ from the owned install record",
            ));
        }
        Ok(())
    }

    fn verify_pid_owner(pid: u32, r: &InstallRecord) -> io::Result<()> {
        let proc = PathBuf::from(format!("/proc/{pid}"));
        let m = fs::metadata(&proc)?;
        if m.uid() != r.uid {
            return Err(invalid(
                "systemd main process is not owned by the current user",
            ));
        }
        let exe = fs::read_link(proc.join("exe"))?;
        if exe != r.executable {
            return Err(invalid(
                "systemd main process executable does not match this Agent root",
            ));
        }
        let args = fs::read(proc.join("cmdline"))?;
        let args = String::from_utf8_lossy(&args);
        if !args.contains("run") || !args.contains(r.config.to_string_lossy().as_ref()) {
            return Err(invalid(
                "systemd main process command line does not match this Agent config",
            ));
        }
        Ok(())
    }

    fn canonical_private_dir(path: &Path, uid: u32) -> io::Result<PathBuf> {
        let requested = fs::symlink_metadata(path)?;
        if requested.file_type().is_symlink() {
            return Err(invalid("install root must not be a symlink"));
        }
        let canonical = path.canonicalize()?;
        let m = fs::symlink_metadata(&canonical)?;
        if !m.is_dir() || m.file_type().is_symlink() || m.uid() != uid || m.mode() & 0o077 != 0 {
            return Err(invalid(
                "install root must be an existing private directory owned by the current user",
            ));
        }
        Ok(canonical)
    }
    fn canonical_regular(path: &Path, uid: u32) -> io::Result<PathBuf> {
        let m = fs::symlink_metadata(path)?;
        if !m.is_file() || m.file_type().is_symlink() || m.uid() != uid || m.mode() & 0o022 != 0 {
            return Err(invalid(
                "service input must be a regular current-user-owned file without symlinks or group/world write access",
            ));
        }
        path.canonicalize()
    }
    fn verify_enrollment_root(root: &Path, uid: u32) -> io::Result<()> {
        let state = root.join("state");
        let directory = fs::symlink_metadata(&state)?;
        if !directory.is_dir()
            || directory.file_type().is_symlink()
            || directory.uid() != uid
            || directory.mode() & 0o077 != 0
        {
            return Err(invalid(
                "Agent enrollment state must be a private current-user-owned directory",
            ));
        }
        let machine_path = state.join("machine.json");
        let manifest_path = state.join("manifest.json");
        let machine_file = private_input(&machine_path, uid, 16 * 1024)?;
        let manifest_file = private_input(&manifest_path, uid, 64 * 1024)?;
        let machine: serde_json::Value = serde_json::from_slice(&machine_file)
            .map_err(|_| invalid("Agent enrollment identity is invalid"))?;
        let manifest: EnrollmentManifest = serde_json::from_slice(&manifest_file)
            .map_err(|_| invalid("Agent enrollment manifest is invalid"))?;
        let machine_id = machine
            .get("machine_id")
            .and_then(serde_json::Value::as_str);
        if machine.get("format").and_then(serde_json::Value::as_u64) != Some(1)
            || machine_id != Some(manifest.machine_id.as_str())
            || machine
                .get("name")
                .and_then(serde_json::Value::as_str)
                .is_none()
            || machine
                .get("ssh_public_key")
                .and_then(serde_json::Value::as_str)
                .is_none()
            || machine
                .get("ssh_host_public_key")
                .and_then(serde_json::Value::as_str)
                .is_none()
            || manifest.format != 1
        {
            return Err(invalid(
                "Agent enrollment identity and manifest do not match",
            ));
        }
        for required in [
            "agent.json",
            "authorized_keys",
            "gateway_host_key",
            "gateway_identity",
            "host_key",
            "machine.json",
        ] {
            if !manifest.files.contains_key(required) {
                return Err(invalid("Agent enrollment manifest is incomplete"));
            }
        }
        for (name, expected) in manifest.files {
            if name.contains('/') || name.contains('\\') || name == "." || name == ".." {
                return Err(invalid(
                    "Agent enrollment manifest contains an unsafe file name",
                ));
            }
            let path = state.join(&name);
            let bytes = private_input(&path, uid, 1024 * 1024)?;
            let digest = format!("{:x}", Sha256::digest(&bytes));
            if bytes.len() as u64 != expected.size || expected.sha256 != digest {
                return Err(invalid("Agent enrollment file does not match its manifest"));
            }
        }
        Ok(())
    }
    fn private_input(path: &Path, uid: u32, limit: usize) -> io::Result<Vec<u8>> {
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.uid() != uid
            || metadata.mode() & 0o077 != 0
            || metadata.len() as usize > limit
        {
            return Err(invalid(
                "Agent enrollment file must be a bounded private regular file owned by this user",
            ));
        }
        fs::read(path)
    }
    fn load_config(path: &Path) -> io::Result<crate::AgentConfig> {
        let canonical = canonical_regular(path, unsafe { libc::geteuid() })?;
        let metadata = fs::metadata(&canonical)?;
        if metadata.len() > 64 * 1024 {
            return Err(invalid("Agent config exceeds size limit"));
        }
        let bytes = fs::read(&canonical)?;
        let mut config: crate::AgentConfig =
            serde_json::from_slice(&bytes).map_err(|_| invalid("Agent config is invalid"))?;
        let base = canonical.parent().unwrap_or_else(|| Path::new("."));
        if config.host_key.is_relative() {
            config.host_key = base.join(config.host_key);
        }
        if config.authorized_keys.is_relative() {
            config.authorized_keys = base.join(config.authorized_keys);
        }
        if config.jobs_root.is_relative() {
            config.jobs_root = base.join(config.jobs_root);
        }
        if let Some(gateway) = &mut config.gateway {
            if gateway.identity.is_relative() {
                gateway.identity = base.join(&gateway.identity);
            }
            if gateway.host_public_key.is_relative() {
                gateway.host_public_key = base.join(&gateway.host_public_key);
            }
        }
        config.validate()?;
        Ok(config)
    }
    fn unit_dir() -> io::Result<PathBuf> {
        Ok(user_config_base()?.join("systemd/user"))
    }
    fn user_config_base() -> io::Result<PathBuf> {
        let base = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
            .ok_or_else(|| invalid("HOME or XDG_CONFIG_HOME is required"))?;
        Ok(base)
    }
    fn validate_unit_dirs(path: &Path, uid: u32) -> io::Result<()> {
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
    fn has_enrollment(root: &Path) -> bool {
        let path = root.join("state/machine.json");
        fs::symlink_metadata(path).is_ok_and(|m| m.is_file() && !m.file_type().is_symlink())
    }
    fn ensure_user_scope() -> io::Result<()> {
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
    fn systemctl(args: &[&str]) -> io::Result<()> {
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
    fn systemctl_output(args: &[&str]) -> io::Result<Output> {
        Command::new("systemctl")
            .arg("--user")
            .args(args)
            .stdin(std::process::Stdio::null())
            .output()
    }
    fn ssh_banner(addr: std::net::SocketAddr) -> io::Result<bool> {
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
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                Ok(false)
            }
            Err(e) => Err(e),
        }
    }
    fn render_unit(r: &InstallRecord) -> String {
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
    fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)?;
        file.write_all(bytes)?;
        file.sync_all()
    }
    fn unit_name(root: &Path) -> String {
        let suffix = hex(&Sha256::digest(root.as_os_str().as_encoded_bytes())[..10]);
        format!("hostlink-agent-{suffix}.service")
    }
    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
    fn sha256_file(path: &Path) -> io::Result<String> {
        let mut f = File::open(path)?;
        let mut h = Sha256::new();
        let mut b = [0; 64 * 1024];
        loop {
            let n = f.read(&mut b)?;
            if n == 0 {
                break;
            }
            h.update(&b[..n]);
        }
        Ok(hex(&h.finalize()))
    }
    fn busy(ids: &[String]) -> io::Error {
        io::Error::new(
            io::ErrorKind::WouldBlock,
            format!(
                "Agent lifecycle deferred: {} durable jobs are Prepared, Running or Interrupted; inspect jobs before stopping or removing service",
                ids.len()
            ),
        )
    }
    fn invalid(s: &str) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidInput, s)
    }

    pub use {
        install as install_impl, remove as remove_impl, start as start_impl, status as status_impl,
        stop as stop_impl,
    };
}

#[cfg(target_os = "linux")]
pub use linux::{
    install_impl as install, remove_impl as remove, start_impl as start, status_impl as status,
    stop_impl as stop,
};

#[cfg(not(target_os = "linux"))]
fn unsupported() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "persistent Agent service management is currently supported only on Linux systemd --user; Windows startup is not installed by this command",
    )
}
#[cfg(not(target_os = "linux"))]
pub fn install(_: &Path, _: &Path) -> io::Result<()> {
    Err(unsupported())
}
#[cfg(not(target_os = "linux"))]
pub fn start(_: &Path) -> io::Result<()> {
    Err(unsupported())
}
#[cfg(not(target_os = "linux"))]
pub fn stop(_: &Path) -> io::Result<()> {
    Err(unsupported())
}
#[cfg(not(target_os = "linux"))]
pub fn remove(_: &Path) -> io::Result<()> {
    Err(unsupported())
}
#[cfg(not(target_os = "linux"))]
pub fn status(_: &Path) -> io::Result<ServiceStatus> {
    Err(unsupported())
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    #[test]
    fn systemd_argument_escaping_cannot_expand_specifiers_or_split_arguments() {
        #[cfg(target_os = "linux")]
        {
            assert_eq!(
                linux::systemd_arg(Path::new("/tmp/a b%\"c\\d")),
                "\"/tmp/a b%%\\\"c\\\\d\""
            );
            assert_eq!(linux::systemd_arg(Path::new("/tmp/x%h")), "\"/tmp/x%%h\"");
        }
    }
}
