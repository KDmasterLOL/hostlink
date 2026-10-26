//! User-scoped Agent lifecycle integration.
//!
//! Linux uses only `systemctl --user`; this module never contacts the system
//! manager or changes login lingering. The service record binds a unit to the
//! exact private install root, executable digest, config and current uid.

use std::{io, path::Path};

#[cfg(target_os = "linux")]
use crate::jobs;
#[cfg(windows)]
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

#[cfg(windows)]
use sha2::{Digest, Sha256};
#[cfg(windows)]
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::PathBuf,
    process::{Command, Stdio},
    time::Duration,
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
    pub owner_sid: Option<String>,
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
                    owner_sid: None,
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
                owner_sid: None,
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
                owner_sid: None,
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
            owner_sid: None,
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

#[cfg(windows)]
mod windows {
    use super::*;
    use std::os::windows::fs::MetadataExt;
    use windows_sys::Win32::{
        Foundation::{
            CloseHandle, ERROR_SUCCESS, GetLastError, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT,
        },
        Security::{EqualSid, GetTokenInformation, TOKEN_QUERY, TOKEN_USER, TokenUser},
        Storage::FileSystem::SYNCHRONIZE,
        System::Registry::{
            HKEY, HKEY_CURRENT_USER, KEY_QUERY_VALUE, KEY_SET_VALUE, REG_OPTION_NON_VOLATILE,
            REG_SZ, RegCloseKey, RegCreateKeyExW, RegDeleteValueW, RegOpenKeyExW, RegQueryValueExW,
            RegSetValueExW,
        },
        System::{
            Com::CoTaskMemFree,
            SystemInformation::GetSystemDirectoryW,
            Threading::{
                OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
                QueryFullProcessImageNameW, WaitForSingleObject,
            },
        },
        UI::Shell::{FOLDERID_LocalAppData, SHGetKnownFolderPath},
    };

    const MARKER: &str = ".hostlink-user-service.json";
    const RUN_KEY: &str = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
    const MARKER_FORMAT: u32 = 1;
    const MAX_MARKER: usize = 16 * 1024;
    const MAX_PIPE_MESSAGE: usize = 1024;

    #[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct InstallRecord {
        format: u32,
        owner_sid: String,
        root: PathBuf,
        executable: PathBuf,
        executable_sha256: String,
        config: PathBuf,
        launcher_executable: PathBuf,
        startup_script: PathBuf,
        startup_script_sha256: String,
        pipe_name: String,
        control_token: String,
        run_value: String,
        #[serde(default)]
        maintenance: bool,
        #[serde(default)]
        maintenance_previous_sha256: Option<String>,
    }

    /// Opaque, in-process evidence captured before the login registration is disabled.
    /// The durable marker retains the prior executable digest for crash-safe rollback.
    #[must_use = "retain the receipt through publication, registration, and any rollback"]
    pub(crate) struct MaintenanceReceipt {
        old_marker: Vec<u8>,
        old_record: InstallRecord,
        run_command: String,
    }

    pub fn install(root: &Path, config: &Path) -> io::Result<()> {
        ensure_user_scope()?;
        let record = prepare_record(root, config)?;
        let marker_path = record.root.join(MARKER);
        match owned_record(&record.root) {
            Ok(existing) => {
                verify_record(&existing)?;
                if existing.root != record.root
                    || existing.config != record.config
                    || existing.executable_sha256 != record.executable_sha256
                {
                    return Err(invalid(
                        "this root is already registered with a different Agent binary or config",
                    ));
                }
                verify_registration(&existing)?;
                println!(
                    "HostLink Agent current-user login startup is already installed for this root"
                );
                return Ok(());
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let existing = registry_value(&record.run_value)?;
        if existing.is_some() {
            return Err(invalid(
                "the current-user startup value is already occupied; it was not changed",
            ));
        }
        let script = render_script(&record);
        write_private(&record.startup_script, script.as_bytes())?;
        if let Err(error) = write_private(
            &marker_path,
            &serde_json::to_vec(&record).map_err(io::Error::other)?,
        ) {
            let _ = fs::remove_file(&record.startup_script);
            return Err(error);
        }
        if let Err(error) = set_registry_value(&record.run_value, &render_command(&record)) {
            let cleanup = fs::remove_file(&marker_path);
            let script_cleanup = fs::remove_file(&record.startup_script);
            return Err(io::Error::other(format!(
                "cannot register current-user login startup: {error}; marker cleanup: {cleanup:?}; script cleanup: {script_cleanup:?}"
            )));
        }
        println!(
            "Installed current-user HostLink Agent login startup (interactive login required; not started)"
        );
        Ok(())
    }

    pub fn start(root: &Path) -> io::Result<()> {
        ensure_user_scope()?;
        let record = owned_record(root)?;
        verify_record(&record)?;
        refuse_maintenance(&record)?;
        crate::update::ensure_no_pending_windows_handoff(&record.root)?;
        verify_registration(&record)?;
        match pipe_request(&record, "STATUS") {
            Ok(reply) if running_pid(&reply).is_some() => {
                println!("HostLink Agent is already running for this root");
                return Ok(());
            }
            Ok(_) => {
                return Err(invalid(
                    "lifecycle endpoint exists but did not authenticate this Agent root",
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        launch_and_wait(&record)?;
        println!(
            "Started current-user HostLink Agent (pid verified by authenticated control pipe)"
        );
        Ok(())
    }

    pub fn stop(root: &Path) -> io::Result<()> {
        ensure_user_scope()?;
        let record = owned_record(root)?;
        verify_record(&record)?;
        verify_registration(&record)?;
        refuse_active_jobs(&record)?;
        let pid = match pipe_request(&record, "STATUS") {
            Ok(reply) => running_pid(&reply).ok_or_else(|| {
                invalid("Agent lifecycle status did not prove an owned running process")
            })?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "lifecycle pipe is absent; process exit cannot be proven without an authenticated PID",
                ));
            }
            Err(error) => return Err(error),
        };
        let process = open_owned_process(pid, &record)?;
        let reply = pipe_request(&record, "STOP")?;
        if reply.starts_with("BUSY ") {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "Agent refused shutdown because durable jobs are not terminal",
            ));
        }
        if reply != format!("STOPPING {pid}") {
            return Err(invalid(
                "Agent lifecycle control returned an invalid stop response",
            ));
        }
        // Pipe availability is not a process-exit signal. Keep the verified process
        // handle and wait on the kernel object, which is supported on Windows 7.
        // SAFETY: process.handle is a live handle opened with SYNCHRONIZE.
        match unsafe { WaitForSingleObject(process.handle, 10_000) } {
            WAIT_OBJECT_0 => {
                let active = active_jobs(&record)?;
                if !active.is_empty() {
                    if let Err(error) = launch_and_wait(&record) {
                        return Err(io::Error::other(format!(
                            "shutdown raced with durable job admission; Agent restart failed: {error}"
                        )));
                    }
                    return Err(busy(&active));
                }
                println!("Stopped the authenticated current-user HostLink Agent process");
                Ok(())
            }
            WAIT_TIMEOUT => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "Agent did not stop within 10 seconds; no process was force-terminated",
            )),
            _ => Err(io::Error::last_os_error()),
        }
    }

    /// Enter maintenance while the caller holds jobs::acquire_update_lock(root).
    /// No Run value or marker is changed until owner, image, registration, and jobs verify.
    pub(crate) fn begin_maintenance(root: &Path) -> io::Result<MaintenanceReceipt> {
        ensure_user_scope()?;
        let mut record = owned_record(root)?;
        verify_record(&record)?;
        verify_registration(&record)?;
        if record.maintenance || record.maintenance_previous_sha256.is_some() {
            return Err(invalid("service maintenance is already in progress"));
        }
        refuse_active_jobs(&record)?;

        let old_marker = read_marker_bytes(&record.root)?;
        let run_command = render_command(&record);
        let pid = match pipe_request(&record, "STATUS")? {
            reply => running_pid(&reply).ok_or_else(|| {
                invalid("maintenance requires an authenticated running Agent process")
            })?,
        };
        let process = open_owned_process(pid, &record)?;

        if read_marker_bytes(&record.root)? != old_marker
            || registry_value(&record.run_value)?.as_deref() != Some(run_command.as_str())
        {
            return Err(invalid(
                "service ownership state changed before maintenance entry",
            ));
        }
        refuse_active_jobs(&record)?;

        let old_record = record.clone();
        record.maintenance = true;
        record.maintenance_previous_sha256 = Some(record.executable_sha256.clone());
        replace_record_atomically(&record)?;
        if let Err(error) = delete_registry_value(&record.run_value) {
            let rollback = replace_marker_bytes(&record.root, &old_marker);
            let registration = match registry_value(&record.run_value) {
                Ok(None) => set_registry_value(&record.run_value, &run_command),
                Ok(Some(value)) if value == run_command => Ok(()),
                Ok(Some(_)) => Err(invalid(
                    "current-user login value changed during maintenance entry",
                )),
                Err(error) => Err(error),
            };
            return Err(io::Error::other(format!(
                "cannot disable the verified current-user login value: {error}; marker rollback: {rollback:?}; registration rollback: {registration:?}"
            )));
        }
        if registry_value(&record.run_value)?.is_some() {
            return Err(invalid(
                "current-user login value remained after maintenance disable",
            ));
        }

        let reply = pipe_request(&record, "STOP")?;
        if reply != format!("STOPPING {pid}") {
            return Err(invalid("authenticated Agent refused maintenance stop"));
        }
        // SAFETY: process.handle is a verified live handle opened with SYNCHRONIZE.
        match unsafe { WaitForSingleObject(process.handle, 10_000) } {
            WAIT_OBJECT_0 => {
                refuse_active_jobs(&record)?;
                Ok(MaintenanceReceipt {
                    old_marker,
                    old_record,
                    run_command,
                })
            }
            WAIT_TIMEOUT => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "Agent did not stop within 10 seconds; maintenance remains disabled and no process was force-terminated",
            )),
            _ => Err(io::Error::last_os_error()),
        }
    }

    /// Change only the owner marker's executable digest after the updater verified the file.
    pub(crate) fn update_maintenance_executable(
        receipt: &MaintenanceReceipt,
        expected_sha256: &str,
    ) -> io::Result<()> {
        validate_sha256(expected_sha256)?;
        let mut record = maintenance_record(receipt)?;
        if registry_value(&record.run_value)?.is_some() {
            return Err(invalid(
                "login registration must remain disabled while the executable is replaced",
            ));
        }
        if sha256_file(&record.executable)? != expected_sha256 {
            return Err(invalid(
                "replacement executable digest does not match verified bytes",
            ));
        }
        record.executable_sha256 = expected_sha256.to_owned();
        replace_record_atomically(&record)?;
        verify_record(&record)
    }

    /// Re-enable only the source-derived Run value after the marker matches the installed EXE.
    /// This does not launch the Agent or assert health.
    pub(crate) fn register_maintenance(receipt: &MaintenanceReceipt) -> io::Result<()> {
        let mut record = maintenance_record(receipt)?;
        if sha256_file(&record.executable)? != record.executable_sha256 {
            return Err(invalid(
                "installed executable does not match maintenance marker",
            ));
        }
        match registry_value(&record.run_value)? {
            None => set_registry_value(&record.run_value, &receipt.run_command)?,
            Some(value) if value == receipt.run_command => {}
            Some(_) => {
                return Err(invalid(
                    "current-user login value changed during maintenance",
                ));
            }
        }
        record.maintenance = false;
        record.maintenance_previous_sha256 = None;
        replace_record_atomically(&record)?;
        verify_record(&record)?;
        verify_registration(&record)
    }

    /// Restore old ownership bytes and login registration only after the coordinator proves
    /// the complete old file inventory from its validated transaction journal.
    pub(crate) fn restore_maintenance(
        receipt: &MaintenanceReceipt,
        verify_old_inventory: impl FnOnce(&Path) -> io::Result<()>,
    ) -> io::Result<()> {
        let record = maintenance_record(receipt)?;
        if sha256_file(&record.executable)? != receipt.old_record.executable_sha256 {
            return Err(invalid(
                "old executable inventory is not restored; maintenance rollback refused",
            ));
        }
        verify_old_inventory(&record.root)?;
        restore_old_marker_and_registration(receipt)
    }

    /// Re-enter the same maintenance receipt after a candidate restart failed, before
    /// the updater restores the old file inventory and calls restore_maintenance.
    pub(crate) fn stop_for_maintenance_rollback(receipt: &MaintenanceReceipt) -> io::Result<()> {
        let mut record = owned_record(&receipt.old_record.root)?;
        if record.maintenance {
            let _ = maintenance_record(receipt)?;
            return Ok(());
        }
        verify_record(&record)?;
        verify_registration(&record)?;
        if record.owner_sid != receipt.old_record.owner_sid
            || record.root != receipt.old_record.root
            || record.executable != receipt.old_record.executable
            || record.pipe_name != receipt.old_record.pipe_name
            || record.control_token != receipt.old_record.control_token
            || record.run_value != receipt.old_record.run_value
        {
            return Err(invalid(
                "rollback service identity differs from the maintenance receipt",
            ));
        }
        refuse_active_jobs(&record)?;
        let pid = running_pid(&pipe_request(&record, "STATUS")?)
            .ok_or_else(|| invalid("rollback requires authenticated running Agent status"))?;
        let process = open_owned_process(pid, &record)?;
        record.maintenance = true;
        record.maintenance_previous_sha256 = Some(receipt.old_record.executable_sha256.clone());
        replace_record_atomically(&record)?;
        if let Err(error) = delete_registry_value(&record.run_value) {
            return Err(io::Error::other(format!(
                "cannot disable login startup for rollback: {error}"
            )));
        }
        match registry_value(&record.run_value)? {
            None => {}
            _ => return Err(invalid("rollback login startup remained registered")),
        }
        if pipe_request(&record, "STOP")? != format!("STOPPING {pid}") {
            return Err(invalid("authenticated Agent refused rollback stop"));
        }
        match unsafe { WaitForSingleObject(process.handle, 10_000) } {
            WAIT_OBJECT_0 => refuse_active_jobs(&record),
            WAIT_TIMEOUT => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "candidate Agent did not stop for rollback; no process was force-terminated",
            )),
            _ => Err(io::Error::last_os_error()),
        }
    }

    /// Restore a durable maintenance marker only after the coordinator verifies the stopped
    /// process and complete old file inventory from its validated update journal. The callback
    /// must not mutate.
    pub(crate) fn recover_maintenance_after_inventory(
        root: &Path,
        verify_old_inventory: impl FnOnce(&Path) -> io::Result<()>,
    ) -> io::Result<()> {
        ensure_user_scope()?;
        let mut record = owned_record(root)?;
        let old_sha256 = match (
            record.maintenance,
            record.maintenance_previous_sha256.clone(),
        ) {
            (true, Some(digest)) => digest,
            (false, None) => record.executable_sha256.clone(),
            _ => return Err(invalid("service maintenance marker is inconsistent")),
        };
        validate_sha256(&old_sha256)?;
        if sha256_file(&record.executable)? != old_sha256 {
            return Err(invalid(
                "old executable digest does not match maintenance receipt",
            ));
        }
        match registry_value(&record.run_value)? {
            None => {}
            Some(value) if value == render_command(&record) => {}
            Some(_) => {
                return Err(invalid(
                    "current-user login value is occupied by another command",
                ));
            }
        }
        validate_record_paths(&record)?;
        verify_old_inventory(&record.root)?;

        if record.maintenance {
            record.executable_sha256 = old_sha256;
            record.maintenance = false;
            record.maintenance_previous_sha256 = None;
            replace_record_atomically(&record)?;
        }
        match registry_value(&record.run_value)? {
            None => set_registry_value(&record.run_value, &render_command(&record))?,
            Some(value) if value == render_command(&record) => {}
            Some(_) => return Err(invalid("current-user login value changed during recovery")),
        }
        verify_record(&record)?;
        verify_registration(&record)
    }

    pub fn remove(root: &Path) -> io::Result<()> {
        ensure_user_scope()?;
        let record = owned_record(root)?;
        refuse_maintenance(&record)?;
        verify_record(&record)?;
        crate::update::ensure_no_pending_windows_handoff(&record.root)?;
        verify_registration(&record)?;
        refuse_active_jobs(&record)?;
        match pipe_request(&record, "STATUS") {
            Ok(_) => stop(root)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "lifecycle pipe is absent; remove cannot prove the Agent process has exited",
                ));
            }
            Err(error) => return Err(error),
        }
        delete_registry_value(&record.run_value)?;
        if let Err(error) = fs::remove_file(&record.startup_script) {
            let rollback = set_registry_value(&record.run_value, &render_command(&record));
            return Err(io::Error::other(format!(
                "cannot remove startup launcher: {error}; startup registration restore: {rollback:?}"
            )));
        }
        if let Err(error) = fs::remove_file(record.root.join(MARKER)) {
            let rollback = set_registry_value(&record.run_value, &render_command(&record));
            let script_rollback =
                write_private(&record.startup_script, render_script(&record).as_bytes());
            return Err(io::Error::other(format!(
                "cannot remove service marker: {error}; startup registration restore: {rollback:?}; launcher restore: {script_rollback:?}"
            )));
        }
        println!(
            "Removed HostLink current-user login startup and ownership marker; enrollment keys, jobs, config and executable remain at {}",
            record.root.display()
        );
        Ok(())
    }

    pub fn status(root: &Path) -> io::Result<ServiceStatus> {
        ensure_user_scope()?;
        let root = verify_install_root(root)?;
        let record = match owned_record(&root) {
            Ok(record) => record,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(ServiceStatus {
                    installed: false,
                    active: false,
                    owner_uid: None,
                    owner_sid: None,
                    pid: None,
                    executable_sha256: None,
                    ssh_banner: false,
                    local_enrollment: false,
                    detail:
                        "unmanaged: no HostLink current-user lifecycle marker exists for this root"
                            .into(),
                });
            }
            Err(error) => return Err(error),
        };
        verify_record(&record)?;
        verify_registration(&record)?;
        let reply = match pipe_request(&record, "STATUS") {
            Ok(reply) => reply,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(ServiceStatus {
                    installed: true,
                    active: false,
                    owner_uid: None,
                    owner_sid: Some(record.owner_sid),
                    pid: None,
                    executable_sha256: Some(record.executable_sha256),
                    ssh_banner: false,
                    local_enrollment: has_enrollment(&record.root),
                    detail:
                        "installed for current-user interactive login; Agent process is not running"
                            .into(),
                });
            }
            Err(error) => return Err(error),
        };
        let pid = process_pid(&reply).ok_or_else(|| {
            invalid("Agent lifecycle control returned an invalid status response")
        })?;
        let stopping = stopping_pid(&reply).is_some();
        let config = load_config(&record.config)?;
        let ssh_banner = ssh_banner(config.listen)?;
        Ok(ServiceStatus {
            installed: true, active: !stopping, owner_uid: None, owner_sid: Some(record.owner_sid), pid: Some(pid),
            executable_sha256: Some(record.executable_sha256), ssh_banner,
            local_enrollment: has_enrollment(&record.root),
            detail: if stopping { "current-user Agent process is completing graceful shutdown" } else if ssh_banner { "current-user Agent process authenticated by private lifecycle pipe; loopback SSH 2.0 banner verified; Hub reachability not queried" } else { "current-user Agent process authenticated by private lifecycle pipe; loopback SSH endpoint is unreachable; Hub reachability not queried" }.into(),
        })
    }

    pub fn validate_managed_run(config: &Path) -> io::Result<(String, String)> {
        ensure_user_scope()?;
        let config = canonical_regular(config)?;
        let root = config
            .parent()
            .and_then(Path::parent)
            .ok_or_else(|| invalid("managed Agent config is outside its install root"))?;
        let record = owned_record(root)?;
        refuse_maintenance(&record)?;
        verify_record(&record)?;
        crate::update::ensure_no_pending_windows_handoff(&record.root)?;
        verify_registration(&record)?;
        if config != record.config || std::env::current_exe()?.canonicalize()? != record.executable
        {
            return Err(invalid(
                "managed Agent startup identity or source executable does not match its private record",
            ));
        }
        load_config(&record.config)?;
        Ok((record.pipe_name, record.control_token))
    }

    pub fn ensure_update_unregistered(root: &Path) -> io::Result<()> {
        let root = verify_install_root(root)?;
        match fs::symlink_metadata(root.join(MARKER)) {
            Ok(_) => Err(invalid(
                "remove the current-user Agent lifecycle registration before updating its executable",
            )),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }

    pub fn validate_update_root(root: &Path) -> io::Result<()> {
        let root = verify_install_root(root)?;
        let expected = local_app_data_path()?.join("HostLink").join("Agent");
        if fs::canonicalize(expected)? != root {
            return Err(invalid(
                "Agent updater root must be the exact OS-owned LocalAppData/HostLink/Agent directory",
            ));
        }
        Ok(())
    }

    pub async fn control_loop(
        config: &crate::AgentConfig,
        pipe_name: String,
        token: String,
        shutdown: tokio_util::sync::CancellationToken,
        finished: tokio_util::sync::CancellationToken,
    ) -> io::Result<()> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut pipe = create_private_pipe(&pipe_name, true)?;
        loop {
            tokio::select! {
                _ = finished.cancelled() => return Ok(()),
                result = pipe.connect() => result?,
            }
            // Publish the next private server instance before handling this client.
            // This keeps STATUS continuously available while bounding live instances to two.
            let next_pipe = create_private_pipe(&pipe_name, false)?;
            let mut request = vec![0u8; MAX_PIPE_MESSAGE];
            let count = tokio::select! {
                _ = finished.cancelled() => return Ok(()),
                result = pipe.read(&mut request) => result?,
            };
            let request = std::str::from_utf8(&request[..count]).unwrap_or("").trim();
            let response = if request == format!("STATUS {token}") {
                if shutdown.is_cancelled() {
                    format!("STOPPING {}\n", std::process::id())
                } else {
                    format!("RUNNING {}\n", std::process::id())
                }
            } else if request == format!("STOP {token}") {
                let active = jobs::active_ids(&config.jobs_root)?;
                if active.is_empty() {
                    shutdown.cancel();
                    format!("STOPPING {}\n", std::process::id())
                } else {
                    format!("BUSY {}\n", active.len())
                }
            } else {
                "DENIED\n".to_owned()
            };
            pipe.write_all(response.as_bytes()).await?;
            pipe.flush().await?;
            drop(pipe);
            pipe = next_pipe;
        }
    }

    fn create_private_pipe(
        pipe_name: &str,
        first: bool,
    ) -> io::Result<tokio::net::windows::named_pipe::NamedPipeServer> {
        use tokio::net::windows::named_pipe::ServerOptions;
        use windows_permissions::{LocalBox, SecurityDescriptor};
        use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;

        let owner =
            windows_permissions::utilities::current_process_sid().map_err(io::Error::other)?;
        let owner_text = windows_permissions::wrappers::ConvertSidToStringSid(&owner)
            .map_err(io::Error::other)?;
        let sddl = format!("D:P(A;;GA;;;{})", owner_text.to_string_lossy());
        let descriptor: LocalBox<SecurityDescriptor> = sddl.parse().map_err(io::Error::other)?;
        let mut attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.as_ptr().cast(),
            bInheritHandle: 0,
        };
        // SAFETY: the security attributes and descriptor stay alive through CreateNamedPipeW;
        // Windows copies the descriptor into the new pipe object before this call returns.
        unsafe {
            ServerOptions::new()
                .reject_remote_clients(true)
                .first_pipe_instance(first)
                .create_with_security_attributes_raw(
                    pipe_name,
                    (&mut attributes as *mut SECURITY_ATTRIBUTES).cast(),
                )
        }
    }

    fn prepare_record(root: &Path, config: &Path) -> io::Result<InstallRecord> {
        let owner = current_sid()?;
        let root = verify_install_root(root)?;
        let config = canonical_regular(config)?;
        if config != root.join("state/agent.json") {
            return Err(invalid(
                "service install requires the fresh enrollment config at ROOT/state/agent.json",
            ));
        }
        verify_enrollment_root(&root)?;
        canonical_private_dir(&root.join("bin"))?;
        let _config = load_config(&config)?;
        let executable = std::env::current_exe()?.canonicalize()?;
        if executable != agent_executable(&root) {
            return Err(invalid(
                "hostlink-agent executable must be ROOT/bin/hostlink-agent for this fresh install root",
            ));
        }
        canonical_regular(&executable)?;
        let executable_sha256 = sha256_file(&executable)?;
        let digest = hex(&Sha256::digest(root.as_os_str().to_string_lossy().as_bytes())[..12]);
        let token = random_token();
        let pipe_name = format!(r"\\.\pipe\hostlink-agent-{digest}-{}", &token[..16]);
        let startup_script = root.join(".hostlink-agent-start.vbs");
        let launcher_executable = system_wscript()?;
        let launcher_metadata = fs::symlink_metadata(&launcher_executable)?;
        if !launcher_metadata.is_file() || is_reparse(&launcher_metadata) {
            return Err(invalid(
                "system Windows Script Host executable is missing or unsafe",
            ));
        }
        let mut record = InstallRecord {
            format: MARKER_FORMAT,
            owner_sid: owner,
            root,
            executable,
            executable_sha256,
            config,
            launcher_executable,
            startup_script,
            startup_script_sha256: String::new(),
            pipe_name,
            control_token: token,
            run_value: String::new(),
            maintenance: false,
            maintenance_previous_sha256: None,
        };
        record.startup_script_sha256 =
            format!("{:x}", Sha256::digest(render_script(&record).as_bytes()));
        record.run_value = run_value_name(&record.root);
        let command = render_command(&record);
        if command.encode_utf16().count() + 1 > 260 {
            return Err(invalid(
                "HostLink startup command exceeds the Windows HKCU Run 260-character limit; choose a shorter private install root",
            ));
        }
        Ok(record)
    }

    fn owned_record(root: &Path) -> io::Result<InstallRecord> {
        let root = verify_install_root(root)?;
        let path = root.join(MARKER);
        let metadata = fs::symlink_metadata(&path)?;
        if !metadata.is_file() || is_reparse(&metadata) {
            return Err(invalid("service marker must be a regular non-reparse file"));
        }
        verify_private_acl(&path)?;
        let mut bytes = Vec::new();
        File::open(path)?
            .take((MAX_MARKER + 1) as u64)
            .read_to_end(&mut bytes)?;
        if bytes.len() > MAX_MARKER {
            return Err(invalid("service marker exceeds size limit"));
        }
        let record: InstallRecord =
            serde_json::from_slice(&bytes).map_err(|_| invalid("service marker is invalid"))?;
        if record.format != MARKER_FORMAT
            || record.owner_sid != current_sid()?
            || record.root != root
        {
            return Err(invalid(
                "service marker owner or root does not match the current user",
            ));
        }
        Ok(record)
    }

    fn verify_record(record: &InstallRecord) -> io::Result<()> {
        if record.owner_sid != current_sid()?
            || record.run_value != run_value_name(&record.root)
            || record.executable != agent_executable(&record.root)
            || record.config != record.root.join("state/agent.json")
            || record.launcher_executable != system_wscript()?
            || record.startup_script != record.root.join(".hostlink-agent-start.vbs")
            || !record.pipe_name.starts_with(r"\\.\pipe\hostlink-agent-")
            || record.control_token.len() != 64
            || !record.control_token.bytes().all(|b| b.is_ascii_hexdigit())
            || record.maintenance != record.maintenance_previous_sha256.is_some()
        {
            return Err(invalid(
                "service marker paths or current-user identity are inconsistent",
            ));
        }
        if let Some(previous) = &record.maintenance_previous_sha256 {
            validate_sha256(previous)?;
        }
        validate_sha256(&record.executable_sha256)?;
        if canonical_regular(&record.executable)? != record.executable
            || canonical_regular(&record.config)? != record.config
        {
            return Err(invalid(
                "service executable or config path is not canonical",
            ));
        }
        verify_enrollment_root(&record.root)?;
        canonical_private_dir(&record.root.join("bin"))?;
        if sha256_file(&record.executable)? != record.executable_sha256 {
            return Err(invalid(
                "installed Agent executable SHA-256 changed; service will not be controlled",
            ));
        }
        canonical_regular(&record.startup_script)?;
        let script = fs::read(&record.startup_script)?;
        if format!("{:x}", Sha256::digest(&script)) != record.startup_script_sha256
            || script != render_script(record).as_bytes()
        {
            return Err(invalid(
                "current-user startup launcher differs from the owned record",
            ));
        }
        if render_command(record).encode_utf16().count() + 1 > 260 {
            return Err(invalid(
                "owned startup command exceeds the Windows HKCU Run limit",
            ));
        }
        let launcher_metadata = fs::symlink_metadata(&record.launcher_executable)?;
        if !launcher_metadata.is_file() || is_reparse(&launcher_metadata) {
            return Err(invalid("Windows Script Host launcher path is unsafe"));
        }
        Ok(())
    }

    fn spawn(record: &InstallRecord) -> io::Result<OwnedProcess> {
        use std::os::windows::process::CommandExt;
        let child = Command::new(&record.executable)
            .arg("run")
            .arg(format!("--config={}", record.config.display()))
            .arg("--managed-service")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .creation_flags(windows_sys::Win32::System::Threading::CREATE_NO_WINDOW)
            .spawn()?;
        let process = open_owned_process(child.id(), record)?;
        drop(child); // Detach without terminating; keep the synchronized handle.
        Ok(process)
    }

    fn launch_and_wait(record: &InstallRecord) -> io::Result<()> {
        let process = spawn(record)?;
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

    fn render_command(record: &InstallRecord) -> String {
        format!(
            "{} //B //NoLogo {}",
            windows_quote(&record.launcher_executable.to_string_lossy()),
            windows_quote(&record.startup_script.to_string_lossy())
        )
    }

    fn render_script(record: &InstallRecord) -> String {
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

    fn system_wscript() -> io::Result<PathBuf> {
        let mut buffer = vec![0u16; 32_768];
        // SAFETY: GetSystemDirectoryW writes at most the supplied UTF-16 buffer length.
        let length =
            unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) } as usize;
        if length == 0 || length >= buffer.len() {
            return Err(io::Error::last_os_error());
        }
        let directory = String::from_utf16_lossy(&buffer[..length]);
        Ok(PathBuf::from(directory).join("wscript.exe"))
    }

    fn pipe_request(record: &InstallRecord, action: &str) -> io::Result<String> {
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

    fn running_pid(reply: &str) -> Option<u32> {
        reply
            .strip_prefix("RUNNING ")
            .and_then(|value| value.parse::<u32>().ok())
            .filter(|pid| *pid != 0)
    }

    fn stopping_pid(reply: &str) -> Option<u32> {
        reply
            .strip_prefix("STOPPING ")
            .and_then(|value| value.parse::<u32>().ok())
            .filter(|pid| *pid != 0)
    }

    fn process_pid(reply: &str) -> Option<u32> {
        running_pid(reply).or_else(|| stopping_pid(reply))
    }

    struct OwnedProcess {
        handle: HANDLE,
        pid: u32,
    }

    impl Drop for OwnedProcess {
        fn drop(&mut self) {
            // SAFETY: this type uniquely owns a valid process handle.
            unsafe { CloseHandle(self.handle) };
        }
    }

    fn open_owned_process(pid: u32, record: &InstallRecord) -> io::Result<OwnedProcess> {
        // SAFETY: OpenProcess receives a PID obtained from the authenticated private pipe.
        let handle =
            unsafe { OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
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
        if unsafe { QueryFullProcessImageNameW(handle, 0, image.as_mut_ptr(), &mut image_len) } == 0
        {
            return Err(io::Error::other(format!(
                "cannot verify authenticated Agent process image path: {}",
                io::Error::last_os_error()
            )));
        }
        use std::os::windows::ffi::OsStringExt;
        let image_path = PathBuf::from(std::ffi::OsString::from_wide(&image[..image_len as usize]))
            .canonicalize()?;
        if image_path != record.executable || sha256_file(&image_path)? != record.executable_sha256
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "authenticated lifecycle PID image does not match the owned Agent path and SHA-256",
            ));
        }
        Ok(process)
    }

    fn refuse_active_jobs(record: &InstallRecord) -> io::Result<()> {
        let active = active_jobs(record)?;
        if active.is_empty() {
            Ok(())
        } else {
            Err(busy(&active))
        }
    }

    fn verify_registration(record: &InstallRecord) -> io::Result<()> {
        if registry_value(&record.run_value)?.as_deref() == Some(render_command(record).as_str()) {
            Ok(())
        } else {
            Err(invalid(
                "current-user startup registration differs from the owned record",
            ))
        }
    }

    fn refuse_maintenance(record: &InstallRecord) -> io::Result<()> {
        if record.maintenance || record.maintenance_previous_sha256.is_some() {
            Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "HostLink Agent is held in service maintenance; managed startup is disabled",
            ))
        } else {
            Ok(())
        }
    }

    fn read_marker_bytes(root: &Path) -> io::Result<Vec<u8>> {
        let path = root.join(MARKER);
        let metadata = fs::symlink_metadata(&path)?;
        if !metadata.is_file() || is_reparse(&metadata) || metadata.len() > MAX_MARKER as u64 {
            return Err(invalid("service marker is unsafe or exceeds size limit"));
        }
        verify_private_acl(&path)?;
        fs::read(path)
    }

    fn maintenance_record(receipt: &MaintenanceReceipt) -> io::Result<InstallRecord> {
        let record = owned_record(&receipt.old_record.root)?;
        let old = &receipt.old_record;
        if !record.maintenance
            || record.maintenance_previous_sha256.as_deref() != Some(old.executable_sha256.as_str())
            || record.owner_sid != old.owner_sid
            || record.root != old.root
            || record.executable != old.executable
            || record.config != old.config
            || record.pipe_name != old.pipe_name
            || record.control_token != old.control_token
            || record.run_value != old.run_value
            || render_command(&record) != receipt.run_command
        {
            return Err(invalid(
                "service maintenance receipt no longer matches its owner marker",
            ));
        }
        match registry_value(&record.run_value)? {
            None => {}
            Some(value) if value == receipt.run_command => {}
            Some(_) => {
                return Err(invalid(
                    "current-user login value was occupied during maintenance",
                ));
            }
        }
        validate_record_paths(&record)?;
        Ok(record)
    }

    fn restore_old_marker_and_registration(receipt: &MaintenanceReceipt) -> io::Result<()> {
        let record = maintenance_record(receipt)?;
        if sha256_file(&record.executable)? != receipt.old_record.executable_sha256 {
            return Err(invalid(
                "old executable inventory is not restored; marker rollback refused",
            ));
        }
        replace_marker_bytes(&record.root, &receipt.old_marker)?;
        match registry_value(&record.run_value)? {
            None => set_registry_value(&record.run_value, &receipt.run_command)?,
            Some(value) if value == receipt.run_command => {}
            Some(_) => {
                return Err(invalid(
                    "current-user login value is occupied by another command",
                ));
            }
        }
        verify_record(&receipt.old_record)?;
        verify_registration(&receipt.old_record)
    }

    fn replace_record_atomically(record: &InstallRecord) -> io::Result<()> {
        let bytes = serde_json::to_vec(record).map_err(io::Error::other)?;
        replace_marker_bytes(&record.root, &bytes)?;
        let actual = owned_record(&record.root)?;
        if actual.maintenance != record.maintenance
            || actual.maintenance_previous_sha256 != record.maintenance_previous_sha256
            || actual.executable_sha256 != record.executable_sha256
        {
            return Err(invalid(
                "service marker atomic readback did not match requested state",
            ));
        }
        Ok(())
    }

    fn replace_marker_bytes(root: &Path, bytes: &[u8]) -> io::Result<()> {
        if bytes.len() > MAX_MARKER {
            return Err(invalid("service marker exceeds size limit"));
        }
        let marker = root.join(MARKER);
        let temporary = root.join(format!(".hostlink-service-marker-{}.tmp", random_token()));
        write_private(&temporary, bytes)?;
        let result = replace_file(&marker, &temporary);
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result?;
        let metadata = fs::symlink_metadata(&marker)?;
        if !metadata.is_file() || is_reparse(&metadata) {
            return Err(invalid("replaced service marker is not a regular file"));
        }
        verify_private_acl(&marker)?;
        if fs::read(&marker)? != bytes {
            return Err(invalid("service marker replacement readback failed"));
        }
        Ok(())
    }

    fn replace_file(target: &Path, replacement: &Path) -> io::Result<()> {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Storage::FileSystem::ReplaceFileW;
        let target = target
            .as_os_str()
            .encode_wide()
            .chain(Some(0))
            .collect::<Vec<_>>();
        let replacement = replacement
            .as_os_str()
            .encode_wide()
            .chain(Some(0))
            .collect::<Vec<_>>();
        // SAFETY: paths are NUL-terminated and zero flags require ACL preservation to succeed.
        if unsafe {
            ReplaceFileW(
                target.as_ptr(),
                replacement.as_ptr(),
                std::ptr::null(),
                0,
                std::ptr::null(),
                std::ptr::null(),
            )
        } == 0
        {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    fn validate_record_paths(record: &InstallRecord) -> io::Result<()> {
        if record.owner_sid != current_sid()?
            || record.root != verify_install_root(&record.root)?
            || record.run_value != run_value_name(&record.root)
            || record.executable != agent_executable(&record.root)
            || record.config != record.root.join("state/agent.json")
            || record.launcher_executable != system_wscript()?
            || record.startup_script != record.root.join(".hostlink-agent-start.vbs")
        {
            return Err(invalid("service maintenance owner paths are inconsistent"));
        }
        verify_enrollment_root(&record.root)?;
        canonical_regular(&record.config)?;
        canonical_regular(&record.startup_script)?;
        Ok(())
    }

    fn validate_sha256(value: &str) -> io::Result<()> {
        if value.len() != 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(invalid("executable digest must be lowercase SHA-256"));
        }
        Ok(())
    }

    fn active_jobs(record: &InstallRecord) -> io::Result<Vec<String>> {
        jobs::active_ids(&load_config(&record.config)?.jobs_root)
    }

    fn load_config(path: &Path) -> io::Result<crate::AgentConfig> {
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.is_file() || is_reparse(&metadata) || metadata.len() > 64 * 1024 {
            return Err(invalid("Agent config is unsafe or exceeds size limit"));
        }
        verify_private_acl(path)?;
        let bytes = fs::read(path)?;
        let mut config: crate::AgentConfig =
            serde_json::from_slice(&bytes).map_err(io::Error::other)?;
        let base = path.parent().unwrap_or_else(|| Path::new("."));
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
        let state = path.parent().unwrap_or_else(|| Path::new("."));
        let root = state
            .parent()
            .ok_or_else(|| invalid("Agent config is outside its install root"))?;
        let expected_host_key = canonical_regular(&state.join("host_key"))?;
        let expected_authorized_keys = canonical_regular(&state.join("authorized_keys"))?;
        let expected_jobs_root = canonical_private_dir(&root.join("jobs"))?;
        config.host_key = canonical_regular(&config.host_key)?;
        config.authorized_keys = canonical_regular(&config.authorized_keys)?;
        config.jobs_root = canonical_private_dir(&config.jobs_root)?;
        if config.host_key != expected_host_key
            || config.authorized_keys != expected_authorized_keys
            || config.jobs_root != expected_jobs_root
        {
            return Err(invalid(
                "service config credentials and durable jobs must remain in the fresh Agent root",
            ));
        }
        for (index, gateway) in config
            .gateway
            .iter_mut()
            .chain(config.gateway_alternates.iter_mut())
            .enumerate()
        {
            let expected_host_key = if index == 0 {
                state.join("gateway_host_key")
            } else {
                state.join(format!("gateway_host_key_{index}"))
            };
            let expected_identity = canonical_regular(&state.join("gateway_identity"))?;
            let expected_host_key = canonical_regular(&expected_host_key)?;
            gateway.identity = canonical_regular(&gateway.identity)?;
            gateway.host_public_key = canonical_regular(&gateway.host_public_key)?;
            if gateway.identity != expected_identity || gateway.host_public_key != expected_host_key
            {
                return Err(invalid(
                    "service gateway credentials must remain in the fresh Agent root",
                ));
            }
        }
        config.validate()?;
        Ok(config)
    }

    fn verify_enrollment_root(root: &Path) -> io::Result<()> {
        let state = root.join("state");
        canonical_private_dir(&state)?;
        for name in [
            "agent.json",
            "machine.json",
            "manifest.json",
            "authorized_keys",
            "gateway_host_key",
            "gateway_identity",
            "host_key",
        ] {
            canonical_regular(&state.join(name))?;
        }
        let manifest_bytes = read_private(&state.join("manifest.json"), 64 * 1024)?;
        let machine_bytes = read_private(&state.join("machine.json"), 16 * 1024)?;
        let manifest: serde_json::Value = serde_json::from_slice(&manifest_bytes)
            .map_err(|_| invalid("Agent enrollment manifest is invalid"))?;
        let machine: serde_json::Value = serde_json::from_slice(&machine_bytes)
            .map_err(|_| invalid("Agent enrollment identity is invalid"))?;
        if manifest["format"].as_u64() != Some(1)
            || machine["format"].as_u64() != Some(1)
            || manifest["machine_id"] != machine["machine_id"]
            || machine["machine_id"].as_str().is_none_or(str::is_empty)
            || machine["name"].as_str().is_none_or(str::is_empty)
            || machine["ssh_public_key"].as_str().is_none_or(str::is_empty)
            || machine["ssh_host_public_key"]
                .as_str()
                .is_none_or(str::is_empty)
        {
            return Err(invalid(
                "Agent enrollment identity and manifest do not match",
            ));
        }
        let files = manifest["files"]
            .as_object()
            .ok_or_else(|| invalid("Agent enrollment manifest files are missing"))?;
        for required in [
            "agent.json",
            "machine.json",
            "authorized_keys",
            "gateway_host_key",
            "gateway_identity",
            "host_key",
        ] {
            if !files.contains_key(required) {
                return Err(invalid("Agent enrollment manifest is incomplete"));
            }
        }
        for (name, expected) in files {
            if name.contains('/') || name.contains('\\') || name == "." || name == ".." {
                return Err(invalid("Agent enrollment manifest contains unsafe path"));
            }
            let path = state.join(name);
            canonical_regular(&path)?;
            let bytes = read_private(&path, 1024 * 1024)?;
            let digest = format!("{:x}", Sha256::digest(&bytes));
            if expected["size"].as_u64() != Some(bytes.len() as u64)
                || expected["sha256"].as_str() != Some(&digest)
            {
                return Err(invalid("Agent enrollment file does not match its manifest"));
            }
        }
        Ok(())
    }

    fn read_private(path: &Path, limit: u64) -> io::Result<Vec<u8>> {
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.is_file() || is_reparse(&metadata) || metadata.len() > limit {
            return Err(invalid(
                "Agent enrollment file is unsafe or exceeds its size limit",
            ));
        }
        verify_private_acl(path)?;
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        File::open(path)?.take(limit + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > limit {
            return Err(invalid("Agent enrollment file exceeds its size limit"));
        }
        Ok(bytes)
    }

    fn canonical_private_dir(path: &Path) -> io::Result<PathBuf> {
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.is_dir() || is_reparse(&metadata) {
            return Err(invalid(
                "Agent service directory must be a non-reparse directory",
            ));
        }
        verify_private_acl(path)?;
        let mut ancestor = path;
        while let Some(parent) = ancestor.parent() {
            let metadata = fs::symlink_metadata(parent)?;
            if is_reparse(&metadata) {
                return Err(invalid("Agent service path contains a reparse point"));
            }
            ancestor = parent;
        }
        path.canonicalize()
    }

    fn verify_install_root(path: &Path) -> io::Result<PathBuf> {
        let root = canonical_private_dir(path)?;
        let local_app_data = local_app_data_path()?;
        let profile_metadata = fs::symlink_metadata(&local_app_data)?;
        if !profile_metadata.is_dir() || is_reparse(&profile_metadata) {
            return Err(invalid(
                "Windows LocalAppData profile boundary is missing or is a reparse point",
            ));
        }
        // SHGetKnownFolderPath is used instead of an environment variable, so a
        // caller cannot redirect lifecycle storage to a shared or spoofed tree.
        // The OS-owned profile directory is the trust boundary for ancestors.
        // The official installer uses LocalAppData/HostLink/Agent. Verify
        // every intermediate directory's private owner-only ACL rather than
        // rejecting the valid two-level layout or trusting shared parents.
        let descriptor = windows_permissions::wrappers::GetNamedSecurityInfo(
            local_app_data.as_os_str(),
            windows_permissions::constants::SeObjectType::SE_FILE_OBJECT,
            windows_permissions::constants::SecurityInformation::Owner
                | windows_permissions::constants::SecurityInformation::Dacl,
        )
        .map_err(io::Error::other)?;
        let current =
            windows_permissions::utilities::current_process_sid().map_err(io::Error::other)?;
        if descriptor.owner() != Some(current.as_ref()) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Windows LocalAppData profile boundary is not owned by the current user",
            ));
        }
        let system: windows_permissions::LocalBox<windows_permissions::Sid> =
            "S-1-5-18".parse().map_err(io::Error::other)?;
        let administrators: windows_permissions::LocalBox<windows_permissions::Sid> =
            "S-1-5-32-544".parse().map_err(io::Error::other)?;
        let dacl = descriptor
            .dacl()
            .ok_or_else(|| invalid("Windows LocalAppData profile boundary has no DACL"))?;
        for index in 0..dacl.len() {
            let ace = dacl
                .get_ace(index)
                .ok_or_else(|| invalid("Windows LocalAppData DACL entry is unreadable"))?;
            if matches!(
                ace.ace_type(),
                windows_permissions::constants::AceType::ACCESS_ALLOWED_ACE_TYPE
                    | windows_permissions::constants::AceType::ACCESS_ALLOWED_CALLBACK_ACE_TYPE
                    | windows_permissions::constants::AceType::ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE
                    | windows_permissions::constants::AceType::ACCESS_ALLOWED_OBJECT_ACE_TYPE
            ) && ![
                Some(current.as_ref()),
                Some(system.as_ref()),
                Some(administrators.as_ref()),
            ]
            .contains(&ace.sid())
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "Windows LocalAppData profile boundary grants access to an untrusted SID",
                ));
            }
        }
        // Canonicalize both sides: Windows typically returns a \\?\ path for
        // fs::canonicalize but SHGetKnownFolderPath yields an ordinary C:\ path.
        let profile = fs::canonicalize(&local_app_data)?;
        let relative = root.strip_prefix(&profile).map_err(|_| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Agent root is outside the current user's Windows LocalAppData directory",
            )
        })?;
        let depth = relative.components().count();
        if depth == 0 || depth > 8 {
            return Err(invalid(
                "Agent root must be a bounded private descendant of LocalAppData",
            ));
        }
        let mut parent = root.parent();
        while let Some(directory) = parent {
            if directory == profile {
                break;
            }
            canonical_private_dir(directory)?;
            parent = directory.parent();
        }
        if parent != Some(profile.as_path()) {
            return Err(invalid("Agent root ancestry could not be verified"));
        }
        Ok(root)
    }

    fn local_app_data_path() -> io::Result<PathBuf> {
        use std::{ffi::OsString, os::windows::ffi::OsStringExt};
        let mut path = std::ptr::null_mut();
        // SAFETY: the known-folder GUID is static and the output pointer is writable.
        let result = unsafe {
            SHGetKnownFolderPath(&FOLDERID_LocalAppData, 0, std::ptr::null_mut(), &mut path)
        };
        if result < 0 || path.is_null() {
            return Err(io::Error::other(format!(
                "cannot resolve the current user's Windows LocalAppData folder (HRESULT {result:#x})"
            )));
        }
        // SAFETY: SHGetKnownFolderPath returns a NUL-terminated CoTaskMem allocation.
        let value = unsafe {
            let mut length = 0usize;
            while *path.add(length) != 0 {
                length += 1;
            }
            let result = PathBuf::from(OsString::from_wide(std::slice::from_raw_parts(
                path, length,
            )));
            CoTaskMemFree(path.cast());
            result
        };
        value.canonicalize()
    }
    fn canonical_regular(path: &Path) -> io::Result<PathBuf> {
        use std::os::windows::io::AsRawHandle;
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.is_file() || is_reparse(&metadata) {
            return Err(invalid(
                "Agent service input must be a regular non-reparse file",
            ));
        }
        let file = File::open(path)?;
        let mut info = std::mem::MaybeUninit::<
            windows_sys::Win32::Storage::FileSystem::BY_HANDLE_FILE_INFORMATION,
        >::uninit();
        // SAFETY: the open file handle is live and the API initializes the full output structure on success.
        if unsafe {
            windows_sys::Win32::Storage::FileSystem::GetFileInformationByHandle(
                file.as_raw_handle().cast(),
                info.as_mut_ptr(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: GetFileInformationByHandle returned success and initialized `info`.
        if unsafe { info.assume_init() }.nNumberOfLinks != 1 {
            return Err(invalid("Agent service input must not have hard links"));
        }
        verify_private_acl(path)?;
        let mut ancestor = path.parent();
        while let Some(parent) = ancestor {
            let metadata = fs::symlink_metadata(parent)?;
            if is_reparse(&metadata) {
                return Err(invalid("Agent service input path contains a reparse point"));
            }
            ancestor = parent.parent();
        }
        path.canonicalize()
    }
    fn verify_private_acl(path: &Path) -> io::Result<()> {
        use windows_permissions::{
            constants::{AceType, SeObjectType, SecurityInformation},
            wrappers::{ConvertSecurityDescriptorToStringSecurityDescriptor, GetNamedSecurityInfo},
        };
        let descriptor = GetNamedSecurityInfo(
            path.as_os_str(),
            SeObjectType::SE_FILE_OBJECT,
            SecurityInformation::Dacl | SecurityInformation::Owner,
        )
        .map_err(io::Error::other)?;
        let current =
            windows_permissions::utilities::current_process_sid().map_err(io::Error::other)?;
        if descriptor.owner() != Some(current.as_ref()) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Agent service path is not owned by the current user",
            ));
        }
        let sddl = ConvertSecurityDescriptorToStringSecurityDescriptor(
            &descriptor,
            SecurityInformation::Dacl,
        )
        .map_err(io::Error::other)?;
        if !sddl.to_string_lossy().starts_with("D:P") {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Agent service path ACL must be protected from inheritance",
            ));
        }
        let dacl = descriptor
            .dacl()
            .ok_or_else(|| invalid("Agent service path has no DACL"))?;
        for index in 0..dacl.len() {
            let ace = dacl
                .get_ace(index)
                .ok_or_else(|| invalid("Agent service DACL entry is unreadable"))?;
            if matches!(
                ace.ace_type(),
                AceType::ACCESS_ALLOWED_ACE_TYPE
                    | AceType::ACCESS_ALLOWED_CALLBACK_ACE_TYPE
                    | AceType::ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE
                    | AceType::ACCESS_ALLOWED_OBJECT_ACE_TYPE
            ) && ace.sid() != Some(current.as_ref())
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "Agent service ACL grants access to a different user",
                ));
            }
        }
        Ok(())
    }
    fn is_reparse(metadata: &fs::Metadata) -> bool {
        metadata.file_attributes() & 0x400 != 0
    }
    fn current_sid() -> io::Result<String> {
        Ok(windows_permissions::utilities::current_process_sid()
            .map_err(io::Error::other)?
            .to_string())
    }
    fn ensure_user_scope() -> io::Result<()> {
        let current =
            windows_permissions::utilities::current_process_sid().map_err(io::Error::other)?;
        let system: windows_permissions::LocalBox<windows_permissions::Sid> =
            "S-1-5-18".parse().map_err(io::Error::other)?;
        if current.as_ref() == system.as_ref() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Agent service management must not run as SYSTEM",
            ));
        }
        let mut token = std::ptr::null_mut();
        // SAFETY: token APIs receive a valid current-process pseudo handle and writable output buffer.
        unsafe {
            use windows_sys::Win32::{
                Security::{GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation},
                System::Threading::{GetCurrentProcess, OpenProcessToken},
            };
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                return Err(io::Error::from_raw_os_error(GetLastError() as i32));
            }
            let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
            let mut returned = 0;
            let ok = GetTokenInformation(
                token,
                TokenElevation,
                (&mut elevation as *mut TOKEN_ELEVATION).cast(),
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut returned,
            );
            windows_sys::Win32::Foundation::CloseHandle(token);
            if ok == 0 {
                return Err(io::Error::from_raw_os_error(GetLastError() as i32));
            }
            if elevation.TokenIsElevated != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "Agent service management must run as a non-elevated current user",
                ));
            }
        }
        Ok(())
    }
    fn run_value_name(root: &Path) -> String {
        format!(
            "HostLinkAgent-{}",
            hex(&Sha256::digest(root.as_os_str().to_string_lossy().as_bytes())[..12])
        )
    }

    fn agent_executable(root: &Path) -> PathBuf {
        root.join("bin/hostlink-agent.exe")
    }
    fn registry_value(name: &str) -> io::Result<Option<String>> {
        let key_name = wide(RUN_KEY);
        let value_name = wide(name);
        let mut key: HKEY = std::ptr::null_mut();
        // SAFETY: registry handles and buffers follow the documented Win32 API contracts.
        let status = unsafe {
            RegOpenKeyExW(
                HKEY_CURRENT_USER,
                key_name.as_ptr(),
                0,
                KEY_QUERY_VALUE,
                &mut key,
            )
        };
        if status != ERROR_SUCCESS {
            return if status == 2 {
                Ok(None)
            } else {
                Err(io::Error::from_raw_os_error(status as i32))
            };
        }
        let mut kind = 0;
        let mut bytes = 0;
        let status = unsafe {
            RegQueryValueExW(
                key,
                value_name.as_ptr(),
                std::ptr::null(),
                &mut kind,
                std::ptr::null_mut(),
                &mut bytes,
            )
        };
        if status != ERROR_SUCCESS {
            unsafe {
                RegCloseKey(key);
            }
            return if status == 2 {
                Ok(None)
            } else {
                Err(io::Error::from_raw_os_error(status as i32))
            };
        }
        if kind != REG_SZ || bytes < 2 || bytes as usize > 64 * 1024 {
            unsafe {
                RegCloseKey(key);
            }
            return Err(invalid(
                "HKCU startup value has an unexpected registry type or size",
            ));
        }
        let mut data = vec![0u16; bytes as usize / 2];
        let status = unsafe {
            RegQueryValueExW(
                key,
                value_name.as_ptr(),
                std::ptr::null(),
                &mut kind,
                data.as_mut_ptr().cast(),
                &mut bytes,
            )
        };
        unsafe {
            RegCloseKey(key);
        }
        if status != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        let end = data.iter().position(|ch| *ch == 0).unwrap_or(data.len());
        String::from_utf16(&data[..end])
            .map(Some)
            .map_err(io::Error::other)
    }
    fn set_registry_value(name: &str, value: &str) -> io::Result<()> {
        let key_name = wide(RUN_KEY);
        let value_name = wide(name);
        let data = wide(value);
        let mut key: HKEY = std::ptr::null_mut();
        let mut disposition = 0;
        let status = unsafe {
            RegCreateKeyExW(
                HKEY_CURRENT_USER,
                key_name.as_ptr(),
                0,
                std::ptr::null(),
                REG_OPTION_NON_VOLATILE,
                KEY_SET_VALUE,
                std::ptr::null(),
                &mut key,
                &mut disposition,
            )
        };
        if status != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        let status = unsafe {
            RegSetValueExW(
                key,
                value_name.as_ptr(),
                0,
                REG_SZ,
                data.as_ptr().cast(),
                (data.len() * 2) as u32,
            )
        };
        unsafe {
            RegCloseKey(key);
        }
        if status == ERROR_SUCCESS {
            Ok(())
        } else {
            Err(io::Error::from_raw_os_error(status as i32))
        }
    }
    fn delete_registry_value(name: &str) -> io::Result<()> {
        let key_name = wide(RUN_KEY);
        let value_name = wide(name);
        let mut key: HKEY = std::ptr::null_mut();
        let status = unsafe {
            RegOpenKeyExW(
                HKEY_CURRENT_USER,
                key_name.as_ptr(),
                0,
                KEY_SET_VALUE,
                &mut key,
            )
        };
        if status != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        let status = unsafe { RegDeleteValueW(key, value_name.as_ptr()) };
        unsafe {
            RegCloseKey(key);
        }
        if status == ERROR_SUCCESS {
            Ok(())
        } else {
            Err(io::Error::from_raw_os_error(status as i32))
        }
    }
    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(Some(0)).collect()
    }
    fn windows_quote(value: &str) -> String {
        let mut out = String::from("\"");
        let mut slashes = 0;
        for ch in value.chars() {
            if ch == '\\' {
                slashes += 1;
                continue;
            }
            if ch == '"' {
                out.push_str(&"\\".repeat(slashes * 2 + 1));
                out.push(ch);
                slashes = 0;
                continue;
            }
            out.push_str(&"\\".repeat(slashes));
            slashes = 0;
            out.push(ch);
        }
        out.push_str(&"\\".repeat(slashes * 2));
        out.push('"');
        out
    }
    fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        let mut file = options.open(path)?;
        let result = (|| {
            set_private_acl(path)?;
            verify_private_acl(path)?;
            file.write_all(bytes)?;
            file.sync_all()
        })();
        if result.is_err() {
            let _ = fs::remove_file(path);
        }
        result
    }

    fn set_private_acl(path: &Path) -> io::Result<()> {
        use windows_permissions::constants::{SeObjectType, SecurityInformation};
        use windows_permissions::wrappers::SetNamedSecurityInfo;
        use windows_permissions::{LocalBox, SecurityDescriptor};

        let current =
            windows_permissions::utilities::current_process_sid().map_err(io::Error::other)?;
        let sid = windows_permissions::wrappers::ConvertSidToStringSid(&current)
            .map_err(io::Error::other)?;
        let sddl = format!("D:P(A;;FA;;;{})", sid.to_string_lossy());
        let descriptor: LocalBox<SecurityDescriptor> = sddl.parse().map_err(io::Error::other)?;
        SetNamedSecurityInfo(
            path.as_os_str(),
            SeObjectType::SE_FILE_OBJECT,
            SecurityInformation::Dacl | SecurityInformation::ProtectedDacl,
            None,
            None,
            Some(
                descriptor
                    .dacl()
                    .ok_or_else(|| invalid("cannot create private service DACL"))?,
            ),
            None,
        )
        .map_err(io::Error::other)
    }
    fn sha256_file(path: &Path) -> io::Result<String> {
        let mut file = File::open(path)?;
        let mut hash = Sha256::new();
        let mut buffer = [0u8; 8192];
        loop {
            let count = file.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            hash.update(&buffer[..count]);
        }
        Ok(format!("{:x}", hash.finalize()))
    }
    fn random_token() -> String {
        use rand::RngExt;
        let mut bytes = [0u8; 32];
        rand::rng().fill(&mut bytes);
        hex(&bytes)
    }
    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
    fn has_enrollment(root: &Path) -> bool {
        fs::symlink_metadata(root.join("state/machine.json"))
            .is_ok_and(|m| m.is_file() && !is_reparse(&m))
    }
    fn ssh_banner(addr: std::net::SocketAddr) -> io::Result<bool> {
        use std::net::TcpStream;
        let mut stream = match TcpStream::connect_timeout(&addr, Duration::from_millis(750)) {
            Ok(stream) => stream,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::ConnectionRefused
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::NotFound
                ) =>
            {
                return Ok(false);
            }
            Err(error) => return Err(error),
        };
        stream.set_read_timeout(Some(Duration::from_millis(750)))?;
        let mut bytes = [0; 256];
        match stream.read(&mut bytes) {
            Ok(n) => Ok(String::from_utf8_lossy(&bytes[..n]).starts_with("SSH-2.0-")),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                Ok(false)
            }
            Err(error) => Err(error),
        }
    }
    fn busy(ids: &[String]) -> io::Error {
        io::Error::new(
            io::ErrorKind::WouldBlock,
            format!(
                "Agent lifecycle refused while durable jobs are not terminal ({} job(s))",
                ids.len()
            ),
        )
    }
    fn invalid(message: &'static str) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidInput, message)
    }

    #[cfg(test)]
    mod maintenance_tests {
        use super::*;

        fn record_fields() -> serde_json::Value {
            serde_json::json!({
                "format": 1,
                "owner_sid": "S-1-5-21-1000",
                "root": r"C:\Users\fixture\AppData\Local\HostLink\Agent",
                "executable": r"C:\Users\fixture\AppData\Local\HostLink\Agent\bin\hostlink-agent.exe",
                "executable_sha256": "a".repeat(64),
                "config": r"C:\Users\fixture\AppData\Local\HostLink\Agent\state\agent.json",
                "launcher_executable": r"C:\Windows\System32\wscript.exe",
                "startup_script": r"C:\Users\fixture\AppData\Local\HostLink\Agent\.hostlink-agent-start.vbs",
                "startup_script_sha256": "b".repeat(64),
                "pipe_name": r"\\.\pipe\hostlink-agent-fixture",
                "control_token": "c".repeat(64),
                "run_value": "hostlink-agent-fixture"
            })
        }

        #[test]
        fn legacy_marker_defaults_to_normal_startup_and_maintenance_blocks_it() {
            let legacy: InstallRecord = serde_json::from_value(record_fields()).unwrap();
            assert!(!legacy.maintenance);
            assert!(legacy.maintenance_previous_sha256.is_none());
            assert!(refuse_maintenance(&legacy).is_ok());

            let mut pending = record_fields();
            pending["maintenance"] = serde_json::json!(true);
            pending["maintenance_previous_sha256"] = serde_json::json!("d".repeat(64));
            let pending: InstallRecord = serde_json::from_value(pending).unwrap();
            assert_eq!(
                refuse_maintenance(&pending).unwrap_err().kind(),
                io::ErrorKind::WouldBlock
            );
        }

        #[test]
        fn executable_digest_input_is_exact_lowercase_sha256() {
            assert!(validate_sha256(&"0".repeat(64)).is_ok());
            assert!(validate_sha256(&"A".repeat(64)).is_err());
            assert!(validate_sha256("short").is_err());
        }
    }
}

#[cfg(windows)]
pub use windows::{install, remove, start, status, stop};

#[cfg(windows)]
#[allow(dead_code)] // Consumed by the separately owned Windows updater integration.
pub(crate) use windows::{
    MaintenanceReceipt, begin_maintenance, recover_maintenance_after_inventory,
    register_maintenance, restore_maintenance, stop_for_maintenance_rollback,
    update_maintenance_executable,
};

#[cfg(not(any(target_os = "linux", windows)))]
fn unsupported() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "persistent Agent lifecycle is supported on Linux systemd --user and Windows current-user login startup only",
    )
}
#[cfg(not(any(target_os = "linux", windows)))]
pub fn install(_: &Path, _: &Path) -> io::Result<()> {
    Err(unsupported())
}
#[cfg(not(any(target_os = "linux", windows)))]
pub fn start(_: &Path) -> io::Result<()> {
    Err(unsupported())
}
#[cfg(not(any(target_os = "linux", windows)))]
pub fn stop(_: &Path) -> io::Result<()> {
    Err(unsupported())
}
#[cfg(not(any(target_os = "linux", windows)))]
pub fn remove(_: &Path) -> io::Result<()> {
    Err(unsupported())
}
#[cfg(not(any(target_os = "linux", windows)))]
pub fn status(_: &Path) -> io::Result<ServiceStatus> {
    Err(unsupported())
}

#[cfg(windows)]
pub async fn control_loop(
    config: &crate::AgentConfig,
    pipe_name: String,
    token: String,
    shutdown: tokio_util::sync::CancellationToken,
    finished: tokio_util::sync::CancellationToken,
) -> io::Result<()> {
    windows::control_loop(config, pipe_name, token, shutdown, finished).await
}

#[cfg(windows)]
pub fn validate_managed_run(config: &Path) -> io::Result<(String, String)> {
    windows::validate_managed_run(config)
}

#[cfg(windows)]
pub fn ensure_update_unregistered(root: &Path) -> io::Result<()> {
    windows::ensure_update_unregistered(root)
}

#[cfg(windows)]
pub(crate) fn validate_windows_update_root(root: &Path) -> io::Result<()> {
    windows::validate_update_root(root)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    #[cfg(target_os = "linux")]
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
