use super::*;
use std::os::unix::fs::MetadataExt;

pub(super) fn prepare_record(root: &Path, config: &Path) -> io::Result<InstallRecord> {
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
pub(super) fn owned_record(root: &Path) -> io::Result<InstallRecord> {
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
pub(super) fn read_record(root: &Path) -> io::Result<InstallRecord> {
    owned_record(root)
}
pub(super) fn verify_record(r: &InstallRecord) -> io::Result<()> {
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
pub(super) fn verify_unit_file(r: &InstallRecord, path: &Path) -> io::Result<()> {
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
pub(super) fn verify_pid_owner(pid: u32, r: &InstallRecord) -> io::Result<()> {
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
pub(super) fn verify_enrollment_root(root: &Path, uid: u32) -> io::Result<()> {
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
pub(super) fn private_input(path: &Path, uid: u32, limit: usize) -> io::Result<Vec<u8>> {
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
pub(super) fn load_config(path: &Path) -> io::Result<crate::AgentConfig> {
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
