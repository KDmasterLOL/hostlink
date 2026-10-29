use super::*;
use std::os::unix::fs::MetadataExt;

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
    systemctl(&["stop", &record.unit_name])?;
    println!("Stopped {}", record.unit_name);
    Ok(())
}
pub fn remove(root: &Path) -> io::Result<()> {
    let record = owned_record(root)?;
    verify_record(&record)?;
    let unit = unit_dir()?.join(&record.unit_name);
    verify_unit_file(&record, &unit)?;
    systemctl(&["stop", &record.unit_name])?;
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
pub(super) fn rollback_uninstall(
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
