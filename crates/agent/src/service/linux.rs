//! Minimal systemd user lifecycle; systemd alone owns process state.
use super::ServiceStatus;
use crate::private_fs::validate_private_path;
use service_manager::{
    ServiceInstallCtx, ServiceLabel, ServiceManager, ServiceStartCtx, ServiceStatus as OsStatus,
    ServiceStatusCtx, ServiceStopCtx, ServiceUninstallCtx, SystemdServiceManager,
    systemd_user_dir_path,
};
use sha2::{Digest as _, Sha256};
use std::{
    fs,
    io::{self, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::Command,
};

/// Enable the installed Agent without starting it.
/// # Errors
/// Rejects unsafe paths, legacy/colliding units, or systemd failures.
pub fn install(root: &Path, config: &Path) -> io::Result<()> {
    let (root, label) = root_label(root)?;
    // Only installation may conflict with the former launcher. A stale
    // marker must not prevent stopping/removing an already owned unit.
    match fs::symlink_metadata(root.join(".hostlink-user-service.json")) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
        Ok(_) => return Err(io::Error::other("legacy marker requires migration")),
    }
    let program = root.join("bin/hostlink-agent");
    validate_private_path(&program, false)?;
    validate_private_path(config, false)?;
    if config.canonicalize()? != root.join("state/agent.json")
        || std::env::current_exe()?.canonicalize()? != program
    {
        return Err(io::Error::other("installed executable/config required"));
    }
    let (path, exists) = check_unit(&root, &label, false)?;
    let manager = SystemdServiceManager::user();
    let contents = unit_text(&root, &label);
    if !exists {
        let state = manager.status(ServiceStatusCtx {
            label: label.clone(),
        })?;
        if state != OsStatus::NotInstalled {
            return Err(io::Error::other("user service name is already registered"));
        }
        fs::create_dir_all(path.parent().unwrap())?;
        // Reserve the unit atomically: the library otherwise truncates collisions.
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .open(&path)?
            .write_all(contents.as_bytes())?;
    }
    manager.install(ServiceInstallCtx {
        label: label.clone(),
        program,
        args: Vec::new(), // ExecStart and restart policy come from contents.
        contents: Some(contents),
        username: None,
        working_directory: None,
        environment: None,
        autostart: true,
        restart_policy: Default::default(),
    })?;
    println!(
        "Installed user service {}.service (enabled for this user's login; not started)",
        label.application
    );
    Ok(())
}

/// Start the matching unit.
/// # Errors
/// Rejects unsafe/missing/modified registrations or systemd failures.
pub fn start(root: &Path) -> io::Result<()> {
    let (root, label) = root_label(root)?;
    check_unit(&root, &label, true)?;
    SystemdServiceManager::user().start(ServiceStartCtx {
        label: label.clone(),
    })?;
    println!("Started {}.service", label.application);
    Ok(())
}

/// Stop the matching unit (systemd defaults to SIGTERM).
/// # Errors
/// Rejects unsafe/missing/modified registrations or systemd failures.
pub fn stop(root: &Path) -> io::Result<()> {
    let (root, label) = root_label(root)?;
    check_unit(&root, &label, true)?;
    SystemdServiceManager::user().stop(ServiceStopCtx {
        label: label.clone(),
    })?;
    println!("Stopped {}.service", label.application);
    Ok(())
}

/// Stop and unregister the matching unit, preserving all Agent files.
/// # Errors
/// Rejects unsafe/missing/modified registrations or systemd failures.
pub fn remove(root: &Path) -> io::Result<()> {
    let (root, label) = root_label(root)?;
    check_unit(&root, &label, true)?;
    let manager = SystemdServiceManager::user();
    manager.stop(ServiceStopCtx {
        label: label.clone(),
    })?;
    manager.uninstall(ServiceUninstallCtx {
        label: label.clone(),
    })?;
    reload()?;
    println!(
        "Unregistered user service {}.service (Agent binary, keys and jobs preserved)",
        label.application
    );
    Ok(())
}

/// Return only OS installation/activity state, without Agent health probes.
/// # Errors
/// Rejects unsafe/modified units, inconsistent registration or systemd failures.
pub fn status(root: &Path) -> io::Result<ServiceStatus> {
    let (root, label) = root_label(root)?;
    let (_, exists) = check_unit(&root, &label, false)?;
    let state = SystemdServiceManager::user().status(ServiceStatusCtx { label })?;
    let installed = !matches!(state, OsStatus::NotInstalled);
    if installed != exists {
        return Err(io::Error::other("OS/unit registration mismatch"));
    }
    Ok(ServiceStatus {
        installed,
        active: matches!(state, OsStatus::Running),
    })
}

fn root_label(root: &Path) -> io::Result<(PathBuf, ServiceLabel)> {
    // SAFETY: geteuid reads only this process's effective user identity.
    if unsafe { libc::geteuid() } == 0
        || std::env::var_os("XDG_RUNTIME_DIR").is_none_or(|v| v.is_empty())
    {
        return Err(io::Error::other("non-root systemd user session required"));
    }
    validate_private_path(root, true)?;
    let canonical = root.canonicalize()?;
    if std::path::absolute(root)? != canonical
        || canonical
            .to_str()
            .is_none_or(|s| s.chars().any(char::is_control))
    {
        return Err(io::Error::other("unsafe root path"));
    }
    let hash = Sha256::digest(canonical.as_os_str().as_encoded_bytes());
    let digest = format!("{hash:x}");
    let label = format!("hostlink-agent-{}", &digest[..20]).parse()?;
    Ok((canonical, label))
}

fn check_unit(root: &Path, label: &ServiceLabel, required: bool) -> io::Result<(PathBuf, bool)> {
    let path = systemd_user_dir_path()?.join(format!("{}.service", label.application));
    // Locate the existing parent; metadata below propagates lookup errors.
    let parent = path.parent().unwrap();
    let dir = parent
        .ancestors()
        .find(|p| p.try_exists().unwrap_or(true))
        .unwrap();
    let meta = fs::metadata(dir)?;
    // SAFETY: geteuid only reads this process's effective user identity.
    let uid = unsafe { libc::geteuid() };
    if dir.canonicalize()? != std::path::absolute(dir)?
        || meta.uid() != uid
        || meta.mode() & 0o022 != 0
    {
        return Err(io::Error::other("unsafe user systemd directory"));
    }
    let meta = match fs::symlink_metadata(&path) {
        Err(e) if !required && e.kind() == io::ErrorKind::NotFound => return Ok((path, false)),
        result => result?,
    };
    // Units are library-created 0644 files, not private Agent data files.
    if !meta.is_file()
        || meta.uid() != uid
        || meta.mode() & 0o022 != 0
        || meta.nlink() != 1
        || fs::read_to_string(&path)? != unit_text(root, label)
    {
        return Err(io::Error::other("unsafe or conflicting user service unit"));
    }
    Ok((path, true))
}

fn unit_text(root: &Path, label: &ServiceLabel) -> String {
    let root = root.to_string_lossy();
    let config = systemd_arg(&format!("{root}/state/agent.json"));
    let prefix = if root.contains('$') { ":" } else { "" }; // Disable $ expansion.
    format!(
        "[Unit]\nDescription=HostLink Agent ({}.service)\nStartLimitIntervalSec=300\nStartLimitBurst=5\n\
         \n[Service]\nType=simple\nExecStart={prefix}{} run --config={config}\n\
         Restart=on-failure\nRestartSec=15s\n\
         \n[Install]\nWantedBy=default.target\n",
        label.application,
        systemd_arg(&format!("{root}/bin/hostlink-agent"))
    )
}

fn systemd_arg(value: &str) -> String {
    let escaped = value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('%', "%%");
    format!("\"{escaped}\"")
}

fn reload() -> io::Result<()> {
    let status = Command::new("systemctl")
        .args(["--user", "daemon-reload"])
        .status()?;
    if !status.success() {
        return Err(io::Error::other("systemd daemon-reload failed"));
    }
    Ok(())
}
