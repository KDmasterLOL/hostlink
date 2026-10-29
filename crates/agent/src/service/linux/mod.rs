//! Per-user systemd lifecycle delegated to service-manager.
//!
//! The OS is the authoritative process supervisor. Installation identity is
//! the deterministic unit name and the unit's exact command; no JSON marker,
//! duplicate PID registry or custom process manager is maintained.

mod unit;

use super::ServiceStatus;
use std::{io, path::Path};

use service_manager::{
    ServiceInstallCtx, ServiceManager, ServiceStartCtx, ServiceStatus as OsStatus,
    ServiceStatusCtx, ServiceStopCtx, ServiceUninstallCtx, SystemdServiceManager,
};

pub fn install(root: &Path, config: &Path) -> io::Result<()> {
    let unit = unit::Unit::new(root)?;
    unit.verify_source(config)?;
    unit.reject_legacy_marker()?;
    if unit.path.exists() {
        unit.verify_contents()?;
        return Ok(());
    }
    unit.verify_unit_dir()?;
    let manager = SystemdServiceManager::user();
    manager.install(ServiceInstallCtx {
        label: unit.label.clone(),
        program: unit.executable.clone(),
        args: vec![
            "run".into(),
            format!("--config={}", unit.config.display()).into(),
        ],
        contents: Some(unit.contents()),
        username: None,
        working_directory: None,
        environment: None,
        autostart: true,
        restart_policy: service_manager::RestartPolicy::OnFailure {
            delay_secs: Some(15),
            max_retries: None,
            reset_after_secs: None,
        },
    })?;
    unit.reload()?;
    println!(
        "Installed user service {} (enabled for this user's login; not started)",
        unit.name()
    );
    Ok(())
}

pub fn start(root: &Path) -> io::Result<()> {
    let unit = unit::Unit::new(root)?;
    unit.verify_contents()?;
    SystemdServiceManager::user().start(ServiceStartCtx {
        label: unit.label.clone(),
    })?;
    println!("Started {}", unit.name());
    Ok(())
}

pub fn stop(root: &Path) -> io::Result<()> {
    let unit = unit::Unit::new(root)?;
    unit.verify_contents()?;
    SystemdServiceManager::user().stop(ServiceStopCtx {
        label: unit.label.clone(),
    })?;
    println!("Stopped {}", unit.name());
    Ok(())
}

pub fn remove(root: &Path) -> io::Result<()> {
    let unit = unit::Unit::new(root)?;
    unit.verify_contents()?;
    let manager = SystemdServiceManager::user();
    manager.stop(ServiceStopCtx {
        label: unit.label.clone(),
    })?;
    manager.uninstall(ServiceUninstallCtx {
        label: unit.label.clone(),
    })?;
    unit.reload()?;
    println!(
        "Unregistered user service {} (Agent binary, keys and jobs preserved)",
        unit.name()
    );
    Ok(())
}

pub fn status(root: &Path) -> io::Result<ServiceStatus> {
    let unit = unit::Unit::new(root)?;
    let manager = SystemdServiceManager::user();
    let os_status = manager.status(ServiceStatusCtx {
        label: unit.label.clone(),
    })?;
    if matches!(os_status, OsStatus::NotInstalled) {
        if unit.path.exists() {
            return Err(io::Error::other(
                "systemd unit exists but is not registered",
            ));
        }
        return Ok(ServiceStatus {
            installed: false,
            active: false,
            owner_uid: None,
            owner_sid: None,
            pid: None,
            executable_sha256: None,
            ssh_banner: false,
            local_enrollment: false,
            detail: "user service is not installed".into(),
        });
    }
    unit.verify_contents()?;
    let active = matches!(os_status, OsStatus::Running);
    let ssh_banner = if active { unit.ssh_banner()? } else { false };
    let detail = if !active {
        "installed but service is not active"
    } else if ssh_banner {
        "user service running; loopback SSH banner verified; Hub reachability not queried"
    } else {
        "user service running but loopback SSH endpoint is unreachable; Hub reachability not queried"
    };
    Ok(ServiceStatus {
        installed: true,
        active,
        owner_uid: Some(unsafe { libc::geteuid() }),
        owner_sid: None,
        pid: None,
        executable_sha256: None,
        ssh_banner,
        local_enrollment: unit.root.join("state/machine.json").is_file(),
        detail: detail.into(),
    })
}
