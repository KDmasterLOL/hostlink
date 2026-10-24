//! Windows Service Control Manager lifecycle ownership.

use super::super::{SERVICE_NAME, ServiceRuntimeState, ServiceRuntimeStatus};
use super::support::{
    DESCRIPTION, DISPLAY_NAME, SERVICE_WAIT, manager, open_required_service, service_error,
    service_missing, service_state, status_from_service, wait_for_state, ws,
};
use std::ffi::{OsStr, OsString};
use std::io;
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};
use windows_service::service::{
    ServiceAccess, ServiceAction, ServiceActionType, ServiceErrorControl, ServiceFailureActions,
    ServiceFailureResetPeriod, ServiceInfo, ServiceStartType, ServiceState, ServiceType,
};
use windows_service::service_manager::ServiceManagerAccess;

pub(in crate::service) fn install(config: &Path, start_after_install: bool) -> io::Result<()> {
    let executable = std::env::current_exe()?.canonicalize()?;
    let config = config.canonicalize()?;
    let manager = manager(ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE)?;
    let access = ServiceAccess::QUERY_STATUS
        | ServiceAccess::QUERY_CONFIG
        | ServiceAccess::START
        | ServiceAccess::STOP
        | ServiceAccess::DELETE
        | ServiceAccess::CHANGE_CONFIG;

    let service = match manager.open_service(SERVICE_NAME, access) {
        Ok(service) => {
            validate_existing_service(&service, &executable, &config)?;
            service
        }
        Err(error) if service_missing(&error) => {
            let info = service_info(&executable, &config);
            ws(manager.create_service(&info, access))?
        }
        Err(error) => return Err(service_error(error)),
    };
    ws(service.set_description(DESCRIPTION))?;
    ws(service.update_failure_actions(ServiceFailureActions {
        reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(86_400)),
        reboot_msg: None,
        command: None,
        actions: Some(vec![
            ServiceAction {
                action_type: ServiceActionType::Restart,
                delay: Duration::from_secs(5),
            },
            ServiceAction {
                action_type: ServiceActionType::Restart,
                delay: Duration::from_secs(15),
            },
            ServiceAction {
                action_type: ServiceActionType::Restart,
                delay: Duration::from_secs(60),
            },
        ]),
    }))?;
    ws(service.set_failure_actions_on_non_crash_failures(true))?;

    if start_after_install {
        start_open_service(&service)?;
    }
    Ok(())
}

pub(in crate::service) fn start() -> io::Result<ServiceRuntimeStatus> {
    let manager = manager(ServiceManagerAccess::CONNECT)?;
    let service =
        open_required_service(&manager, ServiceAccess::QUERY_STATUS | ServiceAccess::START)?;
    start_open_service(&service)?;
    status_from_service(&service)
}

pub(in crate::service) fn stop() -> io::Result<ServiceRuntimeStatus> {
    let manager = manager(ServiceManagerAccess::CONNECT)?;
    let service =
        open_required_service(&manager, ServiceAccess::QUERY_STATUS | ServiceAccess::STOP)?;
    stop_open_service(&service)?;
    status_from_service(&service)
}

pub(in crate::service) fn status() -> io::Result<ServiceRuntimeStatus> {
    let manager = manager(ServiceManagerAccess::CONNECT)?;
    match manager.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS) {
        Ok(service) => status_from_service(&service),
        Err(error) if service_missing(&error) => Ok(ServiceRuntimeStatus {
            installed: false,
            state: ServiceRuntimeState::NotInstalled,
            process_id: None,
        }),
        Err(error) => Err(service_error(error)),
    }
}

pub(in crate::service) fn uninstall(stop_before_delete: bool) -> io::Result<()> {
    let manager = manager(ServiceManagerAccess::CONNECT)?;
    let access = ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE;
    let service = match manager.open_service(SERVICE_NAME, access) {
        Ok(service) => service,
        Err(error) if service_missing(&error) => return Ok(()),
        Err(error) => return Err(service_error(error)),
    };

    if stop_before_delete {
        stop_open_service(&service)?;
    }
    ws(service.delete())?;
    drop(service);

    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        match manager.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS) {
            Err(error) if service_missing(&error) => return Ok(()),
            Ok(_) => thread::sleep(Duration::from_millis(100)),
            Err(error) => return Err(service_error(error)),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        format!("Windows service {SERVICE_NAME} is still pending deletion"),
    ))
}

fn service_info(executable: &Path, config: &Path) -> ServiceInfo {
    ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(DISPLAY_NAME),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: executable.to_path_buf(),
        launch_arguments: vec![
            OsString::from("service"),
            OsString::from("--config"),
            config.as_os_str().to_owned(),
        ],
        dependencies: Vec::new(),
        account_name: None,
        account_password: None,
    }
}

fn validate_existing_service(
    service: &windows_service::service::Service,
    executable: &Path,
    expected_config: &Path,
) -> io::Result<()> {
    let config = ws(service.query_config())?;
    if config.display_name != OsStr::new(DISPLAY_NAME) {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!(
                "Windows service {SERVICE_NAME} already exists with a different display name; refusing to overwrite user-managed service configuration"
            ),
        ));
    }
    if !config.service_type.contains(ServiceType::OWN_PROCESS) {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!(
                "Windows service {SERVICE_NAME} is not an own-process service; refusing to overwrite it"
            ),
        ));
    }
    if config.start_type != ServiceStartType::AutoStart {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!(
                "Windows service {SERVICE_NAME} is not configured for automatic start; refusing to overwrite user-managed service configuration"
            ),
        ));
    }
    if config.account_name.as_deref().is_some_and(|name| {
        !name.eq_ignore_ascii_case(OsStr::new("LocalSystem"))
            && !name.eq_ignore_ascii_case(OsStr::new("NT AUTHORITY\\SYSTEM"))
            && !name.eq_ignore_ascii_case(OsStr::new(".\\LocalSystem"))
    }) {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!(
                "Windows service {SERVICE_NAME} uses a non-LocalSystem account; refusing to overwrite user-managed service configuration"
            ),
        ));
    }
    let configured = config
        .executable_path
        .to_string_lossy()
        .to_ascii_lowercase();
    let expected_executable = executable.to_string_lossy().to_ascii_lowercase();
    let expected_config = expected_config.to_string_lossy().to_ascii_lowercase();
    if !configured.contains(&expected_executable)
        || !configured.contains(" service ")
        || !configured.contains(" --config ")
        || !configured.contains(&expected_config)
    {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!(
                "Windows service {SERVICE_NAME} has a different executable/config launch contract; uninstall it explicitly before changing ownership"
            ),
        ));
    }
    Ok(())
}

fn start_open_service(service: &windows_service::service::Service) -> io::Result<()> {
    let current = ws(service.query_status())?;
    match current.current_state {
        ServiceState::Running => return Ok(()),
        ServiceState::StartPending => {
            wait_for_state(service, ServiceState::Running, SERVICE_WAIT)?;
            return Ok(());
        }
        ServiceState::Stopped => {}
        state => {
            return Err(io::Error::other(format!(
                "cannot start Windows service {SERVICE_NAME} while it is {}",
                service_state(state)
            )));
        }
    }
    let no_args: [&OsStr; 0] = [];
    ws(service.start(&no_args))?;
    wait_for_state(service, ServiceState::Running, SERVICE_WAIT)
}

fn stop_open_service(service: &windows_service::service::Service) -> io::Result<()> {
    let current = ws(service.query_status())?;
    match current.current_state {
        ServiceState::Stopped => return Ok(()),
        ServiceState::StopPending => {
            wait_for_state(service, ServiceState::Stopped, SERVICE_WAIT)?;
            return Ok(());
        }
        ServiceState::Running | ServiceState::Paused => {}
        state => {
            return Err(io::Error::other(format!(
                "cannot stop Windows service {SERVICE_NAME} while it is {}",
                service_state(state)
            )));
        }
    }
    let _ = ws(service.stop())?;
    wait_for_state(service, ServiceState::Stopped, SERVICE_WAIT)
}
