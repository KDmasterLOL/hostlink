//! Shared Windows SCM helpers.

use super::super::{SERVICE_NAME, ServiceRuntimeState, ServiceRuntimeStatus};
use std::io;
use std::thread;
use std::time::{Duration, Instant};
use windows_service::Error as WindowsServiceError;
use windows_service::service::{ServiceAccess, ServiceState};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_sys::Win32::Foundation::ERROR_SERVICE_DOES_NOT_EXIST;

pub(super) const DISPLAY_NAME: &str = "onec-toolkit remote agent";
pub(super) const DESCRIPTION: &str = "Outbound-only onec-toolkit remote operations agent";
pub(super) const SERVICE_WAIT: Duration = Duration::from_secs(30);

pub(super) fn manager(access: ServiceManagerAccess) -> io::Result<ServiceManager> {
    ws(ServiceManager::local_computer(None::<&str>, access))
}

pub(super) fn open_required_service(
    manager: &ServiceManager,
    access: ServiceAccess,
) -> io::Result<windows_service::service::Service> {
    match manager.open_service(SERVICE_NAME, access) {
        Ok(service) => Ok(service),
        Err(error) if service_missing(&error) => Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("Windows service {SERVICE_NAME} is not installed"),
        )),
        Err(error) => Err(service_error(error)),
    }
}

pub(super) fn service_missing(error: &WindowsServiceError) -> bool {
    matches!(
        error,
        WindowsServiceError::Winapi(error)
            if error.raw_os_error() == Some(ERROR_SERVICE_DOES_NOT_EXIST as i32)
    )
}

pub(super) fn wait_for_state(
    service: &windows_service::service::Service,
    desired: ServiceState,
    timeout: Duration,
) -> io::Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        let status = ws(service.query_status())?;
        if status.current_state == desired {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "Windows service {SERVICE_NAME} did not reach {} within {} seconds; current state is {}",
                    service_state(desired),
                    timeout.as_secs(),
                    service_state(status.current_state)
                ),
            ));
        }
        thread::sleep(Duration::from_millis(100));
    }
}

pub(super) fn status_from_service(
    service: &windows_service::service::Service,
) -> io::Result<ServiceRuntimeStatus> {
    let status = ws(service.query_status())?;
    Ok(ServiceRuntimeStatus {
        installed: true,
        state: service_state(status.current_state),
        process_id: status.process_id,
    })
}

pub(super) fn service_state(state: ServiceState) -> ServiceRuntimeState {
    match state {
        ServiceState::Stopped => ServiceRuntimeState::Stopped,
        ServiceState::StartPending => ServiceRuntimeState::StartPending,
        ServiceState::StopPending => ServiceRuntimeState::StopPending,
        ServiceState::Running => ServiceRuntimeState::Running,
        ServiceState::ContinuePending => ServiceRuntimeState::ContinuePending,
        ServiceState::PausePending => ServiceRuntimeState::PausePending,
        ServiceState::Paused => ServiceRuntimeState::Paused,
    }
}

pub(super) fn ws<T>(result: windows_service::Result<T>) -> io::Result<T> {
    result.map_err(service_error)
}

pub(super) fn service_error(error: WindowsServiceError) -> io::Error {
    match error {
        WindowsServiceError::Winapi(error) => error,
        other => io::Error::other(other.to_string()),
    }
}
