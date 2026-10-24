//! Windows ServiceMain callback and service-owned tunnel lifetime.

use super::super::SERVICE_NAME;
use super::support::ws;
use crate::{
    AgentConfig, AgentEventFields, agent_event, run_with_tunnel_until, set_agent_event_log_path,
};
use std::ffi::OsString;
use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_dispatcher;

static CONFIG_PATH: OnceLock<PathBuf> = OnceLock::new();

windows_service::define_windows_service!(ffi_service_main, service_main);

pub(in crate::service) fn dispatch(config: PathBuf) -> io::Result<()> {
    CONFIG_PATH.set(config).map_err(|_| {
        io::Error::new(
            io::ErrorKind::AlreadyExists,
            "service config path is already set",
        )
    })?;
    ws(service_dispatcher::start(SERVICE_NAME, ffi_service_main))
}

fn service_main(_arguments: Vec<OsString>) {
    if let Err(error) = run_service_main() {
        agent_event("service.failed", "error", AgentEventFields::default());
        eprintln!("onec-agent service stopped: {error}");
    }
}

fn run_service_main() -> io::Result<()> {
    let config_path = CONFIG_PATH
        .get()
        .ok_or_else(|| io::Error::other("service config path is missing"))?
        .clone();
    let agent_dir = config_path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "service config has no parent directory",
        )
    })?;
    let root = agent_dir.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "service config is not below toolkit root",
        )
    })?;
    std::env::set_current_dir(root)?;
    set_agent_event_log_path(agent_dir.join("agent-events.log"));

    let shutdown = Arc::new(AtomicBool::new(false));
    let handler_shutdown = Arc::clone(&shutdown);
    let status_handle = ws(service_control_handler::register(
        SERVICE_NAME,
        move |control_event| match control_event {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                handler_shutdown.store(true, Ordering::Release);
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        },
    ))?;

    ws(status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::StartPending,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::NO_ERROR,
        checkpoint: 1,
        wait_hint: Duration::from_secs(10),
        process_id: None,
    }))?;

    let result = (|| {
        let config = AgentConfig::load(&config_path)?;
        config.apply_process_environment()?;
        ws(status_handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Running,
            controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
            exit_code: ServiceExitCode::NO_ERROR,
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        }))?;
        agent_event("service.started", "info", AgentEventFields::default());
        run_with_tunnel_until(&config, shutdown.as_ref())
    })();

    let exit_code = if result.is_ok() {
        ServiceExitCode::NO_ERROR
    } else {
        ServiceExitCode::ServiceSpecific(1)
    };
    let _ = status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code,
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    });
    result
}
