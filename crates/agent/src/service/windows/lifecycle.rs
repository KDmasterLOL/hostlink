use super::*;

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
    println!("Started current-user HostLink Agent (pid verified by authenticated control pipe)");
    Ok(())
}
pub fn stop(root: &Path) -> io::Result<()> {
    ensure_user_scope()?;
    let record = owned_record(root)?;
    verify_record(&record)?;
    verify_registration(&record)?;
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
pub fn remove(root: &Path) -> io::Result<()> {
    ensure_user_scope()?;
    let record = owned_record(root)?;
    refuse_maintenance(&record)?;
    verify_record(&record)?;
    crate::update::ensure_no_pending_windows_handoff(&record.root)?;
    verify_registration(&record)?;
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
                detail: "unmanaged: no HostLink current-user lifecycle marker exists for this root"
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
    let pid = process_pid(&reply)
        .ok_or_else(|| invalid("Agent lifecycle control returned an invalid status response"))?;
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
pub fn validate_managed_run(
    config: &Path,
    maintenance_start: bool,
) -> io::Result<(String, String)> {
    ensure_user_scope()?;
    let config = canonical_regular(config)?;
    let root = config
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| invalid("managed Agent config is outside its install root"))?;
    let record = owned_record(root)?;
    if maintenance_start {
        if !record.maintenance
            || record.maintenance_previous_sha256.is_none()
            || registry_value(&record.run_value)?.is_some()
        {
            return Err(invalid(
                "maintenance startup is not authorized by the owner marker",
            ));
        }
    } else {
        refuse_maintenance(&record)?;
    }
    verify_record(&record)?;
    if !maintenance_start {
        crate::update::ensure_no_pending_windows_handoff(&record.root)?;
    }
    if !maintenance_start {
        verify_registration(&record)?;
    }
    if config != record.config || std::env::current_exe()?.canonicalize()? != record.executable {
        return Err(invalid(
            "managed Agent startup identity or source executable does not match its private record",
        ));
    }
    if maintenance_start {
        consume_maintenance_admission(&record)?;
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
            shutdown.cancel();
            format!("STOPPING {}\n", std::process::id())
        } else {
            "DENIED\n".to_owned()
        };
        pipe.write_all(response.as_bytes()).await?;
        pipe.flush().await?;
        drop(pipe);
        pipe = next_pipe;
    }
}
pub(super) fn create_private_pipe(
    pipe_name: &str,
    first: bool,
) -> io::Result<tokio::net::windows::named_pipe::NamedPipeServer> {
    use tokio::net::windows::named_pipe::ServerOptions;
    use windows_permissions::{LocalBox, SecurityDescriptor};
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;

    let owner = windows_permissions::utilities::current_process_sid().map_err(io::Error::other)?;
    let owner_text =
        windows_permissions::wrappers::ConvertSidToStringSid(&owner).map_err(io::Error::other)?;
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
pub(super) fn verify_registration(record: &InstallRecord) -> io::Result<()> {
    if registry_value(&record.run_value)?.as_deref() == Some(render_command(record).as_str()) {
        Ok(())
    } else {
        Err(invalid(
            "current-user startup registration differs from the owned record",
        ))
    }
}
pub(super) fn refuse_maintenance(record: &InstallRecord) -> io::Result<()> {
    if record.maintenance || record.maintenance_previous_sha256.is_some() {
        Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "HostLink Agent is held in service maintenance; managed startup is disabled",
        ))
    } else {
        Ok(())
    }
}
