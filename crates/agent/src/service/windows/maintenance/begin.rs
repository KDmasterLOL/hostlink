use super::*;

/// Enter maintenance while the caller holds durable::acquire_update_lock(root).
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
    let pid = match pipe_request(&record, "STATUS") {
        Ok(reply) => Some(running_pid(&reply).ok_or_else(|| {
            invalid("maintenance lifecycle endpoint did not prove a running Agent process")
        })?),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            crate::update::reject_running_agent(&record.executable)?;
            None
        }
        Err(error) => return Err(error),
    };
    let process = pid
        .map(|pid| open_owned_process(pid, &record))
        .transpose()?;

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

    if let (Some(pid), Some(process)) = (pid, process) {
        let reply = pipe_request(&record, "STOP")?;
        if reply != format!("STOPPING {pid}") {
            return Err(invalid("authenticated Agent refused maintenance stop"));
        }
        // SAFETY: process.handle is a verified live handle opened with SYNCHRONIZE.
        match unsafe { WaitForSingleObject(process.handle, 10_000) } {
            WAIT_OBJECT_0 => refuse_active_jobs(&record)?,
            WAIT_TIMEOUT => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "Agent did not stop within 10 seconds; maintenance remains disabled and no process was force-terminated",
                ));
            }
            _ => return Err(io::Error::last_os_error()),
        }
    }
    refuse_active_jobs(&record)?;
    Ok(MaintenanceReceipt {
        old_marker,
        old_record,
        run_command,
        transaction_id: random_token(),
    })
}

pub(crate) fn begin_recovery_maintenance(
    root: &Path,
    old_sha256: &str,
    new_sha256: &str,
) -> io::Result<()> {
    validate_sha256(old_sha256)?;
    validate_sha256(new_sha256)?;
    ensure_user_scope()?;
    let mut record = owned_record(root)?;
    verify_record(&record)?;
    if record.maintenance
        || record.executable_sha256 != new_sha256
        || sha256_file(&record.executable)? != new_sha256
    {
        return Err(invalid(
            "recovery owner marker does not match the journal candidate",
        ));
    }
    verify_registration(&record)?;
    refuse_active_jobs(&record)?;
    let pid = match pipe_request(&record, "STATUS") {
        Ok(reply) => Some(
            running_pid(&reply)
                .ok_or_else(|| invalid("recovery health endpoint returned an invalid PID"))?,
        ),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            crate::update::reject_running_agent(&record.executable)?;
            None
        }
        Err(error) => return Err(error),
    };
    let process = pid
        .map(|pid| open_owned_process(pid, &record))
        .transpose()?;
    record.maintenance = true;
    record.maintenance_previous_sha256 = Some(old_sha256.to_owned());
    replace_record_atomically(&record)?;
    delete_registry_value(&record.run_value)?;
    if registry_value(&record.run_value)?.is_some() {
        return Err(invalid(
            "recovery could not disable the exact login registration",
        ));
    }
    if let (Some(pid), Some(process)) = (pid, process) {
        if pipe_request(&record, "STOP")? != format!("STOPPING {pid}") {
            return Err(invalid("recovered candidate refused authenticated stop"));
        }
        match unsafe { WaitForSingleObject(process.handle, 10_000) } {
            WAIT_OBJECT_0 => refuse_active_jobs(&record)?,
            WAIT_TIMEOUT => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "recovered candidate did not stop; no process was force-terminated",
                ));
            }
            _ => return Err(io::Error::last_os_error()),
        }
    }
    Ok(())
}
