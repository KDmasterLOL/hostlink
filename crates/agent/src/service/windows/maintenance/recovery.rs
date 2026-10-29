use super::*;

/// Re-establish the stopped-runtime precondition after an updater crash. Only the exact
/// owner pipe/process may be asked to stop; an absent pipe is accepted only when process
/// enumeration also proves the installed image is not running.
pub(crate) fn recover_maintenance_stop(root: &Path) -> io::Result<()> {
    ensure_user_scope()?;
    let record = owned_record(root)?;
    if !record.maintenance || record.maintenance_previous_sha256.is_none() {
        return Err(invalid("durable service marker is not in maintenance"));
    }
    validate_record_paths(&record)?;
    match registry_value(&record.run_value)? {
        None => {}
        Some(value) if value == render_command(&record) => {
            delete_registry_value(&record.run_value)?
        }
        Some(_) => {
            return Err(invalid(
                "current-user login value changed during maintenance recovery",
            ));
        }
    }
    let reply = match pipe_request(&record, "STATUS") {
        Ok(reply) => reply,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return crate::update::reject_running_agent(&record.executable);
        }
        Err(error) => return Err(error),
    };
    let pid = running_pid(&reply).ok_or_else(|| {
        invalid("maintenance recovery status did not prove a running owner process")
    })?;
    let process = open_owned_process(pid, &record)?;
    if pipe_request(&record, "STOP")? != format!("STOPPING {pid}") {
        return Err(invalid(
            "authenticated Agent refused maintenance recovery stop",
        ));
    }
    match unsafe { WaitForSingleObject(process.handle, 10_000) } {
        WAIT_OBJECT_0 => Ok(()),
        WAIT_TIMEOUT => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "maintenance recovery Agent did not stop; no process was force-terminated",
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
