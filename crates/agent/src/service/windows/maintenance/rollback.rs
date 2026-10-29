use super::*;

/// Restore old ownership bytes and login registration only after the coordinator proves
/// the complete old file inventory from its validated transaction journal.
pub(crate) fn restore_maintenance(
    receipt: &MaintenanceReceipt,
    verify_old_inventory: impl FnOnce(&Path) -> io::Result<()>,
) -> io::Result<()> {
    let record = maintenance_record(receipt)?;
    if sha256_file(&record.executable)? != receipt.old_record.executable_sha256 {
        return Err(invalid(
            "old executable inventory is not restored; maintenance rollback refused",
        ));
    }
    verify_old_inventory(&record.root)?;
    restore_old_marker_and_registration(receipt)
}
/// Re-enter the same maintenance receipt after a candidate restart failed, before
/// the updater restores the old file inventory and calls restore_maintenance.
pub(crate) fn stop_for_maintenance_rollback(receipt: &MaintenanceReceipt) -> io::Result<()> {
    let mut record = owned_record(&receipt.old_record.root)?;
    if record.maintenance {
        let _ = maintenance_record(receipt)?;
        if registry_value(&record.run_value)?.is_some() {
            return Err(invalid(
                "login registration became enabled before rollback stop",
            ));
        }
        let pid = match pipe_request(&record, "STATUS") {
            Ok(reply) => running_pid(&reply),
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(error),
        };
        let Some(pid) = pid else {
            return crate::update::reject_running_agent(&record.executable);
        };
        let process = open_owned_process(pid, &record)?;
        if pipe_request(&record, "STOP")? != format!("STOPPING {pid}") {
            return Err(invalid("authenticated candidate refused rollback stop"));
        }
        return match unsafe { WaitForSingleObject(process.handle, 10_000) } {
            WAIT_OBJECT_0 => Ok(()),
            WAIT_TIMEOUT => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "candidate Agent did not stop for rollback; no process was force-terminated",
            )),
            _ => Err(io::Error::last_os_error()),
        };
    }
    verify_record(&record)?;
    verify_registration(&record)?;
    if record.owner_sid != receipt.old_record.owner_sid
        || record.root != receipt.old_record.root
        || record.executable != receipt.old_record.executable
        || record.pipe_name != receipt.old_record.pipe_name
        || record.control_token != receipt.old_record.control_token
        || record.run_value != receipt.old_record.run_value
    {
        return Err(invalid(
            "rollback service identity differs from the maintenance receipt",
        ));
    }
    let pid = running_pid(&pipe_request(&record, "STATUS")?)
        .ok_or_else(|| invalid("rollback requires authenticated running Agent status"))?;
    let process = open_owned_process(pid, &record)?;
    record.maintenance = true;
    record.maintenance_previous_sha256 = Some(receipt.old_record.executable_sha256.clone());
    replace_record_atomically(&record)?;
    if let Err(error) = delete_registry_value(&record.run_value) {
        return Err(io::Error::other(format!(
            "cannot disable login startup for rollback: {error}"
        )));
    }
    match registry_value(&record.run_value)? {
        None => {}
        _ => return Err(invalid("rollback login startup remained registered")),
    }
    if pipe_request(&record, "STOP")? != format!("STOPPING {pid}") {
        return Err(invalid("authenticated Agent refused rollback stop"));
    }
    match unsafe { WaitForSingleObject(process.handle, 10_000) } {
        WAIT_OBJECT_0 => Ok(()),
        WAIT_TIMEOUT => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "candidate Agent did not stop for rollback; no process was force-terminated",
        )),
        _ => Err(io::Error::last_os_error()),
    }
}
