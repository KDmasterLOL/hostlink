use super::*;

/// Enter maintenance while the caller holds jobs::acquire_update_lock(root).
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
pub(crate) fn has_registration(root: &Path) -> io::Result<bool> {
    let root = verify_install_root(root)?;
    match fs::symlink_metadata(root.join(MARKER)) {
        Ok(metadata) if metadata.is_file() && !is_reparse(&metadata) => Ok(true),
        Ok(_) => Err(invalid("current-user lifecycle marker is unsafe")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}
pub(crate) fn is_in_maintenance(root: &Path) -> io::Result<bool> {
    let record = owned_record(root)?;
    verify_record(&record)?;
    Ok(record.maintenance && record.maintenance_previous_sha256.is_some())
}
pub(crate) fn verify_registered_health(root: &Path, expected_sha256: &str) -> io::Result<()> {
    let record = owned_record(root)?;
    verify_record(&record)?;
    if record.maintenance
        || record.executable_sha256 != expected_sha256
        || sha256_file(&record.executable)? != expected_sha256
    {
        return Err(invalid(
            "registered Agent does not match the committed update identity",
        ));
    }
    verify_registration(&record)?;
    let reply = pipe_request(&record, "STATUS")?;
    let pid = running_pid(&reply).ok_or_else(|| {
        invalid("registered Agent health endpoint did not report a running process")
    })?;
    let process = open_owned_process(pid, &record)?;
    if process.pid != pid || sha256_file(&record.executable)? != expected_sha256 {
        return Err(invalid(
            "registered Agent health identity changed during readback",
        ));
    }
    if !ssh_banner(load_config(&record.config)?.listen)? {
        return Err(io::Error::new(
            io::ErrorKind::NotConnected,
            "registered Agent lifecycle pipe is healthy but its SSH listener is not ready",
        ));
    }
    // SAFETY: process.handle remains open and is the exact authenticated process handle.
    if unsafe { WaitForSingleObject(process.handle, 0) } != WAIT_TIMEOUT {
        return Err(invalid("registered Agent exited during health readback"));
    }
    Ok(())
}
pub(crate) fn verify_registered_image(root: &Path, expected_sha256: &str) -> io::Result<()> {
    let record = owned_record(root)?;
    verify_record(&record)?;
    if record.maintenance
        || record.executable_sha256 != expected_sha256
        || sha256_file(&record.executable)? != expected_sha256
    {
        return Err(invalid(
            "registered Agent image does not match the journal identity",
        ));
    }
    verify_registration(&record)
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
        WAIT_OBJECT_0 => refuse_active_jobs(&record),
        WAIT_TIMEOUT => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "maintenance recovery Agent did not stop; no process was force-terminated",
        )),
        _ => Err(io::Error::last_os_error()),
    }
}
/// Change only the owner marker's executable digest after the updater verified the file.
pub(crate) fn update_maintenance_executable(
    receipt: &MaintenanceReceipt,
    expected_sha256: &str,
) -> io::Result<()> {
    validate_sha256(expected_sha256)?;
    let mut record = maintenance_record(receipt)?;
    if registry_value(&record.run_value)?.is_some() {
        return Err(invalid(
            "login registration must remain disabled while the executable is replaced",
        ));
    }
    if sha256_file(&record.executable)? != expected_sha256 {
        return Err(invalid(
            "replacement executable digest does not match verified bytes",
        ));
    }
    record.executable_sha256 = expected_sha256.to_owned();
    replace_record_atomically(&record)?;
    verify_record(&record)
}
/// Start the verified replacement while the maintenance marker and disabled Run value
/// continue to fence login startup. The authenticated pipe PID is then checked against
/// the current SID, exact image path, and new image digest.
pub(crate) fn start_maintenance_candidate(
    receipt: &MaintenanceReceipt,
    expected_sha256: &str,
) -> io::Result<()> {
    let record = maintenance_record(receipt)?;
    if !record.maintenance || record.executable_sha256 != expected_sha256 {
        return Err(invalid("maintenance candidate identity is not current"));
    }
    if registry_value(&record.run_value)?.is_some() {
        return Err(invalid(
            "login registration must remain disabled during candidate health check",
        ));
    }
    if sha256_file(&record.executable)? != expected_sha256 {
        return Err(invalid("maintenance candidate executable digest changed"));
    }
    crate::update::reject_running_agent(&record.executable)?;
    let capability = format!("{}{}", receipt.transaction_id, random_token());
    let admission = MaintenanceAdmission {
        format: 1,
        transaction_id: receipt.transaction_id.clone(),
        root: record.root.clone(),
        owner_sid: record.owner_sid.clone(),
        executable_sha256: expected_sha256.to_owned(),
        capability_sha256: format!("{:x}", Sha256::digest(&capability[64..])),
    };
    let admission_path = record.root.join(MAINTENANCE_ADMISSION);
    let admission_bytes = serde_json::to_vec(&admission).map_err(io::Error::other)?;
    if admission_bytes.len() > MAX_MAINTENANCE_ADMISSION {
        return Err(invalid("maintenance admission record exceeds size limit"));
    }
    write_maintenance_admission(&admission_path, &admission_bytes)?;
    let result = (|| {
        let process = spawn(&record, true, Some(&capability))?;
        for _ in 0..40 {
            match pipe_request(&record, "STATUS") {
                Ok(reply) if running_pid(&reply) == Some(process.pid) => {
                    let verified = open_owned_process(process.pid, &record)?;
                    if verified.pid != process.pid
                        || sha256_file(&record.executable)? != expected_sha256
                    {
                        return Err(invalid("maintenance candidate health identity changed"));
                    }
                    if ssh_banner(load_config(&record.config)?.listen)? {
                        // SAFETY: process.handle remains open and is the exact spawned process.
                        if unsafe { WaitForSingleObject(process.handle, 0) } == WAIT_TIMEOUT {
                            return Ok(());
                        }
                        return Err(invalid(
                            "maintenance candidate exited during health readback",
                        ));
                    }
                }
                Ok(_) => {
                    return Err(invalid(
                        "maintenance candidate pipe returned an unexpected PID",
                    ));
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "maintenance candidate did not establish authenticated health",
        ))
    })();
    let cleanup = remove_maintenance_admission(&admission_path, &admission_bytes);
    match (result, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) => Err(error),
        (Ok(()), Err(cleanup_error)) => Err(io::Error::other(format!(
            "maintenance candidate started but admission cleanup failed: {cleanup_error}"
        ))),
        (Err(error), Err(cleanup_error)) => Err(io::Error::other(format!(
            "maintenance candidate failed ({error}); admission cleanup failed: {cleanup_error}"
        ))),
    }
}
/// Re-enable only the source-derived Run value after the marker matches the installed EXE.
/// This does not launch the Agent or assert health.
pub(crate) fn register_maintenance(receipt: &MaintenanceReceipt) -> io::Result<()> {
    let mut record = maintenance_record(receipt)?;
    if sha256_file(&record.executable)? != record.executable_sha256 {
        return Err(invalid(
            "installed executable does not match maintenance marker",
        ));
    }
    match registry_value(&record.run_value)? {
        None => set_registry_value(&record.run_value, &receipt.run_command)?,
        Some(value) if value == receipt.run_command => {}
        Some(_) => {
            return Err(invalid(
                "current-user login value changed during maintenance",
            ));
        }
    }
    record.maintenance = false;
    record.maintenance_previous_sha256 = None;
    replace_record_atomically(&record)?;
    verify_record(&record)?;
    verify_registration(&record)
}
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
            WAIT_OBJECT_0 => refuse_active_jobs(&record),
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
    refuse_active_jobs(&record)?;
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
        WAIT_OBJECT_0 => refuse_active_jobs(&record),
        WAIT_TIMEOUT => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "candidate Agent did not stop for rollback; no process was force-terminated",
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
pub(super) fn read_marker_bytes(root: &Path) -> io::Result<Vec<u8>> {
    let path = root.join(MARKER);
    let metadata = fs::symlink_metadata(&path)?;
    if !metadata.is_file() || is_reparse(&metadata) || metadata.len() > MAX_MARKER as u64 {
        return Err(invalid("service marker is unsafe or exceeds size limit"));
    }
    verify_private_acl(&path)?;
    fs::read(path)
}
pub(super) fn maintenance_record(receipt: &MaintenanceReceipt) -> io::Result<InstallRecord> {
    let record = owned_record(&receipt.old_record.root)?;
    let old = &receipt.old_record;
    if !record.maintenance
        || record.maintenance_previous_sha256.as_deref() != Some(old.executable_sha256.as_str())
        || record.owner_sid != old.owner_sid
        || record.root != old.root
        || record.executable != old.executable
        || record.config != old.config
        || record.pipe_name != old.pipe_name
        || record.control_token != old.control_token
        || record.run_value != old.run_value
        || render_command(&record) != receipt.run_command
    {
        return Err(invalid(
            "service maintenance receipt no longer matches its owner marker",
        ));
    }
    match registry_value(&record.run_value)? {
        None => {}
        Some(value) if value == receipt.run_command => {}
        Some(_) => {
            return Err(invalid(
                "current-user login value was occupied during maintenance",
            ));
        }
    }
    validate_record_paths(&record)?;
    Ok(record)
}
pub(super) fn restore_old_marker_and_registration(receipt: &MaintenanceReceipt) -> io::Result<()> {
    let record = maintenance_record(receipt)?;
    if sha256_file(&record.executable)? != receipt.old_record.executable_sha256 {
        return Err(invalid(
            "old executable inventory is not restored; marker rollback refused",
        ));
    }
    replace_marker_bytes(&record.root, &receipt.old_marker)?;
    match registry_value(&record.run_value)? {
        None => set_registry_value(&record.run_value, &receipt.run_command)?,
        Some(value) if value == receipt.run_command => {}
        Some(_) => {
            return Err(invalid(
                "current-user login value is occupied by another command",
            ));
        }
    }
    verify_record(&receipt.old_record)?;
    verify_registration(&receipt.old_record)
}
pub(super) fn replace_record_atomically(record: &InstallRecord) -> io::Result<()> {
    let bytes = serde_json::to_vec(record).map_err(io::Error::other)?;
    replace_marker_bytes(&record.root, &bytes)?;
    let actual = owned_record(&record.root)?;
    if actual.maintenance != record.maintenance
        || actual.maintenance_previous_sha256 != record.maintenance_previous_sha256
        || actual.executable_sha256 != record.executable_sha256
    {
        return Err(invalid(
            "service marker atomic readback did not match requested state",
        ));
    }
    Ok(())
}
pub(super) fn replace_marker_bytes(root: &Path, bytes: &[u8]) -> io::Result<()> {
    if bytes.len() > MAX_MARKER {
        return Err(invalid("service marker exceeds size limit"));
    }
    let marker = root.join(MARKER);
    let temporary = root.join(format!(".hostlink-service-marker-{}.tmp", random_token()));
    write_private(&temporary, bytes)?;
    let result = replace_file(&marker, &temporary);
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result?;
    let metadata = fs::symlink_metadata(&marker)?;
    if !metadata.is_file() || is_reparse(&metadata) {
        return Err(invalid("replaced service marker is not a regular file"));
    }
    verify_private_acl(&marker)?;
    if fs::read(&marker)? != bytes {
        return Err(invalid("service marker replacement readback failed"));
    }
    Ok(())
}
