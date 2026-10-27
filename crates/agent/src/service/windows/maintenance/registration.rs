use super::*;

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
