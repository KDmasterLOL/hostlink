use super::*;

mod begin;
mod recovery;
mod registration;
mod rollback;

pub(crate) use begin::{begin_maintenance, begin_recovery_maintenance};
pub(crate) use recovery::{recover_maintenance_after_inventory, recover_maintenance_stop};
pub(crate) use registration::{
    has_registration, is_in_maintenance, register_maintenance, start_maintenance_candidate,
    update_maintenance_executable, verify_registered_health, verify_registered_image,
};
pub(crate) use rollback::{restore_maintenance, stop_for_maintenance_rollback};

fn read_marker_bytes(root: &Path) -> io::Result<Vec<u8>> {
    let path = root.join(MARKER);
    let metadata = fs::symlink_metadata(&path)?;
    if !metadata.is_file() || is_reparse(&metadata) || metadata.len() > MAX_MARKER as u64 {
        return Err(invalid("service marker is unsafe or exceeds size limit"));
    }
    verify_private_acl(&path)?;
    fs::read(path)
}
fn maintenance_record(receipt: &MaintenanceReceipt) -> io::Result<InstallRecord> {
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
fn restore_old_marker_and_registration(receipt: &MaintenanceReceipt) -> io::Result<()> {
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
fn replace_record_atomically(record: &InstallRecord) -> io::Result<()> {
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
fn replace_marker_bytes(root: &Path, bytes: &[u8]) -> io::Result<()> {
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
