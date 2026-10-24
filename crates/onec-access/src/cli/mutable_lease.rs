//! Controller-local cross-process admission for mutable managed-target runs.

use directories::ProjectDirs;
use hostlink_access::{AppResult, ManagedTargetEffect};
use hostlink_protocol::NativeExecutionEffect;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::{
    fs::{self, File},
    path::{Path, PathBuf},
    time::Duration,
};

const LEASE_DIRECTORY: &str = "mutable-target-leases";
const RESERVATION_DIRECTORY: &str = "durable-run-local-reservations";
const MUTABLE_LEASE_WAIT: Duration = Duration::from_millis(100);
const DISCOVERY_LEASE_WAIT: Duration = super::transport::MAX_RUN_LOCAL_STAGING_DEADLINE;
const MUTABLE_LEASE_POLL: Duration = Duration::from_millis(5);
const MAX_NATIVE_INVOCATION_RESERVATION_BYTES: u64 = 4096;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct DurableNativeInvocationReservation {
    schema_version: u32,
    machine_id: String,
    run_id: String,
    candidate_sha256: String,
    invocation_sha256: String,
    native_effect: NativeExecutionEffect,
}

impl DurableNativeInvocationReservation {
    pub(crate) fn candidate_sha256(&self) -> &str {
        &self.candidate_sha256
    }

    pub(crate) fn invocation_sha256(&self) -> &str {
        &self.invocation_sha256
    }

    pub(crate) fn native_effect(&self) -> NativeExecutionEffect {
        self.native_effect
    }
}

/// Acquires the mutable lease for run-local execution.
///
/// Canonical test inventory may wait longer for the same lease so simultaneous
/// Nextest controllers queue instead of failing on the ordinary short timeout.
/// It still holds the lease and checks durable reservations before execution.
pub(crate) fn acquire_run_local_lease(
    machine_id: &str,
    effect: ManagedTargetEffect,
    args: &[String],
) -> AppResult<Option<File>> {
    if effect == ManagedTargetEffect::ReadOnly {
        return Ok(None);
    }
    let project_dirs = ProjectDirs::from("", "", "onec-access").ok_or_else(|| {
        hostlink_access::invalid_config(
            "cannot determine OS-native application directories for hostlink".to_owned(),
        )
    })?;
    let data_root = project_dirs.data_local_dir();
    acquire_run_local_lease_in(data_root, machine_id, effect, args)
}

fn acquire_run_local_lease_in(
    data_root: &Path,
    machine_id: &str,
    effect: ManagedTargetEffect,
    args: &[String],
) -> AppResult<Option<File>> {
    if effect == ManagedTargetEffect::ReadOnly {
        return Ok(None);
    }

    let wait = if is_canonical_nextest_inventory(args) {
        DISCOVERY_LEASE_WAIT
    } else {
        MUTABLE_LEASE_WAIT
    };
    let lease = acquire_mutable_target_lease_in_with_wait(data_root, machine_id, effect, wait)?;
    if has_durable_reservation(data_root, machine_id)? {
        drop(lease);
        return Err(hostlink_access::invalid_config(format!(
            "TARGET BUSY: managed target {machine_id:?} has a durable run-local job; resume or clean that job before another mutable run"
        )));
    }
    Ok(lease)
}

pub(crate) fn reserve_durable_run_local(
    data_root: &Path,
    machine_id: &str,
    run_id: &str,
) -> AppResult<()> {
    validate_run_id(run_id)?;
    let _guard =
        acquire_mutable_target_lease_in(data_root, machine_id, ManagedTargetEffect::RunOwned)?;
    if has_durable_reservation(data_root, machine_id)? {
        return Err(hostlink_access::invalid_config(format!(
            "TARGET BUSY: managed target {machine_id:?} already has a durable run-local job"
        )));
    }
    let _ = ensure_reservation_machine_dir(data_root, machine_id, true)?
        .expect("create=true always returns the reservation directory");
    let path = pending_reservation_path(data_root, machine_id, run_id);
    write_reservation(&path, machine_id, run_id, "")
}

pub(crate) fn persist_durable_native_invocation(
    data_root: &Path,
    machine_id: &str,
    run_id: &str,
    candidate_sha256: &str,
    invocation_sha256: &str,
    native_effect: NativeExecutionEffect,
) -> AppResult<()> {
    validate_run_id(run_id)?;
    validate_sha256(candidate_sha256, "candidate")?;
    validate_sha256(invocation_sha256, "invocation")?;
    if native_effect == NativeExecutionEffect::ReadOnly {
        return Err(hostlink_access::invalid_config(
            "durable run-local native invocation reservations require run-owned or disposable effect"
                .to_owned(),
        ));
    }
    let (_, pending, released) = reservation_identity(data_root, machine_id, run_id)?;
    if pending.is_none() || released.is_some() {
        return Err(hostlink_access::invalid_config(
            "native invocation commitment requires this run's active pending reservation"
                .to_owned(),
        ));
    }
    let reservation = DurableNativeInvocationReservation {
        schema_version: 1,
        machine_id: machine_id.to_owned(),
        run_id: run_id.to_owned(),
        candidate_sha256: candidate_sha256.to_owned(),
        invocation_sha256: invocation_sha256.to_owned(),
        native_effect,
    };
    let bytes = serde_json::to_vec(&reservation).map_err(|source| {
        hostlink_access::invalid_config(format!(
            "cannot encode durable native invocation reservation: {source}"
        ))
    })?;
    hostlink_core::write_new_private_bytes(
        &native_invocation_reservation_path(data_root, machine_id, run_id),
        &bytes,
    )
    .map_err(|source| {
        anyhow::Error::new(source).context("cannot persist private native invocation commitment")
    })
}

pub(crate) fn durable_native_invocation_reservation(
    data_root: &Path,
    machine_id: &str,
    run_id: &str,
) -> AppResult<DurableNativeInvocationReservation> {
    validate_run_id(run_id)?;
    let path = native_invocation_reservation_path(data_root, machine_id, run_id);
    let metadata = fs::symlink_metadata(&path).map_err(|source| {
        anyhow::Error::new(source).context("native invocation commitment is unavailable")
    })?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_NATIVE_INVOCATION_RESERVATION_BYTES {
        return Err(hostlink_access::invalid_config(
            "native invocation commitment is not a bounded regular file".to_owned(),
        ));
    }
    hostlink_core::validate_private_file(&path).map_err(|source| {
        anyhow::Error::new(source).context("native invocation commitment is not private")
    })?;
    let bytes = fs::read(&path).map_err(|source| {
        anyhow::Error::new(source).context("cannot read native invocation commitment")
    })?;
    let reservation: DurableNativeInvocationReservation =
        serde_json::from_slice(&bytes).map_err(|source| {
            hostlink_access::invalid_config(format!(
                "native invocation commitment is malformed: {source}"
            ))
        })?;
    if reservation.schema_version != 1
        || reservation.machine_id != machine_id
        || reservation.run_id != run_id
        || reservation.native_effect == NativeExecutionEffect::ReadOnly
    {
        return Err(hostlink_access::invalid_config(
            "native invocation commitment does not match the requested machine/run/effect"
                .to_owned(),
        ));
    }
    validate_sha256(&reservation.candidate_sha256, "candidate")?;
    validate_sha256(&reservation.invocation_sha256, "invocation")?;
    Ok(reservation)
}

/// Binds a previously published run identity to the Agent-generated durable job identity.
pub(crate) fn bind_durable_run_local_job(
    data_root: &Path,
    machine_id: &str,
    run_id: &str,
    job_id: &str,
) -> AppResult<()> {
    validate_run_id(run_id)?;
    validate_job_id(job_id)?;
    let _guard =
        acquire_mutable_target_lease_in(data_root, machine_id, ManagedTargetEffect::RunOwned)?;
    let (bound, pending, released) = reservation_identity(data_root, machine_id, run_id)?;
    if released.is_some() {
        if pending.is_none() && bound.as_deref() == Some(job_id) {
            return Ok(());
        }
        return Err(hostlink_access::invalid_config(
            "completed durable run-local reservation belongs to another Agent job".to_owned(),
        ));
    }
    match bound.as_deref() {
        Some(existing) if existing == job_id => {
            if let Some(pending) = pending {
                remove_file_if_present(
                    &pending,
                    "cannot retire pending durable run-local reservation",
                )?;
            }
            return Ok(());
        }
        Some(_) => {
            return Err(hostlink_access::invalid_config(
                "durable run-local reservation is already bound to another Agent job".to_owned(),
            ));
        }
        None if pending.is_none() => {
            return Err(hostlink_access::invalid_config(
                "durable run-local pending reservation is missing".to_owned(),
            ));
        }
        None => {}
    }
    let bound_path = job_reservation_path(data_root, machine_id, job_id);
    write_reservation(&bound_path, machine_id, run_id, job_id)?;
    if let Some(pending) = pending {
        remove_file_if_present(
            &pending,
            "cannot retire pending durable run-local reservation",
        )?;
    }
    Ok(())
}

pub(crate) fn verify_durable_run_local_job(
    data_root: &Path,
    machine_id: &str,
    run_id: &str,
    job_id: &str,
) -> AppResult<()> {
    bind_durable_run_local_job(data_root, machine_id, run_id, job_id)
}

/// Returns the already-bound active Agent job identity for one controller run reservation.
pub(crate) fn durable_run_local_job_id(
    data_root: &Path,
    machine_id: &str,
    run_id: &str,
) -> AppResult<String> {
    let (job_id, pending, released) = reservation_identity(data_root, machine_id, run_id)?;
    if pending.is_some() || released.is_some() {
        return Err(hostlink_access::invalid_config(
            "native attestation requires an active, job-bound durable run-local reservation"
                .to_owned(),
        ));
    }
    job_id.ok_or_else(|| {
        hostlink_access::invalid_config(
            "native attestation requires an active, job-bound durable run-local reservation"
                .to_owned(),
        )
    })
}

pub(crate) fn durable_run_local_recorded_job_id(
    data_root: &Path,
    machine_id: &str,
    run_id: &str,
) -> AppResult<String> {
    let (job_id, pending, _) = reservation_identity(data_root, machine_id, run_id)?;
    if pending.is_some() {
        return Err(hostlink_access::invalid_config(
            "durable run-local reservation is not bound to an Agent job".to_owned(),
        ));
    }
    job_id.ok_or_else(|| {
        hostlink_access::invalid_config(
            "durable run-local reservation has no recorded Agent job identity".to_owned(),
        )
    })
}

pub(crate) fn remove_durable_native_invocation_reservation(
    data_root: &Path,
    machine_id: &str,
    run_id: &str,
) -> AppResult<()> {
    validate_run_id(run_id)?;
    remove_file_if_present(
        &native_invocation_reservation_path(data_root, machine_id, run_id),
        "cannot remove durable native invocation commitment",
    )
}

/// Serializes one full controller-side durable run-local completion transition.
pub(crate) fn acquire_durable_run_local_operation_lease(
    data_root: &Path,
    machine_id: &str,
) -> AppResult<File> {
    acquire_mutable_target_lease_in(data_root, machine_id, ManagedTargetEffect::RunOwned)?
        .ok_or_else(|| {
            hostlink_access::invalid_config(
                "durable run-local operation lease was not acquired".to_owned(),
            )
        })
}

pub(crate) fn release_durable_run_local(
    data_root: &Path,
    machine_id: &str,
    run_id: &str,
    expected_job_id: &str,
) -> AppResult<()> {
    let (recorded_job, pending, released) = reservation_identity(data_root, machine_id, run_id)?;
    if released.is_some() && pending.is_some() {
        return Err(hostlink_access::invalid_config(
            "released durable run-local receipt conflicts with a pending reservation".to_owned(),
        ));
    }
    if released.is_some() && recorded_job.as_deref() == Some(expected_job_id) {
        cleanup_result_markers(data_root, machine_id, run_id)?;
        return Ok(());
    }
    match (recorded_job.as_deref(), pending.is_some()) {
        (Some(recorded), _) if recorded == expected_job_id => {}
        (None, false) => {
            cleanup_result_markers(data_root, machine_id, run_id)?;
            return Ok(());
        }
        _ => {
            return Err(hostlink_access::invalid_config(
                "durable run-local reservation belongs to another Agent job".to_owned(),
            ));
        }
    }
    if !durable_run_local_results_complete(data_root, machine_id, run_id)? {
        return Err(hostlink_access::invalid_config(
            "durable run-local reservation cannot be released before result retrieval and cleanup"
                .to_owned(),
        ));
    }
    release_durable_run_local_files(
        data_root,
        machine_id,
        run_id,
        Some(expected_job_id),
        false,
        false,
    )
}

pub(crate) fn release_abandoned_run_local(
    data_root: &Path,
    machine_id: &str,
    run_id: &str,
) -> AppResult<()> {
    release_durable_run_local_files(data_root, machine_id, run_id, None, false, false)?;
    remove_durable_native_invocation_reservation(data_root, machine_id, run_id)
}

fn release_durable_run_local_files(
    data_root: &Path,
    machine_id: &str,
    run_id: &str,
    expected_job_id: Option<&str>,
    inject_failure_after_download_marker: bool,
    inject_failure_after_release_receipt: bool,
) -> AppResult<()> {
    validate_run_id(run_id)?;
    let _guard =
        acquire_mutable_target_lease_in(data_root, machine_id, ManagedTargetEffect::RunOwned)?;
    let (job_id, pending, released) = reservation_identity(data_root, machine_id, run_id)?;
    if job_id.as_deref() != expected_job_id && (job_id.is_some() || expected_job_id.is_some()) {
        return Err(hostlink_access::invalid_config(
            "durable run-local reservation ownership does not match the requested cleanup"
                .to_owned(),
        ));
    }
    remove_file_if_present(
        &results_downloaded_path(data_root, machine_id, run_id),
        "cannot remove durable run-local download marker",
    )?;
    if inject_failure_after_download_marker {
        return Err(hostlink_access::invalid_config(
            "injected durable reservation release failure".to_owned(),
        ));
    }
    // Keep results-complete evidence until the active reservation has atomically become a
    // released identity receipt. A retry can then verify both run and job after any crash.
    if let Some(released) = released {
        if job_id.as_deref() != Some(released.as_str()) {
            return Err(hostlink_access::invalid_config(
                "released durable run-local receipt does not match its Agent job identity"
                    .to_owned(),
            ));
        }
        return cleanup_result_markers(data_root, machine_id, run_id);
    }
    if let Some(pending) = pending {
        remove_file_if_present(
            &pending,
            "cannot release pending durable run-local reservation",
        )?;
    }
    if let Some(job_id) = job_id {
        fs::rename(
            job_reservation_path(data_root, machine_id, &job_id),
            released_reservation_path(data_root, machine_id, &job_id),
        )
        .map_err(|source| {
            anyhow::Error::new(source).context("cannot persist released run-local identity receipt")
        })?;
    }
    if inject_failure_after_release_receipt {
        return Err(hostlink_access::invalid_config(
            "injected durable reservation failure after released identity receipt".to_owned(),
        ));
    }
    cleanup_result_markers(data_root, machine_id, run_id)
}

pub(crate) fn mark_durable_run_local_results_downloaded(
    data_root: &Path,
    machine_id: &str,
    run_id: &str,
) -> AppResult<()> {
    validate_run_id(run_id)?;
    let _guard =
        acquire_mutable_target_lease_in(data_root, machine_id, ManagedTargetEffect::RunOwned)?;
    require_bound_reservation(data_root, machine_id, run_id)?;
    let marker = results_downloaded_path(data_root, machine_id, run_id);
    if !marker.exists() {
        hostlink_core::write_new_private_bytes(&marker, b"results-downloaded\n").map_err(
            |source| {
                anyhow::Error::new(source)
                    .context("cannot persist durable run-local download completion")
            },
        )?;
    }
    Ok(())
}

pub(crate) fn durable_run_local_results_downloaded(
    data_root: &Path,
    machine_id: &str,
    run_id: &str,
) -> AppResult<bool> {
    validate_run_id(run_id)?;
    require_bound_reservation(data_root, machine_id, run_id)?;
    match fs::read(results_downloaded_path(data_root, machine_id, run_id)) {
        Ok(bytes) => Ok(bytes == b"results-downloaded\n"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(source) => {
            Err(anyhow::Error::new(source).context("cannot read durable run-local download marker"))
        }
    }
}

pub(crate) fn mark_durable_run_local_results_complete(
    data_root: &Path,
    machine_id: &str,
    run_id: &str,
) -> AppResult<()> {
    validate_run_id(run_id)?;
    let _guard =
        acquire_mutable_target_lease_in(data_root, machine_id, ManagedTargetEffect::RunOwned)?;
    require_bound_reservation(data_root, machine_id, run_id)?;
    if fs::read(results_downloaded_path(data_root, machine_id, run_id)).map_err(|source| {
        anyhow::Error::new(source).context("durable run-local result downloads are not recorded")
    })? != b"results-downloaded\n"
    {
        return Err(hostlink_access::invalid_config(
            "durable run-local result downloads are not complete".to_owned(),
        ));
    }
    let marker = results_complete_path(data_root, machine_id, run_id);
    if !marker.exists() {
        hostlink_core::write_new_private_bytes(&marker, b"results-complete\n").map_err(
            |source| {
                anyhow::Error::new(source)
                    .context("cannot persist durable run-local result completion")
            },
        )?;
    }
    Ok(())
}

pub(crate) fn durable_run_local_results_complete(
    data_root: &Path,
    machine_id: &str,
    run_id: &str,
) -> AppResult<bool> {
    validate_run_id(run_id)?;
    let (_, _, released) = reservation_identity(data_root, machine_id, run_id)?;
    if released.is_some() {
        return Ok(true);
    }
    require_bound_reservation(data_root, machine_id, run_id)?;
    match fs::read(results_complete_path(data_root, machine_id, run_id)) {
        Ok(bytes) => Ok(bytes == b"results-complete\n"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(source) => {
            Err(anyhow::Error::new(source)
                .context("cannot read durable run-local result completion"))
        }
    }
}

fn require_bound_reservation(
    data_root: &Path,
    machine_id: &str,
    run_id: &str,
) -> AppResult<String> {
    let (job_id, _, _) = reservation_identity(data_root, machine_id, run_id)?;
    job_id.ok_or_else(|| {
        hostlink_access::invalid_config(
            "durable run-local reservation is not bound to an Agent job".to_owned(),
        )
    })
}

fn reservation_identity(
    data_root: &Path,
    machine_id: &str,
    run_id: &str,
) -> AppResult<(Option<String>, Option<PathBuf>, Option<String>)> {
    validate_run_id(run_id)?;
    let directory = reservation_machine_dir(data_root, machine_id);
    ensure_reservation_machine_dir(data_root, machine_id, false)?;
    let entries = match fs::read_dir(&directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok((None, None, None));
        }
        Err(source) => {
            return Err(
                anyhow::Error::new(source).context("cannot inspect durable run-local reservations")
            );
        }
    };
    let mut job = None;
    let mut pending = None;
    let mut released = None;
    for entry in entries {
        let entry = entry.map_err(anyhow::Error::new)?;
        let name = entry.file_name();
        let relevant = name.to_string_lossy().ends_with(".reservation")
            || name.to_string_lossy().ends_with(".pending")
            || name.to_string_lossy().ends_with(".released");
        if !relevant {
            continue;
        }
        if !entry.file_type().map_err(anyhow::Error::new)?.is_file() {
            return Err(hostlink_access::invalid_config(
                "durable run-local reservation entry is not a regular file".to_owned(),
            ));
        }
        let contents = fs::read_to_string(entry.path()).map_err(anyhow::Error::new)?;
        let fields = contents.lines().collect::<Vec<_>>();
        if fields.len() != 3 || fields[0] != machine_id || fields[1] != run_id {
            continue;
        }
        if fields[2].is_empty() {
            if entry.path() != pending_reservation_path(data_root, machine_id, run_id) {
                return Err(hostlink_access::invalid_config(
                    "pending durable reservation path does not match its identity".to_owned(),
                ));
            }
            pending = Some(entry.path());
        } else {
            validate_job_id(fields[2])?;
            let is_released = name.to_string_lossy().ends_with(".released");
            let expected_path = if is_released {
                released_reservation_path(data_root, machine_id, fields[2])
            } else {
                job_reservation_path(data_root, machine_id, fields[2])
            };
            if entry.path() != expected_path {
                return Err(hostlink_access::invalid_config(
                    "durable reservation path does not match its Agent job identity".to_owned(),
                ));
            }
            if is_released {
                if released
                    .as_deref()
                    .is_some_and(|current| current != fields[2])
                {
                    return Err(hostlink_access::invalid_config(
                        "run identity has conflicting released Agent job receipts".to_owned(),
                    ));
                }
                released = Some(fields[2].to_owned());
                continue;
            }
            if job.as_deref().is_some_and(|current| current != fields[2]) {
                return Err(hostlink_access::invalid_config(
                    "run identity has conflicting durable Agent job reservations".to_owned(),
                ));
            }
            job = Some(fields[2].to_owned());
        }
    }
    if released.is_some() && (job.is_some() || pending.is_some()) {
        return Err(hostlink_access::invalid_config(
            "active and released durable reservations conflict for one run identity".to_owned(),
        ));
    }
    if job.is_none() {
        job.clone_from(&released);
    }
    Ok((job, pending, released))
}

/// Lists controller reservations for the exact managed machine identity.
pub(crate) fn list_durable_run_local_reservations(
    data_root: &Path,
    machine_id: &str,
) -> AppResult<Vec<(String, Option<String>)>> {
    let directory = reservation_machine_dir(data_root, machine_id);
    ensure_reservation_machine_dir(data_root, machine_id, false)?;
    let entries = match fs::read_dir(&directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(source) => {
            return Err(
                anyhow::Error::new(source).context("cannot inspect durable run-local reservations")
            );
        }
    };
    let mut reservations = std::collections::BTreeMap::new();
    for entry in entries {
        let entry = entry.map_err(anyhow::Error::new)?;
        let name = entry.file_name();
        let is_reservation = name.to_string_lossy().ends_with(".reservation")
            || name.to_string_lossy().ends_with(".pending");
        if !is_reservation {
            continue;
        }
        if !entry.file_type().map_err(anyhow::Error::new)?.is_file() {
            return Err(hostlink_access::invalid_config(
                "durable run-local reservation entry is not a regular file".to_owned(),
            ));
        }
        let contents = fs::read_to_string(entry.path()).map_err(anyhow::Error::new)?;
        let fields = contents.lines().collect::<Vec<_>>();
        let name = entry.file_name();
        let is_reservation = name.to_string_lossy().ends_with(".reservation")
            || name.to_string_lossy().ends_with(".pending");
        if !is_reservation {
            continue;
        }
        if fields.len() != 3 || fields[0] != machine_id {
            return Err(hostlink_access::invalid_config(
                "malformed durable run-local reservation in machine identity store".to_owned(),
            ));
        }
        validate_run_id(fields[1])?;
        let job_id = if fields[2].is_empty() {
            if entry.path() != pending_reservation_path(data_root, machine_id, fields[1]) {
                return Err(hostlink_access::invalid_config(
                    "pending durable reservation path does not match its identity".to_owned(),
                ));
            }
            None
        } else {
            validate_job_id(fields[2])?;
            if entry.path() != job_reservation_path(data_root, machine_id, fields[2]) {
                return Err(hostlink_access::invalid_config(
                    "durable reservation path does not match its Agent job identity".to_owned(),
                ));
            }
            Some(fields[2].to_owned())
        };
        match reservations.entry(fields[1].to_owned()) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(job_id);
            }
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                match (entry.get().as_deref(), job_id.as_deref()) {
                    (Some(left), Some(right)) if left != right => {
                        return Err(hostlink_access::invalid_config(
                            "run identity has conflicting durable Agent job reservations"
                                .to_owned(),
                        ));
                    }
                    (None, Some(_)) => {
                        entry.insert(job_id);
                    }
                    _ => {}
                }
            }
        }
    }
    Ok(reservations.into_iter().collect())
}

fn write_reservation(path: &Path, machine_id: &str, run_id: &str, job_id: &str) -> AppResult<()> {
    hostlink_core::write_new_private_bytes(
        path,
        format!("{machine_id}\n{run_id}\n{job_id}\n").as_bytes(),
    )
    .map_err(|source| {
        anyhow::Error::new(source).context("cannot persist durable run-local reservation")
    })
}

fn cleanup_result_markers(data_root: &Path, machine_id: &str, run_id: &str) -> AppResult<()> {
    remove_file_if_present(
        &results_complete_path(data_root, machine_id, run_id),
        "cannot remove durable run-local result marker",
    )?;
    remove_file_if_present(
        &results_downloaded_path(data_root, machine_id, run_id),
        "cannot remove durable run-local download marker",
    )?;
    Ok(())
}

fn remove_file_if_present(path: &Path, context: &str) -> AppResult<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(anyhow::Error::new(source).context(context.to_owned())),
    }
}

fn has_durable_reservation(data_root: &Path, machine_id: &str) -> AppResult<bool> {
    let directory = reservation_machine_dir(data_root, machine_id);
    ensure_reservation_machine_dir(data_root, machine_id, false)?;
    match fs::read_dir(directory) {
        Ok(entries) => {
            for entry in entries {
                let entry = entry.map_err(|source| {
                    anyhow::Error::new(source)
                        .context("cannot inspect durable run-local reservations")
                })?;
                let file_type = entry.file_type().map_err(anyhow::Error::new)?;
                let name = entry.file_name();
                let is_active_record = name.to_string_lossy().ends_with(".reservation")
                    || name.to_string_lossy().ends_with(".pending");
                if is_active_record && !file_type.is_file() {
                    return Err(hostlink_access::invalid_config(
                        "durable run-local reservation entry is not a regular file".to_owned(),
                    ));
                }
                if is_active_record {
                    return Ok(true);
                }
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(source) => {
            return Err(
                anyhow::Error::new(source).context("cannot inspect durable run-local reservations")
            );
        }
    }
    Ok(false)
}

fn reservation_machine_dir(data_root: &Path, machine_id: &str) -> PathBuf {
    let digest = Sha256::digest(machine_id.as_bytes());
    let mut key = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut key, "{byte:02x}").expect("writing SHA-256 into String cannot fail");
    }
    data_root.join(RESERVATION_DIRECTORY).join(key)
}

fn ensure_reservation_machine_dir(
    data_root: &Path,
    machine_id: &str,
    create: bool,
) -> AppResult<Option<PathBuf>> {
    let root = data_root.join(RESERVATION_DIRECTORY);
    let machine = reservation_machine_dir(data_root, machine_id);
    for path in [&root, &machine] {
        match fs::symlink_metadata(path) {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
                if create {
                    hostlink_core::ensure_private_directory(path).map_err(|source| {
                        anyhow::Error::new(source)
                            .context("cannot secure durable run-local reservation directory")
                    })?;
                }
            }
            Ok(_) => {
                return Err(hostlink_access::invalid_config(
                    "durable run-local reservation directory is not an owned directory".to_owned(),
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound && !create => {
                return Ok(None);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                hostlink_core::ensure_private_directory(path).map_err(|source| {
                    anyhow::Error::new(source)
                        .context("cannot create durable run-local reservation directory")
                })?;
            }
            Err(source) => {
                return Err(anyhow::Error::new(source)
                    .context("cannot inspect durable run-local reservation directory"));
            }
        }
    }
    Ok(Some(machine))
}

fn pending_reservation_path(data_root: &Path, machine_id: &str, run_id: &str) -> PathBuf {
    reservation_machine_dir(data_root, machine_id).join(format!("{run_id}.pending"))
}

fn job_reservation_path(data_root: &Path, machine_id: &str, job_id: &str) -> PathBuf {
    reservation_machine_dir(data_root, machine_id).join(format!("{job_id}.reservation"))
}

fn released_reservation_path(data_root: &Path, machine_id: &str, job_id: &str) -> PathBuf {
    reservation_machine_dir(data_root, machine_id).join(format!("{job_id}.released"))
}

fn results_complete_path(data_root: &Path, machine_id: &str, run_id: &str) -> PathBuf {
    reservation_machine_dir(data_root, machine_id).join(format!("{run_id}.results-complete"))
}

fn results_downloaded_path(data_root: &Path, machine_id: &str, run_id: &str) -> PathBuf {
    reservation_machine_dir(data_root, machine_id).join(format!("{run_id}.results-downloaded"))
}

fn native_invocation_reservation_path(data_root: &Path, machine_id: &str, run_id: &str) -> PathBuf {
    reservation_machine_dir(data_root, machine_id).join(format!("{run_id}.native-invocation.json"))
}

fn validate_sha256(value: &str, subject: &str) -> AppResult<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(hostlink_access::invalid_config(format!(
            "{subject} SHA-256 must be 64 lowercase hexadecimal characters"
        )));
    }
    Ok(())
}

fn validate_run_id(run_id: &str) -> AppResult<()> {
    if run_id.len() != 32 || !run_id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(hostlink_access::invalid_config(
            "run-local identity must be a 32-character hexadecimal UUID".to_owned(),
        ));
    }
    Ok(())
}

fn validate_job_id(job_id: &str) -> AppResult<()> {
    if !job_id.starts_with("job-")
        || job_id.len() > 128
        || !job_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err(hostlink_access::invalid_config(
            "invalid Agent job identity in durable run-local reservation".to_owned(),
        ));
    }
    Ok(())
}

fn is_canonical_nextest_inventory(args: &[String]) -> bool {
    matches!(
        args,
        [list, format, terse] if list == "--list" && format == "--format" && terse == "terse"
    ) || matches!(
        args,
        [list, format, terse, ignored]
            if list == "--list" && format == "--format" && terse == "terse" && ignored == "--ignored"
    )
}

fn acquire_mutable_target_lease_in(
    data_root: &Path,
    machine_id: &str,
    effect: ManagedTargetEffect,
) -> AppResult<Option<File>> {
    acquire_mutable_target_lease_in_with_wait(data_root, machine_id, effect, MUTABLE_LEASE_WAIT)
}

fn acquire_mutable_target_lease_in_with_wait(
    data_root: &Path,
    machine_id: &str,
    effect: ManagedTargetEffect,
    wait: Duration,
) -> AppResult<Option<File>> {
    if effect == ManagedTargetEffect::ReadOnly {
        return Ok(None);
    }

    let directory = data_root.join(LEASE_DIRECTORY);
    fs::create_dir_all(&directory).map_err(|source| {
        anyhow::Error::new(source).context(format!("I/O error at {}", directory.display()))
    })?;
    let path = lease_path(&directory, machine_id);
    match hostlink_core::acquire_exclusive_file_lock(&path, wait, MUTABLE_LEASE_POLL) {
        Ok(file) => Ok(Some(file)),
        Err(source) if source.kind() == std::io::ErrorKind::TimedOut => {
            Err(hostlink_access::invalid_config(format!(
                "TARGET BUSY: managed target {machine_id:?} already has a mutable run-local execution; wait for it to finish and retry"
            )))
        }
        Err(source) => {
            Err(anyhow::Error::new(source).context(format!("I/O error at {}", path.display())))
        }
    }
}

fn lease_path(directory: &Path, machine_id: &str) -> PathBuf {
    let digest = Sha256::digest(machine_id.as_bytes());
    let mut key = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut key, "{byte:02x}").expect("writing SHA-256 into String cannot fail");
    }
    directory.join(format!("{key}.lock"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{BufRead as _, BufReader, Read as _, Write as _},
        process::{Child, Command, Stdio},
    };
    use tempfile::tempdir;

    const READY: &str = "ONEC_ACCESS_MUTABLE_LEASE_READY";

    #[test]
    fn discovery_lease_wait_matches_run_local_staging_deadline() {
        assert_eq!(
            DISCOVERY_LEASE_WAIT,
            super::super::transport::MAX_RUN_LOCAL_STAGING_DEADLINE
        );
    }

    #[test]
    fn lease_child_process() {
        let (Some(root), Some(machine_id), Some(effect)) = (
            std::env::var_os("ONEC_ACCESS_MUTABLE_LEASE_ROOT"),
            std::env::var("ONEC_ACCESS_MUTABLE_LEASE_MACHINE").ok(),
            std::env::var("ONEC_ACCESS_MUTABLE_LEASE_EFFECT").ok(),
        ) else {
            return;
        };
        let effect = match effect.as_str() {
            "read-only" => ManagedTargetEffect::ReadOnly,
            "run-owned" => ManagedTargetEffect::RunOwned,
            "disposable" => ManagedTargetEffect::Disposable,
            _ => panic!("invalid test effect"),
        };
        let args = Vec::new();
        if std::env::var("ONEC_ACCESS_MUTABLE_LEASE_EXPECT_BUSY").as_deref() == Ok("true") {
            let error = acquire_run_local_lease_in(Path::new(&root), &machine_id, effect, &args)
                .expect_err("persistent reservation must block a new controller process");
            assert!(
                error.to_string().contains("durable run-local job"),
                "{error:#}"
            );
            return;
        }
        let _lease = acquire_run_local_lease_in(Path::new(&root), &machine_id, effect, &args)
            .expect("child lease acquisition");
        println!("{READY}");
        std::io::stdout().flush().expect("flush readiness");
        let mut release = Vec::new();
        std::io::stdin()
            .read_to_end(&mut release)
            .expect("wait for parent release");
    }

    #[test]
    fn mutable_target_lease_excludes_same_target_across_processes_and_releases_on_termination() {
        let root = tempdir().expect("temporary lease root");
        let mut holder = spawn_holder(root.path(), "machine-a", "run-owned");

        let error = acquire_mutable_target_lease_in(
            root.path(),
            "machine-a",
            ManagedTargetEffect::Disposable,
        )
        .expect_err("independent process must not enter same mutable target");
        assert!(error.to_string().contains("TARGET BUSY"), "{error:#}");

        holder.kill().expect("terminate holder process");
        let status = holder.wait().expect("reap holder process");
        assert!(
            !status.success(),
            "holder process should have been terminated"
        );
        let _lease = acquire_mutable_target_lease_in(
            root.path(),
            "machine-a",
            ManagedTargetEffect::RunOwned,
        )
        .expect("OS must release the lease when the holder process terminates");
    }

    #[test]
    fn nextest_discovery_queues_for_the_mutable_lease() {
        let root = tempdir().expect("temporary lease root");
        let mut holder = spawn_holder(root.path(), "machine-a", "run-owned");
        let (sent, received) = std::sync::mpsc::channel();
        let root_path = root.path().to_owned();
        let waiter = std::thread::spawn(move || {
            let args = ["--list", "--format", "terse"].map(str::to_owned);
            let lease = acquire_run_local_lease_in(
                &root_path,
                "machine-a",
                ManagedTargetEffect::Disposable,
                &args,
            )
            .expect("bounded discovery wait acquires the lease after the holder exits");
            sent.send(lease.is_some()).expect("report acquired lease");
        });

        assert!(received.recv_timeout(Duration::from_millis(150)).is_err());
        release_holder(&mut holder);
        assert!(received.recv_timeout(DISCOVERY_LEASE_WAIT).unwrap());
        waiter.join().expect("join queued discovery");
    }

    #[test]
    fn arbitrary_executable_with_canonical_list_args_cannot_bypass_busy_lease() {
        let root = tempdir().expect("temporary lease root");
        let mut holder = spawn_holder(root.path(), "machine-a", "run-owned");

        let (sent, received) = std::sync::mpsc::channel();
        let root_path = root.path().to_owned();
        let waiter = std::thread::spawn(move || {
            // The lease layer does not attest the executable. These args are safe
            // only because admission still waits for and holds the same OS lock.
            let arbitrary_executable_args = ["--list", "--format", "terse"].map(str::to_owned);
            let lease = acquire_run_local_lease_in(
                &root_path,
                "machine-a",
                ManagedTargetEffect::Disposable,
                &arbitrary_executable_args,
            )
            .expect("queued mutable execution acquires the lease after release");
            sent.send(lease.is_some()).expect("report acquired lease");
        });
        assert!(received.recv_timeout(Duration::from_millis(150)).is_err());
        release_holder(&mut holder);
        assert!(received.recv_timeout(DISCOVERY_LEASE_WAIT).unwrap());
        waiter.join().expect("join queued arbitrary execution");
    }

    #[test]
    fn mutable_test_execution_still_excludes_other_mutable_execution() {
        let root = tempdir().expect("temporary lease root");
        let mut holder = spawn_holder(root.path(), "machine-a", "run-owned");
        let execution_args = ["native_test"].map(str::to_owned);

        let error = acquire_run_local_lease_in(
            root.path(),
            "machine-a",
            ManagedTargetEffect::Disposable,
            &execution_args,
        )
        .expect_err("actual mutable test execution remains exclusive");
        assert!(error.to_string().contains("TARGET BUSY"), "{error:#}");
        release_holder(&mut holder);
    }

    #[test]
    fn near_miss_libtest_discovery_argv_does_not_bypass_lease() {
        let root = tempdir().expect("temporary lease root");
        let mut holder = spawn_holder(root.path(), "machine-a", "run-owned");
        let args = ["--list", "--format", "terse", "extra"].map(str::to_owned);

        let error = acquire_run_local_lease_in(
            root.path(),
            "machine-a",
            ManagedTargetEffect::Disposable,
            &args,
        )
        .expect_err("unrecognized listing argv must still acquire the lease");
        assert!(error.to_string().contains("TARGET BUSY"), "{error:#}");
        release_holder(&mut holder);
    }

    #[test]
    fn mutable_target_lease_allows_different_target_across_processes() {
        let root = tempdir().expect("temporary lease root");
        let _first = acquire_mutable_target_lease_in(
            root.path(),
            "machine-a",
            ManagedTargetEffect::RunOwned,
        )
        .expect("first target lease")
        .expect("mutable effect lease");
        let mut second = spawn_holder(root.path(), "machine-b", "disposable");
        release_holder(&mut second);
    }

    #[test]
    fn read_only_run_bypasses_mutable_lease_across_processes() {
        let root = tempdir().expect("temporary lease root");
        let _holder = acquire_mutable_target_lease_in(
            root.path(),
            "machine-a",
            ManagedTargetEffect::RunOwned,
        )
        .expect("mutable target lease")
        .expect("mutable effect lease");

        let mut read_only = spawn_holder(root.path(), "machine-a", "read-only");
        release_holder(&mut read_only);
        assert!(
            acquire_mutable_target_lease_in(
                root.path(),
                "machine-a",
                ManagedTargetEffect::ReadOnly
            )
            .expect("read-only bypass")
            .is_none()
        );
    }

    #[test]
    fn durable_reservation_survives_controller_exit_until_result_cleanup_and_release() {
        let root = tempdir().expect("temporary lease root");
        let run_id = "0123456789abcdef0123456789abcdef";
        let job_id = "job-100-200-1";
        reserve_durable_run_local(root.path(), "machine-a", run_id)
            .expect("persist durable reservation");
        assert_eq!(
            list_durable_run_local_reservations(root.path(), "machine-a").expect("list"),
            vec![(run_id.to_owned(), None)],
            "the pre-output pending reservation is discoverable"
        );
        bind_durable_run_local_job(root.path(), "machine-a", run_id, job_id)
            .expect("bind Agent job identity");
        let job_keyed_path = job_reservation_path(root.path(), "machine-a", job_id);
        assert!(
            job_keyed_path.is_file(),
            "reservation key includes Agent job id"
        );
        assert!(!pending_reservation_path(root.path(), "machine-a", run_id).exists());
        assert_eq!(
            list_durable_run_local_reservations(root.path(), "machine-a").expect("list bound"),
            vec![(run_id.to_owned(), Some(job_id.to_owned()))]
        );
        assert!(
            list_durable_run_local_reservations(root.path(), "machine-b")
                .expect("different exact machine identity")
                .is_empty()
        );
        assert!(
            bind_durable_run_local_job(root.path(), "machine-a", run_id, "job-else-1").is_err()
        );
        assert_new_process_blocked(root.path(), "run-owned");
        let discovery = ["--list", "--format", "terse"].map(str::to_owned);
        assert!(
            acquire_run_local_lease_in(
                root.path(),
                "machine-a",
                ManagedTargetEffect::RunOwned,
                &discovery
            )
            .expect_err("canonical listing args cannot bypass a persistent reservation")
            .to_string()
            .contains("durable run-local job")
        );
        let ignored_discovery = ["--list", "--format", "terse", "--ignored"].map(str::to_owned);
        assert!(
            acquire_run_local_lease_in(
                root.path(),
                "machine-a",
                ManagedTargetEffect::RunOwned,
                &ignored_discovery
            )
            .expect_err("ignored listing args cannot bypass a persistent reservation")
            .to_string()
            .contains("durable run-local job")
        );
        let near_miss = ["--list", "--format", "terse", "--ignored", "extra"].map(str::to_owned);
        assert!(
            acquire_run_local_lease_in(
                root.path(),
                "machine-a",
                ManagedTargetEffect::RunOwned,
                &near_miss
            )
            .expect_err("near-miss discovery remains blocked by durable reservation")
            .to_string()
            .contains("durable run-local job")
        );
        assert!(release_durable_run_local(root.path(), "machine-a", run_id, job_id).is_err());
        assert_new_process_blocked(root.path(), "run-owned");
        let mut read_only = spawn_holder(root.path(), "machine-a", "read-only");
        release_holder(&mut read_only);

        mark_durable_run_local_results_downloaded(root.path(), "machine-a", run_id)
            .expect("record successful result downloads");
        mark_durable_run_local_results_complete(root.path(), "machine-a", run_id)
            .expect("record result retrieval");
        assert!(
            durable_run_local_results_complete(root.path(), "machine-a", run_id)
                .expect("read result marker")
        );
        assert_new_process_blocked(root.path(), "disposable");
        release_durable_run_local(root.path(), "machine-a", run_id, job_id)
            .expect("release only after cleanup");
        release_durable_run_local(root.path(), "machine-a", run_id, job_id)
            .expect("release is idempotent after reservation removal");
        let mut mutable = spawn_holder(root.path(), "machine-a", "run-owned");
        release_holder(&mut mutable);
    }

    #[test]
    fn native_invocation_commitment_is_private_bound_to_machine_run_and_survives_observed_release()
    {
        let root = tempdir().expect("temporary reservation root");
        let run_id = "4123456789abcdef0123456789abcdef";
        let job_id = "job-103-203-3";
        let candidate_sha256 = "ab".repeat(32);
        let invocation_sha256 = "cd".repeat(32);
        reserve_durable_run_local(root.path(), "machine-a", run_id).expect("reserve durable run");
        persist_durable_native_invocation(
            root.path(),
            "machine-a",
            run_id,
            &candidate_sha256,
            &invocation_sha256,
            NativeExecutionEffect::Disposable,
        )
        .expect("persist canonical invocation identity");
        let path = native_invocation_reservation_path(root.path(), "machine-a", run_id);
        hostlink_core::validate_private_file(&path).expect("private commitment");
        let persisted = durable_native_invocation_reservation(root.path(), "machine-a", run_id)
            .expect("read exact commitment");
        assert_eq!(persisted.candidate_sha256(), candidate_sha256);
        assert_eq!(persisted.invocation_sha256(), invocation_sha256);
        assert_eq!(persisted.native_effect(), NativeExecutionEffect::Disposable);
        assert!(
            durable_native_invocation_reservation(root.path(), "machine-b", run_id).is_err(),
            "commitment must bind exact machine identity"
        );

        bind_durable_run_local_job(root.path(), "machine-a", run_id, job_id)
            .expect("bind durable job");
        mark_durable_run_local_results_downloaded(root.path(), "machine-a", run_id)
            .expect("results downloaded");
        mark_durable_run_local_results_complete(root.path(), "machine-a", run_id)
            .expect("results cleaned");
        release_durable_run_local(root.path(), "machine-a", run_id, job_id)
            .expect("release completed invocation reservation");
        assert!(
            path.exists(),
            "commitment is retained to verify a stored observation after release"
        );
        assert_eq!(
            durable_run_local_recorded_job_id(root.path(), "machine-a", run_id)
                .expect("released identity remains available"),
            job_id
        );
        remove_durable_native_invocation_reservation(root.path(), "machine-a", run_id)
            .expect("ordinary cleanup retires the commitment");
        assert!(!path.exists());
    }

    #[test]
    fn result_completion_survives_fault_during_reservation_release() {
        let root = tempdir().expect("temporary lease root");
        let run_id = "1123456789abcdef0123456789abcdef";
        let job_id = "job-101-201-2";
        reserve_durable_run_local(root.path(), "machine-a", run_id).expect("pending reservation");
        bind_durable_run_local_job(root.path(), "machine-a", run_id, job_id).expect("bind job");
        mark_durable_run_local_results_downloaded(root.path(), "machine-a", run_id)
            .expect("downloaded marker");
        mark_durable_run_local_results_complete(root.path(), "machine-a", run_id)
            .expect("completion marker");

        assert!(
            release_durable_run_local_files(
                root.path(),
                "machine-a",
                run_id,
                Some(job_id),
                true,
                false
            )
            .is_err()
        );
        assert!(has_durable_reservation(root.path(), "machine-a").expect("reservation retained"));
        assert!(
            durable_run_local_results_complete(root.path(), "machine-a", run_id)
                .expect("completion survives interrupted release")
        );

        release_durable_run_local(root.path(), "machine-a", run_id, job_id)
            .expect("retry completes release");
        assert!(!has_durable_reservation(root.path(), "machine-a").expect("released"));
    }

    #[test]
    fn released_identity_receipt_recovers_crash_before_marker_cleanup() {
        let root = tempdir().expect("temporary lease root");
        let run_id = "2123456789abcdef0123456789abcdef";
        let job_id = "job-102-202-2";
        reserve_durable_run_local(root.path(), "machine-a", run_id).expect("pending reservation");
        bind_durable_run_local_job(root.path(), "machine-a", run_id, job_id).expect("bind job");
        mark_durable_run_local_results_downloaded(root.path(), "machine-a", run_id)
            .expect("downloaded marker");
        mark_durable_run_local_results_complete(root.path(), "machine-a", run_id)
            .expect("completion marker");

        assert!(
            release_durable_run_local_files(
                root.path(),
                "machine-a",
                run_id,
                Some(job_id),
                false,
                true,
            )
            .is_err()
        );
        assert!(
            !has_durable_reservation(root.path(), "machine-a")
                .expect("released receipt is not an active reservation"),
            "reservation entries: {:?}",
            fs::read_dir(reservation_machine_dir(root.path(), "machine-a"))
                .expect("reservation directory")
                .map(|entry| entry.expect("entry").file_name())
                .collect::<Vec<_>>()
        );
        assert!(
            list_durable_run_local_reservations(root.path(), "machine-a")
                .expect("list active reservations")
                .is_empty()
        );
        assert!(
            durable_run_local_results_complete(root.path(), "machine-a", run_id)
                .expect("released receipt proves result completion")
        );
        assert_eq!(
            fs::read_to_string(released_reservation_path(root.path(), "machine-a", job_id))
                .expect("read released identity receipt"),
            format!("machine-a\n{run_id}\n{job_id}\n")
        );

        release_durable_run_local(root.path(), "machine-a", run_id, job_id)
            .expect("retry verifies receipt and cleans remaining markers");
        assert!(!results_complete_path(root.path(), "machine-a", run_id).exists());
        assert!(!results_downloaded_path(root.path(), "machine-a", run_id).exists());
        assert!(release_durable_run_local(root.path(), "machine-a", run_id, "job-999-2").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn durable_reservation_admission_fails_closed_on_linked_record() {
        use std::os::unix::fs::symlink;

        let root = tempdir().expect("temporary lease root");
        let run_id = "3123456789abcdef0123456789abcdef";
        let directory = ensure_reservation_machine_dir(root.path(), "machine-a", true)
            .expect("create reservation directory")
            .expect("reservation directory exists");
        let target = root.path().join("unrelated-file");
        fs::write(&target, b"not a reservation").expect("write symlink target");
        symlink(
            target,
            pending_reservation_path(root.path(), "machine-a", run_id),
        )
        .expect("create linked pending record");

        assert!(
            has_durable_reservation(root.path(), "machine-a")
                .expect_err("linked active record is rejected")
                .to_string()
                .contains("not a regular file")
        );
        assert!(directory.exists());
    }

    fn assert_new_process_blocked(root: &Path, effect: &str) {
        let output = Command::new(std::env::current_exe().expect("test executable"))
            .arg("--exact")
            .arg("cli::mutable_lease::tests::lease_child_process")
            .arg("--nocapture")
            .env("ONEC_ACCESS_MUTABLE_LEASE_ROOT", root)
            .env("ONEC_ACCESS_MUTABLE_LEASE_MACHINE", "machine-a")
            .env("ONEC_ACCESS_MUTABLE_LEASE_EFFECT", effect)
            .env("ONEC_ACCESS_MUTABLE_LEASE_EXPECT_BUSY", "true")
            .output()
            .expect("spawn new controller process");
        assert!(
            output.status.success(),
            "new controller process was not blocked: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn lease_identity_is_exact_and_private_to_managed_target() {
        let root = tempdir().expect("temporary lease root");
        let directory = root.path().join(LEASE_DIRECTORY);
        assert_ne!(
            lease_path(&directory, "Machine-A"),
            lease_path(&directory, "machine-a")
        );
        assert_ne!(
            lease_path(&directory, "machine-a"),
            lease_path(&directory, " machine-a ")
        );
        assert_ne!(
            lease_path(&directory, "machine-a"),
            lease_path(&directory, "machine-b")
        );
    }

    fn spawn_holder(root: &Path, machine_id: &str, effect: &str) -> Child {
        let mut child = Command::new(std::env::current_exe().expect("test executable"))
            .arg("--exact")
            .arg("cli::mutable_lease::tests::lease_child_process")
            .arg("--nocapture")
            .env("ONEC_ACCESS_MUTABLE_LEASE_ROOT", root)
            .env("ONEC_ACCESS_MUTABLE_LEASE_MACHINE", machine_id)
            .env("ONEC_ACCESS_MUTABLE_LEASE_EFFECT", effect)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("spawn independent lock-holder process");
        let stdout = child.stdout.take().expect("child stdout");
        let mut output = BufReader::new(stdout);
        let mut line = String::new();
        loop {
            line.clear();
            assert_ne!(
                output.read_line(&mut line).expect("read child readiness"),
                0,
                "child exited before acquiring its lease"
            );
            if line.trim() == READY {
                break;
            }
        }
        child.stdout = Some(output.into_inner());
        child
    }

    fn release_holder(child: &mut Child) {
        drop(child.stdin.take());
        assert!(child.wait().expect("wait for lock-holder child").success());
    }
}
