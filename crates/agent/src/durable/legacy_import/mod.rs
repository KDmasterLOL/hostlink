//! Explicit snapshot-only preparation. There is deliberately no publication path.
//!
//! The 4570a45 Agent has no lifetime runner lease. Its process/output writers
//! survive update.lock and state.lock acquisition. These locks cannot establish
//! offline ownership or fence rollback, so this implementation cannot cut over.

use super::*;

mod snapshot;
mod staging;
#[cfg(test)]
mod tests;

use snapshot::{Snapshot, lock_existing, private_directory};

const QUARANTINE_VERSION: i64 = -1075;
const JOURNAL: &str = "import.json";
const LEGACY_SOURCE: &str = "4570a45c5ba53f5440a8265906393cbcf629c033";
const BLOCKER: &str = "publication blocked: legacy Agent 4570a45 has no lifetime runner lease; update/state locks cannot prove process/output quiescence or fence old-Agent rollback. Preserve the original install and snapshot. This quarantined stage MUST NOT replace jobs_root; a separately verified offline cutover and rollback fence are required";

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    format: u32,
    legacy_source: String,
    snapshot_sha256: String,
    records: usize,
    publication: String,
    blocker: String,
}

/// Verify a private legacy jobs snapshot and prepare a quarantined Apalis stage.
///
/// `root` is an absolute path to a separately copied legacy jobs directory;
/// `stage` is an absolute, separate destination with an existing private parent.
/// No source file is created, changed, renamed or deleted. Existing source locks
/// are acquired without waiting, but do **not** prove the old Agent is stopped.
/// This never calls service management, executes a job, or publishes a backend.
///
/// # Errors
/// Always returns an error: even a fully verified stage reports Unsupported with
/// the publication blocker. Invalid/unsafe snapshots and contended locks fail
/// before staging; detected source drift leaves a quarantined partial stage.
/// Interrupted stages are preserved and rejected;
/// completed retries reverify everything without adding tasks or rewriting data.
pub async fn stage_legacy_snapshot(root: &Path, stage: &Path) -> io::Result<()> {
    private_directory(root)?;
    let source_parent = root
        .parent()
        .ok_or_else(|| invalid("snapshot has no parent"))?;
    private_directory(source_parent)?;
    let stage_parent = stage
        .parent()
        .ok_or_else(|| invalid("stage has no parent"))?;
    private_directory(stage_parent)?;
    let canonical_root = root.canonicalize()?;
    let canonical_stage = stage_parent.canonicalize()?.join(
        stage
            .file_name()
            .ok_or_else(|| invalid("stage has no filename"))?,
    );
    if !stage.is_absolute()
        || stage.file_name().is_none()
        || stage
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
        || canonical_stage.starts_with(&canonical_root)
        || canonical_root.starts_with(&canonical_stage)
        || stage == source_parent
    {
        return Err(invalid("stage must be separate from the legacy snapshot"));
    }
    // Never create/harden source locks. A full install-parent snapshot must
    // include update.lock; absence cannot establish even admission exclusion.
    let _update = lock_existing(&source_parent.join(UPDATE_LOCK_FILE))?;
    let mut locks = Vec::new();
    for (scanned, entry) in fs::read_dir(root)?.enumerate() {
        let entry = entry?;
        if scanned >= MAX_JOBS {
            return Err(invalid("too many legacy locks"));
        }
        // A new Agent root is never accepted as a legacy snapshot. Probe the
        // runner first so contention is explicit, without creating a lease.
        if entry.file_name() == "runner.lock" {
            let _runner = lock_existing(&entry.path())?;
            return Err(invalid("runner.lock identifies a non-legacy jobs root"));
        }
        validate_private_path(&entry.path(), true)?;
        let path = entry.path().join("state.lock");
        match fs::symlink_metadata(&path) {
            Ok(_) => locks.push(lock_existing(&path)?),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }
    let snapshot = Snapshot::read(root)?;
    let expected = Journal {
        format: 1,
        legacy_source: LEGACY_SOURCE.into(),
        snapshot_sha256: snapshot.digest()?,
        records: snapshot.records.len(),
        publication: "blocked".into(),
        blocker: BLOCKER.into(),
    };
    match fs::symlink_metadata(stage) {
        Ok(_) => {
            private_directory(stage)?;
            let _lease = lock_existing(&stage.join("stage.lock"))?;
            validate_stage_entries(stage)?;
            let journal: Journal = serde_json::from_slice(&snapshot::read_file(
                &stage.join(JOURNAL),
                MAX_RECORD_BYTES as u64,
            )?)
            .map_err(|_| invalid("stage journal is invalid; preserve it for reconciliation"))?;
            if journal != expected {
                return Err(invalid(
                    "stage belongs to a different snapshot; preserve both",
                ));
            }
            if snapshot::read_file(&stage.join("verified"), 64)?
                != expected.snapshot_sha256.as_bytes()
            {
                return Err(invalid(
                    "stage verification incomplete; preserve it and use a separate new stage",
                ));
            }
            staging::verify(stage, &snapshot).await?;
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            // Atomic directory reservation prevents competing staging writers.
            fs::create_dir(stage)?;
            restrict_private_path(stage, true)?;
            sync_directory(stage_parent)?;
            snapshot::write_file(&stage.join("stage.lock"), b"")?;
            let _lease = lock_existing(&stage.join("stage.lock"))?;
            snapshot::write_file(
                &stage.join(JOURNAL),
                &serde_json::to_vec(&expected).map_err(io::Error::other)?,
            )?;
            staging::build(stage, root, &snapshot).await?;
            staging::verify(stage, &snapshot).await?;
            // Full second source inventory, not just a record-count check.
            if Snapshot::read(root)? != snapshot {
                return Err(invalid(
                    "source changed during staging; preserve stage and snapshot",
                ));
            }
            snapshot::write_file(&stage.join("verified"), expected.snapshot_sha256.as_bytes())?;
        }
        Err(e) => return Err(e),
    }
    if Snapshot::read(root)? != snapshot {
        return Err(invalid(
            "source changed during verification; stage remains quarantined",
        ));
    }
    // A lost CLI acknowledgement is repeat-safe: verify the existing stage,
    // never silently rebuild or promote it. No success-like import result.
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        format!(
            "verified snapshot stage at {} ({} jobs); {BLOCKER}",
            stage.display(),
            snapshot.records.len()
        ),
    ))
}

fn validate_stage_entries(stage: &Path) -> io::Result<()> {
    let mut count = 0;
    for entry in fs::read_dir(stage)? {
        let entry = entry?;
        count += 1;
        if count > 5
            || !matches!(
                entry.file_name().to_str(),
                Some("stage.lock" | JOURNAL | "built" | "verified" | "store")
            )
        {
            return Err(invalid("unknown stage entry; preserve for reconciliation"));
        }
        validate_private_path(&entry.path(), entry.file_name() == "store")?;
    }
    Ok(())
}
