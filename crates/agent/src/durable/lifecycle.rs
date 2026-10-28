use super::*;
use super::{
    database::{secure_sidecars, update_lock},
    persistence::{authenticate, queue_status, read_record},
};

impl DurableStore {
    /// Irreversibly reserve one OS process attempt for this immutable task.
    ///
    /// The claim and Apalis Running payload commit in one transaction BEFORE
    /// processkit may launch. An uncertain commit is an error, never permission
    /// to spawn. Apalis orphan requeue cannot erase this claim.
    ///
    /// # Errors
    /// Rejects foreign owners, stale/non-Prepared state, prior claims, corruption,
    /// future eligibility, or any uncertain SQLite commit.
    pub async fn claim_start(&self, id: JobId, owner: &str) -> io::Result<JobRecord> {
        self.claim(id, owner, None).await
    }

    // Only an actual WorkerBuilder dequeue may use this entrypoint. Bind the
    // fetched snapshot and both Apalis identities to the same atomic claim.
    pub(crate) async fn claim_dequeued(
        &self,
        snapshot: &JobRecord,
        task_id: &str,
        worker: &str,
    ) -> io::Result<JobRecord> {
        self.claim(
            snapshot.id,
            &snapshot.controller_key_sha256,
            Some((snapshot, task_id, worker)),
        )
        .await
    }

    async fn claim(
        &self,
        id: JobId,
        owner: &str,
        dequeued: Option<(&JobRecord, &str, &str)>,
    ) -> io::Result<JobRecord> {
        validate_digest(owner)?;
        let _lock = update_lock(&self.root).await?;
        database::inspect_layout(&self.root)?;
        let mut tx = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(io::Error::other)?;
        let (mut record, task_id) = read_record(&mut tx, id, false).await?;
        authenticate(&record, owner)?;
        if record.state != JobState::Prepared {
            return Err(invalid("job has already been claimed or is not eligible"));
        }
        let (status, worker) = if let Some((snapshot, expected_id, worker)) = dequeued {
            if *snapshot != record || expected_id != task_id {
                return Err(invalid(
                    "dequeued task identity/payload changed before claim",
                ));
            }
            ("Queued", Some(worker))
        } else {
            ("Pending", None)
        };
        let due: bool = sqlx::query_scalar("SELECT run_at <= CAST(strftime('%s','now') AS INTEGER) AND attempts=0 AND status=? AND lock_by IS ? AND (? IS NULL OR lock_at IS NOT NULL) FROM Jobs WHERE id=?")
            .bind(status).bind(worker).bind(worker).bind(&task_id)
            .fetch_one(&mut *tx).await.map_err(io::Error::other)?;
        if !due {
            return Err(invalid("Apalis task is not eligible for its one-use claim"));
        }
        sqlx::query(
            "INSERT INTO StartedClaims(job_id,task_id,owner,request_sha256) VALUES(?,?,?,?)",
        )
        .bind(id.to_string())
        .bind(&task_id)
        .bind(owner)
        .bind(&record.request_sha256)
        .execute(&mut *tx)
        .await
        .map_err(io::Error::other)?;
        record.state = JobState::Running;
        write_state(&mut tx, &task_id, &record).await?;
        tx.commit().await.map_err(io::Error::other)?;
        secure_sidecars(&self.root)?;
        Ok(record)
    }

    /// Persist a permitted state change. Only an atomic one-use claim enters Running.
    ///
    /// # Errors
    /// Rejects wrong owner, stale/terminal transitions, corruption and commit errors.
    pub async fn transition(
        &self,
        id: JobId,
        owner: &str,
        expected: JobState,
        next: JobState,
    ) -> io::Result<JobRecord> {
        validate_digest(owner)?;
        if next == JobState::Running || !expected.can_transition_to(next) {
            return Err(invalid("invalid durable job state transition"));
        }
        let mut tx = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(io::Error::other)?;
        let (mut record, task_id) = read_record(&mut tx, id, false).await?;
        authenticate(&record, owner)?;
        if record.state != expected {
            return Err(invalid("stale durable job state transition"));
        }
        record.state = next;
        write_state(&mut tx, &task_id, &record).await?;
        tx.commit().await.map_err(io::Error::other)?;
        secure_sidecars(&self.root)?;
        Ok(record)
    }

    /// Mark previous Prepared/Running attempts UNKNOWN without executing them.
    /// Caller must hold acquire_runner for the complete serving lifetime.
    /// Also seals historical retryable Failed rows and expires the previous
    /// named worker heartbeat, permitting immediate safe re-registration.
    ///
    /// # Errors
    /// Rejects corrupt/unknown persisted state or uncertain SQLite commits.
    pub async fn recover_nonterminal(&self) -> io::Result<()> {
        // Called only after the Agent holds the exclusive runner lease.
        // Admission/start still require update.lock; recovery must be able to
        // run during the registered updater's fenced replacement health check.
        // If an active job was visible, the updater already deferred.
        let records = self.inventory_inner(true).await?;
        let mut tx = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(io::Error::other)?;
        for record in records {
            if matches!(record.state, JobState::Prepared | JobState::Running) {
                let (mut current, task_id) = read_record(&mut tx, record.id, true).await?;
                if current != record {
                    return Err(invalid("job changed during restart recovery"));
                }
                current.state = JobState::Interrupted;
                write_state(&mut tx, &task_id, &current).await?;
            } else if record.state == JobState::Failed {
                // Production storage-only Agents could publish a pre-launch
                // Failed with attempts=0. Seal it against Apalis Failed polling.
                let (_, task_id) = read_record(&mut tx, record.id, false).await?;
                sqlx::query(
                    "UPDATE Jobs SET attempts=1 WHERE id=? AND status='Failed' AND attempts=0",
                )
                .bind(task_id)
                .execute(&mut *tx)
                .await
                .map_err(io::Error::other)?;
            }
        }
        // The exclusive runner lease proves the old Agent is gone. Reuse one
        // bounded worker row without waiting for its heartbeat timeout; all
        // previous nonterminal jobs are already Interrupted in this transaction.
        sqlx::query("UPDATE Workers SET last_seen=0 WHERE id=? AND worker_type=?")
            .bind(WORKER_NAME)
            .bind(database::QUEUE)
            .execute(&mut *tx)
            .await
            .map_err(io::Error::other)?;
        tx.commit().await.map_err(io::Error::other)?;
        secure_sidecars(&self.root)?;
        Ok(())
    }
}

async fn write_state(
    conn: &mut sqlx::SqliteConnection,
    task_id: &str,
    record: &JobRecord,
) -> io::Result<()> {
    let bytes = serde_json::to_vec(record).map_err(io::Error::other)?;
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(invalid("durable record exceeds limit"));
    }
    let result = sqlx::query("UPDATE Jobs SET job=?,status=?,attempts=CASE WHEN ?!='Pending' THEN MAX(attempts,1) ELSE attempts END,done_at=CASE WHEN ? IN ('Done','Failed','Killed') THEN CAST(strftime('%s','now') AS INTEGER) ELSE NULL END WHERE id=?")
        .bind(bytes).bind(queue_status(record.state)).bind(queue_status(record.state))
        .bind(queue_status(record.state)).bind(task_id).execute(conn).await.map_err(io::Error::other)?;
    if result.rows_affected() != 1 {
        return Err(invalid("lost durable state transition"));
    }
    Ok(())
}
