use super::database::{secure_sidecars, try_update_lock};
use super::*;

impl JobStore {
    /// Only an actual WorkerBuilder dequeue may enter Running. Bind its snapshot,
    /// task ID and worker to one durable claim BEFORE ProcessKit can launch.
    pub(crate) async fn claim_dequeued(
        &self,
        snapshot: &JobPayload,
        task_id: &str,
        worker: &str,
    ) -> io::Result<JobView> {
        snapshot.validate(snapshot.id)?;
        if task_id != snapshot.id.to_string() {
            return Err(invalid("dequeued ID mismatch"));
        }
        let lock = try_update_lock(&self.root)?;
        let result = async {
        database::inspect_layout(&self.root)?;
        let mut tx = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(io::Error::other)?;
        // INSERT SELECT fences the exact worker snapshot and eligibility atomically.
        // The primary key rejects every spent claim, including upstream orphan requeues.
        let claimed = sqlx::query("INSERT INTO StartedClaims(task_id,owner,request_sha256) SELECT id,?,? FROM Jobs WHERE id=? AND job_type=? AND idempotency_key=id AND job=? AND max_attempts=1 AND run_at<=CAST(strftime('%s','now') AS INTEGER) AND ((attempts=0 AND last_result IS NULL) OR (attempts>0 AND COALESCE(last_result IN (?,?),0))) AND status='Queued' AND lock_by=? AND lock_at IS NOT NULL")
            .bind(&snapshot.controller_key_sha256).bind(&snapshot.request_sha256)
            .bind(task_id).bind(database::QUEUE).bind(serde_json::to_vec(snapshot).map_err(io::Error::other)?)
            .bind(super::query::REQUEUED_RESULTS[0]).bind(super::query::REQUEUED_RESULTS[1])
            .bind(worker).execute(&mut *tx).await.map_err(io::Error::other)?;
        if claimed.rows_affected() != 1 {
            return Err(invalid("task is not eligible for its worker claim"));
        }
        sqlx::query("UPDATE Jobs SET status='Running',attempts=1,last_result=NULL WHERE id=?")
            .bind(task_id)
            .execute(&mut *tx)
            .await
            .map_err(io::Error::other)?;
        tx.commit().await.map_err(io::Error::other)?;
        secure_sidecars(&self.root)?;
        Ok(JobView {
            job: snapshot.clone(),
            state: JobState::Running,
            started: true,
        })
        }.await;
        // Explicit unlock before close: a concurrent child fork can briefly
        // inherit the FD until exec, so close alone can retain its flock.
        lock.unlock()?;
        result
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
    ) -> io::Result<JobView> {
        validate_digest(owner)?;
        if !matches!(expected, JobState::Prepared | JobState::Running)
            || !matches!(
                next,
                JobState::Exited { .. } | JobState::Failed | JobState::Interrupted
            )
            || (expected == JobState::Prepared && matches!(next, JobState::Exited { .. }))
        {
            return Err(invalid("invalid durable job state transition"));
        }
        let mut record = self.lookup(id, owner).await?;
        if record.state != expected {
            return Err(invalid("stale job completion"));
        }
        let mut tx = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(io::Error::other)?;
        let (task_id, worker): (String, Option<String>) = sqlx::query_as(
            "SELECT id,lock_by FROM Jobs WHERE job_type=? AND id=? AND job=? AND status IN (?,?)",
        )
        .bind(database::QUEUE)
        .bind(id.to_string())
        .bind(serde_json::to_vec(&record.job).map_err(io::Error::other)?)
        .bind(if expected == JobState::Running {
            "Running"
        } else {
            "Pending"
        })
        .bind(if expected == JobState::Running {
            "Running"
        } else {
            "Queued"
        })
        .fetch_optional(&mut *tx)
        .await
        .map_err(io::Error::other)?
        .ok_or_else(|| invalid("stale native Apalis status"))?;
        record.state = next;
        write_state(&mut tx, &task_id, worker.as_deref(), &record).await?;
        tx.commit().await.map_err(io::Error::other)?;
        secure_sidecars(&self.root)?;
        Ok(record)
    }

    /// Preserve unclaimed work; mark spent/uncertain attempts UNKNOWN without replay.
    /// Caller must hold acquire_runner for the complete serving lifetime.
    /// Expires the named worker heartbeat for immediate safe re-registration.
    ///
    /// # Errors
    /// Rejects corrupt/unknown persisted state or uncertain SQLite commits.
    pub async fn recover_nonterminal(&self) -> io::Result<()> {
        // Called only after the Agent holds the exclusive runner lease.
        // Admission/start still require update.lock; recovery must be able to
        // run during the registered updater's fenced replacement health check.
        // If an active job was visible, the updater already deferred.
        self.inventory().await?;
        let mut tx = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(io::Error::other)?;
        sqlx::query("UPDATE Jobs SET status='Killed',last_result=?,attempts=1,done_at=CAST(strftime('%s','now') AS INTEGER) WHERE status IN ('Pending','Queued','Running') AND (EXISTS(SELECT 1 FROM StartedClaims c WHERE c.task_id=Jobs.id) OR NOT ((attempts=0 AND last_result IS NULL) OR (attempts>0 AND COALESCE(last_result IN (?,?),0))))")
            .bind(serde_json::to_string(&Err::<i32,_>("UNKNOWN: Agent restarted")).map_err(io::Error::other)?)
            .bind(super::query::REQUEUED_RESULTS[0]).bind(super::query::REQUEUED_RESULTS[1])
            .execute(&mut *tx).await.map_err(io::Error::other)?;
        // The exclusive runner lease proves the old Agent is gone. Reuse one
        // bounded worker row without waiting for its heartbeat timeout; all
        // spent/uncertain attempts are Killed. Apalis registration reenqueues
        // pristine Queued work; its exact requeue result is accepted without a claim.
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
    worker: Option<&str>,
    record: &JobView,
) -> io::Result<()> {
    use apalis_core::{
        backend::TaskResult,
        task::{status::Status, task_id::TaskId},
    };
    let (status, result) = match record.state {
        JobState::Exited { code } => (Status::Done, Ok(serde_json::json!(code))),
        JobState::Failed => (
            Status::Failed,
            Err("execution failed or cancelled".to_owned()),
        ),
        JobState::Interrupted => (
            Status::Killed,
            Err("UNKNOWN: reconcile before replacement".to_owned()),
        ),
        _ => return Err(invalid("only terminal results may be published")),
    };
    if let Some(worker) = worker {
        let ack = TaskResult {
            task_id: task_id.parse::<TaskId>().map_err(io::Error::other)?,
            attempt: 1,
            status,
            result,
        };
        if apalis_sqlite::queries::ack_tasks(&mut *conn, &[&ack], worker)
            .await
            .map_err(io::Error::other)?
            != 1
        {
            return Err(invalid("lost Apalis result publication"));
        }
    } else {
        // Cancellation/restart of work that never reached a worker has no
        // lock_by for upstream ack_tasks. Publish in the same native columns.
        sqlx::query("UPDATE Jobs SET status=?,last_result=?,attempts=1,done_at=CAST(strftime('%s','now') AS INTEGER) WHERE id=?")
            .bind(status.to_string()).bind(serde_json::to_string(&result).map_err(io::Error::other)?)
            .bind(task_id).execute(&mut *conn).await.map_err(io::Error::other)?;
    }
    Ok(())
}
