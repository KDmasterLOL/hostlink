use super::*;

impl JobStore {
    /// Cancel an authenticated task only while it remains pending or queued.
    ///
    /// # Errors
    /// Rejects foreign owners, stale state and SQLite failures.
    pub async fn cancel_pending(&self, id: JobId, owner: &str) -> io::Result<JobView> {
        let record = self.lookup(id, owner).await?;
        let changed = sqlx::query("UPDATE Jobs SET status='Killed',last_result=?,done_at=CAST(strftime('%s','now') AS INTEGER),lock_by=NULL,lock_at=NULL WHERE id=? AND job_type=? AND job=? AND status IN ('Pending','Queued')")
            .bind(r#"{"Err":"cancelled before execution"}"#)
            .bind(id.to_string())
            .bind(database::QUEUE)
            .bind(serde_json::to_vec(&record.job).map_err(io::Error::other)?)
            .execute(&self.pool).await.map_err(io::Error::other)?;
        if changed.rows_affected() != 1 {
            return Err(invalid("job is no longer pending"));
        }
        database::secure_sidecars(&self.root)?;
        self.lookup(id, owner).await
    }
}
