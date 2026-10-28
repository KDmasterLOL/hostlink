use super::*;
use sqlx::{Row, sqlite::SqliteRow};

// Exact results written by pinned Apalis reenqueue_orphaned/abandoned.sql.
// These consume native bookkeeping attempts, never HostLink's process claim.
pub(super) const REQUEUED_RESULTS: [&str; 2] = [
    r#"{"Err": "Re-enqueued due to worker heartbeat timeout."}"#,
    r#"{"Err": "Re-enqueued due to worker shutdown"}"#,
];

// One SQLite statement/snapshot for payload, native lifecycle/result and fence.
// CASE bounds bytes before they cross the SQLite interface, even on corrupt roots.
pub(super) const ROWS: &str = "SELECT CASE WHEN length(j.id)<=26 THEN j.id END AS id,
 CASE WHEN length(j.idempotency_key)<=26 THEN j.idempotency_key END AS idempotency_key,
 CASE WHEN length(j.job_type)<=32 THEN j.job_type END AS job_type,
 j.max_attempts,CASE WHEN length(j.status)<=16 THEN j.status END AS status,j.attempts,
 CASE WHEN length(CAST(j.job AS BLOB))<=65536 THEN j.job END AS payload,
 CASE WHEN length(CAST(j.last_result AS BLOB))<=1024 THEN j.last_result END AS result,
 length(CAST(j.last_result AS BLOB)) AS result_len,CASE WHEN length(c.task_id)<=26 THEN c.task_id END AS task_id,
 CASE WHEN length(c.owner)=64 THEN c.owner END AS owner,
 CASE WHEN length(c.request_sha256)=64 THEN c.request_sha256 END AS request_sha256
 FROM Jobs j LEFT JOIN StartedClaims c ON c.task_id=j.id";

pub(super) fn decode(row: SqliteRow, owner: Option<&str>) -> io::Result<JobView> {
    let get = |name| row.try_get::<String, _>(name).map_err(io::Error::other);
    let bytes: Vec<u8> = row.try_get("payload").map_err(io::Error::other)?;
    let job: JobPayload = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
    if owner.is_some_and(|owner| owner != job.controller_key_sha256) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "job access denied",
        ));
    }
    let id = JobId::parse(&get("id")?)?;
    if get("idempotency_key")? != id.to_string()
        || get("job_type")? != database::QUEUE
        || row
            .try_get::<i64, _>("max_attempts")
            .map_err(io::Error::other)?
            != 1
    {
        return Err(invalid("unrecognized Apalis task contract"));
    }
    job.validate(id)?;
    let result_len: Option<i64> = row.try_get("result_len").map_err(io::Error::other)?;
    if result_len.is_some_and(|n| n > 1024) {
        return Err(invalid("oversized native result"));
    }
    let result: Option<String> = row.try_get("result").map_err(io::Error::other)?;
    let requeued = result
        .as_deref()
        .is_some_and(|r| REQUEUED_RESULTS.contains(&r));
    let result = result
        .as_deref()
        .map(serde_json::from_str::<Result<i32, String>>)
        .transpose()
        .map_err(io::Error::other)?;
    let claim: Option<String> = row.try_get("task_id").map_err(io::Error::other)?;
    if claim.is_some()
        && (get("owner")? != job.controller_key_sha256
            || get("request_sha256")? != job.request_sha256)
    {
        return Err(invalid("started claim does not match immutable task"));
    }
    let attempts: i64 = row.try_get("attempts").map_err(io::Error::other)?;
    let mut state = match (get("status")?.as_str(), &result) {
        ("Pending" | "Queued", _) => JobState::Prepared,
        ("Running", None) => JobState::Running,
        ("Done", Some(Ok(code))) => JobState::Exited { code: *code },
        ("Failed", Some(Err(_))) => JobState::Failed,
        ("Killed", Some(Err(_))) => JobState::Interrupted,
        _ => return Err(invalid("inconsistent native Apalis status/result")),
    };
    if state == JobState::Prepared {
        if claim.is_some() || !((attempts == 0 && result.is_none()) || (attempts > 0 && requeued)) {
            state = JobState::Interrupted;
        }
    } else if attempts != 1 {
        return Err(invalid("native attempts would permit an unsafe retry"));
    }
    if matches!(state, JobState::Running | JobState::Exited { .. }) && claim.is_none() {
        return Err(invalid("native status lacks its one-use start claim"));
    }
    Ok(JobView {
        job,
        state,
        started: claim.is_some(),
    })
}

/// Bounded read-only operator projection of native Apalis state.
#[derive(Debug, Serialize)]
pub struct JobSummary {
    pub id: JobId,
    pub state: JobState,
}

impl JobStore {
    pub(super) async fn find(&self, id: JobId, owner: &str) -> io::Result<Option<JobView>> {
        validate_digest(owner)?;
        let row = sqlx::query(sqlx::AssertSqlSafe(format!("{ROWS} WHERE j.id=?")))
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(io::Error::other)?;
        row.map(|row| decode(row, Some(owner))).transpose()
    }

    /// One bounded owner-aware SELECT; ListTasks has neither owner filtering nor all-status defaults.
    /// # Errors
    /// Rejects invalid filters, corrupt owned rows and database errors.
    pub async fn list(
        &self,
        owner: &str,
        page: u32,
        status: Option<&str>,
    ) -> io::Result<Vec<JobSummary>> {
        validate_digest(owner)?;
        if !(1..=128).contains(&page)
            || status.is_some_and(|s| {
                !["Pending", "Queued", "Running", "Done", "Failed", "Killed"].contains(&s)
            })
        {
            return Err(invalid("invalid jobs list filter"));
        }
        let rows = sqlx::query(sqlx::AssertSqlSafe(format!("{ROWS} WHERE CASE WHEN length(CAST(j.job AS BLOB))<=65536 THEN CASE WHEN json_valid(j.job) THEN json_extract(j.job,'$.controller_key_sha256') END END=? AND (? IS NULL OR j.status=?) ORDER BY j.id LIMIT 32 OFFSET ?")))
            .bind(owner).bind(status).bind(status).bind(i64::from(page-1)*32)
            .fetch_all(&self.pool).await.map_err(io::Error::other)?;
        rows.into_iter()
            .map(|row| {
                decode(row, Some(owner)).map(|r| JobSummary {
                    id: r.id,
                    state: r.state,
                })
            })
            .collect()
    }
}
