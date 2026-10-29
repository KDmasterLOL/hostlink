use super::*;
use sqlx::{Row, sqlite::SqliteRow};

// Bounded owner-aware snapshot of the native task and result.
pub(super) const ROWS: &str = "SELECT CASE WHEN length(j.id)<=26 THEN j.id END AS id,
 CASE WHEN length(j.idempotency_key)<=26 THEN j.idempotency_key END AS idempotency_key,
 CASE WHEN length(j.job_type)<=32 THEN j.job_type END AS job_type,
 j.max_attempts,CASE WHEN length(j.status)<=16 THEN j.status END AS status,j.attempts,
 CASE WHEN length(CAST(j.job AS BLOB))<=65536 THEN j.job END AS payload,
 CASE WHEN length(CAST(j.last_result AS BLOB))<=1024 THEN j.last_result END AS result,
 length(CAST(j.last_result AS BLOB)) AS result_len FROM Jobs j";

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
    let result = result
        .as_deref()
        .map(serde_json::from_str::<Result<i32, String>>)
        .transpose()
        .map_err(io::Error::other)?;
    let attempts: i64 = row.try_get("attempts").map_err(io::Error::other)?;
    if attempts < 0 {
        return Err(invalid("invalid native attempt count"));
    }
    let state = match (get("status")?.as_str(), &result) {
        ("Pending" | "Queued", _) => JobState::Prepared,
        ("Running", _) => JobState::Running,
        ("Done", Some(Ok(code))) => JobState::Exited { code: *code },
        ("Failed", Some(Err(_))) => JobState::Failed,
        // Native cancellation of a never-executed task is terminal. Killed
        // after at least one attempt instead means the outcome is uncertain.
        ("Killed", Some(Err(_))) if attempts == 0 => JobState::Failed,
        ("Killed", Some(Err(_))) => JobState::Interrupted,
        _ => return Err(invalid("inconsistent native Apalis status/result")),
    };
    Ok(JobView {
        job,
        state,
        started: attempts > 0,
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
