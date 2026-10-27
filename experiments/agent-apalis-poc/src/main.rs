use hostlink_apalis_poc::{Admission, ApalisJobStore, JobRecord, JobSpec};
use uuid::Uuid;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let dir = tempfile::tempdir()?;
    let mut store = ApalisJobStore::open(&dir.path().join("jobs.db")).await?;
    let record = JobRecord::new(
        Uuid::new_v4(),
        &"b".repeat(64),
        JobSpec {
            program: "example-nonexecuted-command".into(),
            args: vec!["--version".into()],
            source_sha256: "a".repeat(64),
        },
    )?;
    assert_eq!(store.admit(&record).await?, Admission::Created);
    assert_eq!(store.admit(&record).await?, Admission::Existing);
    println!(
        "apalis-sqlite smoke: {} durable jobs, synchronous={}, no command executed",
        store.queue_rows().await?,
        store.durable_mode().await?,
    );
    Ok(())
}
