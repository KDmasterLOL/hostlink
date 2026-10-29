use super::*;
use tokio::io::AsyncWriteExt;

#[tokio::test]
async fn repeated_output_appends_with_one_shared_size_limit() {
    let root = tempfile::tempdir().unwrap();
    restrict_private_path(root.path(), true).unwrap();
    let path = root.path().join("stdout.bin");
    let file = open_output_append(&path).unwrap();
    file.set_len(MAX_JOB_OUTPUT_BYTES - 2).unwrap();
    drop(file);
    let file = open_output_append(&path).unwrap();
    let initial = file.metadata().unwrap().len();
    let cancel = processkit::CancellationToken::new();
    let ended = Arc::new(AtomicBool::new(false));
    let mut writer = CappedOutputWriter::new(
        tokio::fs::File::from_std(file),
        initial,
        cancel.clone(),
        ended.clone(),
    );
    writer.write_all(b"abcd").await.unwrap();
    writer.flush().await.unwrap();
    assert!(cancel.is_cancelled());
    assert!(ended.load(Ordering::Acquire));
    assert_eq!(fs::metadata(&path).unwrap().len(), MAX_JOB_OUTPUT_BYTES);
    let mut file = File::open(&path).unwrap();
    use std::io::{Read, Seek};
    file.seek(io::SeekFrom::End(-2)).unwrap();
    let mut tail = [0; 2];
    file.read_exact(&mut tail).unwrap();
    assert_eq!(&tail, b"ab");
}

#[tokio::test]
async fn stalled_process_reap_is_bounded_and_never_reports_completion() {
    // No child is spawned. This exercises the actual ProcessKit group stop
    // with a pending reap future, so a lost OS wait cannot hang an Agent worker.
    let group = processkit::ProcessGroup::new().unwrap();
    let error = stop_and_drain(
        &group,
        std::future::pending::<processkit::Result<processkit::Outcome>>(),
        Duration::from_millis(50),
    )
    .await
    .expect_err("a stalled reap must remain UNKNOWN");
    assert!(matches!(error.reason(), processkit::ErrorReason::Io(_)));
    assert!(error.to_string().contains("unconfirmed"));
}

#[test]
fn containment_policy_never_trusts_posix_fallback() {
    assert!(!trusted_mechanism(processkit::Mechanism::ProcessGroup));
    assert!(trusted_mechanism(processkit::Mechanism::CgroupV2));
    assert!(!trusted_mechanism(processkit::Mechanism::JobObject));
    assert!(!trusted_mechanism(processkit::Mechanism::ProcessReaper));
}

#[tokio::test]
async fn pump_marker_requires_successful_flush_and_resets_on_further_write() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("raw");
    let file = tokio::fs::File::create(&path).await.unwrap();
    let ended = Arc::new(AtomicBool::new(false));
    let mut writer =
        CappedOutputWriter::new(file, 0, processkit::CancellationToken::new(), ended.clone());
    writer.write_all(b"prefix").await.unwrap();
    assert!(!ended.load(Ordering::Acquire));
    writer.flush().await.unwrap();
    assert!(ended.load(Ordering::Acquire));
    writer.write_all(b"tail").await.unwrap();
    assert!(!ended.load(Ordering::Acquire));
    writer.flush().await.unwrap();
    assert!(ended.load(Ordering::Acquire));
    assert_eq!(fs::read(path).unwrap(), b"prefixtail");
}
