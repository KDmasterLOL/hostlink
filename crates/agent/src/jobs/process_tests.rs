use super::*;
use crate::jobs::{self, JobId, JobOutput, JobSpec, JobState, JobStore};
use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;
use tokio::sync::{Mutex, Semaphore};

#[path = "../../tests/support/containment.rs"]
mod containment;
#[path = "containment_mode_tests.rs"]
mod containment_mode_tests;

pub(super) async fn prepared_job(
    args: Vec<String>,
    cwd: &Path,
) -> (
    tempfile::TempDir,
    Arc<JobRuntime>,
    String,
    crate::jobs::JobView,
) {
    let temp = tempfile::tempdir().expect("private test root");
    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700))
        .expect("private root mode");
    let jobs_root = temp.path().join("jobs");
    std::fs::create_dir(&jobs_root).expect("create job store root");
    std::fs::set_permissions(&jobs_root, std::fs::Permissions::from_mode(0o700))
        .expect("private job store mode");
    let store = JobStore::initialize_fresh(jobs_root)
        .await
        .expect("open private store");
    let owner = "d".repeat(64);
    let artifacts = store.artifacts(&owner).unwrap();
    let bytes = std::fs::read(std::fs::canonicalize("/bin/sh").unwrap()).unwrap();
    let digest = format!("{:x}", Sha256::digest(&bytes));
    let name = format!("{digest}.upload");
    let upload = artifacts.upload_root().join(&name);
    std::fs::write(&upload, &bytes).unwrap();
    restrict_private_path(&upload, false).unwrap();
    let source = artifacts.seal(&name, &digest, bytes.len() as u64).unwrap();
    let spec = JobSpec {
        program: source.display().to_string(),
        args,
        cwd: Some(cwd.to_path_buf()),
        source_sha256: digest,
    };
    let id = JobId::new();
    store.admit(id, &owner, &spec).await.expect("admit job");
    let runner = store.acquire_runner().expect("exclusive runtime lease");
    let runtime = Arc::new(JobRuntime {
        store,
        _runner: runner,
        start_lock: Mutex::new(()),
        slots: Arc::new(Semaphore::new(MAX_ACTIVE_JOBS)),
        channel_slots: Arc::new(Semaphore::new(MAX_JOB_CHANNELS)),
        accepting: AtomicBool::new(true),
        shutdown: processkit::CancellationToken::new(),
        active_jobs: std::sync::Mutex::new(HashMap::new()),
        unknown_permits: std::sync::Mutex::new(Vec::new()),
    });
    let record = runtime
        .store
        .lookup(id, &owner)
        .await
        .expect("read admitted record");
    (temp, runtime, owner, record)
}

// Native positives remain runnable on delegated-cgroup hosts. This probes the
// actual backend exactly as production does, without weakening the launch gate.
pub(crate) fn native_containment_available() -> bool {
    containment::supported()
}

pub(crate) fn linux_process_is_running(pid: u32) -> bool {
    let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
        return false;
    };
    let Some((_, fields)) = stat.rsplit_once(')') else {
        return false;
    };
    !fields.trim_start().starts_with("Z ")
}

#[tokio::test]
async fn agent_shutdown_cancels_the_owned_process_tree() {
    if !native_containment_available() {
        return;
    }
    assert_eq!(
        processkit::Command::kill_on_parent_death_scope(),
        processkit::ParentDeathCleanup::DirectChildOnly,
        "Linux abrupt parent death is documented as direct-child-only"
    );
    let temp = tempfile::tempdir().expect("working directory");
    let pid_path = temp.path().join("descendant-pid");
    let script = format!("sleep 300 & echo $! > '{}'; wait", pid_path.display());
    let (temp_root, runtime, owner, record) =
        prepared_job(vec!["-c".into(), script], temp.path()).await;
    let active = runtime.shutdown.child_token();
    let worker = tokio::spawn(run_job(
        runtime.clone(),
        owner.clone(),
        record,
        active,
        Arc::new(AtomicBool::new(false)),
    ));
    tokio::time::timeout(Duration::from_secs(5), async {
        while !pid_path.exists() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("descendant pid file appears");
    let pid: u32 = std::fs::read_to_string(&pid_path)
        .expect("read descendant pid")
        .trim()
        .parse()
        .expect("valid descendant pid");

    runtime.shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(5), worker)
        .await
        .expect("worker teardown deadline")
        .expect("worker task")
        .expect_err("cancelled job must fail");
    for _ in 0..100 {
        if !linux_process_is_running(pid) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        !linux_process_is_running(pid),
        "owned descendant was reaped"
    );
    drop(temp_root);
}

#[tokio::test]
async fn output_overflow_kills_the_tree_and_never_records_zero_exit() {
    if !native_containment_available() {
        return;
    }
    let temp = tempfile::tempdir().expect("working directory");
    let (temp_root, runtime, owner, record) = prepared_job(
        vec!["-c".into(), "head -c 8388609 /dev/zero".into()],
        temp.path(),
    )
    .await;
    let id = record.id;
    tokio::time::timeout(
        Duration::from_secs(10),
        run_job(
            runtime.clone(),
            owner.clone(),
            record,
            runtime.shutdown.child_token(),
            Arc::new(AtomicBool::new(false)),
        ),
    )
    .await
    .expect("overflow teardown deadline")
    .expect_err("cancelled job must fail");
    assert_eq!(
        std::fs::metadata(runtime.store.output_path(id, JobOutput::Stdout))
            .expect("bounded stdout file")
            .len(),
        jobs::MAX_JOB_OUTPUT_BYTES
    );
    assert!(
        !matches!(
            runtime
                .store
                .lookup(id, &owner)
                .await
                .expect("read status")
                .state,
            JobState::Exited { code: 0 }
        ),
        "an over-limit stream cannot be reported as successful"
    );
    drop(temp_root);
}
