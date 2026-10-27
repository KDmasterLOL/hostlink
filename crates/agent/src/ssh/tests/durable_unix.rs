use super::job_runtime::*;
use super::{MAX_ACTIVE_JOBS, MAX_JOB_CHANNELS};
use crate::jobs::{self, Admission, JobId, JobOutput, JobSpec, JobState, JobStore};
use sha2::{Digest as _, Sha256};
use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;
use tokio::sync::{Mutex, Semaphore};

async fn prepared_job(
    args: Vec<String>,
    cwd: &Path,
) -> (
    tempfile::TempDir,
    Arc<JobRuntime>,
    String,
    crate::jobs::JobRecord,
) {
    let temp = tempfile::tempdir().expect("private test root");
    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700))
        .expect("private root mode");
    let jobs_root = temp.path().join("jobs");
    std::fs::create_dir(&jobs_root).expect("create job store root");
    std::fs::set_permissions(&jobs_root, std::fs::Permissions::from_mode(0o700))
        .expect("private job store mode");
    let source = temp.path().join("pinned-sh");
    std::fs::copy(
        std::fs::canonicalize("/bin/sh").expect("resolve shell"),
        &source,
    )
    .expect("stage executable");
    std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o500))
        .expect("make executable read-only");
    let spec = JobSpec {
        program: source.display().to_string(),
        args,
        cwd: Some(cwd.to_path_buf()),
        source_sha256: format!(
            "{:x}",
            Sha256::digest(std::fs::read(&source).expect("hash executable"))
        ),
    };
    let store = JobStore::open(jobs_root).expect("open private store");
    let id = JobId::new();
    let owner = "d".repeat(64);
    let Admission::Created(_) = store.admit(id, &owner, &spec).expect("admit job") else {
        panic!("fresh job ID is newly admitted");
    };
    let record = store
        .transition(id, &owner, JobState::Prepared, JobState::Running)
        .expect("reserve worker state");
    let runtime = Arc::new(JobRuntime {
        store,
        start_lock: Mutex::new(()),
        slots: Arc::new(Semaphore::new(MAX_ACTIVE_JOBS)),
        channel_slots: Arc::new(Semaphore::new(MAX_JOB_CHANNELS)),
        accepting: AtomicBool::new(true),
        shutdown: processkit::CancellationToken::new(),
        active_jobs: std::sync::Mutex::new(HashMap::new()),
    });
    let _ = record;
    let record = runtime
        .store
        .lookup(id, &owner)
        .expect("read admitted record");
    (temp, runtime, owner, record)
}

fn linux_process_is_running(pid: u32) -> bool {
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
    let id = record.id;
    let active = Arc::new(JobCancellation {
        process: runtime.shutdown.child_token(),
        requested: AtomicBool::new(false),
    });
    let worker = tokio::spawn(run_job(runtime.clone(), owner.clone(), record, active));
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
        .expect("worker task");
    assert_eq!(
        runtime
            .store
            .lookup(id, &owner)
            .expect("read final state")
            .state,
        JobState::Interrupted
    );
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
            Arc::new(JobCancellation {
                process: runtime.shutdown.child_token(),
                requested: AtomicBool::new(false),
            }),
        ),
    )
    .await
    .expect("overflow teardown deadline");
    assert_eq!(
        runtime
            .store
            .lookup(id, &owner)
            .expect("read final state")
            .state,
        JobState::Failed
    );
    assert_eq!(
        std::fs::metadata(runtime.store.output_path(id, JobOutput::Stdout))
            .expect("bounded stdout file")
            .len(),
        jobs::MAX_JOB_OUTPUT_BYTES
    );
    assert!(
        !matches!(
            runtime.store.lookup(id, &owner).expect("read status").state,
            JobState::Exited { code: 0 }
        ),
        "an over-limit stream cannot be reported as successful"
    );
    drop(temp_root);
}
