use super::job_runtime::*;
use super::*;
use crate::jobs::{Admission, JobId, JobSpec, JobState, JobStore};
use std::process::{Command, Stdio};

#[test]
#[ignore = "spawned inside a Windows Agent Job Object by timeout_cancels_descendants"]
fn timeout_worker_root_fixture() {
    let root = std::env::current_dir().expect("fixture current directory");
    assert!(root.join(".hostlink-timeout-fixture").is_file());
    let mut child = Command::new(std::env::current_exe().expect("fixture test binary"))
        .args([
            "--ignored",
            "--exact",
            "ssh::windows_durable_job_tests::timeout_worker_descendant_fixture",
            "--nocapture",
        ])
        .current_dir(&root)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn grandchild in the Agent's Windows Job Object");
    let mut marker = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(root.join("descendant.pid"))
        .expect("create descendant readiness marker");
    use std::io::Write as _;
    writeln!(marker, "{}", child.id()).expect("write descendant readiness marker");
    marker
        .sync_all()
        .expect("persist descendant readiness marker");
    // The Job Object owns both processes. Reap the descendant if it exits,
    // rather than leaving an un-waited Child handle in the test fixture.
    child.wait().expect("reap fixture descendant");
}

#[test]
#[ignore = "spawned inside a Windows Agent Job Object by timeout_cancels_descendants"]
fn timeout_worker_descendant_fixture() {
    let root = std::env::current_dir().expect("fixture current directory");
    assert!(root.join(".hostlink-timeout-fixture").is_file());
    loop {
        std::thread::sleep(Duration::from_secs(1));
    }
}

#[tokio::test]
async fn timeout_cancels_descendants_and_records_failure() {
    let temp = tempfile::tempdir().expect("disposable Windows test root");
    private_test_path(temp.path(), true);
    let marker = temp.path().join(".hostlink-timeout-fixture");
    std::fs::write(&marker, b"private Agent worker fixture").unwrap();
    private_test_path(&marker, false);

    let executable = temp.path().join("agent-test.exe");
    std::fs::copy(std::env::current_exe().unwrap(), &executable)
        .expect("stage source-owned test executable");
    private_test_path(&executable, false);
    let source_sha256 = format!(
        "{:x}",
        Sha256::digest(std::fs::read(&executable).expect("read staged executable"))
    );
    let jobs_root = temp.path().join("jobs");
    std::fs::create_dir(&jobs_root).unwrap();
    private_test_path(&jobs_root, true);
    let store = JobStore::open(jobs_root).expect("open private job store");
    let owner = "e".repeat(64);
    let id = JobId::new();
    let spec = JobSpec {
        program: executable.to_string_lossy().into_owned(),
        args: vec![
            "--ignored".into(),
            "--exact".into(),
            "ssh::windows_durable_job_tests::timeout_worker_root_fixture".into(),
            "--nocapture".into(),
        ],
        cwd: Some(temp.path().to_path_buf()),
        source_sha256,
    };
    let Admission::Created(_) = store.admit(id, &owner, &spec).unwrap() else {
        panic!("new test job ID must be created");
    };
    let record = store
        .transition(id, &owner, JobState::Prepared, JobState::Running)
        .unwrap();
    let runtime = Arc::new(JobRuntime {
        store,
        start_lock: Mutex::new(()),
        slots: Arc::new(Semaphore::new(MAX_ACTIVE_JOBS)),
        channel_slots: Arc::new(Semaphore::new(MAX_JOB_CHANNELS)),
        accepting: AtomicBool::new(true),
        shutdown: processkit::CancellationToken::new(),
        active_jobs: std::sync::Mutex::new(HashMap::new()),
    });
    let active = Arc::new(JobCancellation {
        process: runtime.shutdown.child_token(),
        requested: AtomicBool::new(false),
    });
    let worker = tokio::spawn(run_job(
        runtime.clone(),
        owner.clone(),
        record,
        active.clone(),
    ));
    let pid_path = temp.path().join("descendant.pid");
    let readiness = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if pid_path.exists() {
                return Ok(());
            }
            if worker.is_finished() {
                return Err("job worker exited before the descendant became ready");
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    if !matches!(readiness, Ok(Ok(()))) {
        // Give the process tree an explicit cancellation request before waiting for cleanup.
        // This bounds a broken readiness path without detaching a live test worker.
        if !worker.is_finished() {
            active.requested.store(true, Ordering::Release);
            active.process.cancel();
        }
        let cleanup = tokio::time::timeout(Duration::from_secs(10), worker).await;
        let cleanup_status = match cleanup {
            Ok(Ok(())) => "completed".to_owned(),
            Ok(Err(error)) => format!("worker task failed: {error}"),
            Err(_) => "worker cleanup deadline exceeded".to_owned(),
        };
        let state = runtime.store.lookup(id, &owner).unwrap().state;
        let stdout = timeout_fixture_output(&runtime.store, id, JobOutput::Stdout, temp.path());
        let stderr = timeout_fixture_output(&runtime.store, id, JobOutput::Stderr, temp.path());
        panic!(
            "descendant readiness failed ({readiness:?}); cleanup={cleanup_status}; persisted state={state:?}; stdout={stdout}; stderr={stderr}"
        );
    }
    let pid: u32 = std::fs::read_to_string(&pid_path)
        .expect("read descendant readiness marker")
        .trim()
        .parse()
        .expect("valid descendant PID");
    tokio::time::timeout(Duration::from_secs(40), worker)
        .await
        .expect("timed-out Agent worker teardown deadline")
        .unwrap();
    assert_eq!(
        runtime.store.lookup(id, &owner).unwrap().state,
        JobState::Failed,
        "a timed-out durable job cannot be recorded as successful"
    );
    for _ in 0..100 {
        if process_exited(pid) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        process_exited(pid),
        "Windows timeout must terminate the entire Job Object process tree"
    );
}

fn timeout_fixture_output(
    store: &JobStore,
    id: JobId,
    stream: crate::jobs::JobOutput,
    private_root: &Path,
) -> String {
    const MAX_DIAGNOSTIC_BYTES: usize = 4096;
    let path = store.output_path(id, stream);
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(error) => return format!("<unavailable: {error}>"),
    };
    let mut bytes = Vec::with_capacity(MAX_DIAGNOSTIC_BYTES + 1);
    use std::io::Read as _;
    if let Err(error) = file
        .take((MAX_DIAGNOSTIC_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
    {
        return format!("<unavailable: {error}>");
    }
    let truncated = bytes.len() > MAX_DIAGNOSTIC_BYTES;
    let bytes = &bytes[..bytes.len().min(MAX_DIAGNOSTIC_BYTES)];
    let text = String::from_utf8_lossy(bytes);
    let redacted = text.replace(
        &private_root.to_string_lossy().to_string(),
        "<private-temp>",
    );
    if truncated {
        format!("{redacted}<truncated>")
    } else {
        redacted
    }
}

fn private_test_path(path: &Path, directory: bool) {
    use windows_permissions::constants::{SeObjectType, SecurityInformation};
    use windows_permissions::wrappers::{ConvertSidToStringSid, SetNamedSecurityInfo};
    use windows_permissions::{LocalBox, SecurityDescriptor};
    let sid = windows_permissions::utilities::current_process_sid().unwrap();
    let sid = ConvertSidToStringSid(&sid).unwrap();
    let flags = if directory { "OICI" } else { "" };
    let sddl = format!("D:P(A;{flags};FA;;;{})", sid.to_string_lossy());
    let descriptor: LocalBox<SecurityDescriptor> = sddl.parse().unwrap();
    SetNamedSecurityInfo(
        path.as_os_str(),
        SeObjectType::SE_FILE_OBJECT,
        SecurityInformation::Owner | SecurityInformation::Dacl | SecurityInformation::ProtectedDacl,
        Some(
            windows_permissions::utilities::current_process_sid()
                .unwrap()
                .as_ref(),
        ),
        None,
        Some(descriptor.dacl().unwrap()),
        None,
    )
    .expect("apply protected current-user-only fixture ACL");
}

fn process_exited(pid: u32) -> bool {
    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_INVALID_PARAMETER, GetLastError, WAIT_OBJECT_0,
    };
    use windows_sys::Win32::System::Threading::{
        OpenProcess, PROCESS_SYNCHRONIZE, WaitForSingleObject,
    };
    // SAFETY: PID came from the fixture's child process.
    let process = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, pid) };
    if process.is_null() {
        // SAFETY: GetLastError reads this thread's status from the failed OpenProcess call.
        return unsafe { GetLastError() } == ERROR_INVALID_PARAMETER;
    }
    // SAFETY: process is an owned handle returned by OpenProcess.
    let exited = unsafe { WaitForSingleObject(process, 0) } == WAIT_OBJECT_0;
    // SAFETY: close the owned handle exactly once.
    unsafe { CloseHandle(process) };
    exited
}
