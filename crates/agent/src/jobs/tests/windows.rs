use super::*;
use std::{
    fs::OpenOptions,
    io::Write,
    os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
    path::Path,
    time::Duration,
};
use windows_sys::Win32::{
    Foundation::{ERROR_ALREADY_EXISTS, GetLastError, WAIT_OBJECT_0, WAIT_TIMEOUT},
    System::Threading::{
        CreateEventW, OpenEventW, OpenProcess, PROCESS_SYNCHRONIZE, SYNCHRONIZATION_SYNCHRONIZE,
        SetEvent, WaitForMultipleObjects, WaitForSingleObject,
    },
};

fn wide(value: &str) -> Vec<u16> {
    std::ffi::OsStr::new(value)
        .encode_wide()
        .chain(Some(0))
        .collect()
}

// The event is independent of the worker's Job Object: it is signalled only
// after the containment assertion, or during unwinding on any test failure.
struct FixtureGuard {
    event: OwnedHandle,
    shutdown: processkit::CancellationToken,
}

impl FixtureGuard {
    fn new(root: &Path, shutdown: processkit::CancellationToken) -> Self {
        let name = format!("Local\\hostlink-test-{}", ulid::Ulid::generate());
        // SAFETY: the name is NUL terminated; null security attributes request defaults.
        let raw = unsafe { CreateEventW(std::ptr::null(), 1, 0, wide(&name).as_ptr()) };
        assert!(
            !raw.is_null(),
            "CreateEventW: {}",
            io::Error::last_os_error()
        );
        // SAFETY: GetLastError reads the calling thread's last error immediately after CreateEventW.
        let already_exists = unsafe { GetLastError() } == ERROR_ALREADY_EXISTS;
        // SAFETY: CreateEventW returned a new owned handle.
        let event = unsafe { OwnedHandle::from_raw_handle(raw) };
        assert!(!already_exists, "fixture event name already exists");
        fs::write(
            root.join("process-tree-fixture"),
            format!("{name}\n{}", std::process::id()),
        )
        .unwrap();
        Self { event, shutdown }
    }

    fn signal(&self) -> io::Result<()> {
        // SAFETY: event is a live owned event handle.
        if unsafe { SetEvent(self.event.as_raw_handle()) } == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

impl Drop for FixtureGuard {
    fn drop(&mut self) {
        self.shutdown.cancel();
        // On failure the test is already failing; both fixtures also watch the
        // test process and have a finite deadline if signalling itself fails.
        let _ = self.signal();
    }
}

fn fixture_handles() -> (OwnedHandle, OwnedHandle) {
    let marker = fs::read_to_string("process-tree-fixture").unwrap();
    let (name, owner) = marker.split_once('\n').unwrap();
    let owner: u32 = owner.parse().unwrap();
    // SAFETY: the event name is NUL terminated and names this test's event.
    let event = unsafe { OpenEventW(SYNCHRONIZATION_SYNCHRONIZE, 0, wide(name).as_ptr()) };
    assert!(
        !event.is_null(),
        "OpenEventW: {}",
        io::Error::last_os_error()
    );
    // SAFETY: OpenEventW returned a new owned handle.
    let event = unsafe { OwnedHandle::from_raw_handle(event) };
    // SAFETY: the PID is the test owner recorded in its private fixture directory.
    let owner = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, owner) };
    assert!(
        !owner.is_null(),
        "OpenProcess owner: {}",
        io::Error::last_os_error()
    );
    // SAFETY: OpenProcess returned a new owned handle.
    let owner = unsafe { OwnedHandle::from_raw_handle(owner) };
    (event, owner)
}

fn fixture_wait(event: &OwnedHandle, owner: &OwnedHandle) {
    let handles = [event.as_raw_handle(), owner.as_raw_handle()];
    // SAFETY: both handles remain live for this bounded wait.
    let result = unsafe { WaitForMultipleObjects(2, handles.as_ptr(), 0, 60_000) };
    assert!(
        result == WAIT_OBJECT_0 || result == WAIT_OBJECT_0 + 1,
        "fixture wait failed or timed out: {result}"
    );
}

fn require_job_object() {
    let group = processkit::ProcessGroup::new().expect("create Windows process group");
    assert_eq!(group.mechanism(), processkit::Mechanism::JobObject);
}

async fn start_board(
    root: &Path,
) -> (
    String,
    processkit::CancellationToken,
    tokio::task::JoinHandle<io::Result<()>>,
) {
    JobStore::initialize_fresh(root)
        .await
        .unwrap()
        .close()
        .await;
    let reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = reservation.local_addr().unwrap();
    drop(reservation);
    let shutdown = processkit::CancellationToken::new();
    let stop = shutdown.clone();
    let jobs = root.to_owned();
    let server = tokio::spawn(async move { serve_until(&jobs, Some(address), stop).await });
    (
        format!("http://{address}/api/v1/queues/commands/tasks"),
        shutdown,
        server,
    )
}

async fn submit(url: &str, job: &CommandJob) {
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap();
    for _ in 0..100 {
        match client
            .put(url)
            .header("x-task-max-attempts", "1")
            .json(job)
            .send()
            .await
        {
            Ok(reply) => {
                assert!(
                    reply.status().is_success(),
                    "Board rejected task: {reply:?}"
                );
                return;
            }
            Err(error) if error.is_connect() => {}
            Err(error) => panic!("Board task submission outcome is uncertain: {error}"),
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("Board HTTP listener did not accept a task");
}

async fn finish(
    shutdown: processkit::CancellationToken,
    server: tokio::task::JoinHandle<io::Result<()>>,
) {
    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(20), server)
        .await
        .expect("worker shutdown timed out")
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn board_executes_windows_command_and_persists_exit_code() {
    require_job_object();
    let (_parent, root) = private_job_root();
    let (url, shutdown, server) = start_board(&root).await;
    submit(
        &url,
        &CommandJob {
            program: std::env::var("ComSpec")
                .expect("ComSpec must identify the Windows command interpreter"),
            args: vec!["/C".into(), "exit /B 7".into()],
            cwd: None,
            timeout_seconds: None,
        },
    )
    .await;
    let store = JobStore::open(&root).await.unwrap();
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let (status, result): (String, Option<String>) =
                sqlx::query_as("SELECT status,last_result FROM Jobs")
                    .fetch_one(&store.pool)
                    .await
                    .unwrap();
            if status == "Done" {
                assert_eq!(result.as_deref(), Some(r#"{"Ok":7}"#));
                break;
            }
            assert!(
                matches!(status.as_str(), "Pending" | "Queued" | "Running"),
                "unexpected task state: {status}, {result:?}"
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("native Windows task did not finish");
    store.close().await;
    finish(shutdown, server).await;
}

// These ignored tests are invoked as separate processes in the private test root.
// create_new makes an unexpected second execution observable instead of overwriting evidence.
fn write_pid(name: &str) {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(name)
        .unwrap();
    writeln!(file, "{}", std::process::id()).unwrap();
}

#[test]
#[ignore]
fn process_tree_parent_fixture() {
    if !Path::new("process-tree-fixture").is_file() {
        return;
    }
    let (event, owner) = fixture_handles();
    write_pid("parent.pid");
    let mut descendant = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "jobs::tests::windows::process_tree_descendant_fixture",
        ])
        .spawn()
        .unwrap();
    fixture_wait(&event, &owner);
    descendant.wait().unwrap();
}

#[test]
#[ignore]
fn process_tree_descendant_fixture() {
    if !Path::new("process-tree-fixture").is_file() {
        return;
    }
    let (event, owner) = fixture_handles();
    write_pid("descendant.pid");
    fixture_wait(&event, &owner);
}

async fn process_handle(path: &Path) -> OwnedHandle {
    let pid = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if let Ok(text) = fs::read_to_string(path)
                && let Ok(pid) = text.trim().parse::<u32>()
            {
                break pid;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("fixture process did not publish its PID");
    // SAFETY: OpenProcess returns a new owned handle or null; PID is from the private fixture.
    let handle = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, pid) };
    assert!(
        !handle.is_null(),
        "OpenProcess({pid}): {}",
        io::Error::last_os_error()
    );
    // SAFETY: the non-null handle was returned by OpenProcess and is owned here.
    let handle = unsafe { OwnedHandle::from_raw_handle(handle) };
    assert_eq!(
        process_state(&handle),
        WAIT_TIMEOUT,
        "fixture must be running before shutdown"
    );
    handle
}

fn process_state(handle: &OwnedHandle) -> u32 {
    // SAFETY: handle remains owned and valid for the duration of this nonblocking wait.
    unsafe { WaitForSingleObject(handle.as_raw_handle(), 0) }
}

#[tokio::test]
async fn fixture_guard_signals_both_processes_during_unwind() {
    let (_parent, root) = private_job_root();
    let stop = processkit::CancellationToken::new();
    let guard = FixtureGuard::new(&root, stop.clone());
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "jobs::tests::windows::process_tree_parent_fixture",
        ])
        .current_dir(&root)
        .spawn()
        .unwrap();
    let parent = process_handle(&root.join("parent.pid")).await;
    let descendant = process_handle(&root.join("descendant.pid")).await;
    let unwind = std::panic::catch_unwind(|| {
        let _guard = guard;
        panic!("exercise fixture cleanup on failure");
    });
    assert!(unwind.is_err());
    assert!(stop.is_cancelled());
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if process_state(&parent) == WAIT_OBJECT_0
                && process_state(&descendant) == WAIT_OBJECT_0
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("unwinding must release both fixture processes");
    assert!(child.wait().unwrap().success());
}

#[tokio::test]
async fn shutdown_terminates_windows_job_object_process_tree() {
    require_job_object();
    let (_parent, root) = private_job_root();
    let (url, shutdown, server) = start_board(&root).await;
    let guard = FixtureGuard::new(&root, shutdown.clone());
    tokio::time::timeout(Duration::from_secs(40), async {
        submit(
            &url,
            &CommandJob {
                program: std::env::current_exe().unwrap().to_str().unwrap().into(),
                args: vec![
                    "--ignored".into(),
                    "--exact".into(),
                    "jobs::tests::windows::process_tree_parent_fixture".into(),
                ],
                cwd: Some(root.to_str().unwrap().into()),
                timeout_seconds: None,
            },
        )
        .await;
        let parent = process_handle(&root.join("parent.pid")).await;
        let descendant = process_handle(&root.join("descendant.pid")).await;
        let store = JobStore::open(&root).await.unwrap();
        let before: String = sqlx::query_scalar("SELECT status FROM Jobs")
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert_eq!(before, "Running");
        assert_eq!(
            process_state(&parent),
            WAIT_TIMEOUT,
            "parent exited before shutdown"
        );
        assert_eq!(
            process_state(&descendant),
            WAIT_TIMEOUT,
            "descendant exited before shutdown"
        );
        finish(shutdown, server).await;
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if process_state(&parent) == WAIT_OBJECT_0
                    && process_state(&descendant) == WAIT_OBJECT_0
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("parent and descendant must both terminate");
        let after: (String, i64, Option<String>) =
            sqlx::query_as("SELECT status,attempts,last_result FROM Jobs")
                .fetch_one(&store.pool)
                .await
                .unwrap();
        assert_ne!(
            after.0, "Done",
            "shutdown must not report a successful command"
        );
        store.close().await;
        let reopened = JobStore::open(&root).await.unwrap();
        let persisted: (String, i64, Option<String>) =
            sqlx::query_as("SELECT status,attempts,last_result FROM Jobs")
                .fetch_one(&reopened.pool)
                .await
                .unwrap();
        assert_eq!(
            persisted, after,
            "opening the store must not rewrite the task"
        );
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM Jobs")
            .fetch_one(&reopened.pool)
            .await
            .unwrap();
        assert_eq!(count, 1);
        reopened.close().await;
    })
    .await
    .expect("process tree test exceeded its bounded evidence phase");
    guard.signal().expect("signal fixture cleanup event");
}
