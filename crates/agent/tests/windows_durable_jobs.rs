#![cfg(windows)]

#[path = "support/started_job.rs"]
mod started_job;

use hostlink_agent::{
    AgentConfig,
    jobs::{JobId, JobSpec, JobStore},
    ssh,
};
use russh::client::{self, Handler};
use russh::keys::{
    Algorithm, PrivateKey, PrivateKeyWithHashAlg, PublicKeyBase64, PublicKeyOrCertificate,
};
use russh::{ChannelMsg, Disconnect};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

fn private_windows_test_path(path: &Path, directory: bool) {
    use windows_permissions::constants::{SeObjectType, SecurityInformation};
    use windows_permissions::wrappers::{ConvertSidToStringSid, SetNamedSecurityInfo};
    use windows_permissions::{LocalBox, SecurityDescriptor};
    let current = windows_permissions::utilities::current_process_sid()
        .expect("current user token for fixture");
    let sid = ConvertSidToStringSid(&current).expect("SID string");
    let flags = if directory { "OICI" } else { "" };
    let sddl = format!("D:P(A;{flags};FA;;;{})", sid.to_string_lossy());
    let descriptor: LocalBox<SecurityDescriptor> = sddl.parse().expect("protected fixture DACL");
    SetNamedSecurityInfo(
        path.as_os_str(),
        SeObjectType::SE_FILE_OBJECT,
        SecurityInformation::Owner | SecurityInformation::Dacl | SecurityInformation::ProtectedDacl,
        Some(current.as_ref()),
        None,
        Some(descriptor.dacl().expect("DACL")),
        None,
    )
    .expect("apply current-user-only private test fixture ACL");
}

struct Pin(russh::keys::PublicKey);
impl Handler for Pin {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(key.certificate().is_none()
            && key.public_key().algorithm() == Algorithm::Ed25519
            && key.public_key().key_data() == self.0.key_data())
    }
}

async fn connect(addr: SocketAddr, host_key: &russh::keys::PublicKey) -> client::Handle<Pin> {
    client::connect(
        Arc::new(client::Config::default()),
        addr,
        Pin(host_key.clone()),
    )
    .await
    .expect("connect to embedded Agent SSH server")
}

async fn authenticate(session: &mut client::Handle<Pin>, key: PrivateKey) -> bool {
    session
        .authenticate_publickey("agent", PrivateKeyWithHashAlg::new(Arc::new(key), None))
        .await
        .expect("controller authentication result")
        .success()
}

async fn job_request(
    session: &mut client::Handle<Pin>,
    value: &serde_json::Value,
) -> serde_json::Value {
    let bytes = serde_json::to_vec(value).unwrap();
    let mut channel = session
        .channel_open_session()
        .await
        .expect("open jobs channel");
    channel
        .request_subsystem(true, "hostlink-jobs")
        .await
        .expect("request jobs subsystem");
    loop {
        match channel.wait().await {
            Some(ChannelMsg::Success) => break,
            Some(ChannelMsg::Failure) => panic!("jobs subsystem rejected request"),
            Some(_) => {}
            None => panic!("jobs channel closed before acceptance"),
        }
    }
    channel
        .data(&(bytes.len() as u32).to_be_bytes()[..])
        .await
        .unwrap();
    channel.data(bytes.as_slice()).await.unwrap();
    channel.eof().await.unwrap();
    let mut frame = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), async {
        while let Some(message) = channel.wait().await {
            match message {
                ChannelMsg::Data { data } => frame.extend_from_slice(&data),
                ChannelMsg::Close => break,
                _ => {}
            }
        }
    })
    .await
    .expect("jobs response deadline");
    let size = u32::from_be_bytes(frame[..4].try_into().unwrap()) as usize;
    assert_eq!(size, frame.len() - 4);
    serde_json::from_slice(&frame[4..]).expect("decode jobs response")
}

async fn send_job_request_and_drop_response(
    session: &mut client::Handle<Pin>,
    value: &serde_json::Value,
) {
    let bytes = serde_json::to_vec(value).unwrap();
    let mut channel = session
        .channel_open_session()
        .await
        .expect("open jobs channel for lost-ack fixture");
    channel
        .request_subsystem(true, "hostlink-jobs")
        .await
        .expect("request jobs subsystem");
    loop {
        match channel.wait().await {
            Some(ChannelMsg::Success) => break,
            Some(ChannelMsg::Failure) => panic!("jobs subsystem rejected request"),
            Some(_) => {}
            None => panic!("jobs channel closed before acceptance"),
        }
    }
    channel
        .data(&(bytes.len() as u32).to_be_bytes()[..])
        .await
        .unwrap();
    channel.data(bytes.as_slice()).await.unwrap();
    channel.eof().await.unwrap();
    // The caller disconnects this SSH session without consuming the response frame.
}

#[derive(Serialize)]
struct TestJobSpec {
    program: String,
    args: Vec<String>,
    cwd: Option<PathBuf>,
    source_sha256: String,
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn start(id: &str, spec: &TestJobSpec) -> serde_json::Value {
    serde_json::json!({"op":"run","id":id,"spec":spec})
}

async fn status(session: &mut client::Handle<Pin>, id: &str) -> serde_json::Value {
    job_request(session, &serde_json::json!({"op":"status","id":id})).await
}

async fn wait_for_state(
    session: &mut client::Handle<Pin>,
    id: &str,
    expected: &str,
    budget: Duration,
) -> serde_json::Value {
    let deadline = tokio::time::Instant::now() + budget;
    loop {
        let response = status(session, id).await;
        if response["state"]["state"] == expected {
            return response;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "job {id} did not reach {expected}: {response}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test]
async fn windows_agent_jobs_reattach_and_cancel_the_complete_process_tree() {
    let temp = tempfile::tempdir().expect("disposable Windows test root");
    private_windows_test_path(temp.path(), true);
    let source = temp.path().join("fixture.exe");
    let fixture_source = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("windows_job_worker.rs");
    let compiled = Command::new("rustc")
        .args(["--edition=2024"])
        .arg(fixture_source)
        .arg("-o")
        .arg(&source)
        .status()
        .expect("compile source-owned Windows fixture with the active Rust toolchain");
    assert!(compiled.success(), "Windows fixture compilation failed");
    private_windows_test_path(&source, false);
    let source_sha256 = sha256(&std::fs::read(&source).unwrap());
    let current_sid = windows_permissions::utilities::current_process_sid()
        .expect("exact Windows test owner SID");
    let current_sid = windows_permissions::wrappers::ConvertSidToStringSid(&current_sid)
        .expect("render exact Windows test owner SID");
    eprintln!(
        "Windows durable-job fixture: executable_sha256={source_sha256} owner_sid={}",
        current_sid.to_string_lossy()
    );
    let host = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("host key");
    let controller =
        PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("controller key");
    let wrong = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("wrong key");
    let host_path = temp.path().join("host_key");
    let auth_path = temp.path().join("authorized_keys");
    let jobs = temp.path().join("jobs");
    std::fs::create_dir(&jobs).expect("jobs root");
    private_windows_test_path(&jobs, true);
    std::fs::write(
        &host_path,
        host.to_openssh(russh::keys::ssh_key::LineEnding::LF)
            .unwrap(),
    )
    .unwrap();
    private_windows_test_path(&host_path, false);
    let authorized = controller.public_key().to_openssh().unwrap();
    let other_authorized = wrong.public_key().to_openssh().unwrap();
    std::fs::write(
        &auth_path,
        format!("{authorized} test-controller\n{other_authorized} second-controller\n"),
    )
    .unwrap();
    private_windows_test_path(&auth_path, false);

    let owner = sha256(&controller.public_key().public_key_bytes());
    // Crash fault injection precedes SSH startup: reproduce the private sealed
    // layout for a native Apalis orphan. Live admissions below still upload
    // and call the real Seal handler before using its returned canonical path.
    let artifacts = temp.path().join("artifacts");
    let owner_root = artifacts.join(&owner);
    let sealed_root = owner_root.join("sealed");
    for directory in [
        &artifacts,
        &owner_root,
        &owner_root.join("uploads"),
        &sealed_root,
    ] {
        std::fs::create_dir(directory).unwrap();
        private_windows_test_path(directory, true);
    }
    let crash_source = sealed_root.join(format!("{source_sha256}.program"));
    std::fs::copy(&source, &crash_source).unwrap();
    private_windows_test_path(&crash_source, false);
    let crash_source = crash_source.canonicalize().unwrap();
    let unknown_id = ulid::Ulid::generate().to_string();
    let unknown_spec = TestJobSpec {
        program: crash_source.to_string_lossy().into_owned(),
        args: vec!["exit7".into()],
        cwd: Some(temp.path().to_path_buf()),
        source_sha256: source_sha256.clone(),
    };
    // Simulate a crashed worker whose native Running task may be replayed.
    let store = JobStore::initialize_fresh(&jobs)
        .await
        .expect("private SQLite store");
    let unknown_job_id = JobId::parse(&unknown_id).expect("canonical fixture ULID");
    store
        .admit(
            unknown_job_id,
            &owner,
            &JobSpec {
                program: unknown_spec.program.clone(),
                args: unknown_spec.args.clone(),
                cwd: unknown_spec.cwd.clone(),
                source_sha256: unknown_spec.source_sha256.clone(),
            },
        )
        .await
        .expect("admit durable pre-crash fixture");
    started_job::started(&jobs, &store, unknown_job_id, &owner).await;
    store.close().await;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen = listener.local_addr().unwrap();
    let config = AgentConfig {
        listen,
        user: "agent".into(),
        host_key: host_path,
        authorized_keys: auth_path,
        jobs_root: jobs.clone(),
        gateway: None,
        gateway_alternates: Vec::new(),
    };
    let (stop, shutdown) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        ssh::serve_on(listener, &config, async {
            let _ = shutdown.await;
        })
        .await
    });
    let host_public = host.public_key().clone();

    let mut session = connect(listen, &host_public).await;
    assert!(authenticate(&mut session, controller.clone()).await);
    let recovered = job_request(&mut session, &start(&unknown_id, &unknown_spec)).await;
    assert_eq!(recovered["ok"], true);
    // Apalis recovers another worker's orphan on heartbeat; the native
    // default heartbeat is 30 seconds, not an immediate custom recovery.
    let replayed =
        wait_for_state(&mut session, &unknown_id, "exited", Duration::from_secs(95)).await;
    assert_eq!(replayed["state"]["code"], 7);
    assert_eq!(
        std::fs::read(temp.path().join("launch-count")).unwrap(),
        b"x",
        "native Apalis must re-execute the abandoned task exactly once in this fixture"
    );
    let source_bytes = std::fs::read(&source).unwrap();
    let upload_name = format!("{source_sha256}.upload");
    let channel = session.channel_open_session().await.unwrap();
    channel.request_subsystem(true, "sftp").await.unwrap();
    let sftp = russh_sftp::client::SftpSession::new(channel.into_stream())
        .await
        .unwrap();
    let mut upload = sftp
        .open_with_flags(
            upload_name.clone(),
            russh_sftp::protocol::OpenFlags::CREATE
                | russh_sftp::protocol::OpenFlags::EXCLUDE
                | russh_sftp::protocol::OpenFlags::WRITE,
        )
        .await
        .unwrap();
    use tokio::io::AsyncWriteExt as _;
    upload.write_all(&source_bytes).await.unwrap();
    upload.close().await.unwrap();
    sftp.close().await.unwrap();
    let sealed = job_request(
        &mut session,
        &serde_json::json!({
            "op":"seal", "name":upload_name, "sha256":source_sha256, "size":source_bytes.len()
        }),
    )
    .await;
    assert_eq!(sealed["ok"], true);
    let source = PathBuf::from(
        sealed["program"]
            .as_str()
            .expect("canonical authenticated sealed source"),
    );
    let success_id = ulid::Ulid::generate().to_string();
    let success = TestJobSpec {
        program: source.to_string_lossy().into_owned(),
        args: vec!["exit7".into()],
        cwd: Some(temp.path().to_path_buf()),
        source_sha256: source_sha256.clone(),
    };
    send_job_request_and_drop_response(&mut session, &start(&success_id, &success)).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    session
        .disconnect(
            Disconnect::ByApplication,
            "simulate lost start acknowledgement",
            "en",
        )
        .await
        .unwrap();

    let mut resumed = connect(listen, &host_public).await;
    assert!(authenticate(&mut resumed, controller.clone()).await);
    let retried = job_request(&mut resumed, &start(&success_id, &success)).await;
    assert_eq!(retried["ok"], true);
    assert_eq!(retried["id"], success_id);
    let exited = wait_for_state(&mut resumed, &success_id, "exited", Duration::from_secs(15)).await;
    assert_eq!(exited["state"]["code"], 7);
    let duplicate = job_request(&mut resumed, &start(&success_id, &success)).await;
    assert_eq!(duplicate["state"]["code"], 7);
    assert_eq!(
        std::fs::read(temp.path().join("launch-count")).unwrap(),
        b"x"
    );

    let mut foreign = connect(listen, &host_public).await;
    assert!(authenticate(&mut foreign, wrong.clone()).await);
    let foreign_status = status(&mut foreign, &success_id).await;
    assert_eq!(
        foreign_status["ok"], false,
        "a different authorized key cannot inspect another controller's job"
    );
    foreign
        .disconnect(
            Disconnect::ByApplication,
            "foreign job access rejected",
            "en",
        )
        .await
        .unwrap();

    use base64::Engine as _;
    let first = job_request(
        &mut resumed,
        &serde_json::json!({"op":"logs","id":success_id,"stream":"stdout","offset":0}),
    )
    .await;
    assert_eq!(
        base64::engine::general_purpose::STANDARD
            .decode(first["data_base64"].as_str().unwrap())
            .unwrap(),
        [0, 255]
    );
    assert_eq!(first["next_offset"], 2);
    assert_eq!(first["eof"], true);
    let tail = job_request(
        &mut resumed,
        &serde_json::json!({"op":"logs","id":success_id,"stream":"stdout","offset":1}),
    )
    .await;
    assert_eq!(
        base64::engine::general_purpose::STANDARD
            .decode(tail["data_base64"].as_str().unwrap())
            .unwrap(),
        [255]
    );
    let stderr = job_request(
        &mut resumed,
        &serde_json::json!({"op":"logs","id":success_id,"stream":"stderr","offset":0}),
    )
    .await;
    assert_eq!(
        base64::engine::general_purpose::STANDARD
            .decode(stderr["data_base64"].as_str().unwrap())
            .unwrap(),
        [255, b'E']
    );
    assert_eq!(stderr["eof"], true);

    let bad_hash_id = ulid::Ulid::generate().to_string();
    let mut invalid_source = TestJobSpec {
        program: source.to_string_lossy().into_owned(),
        args: success.args.clone(),
        cwd: Some(temp.path().to_path_buf()),
        source_sha256: "0".repeat(64),
    };
    assert_eq!(
        job_request(&mut resumed, &start(&bad_hash_id, &invalid_source)).await["ok"],
        false,
        "incorrect executable digest must be rejected"
    );

    let unprotected_source = temp.path().join("unprotected.exe");
    std::fs::copy(&source, &unprotected_source).unwrap();
    set_unprotected_fixture_acl(&unprotected_source);
    invalid_source.program = unprotected_source.to_string_lossy().into_owned();
    invalid_source.source_sha256 = source_sha256.clone();
    let bad_acl_id = ulid::Ulid::generate().to_string();
    assert_eq!(
        job_request(&mut resumed, &start(&bad_acl_id, &invalid_source)).await["ok"],
        false,
        "inheriting source ACL must be rejected"
    );

    let multiply_linked = temp.path().join("multiply-linked.exe");
    std::fs::copy(&source, &multiply_linked).unwrap();
    private_windows_test_path(&multiply_linked, false);
    let second_link = temp.path().join("executable-alias.exe");
    std::fs::hard_link(&multiply_linked, &second_link).unwrap();
    let linked_id = ulid::Ulid::generate().to_string();
    invalid_source.program = multiply_linked.to_string_lossy().into_owned();
    invalid_source.source_sha256 = source_sha256.clone();
    assert_eq!(
        job_request(&mut resumed, &start(&linked_id, &invalid_source)).await["ok"],
        false,
        "an executable with an alias path must be rejected"
    );

    let tree_id = ulid::Ulid::generate().to_string();
    let tree = TestJobSpec {
        program: source.to_string_lossy().into_owned(),
        args: vec![
            "tree".into(),
            temp.path()
                .join("descendant.pid")
                .to_string_lossy()
                .into_owned(),
        ],
        cwd: Some(temp.path().to_path_buf()),
        source_sha256: source_sha256.clone(),
    };
    assert_eq!(
        job_request(&mut resumed, &start(&tree_id, &tree)).await["ok"],
        true
    );
    let pid_path = temp.path().join("descendant.pid");
    tokio::time::timeout(Duration::from_secs(10), async {
        while !pid_path.exists() {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("descendant process started");
    let descendant_pid: u32 = std::fs::read_to_string(&pid_path).unwrap().parse().unwrap();
    let cancel = job_request(
        &mut resumed,
        &serde_json::json!({"op":"cancel","id":tree_id}),
    )
    .await;
    assert_eq!(cancel["ok"], true);
    let final_state =
        wait_for_state(&mut resumed, &tree_id, "failed", Duration::from_secs(15)).await;
    assert_eq!(final_state["state"]["state"], "failed");
    assert!(
        process_exited(descendant_pid),
        "Agent cancellation must close the Windows Job Object and terminate its grandchild"
    );

    resumed
        .disconnect(Disconnect::ByApplication, "test complete", "en")
        .await
        .unwrap();
    let _ = stop.send(());
    tokio::time::timeout(Duration::from_secs(10), server)
        .await
        .expect("Agent shutdown deadline")
        .unwrap()
        .expect("Agent server shutdown");
}

fn set_unprotected_fixture_acl(path: &Path) {
    use windows_permissions::constants::{SeObjectType, SecurityInformation};
    use windows_permissions::wrappers::{
        ConvertSidToStringSid, ConvertStringSecurityDescriptorToSecurityDescriptor,
        SetNamedSecurityInfo,
    };
    let current = windows_permissions::utilities::current_process_sid().unwrap();
    let current = ConvertSidToStringSid(&current).unwrap();
    let sddl = format!("D:(A;;FA;;;{})", current.to_string_lossy());
    let descriptor = ConvertStringSecurityDescriptorToSecurityDescriptor(&sddl).unwrap();
    SetNamedSecurityInfo(
        path.as_os_str(),
        SeObjectType::SE_FILE_OBJECT,
        SecurityInformation::Dacl | SecurityInformation::UnprotectedDacl,
        None,
        None,
        Some(descriptor.dacl().unwrap()),
        None,
    )
    .expect("fixture ACL must lose its protected flag");
}

fn process_exited(pid: u32) -> bool {
    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_INVALID_PARAMETER, GetLastError, WAIT_OBJECT_0,
    };
    use windows_sys::Win32::System::Threading::{
        OpenProcess, PROCESS_SYNCHRONIZE, WaitForSingleObject,
    };
    // SAFETY: OpenProcess receives a PID read from this fixture's child process.
    let process = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, pid) };
    if process.is_null() {
        // SAFETY: GetLastError reads this thread's status from the failed OpenProcess call.
        return unsafe { GetLastError() } == ERROR_INVALID_PARAMETER;
    }
    // SAFETY: process is an owned handle returned by OpenProcess and is closed below.
    let exited = unsafe { WaitForSingleObject(process, 0) } == WAIT_OBJECT_0;
    // SAFETY: the handle is owned by this helper and closed exactly once.
    unsafe { CloseHandle(process) };
    exited
}
