#![cfg(windows)]

use hostlink_agent::{AgentConfig, ssh};
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
        .request_subsystem(true, "hostlink-jobs-v1")
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
        .request_subsystem(true, "hostlink-jobs-v1")
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

#[derive(Serialize)]
struct InterruptedJobRecord<'a> {
    version: u32,
    id: &'a str,
    controller_key_sha256: String,
    request_sha256: String,
    spec: &'a TestJobSpec,
    state: serde_json::Value,
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn start(id: &str, spec: &TestJobSpec) -> serde_json::Value {
    serde_json::json!({"version":1,"op":"start","id":id,"spec":spec})
}

async fn status(session: &mut client::Handle<Pin>, id: &str) -> serde_json::Value {
    job_request(
        session,
        &serde_json::json!({"version":1,"op":"status","id":id}),
    )
    .await
}

async fn wait_for_state(
    session: &mut client::Handle<Pin>,
    id: &str,
    expected: &str,
) -> serde_json::Value {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
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

    let unknown_id = uuid::Uuid::new_v4().to_string();
    let unknown_spec = TestJobSpec {
        program: source.to_string_lossy().into_owned(),
        args: vec!["exit7".into()],
        cwd: Some(temp.path().to_path_buf()),
        source_sha256: source_sha256.clone(),
    };
    let spec_bytes = serde_json::to_vec(&unknown_spec).unwrap();
    let record = InterruptedJobRecord {
        version: 1,
        id: &unknown_id,
        controller_key_sha256: sha256(&controller.public_key().public_key_bytes()),
        request_sha256: sha256(&spec_bytes),
        spec: &unknown_spec,
        state: serde_json::json!({"state":"running"}),
    };
    let unknown_dir = jobs.join(&unknown_id);
    std::fs::create_dir(&unknown_dir).unwrap();
    private_windows_test_path(&unknown_dir, true);
    let record_path = unknown_dir.join("record.json");
    std::fs::write(
        &record_path,
        serde_json::to_vec(&record).expect("persist crash-state record"),
    )
    .unwrap();
    private_windows_test_path(&record_path, false);

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
    assert_eq!(recovered["state"]["state"], "interrupted");
    assert!(
        !temp.path().join("launch-count").exists(),
        "an unknown pre-crash worker must never be replayed during recovery"
    );
    let success_id = uuid::Uuid::new_v4().to_string();
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
    let exited = wait_for_state(&mut resumed, &success_id, "exited").await;
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
        &serde_json::json!({"version":1,"op":"output","id":success_id,"stream":"stdout","offset":0}),
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
        &serde_json::json!({"version":1,"op":"output","id":success_id,"stream":"stdout","offset":1}),
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
        &serde_json::json!({"version":1,"op":"output","id":success_id,"stream":"stderr","offset":0}),
    )
    .await;
    assert_eq!(
        base64::engine::general_purpose::STANDARD
            .decode(stderr["data_base64"].as_str().unwrap())
            .unwrap(),
        [255, b'E']
    );
    assert_eq!(stderr["eof"], true);

    let bad_hash_id = uuid::Uuid::new_v4().to_string();
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
    let bad_acl_id = uuid::Uuid::new_v4().to_string();
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
    let linked_id = uuid::Uuid::new_v4().to_string();
    invalid_source.program = multiply_linked.to_string_lossy().into_owned();
    invalid_source.source_sha256 = source_sha256.clone();
    assert_eq!(
        job_request(&mut resumed, &start(&linked_id, &invalid_source)).await["ok"],
        false,
        "an executable with an alias path must be rejected"
    );

    let tree_id = uuid::Uuid::new_v4().to_string();
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
        &serde_json::json!({"version":1,"op":"cancel","id":tree_id}),
    )
    .await;
    assert_eq!(cancel["ok"], true);
    let final_state = wait_for_state(&mut resumed, &tree_id, "failed").await;
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
    use windows_sys::Win32::System::Threading::{OpenProcess, SYNCHRONIZE, WaitForSingleObject};
    // SAFETY: OpenProcess receives a PID read from this fixture's child process.
    let process = unsafe { OpenProcess(SYNCHRONIZE, 0, pid) };
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
