#![cfg(windows)]

#[path = "support/started_job.rs"]
mod started_job;

use hostlink_agent::jobs::{JobId, JobSpec, JobState, JobStore};
use russh::keys::{Algorithm, PrivateKey, ssh_key::LineEnding};
use serde_json::{Map, json};
use sha2::{Digest, Sha256};
use std::{fs, path::Path, process::Command};

// This test writes one root-derived value to the current user's HKCU Run key.
// Keep it ignored by default; run only in a disposable, non-elevated Windows profile.
#[tokio::test]
#[ignore = "requires HOSTLINK_WINDOWS_LIFECYCLE_DISPOSABLE=1 and a disposable Windows user profile"]
async fn current_user_lifecycle_installs_reports_and_removes_only_its_disposable_root() {
    assert_eq!(
        std::env::var("HOSTLINK_WINDOWS_LIFECYCLE_DISPOSABLE").as_deref(),
        Ok("1"),
        "refusing to write HKCU Run without an explicit disposable-profile guard"
    );
    assert_disposable_context();
    let source_agent = Path::new(env!("CARGO_BIN_EXE_hostlink-agent"));
    let expected_hash = std::env::var("HOSTLINK_WINDOWS_LIFECYCLE_AGENT_SHA256")
        .expect("harness supplies the source Agent SHA-256 after build");
    assert_eq!(
        sha256_file(source_agent),
        expected_hash,
        "test Agent hash changed"
    );

    let temp = tempfile::tempdir().expect("disposable test scratch root");
    let local_app_data = known_local_app_data();
    let private_parent = local_app_data.join(format!(
        "HostLink Lifecycle Test & (fixture) {}",
        uuid::Uuid::new_v4()
    ));
    fs::create_dir(&private_parent).expect("private test install parent");
    let _fixture_cleanup = ProfileFixture(private_parent.clone());
    private_windows_path(&private_parent, true);
    // Match the real installer, which creates LocalAppData/HostLink/Agent,
    // without modifying or adopting any real HostLink directory.
    let root = private_parent.join("Agent");
    let state = root.join("state");
    let bin = root.join("bin");
    fs::create_dir_all(&state).expect("state directory");
    fs::create_dir_all(&bin).expect("bin directory");
    fs::create_dir(root.join("jobs")).expect("jobs directory");
    for directory in [&root, &state, &bin, &root.join("jobs")] {
        private_windows_path(directory, true);
    }
    JobStore::initialize_fresh(root.join("jobs"))
        .await
        .expect("initialize installed Agent SQLite state")
        .close()
        .await;

    let probe = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("choose disposable port");
    let listen_port = probe.local_addr().expect("read disposable port").port();
    drop(probe);
    let config = json!({
        "listen": format!("127.0.0.1:{listen_port}"),
        "user": "fixture",
        "host_key": "host_key",
        "authorized_keys": "authorized_keys",
        "jobs_root": root.join("jobs").to_string_lossy(),
        "gateway": null
    })
    .to_string()
    .into_bytes();
    let machine_id = "00000000-0000-4000-8000-000000000001";
    let host_key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519)
        .expect("generate disposable Agent host key");
    let controller_key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519)
        .expect("generate disposable controller key");
    let host_private = host_key
        .to_openssh(LineEnding::LF)
        .expect("serialize disposable Agent host key")
        .to_string()
        .into_bytes();
    let authorized_key = format!(
        "{} lifecycle-fixture\n",
        controller_key
            .public_key()
            .to_openssh()
            .expect("serialize controller public key")
    )
    .into_bytes();
    let payloads = [
        ("agent.json", config),
        ("authorized_keys", authorized_key),
        ("gateway_host_key", b"fixture gateway public key\n".to_vec()),
        (
            "gateway_identity",
            b"fixture gateway private key\n".to_vec(),
        ),
        ("host_key", host_private),
        (
            "machine.json",
            json!({
                "format": 1,
                "machine_id": machine_id,
                "name": "lifecycle-fixture",
                "ssh_public_key": "ssh-ed25519 AAAA fixture",
                "ssh_host_public_key": "ssh-ed25519 AAAA host"
            })
            .to_string()
            .into_bytes(),
        ),
    ];
    let mut files = Map::new();
    for (name, bytes) in payloads {
        fs::write(state.join(name), &bytes).expect("write enrollment fixture");
        private_windows_path(&state.join(name), false);
        files.insert(
            name.to_owned(),
            json!({
                "size": bytes.len(),
                "sha256": format!("{:x}", Sha256::digest(&bytes))
            }),
        );
    }
    fs::write(
        state.join("manifest.json"),
        json!({ "format": 1, "machine_id": machine_id, "files": files }).to_string(),
    )
    .expect("write enrollment manifest");
    private_windows_path(&state.join("manifest.json"), false);

    let executable = root.join("bin/hostlink-agent.exe");
    fs::copy(source_agent, &executable).expect("copy exact test Agent");
    private_windows_path(&executable, false);
    assert_eq!(
        sha256_file(&executable),
        expected_hash,
        "installed Agent differs from source binary"
    );

    let wrong_root = private_parent.join("Wrong Root");
    fs::create_dir(&wrong_root).expect("create unrelated private root");
    private_windows_path(&wrong_root, true);
    let wrong_root_status = Command::new(source_agent)
        .args(["service", "status", "--root"])
        .arg(&wrong_root)
        .output()
        .expect("query unrelated private root");
    assert!(wrong_root_status.status.success());
    assert!(String::from_utf8_lossy(&wrong_root_status.stdout).contains("installed=false"));

    // A private final root does not make a shared or replaceable parent safe.
    // The lifecycle must reject this disposable world-writable ancestor path.
    let shared_parent = temp.path().join("Shared Parent");
    fs::create_dir(&shared_parent).expect("create disposable shared parent");
    world_writable_windows_directory(&shared_parent);
    let unsafe_root = shared_parent.join("private-looking-root");
    fs::create_dir(&unsafe_root).expect("create private-looking child");
    private_windows_path(&unsafe_root, true);
    let refused = Command::new(source_agent)
        .args([
            "service",
            "install",
            "--root",
            unsafe_root.to_str().unwrap(),
            "--config",
            unsafe_root.join("state/agent.json").to_str().unwrap(),
        ])
        .output()
        .expect("refuse install beneath shared ancestor");
    assert!(!refused.status.success());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("LocalAppData"));

    let install = Command::new(&executable)
        .args([
            "service",
            "install",
            "--root",
            root.to_str().expect("UTF-8 fixture root"),
            "--config",
            state
                .join("agent.json")
                .to_str()
                .expect("UTF-8 config path"),
        ])
        .output()
        .expect("invoke service install");
    let _cleanup = CleanupService {
        executable: executable.clone(),
        root: root.clone(),
    };
    assert!(
        install.status.success(),
        "{}",
        String::from_utf8_lossy(&install.stderr)
    );
    assert!(root.join(".hostlink-user-service.json").is_file());
    let marker: serde_json::Value = serde_json::from_slice(
        &fs::read(root.join(".hostlink-user-service.json")).expect("read private marker"),
    )
    .expect("parse private marker");
    let control_token = marker["control_token"]
        .as_str()
        .expect("marker control token");
    let run_value = marker["run_value"]
        .as_str()
        .expect("root-derived HKCU Run value")
        .to_owned();
    let startup_script =
        fs::read_to_string(root.join(".hostlink-agent-start.vbs")).expect("read startup script");
    assert!(!startup_script.contains(control_token));
    assert!(!startup_script.contains("service-control-token"));
    let reinstall = Command::new(&executable)
        .args([
            "service",
            "install",
            "--root",
            root.to_str().unwrap(),
            "--config",
            state.join("agent.json").to_str().unwrap(),
        ])
        .output()
        .expect("repeat idempotent service install");
    assert!(reinstall.status.success());

    let wrong_sha = "0".repeat(64);
    let update = Command::new(&executable)
        .args([
            "update",
            "--root",
            root.to_str().unwrap(),
            "--archive",
            temp.path().join("missing.zip").to_str().unwrap(),
            "--sha256",
            wrong_sha.as_str(),
            "--target",
            "x86_64-pc-windows-msvc",
            "--version",
            "0.1.0",
        ])
        .output()
        .expect("refuse updater while current-user lifecycle is installed");
    assert!(!update.status.success());
    assert!(
        String::from_utf8_lossy(&update.stderr)
            .contains("remove the current-user Agent lifecycle registration")
    );

    // Offline status is expected to report installed but inactive; no listener is started.
    let status = Command::new(&executable)
        .args(["service", "status", "--root", root.to_str().unwrap()])
        .output()
        .expect("invoke service status");
    assert!(String::from_utf8_lossy(&status.stdout).contains("installed=true active=false"));

    let original_binary = fs::read(&executable).expect("read installed source binary");
    let mut changed_binary = original_binary.clone();
    changed_binary[0] ^= 1;
    fs::write(&executable, &changed_binary).expect("tamper disposable binary");
    // Invoke the CLI from the original test binary: the deliberately
    // corrupted installed PE cannot itself be launched by Windows.
    let refused = Command::new(source_agent)
        .args(["service", "start", "--root", root.to_str().unwrap()])
        .output()
        .expect("invoke start with tampered binary");
    assert!(!refused.status.success());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("SHA-256 changed"));
    fs::write(&executable, &original_binary).expect("restore exact installed binary");

    let launcher = root.join(".hostlink-agent-start.vbs");
    let original_launcher = fs::read(&launcher).expect("read private startup launcher");
    fs::write(
        &launcher,
        b"CreateObject(\"WScript.Shell\").Run \"not-the-Agent\", 0, False\r\n",
    )
    .expect("tamper disposable startup launcher");
    let refused = Command::new(&executable)
        .args(["service", "status", "--root", root.to_str().unwrap()])
        .output()
        .expect("invoke status with tampered launcher");
    assert!(!refused.status.success());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("startup launcher differs"));
    fs::write(&launcher, original_launcher).expect("restore exact private startup launcher");

    // Model a stale owner record whose old PID has since been reused by this
    // unrelated test process. Its authenticated-looking pipe response must not
    // make stop signal or accept that PID as the installed Agent.
    let marker_path = root.join(".hostlink-user-service.json");
    let original_marker =
        fs::read(&marker_path).expect("read owned marker before PID-reuse fixture");
    let mut reused_marker: serde_json::Value =
        serde_json::from_slice(&original_marker).expect("parse owned marker for PID-reuse fixture");
    let fake_pipe = format!(r"\\.\pipe\hostlink-agent-reused-{}", uuid::Uuid::new_v4());
    reused_marker["pipe_name"] = json!(fake_pipe);
    fs::write(
        &marker_path,
        serde_json::to_vec(&reused_marker).expect("serialize disposable PID-reuse marker"),
    )
    .expect("write disposable PID-reuse marker");
    let fake_pipe_server = spawn_reused_pid_pipe(fake_pipe, std::process::id());
    let refused = Command::new(&executable)
        .args(["service", "stop", "--root", root.to_str().unwrap()])
        .output()
        .expect("refuse stale PID reused by an unrelated process");
    assert!(!refused.status.success());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("image does not match"));
    assert!(marker_path.is_file());
    fake_pipe_server.join().expect("finish fake PID-reuse pipe");
    fs::write(&marker_path, original_marker).expect("restore exact disposable ownership marker");
    private_windows_path(&marker_path, false);

    let store = JobStore::open(root.join("jobs"))
        .await
        .expect("open durable job store");
    for target_state in [JobState::Prepared, JobState::Running] {
        let job_id = JobId::new();
        let owner = "a".repeat(64);
        let admission = store
            .admit(
                job_id,
                &owner,
                &JobSpec {
                    program: "disposable lifecycle interlock".into(),
                    args: Vec::new(),
                    cwd: None,
                    source_sha256: "b".repeat(64),
                },
            )
            .await
            .expect("admit real durable job fixture");
        assert_eq!(admission.id, job_id);
        if target_state != JobState::Prepared {
            started_job::started(&root.join("jobs"), &store, job_id, &owner).await;
        }
        for action in ["stop", "remove"] {
            let refused = Command::new(&executable)
                .args(["service", action, "--root", root.to_str().unwrap()])
                .output()
                .expect("invoke lifecycle action with nonterminal job");
            assert!(
                !refused.status.success(),
                "{action} accepted {target_state:?}"
            );
            assert!(String::from_utf8_lossy(&refused.stderr).contains("durable jobs"));
            assert!(root.join(".hostlink-user-service.json").is_file());
        }
    }
    store.close().await;
    // Both native nonterminal records remain durable until the disposable
    // test store is removed; crash-recovered work may be replayed by Apalis.
    fs::remove_dir_all(root.join("jobs")).expect("remove exact disposable SQLite fixture");
    fs::create_dir(root.join("jobs")).expect("fresh empty disposable job store");
    private_windows_path(&root.join("jobs"), true);
    JobStore::initialize_fresh(root.join("jobs"))
        .await
        .expect("initialize fresh disposable SQLite state")
        .close()
        .await;

    let unknown_job = root.join("jobs/unknown-fixture-entry");
    fs::create_dir(&unknown_job).expect("create unknown disposable job entry");
    private_windows_path(&unknown_job, true);
    for action in ["stop", "remove"] {
        let refused = Command::new(&executable)
            .args(["service", action, "--root", root.to_str().unwrap()])
            .output()
            .expect("invoke lifecycle action with unknown job entry");
        assert!(!refused.status.success());
        assert!(root.join(".hostlink-user-service.json").is_file());
    }
    fs::remove_dir_all(&unknown_job).expect("remove exact unknown disposable job fixture");

    for action in ["stop", "remove"] {
        let refused = Command::new(&executable)
            .args(["service", action, "--root", root.to_str().unwrap()])
            .output()
            .expect("refuse to infer process exit from missing lifecycle pipe");
        assert!(!refused.status.success());
        assert!(String::from_utf8_lossy(&refused.stderr).contains("pipe is absent"));
        assert!(root.join(".hostlink-user-service.json").is_file());
    }

    let start = Command::new(&executable)
        .args(["service", "start", "--root", root.to_str().unwrap()])
        .output()
        .expect("start exact disposable Agent");
    assert!(
        start.status.success(),
        "{}",
        String::from_utf8_lossy(&start.stderr)
    );
    let running = Command::new(&executable)
        .args(["service", "status", "--root", root.to_str().unwrap()])
        .output()
        .expect("read running Agent status");
    assert!(
        running.status.success(),
        "{}",
        String::from_utf8_lossy(&running.stderr)
    );
    assert!(String::from_utf8_lossy(&running.stdout).contains("active=true"));
    assert!(String::from_utf8_lossy(&running.stdout).contains("ssh_banner=true"));
    for _ in 0..8 {
        let status = Command::new(&executable)
            .args(["service", "status", "--root", root.to_str().unwrap()])
            .output()
            .expect("repeat status while stable pipe listener is running");
        assert!(
            status.status.success(),
            "{}",
            String::from_utf8_lossy(&status.stderr)
        );
    }

    let stop = Command::new(&executable)
        .args(["service", "stop", "--root", root.to_str().unwrap()])
        .output()
        .expect("gracefully stop exact disposable Agent");
    assert!(
        stop.status.success(),
        "{}",
        String::from_utf8_lossy(&stop.stderr)
    );
    assert!(std::net::TcpStream::connect(("127.0.0.1", listen_port)).is_err());

    // Exercise removal while an authenticated process is live; remove must
    // perform its own cooperative stop and prove exit with the process handle.
    let start_again = Command::new(&executable)
        .args(["service", "start", "--root", root.to_str().unwrap()])
        .output()
        .expect("restart exact disposable Agent before remove");
    assert!(
        start_again.status.success(),
        "{}",
        String::from_utf8_lossy(&start_again.stderr)
    );

    let remove = Command::new(&executable)
        .args(["service", "remove", "--root", root.to_str().unwrap()])
        .output()
        .expect("invoke service remove");
    assert!(
        remove.status.success(),
        "{}",
        String::from_utf8_lossy(&remove.stderr)
    );
    assert!(!root.join(".hostlink-user-service.json").exists());
    assert_no_run_registration(&run_value);
    assert!(
        executable.is_file(),
        "Windows removal preserves the executable and enrollment for recovery"
    );
    drop(temp);
    fs::remove_dir_all(&private_parent).expect("remove disposable profile fixture");
}

struct CleanupService {
    executable: std::path::PathBuf,
    root: std::path::PathBuf,
}

impl Drop for CleanupService {
    fn drop(&mut self) {
        if self.root.join(".hostlink-user-service.json").exists() {
            // Never start a process during a failing test's cleanup. Removal
            // may proceed only through the normal authenticated owner checks.
            let _ = Command::new(&self.executable)
                .args(["service", "remove", "--root"])
                .arg(&self.root)
                .output();
        }
        if !self.root.join(".hostlink-user-service.json").exists() {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
}

struct ProfileFixture(std::path::PathBuf);

impl Drop for ProfileFixture {
    fn drop(&mut self) {
        // A failed test may leave an installed service marker or live Agent.
        // Never recursively erase such a root and strand its HKCU Run entry.
        // Successful acceptance explicitly removes the owned root after stop.
        let _ = fs::remove_dir(&self.0);
    }
}

fn spawn_reused_pid_pipe(pipe_name: String, reused_pid: u32) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("create fake PID-reuse pipe runtime");
        runtime.block_on(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            use tokio::net::windows::named_pipe::ServerOptions;
            let mut pipe = ServerOptions::new()
                .first_pipe_instance(true)
                .create(&pipe_name)
                .expect("create disposable PID-reuse pipe");
            tokio::time::timeout(std::time::Duration::from_secs(5), pipe.connect())
                .await
                .expect("lifecycle probe must connect within 5 seconds")
                .expect("accept lifecycle probe");
            let mut request = [0u8; 1024];
            let _ =
                tokio::time::timeout(std::time::Duration::from_secs(5), pipe.read(&mut request))
                    .await
                    .expect("lifecycle probe must send within 5 seconds")
                    .expect("read lifecycle probe");
            pipe.write_all(format!("RUNNING {reused_pid}\n").as_bytes())
                .await
                .expect("respond with reused PID");
            pipe.flush().await.expect("flush PID-reuse response");
        });
    })
}

fn assert_disposable_context() {
    let current = windows_permissions::utilities::current_process_sid().expect("current SID");
    use windows_permissions::wrappers::ConvertSidToStringSid;
    let current_sid = ConvertSidToStringSid(&current)
        .expect("format current SID")
        .to_string_lossy()
        .into_owned();
    assert_ne!(current_sid, "S-1-5-18", "SYSTEM profile is forbidden");
    assert_eq!(
        std::env::var("HOSTLINK_WINDOWS_LIFECYCLE_EXPECTED_SID").as_deref(),
        Ok(current_sid.as_str()),
        "current SID differs from the harness-verified disposable SID"
    );
    let profile = known_user_profile();
    assert_eq!(
        std::env::var("HOSTLINK_WINDOWS_LIFECYCLE_EXPECTED_PROFILE")
            .ok()
            .as_deref(),
        Some(profile.to_string_lossy().as_ref()),
        "current profile differs from the harness-verified disposable profile"
    );
    assert!(
        std::env::var("HOSTLINK_WINDOWS_LIFECYCLE_PROTECTED_WORK_SID").as_deref()
            != Ok(current_sid.as_str()),
        "refusing to run in the protected WORK SID"
    );
}

fn sha256_file(path: &Path) -> String {
    format!(
        "{:x}",
        Sha256::digest(fs::read(path).expect("read exact Agent binary"))
    )
}

fn assert_no_run_registration(run_value: &str) {
    use windows_sys::Win32::System::Registry::{
        HKEY, HKEY_CURRENT_USER, KEY_QUERY_VALUE, RegCloseKey, RegOpenKeyExW, RegQueryValueExW,
    };
    let key_name: Vec<u16> = "Software\\Microsoft\\Windows\\CurrentVersion\\Run\0"
        .encode_utf16()
        .collect();
    let value_name: Vec<u16> = format!("{run_value}\0").encode_utf16().collect();
    let mut key: HKEY = std::ptr::null_mut();
    // SAFETY: key_name is NUL-terminated and key points to writable storage.
    let open = unsafe {
        RegOpenKeyExW(
            HKEY_CURRENT_USER,
            key_name.as_ptr(),
            0,
            KEY_QUERY_VALUE,
            &mut key,
        )
    };
    assert_eq!(open, 0, "cannot verify current-user Run key after teardown");
    let mut size = 0u32;
    // SAFETY: value_name is NUL-terminated; a null data pointer requests only its size.
    let query = unsafe {
        RegQueryValueExW(
            key,
            value_name.as_ptr(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut size,
        )
    };
    // SAFETY: key was opened successfully above and is closed exactly once.
    unsafe { RegCloseKey(key) };
    assert_eq!(query, 2, "owned HKCU Run value survived lifecycle teardown");
}

fn private_windows_path(path: &Path, directory: bool) {
    use windows_permissions::constants::{SeObjectType, SecurityInformation};
    use windows_permissions::wrappers::{ConvertSidToStringSid, SetNamedSecurityInfo};
    use windows_permissions::{LocalBox, SecurityDescriptor};

    let current = windows_permissions::utilities::current_process_sid().expect("current SID");
    let sid = ConvertSidToStringSid(&current).expect("SID string");
    let inheritance = if directory { "OICI" } else { "" };
    let sddl = format!("D:P(A;{inheritance};FA;;;{})", sid.to_string_lossy());
    let descriptor: LocalBox<SecurityDescriptor> = sddl.parse().expect("protected private DACL");
    SetNamedSecurityInfo(
        path.as_os_str(),
        SeObjectType::SE_FILE_OBJECT,
        SecurityInformation::Owner | SecurityInformation::Dacl | SecurityInformation::ProtectedDacl,
        Some(current.as_ref()),
        None,
        Some(descriptor.dacl().expect("DACL")),
        None,
    )
    .expect("apply current-user-only DACL");
}

fn world_writable_windows_directory(path: &Path) {
    use windows_permissions::constants::{SeObjectType, SecurityInformation};
    use windows_permissions::wrappers::{ConvertSidToStringSid, SetNamedSecurityInfo};
    use windows_permissions::{LocalBox, SecurityDescriptor};

    let current = windows_permissions::utilities::current_process_sid().expect("current SID");
    let sid = ConvertSidToStringSid(&current).expect("SID string");
    let sddl = format!("D:P(A;OICI;FA;;;WD)(A;OICI;FA;;;{})", sid.to_string_lossy());
    let descriptor: LocalBox<SecurityDescriptor> = sddl.parse().expect("shared parent DACL");
    SetNamedSecurityInfo(
        path.as_os_str(),
        SeObjectType::SE_FILE_OBJECT,
        SecurityInformation::Owner | SecurityInformation::Dacl | SecurityInformation::ProtectedDacl,
        Some(current.as_ref()),
        None,
        Some(descriptor.dacl().expect("DACL")),
        None,
    )
    .expect("apply disposable world-writable DACL");
}

fn known_local_app_data() -> std::path::PathBuf {
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::{
        System::Com::CoTaskMemFree,
        UI::Shell::{FOLDERID_LocalAppData, SHGetKnownFolderPath},
    };

    let mut path = std::ptr::null_mut();
    // SAFETY: the known-folder GUID is static and the output pointer is writable.
    let result =
        unsafe { SHGetKnownFolderPath(&FOLDERID_LocalAppData, 0, std::ptr::null_mut(), &mut path) };
    assert!(
        result >= 0 && !path.is_null(),
        "resolve disposable LocalAppData"
    );
    // SAFETY: SHGetKnownFolderPath returns a NUL-terminated CoTaskMem allocation.
    unsafe {
        let mut length = 0usize;
        while *path.add(length) != 0 {
            length += 1;
        }
        let value = std::path::PathBuf::from(std::ffi::OsString::from_wide(
            std::slice::from_raw_parts(path, length),
        ));
        CoTaskMemFree(path.cast());
        value
    }
}

fn known_user_profile() -> std::path::PathBuf {
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::{
        System::Com::CoTaskMemFree,
        UI::Shell::{FOLDERID_Profile, SHGetKnownFolderPath},
    };
    let mut path = std::ptr::null_mut();
    // SAFETY: the known-folder GUID is static and the output pointer is writable.
    let result =
        unsafe { SHGetKnownFolderPath(&FOLDERID_Profile, 0, std::ptr::null_mut(), &mut path) };
    assert!(
        result >= 0 && !path.is_null(),
        "resolve current user profile"
    );
    // SAFETY: SHGetKnownFolderPath returns a NUL-terminated CoTaskMem allocation.
    unsafe {
        let mut length = 0usize;
        while *path.add(length) != 0 {
            length += 1;
        }
        let value = std::path::PathBuf::from(std::ffi::OsString::from_wide(
            std::slice::from_raw_parts(path, length),
        ));
        CoTaskMemFree(path.cast());
        value
    }
}
