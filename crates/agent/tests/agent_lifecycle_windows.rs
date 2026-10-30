#![cfg(windows)]

use hostlink_agent::jobs::JobStore;
use russh::keys::{Algorithm, PrivateKey, ssh_key::LineEnding};
use serde_json::{Map, json};
use sha2::{Digest, Sha256};
use std::{fs, path::Path, process::Command};

// This test creates one root-derived current-user Task Scheduler task.
// Keep it ignored by default; run only in a disposable, non-elevated Windows profile.
#[tokio::test]
#[ignore = "requires HOSTLINK_WINDOWS_LIFECYCLE_DISPOSABLE=1 and a disposable Windows user profile"]
async fn current_user_lifecycle_installs_reports_and_removes_only_its_disposable_root() {
    assert_eq!(
        std::env::var("HOSTLINK_WINDOWS_LIFECYCLE_DISPOSABLE").as_deref(),
        Ok("1"),
        "refusing to change Task Scheduler without an explicit disposable-profile guard"
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
                "ssh_host_public_key": "ssh-ed25519 AAAA host",
                "gateway": {
                    "host": "127.0.0.1",
                    "port": 22,
                    "user": "fixture",
                    "host_public_key": "ssh-ed25519 AAAA gateway"
                },
                "remote_port": 39427
            })
            .to_string()
            .into_bytes(),
        ),
    ];
    let mut files = Map::new();
    for (name, bytes) in &payloads {
        fs::write(state.join(name), bytes).expect("write enrollment fixture");
        private_windows_path(&state.join(name), false);
        files.insert(
            (*name).to_owned(),
            json!({
                "size": bytes.len(),
                "sha256": format!("{:x}", Sha256::digest(bytes))
            }),
        );
    }
    fs::write(
        state.join("manifest.json"),
        json!({ "format": 1, "machine_id": machine_id, "name": "lifecycle-fixture", "files": files }).to_string(),
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
    let unrelated = hostlink_agent::service::status(&wrong_root).unwrap();
    assert!(!unrelated.installed && !unrelated.active);
    for action in ["start", "stop", "remove"] {
        assert!(
            !service_output(source_agent, &wrong_root, action, None)
                .status
                .success()
        );
    }

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
    assert!(String::from_utf8_lossy(&refused.stderr).contains("private"));

    // A private Agent directory inside LocalAppData is insufficient when its
    // immediate parent can be renamed or replaced by another local user.
    let shared_profile_parent = local_app_data.join(format!(
        "HostLink Untrusted Parent {}",
        uuid::Uuid::new_v4()
    ));
    fs::create_dir(&shared_profile_parent).unwrap();
    let _shared_cleanup = ProfileFixture(shared_profile_parent.clone());
    world_writable_windows_directory(&shared_profile_parent);
    let shared_root = shared_profile_parent.join("Agent");
    fs::create_dir(&shared_root).unwrap();
    private_windows_path(&shared_root, true);
    let shared_install = service_output(
        source_agent,
        &shared_root,
        "install",
        Some(&shared_root.join("state/agent.json")),
    );
    private_windows_path(&shared_profile_parent, true);
    fs::remove_dir(&shared_root).unwrap();
    assert!(
        !shared_install.status.success(),
        "install must reject a replaceable parent even inside LocalAppData"
    );

    let _cleanup = CleanupService {
        executable: source_agent.to_path_buf(),
        root: root.clone(),
    };
    service(
        &executable,
        &root,
        "install",
        Some(&state.join("agent.json")),
    );
    service(
        &executable,
        &root,
        "install",
        Some(&state.join("agent.json")),
    );
    assert!(!root.join(".hostlink-user-service.json").exists());
    assert!(!root.join(".hostlink-agent-start.vbs").exists());
    let stopped = hostlink_agent::service::status(&root).unwrap();
    assert!(stopped.installed && !stopped.active);

    // Status reads the Scheduler registration; a changed filesystem DACL
    // must not prevent the owner from inspecting/removing the registration.
    world_writable_windows_directory(&root);
    assert!(hostlink_agent::service::status(&root).unwrap().installed);
    assert!(
        !service_output(&executable, &root, "start", None)
            .status
            .success(),
        "an untrusted installation must not be started"
    );
    private_windows_path(&root, true);

    let scheduler = NativeScheduler::connect();
    let name = task_name(&root);
    // SAFETY: the fixture uses a live local Scheduler and its unique task name.
    let task = unsafe { scheduler.folder.GetTask(&name.clone().into()).unwrap() };
    // SAFETY: read-only query of the fixture task.
    let original_xml = unsafe { task.Xml().unwrap().to_string() };
    let xml = roxmltree::Document::parse(&original_xml).unwrap();
    let value = |name| {
        xml.descendants()
            .find(|n| n.has_tag_name(name))
            .unwrap()
            .text()
            .unwrap()
    };
    assert_eq!(value("LogonType"), "InteractiveToken");
    assert_eq!(value("RunLevel"), "LeastPrivilege");
    assert_eq!(value("MultipleInstancesPolicy"), "IgnoreNew");
    assert_eq!(value("ExecutionTimeLimit"), "PT0S");
    let sid = windows_permissions::utilities::current_process_sid()
        .unwrap()
        .to_string();
    for user in xml.descendants().filter(|n| n.has_tag_name("UserId")) {
        assert_eq!(user.text(), Some(sid.as_str()));
    }
    assert_eq!(
        value("Command"),
        root.canonicalize()
            .unwrap()
            .join("bin/hostlink-agent.exe")
            .to_str()
            .unwrap()
    );
    assert_eq!(
        value("Arguments"),
        format!(
            r#"run --config="{}""#,
            root.canonicalize()
                .unwrap()
                .join("state/agent.json")
                .display()
        )
    );
    assert_eq!(
        xml.descendants()
            .filter(|n| n.has_tag_name("LogonTrigger"))
            .count(),
        1
    );
    assert!(value("Arguments").starts_with("run --config="));
    assert!(!original_xml.contains("--managed-service"));

    // Each foreign definition is valid Scheduler XML, but is not our task.
    let stale = root.join(".hostlink-service-marker-fixture");
    for foreign_xml in [
        original_xml.replace("run --config=", "check --config="),
        original_xml.replace("hostlink-agent.exe</Command>", "foreign.exe</Command>"),
        original_xml.replace("agent.json", "foreign.json"),
        original_xml.replace("<RunLevel>LeastPrivilege", "<RunLevel>HighestAvailable"),
        original_xml.replace(
            "<MultipleInstancesPolicy>IgnoreNew",
            "<MultipleInstancesPolicy>Parallel",
        ),
        original_xml.replace(
            "</Exec>",
            r"<WorkingDirectory>C:\foreign</WorkingDirectory></Exec>",
        ),
        original_xml.replacen(&sid, "S-1-5-18", 1),
        original_xml.replace(
            "</Actions>",
            &format!(
                "<Exec><Command>{}</Command></Exec></Actions>",
                value("Command").replace('&', "&amp;")
            ),
        ),
    ] {
        assert_ne!(foreign_xml, original_xml, "tamper fixture must alter XML");
        scheduler.replace(&name, &foreign_xml);
        let foreign_before = scheduler.xml(&name);
        let output = service_output(
            &executable,
            &root,
            "install",
            Some(&state.join("agent.json")),
        );
        assert!(
            !output.status.success(),
            "install overwrote a foreign definition"
        );
        fs::write(&stale, b"legacy fixture").unwrap();
        for action in ["start", "stop", "remove"] {
            let output = service_output(&executable, &root, action, None);
            assert!(
                !output.status.success(),
                "{action} accepted a foreign definition"
            );
            assert!(!String::from_utf8_lossy(&output.stderr).contains("legacy"));
        }
        assert!(hostlink_agent::service::status(&root).is_err());
        assert_eq!(scheduler.xml(&name), foreign_before);
        assert_eq!(fs::read(&stale).unwrap(), b"legacy fixture");
        fs::remove_file(&stale).unwrap();
        scheduler.replace(&name, &original_xml);
    }

    // Scheduler may serialize defaults or an operator may disable/delay logon.
    // These do not change execution ownership and must not prevent cleanup.
    let normalized = original_xml
        .replace("</Exec>", "<WorkingDirectory></WorkingDirectory></Exec>")
        .replace("</LogonTrigger>", "<Delay>PT0S</Delay></LogonTrigger>")
        .replace("<Enabled>true</Enabled>", "<Enabled>false</Enabled>");
    scheduler.replace(&name, &normalized);
    // An owned task is refreshed in place, without a second running Agent.
    service(
        &executable,
        &root,
        "install",
        Some(&state.join("agent.json")),
    );
    assert!(hostlink_agent::service::status(&root).unwrap().installed);
    assert!(!hostlink_agent::service::status(&root).unwrap().active);
    scheduler.replace(&name, &normalized);
    let normalized = scheduler.xml(&name);
    assert!(hostlink_agent::service::status(&root).unwrap().installed);
    service(&executable, &root, "stop", None);
    assert_eq!(scheduler.xml(&name), normalized);
    scheduler.replace(&name, &original_xml);

    // Registration ownership is independent of executable/enrollment hashes.
    // Neither status nor stop needs to read the installed executable or config.
    let moved_executable = bin.join("saved-agent.exe");
    let moved_config = state.join("saved-agent.json");
    fs::rename(&executable, &moved_executable).unwrap();
    fs::rename(state.join("agent.json"), &moved_config).unwrap();
    assert!(hostlink_agent::service::status(&root).unwrap().installed);
    hostlink_agent::service::stop(&root).unwrap();
    fs::rename(moved_executable, &executable).unwrap();
    fs::rename(moved_config, state.join("agent.json")).unwrap();

    for name in [
        ".hostlink-user-service.json",
        ".hostlink-agent-start.vbs",
        ".hostlink-maintenance-admission.json",
        ".hostlink-service-marker-fixture",
    ] {
        let legacy = root.join(name);
        fs::write(&legacy, b"legacy fixture").unwrap();
        service(
            &executable,
            &root,
            "install",
            Some(&state.join("agent.json")),
        );
        assert!(hostlink_agent::service::status(&root).unwrap().installed);
        service(&executable, &root, "start", None);
        service(&executable, &root, "stop", None);
        assert!(!hostlink_agent::service::status(&root).unwrap().active);
        assert_eq!(fs::read(&legacy).unwrap(), b"legacy fixture");
        assert_eq!(scheduler.xml(&task_name(&root)), original_xml);
        service(&executable, &root, "start", None);
        service(&executable, &root, "remove", None);
        assert!(!hostlink_agent::service::status(&root).unwrap().installed);
        assert_eq!(fs::read(&legacy).unwrap(), b"legacy fixture");
        service(
            &executable,
            &root,
            "install",
            Some(&state.join("agent.json")),
        );
        fs::remove_file(legacy).unwrap();
        service(
            &executable,
            &root,
            "install",
            Some(&state.join("agent.json")),
        );
    }

    {
        let legacy_run = LegacyRun::create(&root);
        let refused = service_output(
            &executable,
            &root,
            "install",
            Some(&state.join("agent.json")),
        );
        assert!(!refused.status.success());
        assert!(String::from_utf8_lossy(&refused.stderr).contains("old HKCU Run"));
        assert_eq!(scheduler.xml(&name), original_xml);
        legacy_run.assert_unchanged();
    }

    let updates = root.join(".updates");
    let lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(root.join("update.lock"))
        .unwrap();
    lock.try_lock().unwrap();
    for action in ["install", "start", "stop", "remove"] {
        let config = (action == "install").then(|| state.join("agent.json"));
        assert!(
            !service_output(&executable, &root, action, config.as_deref())
                .status
                .success()
        );
    }
    assert!(hostlink_agent::service::status(&root).unwrap().installed);
    assert_eq!(scheduler.xml(&name), original_xml);
    drop(lock);
    fs::create_dir(&updates).unwrap();
    private_windows_path(&updates, true);
    let journal = updates.join("handoff.json");
    // Even an unreadable/malformed pending transaction must block launch.
    fs::write(&journal, b"pending fixture journal").unwrap();
    private_windows_path(&journal, false);
    for action in ["install", "start"] {
        let config = (action == "install").then(|| state.join("agent.json"));
        let refused = service_output(&executable, &root, action, config.as_deref());
        assert!(!refused.status.success());
        assert!(String::from_utf8_lossy(&refused.stderr).contains("journal"));
    }
    assert_eq!(fs::read(&journal).unwrap(), b"pending fixture journal");
    assert_eq!(scheduler.xml(&name), original_xml);
    fs::remove_file(journal).unwrap();
    fs::remove_dir(updates).unwrap();

    service(&executable, &root, "stop", None); // Already stopped is valid.
    service(&executable, &root, "remove", None); // Idle removal needs no PID.
    assert!(!hostlink_agent::service::status(&root).unwrap().installed);
    for action in ["stop", "remove"] {
        assert!(
            !service_output(&executable, &root, action, None)
                .status
                .success()
        );
    }
    service(
        &executable,
        &root,
        "install",
        Some(&state.join("agent.json")),
    );
    for _ in 0..2 {
        service(&executable, &root, "start", None);
    }
    let mut healthy = false;
    for _ in 0..100 {
        let status = hostlink_agent::service::status(&root).unwrap();
        if status.active && ssh_banner(listen_port) {
            healthy = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    assert!(
        healthy,
        "Scheduler activation must eventually expose the Agent SSH banner"
    );
    // SAFETY: read-only OS instance count, no PID-based ownership.
    assert_eq!(
        unsafe {
            scheduler
                .folder
                .GetTask(&name.clone().into())
                .unwrap()
                .GetInstances(0)
                .unwrap()
                .Count()
                .unwrap()
        },
        1
    );
    // Reinstalling the already running, owned task stops it and refreshes its
    // registration, but never starts another process automatically.
    service(
        &executable,
        &root,
        "install",
        Some(&state.join("agent.json")),
    );
    assert!(hostlink_agent::service::status(&root).unwrap().installed);
    assert!(!hostlink_agent::service::status(&root).unwrap().active);
    assert!(std::net::TcpStream::connect(("127.0.0.1", listen_port)).is_err());
    service(&executable, &root, "stop", None);
    assert!(!hostlink_agent::service::status(&root).unwrap().active);
    assert!(std::net::TcpStream::connect(("127.0.0.1", listen_port)).is_err());
    service(&executable, &root, "start", None);
    service(&executable, &root, "remove", None);
    assert!(!hostlink_agent::service::status(&root).unwrap().installed);
    assert!(executable.is_file());
    assert!(root.join("jobs").is_dir());
    for (name, bytes) in &payloads {
        assert_eq!(fs::read(state.join(name)).unwrap(), *bytes);
    }
    fs::remove_dir_all(&private_parent).unwrap();
}

fn service(executable: &Path, root: &Path, action: &str, config: Option<&Path>) {
    let output = service_output(executable, root, action, config);
    assert!(
        output.status.success(),
        "{action}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
fn service_output(
    executable: &Path,
    root: &Path,
    action: &str,
    config: Option<&Path>,
) -> std::process::Output {
    let mut cmd = Command::new(executable);
    cmd.args(["service", action, "--root"]).arg(root);
    if let Some(config) = config {
        cmd.arg("--config").arg(config);
    }
    cmd.output().unwrap()
}
fn ssh_banner(port: u16) -> bool {
    use std::{
        io::Read,
        net::{Ipv4Addr, SocketAddr, TcpStream},
        time::Duration,
    };
    let Ok(mut stream) = TcpStream::connect_timeout(
        &SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
        Duration::from_millis(100),
    ) else {
        return false;
    };
    stream
        .set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    let mut banner = [0; 8];
    stream.read_exact(&mut banner).is_ok() && &banner == b"SSH-2.0-"
}
fn task_name(root: &Path) -> String {
    let root = root.canonicalize().unwrap();
    let digest = format!("{:x}", Sha256::digest(root.to_string_lossy().as_bytes()));
    format!(
        "HostLinkAgent-v2-{}-{}",
        windows_permissions::utilities::current_process_sid().unwrap(),
        &digest[..24]
    )
}
struct NativeScheduler {
    folder: windows::Win32::System::TaskScheduler::ITaskFolder,
}
impl NativeScheduler {
    fn xml(&self, name: &str) -> String {
        // SAFETY: read-only query of the guarded, unique fixture task.
        unsafe {
            self.folder
                .GetTask(&name.into())
                .unwrap()
                .Xml()
                .unwrap()
                .to_string()
        }
    }
    fn connect() -> Self {
        use windows::Win32::System::Variant::VARIANT;
        use windows::Win32::System::{Com::*, TaskScheduler::*};
        // SAFETY: initialize this test thread; interfaces remain on this thread.
        unsafe {
            CoInitializeEx(None, COINIT_MULTITHREADED).ok().unwrap();
            let service: ITaskService =
                CoCreateInstance(&TaskScheduler, None, CLSCTX_INPROC_SERVER).unwrap();
            let empty = VARIANT::default();
            service.Connect(&empty, &empty, &empty, &empty).unwrap();
            Self {
                folder: service.GetFolder(&"\\".into()).unwrap(),
            }
        }
    }
    fn replace(&self, name: &str, xml: &str) {
        use windows::Win32::System::{TaskScheduler::*, Variant::VARIANT};
        let empty = VARIANT::default();
        // SAFETY: guarded disposable test modifies only the exact fixture task.
        unsafe {
            self.folder
                .RegisterTask(
                    &name.into(),
                    &xml.into(),
                    TASK_UPDATE.0,
                    &empty,
                    &empty,
                    TASK_LOGON_INTERACTIVE_TOKEN,
                    &empty,
                )
                .unwrap();
        }
    }
}
// COM apartment intentionally remains initialized until the disposable test thread exits.
// Only the ignored, disposable-profile fixture writes the unique legacy Run
// value. Production lifecycle detection is read-only and must preserve it.
struct LegacyRun {
    key: windows_sys::Win32::System::Registry::HKEY,
    name: Vec<u16>,
    owns_value: bool,
}
impl LegacyRun {
    fn assert_unchanged(&self) {
        use windows_sys::Win32::System::Registry::*;
        let mut data = [0u16; 15];
        let mut size = 30;
        let mut kind = 0;
        // SAFETY: live query handle and writable terminated UTF-16 buffer.
        assert_eq!(
            unsafe {
                RegQueryValueExW(
                    self.key,
                    self.name.as_ptr(),
                    std::ptr::null(),
                    &mut kind,
                    data.as_mut_ptr().cast(),
                    &mut size,
                )
            },
            0
        );
        assert_eq!(kind, REG_SZ);
        assert_eq!(size, 30);
        assert_eq!(
            data.to_vec(),
            "legacy fixture"
                .encode_utf16()
                .chain(Some(0))
                .collect::<Vec<_>>()
        );
    }
    fn create(root: &Path) -> Self {
        use windows_sys::Win32::System::Registry::*;
        let key_name: Vec<_> = r"Software\Microsoft\Windows\CurrentVersion\Run"
            .encode_utf16()
            .chain(Some(0))
            .collect();
        let root = root.canonicalize().unwrap();
        let digest = format!("{:x}", Sha256::digest(root.to_string_lossy().as_bytes()));
        let name: Vec<_> = format!("HostLinkAgent-{}", &digest[..24])
            .encode_utf16()
            .chain(Some(0))
            .collect();
        let mut key = std::ptr::null_mut();
        // SAFETY: guarded disposable HKCU; owned strings and output buffers.
        assert_eq!(
            unsafe {
                RegCreateKeyExW(
                    HKEY_CURRENT_USER,
                    key_name.as_ptr(),
                    0,
                    std::ptr::null(),
                    REG_OPTION_NON_VOLATILE,
                    KEY_QUERY_VALUE | KEY_SET_VALUE,
                    std::ptr::null(),
                    &mut key,
                    std::ptr::null_mut(),
                )
            },
            0
        );
        let mut fixture = Self {
            key,
            name,
            owns_value: false,
        };
        // SAFETY: live handle; existence-only query, no value is overwritten.
        assert_eq!(
            unsafe {
                RegQueryValueExW(
                    key,
                    fixture.name.as_ptr(),
                    std::ptr::null(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            },
            2,
            "refusing to overwrite an existing Run value"
        );
        let data: Vec<_> = "legacy fixture".encode_utf16().chain(Some(0)).collect();
        // SAFETY: byte view covers the complete terminated UTF-16 buffer.
        assert_eq!(
            unsafe {
                RegSetValueExW(
                    key,
                    fixture.name.as_ptr(),
                    0,
                    REG_SZ,
                    data.as_ptr().cast(),
                    u32::try_from(data.len() * 2).unwrap(),
                )
            },
            0
        );
        fixture.owns_value = true;
        fixture
    }
}
impl Drop for LegacyRun {
    fn drop(&mut self) {
        use windows_sys::Win32::System::Registry::*;
        // SAFETY: deletes only the unique value this fixture created, then closes
        // its handle. Never delete the shared Run key, even if we created it.
        unsafe {
            if self.owns_value {
                assert_eq!(RegDeleteValueW(self.key, self.name.as_ptr()), 0);
            }
            RegCloseKey(self.key);
        }
    }
}
struct CleanupService {
    executable: std::path::PathBuf,
    root: std::path::PathBuf,
}
impl Drop for CleanupService {
    fn drop(&mut self) {
        // Preserve the root on failure; never erase unresolved scheduler/process state.
        let _ = Command::new(&self.executable)
            .args(["service", "remove", "--root"])
            .arg(&self.root)
            .output();
    }
}
struct ProfileFixture(std::path::PathBuf);
impl Drop for ProfileFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir(&self.0);
    }
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
    known_folder(0x1c)
}
fn known_user_profile() -> std::path::PathBuf {
    known_folder(0x28)
}
fn known_folder(folder: i32) -> std::path::PathBuf {
    use std::os::windows::ffi::OsStringExt;
    let mut buffer = [0u16; 260];
    // SAFETY: caller-owned MAX_PATH buffer; null token selects current user.
    assert!(
        unsafe {
            windows_sys::Win32::UI::Shell::SHGetFolderPathW(
                std::ptr::null_mut(),
                folder,
                std::ptr::null_mut(),
                0,
                buffer.as_mut_ptr(),
            )
        } >= 0
    );
    let len = buffer.iter().position(|c| *c == 0).unwrap();
    std::path::PathBuf::from(std::ffi::OsString::from_wide(&buffer[..len]))
}
