#![cfg(target_os = "linux")]

use hostlink_agent::durable::{Admission, DurableStore, JobId, JobSpec, JobState};
use std::{fs, os::unix::fs::PermissionsExt, path::Path, process::Command};
use tempfile::TempDir;

fn fixture() -> (
    TempDir,
    std::path::PathBuf,
    std::path::PathBuf,
    std::path::PathBuf,
) {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("home");
    let root = home.join(".local/share/hostlink/new-agent");
    let bin_dir = temp.path().join("bin");
    let config_home = home.join(".config");
    fs::create_dir_all(&root).unwrap();
    fs::create_dir_all(&bin_dir).unwrap();
    fs::create_dir_all(&config_home).unwrap();
    fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let executable = root.join("bin/hostlink-agent");
    fs::create_dir(root.join("bin")).unwrap();
    fs::set_permissions(root.join("bin"), fs::Permissions::from_mode(0o700)).unwrap();
    let built_agent = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("hostlink-agent");
    let help = Command::new(&built_agent).arg("--help").output().unwrap();
    assert!(
        String::from_utf8_lossy(&help.stdout).contains("service"),
        "binary={} output={}",
        built_agent.display(),
        String::from_utf8_lossy(&help.stdout)
    );
    fs::copy(built_agent, &executable).unwrap();
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
    let config = root.join("state/agent.json");
    fs::create_dir_all(config.parent().unwrap()).unwrap();
    fs::set_permissions(config.parent().unwrap(), fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(&config, br#"{"listen":"127.0.0.1:39427","user":"fixture","host_key":"host_key","authorized_keys":"authorized_keys","jobs_root":"jobs","gateway":null}"#).unwrap();
    fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).unwrap();
    write_enrollment_fixture(config.parent().unwrap());
    fs::create_dir(root.join("state/jobs")).unwrap();
    fs::set_permissions(root.join("state/jobs"), fs::Permissions::from_mode(0o700)).unwrap();
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(async {
                        DurableStore::initialize_fresh(root.join("state/jobs"))
                            .await
                            .unwrap()
                            .close()
                            .await;
                    });
            })
            .join()
            .unwrap();
    });
    let runtime = temp.path().join("runtime");
    fs::create_dir(&runtime).unwrap();
    fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700)).unwrap();
    let fake_systemctl = bin_dir.join("systemctl");
    fs::write(
        &fake_systemctl,
        r##"#!/bin/sh
set -eu
printf '%s\n' "$*" >> "$FIXTURE_SYSTEMCTL_LOG"
case "${1-}" in
  show) printf 'ActiveState=inactive\nMainPID=0\n' ;;
esac
if [ "${2-}" = "--version" ]; then printf 'systemd 255\n'; fi
"##,
    )
    .unwrap();
    fs::set_permissions(&fake_systemctl, fs::Permissions::from_mode(0o700)).unwrap();
    (temp, home, root, config)
}

fn invoke(binary: &Path, args: &[&str], home: &Path) -> std::process::Output {
    let temp = home.parent().unwrap();
    Command::new(binary)
        .args(["service"])
        .args(args)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("XDG_RUNTIME_DIR", temp.join("runtime"))
        .env(
            "PATH",
            format!("{}:/usr/bin:/bin", temp.join("bin").display()),
        )
        .env("FIXTURE_SYSTEMCTL_LOG", temp.join("systemctl.log"))
        .env("RUST_LOG", "error")
        .output()
        .unwrap()
}

fn write_enrollment_fixture(state: &Path) {
    use sha2::{Digest, Sha256};
    let machine_id = "00000000-0000-4000-8000-000000000001";
    fs::write(state.join("authorized_keys"), b"ssh-ed25519 AAAA fixture\n").unwrap();
    fs::write(
        state.join("gateway_host_key"),
        b"ssh-ed25519 AAAA gateway\n",
    )
    .unwrap();
    fs::write(state.join("gateway_identity"), b"fixture private key\n").unwrap();
    fs::write(state.join("host_key"), b"fixture host key\n").unwrap();
    fs::write(
        state.join("machine.json"),
        serde_json::json!({
            "format": 1,
            "machine_id": machine_id,
            "name": "fixture",
            "ssh_public_key": "ssh-ed25519 AAAA fixture",
            "ssh_host_public_key": "ssh-ed25519 AAAA host",
            "gateway": {"host": "127.0.0.1", "port": 22, "host_public_key": "ssh-ed25519 AAAA gateway"},
            "remote_port": 39427
        }).to_string(),
    ).unwrap();
    for entry in fs::read_dir(state).unwrap() {
        let path = entry.unwrap().path();
        if path.is_file() {
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
    }
    let mut files = serde_json::Map::new();
    for name in [
        "agent.json",
        "authorized_keys",
        "gateway_host_key",
        "gateway_identity",
        "host_key",
        "machine.json",
    ] {
        let bytes = fs::read(state.join(name)).unwrap();
        files.insert(
            name.to_owned(),
            serde_json::json!({
                "size": bytes.len(),
                "sha256": format!("{:x}", Sha256::digest(&bytes))
            }),
        );
    }
    let manifest = serde_json::json!({"format": 1, "machine_id": machine_id, "files": files});
    fs::write(state.join("manifest.json"), manifest.to_string()).unwrap();
    fs::set_permissions(
        state.join("manifest.json"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
}

#[tokio::test]
async fn service_commands_bind_private_unit_to_root_and_remove_only_service_metadata() {
    let (_temp, home, root, config) = fixture();
    let args = [
        "install",
        "--root",
        root.to_str().unwrap(),
        "--config",
        config.to_str().unwrap(),
    ];
    let output = invoke(&root.join("bin/hostlink-agent"), &args, &home);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let unit_dir = home.join(".config/systemd/user");
    let mut units = fs::read_dir(&unit_dir).unwrap();
    let unit_path = units.next().unwrap().unwrap().path();
    assert!(units.next().is_none(), "one install root creates one unit");
    let unit = fs::read_to_string(&unit_path).unwrap();
    assert!(
        unit.contains(
            "Restart=on-failure\nRestartSec=15s\nRestartSteps=4\nRestartMaxDelaySec=240s"
        )
    );
    assert!(unit.contains(root.to_str().unwrap()));
    assert!(unit.contains("WantedBy=default.target"));
    assert!(!unit.contains("enable-linger"));

    let machine_file = root.join("state/machine.json");
    let saved_machine = fs::read(&machine_file).unwrap();
    let mut machine: serde_json::Value = serde_json::from_slice(&saved_machine).unwrap();
    machine["name"] = serde_json::json!("modified");
    fs::write(&machine_file, machine.to_string()).unwrap();
    let tampered = invoke(
        &root.join("bin/hostlink-agent"),
        &["stop", "--root", root.to_str().unwrap()],
        &home,
    );
    assert!(!tampered.status.success());
    assert!(String::from_utf8_lossy(&tampered.stderr).contains("does not match its manifest"));
    fs::write(&machine_file, saved_machine).unwrap();
    fs::set_permissions(&machine_file, fs::Permissions::from_mode(0o600)).unwrap();

    let jobs_root = root.join("state/jobs");
    let store = DurableStore::open(&jobs_root).await.unwrap();
    let id = JobId::new();
    let admitted = store
        .admit(
            id,
            &"a".repeat(64),
            &JobSpec {
                program: "disposable-fixture".into(),
                args: Vec::new(),
                cwd: None,
                source_sha256: "b".repeat(64),
            },
        )
        .await
        .unwrap();
    assert!(matches!(admitted, Admission::Created(_)));
    for cmd in ["stop", "remove"] {
        let blocked = invoke(
            &root.join("bin/hostlink-agent"),
            &[cmd, "--root", root.to_str().unwrap()],
            &home,
        );
        assert!(!blocked.status.success());
        assert!(String::from_utf8_lossy(&blocked.stderr).contains("durable jobs"));
    }
    store
        .transition(id, &"a".repeat(64), JobState::Prepared, JobState::Failed)
        .await
        .unwrap();

    let status = invoke(
        &root.join("bin/hostlink-agent"),
        &["status", "--root", root.to_str().unwrap()],
        &home,
    );
    assert!(
        !status.status.success(),
        "inactive service must not report healthy"
    );
    assert!(
        String::from_utf8_lossy(&status.stdout).contains("installed but service is not active")
    );
    assert!(
        String::from_utf8_lossy(&status.stdout)
            .contains("local_enrollment_metadata=true hub_reachability=not_checked")
    );

    for cmd in ["start", "stop"] {
        let output = invoke(
            &root.join("bin/hostlink-agent"),
            &[cmd, "--root", root.to_str().unwrap()],
            &home,
        );
        assert!(
            output.status.success(),
            "{}: {}",
            cmd,
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let remove = invoke(
        &root.join("bin/hostlink-agent"),
        &["remove", "--root", root.to_str().unwrap()],
        &home,
    );
    assert!(
        remove.status.success(),
        "{}",
        String::from_utf8_lossy(&remove.stderr)
    );
    assert!(!unit_path.exists());
    assert!(!root.join(".hostlink-user-service.json").exists());
    assert!(
        !root.join("bin/hostlink-agent").exists(),
        "remove uninstalls the owned executable"
    );
    assert!(
        config.exists(),
        "uninstall leaves enrollment data for recovery"
    );
    let log = fs::read_to_string(home.parent().unwrap().join("systemctl.log")).unwrap();
    assert!(log.contains("--user daemon-reload"));
    assert!(log.contains("--user enable "));
    assert!(log.contains("--user disable "));
}

#[test]
fn service_rejects_symlink_root_and_unmanaged_unit_collision() {
    let (_temp, home, root, config) = fixture();
    let link = home.join("root-link");
    std::os::unix::fs::symlink(&root, &link).unwrap();
    let output = invoke(
        &root.join("bin/hostlink-agent"),
        &[
            "install",
            "--root",
            link.to_str().unwrap(),
            "--config",
            config.to_str().unwrap(),
        ],
        &home,
    );
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("must not be a symlink"));

    let foreign_root = home.join("foreign");
    fs::create_dir(&foreign_root).unwrap();
    fs::set_permissions(&foreign_root, fs::Permissions::from_mode(0o700)).unwrap();
    let suffix = {
        use sha2::{Digest, Sha256};
        let b = Sha256::digest(
            foreign_root
                .canonicalize()
                .unwrap()
                .as_os_str()
                .as_encoded_bytes(),
        );
        b[..10]
            .iter()
            .map(|v| format!("{v:02x}"))
            .collect::<String>()
    };
    let unit_dir = home.join(".config/systemd/user");
    fs::create_dir_all(&unit_dir).unwrap();
    let collision = unit_dir.join(format!("hostlink-agent-{suffix}.service"));
    fs::write(&collision, "foreign unit\n").unwrap();
    fs::create_dir(foreign_root.join("bin")).unwrap();
    fs::set_permissions(foreign_root.join("bin"), fs::Permissions::from_mode(0o700)).unwrap();
    let binary = foreign_root.join("bin/hostlink-agent");
    let built_agent = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("hostlink-agent");
    fs::copy(built_agent, &binary).unwrap();
    fs::set_permissions(&binary, fs::Permissions::from_mode(0o700)).unwrap();
    fs::create_dir(foreign_root.join("state")).unwrap();
    fs::set_permissions(
        foreign_root.join("state"),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    let cfg = foreign_root.join("state/agent.json");
    fs::write(&cfg, fs::read(config).unwrap()).unwrap();
    fs::set_permissions(&cfg, fs::Permissions::from_mode(0o600)).unwrap();
    write_enrollment_fixture(cfg.parent().unwrap());
    let output = invoke(
        &binary,
        &[
            "install",
            "--root",
            foreign_root.to_str().unwrap(),
            "--config",
            cfg.to_str().unwrap(),
        ],
        &home,
    );
    assert!(
        !output.status.success(),
        "must not overwrite a colliding unit"
    );
    assert_eq!(fs::read_to_string(collision).unwrap(), "foreign unit\n");
}
