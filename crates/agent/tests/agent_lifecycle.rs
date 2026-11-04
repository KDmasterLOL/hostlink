#![cfg(target_os = "linux")]

use sha2::{Digest, Sha256};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Output},
};
use tempfile::TempDir;

fn fixture(name: &str) -> (TempDir, PathBuf, PathBuf) {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("home");
    let root = home.join(name);
    for dir in [
        &home,
        &root,
        &root.join("bin"),
        &root.join("state"),
        &home.join(".config"),
        &temp.path().join("bin"),
        &temp.path().join("runtime"),
    ] {
        fs::create_dir_all(dir).unwrap();
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let binary = root.join("bin/hostlink-agent");
    // Keep the writable executable descriptor out of this multithreaded test
    // process. A concurrent fork can otherwise inherit it until exec, causing
    // ETXTBSY even after fs::copy has returned and closed its own descriptor.
    let copy = Command::new("cp")
        .arg(env!("CARGO_BIN_EXE_hostlink-agent"))
        .arg(&binary)
        .status()
        .expect("start fixture binary copy");
    assert!(copy.success(), "fixture binary copy failed: {copy}");
    fs::set_permissions(binary, fs::Permissions::from_mode(0o700)).unwrap();
    // Service lifecycle treats these as opaque data, including the jobs store.
    for name in ["agent.json", "host_key", "machine.json", "jobs.db"] {
        let path = root.join("state").join(name);
        fs::write(&path, b"preserve this data\n").unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let systemctl = temp.path().join("bin/systemctl");
    // Synchronous state fixture only: no daemon, SSH endpoint or signal emulation.
    fs::write(
        &systemctl,
        r##"#!/bin/sh
set -eu
printf '%s\n' "$*" >> "$FIXTURE_LOG"
[ "${1-}" = --user ] || exit 2
if [ -f "$FIXTURE_LOG.fail" ] && [ "${2-}" = "$(cat "$FIXTURE_LOG.fail")" ]; then exit 1; fi
case "${3-}" in
  /*) unit=$3 ;;
  *) unit="$XDG_CONFIG_HOME/systemd/user/${3-}.service" ;;
esac
case "${2-}" in
  status)
    if [ -f "$FIXTURE_LOG.race" ]; then
      mkdir -p "$(dirname "$unit")"
      printf 'foreign unit\n' > "$unit"
      exit 4
    fi
    [ -f "$unit" ] || exit 4
    [ -f "$FIXTURE_LOG.active" ] || exit 3 ;;
  start) [ -f "$unit" ] || exit 4; touch "$FIXTURE_LOG.active" ;;
  stop) [ -f "$unit" ] || exit 4; rm -f "$FIXTURE_LOG.active" ;;
  enable|disable) [ -f "$unit" ] || exit 4 ;;
  daemon-reload) ;;
  *) exit 2 ;;
esac
"##,
    )
    .unwrap();
    fs::set_permissions(systemctl, fs::Permissions::from_mode(0o700)).unwrap();
    (temp, home, root)
}

fn command(home: &Path, root: &Path, action: &str) -> Command {
    let temp = home.parent().unwrap();
    let mut command = Command::new(root.join("bin/hostlink-agent"));
    command.args(["service", action, "--root"]).arg(root);
    if action == "install" {
        command.arg("--config").arg(root.join("state/agent.json"));
    }
    command
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("XDG_RUNTIME_DIR", temp.join("runtime"))
        .env(
            "PATH",
            format!("{}:/usr/bin:/bin", temp.join("bin").display()),
        )
        .env("FIXTURE_LOG", temp.join("systemctl.log"));
    command
}

fn run(home: &Path, root: &Path, action: &str) -> Output {
    command(home, root, action).output().unwrap()
}

fn success(home: &Path, root: &Path, action: &str) {
    let output = run(home, root, action);
    assert!(
        output.status.success(),
        "{action}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let expected = match action {
        "install" => "Installed user service",
        "start" => "Started hostlink-agent-",
        "stop" => "Stopped hostlink-agent-",
        "remove" => "Unregistered user service",
        _ => unreachable!("unknown lifecycle operation"),
    };
    assert!(
        String::from_utf8_lossy(&output.stdout).contains(expected),
        "unexpected {action} output: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}

fn unit_path(home: &Path, root: &Path) -> PathBuf {
    let hash = Sha256::digest(root.canonicalize().unwrap().as_os_str().as_encoded_bytes());
    home.join(".config/systemd/user").join(format!(
        "hostlink-agent-{}.service",
        &format!("{hash:x}")[..20]
    ))
}

fn status(home: &Path, root: &Path, installed: bool, active: bool) {
    let output = run(home, root, "status");
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains(&format!("installed={installed} active={active}"))
    );
    assert_eq!(output.status.success(), installed && active);
}

fn refused(home: &Path, root: &Path) {
    let log = home.parent().unwrap().join("systemctl.log");
    let before = fs::read(&log).unwrap_or_default();
    for action in ["install", "start", "stop", "status", "remove"] {
        assert!(!run(home, root, action).status.success(), "{action}");
    }
    assert_eq!(fs::read(log).unwrap_or_default(), before);
}

#[test]
fn lifecycle_preserves_v2_unit_bytes_and_all_agent_data() {
    let (_temp, home, root) = fixture("agent");
    status(&home, &root, false, false);
    success(&home, &root, "install");
    let path = unit_path(&home, &root);
    let expected = format!(
        "[Unit]\nDescription=HostLink Agent ({})\nStartLimitIntervalSec=300\nStartLimitBurst=5\n\
         \n[Service]\nType=simple\nExecStart=\"{}/bin/hostlink-agent\" run --config=\"{}/state/agent.json\"\n\
         Restart=on-failure\nRestartSec=15s\n\
         \n[Install]\nWantedBy=default.target\n",
        path.file_name().unwrap().to_str().unwrap(),
        root.display(),
        root.display()
    );
    assert_eq!(fs::read_to_string(&path).unwrap(), expected);
    let log = home.parent().unwrap().join("systemctl.log");
    assert!(!fs::read_to_string(&log).unwrap().contains("--user start"));
    success(&home, &root, "install");
    status(&home, &root, true, false);
    success(&home, &root, "start");
    status(&home, &root, true, true); // Invalid JSON and no SSH listener are irrelevant.
    success(&home, &root, "stop");
    status(&home, &root, true, false);
    success(&home, &root, "stop");
    success(&home, &root, "start");
    let binary = fs::read(root.join("bin/hostlink-agent")).unwrap();
    success(&home, &root, "remove");
    assert!(!path.exists());
    status(&home, &root, false, false);
    assert_eq!(fs::read(root.join("bin/hostlink-agent")).unwrap(), binary);
    for name in ["agent.json", "host_key", "machine.json", "jobs.db"] {
        assert_eq!(
            fs::read(root.join("state").join(name)).unwrap(),
            b"preserve this data\n"
        );
    }
    let calls = fs::read_to_string(log).unwrap();
    assert!(calls.contains("--user enable ") && calls.contains("--user disable "));
    assert!(!calls.contains("linger"));
}

#[test]
fn private_root_legacy_marker_and_modified_unit_refuse_without_os_actions() {
    let (_temp, home, root) = fixture("agent");
    let link = home.join("root-link");
    std::os::unix::fs::symlink(&root, &link).unwrap();
    refused(&home, &link);
    fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
    refused(&home, &root);
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let marker = root.join(".hostlink-user-service.json");
    fs::write(&marker, b"legacy\n").unwrap();
    assert!(!run(&home, &root, "install").status.success());
    status(&home, &root, false, false);
    for action in ["start", "stop", "remove"] {
        assert!(!run(&home, &root, action).status.success());
    }
    let log = fs::read_to_string(home.parent().unwrap().join("systemctl.log")).unwrap();
    assert!(
        ![
            "--user enable",
            "--user start",
            "--user stop",
            "--user disable"
        ]
        .iter()
        .any(|action| log.contains(action))
    );
    assert_eq!(fs::read(&marker).unwrap(), b"legacy\n");
    fs::remove_file(marker).unwrap();
    success(&home, &root, "install");
    let path = unit_path(&home, &root);
    fs::write(&path, b"foreign unit\n").unwrap();
    refused(&home, &root);
    assert_eq!(fs::read(path).unwrap(), b"foreign unit\n");
}

#[test]
fn old_marker_does_not_block_uninstall_of_verified_user_unit() {
    let (_temp, home, root) = fixture("agent");
    success(&home, &root, "install");
    let marker = root.join(".hostlink-user-service.json");
    fs::write(&marker, b"legacy marker\n").unwrap();
    assert!(!run(&home, &root, "install").status.success());
    status(&home, &root, true, false);
    success(&home, &root, "start");
    success(&home, &root, "stop");
    success(&home, &root, "remove");
    assert_eq!(fs::read(&marker).unwrap(), b"legacy marker\n");
}

#[test]
fn dangling_and_racing_collisions_never_get_overwritten() {
    let (temp, home, root) = fixture("agent");
    let path = unit_path(&home, &root);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let target = home.join("absent");
    std::os::unix::fs::symlink(&target, &path).unwrap();
    refused(&home, &root);
    assert_eq!(fs::read_link(&path).unwrap(), target);
    assert!(!target.exists());
    fs::remove_file(&path).unwrap();
    fs::write(temp.path().join("systemctl.log.race"), b"").unwrap();
    assert!(!run(&home, &root, "install").status.success());
    assert_eq!(fs::read(path).unwrap(), b"foreign unit\n");
    assert!(
        !fs::read_to_string(temp.path().join("systemctl.log"))
            .unwrap()
            .contains("--user enable ")
    );
}

#[test]
fn special_paths_escape_quotes_backslashes_specifiers_and_environment_expansion() {
    let (_temp, home, root) = fixture("space %n ${USER} 'quote' \\\"x");
    success(&home, &root, "install");
    let unit = fs::read_to_string(unit_path(&home, &root)).unwrap();
    assert!(
        unit.contains("ExecStart=:\"") && unit.contains("%%n ${USER} 'quote' \\\\\\\"x"),
        "{unit}"
    );
    success(&home, &root, "start");
    status(&home, &root, true, true);
    success(&home, &root, "remove");
}

#[test]
fn os_failures_propagate_and_failed_stop_preserves_unit() {
    let (temp, home, root) = fixture("agent");
    let failure = temp.path().join("systemctl.log.fail");
    fs::write(&failure, "enable").unwrap();
    assert!(!run(&home, &root, "install").status.success());
    fs::remove_file(&failure).unwrap();
    success(&home, &root, "install");
    for action in ["status", "start", "stop", "disable"] {
        fs::write(&failure, action).unwrap();
        let command = if action == "disable" || action == "stop" {
            "remove"
        } else {
            action
        };
        assert!(!run(&home, &root, command).status.success());
        assert!(unit_path(&home, &root).is_file());
    }
    fs::remove_file(failure).unwrap();
    success(&home, &root, "remove");
}
