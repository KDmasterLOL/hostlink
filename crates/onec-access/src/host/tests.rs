//! OpenSSH projection and managed-include regression tests.

use super::*;
use crate::AppError;
use tempfile::tempdir;

fn io_error_kind(error: &AppError) -> Option<std::io::ErrorKind> {
    error.chain().find_map(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .map(std::io::Error::kind)
    })
}

#[test]
fn managed_include_accepts_exact_user_config_limit() {
    let dir = tempdir().expect("tempdir");
    let user = dir.path().join(".ssh/config");
    let generated = dir.path().join("onec-ops/ssh_config");
    fs::create_dir_all(user.parent().expect("parent")).expect("ssh dir");

    let include = format!("Include {}\n#", ssh_path(&generated).expect("ssh path"));
    assert!(include.len() < USER_SSH_CONFIG_MAX_BYTES);
    let mut config = include.into_bytes();
    config.resize(USER_SSH_CONFIG_MAX_BYTES, b'a');
    fs::write(&user, &config).expect("exact-limit config");

    install_managed_include(&user, &generated).expect("exact-limit config must be accepted");
    assert_eq!(fs::read(&user).expect("preserved config"), config);
}

#[test]
fn managed_include_rejects_user_config_one_byte_over_limit() {
    let dir = tempdir().expect("tempdir");
    let user = dir.path().join(".ssh/config");
    let generated = dir.path().join("onec-ops/ssh_config");
    fs::create_dir_all(user.parent().expect("parent")).expect("ssh dir");
    fs::write(&user, vec![b'#'; USER_SSH_CONFIG_MAX_BYTES + 1]).expect("oversized config");

    let error = install_managed_include(&user, &generated).expect_err("oversized config must fail");
    assert_eq!(io_error_kind(&error), Some(std::io::ErrorKind::InvalidData));
}

#[test]
fn managed_include_rejects_invalid_utf8_as_io_invalid_data() {
    let dir = tempdir().expect("tempdir");
    let user = dir.path().join(".ssh/config");
    let generated = dir.path().join("onec-ops/ssh_config");
    fs::create_dir_all(user.parent().expect("parent")).expect("ssh dir");
    fs::write(&user, [0xff]).expect("invalid UTF-8 config");

    let error = install_managed_include(&user, &generated).expect_err("invalid UTF-8 must fail");
    assert_eq!(io_error_kind(&error), Some(std::io::ErrorKind::InvalidData));
}

#[test]
fn managed_include_is_idempotent_and_preserves_existing_config() {
    let dir = tempdir().expect("tempdir");
    let user = dir.path().join(".ssh/config");
    let generated = dir.path().join("onec-ops/ssh_config");
    fs::create_dir_all(user.parent().expect("parent")).expect("ssh dir");
    fs::write(&user, "Host github.com\n    User git\n").expect("fixture");

    install_managed_include(&user, &generated).expect("first include");
    install_managed_include(&user, &generated).expect("second include");
    let text = fs::read_to_string(&user).expect("read config");
    assert!(text.contains("Host github.com"));
    assert_eq!(text.matches(MANAGED_INCLUDE_BEGIN).count(), 1);
    assert_eq!(text.matches(MANAGED_INCLUDE_END).count(), 1);
    assert!(text.contains("Include"));
}

#[test]
fn regression_inv_163_sync_ssh_retires_exact_legacy_onec_ops_include() {
    let dir = tempdir().expect("tempdir");
    let user = dir.path().join(".ssh/config");
    let generated = dir.path().join("onec-access/ssh_config");
    fs::create_dir_all(user.parent().expect("parent")).expect("ssh dir");
    fs::write(
        &user,
        concat!(
            "Include ~/.ssh/config.d/*.conf\n",
            "# onec-ops owns generated per-target aliases, while Chezmoi owns this include.\n",
            "Include C:/Users/TIS/.config/onec-ops/ssh_config\n",
            "Host github.com\n    User git\n",
        ),
    )
    .expect("fixture");

    install_managed_include(&user, &generated).expect("sync include");
    let text = fs::read_to_string(&user).expect("read config");
    assert!(!text.contains(".config/onec-ops/ssh_config"));
    assert!(!text.contains("onec-ops owns generated per-target aliases"));
    assert!(text.contains("Include ~/.ssh/config.d/*.conf"));
    assert!(text.contains("Host github.com"));
    assert!(text.contains(MANAGED_INCLUDE_BEGIN));
    assert!(text.contains(&format!(
        "Include {}",
        ssh_path(&generated).expect("ssh path")
    )));
}

#[test]
fn regression_inv_163_legacy_cleanup_does_not_remove_other_includes() {
    let dir = tempdir().expect("tempdir");
    let user = dir.path().join(".ssh/config");
    let generated = dir.path().join("onec-access/ssh_config");
    fs::create_dir_all(user.parent().expect("parent")).expect("ssh dir");
    let preserved = concat!(
        "Include ~/.config/other/ssh_config\n",
        "Include C:/Users/TIS/.config/onec-ops-extra/ssh_config\n",
        "Include C:/Users/TIS/.config/onec-ops/ssh_config.backup\n",
    );
    fs::write(&user, preserved).expect("fixture");

    install_managed_include(&user, &generated).expect("sync include");
    let text = fs::read_to_string(&user).expect("read config");
    for line in preserved.lines() {
        assert!(text.lines().any(|actual| actual == line));
    }
}

#[test]
fn regression_inv_049_external_include_owns_user_ssh_config_without_managed_block() {
    let dir = tempdir().expect("tempdir");
    let user = dir.path().join(".ssh/config");
    let generated = dir.path().join("onec-ops/ssh_config");
    fs::create_dir_all(user.parent().expect("parent")).expect("ssh dir");
    let include = format!("Include {}", ssh_path(&generated).expect("ssh path"));
    fs::write(
            &user,
            format!(
                "# externally managed\n{include}\n\n{MANAGED_INCLUDE_BEGIN}\n{include}\n{MANAGED_INCLUDE_END}\n"
            ),
        )
        .expect("fixture");

    install_managed_include(&user, &generated).expect("sync include");
    let text = fs::read_to_string(&user).expect("read config");
    assert!(text.contains("# externally managed"));
    assert_eq!(
        text.lines().filter(|line| line.trim() == include).count(),
        1
    );
    assert!(!text.contains(MANAGED_INCLUDE_BEGIN));
    assert!(!text.contains(MANAGED_INCLUDE_END));
}

#[test]
fn regression_inv_044_managed_ssh_config_path_uses_openssh_slashes() {
    assert_eq!(
        ssh_path(Path::new(r"C:\Example\onec-ops\ssh_config")).expect("ssh path"),
        "C:/Example/onec-ops/ssh_config"
    );
}

#[cfg(unix)]
#[test]
fn ssh_path_rejects_non_utf8_without_lossy_substitution() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt as _;

    let path = PathBuf::from(OsString::from_vec(vec![
        b'/', b't', b'm', b'p', b'/', 0xff, b'.', b'k', b'e', b'y',
    ]));
    let error = ssh_path(&path).expect_err("non-UTF-8 OpenSSH path must fail closed");
    let message = error.to_string();
    assert!(message.contains("OpenSSH path"));
    assert!(message.contains("UTF-8"));
    assert!(!message.contains('\u{fffd}'));
}

#[test]
fn ssh_path_preserves_unicode_and_quotes_spaces() {
    assert_eq!(
        ssh_path(Path::new("/tmp/ключ доступа/id_ed25519")).expect("Unicode SSH path"),
        "\"/tmp/ключ доступа/id_ed25519\""
    );
}

#[test]
fn managed_ssh_command_passes_config_path_as_raw_argv() {
    let config = Path::new(r"C:\Example Root\onec access\ssh_config");
    let command = super::exec::managed_ssh_command(
        Path::new("/usr/bin/ssh"),
        config,
        "onec-ops-host",
        "onec-ops-gateway-2",
        false,
    )
    .expect("managed SSH command");
    let args = command.get_args().collect::<Vec<_>>();

    assert_eq!(args[0], "-F");
    assert_eq!(args[1], "C:/Example Root/onec access/ssh_config");
    assert_eq!(args[2], "-o");
    assert_eq!(args[3], "ProxyJump=onec-ops-gateway-2");
    assert_eq!(args[4], "onec-ops-host");
}

#[cfg(unix)]
#[test]
fn regression_1c_855_managed_ssh_child_gets_only_positive_environment_allowlist() {
    use std::process::Command;

    const FIXTURE_TEST: &str =
        "host::tests::regression_1c_855_managed_ssh_child_gets_only_positive_environment_allowlist";
    const FIXTURE_MODE: &str = "ONEC_855_MANAGED_SSH_TEST_FIXTURE";
    if std::env::var_os(FIXTURE_MODE).is_some() {
        managed_ssh_environment_fixture_parent_with_hostile_environment();
        return;
    }

    let parent_path = std::env::var_os("PATH").unwrap_or_default();
    let parent_home = std::env::var_os("HOME").unwrap_or_else(|| "/fixture/home".into());
    let parent_secret = std::env::var_os("CUSTOM_PRIVATE_CREDENTIAL");
    let result = Command::new(std::env::current_exe().expect("current test executable"))
        .args(["--exact", FIXTURE_TEST, "--nocapture"])
        .env(FIXTURE_MODE, "1")
        .env("PATH", &parent_path)
        .env("HOME", &parent_home)
        .env("ONEC_SSH_ALLOWLIST_FIXTURE", "1")
        .env("SSH_AUTH_SOCK", "fixture-agent-socket")
        .env("CUSTOM_PRIVATE_CREDENTIAL", "fixture-private-credential")
        .env("ONEC_HUB_OPERATOR_TOKEN", "fixture-operator-token")
        .env("CUSTOM_HUB_OPERATOR_TOKEN", "fixture-custom-operator-token")
        .env("LD_PRELOAD", "/nonexistent/fixture-preload.so")
        .env("GIT_SSH_COMMAND", "fixture-git-ssh-command")
        .env("HTTP_PROXY", "http://fixture:secret@example.invalid")
        .output()
        .expect("run isolated environment fixture parent");
    assert!(
        result.status.success(),
        "fixture parent failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(
        String::from_utf8_lossy(&result.stdout).contains("1 passed"),
        "fixture selector did not run exactly one test: {}",
        String::from_utf8_lossy(&result.stdout)
    );
    assert_eq!(std::env::var_os("PATH"), Some(parent_path));
    assert_eq!(std::env::var_os("CUSTOM_PRIVATE_CREDENTIAL"), parent_secret);
}

#[cfg(unix)]
fn managed_ssh_environment_fixture_parent_with_hostile_environment() {
    // Only the regression above authorizes the hostile parent fixture. Ordinary
    // full-suite runs must not require or mutate any process-global credential env.
    if std::env::var_os("ONEC_SSH_ALLOWLIST_FIXTURE").is_none() {
        return;
    }
    assert_eq!(
        std::env::var("CUSTOM_PRIVATE_CREDENTIAL").as_deref(),
        Ok("fixture-private-credential")
    );
    assert_eq!(
        std::env::var("SSH_AUTH_SOCK").as_deref(),
        Ok("fixture-agent-socket")
    );
    assert_eq!(
        std::env::var("ONEC_HUB_OPERATOR_TOKEN").as_deref(),
        Ok("fixture-operator-token")
    );
    assert_eq!(
        std::env::var("CUSTOM_HUB_OPERATOR_TOKEN").as_deref(),
        Ok("fixture-custom-operator-token")
    );

    use std::os::unix::fs::PermissionsExt as _;

    let dir = tempdir().expect("tempdir");
    let child = dir.path().join("fake-ssh");
    fs::write(
        &child,
        concat!(
            "#!/bin/sh\n",
            "printf '%s\\n' \"$PATH\" \"$HOME\" \"$SSH_AUTH_SOCK\"\n",
            "test -n \"$PATH\" && test -n \"$HOME\" && ",
            "test \"$SSH_AUTH_SOCK\" = \"fixture-agent-socket\" && ",
            "test -z \"${CUSTOM_PRIVATE_CREDENTIAL+x}\" && ",
            "test -z \"${ONEC_HUB_OPERATOR_TOKEN+x}\" && ",
            "test -z \"${CUSTOM_HUB_OPERATOR_TOKEN+x}\" && ",
            "test -z \"${LD_PRELOAD+x}\" && ",
            "test -z \"${GIT_SSH_COMMAND+x}\" && ",
            "test -z \"${HTTP_PROXY+x}\"\n",
        ),
    )
    .expect("write fake SSH");
    fs::set_permissions(&child, fs::Permissions::from_mode(0o700)).expect("make executable");

    let parent_environment = [
        "PATH",
        "HOME",
        "SSH_AUTH_SOCK",
        "CUSTOM_PRIVATE_CREDENTIAL",
        "ONEC_HUB_OPERATOR_TOKEN",
        "CUSTOM_HUB_OPERATOR_TOKEN",
        "LD_PRELOAD",
        "GIT_SSH_COMMAND",
        "HTTP_PROXY",
    ]
    .map(|name| (name, std::env::var_os(name)));
    let mut command = Command::new(child);
    super::exec::apply_managed_ssh_environment(&mut command);

    let output = command.output().expect("run owned fake SSH child");
    assert!(
        output.status.success(),
        "fake SSH rejected environment: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        format!(
            "{}\n{}\nfixture-agent-socket\n",
            std::env::var("PATH").expect("scoped fixture PATH"),
            std::env::var("HOME").expect("scoped fixture HOME")
        )
    );
    assert_eq!(
        parent_environment,
        [
            "PATH",
            "HOME",
            "SSH_AUTH_SOCK",
            "CUSTOM_PRIVATE_CREDENTIAL",
            "ONEC_HUB_OPERATOR_TOKEN",
            "CUSTOM_HUB_OPERATOR_TOKEN",
            "LD_PRELOAD",
            "GIT_SSH_COMMAND",
            "HTTP_PROXY",
        ]
        .map(|name| (name, std::env::var_os(name)))
    );
}

#[test]
fn regression_1c_805_rejects_oversized_windows_interactive_command_without_payload() {
    let raw = "anonymous-sensitive-payload-".repeat(400);
    let encoded =
        crate::ssh_argv::encode_remote_command(&["tool.exe".into(), raw.clone()], "windows")
            .expect("encode Windows command");
    assert!(encoded.len() > super::exec::WINDOWS_INTERACTIVE_COMMAND_MAX_BYTES);

    let error = super::exec::check_interactive_command_length(&encoded, "Windows Server")
        .expect_err("oversized Windows command must fail preflight");
    let message = error.to_string();
    assert!(message.contains(&encoded.len().to_string()));
    assert!(message.contains("onec-access upload"));
    assert!(message.contains("onec-access exec --stdin-file"));
    assert!(message.contains("verified stdin-consuming program"));
    assert!(!message.contains(&raw));
    assert!(!message.contains("tool.exe"));
}

#[test]
fn regression_1c_805_keeps_short_windows_and_long_posix_commands_unchanged() {
    let short = vec!["tool.exe".to_owned(), "short argument".to_owned()];
    let encoded = crate::ssh_argv::encode_remote_command(&short, "windows").expect("encode");
    assert!(super::exec::check_interactive_command_length(&encoded, "windows").is_ok());
    assert_eq!(
        encoded,
        crate::ssh_argv::encode_remote_command(&short, "windows").expect("encode")
    );

    let long = vec!["tool".to_owned(), "x".repeat(12_000)];
    let encoded = crate::ssh_argv::encode_remote_command(&long, "linux").expect("encode POSIX");
    assert!(encoded.len() > super::exec::WINDOWS_INTERACTIVE_COMMAND_MAX_BYTES);
    assert!(super::exec::check_interactive_command_length(&encoded, "linux").is_ok());
}

#[cfg(unix)]
#[test]
fn managed_ssh_command_rejects_non_utf8_config_path() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    let config = Path::new(OsStr::from_bytes(b"/tmp/onec-\xff/ssh_config"));
    let error = super::exec::managed_ssh_command(
        Path::new("/usr/bin/ssh"),
        config,
        "onec-ops-host",
        "onec-ops-gateway",
        false,
    )
    .expect_err("non-UTF-8 -F path must fail closed");

    assert!(
        error
            .to_string()
            .contains("cannot be represented exactly as UTF-8")
    );
}

#[cfg(unix)]
#[test]
fn managed_include_rejects_non_utf8_generated_path_before_creating_user_config_parent() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt as _;

    let dir = tempdir().expect("tempdir");
    let user = dir.path().join("missing/.ssh/config");
    let generated = dir
        .path()
        .join(OsString::from_vec(b"generated-\xff.conf".to_vec()));
    let parent = user.parent().expect("parent");
    assert!(!parent.exists());

    let error = install_managed_include(&user, &generated)
        .expect_err("non-UTF-8 generated path must fail before filesystem mutation");
    assert!(error.to_string().contains("OpenSSH path"));
    assert!(!parent.exists(), "user SSH directory must not be created");
    assert!(!user.exists(), "user SSH config must not be created");
}

#[cfg(unix)]
#[test]
fn managed_include_rejects_non_utf8_generated_path_before_rewriting_user_config() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt as _;

    let dir = tempdir().expect("tempdir");
    let user = dir.path().join(".ssh/config");
    let generated = dir
        .path()
        .join(OsString::from_vec(b"generated-\xff.conf".to_vec()));
    fs::create_dir_all(user.parent().expect("parent")).expect("ssh dir");
    let original = b"Host github.com\n    User git\n";
    fs::write(&user, original).expect("fixture");

    let error = install_managed_include(&user, &generated)
        .expect_err("non-UTF-8 generated path must fail before publication");
    assert!(error.to_string().contains("OpenSSH path"));
    assert_eq!(fs::read(&user).expect("preserved user config"), original);
}

#[test]
fn ssh_scalar_preserves_qualified_windows_principal() {
    assert_eq!(
        ssh_scalar(r"EXAMPLE\\svc_user").expect("principal"),
        r"EXAMPLE\\svc_user"
    );
}

#[test]
fn target_host_key_alias_is_machine_specific() {
    let agent = fixture_agent("server-a", "SERVER-A", "machine-123");
    assert_eq!(host_key_alias(&agent), "onec-ops-machine-machine-123");
}

#[test]
fn regression_inv_080_managed_ssh_destination_is_canonical_after_case_insensitive_selection() {
    let agent = fixture_agent("server-a", "MACHINE-A", "machine-123");
    let agents = vec![agent];
    let requested = "SERVER-A";
    let resolved =
        super::exec::resolve_managed_ssh_agent(&agents, requested).expect("managed selector");
    assert_eq!(
        super::exec::managed_ssh_destination(&resolved).expect("managed destination"),
        "server-a"
    );
    assert_ne!(resolved.name, requested);
}

#[test]
fn regression_inv_080_managed_ssh_resolves_unique_machine_hostname_and_rejects_ambiguity() {
    let first = fixture_agent("friendly-a", "SERVER-A", "machine-a");
    let second = fixture_agent("friendly-b", "SERVER-B", "machine-b");
    let agents = vec![first.clone(), second];
    assert_eq!(
        super::exec::resolve_managed_ssh_agent(&agents, "server-a")
            .expect("hostname selector")
            .name,
        first.name
    );

    let duplicate = fixture_agent("friendly-c", "SERVER-A", "machine-c");
    let ambiguous = vec![first, duplicate];
    let error = super::exec::resolve_managed_ssh_agent(&ambiguous, "SERVER-A")
        .expect_err("ambiguous hostname must fail");
    assert!(error.to_string().contains("ambiguous"));
}

#[test]
fn regression_inv_080_managed_ssh_rejects_ambiguous_name_and_missing_selector() {
    let first = fixture_agent("server-a", "MACHINE-A", "machine-a");
    let second = fixture_agent("SERVER-A", "MACHINE-B", "machine-b");
    let agents = vec![first, second];

    let ambiguous = super::exec::resolve_managed_ssh_agent(&agents, "SeRvEr-A")
        .expect_err("case-insensitive duplicate managed names must fail");
    assert!(ambiguous.to_string().contains("ambiguous"));

    let missing = super::exec::resolve_managed_ssh_agent(&agents, "missing-host")
        .expect_err("unknown managed selector must fail before OpenSSH");
    assert!(missing.to_string().contains("not found"));
}

#[test]
fn regression_inv_080_generated_host_projects_unique_exact_machine_hostname() {
    let agent = fixture_agent("server-a", "SERVER-A", "machine-123");
    let agents = vec![agent.clone()];
    assert_eq!(
        super::sync::ssh_host_patterns(&agent, &agents).expect("host patterns"),
        vec!["server-a".to_owned(), "SERVER-A".to_owned()]
    );
}

#[test]
fn regression_inv_080_ambiguous_machine_hostname_is_not_projected() {
    let first = fixture_agent("server-a", "SHARED-HOST", "machine-a");
    let second = fixture_agent("server-b", "shared-host", "machine-b");
    let agents = vec![first.clone(), second];
    assert_eq!(
        super::sync::ssh_host_patterns(&first, &agents).expect("host patterns"),
        vec!["server-a".to_owned()]
    );
}

#[test]
fn regression_inv_080_machine_hostname_conflicting_with_managed_name_is_not_projected() {
    let first = fixture_agent("friendly-a", "SERVER-B", "machine-a");
    let second = fixture_agent("server-b", "MACHINE-B", "machine-b");
    let agents = vec![first.clone(), second];
    assert_eq!(
        super::sync::ssh_host_patterns(&first, &agents).expect("host patterns"),
        vec!["friendly-a".to_owned()]
    );
}

fn fixture_agent(name: &str, hostname: &str, machine_id: &str) -> HubAgent {
    HubAgent {
        id: "agent-id".into(),
        machine_id: machine_id.into(),
        name: name.into(),
        display_name: None,
        hostname: hostname.into(),
        username: Some("TIS".into()),
        os: "windows".into(),
        arch: "x86_64".into(),
        agent_version: "0.1.0".into(),
        transport: "open_ssh".into(),
        persistence_mode: None,
        remote_port: 18402,
        control_credential_nonce: None,
        legacy_control_secret: None,
        ssh_public_key:
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILM+rvN+ot98qgEN796jTiQfZfG1KaT0PtFDJ/XFSqti tunnel"
                .into(),
        ssh_host_public_key: Some(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILM+rvN+ot98qgEN796jTiQfZfG1KaT0PtFDJ/XFSqti host"
                .into(),
        ),
        enrolled_at: 1,
        updated_at: 2,
    }
}
