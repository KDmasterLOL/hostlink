use super::super::*;
use super::direct::{DirectInstall, validate_direct_install};
use super::render::{
    RemoteRuntimeMigrationBootstrap, powershell_encoded_command, remote_runtime_migration_bootstrap,
};
use onec_agent_protocol::AgentRequestKind;
const MIGRATION_TIMEOUT_MS: u64 = 60_000;
const MIGRATION_CONTROLLER_TIMEOUT_MS: u64 = MIGRATION_TIMEOUT_MS + 15_000;
const MIGRATION_RECEIPT_MARKER: &str = "ONEC_TOOLKIT_MIGRATION_RECEIPT:";
const DIAGNOSTIC_LIMIT: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::cli) enum MigrationExecMode {
    Bounded,
    PreBounded,
}

pub(in crate::cli) fn migration_exec_mode(capabilities: &[String]) -> AppResult<MigrationExecMode> {
    if capabilities
        .iter()
        .any(|capability| capability == "exec.bounded-v1")
    {
        return Ok(MigrationExecMode::Bounded);
    }
    if capabilities
        .iter()
        .any(|capability| capability == "exec.argv-v1")
    {
        return Ok(MigrationExecMode::PreBounded);
    }
    Err(hostlink_access::invalid_config(
        "migrate-runtime requires either current exec.bounded-v1 or the pre-unified exec.argv-v1 compatibility contract".to_owned(),
    ))
}

pub(in crate::cli) async fn migrate_runtime(
    args: crate::cli::commands::migrate_runtime::Args,
) -> AppResult<()> {
    let config_path = hub_config_path()?;
    let hub = HubClient::configured()?.ok_or_else(|| {
        crate::not_found_error(format!(
            "hostlink controller config {}; run `hostlink configure ...`",
            config_path.display()
        ))
    })?;
    let agent = hub
        .resolve_agent(&args.target)
        .await?
        .ok_or_else(|| crate::not_found_error(format!("hub-managed host {:?}", args.target)))?;
    if !agent.os.eq_ignore_ascii_case("windows") {
        return Err(crate::invalid_config(format!(
            "migrate-runtime requires a Windows target; {:?} reports {:?}",
            args.target, agent.os
        )));
    }

    validate_migration_persistence(args.persistence, agent.persistence_mode.as_deref())?;

    let direct = direct_install(&args).await?;
    let bootstrap = remote_runtime_migration_bootstrap(&RemoteRuntimeMigrationBootstrap {
        installer_url: direct.installer_url.as_url().as_str(),
        installer_sha256: &direct.installer_sha256,
        persistence: args.persistence.installer_value(),
        direct_package_url: direct.package_url.as_url().as_str(),
        direct_package_sha256: &direct.package_sha256,
        direct_package_version: &direct.package_version,
        direct_package_target: &direct.package_target,
    });
    let encoded = powershell_encoded_command(&bootstrap);

    let server = hub
        .resolve_remote_server_for_machine(&agent.machine_id)
        .await?;
    let client = RemoteAgentClient::new(server)?;
    let capabilities = match client.hello().await {
        Ok(AgentResponseKind::Hello {
            os, capabilities, ..
        }) if os.eq_ignore_ascii_case("windows") => capabilities,
        Ok(AgentResponseKind::Hello { os, .. }) => {
            return Err(crate::invalid_config(format!(
                "target {:?} returned a live agent hello for unsupported OS {:?}; migrate-runtime requires Windows",
                agent.name, os
            )));
        }
        Ok(other) => {
            return Err(crate::invalid_config(format!(
                "target {:?} did not return an agent hello before migration (received {other:?}); verify the enrolled agent with `hostlink info {}`",
                agent.name, agent.name
            )));
        }
        Err(error) => {
            return Err(crate::invalid_config(target_online_error_message(
                &agent.name,
                &error.to_string(),
            )));
        }
    };
    let response = migration_bootstrap_exec(
        &client,
        &agent.name,
        encoded,
        migration_exec_mode(&capabilities)?,
    )
    .await?;
    let AgentResponseKind::Exec {
        exit_code,
        stdout,
        stderr,
        ..
    } = response
    else {
        return Err(crate::invalid_config(
            "remote agent returned a non-exec response during runtime migration",
        ));
    };
    if exit_code != Some(0) {
        return Err(crate::invalid_config(format!(
            "runtime migration bootstrap failed (exit code {exit_code:?}); stdout: {}; stderr: {}",
            sanitized_diagnostic(&stdout),
            sanitized_diagnostic(&stderr),
        )));
    }
    let pid =
        parse_direct_migration_receipt(&stdout, &direct.package_version, &direct.package_sha256)
            .map_err(|error| {
                crate::invalid_config(format!(
                    "{error}; stdout: {}; stderr: {}",
                    sanitized_diagnostic(&stdout),
                    sanitized_diagnostic(&stderr),
                ))
            })?;
    println!(
        "{}",
        direct_migration_success_message(pid, &direct, &agent.name)
    );
    Ok(())
}

async fn direct_install(
    args: &crate::cli::commands::migrate_runtime::Args,
) -> AppResult<DirectInstall> {
    validate_direct_install(
        &args.direct_installer_url,
        &args.direct_installer_sha256,
        &args.direct_package_url,
        &args.direct_package_sha256,
        &args.direct_package_version,
        &args.direct_package_target,
    )
    .await
}

async fn migration_bootstrap_exec(
    client: &RemoteAgentClient,
    target: &str,
    encoded: String,
    exec_mode: MigrationExecMode,
) -> AppResult<AgentResponseKind> {
    let args = migration_powershell_args(encoded);
    let operation = async {
        match exec_mode {
            MigrationExecMode::Bounded => {
                client
                    .exec("powershell.exe")
                    .args(args)
                    .timeout_ms(MIGRATION_TIMEOUT_MS)
                    .call()
                    .await
            }
            MigrationExecMode::PreBounded => {
                // Pre-unified agents advertise exec.argv-v1 and deserialize current Exec
                // requests permissively. The historical handler used synchronous
                // Command::output and did not treat a controller write-half close as
                // cancellation; exec.bounded-v1 was introduced in the same change that
                // replaced that handler with bounded process ownership.
                client.request(legacy_migration_exec_request(args)).await
            }
        }
    };

    tokio::time::timeout(
        std::time::Duration::from_millis(MIGRATION_CONTROLLER_TIMEOUT_MS),
        operation,
    )
    .await
    .map_err(|_| {
        crate::invalid_config(format!(
            "runtime migration bootstrap exceeded the controller deadline for {target:?}; target state is unknown. Do not retry automatically; inspect `hostlink info {target}` and `hostlink verify {target}` first"
        ))
    })?
}

fn migration_powershell_args(encoded: String) -> Vec<String> {
    vec![
        "-NoLogo".to_owned(),
        "-NoProfile".to_owned(),
        "-NonInteractive".to_owned(),
        "-ExecutionPolicy".to_owned(),
        "Bypass".to_owned(),
        "-EncodedCommand".to_owned(),
        encoded,
    ]
}

fn legacy_migration_exec_request(args: Vec<String>) -> AgentRequestKind {
    AgentRequestKind::Exec {
        program: "powershell.exe".to_owned(),
        args,
        cwd: None,
        env: std::collections::BTreeMap::new(),
        secret_env: onec_agent_protocol::SecretEnvironment::default(),
        stdin: None,
        result_set_id: None,
        results: Vec::new(),
        timeout_ms: MIGRATION_TIMEOUT_MS,
        raw_output: false,
    }
}

fn parse_direct_migration_receipt(
    stdout: &str,
    package_version: &str,
    package_sha256: &str,
) -> AppResult<u32> {
    let mut detached_pid = None;
    let mut actual_package_version = None;
    let mut actual_package_sha256 = None;
    let mut receipts = stdout.lines().filter_map(|line| {
        let line = line.trim();
        line.find(MIGRATION_RECEIPT_MARKER)
            .map(|marker| (line, marker))
    });
    let (receipt_line, marker_offset) = receipts.next().ok_or_else(|| {
        crate::invalid_config("runtime migration returned no marked detached-process receipt")
    })?;
    if receipts.next().is_some() {
        return Err(crate::invalid_config(
            "runtime migration returned ambiguous detached-process receipts",
        ));
    }
    if !receipt_line[..marker_offset].trim().is_empty() {
        return Err(crate::invalid_config(
            "runtime migration returned spoofed detached-process output",
        ));
    }
    let fields = receipt_line[marker_offset + MIGRATION_RECEIPT_MARKER.len()..].trim();
    if stdout.lines().any(|line| {
        !line.contains(MIGRATION_RECEIPT_MARKER)
            && [
                "detached_pid=",
                "package_version=",
                "package_sha256=",
                "release_id=",
                "manifest_sha256=",
            ]
            .iter()
            .any(|field| line.contains(field))
    }) {
        return Err(crate::invalid_config(
            "runtime migration returned spoofed detached-process output",
        ));
    }
    for field in fields.split_whitespace() {
        let (key, value) = field.split_once('=').ok_or_else(|| {
            crate::invalid_config("runtime migration returned a malformed detached-process receipt")
        })?;
        if value.is_empty() || value.contains('=') {
            return Err(crate::invalid_config(
                "runtime migration returned a malformed detached-process receipt",
            ));
        }
        let slot = match key {
            "detached_pid" => &mut detached_pid,
            "package_version" => &mut actual_package_version,
            "package_sha256" => &mut actual_package_sha256,
            _ => {
                return Err(crate::invalid_config(
                    "runtime migration returned an unexpected receipt field",
                ));
            }
        };
        if slot.replace(value).is_some() {
            return Err(crate::invalid_config(
                "runtime migration returned a duplicate receipt field",
            ));
        }
    }
    let pid = detached_pid
        .filter(|value| value.bytes().all(|byte| byte.is_ascii_digit()))
        .and_then(|value| value.parse::<u32>().ok())
        .filter(|pid| *pid > 0)
        .ok_or_else(|| crate::invalid_config("runtime migration returned an invalid WMI PID"))?;
    if actual_package_version != Some(package_version)
        || actual_package_sha256 != Some(package_sha256)
    {
        return Err(crate::invalid_config(
            "runtime migration receipt did not match the direct package version and SHA-256",
        ));
    }
    Ok(pid)
}

fn direct_migration_success_message(pid: u32, direct: &DirectInstall, target: &str) -> String {
    format!(
        "Detached launch accepted (installer PID {pid}) for package {} target {} (ZIP SHA-256 {}). Migration completion and reconnection are pending; after the installer finishes, verify with `hostlink info {target}` and `hostlink verify {target}`.",
        direct.package_version, direct.package_target, direct.package_sha256
    )
}

fn sanitized_diagnostic(value: &str) -> String {
    let mut lines = Vec::new();
    let mut remaining = DIAGNOSTIC_LIMIT;
    for line in value.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty()
            || trimmed.len() > 240
            || [
                "token",
                "password",
                "secret",
                "authorization",
                "$",
                "function ",
                "param(",
            ]
            .iter()
            .any(|marker| trimmed.to_ascii_lowercase().contains(marker))
        {
            continue;
        }
        let safe = trimmed
            .chars()
            .map(|character| {
                if character.is_control() {
                    ' '
                } else {
                    character
                }
            })
            .collect::<String>();
        if safe.len() > remaining {
            let mut end = remaining.min(safe.len());
            while !safe.is_char_boundary(end) {
                end -= 1;
            }
            lines.push(safe[..end].to_owned());
            break;
        }
        remaining -= safe.len();
        lines.push(safe);
        if remaining == 0 {
            break;
        }
    }
    let joined = if lines.is_empty() {
        "<no safe diagnostic text>".to_owned()
    } else {
        lines.join(" | ")
    };
    if joined.len() <= DIAGNOSTIC_LIMIT {
        joined
    } else {
        let mut end = DIAGNOSTIC_LIMIT;
        while !joined.is_char_boundary(end) {
            end -= 1;
        }
        joined[..end].to_owned()
    }
}

fn target_online_error_message(target: &str, reason: &str) -> String {
    format!(
        "target {target:?} is enrolled but not online through its configured hub/access route; restore its agent/session or legacy SSH route, then verify with `hostlink info {target}`: {reason}"
    )
}

fn validate_migration_persistence(
    requested: crate::cli::values::Persistence,
    target_mode: Option<&str>,
) -> AppResult<()> {
    if requested != crate::cli::values::Persistence::UserSession {
        return Err(crate::invalid_config(
            "migrate-runtime currently supports only --persistence user-session; windows-service migration requires native acceptance before it can be enabled".to_owned(),
        ));
    }
    if let Some(mode) = target_mode.filter(|mode| !mode.eq_ignore_ascii_case("user-session")) {
        return Err(crate::invalid_config(format!(
            "migrate-runtime cannot preserve target persistence {mode:?} with --persistence user-session; windows-service migration is not accepted"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        DIAGNOSTIC_LIMIT, MIGRATION_TIMEOUT_MS, MigrationExecMode, legacy_migration_exec_request,
        migration_exec_mode, migration_powershell_args, parse_direct_migration_receipt,
        sanitized_diagnostic, target_online_error_message, validate_migration_persistence,
    };
    use crate::cli::Cli;
    use clap::{Parser, error::ErrorKind};
    use onec_agent_protocol::AgentRequest;
    use serde::Deserialize;
    use std::collections::BTreeMap;

    #[derive(Debug, Deserialize)]
    struct LegacyAgentRequest {
        version: u32,
        token: String,
        request: LegacyAgentRequestKind,
    }

    #[derive(Debug, Deserialize)]
    #[serde(tag = "type", rename_all = "snake_case")]
    enum LegacyAgentRequestKind {
        Exec {
            program: String,
            #[serde(default)]
            args: Vec<String>,
            #[serde(default)]
            cwd: Option<String>,
            #[serde(default)]
            env: BTreeMap<String, String>,
            #[serde(default)]
            secret_env: BTreeMap<String, String>,
        },
    }

    #[test]
    fn migration_requires_all_direct_artifact_pins_and_rejects_retired_release_flags() {
        let missing = Cli::try_parse_from([
            "hostlink",
            "migrate-runtime",
            "host",
            "--persistence",
            "user-session",
        ])
        .expect_err("migration must require the complete direct artifact pin");
        assert_eq!(missing.kind(), ErrorKind::MissingRequiredArgument);
        let retired = Cli::try_parse_from([
            "hostlink",
            "migrate-runtime",
            "host",
            "--persistence",
            "user-session",
            "--release-id",
            "old",
            "--release-manifest-sha256",
            "old",
        ])
        .expect_err("retired release flags must not be accepted");
        assert_eq!(retired.kind(), ErrorKind::UnknownArgument);
    }

    #[test]
    fn regression_inv_165_migration_requires_known_exec_capability_class() {
        assert_eq!(
            migration_exec_mode(&["exec.argv-v1".to_owned()]).unwrap(),
            MigrationExecMode::PreBounded
        );
        assert_eq!(
            migration_exec_mode(&["exec.argv-v1".to_owned(), "exec.bounded-v1".to_owned()])
                .unwrap(),
            MigrationExecMode::Bounded
        );
        assert_eq!(
            migration_exec_mode(&["exec.bounded-v1".to_owned()]).unwrap(),
            MigrationExecMode::Bounded
        );
        let error = migration_exec_mode(&["jobs-v1".to_owned()])
            .expect_err("unknown Exec capability class must fail closed");
        assert!(error.to_string().contains("exec.argv-v1"));
        assert!(error.to_string().contains("exec.bounded-v1"));
    }

    #[test]
    fn regression_inv_165_migration_exec_remains_deserializable_by_pre_bounded_agent() {
        let encoded = "encoded-bootstrap".to_owned();
        let request = AgentRequest::new(
            "placeholder",
            legacy_migration_exec_request(migration_powershell_args(encoded.clone())),
        );
        let wire = serde_json::to_vec(&request).expect("serialize current migration request");
        let legacy: LegacyAgentRequest =
            serde_json::from_slice(&wire).expect("pre-bounded schema accepts current request");
        assert_eq!(legacy.version, onec_agent_protocol::PROTOCOL_VERSION);
        assert_eq!(legacy.version, 1);
        assert_eq!(legacy.token, "placeholder");
        let LegacyAgentRequestKind::Exec {
            program,
            args,
            cwd,
            env,
            secret_env,
        } = legacy.request;
        assert_eq!(program, "powershell.exe");
        assert_eq!(args.last().map(String::as_str), Some(encoded.as_str()));
        assert!(cwd.is_none());
        assert!(env.is_empty());
        assert!(secret_env.is_empty());
        let current = serde_json::to_value(request).expect("current request JSON");
        assert_eq!(current["request"]["timeout_ms"], MIGRATION_TIMEOUT_MS);
        assert!(current["request"].get("stdin").is_none());
        assert!(current["request"].get("results").is_none());
    }

    #[test]
    fn direct_migration_receipt_requires_exact_fields_and_matches_operator_pin() {
        let version = "1.2.3";
        let sha256 = "c".repeat(64);
        let receipt = format!(
            "ONEC_TOOLKIT_MIGRATION_RECEIPT: detached_pid=42 package_version={version} package_sha256={sha256}"
        );
        assert_eq!(
            parse_direct_migration_receipt(&receipt, version, &sha256).unwrap(),
            42
        );
        for invalid in [
            receipt.replace("detached_pid=42", "detached_pid=0"),
            receipt.replace("detached_pid=42", "detached_pid=nope"),
            format!("{receipt} release_id=legacy"),
            format!("{receipt}\n{receipt}"),
            format!("spoofed {receipt}"),
            format!("{receipt}\npackage_version=1.2.3"),
        ] {
            assert!(parse_direct_migration_receipt(&invalid, version, &sha256).is_err());
        }
        assert!(parse_direct_migration_receipt(&receipt, "1.2.4", &sha256).is_err());
        assert!(parse_direct_migration_receipt(&receipt, version, &"d".repeat(64)).is_err());
    }

    #[test]
    fn migration_diagnostics_are_bounded_and_hide_sensitive_or_script_lines() {
        let output = format!(
            "safe failure\npassword=hunter2\n$installerBody = 'do not show'\n{}",
            "x".repeat(4000)
        );
        let diagnostic = sanitized_diagnostic(&output);
        assert!(diagnostic.contains("safe failure"));
        assert!(!diagnostic.contains("hunter2"));
        assert!(!diagnostic.contains("installerBody"));
        assert!(diagnostic.len() <= DIAGNOSTIC_LIMIT);
    }

    #[test]
    fn migration_rejects_service_mode_and_known_persistence_switches() {
        validate_migration_persistence(
            crate::cli::values::Persistence::UserSession,
            Some("user-session"),
        )
        .expect("matching user-session migration is supported");
        validate_migration_persistence(crate::cli::values::Persistence::UserSession, None)
            .expect("unknown legacy mode may use explicit user-session");
        assert!(
            validate_migration_persistence(
                crate::cli::values::Persistence::WindowsService,
                Some("windows-service")
            )
            .expect_err("service migration requires native approval")
            .to_string()
            .contains("only --persistence user-session")
        );
        assert!(
            validate_migration_persistence(
                crate::cli::values::Persistence::UserSession,
                Some("windows-service")
            )
            .expect_err("must not switch service target")
            .to_string()
            .contains("cannot preserve target persistence")
        );
    }

    #[test]
    fn offline_target_error_includes_recovery_command_and_route_detail() {
        let error = target_online_error_message("server-a", "connection refused");
        assert!(error.contains("restore its agent/session or legacy SSH route"));
        assert!(error.contains("hostlink info server-a"));
        assert!(error.contains("connection refused"));
    }
}
