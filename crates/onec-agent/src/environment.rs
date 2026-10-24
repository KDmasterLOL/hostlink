//! Explicit environment contract for remotely requested agent child processes.

#![deny(clippy::missing_docs_in_private_items)]

use onec_agent_protocol::SecretEnvironment;
use onec_core::{
    ONEC_EXEC_DEADLINE_UNIX_MS_ENV, ONEC_JOB_ID_ENV, ONEC_JOB_SYSTEM_ENV, ONEC_RESULT_DIR_ENV,
};
use std::collections::BTreeMap;
use std::env;
use std::ffi::{OsStr, OsString};
use std::io;
use std::process::Command;

/// Internal one-shot environment handoff carrying serialized durable-job secret environment.
pub(crate) const INTERNAL_JOB_SECRET_ENV: &str = "ONEC_AGENT_JOB_SECRET_ENV_JSON";
const INTERNAL_ASKPASS_ENV: &str = "ONEC_OPS_INTERNAL_SSH_ASKPASS";
const INTERNAL_ASKPASS_PASSWORD_ENV: &str = "ONEC_OPS_SSH_ASKPASS_PASSWORD";
const DEFAULT_CONTROL_SECRET_ENV: &str = "ONEC_AGENT_SECRET";

const COMMON_SAFE_BASE: &[&str] = &[
    "PATH",
    "HOME",
    "USER",
    "LOGNAME",
    "SHELL",
    "TMPDIR",
    "TEMP",
    "TMP",
    "LANG",
    "LANGUAGE",
    "TZ",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "XDG_CONFIG_HOME",
    "XDG_CACHE_HOME",
    "XDG_DATA_HOME",
    "XDG_STATE_HOME",
    "XDG_RUNTIME_DIR",
];

#[cfg(windows)]
const WINDOWS_SAFE_BASE: &[&str] = &[
    "SystemRoot",
    "WINDIR",
    "SystemDrive",
    "COMSPEC",
    "PATHEXT",
    "USERPROFILE",
    "HOMEDRIVE",
    "HOMEPATH",
    "APPDATA",
    "LOCALAPPDATA",
    "PROGRAMDATA",
    "ProgramFiles",
    "ProgramFiles(x86)",
    "ProgramW6432",
    "CommonProgramFiles",
    "CommonProgramFiles(x86)",
    "ALLUSERSPROFILE",
    "PUBLIC",
    "USERNAME",
    "USERDOMAIN",
    "COMPUTERNAME",
    "OS",
    "PROCESSOR_ARCHITECTURE",
    "PROCESSOR_ARCHITEW6432",
    "NUMBER_OF_PROCESSORS",
    "PSModulePath",
];

#[derive(Debug, Clone)]
/// Policy that builds a narrow inherited environment before applying request-owned variables.
pub(crate) struct AgentEnvironmentPolicy {
    control_secret_env: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Child-process class used to reserve agent-owned environment names correctly.
pub(crate) enum RequestedChildKind {
    /// Immediate bounded Exec request.
    ImmediateExec,
    /// Detached durable job worker/request.
    DurableJob,
}

impl Default for AgentEnvironmentPolicy {
    fn default() -> Self {
        Self::new(DEFAULT_CONTROL_SECRET_ENV)
    }
}

impl AgentEnvironmentPolicy {
    /// Creates policy for an explicit control-secret environment variable name.
    pub(crate) fn new(control_secret_env: impl Into<String>) -> Self {
        Self {
            control_secret_env: control_secret_env.into().trim().to_owned(),
        }
    }

    /// Creates policy for the detached worker, which must not inherit the serving agent secret.
    pub(crate) fn detached_worker() -> Self {
        Self::new("")
    }

    /// Applies the same validated child-environment contract to a ProcessKit command.
    pub(crate) fn prepare_processkit_command(
        &self,
        mut command: processkit::Command,
        environment: &BTreeMap<String, String>,
        secret_env: &SecretEnvironment,
        kind: RequestedChildKind,
    ) -> io::Result<processkit::Command> {
        self.validate_request_environment(environment, secret_env, kind)?;
        command = command.env_clear().envs(self.safe_base_environment());
        command = command.envs(environment);
        command = command.envs(secret_env.clone().into_inner());
        Ok(command)
    }

    /// Clears the command environment and copies only the platform-safe inherited base.
    pub(crate) fn apply_safe_base(&self, command: &mut Command) {
        command.env_clear();
        for (name, value) in self.safe_base_environment() {
            command.env(name, value);
        }
    }

    /// Applies the same safe inherited base to a ProcessKit-owned internal child.
    pub(crate) fn apply_processkit_safe_base(
        &self,
        command: processkit::Command,
    ) -> processkit::Command {
        command.env_clear().envs(self.safe_base_environment())
    }

    /// Returns the narrow ambient environment allowed into a requested child.
    fn safe_base_environment(&self) -> Vec<(OsString, OsString)> {
        env::vars_os()
            .filter(|(name, _)| {
                is_safe_base_environment_name(name) && !self.is_control_secret_name(name)
            })
            .collect()
    }

    /// Rejects request variables that collide with control/internal agent ownership.
    pub(crate) fn validate_request_environment(
        &self,
        environment: &BTreeMap<String, String>,
        secret_env: &SecretEnvironment,
        kind: RequestedChildKind,
    ) -> io::Result<()> {
        for name in environment.keys() {
            if self.is_control_secret_name(OsStr::new(name)) {
                return Err(invalid_environment(format!(
                    "control-secret environment variable {name:?} must be supplied only through secret_env"
                )));
            }
            validate_request_name(name, kind)?;
        }
        for name in secret_env.keys() {
            validate_request_name(name, kind)?;
        }
        Ok(())
    }

    fn is_control_secret_name(&self, name: &OsStr) -> bool {
        !self.control_secret_env.is_empty() && environment_name_eq(name, &self.control_secret_env)
    }
}

/// Validates that a configured control-secret variable does not collide with safe/internal names.
pub(crate) fn validate_control_secret_env_name(name: &str) -> io::Result<()> {
    let name = name.trim();
    if name.is_empty() {
        return Ok(());
    }
    if is_safe_base_environment_name(OsStr::new(name)) {
        return Err(invalid_environment(format!(
            "agent control secret environment name {name:?} must not reuse a safe-base variable"
        )));
    }
    if is_internal_reserved_name(name)
        || environment_name_eq(OsStr::new(name), ONEC_JOB_SYSTEM_ENV)
        || environment_name_eq(OsStr::new(name), ONEC_JOB_ID_ENV)
        || environment_name_eq(OsStr::new(name), ONEC_EXEC_DEADLINE_UNIX_MS_ENV)
        || environment_name_eq(OsStr::new(name), ONEC_RESULT_DIR_ENV)
    {
        return Err(invalid_environment(format!(
            "agent control secret environment name {name:?} is reserved for toolkit-internal state"
        )));
    }
    Ok(())
}

fn validate_request_name(name: &str, kind: RequestedChildKind) -> io::Result<()> {
    if is_internal_reserved_name(name) {
        return Err(invalid_environment(format!(
            "environment variable {name:?} is reserved for toolkit-internal handoff"
        )));
    }
    if kind == RequestedChildKind::ImmediateExec
        && (environment_name_eq(OsStr::new(name), ONEC_JOB_SYSTEM_ENV)
            || environment_name_eq(OsStr::new(name), ONEC_JOB_ID_ENV))
    {
        return Err(invalid_environment(format!(
            "environment variable {name:?} is reserved for agent-owned durable-job identity"
        )));
    }
    Ok(())
}

fn is_internal_reserved_name(name: &str) -> bool {
    environment_name_eq(OsStr::new(name), INTERNAL_JOB_SECRET_ENV)
        || environment_name_eq(OsStr::new(name), INTERNAL_ASKPASS_ENV)
        || environment_name_eq(OsStr::new(name), INTERNAL_ASKPASS_PASSWORD_ENV)
        || environment_name_eq(OsStr::new(name), ONEC_RESULT_DIR_ENV)
        || environment_name_eq(OsStr::new(name), ONEC_EXEC_DEADLINE_UNIX_MS_ENV)
}

fn invalid_environment(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

/// Returns whether one ambient variable is explicitly allowed into agent child safe-base environment.
pub(crate) fn is_safe_base_environment_name(name: &OsStr) -> bool {
    let Some(name) = name.to_str() else {
        return false;
    };
    COMMON_SAFE_BASE
        .iter()
        .any(|candidate| environment_name_eq_str(name, candidate))
        || locale_environment_name(name)
        || cfg!(windows)
            && WINDOWS_SAFE_BASE
                .iter()
                .any(|candidate| environment_name_eq_str(name, candidate))
}

fn locale_environment_name(name: &str) -> bool {
    if cfg!(windows) {
        name.get(..3)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("LC_"))
            && name.len() > 3
    } else {
        name.strip_prefix("LC_")
            .is_some_and(|suffix| !suffix.is_empty())
    }
}

fn environment_name_eq(name: &OsStr, expected: &str) -> bool {
    name.to_str()
        .is_some_and(|name| environment_name_eq_str(name, expected))
}

fn environment_name_eq_str(name: &str, expected: &str) -> bool {
    if cfg!(windows) {
        name.eq_ignore_ascii_case(expected)
    } else {
        name == expected
    }
}

#[cfg(not(windows))]
const WINDOWS_SAFE_BASE: &[&str] = &[];

#[cfg(test)]
mod tests {
    use super::*;

    fn map(entries: &[(&str, &str)]) -> BTreeMap<String, String> {
        entries
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect()
    }

    #[test]
    fn safe_base_is_narrow_and_keeps_path_profile_temp_locale_and_xdg() {
        for name in [
            "PATH",
            "HOME",
            "TEMP",
            "LANG",
            "LC_ALL",
            "XDG_CONFIG_HOME",
            "SSL_CERT_FILE",
        ] {
            assert!(is_safe_base_environment_name(OsStr::new(name)), "{name}");
        }
        for name in [
            "ONEC_AGENT_SECRET",
            "ONEC_OPS_CONFIG",
            "GITHUB_TOKEN",
            "HTTP_PROXY",
            "UNRELATED_SERVICE_CONFIG",
            "LD_PRELOAD",
        ] {
            assert!(!is_safe_base_environment_name(OsStr::new(name)), "{name}");
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_safe_base_is_case_insensitive_and_keeps_process_roots() {
        for name in ["systemroot", "ComSpec", "userprofile", "psmodulepath"] {
            assert!(is_safe_base_environment_name(OsStr::new(name)), "{name}");
        }
    }

    #[test]
    fn control_secret_name_cannot_collide_with_safe_base_or_internal_state() {
        for name in ["PATH", INTERNAL_JOB_SECRET_ENV, ONEC_JOB_SYSTEM_ENV] {
            assert!(validate_control_secret_env_name(name).is_err(), "{name}");
        }
        assert!(validate_control_secret_env_name("CUSTOM_AGENT_CONTROL_SECRET").is_ok());
        assert!(validate_control_secret_env_name("").is_ok());
    }

    #[test]
    fn configured_control_secret_requires_secret_env() {
        let policy = AgentEnvironmentPolicy::new("CUSTOM_CONTROL_SECRET");
        let ordinary = map(&[("CUSTOM_CONTROL_SECRET", "value")]);
        let secret = SecretEnvironment::new(map(&[("CUSTOM_CONTROL_SECRET", "value")]));
        assert!(
            policy
                .validate_request_environment(
                    &ordinary,
                    &SecretEnvironment::default(),
                    RequestedChildKind::ImmediateExec,
                )
                .is_err()
        );
        assert!(
            policy
                .validate_request_environment(
                    &BTreeMap::new(),
                    &secret,
                    RequestedChildKind::ImmediateExec,
                )
                .is_ok()
        );
    }

    #[test]
    fn internal_handoff_names_are_never_request_settable() {
        let policy = AgentEnvironmentPolicy::default();
        for name in [
            INTERNAL_JOB_SECRET_ENV,
            INTERNAL_ASKPASS_ENV,
            INTERNAL_ASKPASS_PASSWORD_ENV,
            ONEC_EXEC_DEADLINE_UNIX_MS_ENV,
        ] {
            let ordinary = map(&[(name, "value")]);
            let secret = SecretEnvironment::new(map(&[(name, "value")]));
            assert!(
                policy
                    .validate_request_environment(
                        &ordinary,
                        &SecretEnvironment::default(),
                        RequestedChildKind::DurableJob,
                    )
                    .is_err(),
                "{name}"
            );
            assert!(
                policy
                    .validate_request_environment(
                        &BTreeMap::new(),
                        &secret,
                        RequestedChildKind::DurableJob,
                    )
                    .is_err(),
                "{name}"
            );
        }
    }

    #[test]
    fn job_identity_is_rejected_for_exec_but_allowed_for_job_overwrite() {
        let policy = AgentEnvironmentPolicy::default();
        let environment = map(&[
            (ONEC_JOB_SYSTEM_ENV, "spoofed"),
            (ONEC_JOB_ID_ENV, "spoofed"),
        ]);
        assert!(
            policy
                .validate_request_environment(
                    &environment,
                    &SecretEnvironment::default(),
                    RequestedChildKind::ImmediateExec,
                )
                .is_err()
        );
        assert!(
            policy
                .validate_request_environment(
                    &environment,
                    &SecretEnvironment::default(),
                    RequestedChildKind::DurableJob,
                )
                .is_ok()
        );
    }
}
