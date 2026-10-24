//! Agent config loading, relative-path resolution, validation, and runtime secret materialization.

use super::model::AgentConfigWire;
use super::*;
use crate::environment::validate_control_secret_env_name;

const AGENT_CONFIG_MAX_BYTES: usize = 256 * 1024;
const AGENT_SECRET_FILE_MAX_BYTES: usize = 64 * 1024;

impl AgentConfig {
    /// Loads, resolves relative paths, and validates one bounded JSON agent configuration.
    ///
    /// # Errors
    ///
    /// Returns [`std::io::Error`] when the document is missing/oversized/invalid, relative path
    /// resolution produces invalid prerequisites, or semantic validation fails.
    pub fn load(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref();
        let mut wire: AgentConfigWire =
            onec_core::read_json_file_bounded(path, AGENT_CONFIG_MAX_BYTES)?;
        let base = path.parent().unwrap_or_else(|| Path::new("."));
        wire.resolve_relative_paths(base);
        let config = Self::try_from(wire)?;
        config.validate_runtime_prerequisites()?;
        Ok(config)
    }

    /// Validates schema, loopback control binding, secret source, PATH additions, and SSH policy.
    ///
    /// # Errors
    ///
    /// Returns [`std::io::Error`] for unsupported versions, unsafe/non-loopback networking,
    /// missing path/secret prerequisites, or invalid SSH/sshd configuration.
    pub(crate) fn validate_static(&self) -> io::Result<()> {
        if self.version != 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unsupported onec-agent config version {}", self.version),
            ));
        }
        if self.name.trim().is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "agent name must not be empty",
            ));
        }
        let listen = self.listen;
        if !listen.ip().is_loopback() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "agent control endpoint must be loopback-only, got {}",
                    self.listen
                ),
            ));
        }
        if listen.port() == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "agent control port must be non-zero",
            ));
        }
        if self.secret_env.trim().is_empty() && self.secret_file.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "either secret_env or secret_file must be configured",
            ));
        }
        if self
            .secret_file
            .as_ref()
            .is_some_and(|path| path.as_os_str().is_empty())
            || self
                .jobs_dir
                .as_ref()
                .is_some_and(|path| path.as_os_str().is_empty())
            || self
                .path_prepend
                .iter()
                .any(|path| path.as_os_str().is_empty())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "agent config paths must not be empty",
            ));
        }
        if self
            .native_suite_policy_sha256
            .as_ref()
            .is_some_and(|digest| {
                digest.len() != 64
                    || !digest
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            })
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "native_suite_policy_sha256 must be lowercase SHA-256",
            ));
        }
        validate_control_secret_env_name(&self.secret_env)?;
        if self.ssh_server.is_some() && self.embedded_ssh_server.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "ssh_server and embedded_ssh_server are mutually exclusive",
            ));
        }
        if let Some(server) = &self.ssh_server
            && server.port == 0
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "ssh_server.port must be non-zero",
            ));
        }
        if self.ssh_server.as_ref().is_some_and(|server| {
            server.program.as_os_str().is_empty() || server.config.as_os_str().is_empty()
        }) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "ssh_server program and config paths must not be empty",
            ));
        }
        if let Some(server) = &self.embedded_ssh_server {
            if server.port == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "embedded_ssh_server.port must be non-zero",
                ));
            }
            if server.port == self.listen.port() {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    "embedded_ssh_server.port must differ from the agent control port",
                ));
            }
            if server.user.trim().is_empty()
                || server.host_key.as_os_str().is_empty()
                || server.authorized_keys.as_os_str().is_empty()
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "embedded_ssh_server user and key paths are required",
                ));
            }
        }
        if let Some(ssh) = &self.ssh {
            ssh.validate_static(self.ssh_target_port())?;
        }
        Ok(())
    }

    /// Rechecks prerequisites whose truth depends on the current filesystem/runtime state.
    pub fn validate(&self) -> io::Result<()> {
        self.validate_static()?;
        if let Some(ssh) = &self.ssh {
            ssh.validate(self.ssh_target_port())?;
        }
        self.validate_runtime_prerequisites()
    }

    fn validate_runtime_prerequisites(&self) -> io::Result<()> {
        for path in &self.path_prepend {
            if !path.is_dir() {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("agent PATH directory does not exist: {}", path.display()),
                ));
            }
        }
        if let Some(server) = &self.ssh_server {
            server.validate()?;
        }
        if let Some(server) = &self.embedded_ssh_server {
            server.validate()?;
        }
        Ok(())
    }

    pub(crate) fn ssh_target_port(&self) -> u16 {
        self.embedded_ssh_server
            .as_ref()
            .map(|server| server.port)
            .or_else(|| self.ssh_server.as_ref().map(|server| server.port))
            .unwrap_or(self.listen.port())
    }

    /// Prepend installer-owned tool directories to this process before any worker, sshd, or
    /// persistent job is spawned. The installer also persists the same directories in the user
    /// PATH for interactive SSH sessions; this process-local projection makes Windows-service
    /// startup deterministic even when SCM has an older environment snapshot.
    pub fn apply_process_environment(&self) -> io::Result<()> {
        if self.path_prepend.is_empty() {
            return Ok(());
        }
        let mut paths = self.path_prepend.clone();
        if let Some(current) = env::var_os("PATH") {
            for path in env::split_paths(&current) {
                if !paths.iter().any(|existing| same_path(existing, &path)) {
                    paths.push(path);
                }
            }
        }
        let joined = env::join_paths(paths).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("cannot construct agent PATH from configured directories: {error}"),
            )
        })?;
        // SAFETY: runtime entrypoints call this before agent worker/control threads are spawned.
        unsafe { env::set_var("PATH", joined) };
        Ok(())
    }

    /// Resolves the control secret and durable-job root into runtime state.
    ///
    /// Secret-file input is bounded/UTF-8 and takes precedence over the configured environment
    /// variable. The resolved secret must contain at least 16 non-empty characters.
    ///
    /// # Errors
    ///
    /// Returns [`std::io::Error`] when secret material or the default jobs directory cannot be
    /// resolved safely.
    pub fn runtime(&self) -> io::Result<AgentRuntime> {
        let (secret, source) = if let Some(path) = &self.secret_file {
            let bytes = onec_core::read_file_bounded(path, AGENT_SECRET_FILE_MAX_BYTES).map_err(
                |source| {
                    io::Error::new(
                        source.kind(),
                        format!(
                            "failed to read agent secret file {}: {source}",
                            path.display()
                        ),
                    )
                },
            )?;
            let secret = std::str::from_utf8(&bytes).map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "agent secret file {} must be UTF-8: {error}",
                        path.display()
                    ),
                )
            })?;
            (
                secret.trim().to_owned(),
                format!("secret file {}", path.display()),
            )
        } else {
            let secret = env::var(&self.secret_env).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!(
                        "environment variable {:?} containing the agent control secret is not set",
                        self.secret_env
                    ),
                )
            })?;
            (
                secret.trim().to_owned(),
                format!("environment variable {:?}", self.secret_env),
            )
        };
        if secret.len() < 16 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("{source} must contain at least 16 non-empty characters"),
            ));
        }
        Ok(AgentRuntime {
            name: self.name.clone(),
            secret: secret.into(),
            jobs_dir: match &self.jobs_dir {
                Some(path) => path.clone(),
                None => default_jobs_dir()?,
            },
            native_suite_policy_sha256: self.native_suite_policy_sha256.clone(),
        })
    }
}

impl EmbeddedSshServerConfig {
    pub(crate) fn validate(&self) -> io::Result<()> {
        if self.port == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "embedded_ssh_server.port must be non-zero",
            ));
        }
        self.runtime_config().validate()
    }

    pub(crate) fn runtime_config(&self) -> crate::embedded_ssh::EmbeddedSshConfig {
        crate::embedded_ssh::EmbeddedSshConfig::new(
            self.user.clone(),
            self.host_key.clone(),
            self.authorized_keys.clone(),
        )
    }
}

fn default_jobs_dir() -> io::Result<PathBuf> {
    let executable = env::current_exe()?;
    let parent = executable.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "onec-agent executable has no parent directory",
        )
    })?;
    let root = if parent
        .file_name()
        .is_some_and(|name| name.eq_ignore_ascii_case("bin"))
    {
        parent.parent().unwrap_or(parent)
    } else {
        parent
    };
    Ok(root.join("jobs"))
}

fn same_path(left: &Path, right: &Path) -> bool {
    if cfg!(windows) {
        left.to_string_lossy()
            .eq_ignore_ascii_case(&right.to_string_lossy())
    } else {
        left == right
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_suite_policy_pin_requires_canonical_lowercase_sha256() {
        let valid: AgentConfig = serde_json::from_value(serde_json::json!({
            "version": 1,
            "name": "fixture",
            "native_suite_policy_sha256": "a".repeat(64)
        }))
        .expect("valid config pin");
        assert_eq!(
            valid.native_suite_policy_sha256.as_deref(),
            Some("a".repeat(64).as_str())
        );

        for invalid in ["A".repeat(64), "a".repeat(63), "z".repeat(64)] {
            assert!(
                serde_json::from_value::<AgentConfig>(serde_json::json!({
                    "version": 1,
                    "name": "fixture",
                    "native_suite_policy_sha256": invalid
                }))
                .is_err()
            );
        }
        assert!(
            serde_json::from_value::<AgentConfig>(serde_json::json!({
                "version": 1,
                "name": "fixture",
                "native_suite_policy_sha256": "a".repeat(64),
                "suite_outcome_key": "caller-controlled"
            }))
            .is_err()
        );
    }

    #[test]
    fn embedded_ssh_config_resolves_relative_keys_and_rejects_mixed_server_owners() {
        let dir = tempfile::tempdir().expect("tempdir");
        let host_key =
            russh::keys::PrivateKey::random(&mut rand::rng(), russh::keys::Algorithm::Ed25519)
                .expect("host key");
        let client_key =
            russh::keys::PrivateKey::random(&mut rand::rng(), russh::keys::Algorithm::Ed25519)
                .expect("client key");
        let host_key_path = dir.path().join("ssh_host_ed25519_key");
        let authorized_keys_path = dir.path().join("sshd_authorized_keys");
        fs::write(
            &host_key_path,
            host_key
                .to_openssh(russh::keys::ssh_key::LineEnding::LF)
                .expect("host key encoding")
                .as_bytes(),
        )
        .expect("host key file");
        onec_core::restrict_private_file(&host_key_path).expect("private host key");
        fs::write(
            &authorized_keys_path,
            client_key
                .public_key()
                .to_openssh()
                .expect("client public key"),
        )
        .expect("authorized keys");

        let config_path = dir.path().join("agent.json");
        fs::write(
            &config_path,
            r#"{
                "version": 1,
                "name": "fixture",
                "embedded_ssh_server": {
                    "user": "managed-user",
                    "host_key": "ssh_host_ed25519_key",
                    "authorized_keys": "sshd_authorized_keys",
                    "port": 2222
                }
            }"#,
        )
        .expect("agent config");

        let config = AgentConfig::load(&config_path).expect("embedded config");
        let embedded = config
            .embedded_ssh_server
            .as_ref()
            .expect("embedded server config");
        assert_eq!(embedded.host_key, host_key_path);
        assert_eq!(embedded.authorized_keys, authorized_keys_path);
        assert_eq!(config.ssh_target_port(), 2222);

        let error = serde_json::from_value::<AgentConfig>(serde_json::json!({
            "version": 1,
            "name": "fixture",
            "embedded_ssh_server": {
                "user": "managed-user",
                "host_key": host_key_path,
                "authorized_keys": authorized_keys_path,
                "port": 2222
            },
            "ssh_server": {
                "program": "unused-sshd",
                "config": "unused-sshd-config",
                "port": 2223
            }
        }))
        .expect_err("two target SSH owners must fail during deserialization");
        assert!(error.to_string().contains("mutually exclusive"), "{error}");
    }

    #[test]
    fn agent_load_resolves_relative_paths_and_rechecks_filesystem_state() {
        let dir = tempfile::tempdir().expect("config directory");
        let tools = dir.path().join("tools");
        fs::create_dir(&tools).expect("tool directory");
        let config_path = dir.path().join("agent.json");
        fs::write(
            &config_path,
            r#"{"version":1,"name":"fixture","path_prepend":["tools"]}"#,
        )
        .expect("agent config");

        let config = AgentConfig::load(&config_path).expect("valid config and directory");
        assert_eq!(config.path_prepend(), std::slice::from_ref(&tools));

        fs::remove_dir(&tools).expect("remove tool directory after load");
        assert_eq!(
            config
                .validate()
                .expect_err("filesystem state is rechecked")
                .kind(),
            io::ErrorKind::NotFound
        );
    }

    #[test]
    fn agent_load_preserves_policy_error_category() {
        let dir = tempfile::tempdir().expect("config directory");
        let config_path = dir.path().join("agent.json");
        fs::write(
            &config_path,
            r#"{"version":1,"name":"fixture","listen":"0.0.0.0:27391"}"#,
        )
        .expect("agent config");

        let error = AgentConfig::load(&config_path).expect_err("public listener must fail");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(error.to_string().contains("loopback-only"), "{error}");
    }

    #[test]
    fn regression_inv_108_agent_config_rejects_oversized_file() {
        let dir = std::env::temp_dir().join(format!(
            "onec-agent-inv108-config-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        fs::create_dir_all(&dir).expect("tempdir");
        let path = dir.join("agent.json");
        fs::write(&path, vec![b' '; AGENT_CONFIG_MAX_BYTES + 1]).expect("oversized config");

        let error = AgentConfig::load(&path).expect_err("oversized config must fail");

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        fs::remove_dir_all(dir).expect("cleanup");
    }
}
