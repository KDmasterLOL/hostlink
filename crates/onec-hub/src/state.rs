//! Persisted hub state and invitation/agent records.

use super::*;
use std::fs::File;
use std::sync::MutexGuard;

const HUB_STATE_MAX_BYTES: usize = 16 * 1024 * 1024;
const HUB_STATE_LOCK_TIMEOUT: Duration = Duration::from_secs(5);
const HUB_STATE_LOCK_POLL_INTERVAL: Duration = Duration::from_millis(10);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct HubState {
    pub(super) version: u32,
    #[serde(default)]
    pub(super) agents: BTreeMap<String, AgentRecord>,
    #[serde(default)]
    pub(super) invitations: BTreeMap<String, Invitation>,
}

impl Default for HubState {
    fn default() -> Self {
        Self {
            version: LEGACY_STATE_VERSION,
            agents: BTreeMap::new(),
            invitations: BTreeMap::new(),
        }
    }
}

impl HubState {
    pub(super) fn load(path: &Path) -> io::Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let state: Self = onec_core::read_json_file_bounded(path, HUB_STATE_MAX_BYTES)?;
        if !matches!(state.version, LEGACY_STATE_VERSION | STATE_VERSION) {
            return Err(invalid(format!(
                "unsupported hub state version {}; expected {LEGACY_STATE_VERSION} or {STATE_VERSION}",
                state.version
            )));
        }
        for record in state.agents.values() {
            if let Some(nonce) = record.control_credential_nonce.as_deref() {
                if state.version == LEGACY_STATE_VERSION {
                    return Err(invalid(
                        "hub state schema v1 cannot contain a control credential nonce".to_owned(),
                    ));
                }
                validate_control_credential_nonce(nonce)?;
            }
        }
        Ok(state)
    }

    pub(super) fn save(&self, path: &Path) -> Result<(), StateCommitError> {
        let data = serde_json::to_vec_pretty(self).map_err(|error| {
            StateCommitError::NotCommitted(io::Error::new(io::ErrorKind::InvalidData, error))
        })?;
        if data.len() > HUB_STATE_MAX_BYTES {
            return Err(StateCommitError::NotCommitted(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "serialized hub state exceeds {HUB_STATE_MAX_BYTES} byte limit: {} bytes",
                    data.len()
                ),
            )));
        }
        match onec_core::write_private_file_atomically(path, &data) {
            Ok(()) => Ok(()),
            Err(error) => classify_state_publication_error(path, &data, error),
        }
    }

    pub(super) fn remove_expired_invites(&mut self, now: i64) {
        self.invitations
            .retain(|_, invite| !invite.used && invite.expires_at > now);
    }
}

pub(super) struct HubStateWriter<'a> {
    app: &'a App,
    _local_lock: MutexGuard<'a, ()>,
    _lock: File,
    state: HubState,
}

#[derive(Debug)]
pub(super) enum StateCommitError {
    NotCommitted(io::Error),
    CommitUncertain(io::Error),
    Committed(io::Error),
}

impl StateCommitError {
    pub(super) fn into_io(self) -> io::Error {
        match self {
            Self::NotCommitted(error) | Self::CommitUncertain(error) | Self::Committed(error) => {
                error
            }
        }
    }

    pub(super) fn committed(&self) -> bool {
        matches!(self, Self::Committed(_))
    }

    pub(super) fn uncertain(&self) -> bool {
        matches!(self, Self::CommitUncertain(_))
    }
}

impl std::fmt::Display for StateCommitError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotCommitted(error) => write!(formatter, "hub state was not committed: {error}"),
            Self::CommitUncertain(error) => write!(
                formatter,
                "hub state publication outcome is uncertain and reconciliation is required: {error}"
            ),
            Self::Committed(error) => {
                write!(
                    formatter,
                    "hub state committed but reconciliation is required: {error}"
                )
            }
        }
    }
}

impl std::error::Error for StateCommitError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::NotCommitted(error) | Self::CommitUncertain(error) | Self::Committed(error) => {
                Some(error)
            }
        }
    }
}

fn classify_state_publication_error(
    path: &Path,
    expected: &[u8],
    publication_error: io::Error,
) -> Result<(), StateCommitError> {
    match onec_core::read_file_bounded(path, HUB_STATE_MAX_BYTES) {
        Ok(observed) if observed == expected => {
            Err(StateCommitError::CommitUncertain(io::Error::new(
                publication_error.kind(),
                format!(
                    "state publication reported an error after the intended bytes became visible: {publication_error}"
                ),
            )))
        }
        Ok(_) => Err(StateCommitError::NotCommitted(publication_error)),
        Err(readback_error) if readback_error.kind() == io::ErrorKind::NotFound => {
            Err(StateCommitError::NotCommitted(publication_error))
        }
        Err(readback_error) => Err(StateCommitError::CommitUncertain(io::Error::other(
            format!(
                "state publication failed and readback could not determine the commit outcome: publication={publication_error}; readback={readback_error}"
            ),
        ))),
    }
}

impl App {
    pub(super) fn lock_state_writer(&self) -> io::Result<HubStateWriter<'_>> {
        self.lock_state_writer_with_timing(HUB_STATE_LOCK_TIMEOUT, HUB_STATE_LOCK_POLL_INTERVAL)
    }

    fn lock_state_writer_with_timing(
        &self,
        timeout: Duration,
        poll_interval: Duration,
    ) -> io::Result<HubStateWriter<'_>> {
        let local_lock = self
            .state_writer
            .lock()
            .map_err(|_| io::Error::other("state writer lock poisoned"))?;
        let lock_path = hub_state_lock_path(&self.config.state_file)?;
        let lock = onec_core::acquire_exclusive_file_lock(lock_path, timeout, poll_interval)?;
        let state = HubState::load(&self.config.state_file)?;
        Ok(HubStateWriter {
            app: self,
            _local_lock: local_lock,
            _lock: lock,
            state,
        })
    }

    #[cfg(test)]
    pub(super) fn lock_state_writer_for_test(
        &self,
        timeout: Duration,
        poll_interval: Duration,
    ) -> io::Result<HubStateWriter<'_>> {
        self.lock_state_writer_with_timing(timeout, poll_interval)
    }

    pub(super) fn reconcile_authoritative_state(&self) -> io::Result<()> {
        let writer = self.lock_state_writer()?;
        if self.config.probe_gateway_ports_locally {
            reconcile_authorized_keys(&self.config.authorized_keys, &writer.state)?;
        }
        Ok(())
    }
}

impl HubStateWriter<'_> {
    pub(super) fn state_mut(&mut self) -> &mut HubState {
        &mut self.state
    }

    pub(super) fn commit(self, reconcile_projection: bool) -> Result<(), StateCommitError> {
        self.state.save(&self.app.config.state_file)?;

        if reconcile_projection && self.app.config.probe_gateway_ports_locally {
            reconcile_authorized_keys(&self.app.config.authorized_keys, &self.state).map_err(
                |error| {
                    StateCommitError::Committed(io::Error::other(format!(
                        "failed to reconcile authorized_keys projection: {error}"
                    )))
                },
            )?;
        }
        Ok(())
    }
}

pub(super) fn hub_state_lock_path(path: &Path) -> io::Result<PathBuf> {
    let Some(file_name) = path.file_name() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("hub state path has no file name: {}", path.display()),
        ));
    };
    let mut lock_name = file_name.to_os_string();
    lock_name.push(".lock");
    Ok(path.with_file_name(lock_name))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct Invitation {
    pub(super) created_at: i64,
    pub(super) expires_at: i64,
    pub(super) used: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) name_hint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct AgentRecord {
    pub(super) id: String,
    pub(super) machine_id: String,
    pub(super) name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) display_name: Option<String>,
    pub(super) hostname: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) username: Option<String>,
    pub(super) os: String,
    pub(super) arch: String,
    pub(super) agent_version: String,
    pub(super) transport: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) persistence_mode: Option<String>,
    pub(super) remote_port: u16,
    pub(super) ssh_public_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) ssh_host_public_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) control_credential_nonce: Option<String>,
    pub(super) enrolled_at: i64,
    pub(super) updated_at: i64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn regression_inv_108_hub_state_rejects_oversized_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("state.json");
        fs::write(&path, vec![b' '; HUB_STATE_MAX_BYTES + 1]).expect("oversized state");

        let error = HubState::load(&path).expect_err("oversized state must fail");

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn save_rejects_serialized_state_larger_than_loader_limit() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("state.json");
        let mut state = HubState::default();
        state.invitations.insert(
            "oversized".into(),
            Invitation {
                created_at: 1,
                expires_at: i64::MAX,
                used: false,
                name_hint: Some("x".repeat(HUB_STATE_MAX_BYTES)),
            },
        );

        let error = state
            .save(&path)
            .expect_err("writer must enforce the loader byte limit");

        assert!(matches!(error, StateCommitError::NotCommitted(_)));
        assert!(!path.exists(), "oversized state must not be published");
    }

    #[test]
    fn post_publication_error_with_expected_bytes_visible_is_commit_uncertain() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("state.json");
        let expected = serde_json::to_vec_pretty(&HubState::default()).expect("state bytes");
        fs::write(&path, &expected).expect("visible published state");

        let error = classify_state_publication_error(
            &path,
            &expected,
            io::Error::other("injected parent directory sync failure"),
        )
        .expect_err("visible bytes after publication error must be uncertain");

        assert!(error.uncertain());
        assert!(!error.committed());
    }

    #[test]
    fn pre_publication_error_with_old_bytes_visible_is_not_committed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("state.json");
        let expected = serde_json::to_vec_pretty(&HubState::default()).expect("state bytes");
        fs::write(&path, b"old-state").expect("old state");

        let error = classify_state_publication_error(
            &path,
            &expected,
            io::Error::other("injected pre-publication failure"),
        )
        .expect_err("different visible bytes must prove non-commit");

        assert!(matches!(error, StateCommitError::NotCommitted(_)));
    }

    #[test]
    fn legacy_agent_record_without_control_credential_nonce_remains_compatible() {
        let record: AgentRecord = serde_json::from_value(serde_json::json!({
            "id": "id-machine-a",
            "machine_id": "machine-a",
            "name": "server-a",
            "hostname": "SERVER-A",
            "os": "windows",
            "arch": "x86_64",
            "agent_version": "0.1.0",
            "transport": "gateway_control",
            "remote_port": 41001,
            "ssh_public_key": "ssh-ed25519 fixture",
            "enrolled_at": 1,
            "updated_at": 2
        }))
        .expect("legacy agent record");

        assert!(record.control_credential_nonce.is_none());
    }

    #[test]
    fn legacy_v1_state_stays_v1_until_a_nonce_bearing_enrollment_promotes_it() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("state.json");
        fs::write(
            &path,
            serde_json::to_vec_pretty(&serde_json::json!({
                "version": 1,
                "agents": {},
                "invitations": {}
            }))
            .expect("legacy state json"),
        )
        .expect("write legacy state");

        let state = HubState::load(&path).expect("load legacy state");
        assert_eq!(state.version, LEGACY_STATE_VERSION);
        state.save(&path).expect("publish upgraded state");

        let persisted: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).expect("read upgraded state"))
                .expect("parse upgraded state");
        assert_eq!(persisted["version"], LEGACY_STATE_VERSION);
    }

    #[test]
    fn future_state_version_is_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("state.json");
        fs::write(
            &path,
            serde_json::to_vec_pretty(&serde_json::json!({
                "version": STATE_VERSION + 1,
                "agents": {},
                "invitations": {}
            }))
            .expect("future state json"),
        )
        .expect("write future state");

        let error = HubState::load(&path).expect_err("future state must fail closed");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn hub_state_load_rejects_v1_state_with_nonce_bearing_agent() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("state.json");
        fs::write(
            &path,
            serde_json::to_vec_pretty(&serde_json::json!({
                "version": LEGACY_STATE_VERSION,
                "agents": {
                    "machine-a": {
                        "id": "id-machine-a",
                        "machine_id": "machine-a",
                        "name": "server-a",
                        "hostname": "SERVER-A",
                        "os": "windows",
                        "arch": "x86_64",
                        "agent_version": "0.1.0",
                        "transport": "gateway_control",
                        "remote_port": 41001,
                        "ssh_public_key": "ssh-ed25519 fixture",
                        "control_credential_nonce": "aa".repeat(32),
                        "enrolled_at": 1,
                        "updated_at": 2
                    }
                },
                "invitations": {}
            }))
            .expect("invalid v1 state json"),
        )
        .expect("write invalid v1 state");

        let error = HubState::load(&path).expect_err("v1 nonce-bearing state must fail closed");

        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("schema v1"));
    }

    #[test]
    fn hub_state_load_rejects_malformed_control_credential_nonce() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("state.json");
        fs::write(
            &path,
            serde_json::to_vec_pretty(&serde_json::json!({
                "version": STATE_VERSION,
                "agents": {
                    "machine-a": {
                        "id": "id-machine-a",
                        "machine_id": "machine-a",
                        "name": "server-a",
                        "hostname": "SERVER-A",
                        "os": "windows",
                        "arch": "x86_64",
                        "agent_version": "0.1.0",
                        "transport": "gateway_control",
                        "remote_port": 41001,
                        "ssh_public_key": "ssh-ed25519 fixture",
                        "control_credential_nonce": "AA",
                        "enrolled_at": 1,
                        "updated_at": 2
                    }
                },
                "invitations": {}
            }))
            .expect("state json"),
        )
        .expect("write malformed state");

        let error = HubState::load(&path).expect_err("malformed nonce must fail closed");

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("control credential nonce"));
    }
}
