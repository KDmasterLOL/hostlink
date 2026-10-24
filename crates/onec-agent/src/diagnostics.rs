//! Structured, secret-free diagnostics emitted by the agent runtime.
//!
//! Diagnostics are append-only JSON lines. Secret material is intentionally absent from the
//! event schema so service/tunnel lifecycle evidence can be persisted safely.

use super::*;

static AGENT_EVENT_LOG_PATH: OnceLock<PathBuf> = OnceLock::new();

#[cfg(windows)]
pub(crate) fn set_agent_event_log_path(path: PathBuf) {
    let _ = AGENT_EVENT_LOG_PATH.set(path);
}

pub(super) const AGENT_EVENT_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Default, Serialize)]
pub(crate) struct AgentEventFields {
    #[serde(skip_serializing_if = "Option::is_none")]
    remote_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    local_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    listen_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    exit_code: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stage: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    elapsed_ms: Option<u64>,
}

impl AgentEventFields {
    pub(super) fn remote_port(mut self, value: u16) -> Self {
        self.remote_port = Some(value);
        self
    }

    pub(super) fn local_port(mut self, value: u16) -> Self {
        self.local_port = Some(value);
        self
    }

    pub(super) fn listen_port(mut self, value: u16) -> Self {
        self.listen_port = Some(value);
        self
    }

    pub(super) fn stage(mut self, value: &'static str) -> Self {
        self.stage = Some(value);
        self
    }

    pub(super) fn elapsed_ms(mut self, value: u64) -> Self {
        self.elapsed_ms = Some(value);
        self
    }
}

#[derive(Debug, Serialize)]
struct AgentEventRecord<'a> {
    schema_version: u32,
    timestamp_unix_ms: u64,
    event_code: &'a str,
    severity: &'a str,
    component: &'static str,
    process_id: u32,
    #[serde(flatten)]
    fields: AgentEventFields,
}

pub(crate) fn agent_event(
    event_code: &'static str,
    severity: &'static str,
    fields: AgentEventFields,
) {
    let Some(path) = AGENT_EVENT_LOG_PATH
        .get()
        .cloned()
        .or_else(|| env::var_os("ONEC_AGENT_EVENT_LOG").map(PathBuf::from))
    else {
        return;
    };
    if let Err(error) = write_agent_event(&path, event_code, severity, fields) {
        tracing::error!(
            event_code = "diagnostics.agent_event_persistence_failed",
            diagnostic_path = %path.display(),
            persistence_error = %error,
            "agent diagnostic JSONL persistence failed"
        );
    }
}

pub(super) fn write_agent_event(
    path: &Path,
    event_code: &'static str,
    severity: &'static str,
    fields: AgentEventFields,
) -> io::Result<()> {
    let timestamp_unix_ms = onec_core::unix_time_ms();
    let record = AgentEventRecord {
        schema_version: AGENT_EVENT_SCHEMA_VERSION,
        timestamp_unix_ms,
        event_code,
        severity,
        component: "onec_agent",
        process_id: std::process::id(),
        fields,
    };
    onec_core::append_json_line(path, &record)
}
