//! Structured, secret-free hub audit events.

use super::*;

#[derive(Debug, Clone, Default, Serialize)]
pub(super) struct HubAuditFields {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) expires_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) machine_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) agent_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) remote_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) reenroll: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) overload_count: Option<u64>,
}

#[derive(Debug, Serialize)]
struct HubAuditEvent<'a> {
    schema_version: u32,
    timestamp_unix_ms: u64,
    event_code: &'a str,
    severity: &'static str,
    component: &'static str,
    process_id: u32,
    #[serde(flatten)]
    fields: HubAuditFields,
}

pub(super) fn hub_audit_line(event_code: &str, fields: HubAuditFields) -> String {
    let timestamp_unix_ms = u64::try_from(Utc::now().timestamp_millis()).unwrap_or_default();
    serde_json::to_string(&HubAuditEvent {
        schema_version: HUB_AUDIT_SCHEMA_VERSION,
        timestamp_unix_ms,
        event_code,
        severity: "info",
        component: "onec_hub",
        process_id: std::process::id(),
        fields,
    })
    .expect("hub audit event serializes")
}

pub(super) fn hub_audit(event_code: &str, fields: HubAuditFields) {
    eprintln!("{}", hub_audit_line(event_code, fields));
}
