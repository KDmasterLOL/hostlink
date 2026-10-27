use super::*;

#[derive(Debug, Deserialize)]
#[serde(tag = "op", deny_unknown_fields)]
pub(super) enum JobRequest {
    #[serde(rename = "start")]
    Start {
        version: u8,
        id: String,
        spec: JobSpec,
    },
    #[serde(rename = "status")]
    Status { version: u8, id: String },
    #[serde(rename = "cancel")]
    Cancel { version: u8, id: String },
    #[serde(rename = "output")]
    Output {
        version: u8,
        id: String,
        stream: JobOutput,
        offset: u64,
    },
    #[serde(rename = "seal")]
    Seal {
        version: u8,
        name: String,
        sha256: String,
        size: u64,
    },
}

#[derive(Serialize)]
pub(super) struct JobResponse {
    pub(super) version: u8,
    pub(super) ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) state: Option<JobState>,
    pub(super) data_base64: Option<String>,
    pub(super) next_offset: Option<u64>,
    pub(super) eof: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) error: Option<&'static str>,
}

impl JobResponse {
    pub(super) fn success(id: impl Into<String>, state: JobState) -> Self {
        Self {
            version: 1,
            ok: true,
            id: Some(id.into()),
            state: Some(state),
            data_base64: None,
            next_offset: None,
            eof: None,
            error: None,
        }
    }

    pub(super) fn error(message: &'static str) -> Self {
        Self {
            version: 1,
            ok: false,
            id: None,
            state: None,
            data_base64: None,
            next_offset: None,
            eof: None,
            error: Some(message),
        }
    }
}
