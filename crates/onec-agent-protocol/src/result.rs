//! Typed declarations and immutable metadata for managed execution result artifacts.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::BTreeSet;

use crate::digest::is_lowercase_sha256;

/// Maximum number of result artifacts one managed process may declare.
pub const MAX_RESULT_ARTIFACTS: usize = 16;
/// Maximum byte ceiling accepted for one declared result artifact.
pub const MAX_RESULT_ARTIFACT_BYTES: u64 = 512 * 1024 * 1024;
/// Maximum aggregate declared bytes for one result set.
pub const MAX_RESULT_SET_BYTES: u64 = 1024 * 1024 * 1024;
/// Maximum UTF-8 byte length of one portable logical result name.
pub const MAX_RESULT_NAME_BYTES: usize = 128;
/// Maximum UTF-8 byte length of one optional media-type hint.
pub const MAX_RESULT_MEDIA_TYPE_BYTES: usize = 128;
/// Maximum byte length of one opaque execution result-set identifier.
pub const MAX_RESULT_SET_ID_BYTES: usize = 128;

/// One result file expected from a managed child process.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(try_from = "ResultArtifactSpecWire")]
pub struct ResultArtifactSpec {
    /// Portable logical filename written directly under ONEC_RESULT_DIR.
    pub(crate) name: String,
    /// Maximum accepted bytes for this result.
    pub(crate) max_bytes: u64,
    /// Optional validated MIME media-type hint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) media_type: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct ResultArtifactSpecWire {
    pub(crate) name: String,
    max_bytes: u64,
    #[serde(default)]
    media_type: Option<String>,
}

impl TryFrom<ResultArtifactSpecWire> for ResultArtifactSpec {
    type Error = String;

    fn try_from(value: ResultArtifactSpecWire) -> Result<Self, Self::Error> {
        Self::try_new(value.name, value.max_bytes, value.media_type)
    }
}

impl ResultArtifactSpec {
    /// Creates one validated result declaration.
    ///
    /// # Errors
    ///
    /// Returns a human-readable protocol validation error.
    pub fn try_new(
        name: String,
        max_bytes: u64,
        media_type: Option<String>,
    ) -> Result<Self, String> {
        let value = Self {
            name,
            max_bytes,
            media_type,
        };
        value.validate()?;
        Ok(value)
    }

    /// Validates the portable name, positive bounded byte limit, and optional MIME type.
    ///
    /// # Errors
    ///
    /// Returns a human-readable protocol validation error.
    pub fn validate(&self) -> Result<(), String> {
        validate_result_name(&self.name)?;
        if self.max_bytes == 0 || self.max_bytes > MAX_RESULT_ARTIFACT_BYTES {
            return Err(format!(
                "result artifact {:?} max_bytes must be in 1..={MAX_RESULT_ARTIFACT_BYTES}",
                self.name
            ));
        }
        validate_media_type(&self.name, self.media_type.as_deref())
    }

    /// Returns the portable logical filename.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the maximum accepted size in bytes.
    pub fn max_bytes(&self) -> u64 {
        self.max_bytes
    }

    /// Returns the optional validated MIME media-type hint.
    pub fn media_type(&self) -> Option<&str> {
        self.media_type.as_deref()
    }
}

/// Immutable metadata for one fully published result artifact.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(try_from = "ResultArtifactInfoWire")]
pub struct ResultArtifactInfo {
    /// Portable logical result name.
    pub(crate) name: String,
    /// Exact published byte count.
    pub(crate) bytes: u64,
    /// Lowercase hexadecimal SHA-256 of the exact published bytes.
    pub(crate) sha256: String,
    /// Optional validated MIME media-type hint copied from the declaration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) media_type: Option<String>,
}

#[derive(Deserialize)]
struct ResultArtifactInfoWire {
    name: String,
    bytes: u64,
    sha256: String,
    #[serde(default)]
    media_type: Option<String>,
}

impl TryFrom<ResultArtifactInfoWire> for ResultArtifactInfo {
    type Error = String;

    fn try_from(value: ResultArtifactInfoWire) -> Result<Self, Self::Error> {
        Self::try_new(value.name, value.bytes, value.sha256, value.media_type)
    }
}

impl ResultArtifactInfo {
    /// Creates validated immutable artifact metadata.
    ///
    /// # Errors
    ///
    /// Returns a human-readable protocol validation error.
    pub fn try_new(
        name: String,
        bytes: u64,
        sha256: String,
        media_type: Option<String>,
    ) -> Result<Self, String> {
        let value = Self {
            name,
            bytes,
            sha256,
            media_type,
        };
        value.validate()?;
        Ok(value)
    }

    /// Validates immutable artifact metadata before transferred bytes are trusted.
    ///
    /// # Errors
    ///
    /// Returns a human-readable protocol validation error.
    pub fn validate(&self) -> Result<(), String> {
        validate_result_name(&self.name)?;
        if self.bytes > MAX_RESULT_ARTIFACT_BYTES {
            return Err(format!(
                "result artifact {:?} published size {} exceeds {MAX_RESULT_ARTIFACT_BYTES}",
                self.name, self.bytes
            ));
        }
        if !is_lowercase_sha256(&self.sha256) {
            return Err(format!(
                "result artifact {:?} has invalid lowercase SHA-256",
                self.name
            ));
        }
        validate_media_type(&self.name, self.media_type.as_deref())
    }

    /// Returns the portable logical filename.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the exact published size in bytes.
    pub fn bytes(&self) -> u64 {
        self.bytes
    }

    /// Returns the lowercase SHA-256 digest.
    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    /// Returns the optional validated MIME media-type hint.
    pub fn media_type(&self) -> Option<&str> {
        self.media_type.as_deref()
    }
}

/// Logical owner of one agent-managed result set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResultOwner(ResultOwnerKind);

#[derive(Debug, Clone, PartialEq, Eq)]
enum ResultOwnerKind {
    Exec(String),
    Job(String),
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum ResultOwnerWire {
    Exec { result_set_id: String },
    Job { job_id: String },
}

impl Serialize for ResultOwner {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match &self.0 {
            ResultOwnerKind::Exec(result_set_id) => ResultOwnerWire::Exec {
                result_set_id: result_set_id.clone(),
            }
            .serialize(serializer),
            ResultOwnerKind::Job(job_id) => ResultOwnerWire::Job {
                job_id: job_id.clone(),
            }
            .serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for ResultOwner {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = ResultOwnerWire::deserialize(deserializer)?;
        Self::try_from(value).map_err(serde::de::Error::custom)
    }
}

impl TryFrom<ResultOwnerWire> for ResultOwner {
    type Error = String;

    fn try_from(value: ResultOwnerWire) -> Result<Self, Self::Error> {
        match value {
            ResultOwnerWire::Exec { result_set_id } => Self::exec(result_set_id),
            ResultOwnerWire::Job { job_id } => Self::job(job_id),
        }
    }
}

impl ResultOwner {
    /// Validates the opaque owner identity before it is used for retrieval or cleanup.
    ///
    /// # Errors
    ///
    /// Returns a human-readable protocol validation error.
    pub fn validate(&self) -> Result<(), String> {
        match &self.0 {
            ResultOwnerKind::Exec(result_set_id) => validate_result_set_id(result_set_id),
            ResultOwnerKind::Job(job_id) => validate_result_set_id(job_id),
        }
    }

    /// Creates an immediate-execution result owner.
    pub fn exec(result_set_id: impl Into<String>) -> Result<Self, String> {
        let owner = Self(ResultOwnerKind::Exec(result_set_id.into()));
        owner.validate()?;
        Ok(owner)
    }

    /// Creates a durable-job result owner.
    pub fn job(job_id: impl Into<String>) -> Result<Self, String> {
        let owner = Self(ResultOwnerKind::Job(job_id.into()));
        owner.validate()?;
        Ok(owner)
    }

    /// Returns the immediate-execution result-set identifier, if this is an Exec owner.
    pub fn exec_id(&self) -> Option<&str> {
        match &self.0 {
            ResultOwnerKind::Exec(value) => Some(value),
            ResultOwnerKind::Job(_) => None,
        }
    }

    /// Returns the durable job identifier, if this is a Job owner.
    pub fn job_id(&self) -> Option<&str> {
        match &self.0 {
            ResultOwnerKind::Job(value) => Some(value),
            ResultOwnerKind::Exec(_) => None,
        }
    }
}

/// Fully published result metadata returned by Exec or durable job status.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(try_from = "ResultSetInfoWire")]
pub struct ResultSetInfo {
    /// Logical owner used for typed retrieval and cleanup.
    pub(crate) owner: ResultOwner,
    /// Fully published immutable artifacts.
    pub(crate) artifacts: Vec<ResultArtifactInfo>,
}

#[derive(Deserialize)]
struct ResultSetInfoWire {
    owner: ResultOwner,
    artifacts: Vec<ResultArtifactInfo>,
}

impl TryFrom<ResultSetInfoWire> for ResultSetInfo {
    type Error = String;

    fn try_from(value: ResultSetInfoWire) -> Result<Self, Self::Error> {
        Self::try_new(value.owner, value.artifacts)
    }
}

impl ResultSetInfo {
    /// Creates one validated immutable result set.
    ///
    /// # Errors
    ///
    /// Returns a human-readable protocol validation error.
    pub fn try_new(owner: ResultOwner, artifacts: Vec<ResultArtifactInfo>) -> Result<Self, String> {
        let value = Self { owner, artifacts };
        value.validate()?;
        Ok(value)
    }

    /// Validates the aggregate count, case-folded names, and byte ceiling.
    ///
    /// # Errors
    ///
    /// Returns a human-readable protocol validation error.
    pub fn validate(&self) -> Result<(), String> {
        if self.artifacts.len() > MAX_RESULT_ARTIFACTS {
            return Err(format!(
                "result artifact count {} exceeds {MAX_RESULT_ARTIFACTS}",
                self.artifacts.len()
            ));
        }
        let mut names = BTreeSet::new();
        let mut total = 0_u64;
        for artifact in &self.artifacts {
            let identity = artifact.name.to_ascii_lowercase();
            if !names.insert(identity) {
                return Err(format!(
                    "published result artifact name {:?} is duplicated case-insensitively",
                    artifact.name
                ));
            }
            total = total
                .checked_add(artifact.bytes)
                .ok_or_else(|| "published result byte total overflowed u64".to_owned())?;
            if total > MAX_RESULT_SET_BYTES {
                return Err(format!(
                    "published result set bytes {total} exceed {MAX_RESULT_SET_BYTES}"
                ));
            }
        }
        Ok(())
    }

    /// Returns the owner of this result set.
    pub fn owner(&self) -> &ResultOwner {
        &self.owner
    }

    /// Returns the published artifacts.
    pub fn artifacts(&self) -> &[ResultArtifactInfo] {
        &self.artifacts
    }
}

/// Validates the aggregate count, byte ceiling, and case-folded name uniqueness of checked specs.
///
/// # Errors
///
/// Returns a human-readable protocol validation error.
pub fn validate_result_specs(specs: &[ResultArtifactSpec]) -> Result<(), String> {
    if specs.len() > MAX_RESULT_ARTIFACTS {
        return Err(format!(
            "result artifact count {} exceeds {MAX_RESULT_ARTIFACTS}",
            specs.len()
        ));
    }
    let mut names = BTreeSet::new();
    let mut total = 0_u64;
    for spec in specs {
        total = total
            .checked_add(spec.max_bytes)
            .ok_or_else(|| "declared result byte total overflowed u64".to_owned())?;
        if total > MAX_RESULT_SET_BYTES {
            return Err(format!(
                "declared result set bytes {total} exceed {MAX_RESULT_SET_BYTES}"
            ));
        }
        let identity = spec.name.to_ascii_lowercase();
        if !names.insert(identity) {
            return Err(format!(
                "result artifact name {:?} is duplicated case-insensitively",
                spec.name
            ));
        }
    }
    Ok(())
}

/// Validates a portable logical result filename.
///
/// Names are filenames rather than paths and compare case-insensitively so a request accepted on
/// Linux cannot become ambiguous on Windows. A leading dot, underscore, or hyphen is allowed;
/// only the exact special names `.` and `..` are rejected.
///
/// # Errors
///
/// Returns a human-readable protocol validation error.
pub fn validate_result_name(name: &str) -> Result<(), String> {
    if name.is_empty() || name.len() > MAX_RESULT_NAME_BYTES {
        return Err(format!(
            "result artifact name length must be in 1..={MAX_RESULT_NAME_BYTES} bytes"
        ));
    }
    if !name.is_ascii() {
        return Err("result artifact name must be portable ASCII".to_owned());
    }
    if matches!(name, "." | "..") {
        return Err(format!(
            "result artifact name {name:?} must not be '.' or '..'"
        ));
    }
    if !name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(format!(
            "result artifact name {name:?} may contain only ASCII letters, digits, '.', '_' and '-'"
        ));
    }
    if name.ends_with('.') || is_windows_reserved_name(name) {
        return Err(format!(
            "result artifact name {name:?} is not a portable Windows filename"
        ));
    }
    Ok(())
}

/// Validates an opaque immediate-execution result-set identifier.
///
/// # Errors
///
/// Returns a human-readable protocol validation error.
pub fn validate_result_set_id(value: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > MAX_RESULT_SET_ID_BYTES {
        return Err(format!(
            "result set id length must be in 1..={MAX_RESULT_SET_ID_BYTES} bytes"
        ));
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err("result set id may contain only ASCII letters, digits, '-' and '_'".to_owned());
    }
    if is_windows_reserved_name(value) {
        return Err(format!(
            "result set id {value:?} is a reserved Windows device name"
        ));
    }
    Ok(())
}

fn is_windows_reserved_name(value: &str) -> bool {
    let stem = value
        .split('.')
        .next()
        .unwrap_or_default()
        .trim_end_matches([' ', '.'])
        .to_ascii_uppercase();
    matches!(
        stem.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CLOCK$" | "CONIN$" | "CONOUT$"
    ) || stem
        .strip_prefix("COM")
        .or_else(|| stem.strip_prefix("LPT"))
        .is_some_and(|suffix| suffix.len() == 1 && matches!(suffix.as_bytes()[0], b'1'..=b'9'))
}

fn validate_media_type(name: &str, media_type: Option<&str>) -> Result<(), String> {
    let Some(media_type) = media_type else {
        return Ok(());
    };
    if media_type.len() > MAX_RESULT_MEDIA_TYPE_BYTES {
        return Err(format!(
            "result artifact {name:?} media type exceeds {MAX_RESULT_MEDIA_TYPE_BYTES} bytes"
        ));
    }
    let trimmed = media_type.trim();
    if trimmed.is_empty() || trimmed != media_type {
        return Err(format!(
            "result artifact {name:?} media type must be non-empty and trimmed"
        ));
    }
    trimmed.parse::<mime::Mime>().map_err(|error| {
        format!("result artifact {name:?} has invalid media type {media_type:?}: {error}")
    })?;
    Ok(())
}
