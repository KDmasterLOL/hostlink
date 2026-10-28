use super::{JobSpec, JobStatus, Seal, Start, sealed_artifact_name, validate_id};
use crate::connect::{HostConnection, SshClientError};
use sha2::{Digest as _, Sha256};

impl HostConnection {
    /// Upload, SHA-verify, seal and enqueue one source-pinned binary. Never retries start.
    /// Generate and retain the canonical ULID before connecting; a lost ACK needs status lookup.
    /// # Errors
    /// Returns validation, SFTP, seal or admission errors. A transport error is UNKNOWN.
    pub async fn job_run(
        &mut self,
        id: &str,
        bytes: &[u8],
        args: &[String],
    ) -> Result<JobStatus, SshClientError> {
        validate_id(id)?;
        if bytes.len() > 64 * 1024 * 1024
            || args.iter().any(|a| a.contains('\0'))
            || serde_json::to_vec(args)
                .map_err(|e| SshClientError::Invalid(e.to_string()))?
                .len()
                > 60 * 1024
        {
            return Err(SshClientError::Invalid(
                "binary or arguments exceed job limits".into(),
            ));
        }
        let digest = format!("{:x}", Sha256::digest(bytes));
        let name = sealed_artifact_name(&digest)?;
        match self.sftp_upload(&name, bytes).await {
            Ok(()) => {}
            // CREATE_EXCL can return generic Failure for an existing upload.
            // Only the following authenticated SHA/size verification may accept it.
            Err(error) if sftp_failure_may_be_existing_file(&error) => {}
            Err(error) => return Err(error),
        }
        let program = self
            .job_seal(&Seal {
                name,
                sha256: digest.clone(),
                size: bytes.len() as u64,
            })
            .await?;
        self.job_start(&Start {
            id: id.into(),
            spec: JobSpec {
                program,
                args: args.into(),
                cwd: None,
                source_sha256: digest,
            },
        })
        .await
    }
}

pub(super) fn sftp_failure_may_be_existing_file(error: &SshClientError) -> bool {
    matches!(error, SshClientError::Sftp(russh_sftp::client::error::Error::Status(status))
        if status.status_code == russh_sftp::protocol::StatusCode::Failure)
}
