//! Typed managed-result retrieval over the authenticated agent protocol.

use super::{create_local_temp_file, download::publish_staged_file, download::transfer_temp_path};
use crate::remote::model::RemoteAgentClient;
use crate::remote::protocol::{read_response_unbuffered, response_into_kind, write_request};
use crate::{AppResult, io_error};
use hostlink_protocol::{
    AgentRequest, AgentRequestKind, AgentResponseKind, ResultArtifactInfo, ResultOwner,
};
use std::fs;
use std::path::Path;
use tokio::io::{self, AsyncReadExt};

impl RemoteAgentClient {
    /// Downloads one logical result artifact through the typed `results-v1` RPC.
    ///
    /// The remote owner is never converted into a physical path, and result retrieval never uses
    /// SFTP. Bytes are verified against the immutable metadata before shared staged publication.
    ///
    /// # Errors
    ///
    /// Returns [`crate::AppError`] for invalid identity, missing capability, transfer/integrity
    /// failure, local I/O/publication failure, or overwrite-policy failure.
    pub async fn result_download(
        &self,
        owner: ResultOwner,
        expected: &ResultArtifactInfo,
        local_path: impl AsRef<Path>,
        overwrite: bool,
    ) -> AppResult<u64> {
        let name = expected.name().to_owned();
        self.require_capability("results-v1").await?;
        let local_path = local_path.as_ref();
        if !overwrite && local_path.exists() {
            return Err(crate::invalid_config(format!(
                "download target already exists: {}",
                local_path.display()
            )));
        }
        if let Some(parent) = local_path.parent() {
            fs::create_dir_all(parent).map_err(|source| io_error(parent, source))?;
        }

        let request = AgentRequest::new(
            self.server.secret()?,
            AgentRequestKind::ResultDownload {
                owner,
                name: name.to_owned(),
            },
        );
        let mut channel = self.open_channel().await?;
        write_request(&mut channel, &request)
            .await
            .map_err(|source| {
                crate::invalid_config(format!("failed to send result download request: {source}"))
            })?;
        channel.close_write().await?;
        let artifact = match response_into_kind(read_response_unbuffered(&mut channel).await?)? {
            AgentResponseKind::ResultDownloadReady { artifact } => artifact,
            other => {
                return Err(crate::invalid_config(format!(
                    "agent returned unexpected result download response: {other:?}"
                )));
            }
        };
        ensure_expected_result_metadata(expected, &artifact)?;
        self.receive_result_bytes(&mut channel, &artifact, local_path, overwrite)
            .await
    }

    /// Removes one complete managed result set through the typed `results-v1` RPC.
    ///
    /// # Errors
    ///
    /// Returns [`crate::AppError`] for invalid identity, missing capability, transport failure,
    /// or an unexpected response.
    pub async fn result_cleanup(&self, owner: ResultOwner) -> AppResult<bool> {
        self.require_capability("results-v1").await?;
        match self
            .request(AgentRequestKind::ResultCleanup { owner })
            .await?
        {
            AgentResponseKind::ResultCleaned { removed } => Ok(removed),
            other => Err(crate::invalid_config(format!(
                "agent returned unexpected result cleanup response: {other:?}"
            ))),
        }
    }

    async fn receive_result_bytes(
        &self,
        channel: &mut crate::remote::ssh::RemoteChannel,
        artifact: &ResultArtifactInfo,
        local_path: &Path,
        overwrite: bool,
    ) -> AppResult<u64> {
        let temp = transfer_temp_path(local_path);
        let (mut temp_guard, mut file) = create_local_temp_file(temp)?;
        let temp = temp_guard.path().to_path_buf();
        let copied = {
            let mut limited = (&mut *channel).take(artifact.bytes());
            match io::copy(&mut limited, &mut file).await {
                Ok(copied) => copied,
                Err(source) => {
                    drop(file);
                    temp_guard.cleanup_best_effort().await;
                    return Err(io_error(&temp, source));
                }
            }
        };
        if copied != artifact.bytes() {
            drop(file);
            temp_guard.cleanup_best_effort().await;
            return Err(crate::invalid_config(format!(
                "result download ended after {copied} of {} bytes",
                artifact.bytes()
            )));
        }
        if let Err(source) = file.sync_all().await {
            drop(file);
            temp_guard.cleanup_best_effort().await;
            return Err(io_error(&temp, source));
        }
        drop(file);
        if let Err(error) = channel.finish().await {
            temp_guard.cleanup_best_effort().await;
            return Err(error);
        }
        publish_staged_file(
            &temp,
            local_path,
            overwrite,
            artifact.bytes(),
            Some(artifact.sha256()),
            &format!("managed result {:?}", artifact.name()),
        )
        .await?;
        temp_guard.disarm();
        Ok(copied)
    }
}

fn ensure_expected_result_metadata(
    expected: &ResultArtifactInfo,
    received: &ResultArtifactInfo,
) -> AppResult<()> {
    if received != expected {
        return Err(crate::invalid_config(format!(
            "agent result metadata for {:?} differs from the authoritative operation metadata",
            expected.name()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info() -> ResultArtifactInfo {
        ResultArtifactInfo::try_new(
            "report.json".to_owned(),
            4,
            "a".repeat(64),
            Some("application/json".to_owned()),
        )
        .expect("valid result metadata")
    }

    #[test]
    fn download_header_must_equal_authoritative_artifact_metadata() {
        let expected = info();
        ensure_expected_result_metadata(&expected, &expected).expect("identical metadata");
        let mut mismatches = Vec::new();
        mismatches.push(
            ResultArtifactInfo::try_new(
                "other.json".to_owned(),
                4,
                "a".repeat(64),
                Some("application/json".to_owned()),
            )
            .expect("valid metadata"),
        );
        mismatches.push(
            ResultArtifactInfo::try_new(
                "report.json".to_owned(),
                5,
                "a".repeat(64),
                Some("application/json".to_owned()),
            )
            .expect("valid metadata"),
        );
        mismatches.push(
            ResultArtifactInfo::try_new(
                "report.json".to_owned(),
                4,
                "b".repeat(64),
                Some("application/json".to_owned()),
            )
            .expect("valid metadata"),
        );
        mismatches.push(
            ResultArtifactInfo::try_new(
                "report.json".to_owned(),
                4,
                "a".repeat(64),
                Some("application/octet-stream".to_owned()),
            )
            .expect("valid metadata"),
        );
        for received in mismatches {
            assert!(ensure_expected_result_metadata(&expected, &received).is_err());
        }
    }
}
