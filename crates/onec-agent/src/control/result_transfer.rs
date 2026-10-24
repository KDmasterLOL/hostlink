//! Typed managed result download and cleanup routing.

use super::*;

pub(super) fn handle(
    mut stream: TcpStream,
    jobs_root: &Path,
    request: AgentRequestKind,
) -> io::Result<()> {
    match request {
        AgentRequestKind::ResultDownload { owner, name } => {
            match crate::results::open_published(jobs_root, &owner, &name) {
                Ok((artifact, mut file)) => {
                    let bytes = artifact.bytes();
                    write_json_line(
                        &mut stream,
                        &AgentResponse::success(AgentResponseKind::ResultDownloadReady {
                            artifact,
                        }),
                    )?;
                    let copied = io::copy(
                        &mut std::io::Read::by_ref(&mut file).take(bytes),
                        &mut stream,
                    )?;
                    if copied != bytes {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            format!(
                                "managed result changed while streaming: expected {bytes} bytes, sent {copied}"
                            ),
                        ));
                    }
                    Ok(())
                }
                Err(error) => write_json_line(&mut stream, &download_failure_response(&error)),
            }
        }
        AgentRequestKind::ResultCleanup { owner } => {
            let response = match crate::results::cleanup(jobs_root, &owner) {
                Ok(removed) => AgentResponse::success(AgentResponseKind::ResultCleaned { removed }),
                Err(error) => cleanup_failure_response(&error),
            };
            write_json_line(&mut stream, &response)
        }
        _ => unreachable!("request routed to wrong managed-result handler"),
    }
}

fn download_failure_response(_error: &io::Error) -> AgentResponse {
    AgentResponse::failure_with_code(
        AgentErrorCode::ResultDownloadFailed,
        "managed result is unavailable or invalid",
    )
}

fn cleanup_failure_response(_error: &io::Error) -> AgentResponse {
    AgentResponse::failure_with_code(
        AgentErrorCode::ResultCleanupFailed,
        "managed result set could not be safely removed",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    #[test]
    fn result_rpc_error_never_returns_the_target_local_root_path() {
        let directory = tempfile::tempdir().expect("target root");
        let jobs_root = directory.path().join("private-target-path");
        let underlying = io::Error::other(format!("open failed under {}", jobs_root.display()));
        let response = download_failure_response(&underlying);
        let serialized = serde_json::to_string(&response).expect("response JSON");
        assert!(!serialized.contains(&jobs_root.to_string_lossy().to_string()));
        assert_eq!(
            response.error_code,
            Some(AgentErrorCode::ResultDownloadFailed)
        );
        assert_eq!(
            response.error.as_deref(),
            Some("managed result is unavailable or invalid")
        );

        let response = cleanup_failure_response(&underlying);
        let serialized = serde_json::to_string(&response).expect("cleanup response JSON");
        assert!(!serialized.contains(&jobs_root.to_string_lossy().to_string()));
        assert_eq!(
            response.error_code,
            Some(AgentErrorCode::ResultCleanupFailed)
        );
    }
}
