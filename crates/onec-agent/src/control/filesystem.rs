//! File transfer, integrity, atomic publication, and scoped filesystem request handling.

use super::*;
use std::path::Path;

pub(super) fn handle(mut stream: TcpStream, request: AgentRequestKind) -> io::Result<()> {
    match request {
        AgentRequestKind::Upload {
            path,
            bytes,
            overwrite,
        } => {
            let path = PathBuf::from(path);
            if !overwrite && path.exists() {
                write_json_line(
                    &mut stream,
                    &AgentResponse::failure(format!(
                        "upload target already exists: {}",
                        path.display()
                    )),
                )?;
                return Ok(());
            }

            let parent = path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            let mut temp = match tempfile::Builder::new()
                .prefix(".onec-upload-")
                .tempfile_in(parent)
            {
                Ok(file) => file,
                Err(error) => {
                    write_json_line(
                        &mut stream,
                        &AgentResponse::failure(format!(
                            "failed to create upload staging file for {}: {error}",
                            path.display()
                        )),
                    )?;
                    return Ok(());
                }
            };

            write_json_line(
                &mut stream,
                &AgentResponse::success(AgentResponseKind::UploadReady),
            )?;
            let copied = {
                let mut limited = (&mut stream).take(bytes);
                io::copy(&mut limited, temp.as_file_mut())?
            };
            if copied != bytes {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    format!("upload ended after {copied} of {bytes} bytes"),
                ));
            }
            temp.as_file().sync_all()?;

            // Close the staging handle before Windows atomic rename while retaining RAII cleanup.
            let temp = temp.into_temp_path();
            let publication = if overwrite {
                hostlink_core::replace_file_atomically(temp.as_ref(), &path)
            } else {
                hostlink_core::move_file_atomically(temp.as_ref(), &path)
            };
            if let Err(error) = publication {
                write_json_line(
                    &mut stream,
                    &AgentResponse::failure(format!(
                        "failed to publish upload {}: {error}",
                        path.display()
                    )),
                )?;
                return Ok(());
            }

            write_json_line(
                &mut stream,
                &AgentResponse::success(AgentResponseKind::Uploaded { bytes: copied }),
            )
        }
        AgentRequestKind::Download { path } => {
            let path = PathBuf::from(path);
            let mut file = match fs::File::open(&path) {
                Ok(file) => file,
                Err(error) => {
                    write_json_line(
                        &mut stream,
                        &AgentResponse::failure(format!(
                            "failed to open download source {}: {error}",
                            path.display()
                        )),
                    )?;
                    return Ok(());
                }
            };
            let bytes = file.metadata()?.len();
            write_json_line(
                &mut stream,
                &AgentResponse::success(AgentResponseKind::DownloadReady { bytes }),
            )?;
            let copied = io::copy(&mut file, &mut stream)?;
            if copied != bytes {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    format!("download sent {copied} of {bytes} bytes"),
                ));
            }
            Ok(())
        }
        AgentRequestKind::PathSha256 { path } => {
            let path = PathBuf::from(path);
            let response = path_sha256_response(&path);
            write_json_line(&mut stream, &response)
        }
        AgentRequestKind::PathRemoveScoped {
            root,
            path,
            recursive,
            missing_ok,
        } => {
            let root = PathBuf::from(root);
            let path = PathBuf::from(path);
            let response = match hostlink_core::remove_path_scoped(&root, &path, recursive, missing_ok)
            {
                Ok(removed) => AgentResponse::success(AgentResponseKind::PathRemoved { removed }),
                Err(error) => AgentResponse::failure(format!(
                    "refused scoped path removal root={} path={}: {error}",
                    root.display(),
                    path.display()
                )),
            };
            write_json_line(&mut stream, &response)
        }
        AgentRequestKind::PathRename {
            from,
            to,
            overwrite,
        } => {
            let from = PathBuf::from(from);
            let to = PathBuf::from(to);
            let response = match if overwrite {
                hostlink_core::replace_file_atomically(&from, &to)
            } else {
                hostlink_core::move_file_atomically(&from, &to)
            } {
                Ok(()) => AgentResponse::success(AgentResponseKind::PathRenamed),
                Err(error) => AgentResponse::failure(format!(
                    "failed to rename {} to {}: {error}",
                    from.display(),
                    to.display()
                )),
            };
            write_json_line(&mut stream, &response)
        }
        _ => unreachable!("request routed to wrong control handler"),
    }
}

fn path_sha256_response(path: &Path) -> AgentResponse {
    match hostlink_core::digest_file(path) {
        Ok(digest) => AgentResponse::success(AgentResponseKind::PathSha256 {
            bytes: digest.bytes(),
            sha256: digest.sha256().to_owned(),
        }),
        Err(error) if error.kind() == io::ErrorKind::NotFound => AgentResponse::failure_with_code(
            onec_agent_protocol::AgentErrorCode::PathNotFound,
            "requested path does not exist",
        ),
        Err(error) => AgentResponse::failure(format!("failed to hash path: {error}")),
    }
}

#[cfg(test)]
mod tests {
    use super::path_sha256_response;
    use onec_agent_protocol::{AgentErrorCode, AgentResponseKind};

    #[test]
    fn path_hash_reports_only_proven_missing_as_typed_not_found() {
        let root = tempfile::tempdir().expect("tempdir");
        let missing = path_sha256_response(&root.path().join("absent.bin"));
        assert!(!missing.ok);
        assert_eq!(missing.error_code, Some(AgentErrorCode::PathNotFound));

        let file = root.path().join("present.bin");
        std::fs::write(&file, b"content").expect("write fixture");
        let present = path_sha256_response(&file);
        assert!(matches!(
            present.response,
            Some(AgentResponseKind::PathSha256 { bytes: 7, .. })
        ));
    }
}
