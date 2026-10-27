use std::{collections::HashMap, sync::Arc};

use russh::{
    Channel, ChannelId,
    keys::{Algorithm, PrivateKey, PublicKey},
    server::{self, Auth, Msg, Session},
};
use serde_json::Value;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::Mutex,
    task::JoinHandle,
};

use super::*;
use crate::connect::{HostConnection, connect_stream_authenticated};

const ID: &str = "550e8400-e29b-41d4-a716-446655440000";

#[derive(Clone, Copy, Debug)]
enum Reply {
    Status,
    State(&'static str),
    WrongVersion,
    Oversized,
    Partial,
    BinaryOutput,
    BadOffset,
    EmptyRunning,
    SealSuccess,
    SealWrongDigest,
    SealMalformed,
    Close,
}

struct Fixture {
    authorized_key: PublicKey,
    channels: Arc<Mutex<HashMap<ChannelId, Channel<Msg>>>>,
    requests: Arc<Mutex<Vec<Value>>>,
    reply: Reply,
}

impl server::Handler for Fixture {
    type Error = russh::Error;

    async fn auth_publickey(&mut self, _user: &str, key: &PublicKey) -> Result<Auth, Self::Error> {
        Ok(if key == &self.authorized_key {
            Auth::Accept
        } else {
            Auth::reject()
        })
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.channels.lock().await.insert(channel.id(), channel);
        reply.accept().await;
        Ok(())
    }

    async fn subsystem_request(
        &mut self,
        channel_id: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if name != SUBSYSTEM {
            session.channel_failure(channel_id)?;
            return Ok(());
        }
        let Some(channel) = self.channels.lock().await.remove(&channel_id) else {
            session.channel_failure(channel_id)?;
            return Ok(());
        };
        session.channel_success(channel_id)?;
        let requests = self.requests.clone();
        let reply = self.reply;
        tokio::spawn(async move {
            let mut stream = channel.into_stream();
            let mut header = [0_u8; 4];
            if stream.read_exact(&mut header).await.is_err() {
                return;
            }
            let length = u32::from_be_bytes(header) as usize;
            if length > MAX_FRAME_BYTES {
                return;
            }
            let mut request = vec![0; length];
            if stream.read_exact(&mut request).await.is_err() {
                return;
            }
            let request: Value =
                serde_json::from_slice(&request).expect("valid client request JSON");
            requests.lock().await.push(request);

            let mut response = match reply {
                Reply::Status | Reply::Close | Reply::State(_) => serde_json::json!({
                    "version": 1, "ok": true, "id": ID,
                    "state": match reply {
                        Reply::State(state) => serde_json::from_str::<Value>(state).unwrap(),
                        _ => serde_json::json!({"state": "exited", "code": 7}),
                    },
                    "data_base64": null, "next_offset": null, "eof": null
                })
                .to_string()
                .into_bytes(),
                Reply::WrongVersion => serde_json::json!({
                    "version": 2, "ok": true, "id": ID,
                    "state": {"state": "running"},
                    "data_base64": null, "next_offset": null, "eof": null
                })
                .to_string()
                .into_bytes(),
                Reply::Oversized => vec![b'x'; MAX_FRAME_BYTES + 5],
                Reply::Partial => vec![0, 0, 0, 25, b'{'],
                Reply::BinaryOutput => serde_json::json!({
                    "version": 1, "ok": true, "id": ID,
                    "state": {"state": "running"},
                    "data_base64": "AP8K/w==", "next_offset": 4, "eof": false
                })
                .to_string()
                .into_bytes(),
                Reply::BadOffset => serde_json::json!({
                    "version": 1, "ok": true, "id": ID,
                    "state": {"state": "running"},
                    "data_base64": "AP8K/w==", "next_offset": 9, "eof": false
                })
                .to_string()
                .into_bytes(),
                Reply::EmptyRunning => serde_json::json!({
                    "version": 1, "ok": true, "id": ID,
                    "state": {"state": "running"},
                    "data_base64": "", "next_offset": 0, "eof": false
                })
                .to_string()
                .into_bytes(),
                Reply::SealSuccess => serde_json::json!({
                    "version": 1, "ok": true,
                    "program": if cfg!(windows) { r"C:\\agent\\artifacts\\pinned.exe" } else { "/agent/artifacts/pinned" },
                    "sha256": "a".repeat(64)
                })
                .to_string()
                .into_bytes(),
                Reply::SealWrongDigest => serde_json::json!({
                    "version": 1, "ok": true,
                    "program": if cfg!(windows) { r"C:\\agent\\artifacts\\pinned.exe" } else { "/agent/artifacts/pinned" },
                    "sha256": "b".repeat(64)
                })
                .to_string()
                .into_bytes(),
                Reply::SealMalformed => serde_json::json!({
                    "version": 1, "ok": true, "program": "relative/path", "sha256": "a".repeat(64)
                })
                .to_string()
                .into_bytes(),
            };
            if matches!(reply, Reply::Close) {
                let _ = stream.shutdown().await;
                return;
            }
            let mut frame = Vec::with_capacity(response.len() + 4);
            if !matches!(reply, Reply::Partial) {
                frame.extend_from_slice(&(response.len() as u32).to_be_bytes());
            }
            frame.append(&mut response);
            let _ = stream.write_all(&frame).await;
            let _ = stream.shutdown().await;
        });
        Ok(())
    }
}

async fn connected(
    reply: Reply,
) -> (
    HostConnection,
    JoinHandle<Result<(), russh::Error>>,
    Arc<Mutex<Vec<Value>>>,
) {
    let identity = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("client key");
    let host_key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("host key");
    let (client_stream, server_stream) = tokio::io::duplex(256 * 1024);
    let channels = Arc::new(Mutex::new(HashMap::new()));
    let requests = Arc::new(Mutex::new(Vec::new()));
    let server_channels = channels.clone();
    let server_requests = requests.clone();
    let authorized_key = identity.public_key().clone();
    let config = Arc::new(server::Config {
        keys: vec![host_key.clone()],
        ..Default::default()
    });
    let task = tokio::spawn(async move {
        let session = server::run_stream(
            config,
            server_stream,
            Fixture {
                authorized_key,
                channels: server_channels,
                requests: server_requests,
                reply,
            },
        )
        .await?;
        session.await
    });
    let session = connect_stream_authenticated(
        client_stream,
        "fixture-user",
        identity,
        host_key.public_key().clone(),
    )
    .await
    .expect("authenticate in-process russh fixture");
    (
        HostConnection::from_authenticated_session(session),
        task,
        requests,
    )
}

fn start() -> Start {
    Start {
        id: ID.into(),
        spec: JobSpec {
            program: if cfg!(windows) {
                r"C:\hostlink-fixture\runner.exe"
            } else {
                "/usr/bin/true"
            }
            .into(),
            args: vec!["--version".into()],
            cwd: None,
            source_sha256: "a".repeat(64),
        },
    }
}

async fn finish(connection: HostConnection, task: JoinHandle<Result<(), russh::Error>>) {
    let _ = connection.close().await;
    task.abort();
}

#[tokio::test]
async fn start_status_and_binary_output_use_one_subsystem_request_each() {
    let (mut connection, task, requests) = connected(Reply::Status).await;
    let status = connection
        .job_start(&start())
        .await
        .expect("start response");
    assert_eq!(status.id, ID);
    assert_eq!(status.state, JobState::Exited { code: 7 });
    assert_eq!(requests.lock().await[0]["op"], "start");
    finish(connection, task).await;

    let (mut connection, task, requests) = connected(Reply::BinaryOutput).await;
    let output = connection
        .job_output(&Output {
            id: ID.into(),
            stream: JobStream::Stdout,
            offset: 0,
        })
        .await
        .expect("output response");
    assert_eq!(output.data, [0, 255, 10, 255]);
    assert_eq!(output.next_offset, 4);
    assert!(!output.eof);
    assert_eq!(requests.lock().await[0]["op"], "output");
    finish(connection, task).await;
}

#[tokio::test]
async fn seal_uses_frozen_contract_and_returns_agent_path_only_after_digest_match() {
    let (mut connection, task, requests) = connected(Reply::SealSuccess).await;
    let sealed = connection
        .job_seal(&Seal {
            name: format!("{}.upload", "a".repeat(64)),
            sha256: "a".repeat(64),
            size: 123,
        })
        .await
        .expect("exact Seal response");
    assert_eq!(sealed.sha256, "a".repeat(64));
    assert!(std::path::Path::new(&sealed.program).is_absolute() || cfg!(windows));
    assert_eq!(requests.lock().await[0]["version"], 1);
    assert_eq!(requests.lock().await[0]["op"], "seal");
    assert_eq!(
        requests.lock().await[0]["name"],
        format!("{}.upload", "a".repeat(64))
    );
    assert_eq!(requests.lock().await[0]["sha256"], "a".repeat(64));
    assert_eq!(requests.lock().await[0]["size"], 123);
    finish(connection, task).await;

    let (mut connection, task, _) = connected(Reply::SealWrongDigest).await;
    assert!(
        connection
            .job_seal(&Seal {
                name: format!("{}.upload", "a".repeat(64)),
                sha256: "a".repeat(64),
                size: 123,
            })
            .await
            .is_err()
    );
    finish(connection, task).await;

    let (mut connection, task, _) = connected(Reply::SealMalformed).await;
    assert!(
        connection
            .job_seal(&Seal {
                name: format!("{}.upload", "a".repeat(64)),
                sha256: "a".repeat(64),
                size: 123,
            })
            .await
            .is_err()
    );
    finish(connection, task).await;

    for invalid_name in [".upload".to_owned(), format!("{}.upload", "b".repeat(64))] {
        let (mut connection, task, requests) = connected(Reply::SealSuccess).await;
        assert!(
            connection
                .job_seal(&Seal {
                    name: invalid_name,
                    sha256: "a".repeat(64),
                    size: 123,
                })
                .await
                .is_err()
        );
        assert!(
            requests.lock().await.is_empty(),
            "invalid name must fail before sending"
        );
        finish(connection, task).await;
    }
}

#[tokio::test]
async fn empty_output_before_first_bytes_is_valid_while_job_runs() {
    let (mut connection, task, _) = connected(Reply::EmptyRunning).await;
    let output = connection
        .job_output(&Output {
            id: ID.into(),
            stream: JobStream::Stdout,
            offset: 0,
        })
        .await
        .expect("empty running stream is a valid read");
    assert!(output.data.is_empty());
    assert!(!output.eof);
    finish(connection, task).await;
}

#[tokio::test]
async fn rejects_wrong_version_oversized_partial_and_bad_offset() {
    for reply in [
        Reply::WrongVersion,
        Reply::Oversized,
        Reply::Partial,
        Reply::BadOffset,
    ] {
        let (mut connection, task, _) = connected(reply).await;
        let result = if matches!(reply, Reply::BadOffset) {
            connection
                .job_output(&Output {
                    id: ID.into(),
                    stream: JobStream::Stderr,
                    offset: 0,
                })
                .await
                .map(|_| ())
        } else {
            connection
                .job_status(&Status { id: ID.into() })
                .await
                .map(|_| ())
        };
        assert!(result.is_err(), "{reply:?} must fail closed");
        finish(connection, task).await;
    }
}

#[tokio::test]
async fn close_before_reply_is_missing_response_not_fabricated_status() {
    let (mut connection, task, _) = connected(Reply::Close).await;
    assert!(
        connection
            .job_status(&Status { id: ID.into() })
            .await
            .is_err()
    );
    finish(connection, task).await;
}

#[tokio::test]
async fn malformed_state_replies_fail_start_without_replaying_it() {
    for state in [
        r#"{"state":"exited"}"#,
        r#"{"state":"exited","code":null}"#,
        r#"{"state":"running","code":7}"#,
        r#"{"state":"prepared","unknown":true}"#,
        r#"{"state":"failed","code":null}"#,
        r#"{"state":"interrupted","extra":0}"#,
        r#"{"state":"exited","code":7,"extra":0}"#,
        r#"{"code":7}"#,
        r#"{"state":"unknown"}"#,
    ] {
        let (mut connection, task, requests) = connected(Reply::State(state)).await;
        assert!(connection.job_start(&start()).await.is_err(), "{state}");
        let requests = requests.lock().await;
        assert_eq!(requests.len(), 1, "invalid ACK must never replay start");
        assert_eq!(requests[0]["op"], "start");
        drop(requests);
        finish(connection, task).await;
    }
}

#[tokio::test]
async fn lost_start_ack_is_not_retried_and_reconnect_status_is_explicit() {
    let (mut first, first_task, first_requests) = connected(Reply::Close).await;
    assert!(first.job_start(&start()).await.is_err());
    assert_eq!(first_requests.lock().await.len(), 1);
    assert_eq!(first_requests.lock().await[0]["op"], "start");
    finish(first, first_task).await;

    let (mut reconnected, next_task, next_requests) = connected(Reply::Status).await;
    let status = reconnected
        .job_status(&Status { id: ID.into() })
        .await
        .expect("explicit status query after reconnect");
    assert_eq!(status.state, JobState::Exited { code: 7 });
    assert_eq!(next_requests.lock().await.len(), 1);
    assert_eq!(next_requests.lock().await[0]["op"], "status");
    finish(reconnected, next_task).await;
}

#[tokio::test]
async fn rejects_noncanonical_id_before_opening_channel() {
    let (mut connection, task, requests) = connected(Reply::Status).await;
    assert!(
        connection
            .job_status(&Status {
                id: "550E8400-E29B-41D4-A716-446655440000".into(),
            })
            .await
            .is_err()
    );
    assert!(requests.lock().await.is_empty());
    finish(connection, task).await;
}

#[test]
fn rejects_partial_and_trailing_frames() {
    assert!(decode_frame(&[0, 0, 0]).is_err());
    assert!(decode_frame(&[0, 0, 0, 0]).is_err());
    assert!(decode_frame(&((MAX_FRAME_BYTES + 1) as u32).to_be_bytes()).is_err());
    assert!(decode_frame(&[0, 0, 0, 3, b'{']).is_err());
    assert!(decode_frame(&[0, 0, 0, 2, b'{', b'}', 0]).is_err());
}
