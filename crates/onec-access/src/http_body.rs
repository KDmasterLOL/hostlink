//! Bounded async HTTP body helpers for HostLink Hub small control/manifest documents.

use crate::{AppResult, http_error};
use reqwest::Response;
use serde::de::DeserializeOwned;

pub(crate) const HUB_CONTROL_JSON_MAX_BYTES: usize = 4 * 1024 * 1024;
pub(crate) const HUB_ERROR_BODY_MAX_BYTES: usize = 64 * 1024;

pub(crate) async fn read_bounded_response_bytes(
    mut response: Response,
    max_bytes: usize,
    label: &str,
) -> AppResult<Vec<u8>> {
    let url = redacted_response_url(response.url());
    let known_length = response.content_length();
    if known_length.is_some_and(|length| length > max_bytes as u64) {
        return Err(http_error(format!(
            "{label} from {url} exceeds/read failed under {max_bytes}-byte limit: stream body exceeds maximum of {max_bytes} bytes (advertised length {})",
            known_length.expect("checked Some")
        )));
    }
    let initial_capacity = known_length
        .and_then(|length| usize::try_from(length).ok())
        .unwrap_or(max_bytes.min(64 * 1024))
        .min(max_bytes);
    let mut bytes = Vec::with_capacity(initial_capacity);
    while let Some(chunk) = response.chunk().await.map_err(|error| {
        http_error(format!(
            "{label} from {url} exceeds/read failed under {max_bytes}-byte limit: {error}"
        ))
    })? {
        if bytes.len().saturating_add(chunk.len()) > max_bytes {
            return Err(http_error(format!(
                "{label} from {url} exceeds/read failed under {max_bytes}-byte limit: stream body exceeds maximum of {max_bytes} bytes"
            )));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

pub(crate) async fn read_bounded_response_json<T: DeserializeOwned>(
    response: Response,
    max_bytes: usize,
    label: &str,
) -> AppResult<T> {
    let bytes = read_bounded_response_bytes(response, max_bytes, label).await?;
    serde_json::from_slice(&bytes)
        .map_err(|error| http_error(format!("{label} is invalid JSON: {error}")))
}

pub(crate) async fn bounded_error_text(response: Response, max_bytes: usize) -> String {
    match read_bounded_response_bytes(response, max_bytes, "HostLink Hub error response").await {
        Ok(bytes) => String::from_utf8_lossy(&bytes).trim().to_owned(),
        Err(_) => {
            "<response body omitted: exceeds diagnostic limit or could not be read>".to_owned()
        }
    }
}

fn redacted_response_url(url: &reqwest::Url) -> String {
    let mut redacted = url.clone();
    redacted.set_query(None);
    redacted.set_fragment(None);
    redacted.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::Client;
    use serde::Deserialize;
    use std::io::{Read as _, Write as _};
    use std::net::TcpListener;
    use std::thread;

    #[derive(Debug, Deserialize, PartialEq, Eq)]
    struct Fixture {
        value: String,
    }

    async fn loopback_response(headers: &str, body: Vec<u8>) -> (Response, thread::JoinHandle<()>) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let headers = headers.to_owned();
        let worker = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 2048];
            let _ = stream.read(&mut request).unwrap();
            write!(
                stream,
                "HTTP/1.1 200 OK\r\n{headers}Connection: close\r\n\r\n"
            )
            .unwrap();
            stream.write_all(&body).unwrap();
        });
        let response = Client::new()
            .get(format!("http://{address}/control?token=secret"))
            .send()
            .await
            .unwrap();
        (response, worker)
    }

    #[tokio::test]
    async fn bounded_hub_json_rejects_known_and_streamed_overflow() {
        let (response, worker) = loopback_response("Content-Length: 1000\r\n", Vec::new()).await;
        let error = read_bounded_response_json::<Fixture>(response, 16, "fixture")
            .await
            .expect_err("known oversized response");
        worker.join().unwrap();
        let message = error.to_string();
        assert!(message.contains("16-byte limit"), "{message}");
        assert!(!message.contains("token=secret"), "{message}");

        let (response, worker) = loopback_response("", vec![b'x'; 17]).await;
        assert!(
            read_bounded_response_bytes(response, 16, "fixture")
                .await
                .is_err(),
            "unknown-length response one byte over cap must fail"
        );
        worker.join().unwrap();
    }

    #[tokio::test]
    async fn bounded_hub_json_accepts_exact_body() {
        let body = br#"{"value":"ok"}"#.to_vec();
        let (response, worker) = loopback_response(
            &format!(
                "Content-Type: application/json\r\nContent-Length: {}\r\n",
                body.len()
            ),
            body.clone(),
        )
        .await;
        let parsed = read_bounded_response_json::<Fixture>(response, body.len(), "fixture")
            .await
            .unwrap();
        worker.join().unwrap();
        assert_eq!(
            parsed,
            Fixture {
                value: "ok".to_owned()
            }
        );
    }
}
