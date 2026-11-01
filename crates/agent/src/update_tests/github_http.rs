//! Real loopback GitHub API responses parsed by the pinned upstream backend.
use super::*;
use std::{
    collections::BTreeMap,
    io::{Read, Write},
    net::TcpListener,
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
};

const API: &str = "/repos/KDmasterLOL/hostlink/releases";
const FIXTURE_CREDENTIAL: &str = "disposable-fixture-credential";

struct Server {
    origin: String,
    // Record policy facts, never credential-bearing request text.
    requests: Arc<Mutex<Vec<(String, bool, bool)>>>,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}

impl Server {
    fn start(routes: BTreeMap<String, (u16, Vec<u8>, Option<String>)>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let received = Arc::clone(&requests);
        let stopped = Arc::clone(&stop);
        let worker = thread::spawn(move || {
            while !stopped.load(Ordering::SeqCst) {
                let (mut stream, _) = match listener.accept() {
                    Ok(stream) => stream,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(error) => panic!("fixture accept: {error}"),
                };
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut bytes = Vec::new();
                while !bytes.ends_with(b"\r\n\r\n") {
                    let mut byte = [0];
                    stream.read_exact(&mut byte).unwrap();
                    bytes.push(byte[0]);
                    assert!(bytes.len() <= 16384);
                }
                let text = std::str::from_utf8(&bytes).unwrap();
                let path = text
                    .lines()
                    .next()
                    .unwrap()
                    .split_whitespace()
                    .nth(1)
                    .unwrap();
                let authenticated = text.lines().any(|line| {
                    line.split_once(':').is_some_and(|(key, value)| {
                        key.eq_ignore_ascii_case("authorization")
                            && value.trim().ends_with(FIXTURE_CREDENTIAL)
                    })
                });
                let octet_stream = text
                    .lines()
                    .any(|line| line.eq_ignore_ascii_case("accept: application/octet-stream"));
                received
                    .lock()
                    .unwrap()
                    .push((path.to_owned(), authenticated, octet_stream));
                let missing = (404, Vec::new(), None);
                let (status, body, redirect) = routes.get(path).unwrap_or(&missing);
                let location = redirect
                    .as_ref()
                    .map_or(String::new(), |url| format!("Location: {url}\r\n"));
                let headers = format!(
                    "HTTP/1.1 {status} Fixture\r\nContent-Length: {}\r\n{location}Connection: close\r\n\r\n",
                    body.len()
                );
                // Oversized-body tests deliberately stop the reader early.
                let _ = stream
                    .write_all(headers.as_bytes())
                    .and_then(|()| stream.write_all(body));
            }
        });
        Self {
            origin,
            requests,
            stop,
            worker: Some(worker),
        }
    }

    fn discovery(&self) -> GitHubUpdate {
        GitHubUpdate::configure()
            .repo_owner("KDmasterLOL")
            .repo_name("hostlink")
            .api_base_url(&self.origin)
            .current_version("1.0.0")
            .bin_name(EXECUTABLE_BASE)
            .target(TARGET)
            .auth_token(FIXTURE_CREDENTIAL)
            .retries(0)
            .http_client(Arc::new(GitHubTransport::new(true, false)))
            .build()
            .unwrap()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        self.worker.take().unwrap().join().unwrap();
    }
}

fn metadata(tag: &str, draft: bool, prerelease: bool) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "tag_name": tag, "draft": draft, "prerelease": prerelease,
        "created_at": "2026-11-01T00:00:00Z", "assets": [{
            "name": format!("hostlink-agent-{TARGET}.zip"),
            "url": format!("https://api.github.com{API}/assets/1"),
            "digest": format!("sha256:{}", "a5".repeat(32))
        }]
    }))
    .unwrap()
}

#[test]
fn latest_and_both_exact_tag_spellings_use_upstream_single_release_api() {
    for (requested, tag, paths) in [
        (None, "v2.0.0", vec![format!("{API}/latest")]),
        (Some("0.9.0"), "v0.9.0", vec![format!("{API}/tags/v0.9.0")]),
        (
            Some("2.0.0-beta.1"),
            "2.0.0-beta.1",
            vec![
                format!("{API}/tags/v2.0.0-beta.1"),
                format!("{API}/tags/2.0.0-beta.1"),
            ],
        ),
    ] {
        let server = Server::start(BTreeMap::from([(
            paths.last().unwrap().clone(),
            (200, metadata(tag, false, tag.contains("beta")), None),
        )]));
        let requested = requested.map(|value| Version::parse(value).unwrap());
        let releases = discover_github_release(&server.discovery(), requested.as_ref()).unwrap();
        let (_, digest, selected) =
            select_github_asset(&releases, TARGET, requested.as_ref()).unwrap();
        assert_eq!(selected.to_string(), tag.trim_start_matches('v'));
        assert_eq!(digest, [0xa5; 32]);
        assert_eq!(
            *server.requests.lock().unwrap(),
            paths
                .into_iter()
                .map(|path| (path, true, false))
                .collect::<Vec<_>>()
        );
    }
}

#[test]
fn metadata_auth_errors_redirects_drafts_and_oversize_fail_closed() {
    for (status, body, redirect) in [
        (401, Vec::new(), None),
        (403, Vec::new(), None),
        (404, Vec::new(), None),
        (302, Vec::new(), Some("/unexpected".to_owned())),
        (200, metadata("v2.0.0", true, false), None),
        (200, metadata("v2.0.0-beta.1", false, true), None),
        (200, br#"{"draft": false}"#.to_vec(), None),
        (200, vec![b' '; MAX_METADATA_BYTES as usize + 1], None),
    ] {
        let server = Server::start(BTreeMap::from([(
            format!("{API}/latest"),
            (status, body, redirect),
        )]));
        let error = discover_github_release(&server.discovery(), None).unwrap_err();
        assert!(!error.to_string().contains(FIXTURE_CREDENTIAL));
        assert_eq!(server.requests.lock().unwrap().len(), 1);
    }
    for status in [401, 403, 500] {
        let server = Server::start(BTreeMap::from([(
            format!("{API}/tags/v2.0.0"),
            (status, Vec::new(), None),
        )]));
        assert!(
            discover_github_release(&server.discovery(), Some(&Version::parse("2.0.0").unwrap()))
                .is_err()
        );
        assert_eq!(server.requests.lock().unwrap().len(), 1);
    }
    let server = Server::start(BTreeMap::from([(
        format!("{API}/tags/v2.0.0"),
        (200, metadata("v2.0.0", true, false), None),
    )]));
    assert!(
        discover_github_release(&server.discovery(), Some(&Version::parse("2.0.0").unwrap()))
            .is_err()
    );
    assert_eq!(server.requests.lock().unwrap().len(), 1);
}

#[test]
fn api_asset_200_and_302_install_with_auth_only_on_initial_request() {
    let body = package("2.0.0", b"GitHub fixture executable", false);
    let cdn = Server::start(BTreeMap::from([(
        "/asset.zip".into(),
        (200, body.clone(), None),
    )]));
    for redirect in [
        None,
        Some(format!("{}/asset.zip", cdn.origin)),
        Some("/same-origin.zip".to_owned()),
    ] {
        let routes = BTreeMap::from([
            (
                format!("{API}/assets/1"),
                if let Some(url) = &redirect {
                    (302, Vec::new(), Some(url.clone()))
                } else {
                    (200, body.clone(), None)
                },
            ),
            ("/same-origin.zip".into(), (200, body.clone(), None)),
        ]);
        let api = Server::start(routes);
        let fixture = Fixture::new();
        let mut publisher = Update::configure();
        publisher
            .http_client(Arc::new(GitHubTransport::new(false, false)))
            .allow_auth_host("127.0.0.1")
            .request_header(
                self_update::http::header::AUTHORIZATION,
                format!("Bearer {FIXTURE_CREDENTIAL}"),
            )
            .request_header(
                self_update::http::header::ACCEPT,
                "application/octet-stream",
            );
        assert!(
            apply_selected(
                &fixture.root,
                &Url::parse(&format!("{}{API}/assets/1", api.origin)).unwrap(),
                hex::decode(digest(&body)).unwrap().try_into().unwrap(),
                TARGET,
                &Version::parse("2.0.0").unwrap(),
                publisher,
                true
            )
            .unwrap()
        );
        let requests = api.requests.lock().unwrap();
        assert!(
            requests[0].1 && requests[0].2,
            "initial API request must have auth and octet-stream accept: {:?}",
            requests
                .iter()
                .map(|(_, auth, octet)| (*auth, *octet))
                .collect::<Vec<_>>()
        );
        assert!(requests.iter().skip(1).all(|request| !request.1));
        assert_eq!(read_installed(&fixture.root).unwrap().0.version, "2.0.0");
    }
    assert!(
        cdn.requests
            .lock()
            .unwrap()
            .iter()
            .all(|request| !request.1)
    );
    assert_eq!(cdn.requests.lock().unwrap().len(), 1);
}
