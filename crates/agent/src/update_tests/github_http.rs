//! Real loopback GitHub API responses parsed by the pinned upstream backend.
use super::*;
use std::{collections::BTreeMap, net::TcpListener, sync::Mutex, thread};

const API: &str = "/repos/KDmasterLOL/hostlink/releases";
const FIXTURE_CREDENTIAL: &str = "disposable-fixture-credential";

struct Server {
    origin: String,
    // Record policy facts, never credential-bearing request text.
    requests: Arc<Mutex<Vec<(String, bool, bool)>>>,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    worker: Option<thread::JoinHandle<()>>,
}

impl Server {
    fn start(routes: BTreeMap<String, (u16, Vec<u8>, Option<String>)>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let received = Arc::clone(&requests);
        let worker = thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async move {
                    let app =
                        axum::Router::new().fallback(move |request: axum::extract::Request| {
                            let path = request.uri().path();
                            let authenticated = request
                                .headers()
                                .get(header::AUTHORIZATION)
                                .and_then(|value| value.to_str().ok())
                                .is_some_and(|value| value.ends_with(FIXTURE_CREDENTIAL));
                            let octet_stream = request
                                .headers()
                                .get(header::ACCEPT)
                                .is_some_and(|value| value == "application/octet-stream");
                            received.lock().unwrap().push((
                                path.into(),
                                authenticated,
                                octet_stream,
                            ));
                            let (status, body, redirect) =
                                routes.get(path).cloned().unwrap_or((404, Vec::new(), None));
                            async move {
                                let mut response = axum::http::Response::builder().status(status);
                                if let Some(location) = redirect {
                                    response = response.header(header::LOCATION, location);
                                }
                                response.body(axum::body::Body::from(body)).unwrap()
                            }
                        });
                    axum::serve(tokio::net::TcpListener::from_std(listener).unwrap(), app)
                        .with_graceful_shutdown(async {
                            let _ = stopped.await;
                        })
                        .await
                        .unwrap();
                });
        });
        Self {
            origin,
            requests,
            stop: Some(stop),
            worker: Some(worker),
        }
    }

    fn apply(&self, fixture: &Fixture, requested: Option<&str>) -> io::Result<bool> {
        // Route actual upstream HTTP through loopback; production metadata still
        // contains the canonical private GitHub URLs and a synthetic credential.
        struct Loopback {
            origin: String,
            client: Box<dyn HttpClient>,
        }
        impl HttpClient for Loopback {
            fn get(
                &self,
                url: &str,
                headers: &HeaderMap,
                timeout: Option<Duration>,
            ) -> self_update::Result<Box<dyn HttpResponse>> {
                let path = url.strip_prefix("https://api.github.com").unwrap();
                self.client
                    .get(&format!("{}{path}", self.origin), headers, timeout)
            }
        }
        let transport = GitHubTransport::new(false);
        let route = |client| {
            Box::new(Loopback {
                origin: self.origin.clone(),
                client,
            }) as Box<dyn HttpClient>
        };
        let transport = Arc::new(GitHubTransport {
            metadata: route(transport.metadata),
            assets: route(transport.assets),
            publication: OnceLock::new(),
        });
        let mut updater = Update::configure();
        updater.auth_token(FIXTURE_CREDENTIAL);
        let version = requested.map(|version| Version::parse(version).unwrap());
        apply_update(&fixture.root, version.as_ref(), updater, transport)
    }

    fn release(tag: &str, body: &[u8]) -> Self {
        Self::start(routes(tag, body))
    }

    fn paths(&self) -> Vec<String> {
        self.requests
            .lock()
            .unwrap()
            .iter()
            .map(|r| r.0.clone())
            .collect()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.stop.take().unwrap().send(());
        self.worker.take().unwrap().join().unwrap();
    }
}

fn metadata(tag: &str, body: &[u8]) -> serde_json::Value {
    serde_json::json!({
        "tag_name": tag, "draft": false, "prerelease": tag.contains("beta"),
        "created_at": "2026-11-01T00:00:00Z", "assets": [{
            "name": format!("hostlink-agent-{TARGET}.zip"),
            "url": format!("https://api.github.com{API}/assets/1"),
            "digest": format!("sha256:{}", digest(body))
        }]
    })
}

fn routes(tag: &str, body: &[u8]) -> BTreeMap<String, (u16, Vec<u8>, Option<String>)> {
    let metadata = serde_json::to_vec(&metadata(tag, body)).unwrap();
    BTreeMap::from([
        (format!("{API}/latest"), (200, metadata.clone(), None)),
        (format!("{API}/tags/{tag}"), (200, metadata, None)),
        (format!("{API}/assets/1"), (200, body.to_vec(), None)),
    ])
}

#[test]
fn latest_and_explicit_downgrade_or_prerelease_install_exact_bundle_and_preserve_state() {
    for (requested, tag) in [
        (None, "v2.0.0"),
        (Some("0.9.0"), "v0.9.0"),
        (Some("2.0.0-beta.1"), "2.0.0-beta.1"),
    ] {
        let fixture = Fixture::new();
        let state = fixture.preserved();
        let version = tag.trim_start_matches('v');
        let body = package(version, b"new executable", false);
        let server = Server::release(tag, &body);
        assert!(server.apply(&fixture, requested).unwrap());
        let (installed, sha) = read_installed(&fixture.root).unwrap();
        assert_eq!(installed.version, version);
        assert_eq!(installed.target, TARGET);
        assert_eq!(hex::encode(sha), digest(&body));
        let source = fixture.temp.path().join("source.zip");
        fs::write(&source, &body).unwrap();
        let (_, manifest) = validate_contents(&source, TARGET, version).unwrap();
        assert_eq!(
            fs::read(fixture.root.join("bin/manifest.json")).unwrap(),
            manifest
        );
        assert_eq!(
            fs::read(fixture.root.join("bin/hostlink-agent")).unwrap(),
            b"new executable"
        );
        assert_eq!(fixture.preserved(), state);
        let discovery =
            requested.map_or_else(|| format!("{API}/latest"), |v| format!("{API}/tags/v{v}"));
        let mut paths = vec![discovery];
        if requested.is_some() && !tag.starts_with('v') {
            paths.push(format!("{API}/tags/{tag}"));
        }
        paths.extend([format!("{API}/tags/{tag}"), format!("{API}/assets/1")]);
        assert_eq!(server.paths(), paths);
        assert!(
            server
                .requests
                .lock()
                .unwrap()
                .iter()
                .all(|(_, auth, _)| *auth)
        );
        assert!(server.requests.lock().unwrap().last().unwrap().2);
    }
}

#[test]
fn latest_never_downgrades_or_republishes_but_explicit_same_version_can_replace() {
    for version in ["0.9.0", "1.0.0"] {
        let fixture = Fixture::new();
        let old_sha = read_installed(&fixture.root).unwrap().1;
        let body = package(version, b"different executable", false);
        let server = Server::release(&format!("v{version}"), &body);
        assert!(!server.apply(&fixture, None).unwrap());
        assert_eq!(server.paths(), [format!("{API}/latest")]);
        assert_eq!(read_installed(&fixture.root).unwrap().1, old_sha);
    }
    let fixture = Fixture::new();
    let body = package("1.0.0", b"repacked executable", false);
    let server = Server::release("v1.0.0", &body);
    assert!(server.apply(&fixture, Some("1.0.0")).unwrap());
    assert!(!server.apply(&fixture, Some("1.0.0")).unwrap());
    assert_eq!(
        server
            .paths()
            .iter()
            .filter(|path| path.ends_with("/assets/1"))
            .count(),
        1
    );
    assert_eq!(
        hex::encode(read_installed(&fixture.root).unwrap().1),
        digest(&body)
    );

    // Identical archive identity cannot be relabelled as another version.
    let wrong = metadata("v2.0.0", &body);
    let server = Server::start(BTreeMap::from([(
        format!("{API}/latest"),
        (200, serde_json::to_vec(&wrong).unwrap(), None),
    )]));
    assert!(server.apply(&fixture, None).is_err());
    assert_eq!(server.paths().len(), 1);
}

#[test]
fn api_auth_errors_redirects_drafts_and_invalid_metadata_fail_without_fallback() {
    let body = package("2.0.0", b"new executable", false);
    let mut draft = metadata("v2.0.0", &body);
    draft["draft"] = true.into();
    for (status, bytes, redirect) in [
        (401, Vec::new(), None),
        (403, Vec::new(), None),
        (404, Vec::new(), None),
        (302, Vec::new(), Some("/unexpected".into())),
        (200, serde_json::to_vec(&draft).unwrap(), None),
        (
            200,
            serde_json::to_vec(&metadata("v2.0.0-beta.1", &body)).unwrap(),
            None,
        ),
        (200, b"{}".to_vec(), None),
        (200, vec![b' '; MAX_METADATA_BYTES as usize + 1], None),
    ] {
        let server = Server::start(BTreeMap::from([(
            format!("{API}/latest"),
            (status, bytes, redirect),
        )]));
        let error = server.apply(&Fixture::new(), None).unwrap_err();
        assert!(!error.to_string().contains(FIXTURE_CREDENTIAL));
        assert_eq!(server.paths().len(), 1);
    }
    for status in [401, 403, 500] {
        let server = Server::start(BTreeMap::from([(
            format!("{API}/tags/v2.0.0"),
            (status, Vec::new(), None),
        )]));
        assert!(server.apply(&Fixture::new(), Some("2.0.0")).is_err());
        assert_eq!(server.paths().len(), 1);
    }
}

#[test]
fn mandatory_digest_unique_target_and_private_asset_url_fail_before_download() {
    let body = package("2.0.0", b"new executable", false);
    let base = metadata("v2.0.0", &body);
    let mut invalid = Vec::new();
    for pin in [
        serde_json::Value::Null,
        "sha512:deadbeef".into(),
        "sha256:abcd".into(),
        format!("sha256:{}", "z".repeat(64)).into(),
    ] {
        let mut value = base.clone();
        value["assets"][0]["digest"] = pin;
        invalid.push(value);
    }
    for url in [
        "https://attacker.example/payload.zip",
        "http://api.github.com/repos/KDmasterLOL/hostlink/releases/assets/1",
        "https://api.github.com/repos/other/hostlink/releases/assets/1",
        "https://user:synthetic@api.github.com/repos/KDmasterLOL/hostlink/releases/assets/1",
        "https://api.github.com/repos/KDmasterLOL/hostlink/releases/assets/1?token=synthetic",
        "https://api.github.com/repos/KDmasterLOL/hostlink/releases/assets/1#fragment",
        "https://api.github.com/repos/KDmasterLOL/hostlink/releases/assets/0",
        "https://api.github.com/repos/KDmasterLOL/hostlink/releases/assets/abc",
    ] {
        let mut value = base.clone();
        value["assets"][0]["url"] = url.into();
        invalid.push(value);
    }
    let mut duplicate = base.clone();
    duplicate["assets"]
        .as_array_mut()
        .unwrap()
        .push(base["assets"][0].clone());
    invalid.push(duplicate);
    let mut missing = base.clone();
    missing["assets"][0]["name"] = "hostlink-agent-foreign-target.zip".into();
    invalid.push(missing);
    let mut mismatch = base.clone();
    mismatch["tag_name"] = "v2.0.1".into();
    // An explicit request must not accept a different semantic version.
    invalid.push(mismatch);
    for value in invalid {
        let server = Server::start(BTreeMap::from([(
            format!("{API}/tags/v2.0.0"),
            (200, serde_json::to_vec(&value).unwrap(), None),
        )]));
        assert!(server.apply(&Fixture::new(), Some("2.0.0")).is_err());
        assert_eq!(server.paths().len(), 1);
    }
}

#[test]
fn refetched_tag_and_asset_must_match_the_selected_identity() {
    let body = package("2.0.0", b"new executable", false);
    let base = metadata("v2.0.0", &body);
    let mut changed = Vec::new();
    for (field, value) in [
        ("digest", serde_json::Value::Null),
        ("digest", format!("sha256:{}", "a5".repeat(32)).into()),
        (
            "url",
            format!("https://api.github.com{API}/assets/2").into(),
        ),
        ("name", "hostlink-agent-foreign-target.zip".into()),
    ] {
        let mut metadata = base.clone();
        metadata["assets"][0][field] = value;
        changed.push(metadata);
    }
    let mut duplicate = base.clone();
    duplicate["assets"]
        .as_array_mut()
        .unwrap()
        .push(base["assets"][0].clone());
    changed.push(duplicate);
    let mut draft = base.clone();
    draft["draft"] = true.into();
    changed.push(draft);
    let mut unstable = base.clone();
    unstable["prerelease"] = true.into();
    changed.push(unstable);
    let mut tag = base.clone();
    tag["tag_name"] = "v2.0.1".into();
    changed.push(tag);
    for metadata in changed {
        let fixture = Fixture::new();
        let mut routes = routes("v2.0.0", &body);
        routes.insert(
            format!("{API}/tags/v2.0.0"),
            (200, serde_json::to_vec(&metadata).unwrap(), None),
        );
        let server = Server::start(routes);
        assert!(server.apply(&fixture, None).is_err());
        assert_eq!(server.paths().len(), 2);
        assert_eq!(read_installed(&fixture.root).unwrap().0.version, "1.0.0");
    }
}

#[test]
fn bad_checksum_manifest_and_symlink_preserve_installed_bundle() {
    let good = package("2.0.0", b"new executable", false);
    let mut corrupt = vec![
        package("2.0.0", b"different executable", false),
        package("2.0.1", b"new executable", false),
        package("2.0.0", b"new executable", true),
    ];
    // Exercise archive target policy and the pre-publication extracted-file hash
    // check independently, with otherwise valid ZIPs and their actual SHA-256.
    for foreign_target in [true, false] {
        let mut source = zip::ZipArchive::new(io::Cursor::new(&good)).unwrap();
        let mut archive = zip::ZipWriter::new(io::Cursor::new(Vec::new()));
        for index in 0..source.len() {
            let mut entry = source.by_index(index).unwrap();
            if entry.name().unwrap().ends_with("/manifest.json") {
                let mut manifest: serde_json::Value = serde_json::from_reader(&mut entry).unwrap();
                if foreign_target {
                    manifest["target"] = "i686-win7-windows-msvc".into();
                } else {
                    manifest["files"]["hostlink-agent"]["sha256"] = digest(b"wrong bytes").into();
                }
                archive
                    .start_file(
                        entry.name().unwrap().as_ref(),
                        zip::write::SimpleFileOptions::default(),
                    )
                    .unwrap();
                use std::io::Write;
                archive
                    .write_all(&serde_json::to_vec(&manifest).unwrap())
                    .unwrap();
            } else {
                archive.raw_copy_file(entry).unwrap();
            }
        }
        corrupt.push(archive.finish().unwrap().into_inner());
    }
    for body in corrupt {
        let fixture = Fixture::new();
        let old_manifest = fs::read(fixture.root.join("bin/manifest.json")).unwrap();
        let old_sha = read_installed(&fixture.root).unwrap().1;
        let state = fixture.preserved();
        let mut routes = routes("v2.0.0", &body);
        if body == package("2.0.0", b"different executable", false) {
            let metadata = serde_json::to_vec(&metadata("v2.0.0", &good)).unwrap();
            routes.insert(format!("{API}/latest"), (200, metadata.clone(), None));
            routes.insert(format!("{API}/tags/v2.0.0"), (200, metadata, None));
        }
        let server = Server::start(routes);
        assert!(server.apply(&fixture, None).is_err());
        assert_eq!(server.paths().len(), 3);
        assert_eq!(read_installed(&fixture.root).unwrap().1, old_sha);
        assert_eq!(
            fs::read(fixture.root.join("bin/manifest.json")).unwrap(),
            old_manifest
        );
        assert_eq!(
            fs::read(fixture.root.join("bin/hostlink-agent")).unwrap(),
            b"old executable"
        );
        assert_eq!(fixture.preserved(), state);
    }
}

#[test]
fn api_asset_redirects_never_forward_authorization_even_on_same_origin() {
    let body = package("2.0.0", b"GitHub fixture executable", false);
    let cdn = Server::start(BTreeMap::from([(
        "/asset.zip".into(),
        (200, body.clone(), None),
    )]));
    for redirect in [
        None,
        Some(format!("{}/asset.zip", cdn.origin)),
        Some("/same-origin.zip".into()),
    ] {
        let mut routes = routes("v2.0.0", &body);
        if let Some(url) = redirect {
            routes.insert(format!("{API}/assets/1"), (302, Vec::new(), Some(url)));
        }
        routes.insert("/same-origin.zip".into(), (200, body.clone(), None));
        let api = Server::start(routes);
        let fixture = Fixture::new();
        assert!(api.apply(&fixture, None).unwrap());
        let requests = api.requests.lock().unwrap();
        assert!(requests.iter().take(3).all(|request| request.1));
        assert!(requests[2].2);
        assert!(requests.iter().skip(3).all(|request| !request.1));
    }
    assert_eq!(cdn.paths().len(), 1);
    assert!(
        cdn.requests
            .lock()
            .unwrap()
            .iter()
            .all(|request| !request.1)
    );
}
