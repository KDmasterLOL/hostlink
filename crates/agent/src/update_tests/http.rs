//! Real HTTP, real high-level self_update and disposable Agent roots; no transport mocks.
use super::*;
use std::{
    io::{Cursor, Read, Write},
    net::TcpListener,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};

struct Server {
    origin: String,
    stop: Arc<AtomicBool>,
    requests: Arc<Mutex<Vec<String>>>,
    worker: Option<thread::JoinHandle<()>>,
}
impl Server {
    fn start(body: Vec<u8>, redirect: Option<&str>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let stop = Arc::new(AtomicBool::new(false));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let stopped = Arc::clone(&stop);
        let received = Arc::clone(&requests);
        let headers=redirect.map_or_else(||format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",body.len()),
            |url|format!("HTTP/1.1 302 Found\r\nLocation: {url}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"));
        let worker = thread::spawn(move || {
            while !stopped.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream
                            .set_read_timeout(Some(Duration::from_secs(2)))
                            .unwrap();
                        let mut request = Vec::new();
                        while !request.ends_with(b"\r\n\r\n") {
                            let mut byte = [0];
                            stream.read_exact(&mut byte).unwrap();
                            request.push(byte[0]);
                            assert!(request.len() <= 8192);
                        }
                        received.lock().unwrap().push(
                            std::str::from_utf8(&request)
                                .unwrap()
                                .lines()
                                .next()
                                .unwrap()
                                .to_owned(),
                        );
                        stream.write_all(headers.as_bytes()).unwrap();
                        stream.write_all(&body).unwrap();
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5))
                    }
                    Err(e) => panic!("fixture accept: {e}"),
                }
            }
        });
        Self {
            origin,
            stop,
            requests,
            worker: Some(worker),
        }
    }
    fn url(&self) -> String {
        format!("{}{ARTIFACT_PATH}", self.origin)
    }
    fn request_count(&self) -> usize {
        self.requests.lock().unwrap().len()
    }
}

const ARTIFACT_PATH: &str = "/objects/a%20b/payload.bin?signature=a%2Bb&download=1";

fn wrong_target_package(body: &[u8]) -> Vec<u8> {
    let mut source = zip::ZipArchive::new(Cursor::new(body)).unwrap();
    let mut archive = zip::ZipWriter::new(Cursor::new(Vec::new()));
    for index in 0..source.len() {
        let mut entry = source.by_index(index).unwrap();
        let name = entry.name().unwrap().into_owned();
        if name.ends_with("/manifest.json") {
            let mut manifest: serde_json::Value = serde_json::from_reader(&mut entry).unwrap();
            manifest["target"] = serde_json::json!("i686-win7-windows-msvc");
            archive
                .start_file(name, zip::write::SimpleFileOptions::default())
                .unwrap();
            archive
                .write_all(&serde_json::to_vec(&manifest).unwrap())
                .unwrap();
        } else {
            archive.raw_copy_file(entry).unwrap();
        }
    }
    archive.finish().unwrap().into_inner()
}
impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        self.worker.take().unwrap().join().unwrap();
    }
}

#[test]
fn idempotency_and_same_version_changed_digest_use_real_upstream_update() {
    let fixture = Fixture::new();
    let before = fixture.preserved();
    let body = package("2.0.0", b"new executable", false);
    let server = Server::start(body.clone(), None);
    assert!(fixture.apply(&server.url(), &body, "2.0.0").unwrap());
    assert_eq!(
        *server.requests.lock().unwrap(),
        [format!("GET {ARTIFACT_PATH} HTTP/1.1")]
    );
    let (manifest, source_sha) = read_installed(&fixture.root).unwrap();
    assert_eq!(manifest.version, "2.0.0");
    assert_eq!(manifest.target, TARGET);
    assert_eq!(source_sha, digest(&body));
    let archive = fixture.temp.path().join("source.zip");
    fs::write(&archive, &body).unwrap();
    let (_, source_manifest) =
        crate::package::validate_contents(&archive, TARGET, "2.0.0").unwrap();
    assert_eq!(
        fs::read(fixture.root.join("bin/manifest.json")).unwrap(),
        source_manifest
    );
    assert_eq!(fixture.preserved(), before);
    assert!(!fixture.root.join("jobs/jobs.db").exists());

    assert!(!fixture.apply(&server.url(), &body, "2.0.0").unwrap());
    assert_eq!(server.request_count(), 1);

    let replacement = package("2.0.0", b"different exact executable", false);
    let other = Server::start(replacement.clone(), None);
    assert!(fixture.apply(&other.url(), &replacement, "2.0.0").unwrap());
    assert_eq!(
        fs::read(fixture.root.join("bin/hostlink-agent")).unwrap(),
        b"different exact executable"
    );
    assert_eq!(
        read_installed(&fixture.root).unwrap().1,
        digest(&replacement)
    );
    assert_eq!(fixture.preserved(), before);

    let same_sha_different_version = other.url();
    assert!(
        update(
            &fixture.root,
            &same_sha_different_version,
            &digest(&replacement),
            TARGET,
            "2.0.1"
        )
        .is_err()
    );
    assert_eq!(other.request_count(), 1);
}

#[test]
fn bad_checksum_manifest_symlink_and_redirect_preserve_old_bundle() {
    let good = package("2.0.0", b"new executable", false);
    for body in [
        package("2.0.0", b"changed executable", false),
        package("2.0.1", b"new executable", false),
        package("2.0.0", b"new executable", true),
        wrong_target_package(&good),
    ] {
        let fixture = Fixture::new();
        let before = fixture.preserved();
        let old_manifest = fs::read(fixture.root.join("bin/manifest.json")).unwrap();
        let old_sha = read_installed(&fixture.root).unwrap().1;
        let server = Server::start(body.clone(), None);
        let pin = if body == package("2.0.0", b"changed executable", false) {
            digest(&good)
        } else {
            digest(&body)
        };
        assert!(update(&fixture.root, &server.url(), &pin, TARGET, "2.0.0").is_err());
        assert_eq!(
            server.request_count(),
            1,
            "failure must follow a real download"
        );
        assert_eq!(read_installed(&fixture.root).unwrap().0.version, "1.0.0");
        assert_eq!(read_installed(&fixture.root).unwrap().1, old_sha);
        assert_eq!(
            fs::read(fixture.root.join("bin/manifest.json")).unwrap(),
            old_manifest
        );
        assert_eq!(
            fs::read(fixture.root.join("bin/hostlink-agent")).unwrap(),
            b"old executable"
        );
        assert_eq!(fixture.preserved(), before);
    }
    let destination = Server::start(good.clone(), None);
    for location in [destination.url(), "/redirected".to_owned()] {
        let redirect = Server::start(Vec::new(), Some(&location));
        let fixture = Fixture::new();
        let before = fixture.preserved();
        let old_sha = read_installed(&fixture.root).unwrap().1;
        assert!(fixture.apply(&redirect.url(), &good, "2.0.0").is_err());
        assert_eq!(
            *redirect.requests.lock().unwrap(),
            [format!("GET {ARTIFACT_PATH} HTTP/1.1")],
            "only the initial request is allowed, including same-origin redirects"
        );
        assert_eq!(destination.request_count(), 0);
        assert_eq!(read_installed(&fixture.root).unwrap().0.version, "1.0.0");
        assert_eq!(read_installed(&fixture.root).unwrap().1, old_sha);
        assert_eq!(
            fs::read(fixture.root.join("bin/hostlink-agent")).unwrap(),
            b"old executable"
        );
        assert_eq!(fixture.preserved(), before);
    }
    let fixture = Fixture::new();
    fs::rename(fixture.root.join("bin"), fixture.root.join("alias-target")).unwrap();
    std::os::unix::fs::symlink(fixture.root.join("alias-target"), fixture.root.join("bin"))
        .unwrap();
    assert!(fixture.apply(&destination.url(), &good, "2.0.0").is_err());
    assert_eq!(destination.request_count(), 0);
}

#[test]
fn upstream_bundle_ordinary_publication_error_restores_old_tree() {
    let fixture = Fixture::new();
    let body = package("2.0.0", b"new executable", false);
    let server = Server::start(body.clone(), None);
    let release = Release::builder()
        .version("2.0.0")
        .asset(ReleaseAsset::new(
            format!("hostlink-agent-{TARGET}.zip"),
            server.url(),
        ))
        .build()
        .unwrap();
    let reached = Arc::new(AtomicBool::new(false));
    let hook_reached = Arc::clone(&reached);
    let transport = ureq::Agent::config_builder()
        .proxy(None)
        .max_redirects(0)
        .timeout_global(Some(Duration::from_secs(5)))
        .build()
        .new_agent();
    let result = self_update::backends::custom::Update::configure()
        .source(SelectedRelease(release))
        .release_tag("2.0.0")
        .current_version("1.0.0")
        .target(TARGET)
        .bin_name("hostlink-agent")
        .bundle_path_in_archive(format!("hostlink-agent-{TARGET}"))
        .bundle_install_path(fixture.root.join("bin"))
        .no_confirm(true)
        .show_output(false)
        .retries(0)
        .verify_checksum(self_update::Checksum::Sha256(digest(&body)))
        .ureq_agent(transport)
        .verify_binary(move |path| {
            hook_reached.store(true, Ordering::SeqCst);
            fs::rename(path, path.with_file_name("removed-by-fault"))?;
            Ok(())
        })
        .build()
        .unwrap()
        .update();
    assert!(result.is_err());
    assert!(reached.load(Ordering::SeqCst));
    assert_eq!(read_installed(&fixture.root).unwrap().0.version, "1.0.0");
    assert_eq!(
        fs::read(fixture.root.join("bin/hostlink-agent")).unwrap(),
        b"old executable"
    );
}

#[tokio::test]
async fn pending_native_apalis_task_and_private_state_survive_update() {
    use crate::jobs::{CommandJob, JobStore};
    use apalis_core::{backend::TaskSink, task::builder::TaskBuilder};
    use apalis_sqlite::{Config, SqliteStorage};
    let fixture = Fixture::new();
    let jobs = fixture.root.join("jobs");
    JobStore::initialize_fresh(&jobs)
        .await
        .unwrap()
        .close()
        .await;
    let pool = sqlx::SqlitePool::connect_with(
        sqlx::sqlite::SqliteConnectOptions::new().filename(jobs.join("jobs.db")),
    )
    .await
    .unwrap();
    let id = ulid::Ulid::generate().to_string();
    let task = TaskBuilder::new(CommandJob {
        program: "echo".into(),
        args: vec!["disposable".into()],
        cwd: None,
    })
    .task_id(id.parse().unwrap())
    .build();
    let mut storage =
        SqliteStorage::<CommandJob>::new(&pool).with_config(Config::default().queue("commands"));
    storage.push_task(task).await.unwrap();
    pool.close().await;
    let db = fs::read(jobs.join("jobs.db")).unwrap();
    let state = fixture.preserved();
    let body = package("2.0.0", b"new executable", false);
    let server = Server::start(body.clone(), None);
    fixture.apply(&server.url(), &body, "2.0.0").unwrap();
    assert_eq!(fs::read(jobs.join("jobs.db")).unwrap(), db);
    assert_eq!(fixture.preserved(), state);
    let pool = sqlx::SqlitePool::connect_with(
        sqlx::sqlite::SqliteConnectOptions::new()
            .filename(jobs.join("jobs.db"))
            .read_only(true),
    )
    .await
    .unwrap();
    let saved: String = sqlx::query_scalar("SELECT id FROM Jobs WHERE id=?")
        .bind(&id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(saved, id);
    pool.close().await;
}

#[test]
fn already_current_manifest_does_not_download_again() {
    let fixture = Fixture::new();
    let current = package("1.0.0", b"old executable", false);
    assert_eq!(read_installed(&fixture.root).unwrap().1, digest(&current));
    let server = Server::start(current.clone(), None);
    let url = server.url();
    assert!(!fixture.apply(&url, &current, "1.0.0").unwrap());
    assert_eq!(server.request_count(), 0);
}

#[test]
fn explicitly_pinned_older_release_is_installed_without_latest_discovery() {
    let fixture = Fixture::new();
    let older = package("0.9.0", b"operator-selected older Agent", false);
    let server = Server::start(older.clone(), None);
    assert!(fixture.apply(&server.url(), &older, "0.9.0").unwrap());
    let (manifest, pinned_sha) = read_installed(&fixture.root).unwrap();
    assert_eq!(manifest.version, "0.9.0");
    assert_eq!(manifest.target, TARGET);
    assert_eq!(pinned_sha, digest(&older));
    assert_eq!(server.request_count(), 1);
}
