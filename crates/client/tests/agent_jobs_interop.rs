#![cfg(unix)]
//! End-to-end SSH jobs-v1 behavior across the actual Controller and Agent packages.

use hostlink::{
    HostSpec,
    connect::HostConnection,
    run::{Cancel, JobSpec, JobState, JobStream, Output, Start, Status},
};
use hostlink_agent::{AgentConfig, ssh};
use russh::keys::{Algorithm, PrivateKey, ssh_key::LineEnding};
use sha2::{Digest as _, Sha256};
use std::fs;
use std::time::Duration;

fn private_file(path: &std::path::Path, bytes: &[u8]) {
    use std::os::unix::fs::PermissionsExt;
    fs::write(path, bytes).expect("write private fixture");
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("private file");
}

#[tokio::test]
async fn job_resumes_after_ssh_disconnect_without_relaunch_or_cross_key_access() {
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::tempdir().expect("owned disposable fixture");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let jobs = root.path().join("jobs");
    fs::create_dir(&jobs).expect("jobs dir");
    fs::set_permissions(&jobs, fs::Permissions::from_mode(0o700)).unwrap();

    let host = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
    let first = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
    let second = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
    let host_key = root.path().join("server.key");
    let first_key = root.path().join("first.key");
    let second_key = root.path().join("second.key");
    let authorized_keys = root.path().join("authorized_keys");
    private_file(
        &host_key,
        host.to_openssh(LineEnding::LF).unwrap().as_bytes(),
    );
    private_file(
        &first_key,
        first.to_openssh(LineEnding::LF).unwrap().as_bytes(),
    );
    private_file(
        &second_key,
        second.to_openssh(LineEnding::LF).unwrap().as_bytes(),
    );
    private_file(
        &authorized_keys,
        format!(
            "{} first\n{} second\n",
            first.public_key().to_openssh().unwrap(),
            second.public_key().to_openssh().unwrap(),
        )
        .as_bytes(),
    );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = listener.local_addr().unwrap();
    let jobs_probe = jobs.clone();
    let config = AgentConfig {
        listen: endpoint,
        user: "hostlink".into(),
        host_key,
        authorized_keys,
        jobs_root: jobs,
        gateway: None,
        gateway_alternates: Vec::new(),
    };
    let (stop, shutdown) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        ssh::serve_on(listener, &config, async {
            let _ = shutdown.await;
        })
        .await
    });

    let spec = HostSpec {
        endpoint,
        user: "hostlink".into(),
        identity: first_key,
        host_public_key: host.public_key().to_openssh().unwrap(),
        gateway: None,
    };
    let second_spec = HostSpec {
        identity: second_key,
        ..spec.clone()
    };
    // The new Agent admits only singly-linked, owner-owned read-only executables.
    // Stage this fixture under our private directory, never on an installed host.
    let program = root.path().join("pinned-test-shell");
    fs::copy(fs::canonicalize("/bin/sh").unwrap(), &program).expect("stage verified shell fixture");
    fs::set_permissions(&program, fs::Permissions::from_mode(0o500))
        .expect("lock executable fixture against writes");
    let digest = format!("{:x}", Sha256::digest(fs::read(&program).unwrap()));
    let id = uuid::Uuid::new_v4().to_string();
    let request = Start {
        id: id.clone(),
        spec: JobSpec {
            program: program.to_str().unwrap().to_owned(),
            args: vec![
                "-c".into(),
                r"printf x >> launch-count; sleep 1; printf '\000\377'; printf '\377E' >&2; exit 7"
                    .into(),
            ],
            cwd: Some(root.path().to_str().unwrap().to_owned()),
            source_sha256: digest,
        },
    };

    let mut original = HostConnection::connect(&spec)
        .await
        .expect("pinned SSH connect");
    let accepted = original
        .job_start(&request)
        .await
        .expect("durable start ACK");
    assert_eq!(accepted.id, id);
    assert!(matches!(
        accepted.state,
        JobState::Running | JobState::Exited { .. }
    ));
    original.close().await.expect("close original SSH session");

    let mut outsider = HostConnection::connect(&second_spec)
        .await
        .expect("authenticate distinct authorized controller key");
    assert!(
        outsider
            .job_status(&Status { id: id.clone() })
            .await
            .is_err(),
        "controller key cannot read another key's job"
    );
    outsider
        .close()
        .await
        .expect("close unauthorized observation session");

    let mut resumed = HostConnection::connect(&spec)
        .await
        .expect("reconnect controller");
    let status = Status { id: id.clone() };
    let mut observed = None;
    for _ in 0..100 {
        let next = resumed
            .job_status(&status)
            .await
            .expect("job status readback");
        if matches!(next.state, JobState::Exited { .. }) {
            observed = Some(next);
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let terminal = observed.expect("accepted job should finish after session disconnect");
    assert_eq!(
        terminal.state,
        JobState::Exited { code: 7 },
        "must retain actual nonzero exit"
    );

    for (stream, expected) in [
        (JobStream::Stdout, &[0_u8, 255][..]),
        (JobStream::Stderr, &[255_u8, b'E'][..]),
    ] {
        let chunk = resumed
            .job_output(&Output {
                id: id.clone(),
                stream,
                offset: 0,
            })
            .await
            .expect("retrieve exact binary output");
        assert_eq!(chunk.data, expected);
        assert_eq!(chunk.next_offset, expected.len() as u64);
        assert!(chunk.eof);
        let again = resumed
            .job_output(&Output {
                id: id.clone(),
                stream,
                offset: chunk.next_offset,
            })
            .await
            .expect("resume at persisted offset");
        assert!(again.data.is_empty() && again.eof);
        assert_eq!(again.next_offset, expected.len() as u64);
    }

    let original_result = resumed
        .job_start(&request)
        .await
        .expect("same ID must be idempotent");
    assert_eq!(original_result.state, JobState::Exited { code: 7 });
    let mut conflicting = request.clone();
    conflicting.spec.args.push("conflicting argv".into());
    assert!(
        resumed.job_start(&conflicting).await.is_err(),
        "different manifest with same UUID must fail closed"
    );
    assert_eq!(
        fs::read_to_string(root.path().join("launch-count")).unwrap(),
        "x",
        "idempotent reattachment must not duplicate side effects"
    );
    // Cancel a second source-pinned job after a descendant exists, then verify
    // that cancellation terminates the entire process tree and leaves a
    // terminal non-success state rather than an indefinitely blocked update.
    let pid_file = root.path().join("owned-cancel-descendant");
    let cancel_id = uuid::Uuid::new_v4().to_string();
    let cancel_request = Start {
        id: cancel_id.clone(),
        spec: JobSpec {
            args: vec![
                "-c".into(),
                format!("sleep 300 & echo $! > '{}'; wait", pid_file.display()),
            ],
            ..request.spec.clone()
        },
    };
    let accepted = resumed
        .job_start(&cancel_request)
        .await
        .expect("start cancellable job");
    assert!(matches!(accepted.state, JobState::Running));
    tokio::time::timeout(Duration::from_secs(7), async {
        while !pid_file.exists() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("owned descendant PID published");
    let child_pid: u32 = fs::read_to_string(&pid_file)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let cancel = Cancel {
        id: cancel_id.clone(),
    };
    let mut other = HostConnection::connect(&second_spec).await.unwrap();
    assert!(
        other.job_cancel(&cancel).await.is_err(),
        "different authorized key must not cancel a foreign job"
    );
    other.close().await.unwrap();
    let cancellation = resumed
        .job_cancel(&cancel)
        .await
        .expect("request owned job cancellation");
    assert_eq!(cancellation.id, cancel_id);
    assert!(matches!(
        cancellation.state,
        JobState::Running | JobState::Failed
    ));
    resumed.close().await.expect("close after cancel request");
    let mut resumed = HostConnection::connect(&spec)
        .await
        .expect("reattach cancellation status");
    let mut final_state = None;
    for _ in 0..140 {
        let status = resumed
            .job_status(&Status {
                id: cancel_id.clone(),
            })
            .await
            .unwrap();
        if matches!(status.state, JobState::Failed | JobState::Interrupted) {
            final_state = Some(status.state);
            break;
        }
        tokio::time::sleep(Duration::from_millis(40)).await;
    }
    assert_eq!(
        final_state,
        Some(JobState::Failed),
        "verified cancelled tree must be terminal failure, not unknown interruption"
    );
    for _ in 0..140 {
        let alive = fs::read_to_string(format!("/proc/{child_pid}/stat")).is_ok_and(|stat| {
            stat.rsplit_once(')')
                .is_some_and(|(_, fields)| !fields.trim_start().starts_with("Z "))
        });
        if !alive {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let alive = fs::read_to_string(format!("/proc/{child_pid}/stat")).is_ok_and(|stat| {
        stat.rsplit_once(')')
            .is_some_and(|(_, fields)| !fields.trim_start().starts_with("Z "))
    });
    assert!(
        !alive,
        "ProcessKit must kill the cancellable job's descendant"
    );
    assert!(
        hostlink_agent::jobs::active_ids(&jobs_probe)
            .unwrap()
            .is_empty(),
        "completed cancellation must no longer block Agent update"
    );
    let repeated = resumed
        .job_cancel(&cancel)
        .await
        .expect("terminal cancel is idempotent");
    assert_eq!(repeated.state, JobState::Failed);
    resumed.close().await.expect("close resumed SSH session");
    stop.send(()).expect("server active");
    tokio::time::timeout(Duration::from_secs(7), server)
        .await
        .expect("shutdown deadline")
        .expect("server join")
        .expect("server shut down");
}
