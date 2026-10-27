use super::gateway::GatewayFixture;
use super::*;

pub(super) async fn verify_durable_job(
    host: &hostlink::HostSpec,
    fixture: &GatewayFixture<'_>,
) -> HostConnection {
    let mut session = connect_retry(host).await;
    // Durable JobStore only contains UUID-named job directories. Test-owned
    // executables live in a separate private sibling, not inside state/jobs.
    let program_root = fixture.agent_root.parent().unwrap().join("programs");
    private_dir(&program_root);
    let program = program_root.join("managed-job-shell");
    fs::copy("/bin/sh", &program).expect("stage private job executable");
    fs::set_permissions(&program, fs::Permissions::from_mode(0o500))
        .expect("lock staged executable");
    let job_id = uuid::Uuid::new_v4().to_string();
    let start = Start {
        id: job_id.clone(),
        spec: JobSpec {
            program: program.to_string_lossy().into_owned(),
            args: vec![
                "-c".into(),
                "sleep 1; printf job-out; printf job-err >&2; exit 7".into(),
            ],
            cwd: Some(program_root.to_string_lossy().into_owned()),
            source_sha256: format!("{:x}", Sha256::digest(fs::read(&program).unwrap())),
        },
    };
    session
        .job_start(&start)
        .await
        .expect("durable job accepted once");
    session
        .close()
        .await
        .expect("close first session before reattach");
    let mut resumed = connect_retry(host).await;
    let status = Status { id: job_id.clone() };
    let terminal = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let result = resumed
                .job_status(&status)
                .await
                .expect("reattach by stable job id");
            if matches!(result.state, JobState::Exited { .. } | JobState::Failed) {
                break result;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("durable job terminal state");
    assert_eq!(terminal.state, JobState::Exited { code: 7 });
    assert_eq!(
        resumed
            .job_output(&Output {
                id: job_id.clone(),
                stream: JobStream::Stdout,
                offset: 0
            })
            .await
            .unwrap()
            .data,
        b"job-out"
    );
    assert_eq!(
        resumed
            .job_output(&Output {
                id: job_id,
                stream: JobStream::Stderr,
                offset: 0
            })
            .await
            .unwrap()
            .data,
        b"job-err"
    );
    resumed
}

pub(super) async fn verify_local_forwarding(resumed: HostConnection) {
    // A local loopback probe proves forward channels traverse sshd and the nested Agent.
    let echo_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo_listener.local_addr().unwrap();
    let echo_task = tokio::spawn(async move {
        while let Ok((mut socket, _)) = echo_listener.accept().await {
            tokio::spawn(async move {
                let mut bytes = [0; 256];
                while let Ok(n) = socket.read(&mut bytes).await {
                    if n == 0 {
                        break;
                    }
                    if socket.write_all(&bytes[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    let forward = forward::start_local_forward(resumed, "127.0.0.1:0".parse().unwrap(), echo_addr)
        .await
        .expect("start loopback-only forwarding");
    let mut probe = tokio::net::TcpStream::connect(forward.local_addr())
        .await
        .unwrap();
    probe.write_all(b"tcp-probe").await.unwrap();
    let mut echoed = [0; 9];
    probe.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"tcp-probe");
    forward
        .shutdown()
        .await
        .expect("close loopback forward cleanly");
    echo_task.abort();
}
