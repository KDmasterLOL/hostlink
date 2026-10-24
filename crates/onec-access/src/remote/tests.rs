#[tokio::test]
async fn regression_inv_764_scoped_remove_requires_its_agent_capability() {
    let client = RemoteAgentClient::new(fixture()).expect("remote client");
    client
        .capabilities
        .set(Vec::new())
        .expect("seed missing capabilities");

    let error = client
        .path_remove_scoped("C:\\owned", "C:\\owned\\run-1", true, false)
        .await
        .expect_err("scoped removal must require the typed capability before transport");

    assert!(error.to_string().contains("filesystem.scoped-remove-v1"));
}

#[tokio::test]
async fn regression_inv_794_gateway_control_cannot_prove_cache_absence_using_target_sftp() {
    // This fixture has deliberately nonexistent transport key files. The carrier must be
    // rejected before any SSH connection, and unknown cache state must never become missing.
    let client = RemoteAgentClient::new(fixture()).expect("managed gateway-control client");
    let private_path = "C:\\private\\cache\\secret=sentinel.exe";
    let error = client
        .target_sftp_path_is_absent(private_path)
        .await
        .expect_err("gateway-control cannot offer target SFTP absence evidence");
    let rendered = error.to_string();
    assert_eq!(
        rendered,
        "TargetSftp unavailable for the selected managed carrier"
    );
    assert!(!rendered.contains(private_path));
    assert!(!rendered.contains("secret=sentinel"));
    assert!(!rendered.contains("known_hosts"));
}

#[tokio::test]
async fn regression_inv_794_job_observation_requires_its_exact_capability() {
    let client = RemoteAgentClient::new(fixture()).expect("remote client");
    client
        .capabilities
        .set(Vec::new())
        .expect("seed absent negotiated capabilities");

    let job_logs_error = client
        .job_logs("00000000-0000-0000-0000-000000000794", 32)
        .await
        .expect_err("job logs must reject an absent jobs-v1 capability");
    assert!(job_logs_error.to_string().contains("jobs-v1"));

    let run_local_error = client
        .run_local_status("0123456789abcdef0123456789abcdef")
        .await
        .expect_err("run-local status must reject an absent local-candidate capability");
    assert!(
        run_local_error
            .to_string()
            .contains("jobs.local-candidate-v1")
    );
}

#[tokio::test]
async fn native_invocation_operations_fail_closed_without_advertised_capability() {
    use hostlink_protocol::{NativeExecutionEffect, RunLocalJobIdentity};
    use std::collections::BTreeMap;

    let client = RemoteAgentClient::new(fixture()).expect("remote client");
    client
        .capabilities
        .set(vec![
            "jobs.local-candidate-v1".to_owned(),
            "jobs-v1".to_owned(),
        ])
        .expect("seed absent native observation capability");
    let identity = RunLocalJobIdentity::try_new(
        "0123456789abcdef0123456789abcdef".to_owned(),
        format!("sha256-{}.exe", "11".repeat(32)),
        "11".repeat(32),
        Vec::new(),
    )
    .expect("valid exact run-local identity");

    let start_error = client
        .start_native_run_local_job("C:\\stage\\candidate.exe")
        .args(Vec::new())
        .cwd("C:\\stage".to_owned())
        .env(BTreeMap::new())
        .results(Vec::new())
        .run_local(identity)
        .native_effect(NativeExecutionEffect::RunOwned)
        .call()
        .await
        .expect_err("native start must not fall back to JobStart");
    assert!(
        start_error
            .to_string()
            .contains("native-invocation-observation-v1")
    );

    let observe_error = client
        .observe_run_local_invocation("job-1", "challenge", "22".repeat(32))
        .await
        .expect_err("signing request requires advertised observation capability");
    assert!(
        observe_error
            .to_string()
            .contains("native-invocation-observation-v1")
    );
    let fetch_error = client
        .fetch_run_local_invocation_observation("job-1", "challenge", "22".repeat(32))
        .await
        .expect_err("read-only recovery fetch requires advertised observation capability");
    assert!(
        fetch_error
            .to_string()
            .contains("native-invocation-observation-v1")
    );
}

#[tokio::test]
async fn native_suite_policy_rejects_launch_field_mismatches_before_agent_request() {
    use hostlink_protocol::{NativeExecutionEffect, NativeSuitePolicy, RunLocalJobIdentity};
    use std::collections::BTreeMap;

    let client = RemoteAgentClient::new(fixture()).expect("remote client");
    let run_local = RunLocalJobIdentity::try_new(
        "0123456789abcdef0123456789abcdef".to_owned(),
        format!("sha256-{}.exe", "11".repeat(32)),
        "11".repeat(32),
        Vec::new(),
    )
    .expect("valid exact run-local identity");
    let valid = NativeSuitePolicy {
        version: 1,
        runner_sha256: "11".repeat(32),
        args: vec!["run".to_owned()],
        env: BTreeMap::new(),
        expected_tests: vec!["suite::case".to_owned()],
        effect: NativeExecutionEffect::RunOwned,
    };
    let mut mismatches = Vec::new();
    let mut wrong_runner = valid.clone();
    wrong_runner.runner_sha256 = "22".repeat(32);
    mismatches.push(wrong_runner);
    let mut wrong_args = valid.clone();
    wrong_args.args = vec!["run".to_owned(), "--ignored".to_owned()];
    mismatches.push(wrong_args);
    let mut wrong_env = valid.clone();
    wrong_env
        .env
        .insert("SUITE_FLAG".to_owned(), "1".to_owned());
    mismatches.push(wrong_env);
    let mut wrong_effect = valid;
    wrong_effect.effect = NativeExecutionEffect::Disposable;
    mismatches.push(wrong_effect);

    for policy in mismatches {
        let error = client
            .start_native_run_local_job("C:\\stage\\candidate.exe")
            .args(vec!["run".to_owned()])
            .cwd("C:\\stage".to_owned())
            .run_local(run_local.clone())
            .native_effect(NativeExecutionEffect::RunOwned)
            .native_suite_policy(policy)
            .call()
            .await
            .expect_err("mismatched policy must not reach or start an Agent job");
        assert!(error.to_string().contains("does not match"));
    }
}

#[tokio::test]
async fn native_suite_policy_rejects_old_agent_hello_before_start_request() {
    use hostlink_protocol::{NativeExecutionEffect, NativeSuitePolicy, RunLocalJobIdentity};
    use std::collections::BTreeMap;

    let client = RemoteAgentClient::new(fixture()).expect("remote client");
    // This is the verified capability set from an older Agent that accepts v1 invocation
    // observation but silently ignores the optional policy JSON field.
    client
        .capabilities
        .set(vec![
            "jobs.local-candidate-v1".to_owned(),
            "native-invocation-observation-v1".to_owned(),
            "jobs-v1".to_owned(),
        ])
        .expect("seed older Agent Hello capabilities");
    let run_local = RunLocalJobIdentity::try_new(
        "0123456789abcdef0123456789abcdef".to_owned(),
        format!("sha256-{}.exe", "11".repeat(32)),
        "11".repeat(32),
        Vec::new(),
    )
    .expect("valid exact run-local identity");
    let policy = NativeSuitePolicy {
        version: 1,
        runner_sha256: "11".repeat(32),
        args: vec!["--exact".to_owned(), "suite::case".to_owned()],
        env: BTreeMap::new(),
        expected_tests: vec!["suite::case".to_owned()],
        effect: NativeExecutionEffect::RunOwned,
    };

    let error = client
        .start_native_run_local_job("/owned/run/candidate")
        .args(policy.args.clone())
        .cwd("/owned/run".to_owned())
        .run_local(run_local)
        .native_effect(NativeExecutionEffect::RunOwned)
        .native_suite_policy(policy)
        .call()
        .await
        .expect_err("old Agent Hello must block policy start before RPC");
    assert!(
        error
            .to_string()
            .contains("native-suite-policy-admission-v1")
    );
}

#[cfg(unix)]
#[tokio::test]
async fn native_invocation_uses_one_authenticated_agent_exchange_for_start_observe_and_fetch() {
    use ed25519_dalek::{Signer, SigningKey};
    use hostlink_protocol::{
        AgentJobInfo, AgentJobState, NativeExecutionEffect, NativeInvocationIdentity,
        NativeSuitePolicy, RunLocalJobIdentity,
    };
    use std::collections::BTreeMap;
    use std::io::BufReader;

    let directory = tempfile::tempdir().expect("native invocation fixture directory");
    let client_key =
        russh::keys::PrivateKey::random(&mut rand::rng(), russh::keys::Algorithm::Ed25519)
            .expect("operator key");
    let gateway_key =
        russh::keys::PrivateKey::random(&mut rand::rng(), russh::keys::Algorithm::Ed25519)
            .expect("gateway key");
    let identity_file = directory.path().join("id_ed25519");
    fs::write(
        &identity_file,
        client_key
            .to_openssh(russh::keys::ssh_key::LineEnding::LF)
            .expect("operator private key")
            .as_bytes(),
    )
    .expect("write operator private key");

    let run_id = "0123456789abcdef0123456789abcdef".to_owned();
    let candidate_sha256 = format!("{:x}", Sha256::digest(b"native invocation candidate"));
    let run_local = RunLocalJobIdentity::try_new(
        run_id.clone(),
        format!("sha256-{candidate_sha256}.exe"),
        candidate_sha256.clone(),
        Vec::new(),
    )
    .expect("exact local candidate identity");
    let suite_policy = NativeSuitePolicy {
        version: 1,
        runner_sha256: candidate_sha256.clone(),
        args: vec!["--exact".to_owned(), "suite::test".to_owned()],
        env: BTreeMap::new(),
        expected_tests: vec!["suite::test".to_owned()],
        effect: NativeExecutionEffect::RunOwned,
    };
    let suite_policy_sha256 = suite_policy.sha256().expect("canonical suite policy");
    let job_id = "job-809-1-1".to_owned();
    let challenge = "controller-pinned-challenge".to_owned();
    let invocation_sha256 = NativeInvocationIdentity {
        program: "/owned/run/candidate.exe",
        args: &suite_policy.args,
        cwd: Some("/owned/run"),
        env: &suite_policy.env,
        stdin: None,
        results: &[],
        run_local: &run_local,
        native_effect: NativeExecutionEffect::RunOwned,
        native_suite_policy_sha256: Some(&suite_policy_sha256),
    }
    .sha256()
    .expect("policy-bound canonical invocation identity");
    let signing_key = SigningKey::from_bytes(&[29; 32]);
    let signer_id = format!(
        "{:x}",
        Sha256::digest(signing_key.verifying_key().to_bytes())
    );
    let record = hostlink_protocol::AgentNativeInvocationRecord {
        schema_version: 1,
        challenge: challenge.clone(),
        job_id: job_id.clone(),
        run_id: run_id.clone(),
        invocation_sha256: invocation_sha256.clone(),
        requested_exact_testcase: None,
        candidate_sha256: candidate_sha256.clone(),
        declared_effect: NativeExecutionEffect::RunOwned,
        host_arch: "x86_64".to_owned(),
        host_os: "linux".to_owned(),
        command_exit_code: 0,
        cleanup_completion: "complete".to_owned(),
        signer_id: signer_id.clone(),
        observed_windows: None,
        output_logs: None,
        result_set: None,
    };
    let signature = signing_key.sign(&record.signing_bytes().expect("canonical record"));
    let signature_hex = hex::encode(signature.to_bytes());

    let agent_listener = TcpListener::bind("127.0.0.1:0").expect("agent listener");
    let agent_port = agent_listener.local_addr().expect("agent address").port();
    let gateway_listener = TcpListener::bind("127.0.0.1:0").expect("gateway listener");
    let gateway_address = gateway_listener.local_addr().expect("gateway address");
    let gateway_pin = gateway_key
        .public_key()
        .to_openssh()
        .expect("gateway public pin");
    let (gateway_stop, gateway_worker, gateway_activity) = spawn_test_ssh_server(
        gateway_listener,
        gateway_key,
        TestGateway {
            expected_user: "operator".to_owned(),
            expected_key: client_key.public_key().clone(),
            control_redirect: Some(agent_port),
            reject_direct_tcpip: false,
            reject_direct_tcpip_flag: None,
            reject_next_direct_tcpip_flag: None,
            close_direct_tcpip_after_accept_flag: None,
            disconnect_direct_tcpip_flag: None,
            sftp_root: None,
            session_channels: Default::default(),
        },
    );
    let expected_secret = fixture().secret().expect("fixture token").to_owned();
    let agent_record = record.clone();
    let agent_signature = signature_hex.clone();
    let agent_run_local = run_local.clone();
    let agent_suite_policy = suite_policy.clone();
    let agent_job_id = job_id.clone();
    let agent_signer_id = signer_id.clone();
    let agent_key_hex = hex::encode(signing_key.verifying_key().to_bytes());
    let agent_challenge = challenge.clone();
    let agent_invocation_sha256 = invocation_sha256.clone();
    let agent = thread::spawn(move || {
        for step in 0..7 {
            let (mut stream, _) = agent_listener.accept().expect("accept control request");
            let mut reader = BufReader::new(stream.try_clone().expect("clone agent stream"));
            let request: AgentRequest =
                hostlink_protocol::read_json_line(&mut reader).expect("read typed request");
            drop(reader);
            assert_eq!(request.token, expected_secret);
            let response = match (step, request.request) {
                (0, AgentRequestKind::Hello) => AgentResponse::success(AgentResponseKind::Hello {
                    name: "fixture-machine-809".to_owned(),
                    agent_version: "0.1.1".to_owned(),
                    hostname: "FIXTURE-809".to_owned(),
                    os: "linux".to_owned(),
                    capabilities: vec![
                        "jobs.local-candidate-v1".to_owned(),
                        "jobs-v1".to_owned(),
                        "native-attestation-v1".to_owned(),
                        "native-invocation-observation-v1".to_owned(),
                        "native-suite-policy-admission-v1".to_owned(),
                    ],
                    agent_executable: None,
                    onec_executable: None,
                }),
                (
                    1,
                    AgentRequestKind::NativeRunLocalJobStart {
                        program,
                        args,
                        cwd,
                        run_local: actual_identity,
                        native_effect,
                        native_suite_policy,
                        secret_env,
                        ..
                    },
                ) => {
                    assert_eq!(program, "/owned/run/candidate.exe");
                    assert_eq!(args, vec!["--exact", "suite::test"]);
                    assert_eq!(cwd.as_deref(), Some("/owned/run"));
                    assert_eq!(actual_identity, agent_run_local);
                    assert_eq!(native_effect, NativeExecutionEffect::RunOwned);
                    assert_eq!(native_suite_policy, Some(agent_suite_policy.clone()));
                    assert!(secret_env.is_empty());
                    AgentResponse::success(AgentResponseKind::JobStarted {
                        job: AgentJobInfo {
                            job_id: agent_job_id.clone(),
                            state: AgentJobState::Running,
                            worker_pid: None,
                            spawn_owner_pid: None,
                            process_pid: Some(809),
                            exit_code: None,
                            created_unix_ms: 1,
                            started_unix_ms: Some(2),
                            finished_unix_ms: None,
                            message: None,
                            stdout_log_truncated: false,
                            stderr_log_truncated: false,
                            result_set: None,
                            run_local: Some(agent_run_local.clone()),
                        },
                    })
                }
                (2, AgentRequestKind::NativeAttestationPublicKey) => {
                    AgentResponse::success(AgentResponseKind::NativeAttestationPublicKey {
                        signer_id: agent_signer_id.clone(),
                        verifying_key_hex: agent_key_hex.clone(),
                    })
                }
                (
                    3,
                    AgentRequestKind::RunLocalInvocationObserve {
                        job_id,
                        challenge,
                        invocation_sha256,
                    },
                ) => {
                    assert_eq!(job_id, agent_job_id);
                    assert_eq!(challenge, agent_challenge);
                    assert_eq!(invocation_sha256, agent_invocation_sha256);
                    AgentResponse::success(AgentResponseKind::NativeInvocationObservation {
                        record: agent_record.clone(),
                        signature_hex: agent_signature.clone(),
                    })
                }
                (
                    4,
                    AgentRequestKind::RunLocalInvocationObservationFetch {
                        job_id,
                        challenge,
                        invocation_sha256,
                    },
                ) => {
                    assert_eq!(job_id, agent_job_id);
                    assert_eq!(challenge, agent_challenge);
                    assert_eq!(invocation_sha256, agent_invocation_sha256);
                    AgentResponse::success(AgentResponseKind::NativeInvocationObservationFetched {
                        record: agent_record.clone(),
                        signature_hex: agent_signature.clone(),
                    })
                }
                (
                    5,
                    AgentRequestKind::NativeRunLocalJobStart {
                        native_suite_policy: Some(policy),
                        ..
                    },
                ) => {
                    assert_eq!(policy, agent_suite_policy);
                    AgentResponse::failure("native suite policy digest is not pinned")
                }
                (6, AgentRequestKind::Hello) => AgentResponse::success(AgentResponseKind::Hello {
                    name: "fixture-machine-809-old".to_owned(),
                    agent_version: "0.1.0".to_owned(),
                    hostname: "FIXTURE-809-OLD".to_owned(),
                    os: "linux".to_owned(),
                    capabilities: vec![
                        "jobs.local-candidate-v1".to_owned(),
                        "jobs-v1".to_owned(),
                        "native-attestation-v1".to_owned(),
                        "native-invocation-observation-v1".to_owned(),
                    ],
                    agent_executable: None,
                    onec_executable: None,
                }),
                (_, other) => panic!("unexpected native invocation request: {other:?}"),
            };
            write_json_line(&mut stream, &response).expect("write Agent response");
        }
    });

    let mut server = fixture();
    server.name = "fixture-machine-809".to_owned();
    server.gateways = vec![crate::GatewayRoute {
        host: "127.0.0.1".to_owned(),
        user: "operator".to_owned(),
        port: gateway_address.port(),
        trust: crate::GatewayTrust::PinnedPublicKey(gateway_pin),
    }];
    server.remote_port = 27391;
    server.identity = Some(identity_file);
    let client = RemoteAgentClient::new(server.clone()).expect("pinned managed client");

    let started = client
        .start_native_run_local_job("/owned/run/candidate.exe")
        .args(vec!["--exact".to_owned(), "suite::test".to_owned()])
        .cwd("/owned/run".to_owned())
        .run_local(run_local.clone())
        .native_effect(NativeExecutionEffect::RunOwned)
        .native_suite_policy(suite_policy)
        .call()
        .await
        .expect("native start uses typed Agent request");
    assert!(matches!(started, AgentResponseKind::JobStarted { ref job } if job.job_id == job_id));

    let public_key = client
        .request(AgentRequestKind::NativeAttestationPublicKey)
        .await
        .expect("read Agent observation public key");
    assert!(matches!(
        public_key,
        AgentResponseKind::NativeAttestationPublicKey { .. }
    ));
    let observed = client
        .observe_run_local_invocation(job_id.clone(), challenge.clone(), invocation_sha256.clone())
        .await
        .expect("one-shot observation request");
    assert!(matches!(
        observed,
        AgentResponseKind::NativeInvocationObservation { .. }
    ));
    let fetched = client
        .fetch_run_local_invocation_observation(job_id, challenge, invocation_sha256)
        .await
        .expect("read-only observation recovery request");
    assert!(matches!(
        fetched,
        AgentResponseKind::NativeInvocationObservationFetched { .. }
    ));

    let rejected = client
        .start_native_run_local_job("/owned/run/candidate.exe")
        .args(vec!["--exact".to_owned(), "suite::test".to_owned()])
        .cwd("/owned/run".to_owned())
        .run_local(run_local.clone())
        .native_effect(NativeExecutionEffect::RunOwned)
        .native_suite_policy(NativeSuitePolicy {
            version: 1,
            runner_sha256: candidate_sha256.clone(),
            args: vec!["--exact".to_owned(), "suite::test".to_owned()],
            env: BTreeMap::new(),
            expected_tests: vec!["suite::test".to_owned()],
            effect: NativeExecutionEffect::RunOwned,
        })
        .call()
        .await
        .expect_err("Agent policy admission failure must not retry without the policy");
    assert!(rejected.to_string().contains("policy digest is not pinned"));

    let legacy_client = RemoteAgentClient::new(server).expect("legacy Agent client");
    let legacy_error = legacy_client
        .start_native_run_local_job("/owned/run/candidate.exe")
        .args(vec!["--exact".to_owned(), "suite::test".to_owned()])
        .cwd("/owned/run".to_owned())
        .run_local(run_local)
        .native_effect(NativeExecutionEffect::RunOwned)
        .native_suite_policy(NativeSuitePolicy {
            version: 1,
            runner_sha256: candidate_sha256,
            args: vec!["--exact".to_owned(), "suite::test".to_owned()],
            env: BTreeMap::new(),
            expected_tests: vec!["suite::test".to_owned()],
            effect: NativeExecutionEffect::RunOwned,
        })
        .call()
        .await
        .expect_err("legacy Hello must block policy start before its RPC");
    assert!(
        legacy_error
            .to_string()
            .contains("native-suite-policy-admission-v1")
    );

    wait_for_test_ssh_idle(&gateway_activity).await;
    agent.join().expect("mock Agent exchange");
    gateway_stop.store(true, std::sync::atomic::Ordering::Release);
    gateway_worker.join().expect("gateway fixture worker");
}

use super::transfer::copy_exact_with_progress;
use super::*;
#[cfg(unix)]
use crate::AppResult;
use hostlink_protocol::{
    AgentRequest, AgentRequestKind, AgentResponse, AgentResponseKind, write_json_line,
};
#[cfg(unix)]
use russh::server::{self, Auth, Server as _};
#[cfg(unix)]
use sha2::{Digest, Sha256};
#[cfg(unix)]
use std::fs;
#[cfg(unix)]
use std::net::Shutdown;
#[cfg(unix)]
use std::path::Path;
use std::{
    io::{self, Read, Write},
    net::TcpListener,
    path::PathBuf,
    thread,
    time::Duration,
};

#[cfg(unix)]
#[derive(Clone)]
struct TestGateway {
    expected_user: String,
    expected_key: russh::keys::ssh_key::PublicKey,
    control_redirect: Option<u16>,
    reject_direct_tcpip: bool,
    reject_direct_tcpip_flag: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    reject_next_direct_tcpip_flag: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    close_direct_tcpip_after_accept_flag: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    disconnect_direct_tcpip_flag: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    sftp_root: Option<PathBuf>,
    session_channels: std::sync::Arc<
        tokio::sync::Mutex<
            std::collections::HashMap<russh::ChannelId, russh::Channel<server::Msg>>,
        >,
    >,
}

#[cfg(unix)]
impl server::Server for TestGateway {
    type Handler = Self;

    fn new_client(&mut self, _: Option<std::net::SocketAddr>) -> Self::Handler {
        let mut handler = self.clone();
        // SSH channel IDs are scoped to a connection. The gateway policies and
        // fault-injection flags may be shared, but sharing this table lets two
        // concurrent sessions overwrite each other's ChannelId(0) SFTP handle.
        handler.session_channels = Default::default();
        handler
    }
}

#[cfg(unix)]
#[test]
fn ssh_gateway_test_sessions_have_independent_sftp_channel_namespaces() {
    let key = russh::keys::PrivateKey::random(&mut rand::rng(), russh::keys::Algorithm::Ed25519)
        .expect("test SSH key");
    let mut gateway = TestGateway {
        expected_user: "operator".to_owned(),
        expected_key: key.public_key().clone(),
        control_redirect: None,
        reject_direct_tcpip: false,
        reject_direct_tcpip_flag: None,
        reject_next_direct_tcpip_flag: None,
        close_direct_tcpip_after_accept_flag: None,
        disconnect_direct_tcpip_flag: None,
        sftp_root: None,
        session_channels: Default::default(),
    };
    let first = gateway.new_client(None);
    let second = gateway.new_client(None);
    assert!(
        !std::sync::Arc::ptr_eq(&first.session_channels, &second.session_channels),
        "independent SSH connections must never share per-session channel IDs"
    );
    assert!(!std::sync::Arc::ptr_eq(
        &first.session_channels,
        &gateway.session_channels,
    ));
}

#[cfg(unix)]
impl server::Handler for TestGateway {
    type Error = anyhow::Error;

    async fn auth_publickey(
        &mut self,
        user: &str,
        public_key: &russh::keys::ssh_key::PublicKey,
    ) -> Result<Auth, Self::Error> {
        if user == self.expected_user && public_key == &self.expected_key {
            Ok(Auth::Accept)
        } else {
            Ok(Auth::reject())
        }
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        channel: russh::Channel<server::Msg>,
        host_to_connect: &str,
        port_to_connect: u32,
        _: &str,
        _: u32,
        reply: server::ChannelOpenHandle,
        _: &mut server::Session,
    ) -> Result<(), Self::Error> {
        if self.reject_direct_tcpip
            || self
                .reject_direct_tcpip_flag
                .as_ref()
                .is_some_and(|reject| reject.load(std::sync::atomic::Ordering::Acquire))
            || self
                .reject_next_direct_tcpip_flag
                .as_ref()
                .is_some_and(|reject| reject.swap(false, std::sync::atomic::Ordering::AcqRel))
        {
            reply.reject(russh::ChannelOpenFailure::ConnectFailed).await;
            return Ok(());
        }
        if host_to_connect != "127.0.0.1" || port_to_connect > u16::MAX as u32 {
            reply
                .reject(russh::ChannelOpenFailure::AdministrativelyProhibited)
                .await;
            return Ok(());
        }
        let requested_port = port_to_connect as u16;
        let connect_port = if requested_port == 27391 {
            self.control_redirect.unwrap_or(requested_port)
        } else {
            requested_port
        };
        let Ok(mut target) = tokio::net::TcpStream::connect((host_to_connect, connect_port)).await
        else {
            reply.reject(russh::ChannelOpenFailure::ConnectFailed).await;
            return Ok(());
        };
        reply.accept().await;
        if self
            .close_direct_tcpip_after_accept_flag
            .as_ref()
            .is_some_and(|drop_channel| drop_channel.load(std::sync::atomic::Ordering::Acquire))
        {
            channel
                .close()
                .await
                .expect("close the accepted SSH channel before dropping its handle");
            drop(channel);
            return Ok(());
        }
        let disconnect_flag = self.disconnect_direct_tcpip_flag.clone();
        tokio::spawn(async move {
            let mut ssh = channel.into_stream();
            let disconnected = if let Some(flag) = disconnect_flag {
                tokio::select! {
                    _ = tokio::io::copy_bidirectional(&mut ssh, &mut target) => false,
                    _ = async {
                        loop {
                            if flag.load(std::sync::atomic::Ordering::Acquire) {
                                break;
                            }
                            tokio::time::sleep(Duration::from_millis(2)).await;
                        }
                    } => true,
                }
            } else {
                let _ = tokio::io::copy_bidirectional(&mut ssh, &mut target).await;
                false
            };
            if !disconnected {
                let _ = tokio::io::AsyncWriteExt::shutdown(&mut ssh).await;
            }
        });
        Ok(())
    }

    async fn channel_open_session(
        &mut self,
        channel: russh::Channel<server::Msg>,
        reply: server::ChannelOpenHandle,
        _: &mut server::Session,
    ) -> Result<(), Self::Error> {
        self.session_channels
            .lock()
            .await
            .insert(channel.id(), channel);
        reply.accept().await;
        Ok(())
    }

    async fn subsystem_request(
        &mut self,
        channel_id: russh::ChannelId,
        name: &str,
        session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        let Some(root) = self.sftp_root.clone() else {
            session.channel_failure(channel_id)?;
            return Ok(());
        };
        if name != "sftp" {
            session.channel_failure(channel_id)?;
            return Ok(());
        }
        let channel = self
            .session_channels
            .lock()
            .await
            .remove(&channel_id)
            .expect("SFTP session channel");
        session.channel_success(channel_id)?;
        russh_sftp::server::run(channel.into_stream(), TestSftpSession::new(root)).await;
        Ok(())
    }
}

#[cfg(unix)]
struct TestSftpSession {
    root: PathBuf,
    handles: std::collections::HashMap<String, fs::File>,
    next_handle: u64,
}

#[cfg(unix)]
impl TestSftpSession {
    fn new(root: PathBuf) -> Self {
        Self {
            root,
            handles: std::collections::HashMap::new(),
            next_handle: 0,
        }
    }

    fn path(&self, remote: &str) -> Result<PathBuf, russh_sftp::protocol::StatusCode> {
        test_remote_path(&self.root, remote)
    }

    fn status(id: u32, code: russh_sftp::protocol::StatusCode) -> russh_sftp::protocol::Status {
        russh_sftp::protocol::Status {
            id,
            status_code: code,
            error_message: code.to_string(),
            language_tag: "en-US".to_owned(),
        }
    }
}

#[cfg(unix)]
impl russh_sftp::server::Handler for TestSftpSession {
    type Error = russh_sftp::protocol::StatusCode;

    fn unimplemented(&self) -> Self::Error {
        russh_sftp::protocol::StatusCode::OpUnsupported
    }

    async fn open(
        &mut self,
        id: u32,
        filename: String,
        pflags: russh_sftp::protocol::OpenFlags,
        _: russh_sftp::protocol::FileAttributes,
    ) -> Result<russh_sftp::protocol::Handle, Self::Error> {
        let path = self.path(&filename)?;
        let options: fs::OpenOptions = pflags.into();
        let file = options.open(path).map_err(test_sftp_io_status)?;
        self.next_handle += 1;
        let handle = format!("h{}", self.next_handle);
        self.handles.insert(handle.clone(), file);
        Ok(russh_sftp::protocol::Handle { id, handle })
    }

    async fn close(
        &mut self,
        id: u32,
        handle: String,
    ) -> Result<russh_sftp::protocol::Status, Self::Error> {
        let file = self
            .handles
            .remove(&handle)
            .ok_or(russh_sftp::protocol::StatusCode::NoSuchFile)?;
        file.sync_all().map_err(test_sftp_io_status)?;
        Ok(Self::status(id, russh_sftp::protocol::StatusCode::Ok))
    }

    async fn read(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        len: u32,
    ) -> Result<russh_sftp::protocol::Data, Self::Error> {
        use std::io::{Seek, SeekFrom};
        let file = self
            .handles
            .get_mut(&handle)
            .ok_or(russh_sftp::protocol::StatusCode::NoSuchFile)?;
        file.seek(SeekFrom::Start(offset))
            .map_err(test_sftp_io_status)?;
        let mut data = vec![0_u8; len as usize];
        let read = file.read(&mut data).map_err(test_sftp_io_status)?;
        data.truncate(read);
        Ok(russh_sftp::protocol::Data { id, data })
    }

    async fn write(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        data: Vec<u8>,
    ) -> Result<russh_sftp::protocol::Status, Self::Error> {
        use std::io::{Seek, SeekFrom};
        let file = self
            .handles
            .get_mut(&handle)
            .ok_or(russh_sftp::protocol::StatusCode::NoSuchFile)?;
        let injected_stall = self.root.join(".stall-next-sftp-write");
        if injected_stall.exists() {
            fs::remove_file(injected_stall).map_err(test_sftp_io_status)?;
            let partial_len = data.len() / 2;
            file.seek(SeekFrom::Start(offset))
                .map_err(test_sftp_io_status)?;
            file.write_all(&data[..partial_len])
                .map_err(test_sftp_io_status)?;
            std::future::pending::<()>().await;
        }
        let injected_delay = self.root.join(".delay-next-sftp-write");
        if injected_delay.exists() {
            fs::remove_file(injected_delay).map_err(test_sftp_io_status)?;
            let in_progress = self.root.join(".sftp-write-in-progress");
            fs::write(&in_progress, b"fixture state").map_err(test_sftp_io_status)?;
            let release = self.root.join(".release-sftp-write");
            let released = tokio::time::timeout(Duration::from_secs(6), async {
                while !release.exists() {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .is_ok();
            fs::remove_file(in_progress).map_err(test_sftp_io_status)?;
            if !released {
                return Err(russh_sftp::protocol::StatusCode::Failure);
            }
            fs::remove_file(release).map_err(test_sftp_io_status)?;
        }
        file.seek(SeekFrom::Start(offset))
            .map_err(test_sftp_io_status)?;
        file.write_all(&data).map_err(test_sftp_io_status)?;
        Ok(Self::status(id, russh_sftp::protocol::StatusCode::Ok))
    }

    async fn stat(
        &mut self,
        id: u32,
        path: String,
    ) -> Result<russh_sftp::protocol::Attrs, Self::Error> {
        let fail_next = self.root.join(".fail-next-sftp-stat");
        if fail_next.exists() {
            fs::remove_file(fail_next).map_err(test_sftp_io_status)?;
            return Err(russh_sftp::protocol::StatusCode::PermissionDenied);
        }
        let metadata = fs::metadata(self.path(&path)?).map_err(test_sftp_io_status)?;
        Ok(russh_sftp::protocol::Attrs {
            id,
            attrs: (&metadata).into(),
        })
    }

    async fn lstat(
        &mut self,
        id: u32,
        path: String,
    ) -> Result<russh_sftp::protocol::Attrs, Self::Error> {
        let metadata = fs::symlink_metadata(self.path(&path)?).map_err(test_sftp_io_status)?;
        Ok(russh_sftp::protocol::Attrs {
            id,
            attrs: (&metadata).into(),
        })
    }

    async fn fstat(
        &mut self,
        id: u32,
        handle: String,
    ) -> Result<russh_sftp::protocol::Attrs, Self::Error> {
        let metadata = self
            .handles
            .get(&handle)
            .ok_or(russh_sftp::protocol::StatusCode::NoSuchFile)?
            .metadata()
            .map_err(test_sftp_io_status)?;
        Ok(russh_sftp::protocol::Attrs {
            id,
            attrs: (&metadata).into(),
        })
    }

    async fn remove(
        &mut self,
        id: u32,
        filename: String,
    ) -> Result<russh_sftp::protocol::Status, Self::Error> {
        let remove_count = self.root.join(".sftp-remove-count");
        if remove_count.exists() {
            let mut counter = fs::OpenOptions::new()
                .append(true)
                .open(remove_count)
                .map_err(test_sftp_io_status)?;
            counter.write_all(b"x").map_err(test_sftp_io_status)?;
        }
        fs::remove_file(self.path(&filename)?).map_err(test_sftp_io_status)?;
        Ok(Self::status(id, russh_sftp::protocol::StatusCode::Ok))
    }
}

#[cfg(unix)]
fn test_sftp_io_status(error: io::Error) -> russh_sftp::protocol::StatusCode {
    match error.kind() {
        io::ErrorKind::NotFound => russh_sftp::protocol::StatusCode::NoSuchFile,
        io::ErrorKind::PermissionDenied => russh_sftp::protocol::StatusCode::PermissionDenied,
        _ => russh_sftp::protocol::StatusCode::Failure,
    }
}

#[cfg(unix)]
fn test_remote_path(
    root: &Path,
    remote: &str,
) -> Result<PathBuf, russh_sftp::protocol::StatusCode> {
    let normalized = remote.replace('\\', "/");
    let normalized = normalized
        .strip_prefix("C:/")
        .or_else(|| normalized.strip_prefix("c:/"))
        .unwrap_or(normalized.trim_start_matches('/'));
    let mut path = root.to_path_buf();
    for component in normalized.split('/') {
        if component.is_empty() || component == "." {
            continue;
        }
        if component == ".." || component.contains(':') {
            return Err(russh_sftp::protocol::StatusCode::PermissionDenied);
        }
        path.push(component);
    }
    Ok(path)
}

#[cfg(unix)]
fn spawn_test_ssh_server(
    listener: std::net::TcpListener,
    server_key: russh::keys::PrivateKey,
    mut handler: TestGateway,
) -> (
    std::sync::Arc<std::sync::atomic::AtomicBool>,
    thread::JoinHandle<()>,
    std::sync::Arc<TestSshActivity>,
) {
    listener
        .set_nonblocking(true)
        .expect("nonblocking SSH listener");
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let worker_stop = stop.clone();
    let activity = std::sync::Arc::new(TestSshActivity::default());
    let worker_activity = activity.clone();
    let worker = thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("SSH test runtime");
        runtime.block_on(async move {
            let listener = tokio::net::TcpListener::from_std(listener).expect("async SSH listener");
            let config = std::sync::Arc::new(server::Config {
                auth_rejection_time: Duration::ZERO,
                auth_rejection_time_initial: Some(Duration::ZERO),
                keys: vec![server_key],
                ..Default::default()
            });
            while !worker_stop.load(std::sync::atomic::Ordering::Acquire) {
                let accepted =
                    tokio::time::timeout(Duration::from_millis(50), listener.accept()).await;
                let Ok(accepted) = accepted else {
                    continue;
                };
                let (socket, _) = accepted.expect("SSH accept");
                let client_handler = handler.new_client(None);
                let config = config.clone();
                worker_activity
                    .active
                    .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
                let activity = worker_activity.clone();
                tokio::spawn(async move {
                    struct ActiveConnection(std::sync::Arc<TestSshActivity>);
                    impl Drop for ActiveConnection {
                        fn drop(&mut self) {
                            self.0
                                .active
                                .fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
                            self.0.changed.notify_waiters();
                        }
                    }
                    let _active = ActiveConnection(activity);
                    let _ = server::run_stream(config, socket, client_handler).await;
                });
            }
        });
    });
    (stop, worker, activity)
}

#[cfg(unix)]
#[derive(Default)]
struct TestSshActivity {
    active: std::sync::atomic::AtomicUsize,
    changed: tokio::sync::Notify,
}

#[cfg(unix)]
async fn wait_for_test_ssh_idle(activity: &TestSshActivity) {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let changed = activity.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if activity.active.load(std::sync::atomic::Ordering::Acquire) == 0 {
                return;
            }
            changed.await;
        }
    })
    .await
    .expect("fixture SSH sessions close within the bounded cleanup window");
}

fn fixture() -> RemoteServer {
    RemoteServer {
        name: "customer-a".into(),
        gateways: vec![crate::GatewayRoute {
            host: "gateway.example".into(),
            user: "operator".into(),
            port: 2222,
            trust: crate::GatewayTrust::KnownHosts(PathBuf::from("/keys/known_hosts")),
        }],
        remote_port: 41001,
        carrier: RemoteCarrier::GatewayControl,
        persistence_mode: Some("user-session".into()),
        identity: Some(PathBuf::from("/keys/customer-a")),
        known_hosts: Some(PathBuf::from("/keys/known_hosts")),
        target_user: None,
        target_known_hosts: None,
        target_host_key_alias: None,
        secret: "fixture-control-secret".into(),
    }
}

#[cfg(unix)]
struct GatewayAdmissionFixture {
    _directory: tempfile::TempDir,
    gateways: Vec<crate::GatewayRoute>,
    identity: PathBuf,
    reverse_port: u16,
    _reverse_listener: TcpListener,
    stops: Vec<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    workers: Vec<thread::JoinHandle<()>>,
}

#[cfg(unix)]
impl GatewayAdmissionFixture {
    fn stop(self) {
        for stop in self.stops {
            stop.store(true, std::sync::atomic::Ordering::Release);
        }
        for worker in self.workers {
            worker.join().expect("SSH gateway worker");
        }
    }
}

#[cfg(unix)]
fn gateway_admission_fixture(
    primary_rejects_direct_tcpip: bool,
    secondary_rejects_direct_tcpip: bool,
) -> GatewayAdmissionFixture {
    use tempfile::tempdir;

    let directory = tempdir().expect("gateway admission directory");
    let client_key =
        russh::keys::PrivateKey::random(&mut rand::rng(), russh::keys::Algorithm::Ed25519)
            .expect("operator key");
    let gateway_key =
        russh::keys::PrivateKey::random(&mut rand::rng(), russh::keys::Algorithm::Ed25519)
            .expect("gateway key");
    let identity = directory.path().join("id_ed25519");
    fs::write(
        &identity,
        client_key
            .to_openssh(russh::keys::ssh_key::LineEnding::LF)
            .expect("private key")
            .as_bytes(),
    )
    .expect("operator identity");
    let expected_key = client_key.public_key().clone();
    let gateway_public_key = gateway_key
        .public_key()
        .to_openssh()
        .expect("gateway public key");
    let reverse_listener = TcpListener::bind("127.0.0.1:0").expect("reverse listener");
    let reverse_port = reverse_listener
        .local_addr()
        .expect("reverse address")
        .port();
    let mut listeners = Vec::new();
    for _ in 0..2 {
        listeners.push(TcpListener::bind("127.0.0.1:0").expect("gateway listener"));
    }

    let mut routes = Vec::new();
    let mut stops = Vec::new();
    let mut workers = Vec::new();
    for (listener, reject_direct_tcpip) in listeners
        .into_iter()
        .zip([primary_rejects_direct_tcpip, secondary_rejects_direct_tcpip])
    {
        let address = listener.local_addr().expect("gateway address");
        let (stop, worker, _) = spawn_test_ssh_server(
            listener,
            gateway_key.clone(),
            TestGateway {
                expected_user: "operator".to_owned(),
                expected_key: expected_key.clone(),
                control_redirect: None,
                reject_direct_tcpip,
                reject_direct_tcpip_flag: None,
                reject_next_direct_tcpip_flag: None,
                close_direct_tcpip_after_accept_flag: None,
                disconnect_direct_tcpip_flag: None,
                sftp_root: None,
                session_channels: Default::default(),
            },
        );
        routes.push(crate::GatewayRoute {
            host: "127.0.0.1".to_owned(),
            user: "operator".to_owned(),
            port: address.port(),
            trust: crate::GatewayTrust::PinnedPublicKey(gateway_public_key.clone()),
        });
        stops.push(stop);
        workers.push(worker);
    }

    GatewayAdmissionFixture {
        _directory: directory,
        gateways: routes,
        identity,
        reverse_port,
        _reverse_listener: reverse_listener,
        stops,
        workers,
    }
}

#[cfg(unix)]
#[tokio::test]
async fn regression_inv_794_read_only_durable_job_observations_reconnect_once_before_submission() {
    use std::io::BufReader;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    let dir = tempfile::tempdir().expect("managed observation directory");
    let client_key =
        russh::keys::PrivateKey::random(&mut rand::rng(), russh::keys::Algorithm::Ed25519)
            .expect("operator key");
    let gateway_key =
        russh::keys::PrivateKey::random(&mut rand::rng(), russh::keys::Algorithm::Ed25519)
            .expect("gateway key");
    let identity = dir.path().join("id_ed25519");
    fs::write(
        &identity,
        client_key
            .to_openssh(russh::keys::ssh_key::LineEnding::LF)
            .expect("operator identity")
            .as_bytes(),
    )
    .expect("write operator identity");

    let expected_run_id = "0123456789abcdef0123456789abcdef".to_owned();
    let candidate_sha256 = format!("{:x}", Sha256::digest(b"fixture run-local candidate"));
    let candidate_name = format!("sha256-{candidate_sha256}.exe");
    let expected_run_identity = hostlink_protocol::RunLocalJobIdentity::try_new(
        expected_run_id.clone(),
        candidate_name,
        candidate_sha256,
        Vec::new(),
    )
    .expect("canonical content-addressed durable run identity");

    let agent_listener = TcpListener::bind("127.0.0.1:0").expect("agent listener");
    let agent_port = agent_listener.local_addr().expect("agent address").port();
    let primary_gateway_listener =
        TcpListener::bind("127.0.0.1:0").expect("primary gateway listener");
    let primary_gateway_address = primary_gateway_listener
        .local_addr()
        .expect("primary gateway address");
    let fallback_gateway_listener =
        TcpListener::bind("127.0.0.1:0").expect("fallback gateway listener");
    let fallback_gateway_address = fallback_gateway_listener
        .local_addr()
        .expect("fallback gateway address");
    let gateway_pin = gateway_key
        .public_key()
        .to_openssh()
        .expect("gateway public key");
    let (primary_gateway_stop, primary_gateway_worker, primary_gateway_activity) =
        spawn_test_ssh_server(
            primary_gateway_listener,
            gateway_key.clone(),
            TestGateway {
                expected_user: "operator".to_owned(),
                expected_key: client_key.public_key().clone(),
                control_redirect: Some(agent_port),
                reject_direct_tcpip: true,
                reject_direct_tcpip_flag: None,
                reject_next_direct_tcpip_flag: None,
                close_direct_tcpip_after_accept_flag: None,
                disconnect_direct_tcpip_flag: None,
                sftp_root: None,
                session_channels: Default::default(),
            },
        );
    let reject_next = std::sync::Arc::new(AtomicBool::new(false));
    let reject_all = std::sync::Arc::new(AtomicBool::new(false));
    let (fallback_gateway_stop, fallback_gateway_worker, fallback_gateway_activity) =
        spawn_test_ssh_server(
            fallback_gateway_listener,
            gateway_key,
            TestGateway {
                expected_user: "operator".to_owned(),
                expected_key: client_key.public_key().clone(),
                control_redirect: Some(agent_port),
                reject_direct_tcpip: false,
                reject_direct_tcpip_flag: Some(reject_all.clone()),
                reject_next_direct_tcpip_flag: Some(reject_next.clone()),
                close_direct_tcpip_after_accept_flag: None,
                disconnect_direct_tcpip_flag: None,
                sftp_root: None,
                session_channels: Default::default(),
            },
        );

    let expected_job_id = "00000000-0000-0000-0000-000000000794".to_owned();
    let expected_secret = "fixture-control-secret".to_owned();
    let observed_requests = std::sync::Arc::new(AtomicUsize::new(0));
    let observed_requests_by_agent = observed_requests.clone();
    let run_id_by_agent = expected_run_id.clone();
    let job_id_by_agent = expected_job_id.clone();
    let agent = thread::spawn(move || {
        for step in 0..3 {
            let (stream, _) = agent_listener.accept().expect("agent accepts observation");
            let mut reader = BufReader::new(stream.try_clone().expect("clone agent stream"));
            let request: AgentRequest =
                hostlink_protocol::read_json_line(&mut reader).expect("observation request");
            drop(reader);
            assert_eq!(request.token, expected_secret);
            observed_requests_by_agent.fetch_add(1, Ordering::AcqRel);
            let response = match (step, request.request) {
                (0, AgentRequestKind::Hello) => AgentResponse::success(AgentResponseKind::Hello {
                    name: "fixture-machine-794".to_owned(),
                    agent_version: "0.1.1".to_owned(),
                    hostname: "FIXTURE-794".to_owned(),
                    os: "windows".to_owned(),
                    capabilities: vec!["jobs.local-candidate-v1".to_owned(), "jobs-v1".to_owned()],
                    agent_executable: None,
                    onec_executable: None,
                }),
                (1, AgentRequestKind::RunLocalStatus { run_id }) if run_id == run_id_by_agent => {
                    AgentResponse::success(AgentResponseKind::JobStatus {
                        job: hostlink_protocol::AgentJobInfo {
                            job_id: job_id_by_agent.clone(),
                            state: hostlink_protocol::AgentJobState::Running,
                            worker_pid: None,
                            spawn_owner_pid: None,
                            process_pid: Some(794),
                            exit_code: None,
                            created_unix_ms: 1,
                            started_unix_ms: Some(2),
                            finished_unix_ms: None,
                            message: None,
                            stdout_log_truncated: false,
                            stderr_log_truncated: false,
                            result_set: None,
                            run_local: Some(expected_run_identity.clone()),
                        },
                    })
                }
                (
                    2,
                    AgentRequestKind::JobLogs {
                        job_id,
                        tail_bytes: 32,
                    },
                ) if job_id == job_id_by_agent => {
                    AgentResponse::success(AgentResponseKind::JobLogs {
                        job_id,
                        stdout: "still-running\n".to_owned(),
                        stderr: String::new(),
                        stdout_truncated: false,
                        stderr_truncated: false,
                        stdout_storage_truncated: false,
                        stderr_storage_truncated: false,
                    })
                }
                (_, other) => panic!("unexpected durable observation request: {other:?}"),
            };
            write_json_line(stream, &response).expect("write observation response");
        }
    });

    let mut remote = fixture();
    remote.name = "fixture-machine-794".to_owned();
    remote.gateways = [primary_gateway_address, fallback_gateway_address]
        .into_iter()
        .map(|address| crate::GatewayRoute {
            host: "127.0.0.1".to_owned(),
            user: "operator".to_owned(),
            port: address.port(),
            trust: crate::GatewayTrust::PinnedPublicKey(gateway_pin.clone()),
        })
        .collect();
    remote.remote_port = 27391;
    remote.identity = Some(identity);
    let client = RemoteAgentClient::new(remote).expect("pinned managed client");
    assert!(client.capabilities.get().is_none());

    reject_next.store(true, Ordering::Release);
    let status = tokio::time::timeout(
        Duration::from_secs(8),
        client.run_local_status(expected_run_id.clone()),
    )
    .await
    .expect("run-local status retries within the bounded route attempts")
    .expect("run-local status recovers after one pre-submission channel failure");
    assert!(matches!(
        status,
        AgentResponseKind::JobStatus { ref job }
            if job.job_id == expected_job_id && job.state == hostlink_protocol::AgentJobState::Running
    ));

    // The capability cache is warm here. Reject the first route pass for the observation itself;
    // only the single approved-route retry may reach the Agent, exactly once.
    let requests_before_logs = observed_requests.load(Ordering::Acquire);
    reject_next.store(true, Ordering::Release);
    let logs = tokio::time::timeout(
        Duration::from_secs(8),
        client.job_logs(expected_job_id.clone(), 32),
    )
    .await
    .expect("job logs retry within the bounded route attempts")
    .expect("job logs recover after one pre-submission channel failure");
    assert!(matches!(
        logs,
        AgentResponseKind::JobLogs { ref job_id, ref stdout, .. }
            if job_id == &expected_job_id && stdout == "still-running\n"
    ));
    assert_eq!(
        observed_requests.load(Ordering::Acquire),
        requests_before_logs + 1,
        "the failed first route pass is retried once and submits one Agent observation"
    );
    assert_eq!(observed_requests.load(Ordering::Acquire), 3);
    wait_for_test_ssh_idle(&primary_gateway_activity).await;
    wait_for_test_ssh_idle(&fallback_gateway_activity).await;

    reject_all.store(true, Ordering::Release);
    let started = tokio::time::Instant::now();
    let unavailable = client
        .job_logs(expected_job_id, 32)
        .await
        .expect_err("persistent approved-route failure remains unavailable");
    assert!(started.elapsed() < Duration::from_secs(8));
    assert_eq!(observed_requests.load(Ordering::Acquire), 3);
    assert!(format!("{unavailable:#}").contains("all approved gateway routes failed"));

    agent.join().expect("agent observation worker");
    primary_gateway_stop.store(true, Ordering::Release);
    primary_gateway_worker
        .join()
        .expect("primary gateway SSH worker");
    fallback_gateway_stop.store(true, Ordering::Release);
    fallback_gateway_worker
        .join()
        .expect("fallback gateway SSH worker");
}

#[cfg(unix)]
#[tokio::test]
async fn regression_inv_205_target_ssh_post_auth_disconnect_is_unknown_and_recovers_without_replay()
{
    use std::io::BufReader;

    let dir = tempfile::tempdir().expect("managed SSH recovery directory");
    let client_key =
        russh::keys::PrivateKey::random(&mut rand::rng(), russh::keys::Algorithm::Ed25519)
            .expect("operator key");
    let gateway_key =
        russh::keys::PrivateKey::random(&mut rand::rng(), russh::keys::Algorithm::Ed25519)
            .expect("gateway key");
    let target_key =
        russh::keys::PrivateKey::random(&mut rand::rng(), russh::keys::Algorithm::Ed25519)
            .expect("target key");
    let identity = dir.path().join("id_ed25519");
    fs::write(
        &identity,
        client_key
            .to_openssh(russh::keys::ssh_key::LineEnding::LF)
            .expect("operator identity")
            .as_bytes(),
    )
    .expect("write operator identity");

    let agent_listener = TcpListener::bind("127.0.0.1:0").expect("agent listener");
    let agent_port = agent_listener.local_addr().expect("agent address").port();
    let target_listener = TcpListener::bind("127.0.0.1:0").expect("target SSH listener");
    let target_address = target_listener.local_addr().expect("target SSH address");
    let gateway_listener = TcpListener::bind("127.0.0.1:0").expect("gateway listener");
    let gateway_address = gateway_listener.local_addr().expect("gateway address");
    let gateway_known_hosts = dir.path().join("gateway-known-hosts");
    fs::write(
        &gateway_known_hosts,
        format!(
            "[127.0.0.1]:{} {}\n",
            gateway_address.port(),
            gateway_key
                .public_key()
                .to_openssh()
                .expect("gateway public key")
        ),
    )
    .expect("pin gateway key");
    let target_host_key_alias = "fixture-target-794";
    let target_known_hosts = dir.path().join("target-known-hosts");
    fs::write(
        &target_known_hosts,
        format!(
            "{target_host_key_alias} {}\n",
            target_key
                .public_key()
                .to_openssh()
                .expect("target public key")
        ),
    )
    .expect("pin target key");

    let expected_key = client_key.public_key().clone();
    let close_gateway_channel_after_accept =
        std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let disconnect_target_channel = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (target_stop, target_worker, target_activity) = spawn_test_ssh_server(
        target_listener,
        target_key.clone(),
        TestGateway {
            expected_user: "target-user".to_owned(),
            expected_key: expected_key.clone(),
            control_redirect: Some(agent_port),
            reject_direct_tcpip: false,
            reject_direct_tcpip_flag: None,
            reject_next_direct_tcpip_flag: None,
            close_direct_tcpip_after_accept_flag: None,
            disconnect_direct_tcpip_flag: Some(disconnect_target_channel.clone()),
            sftp_root: None,
            session_channels: Default::default(),
        },
    );
    // The gateway server owns this switch: it closes only this fixture's accepted forwarded channel.
    let (gateway_stop, gateway_worker, gateway_activity) = spawn_test_ssh_server(
        gateway_listener,
        gateway_key,
        TestGateway {
            expected_user: "operator".to_owned(),
            expected_key,
            control_redirect: None,
            reject_direct_tcpip: false,
            reject_direct_tcpip_flag: None,
            reject_next_direct_tcpip_flag: None,
            close_direct_tcpip_after_accept_flag: Some(close_gateway_channel_after_accept.clone()),
            disconnect_direct_tcpip_flag: None,
            sftp_root: None,
            session_channels: Default::default(),
        },
    );

    let requests = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let observed_requests = requests.clone();
    let expected_secret = "fixture-control-secret".to_owned();
    let agent = thread::spawn(move || {
        for step in 0..8 {
            let (mut stream, _) = agent_listener.accept().expect("agent accept");
            let mut reader = BufReader::new(stream.try_clone().expect("clone agent stream"));
            let request: AgentRequest =
                hostlink_protocol::read_json_line(&mut reader).expect("agent request");
            drop(reader);
            assert_eq!(request.token, expected_secret);
            observed_requests.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
            match (step, request.request) {
                (0 | 5 | 7, AgentRequestKind::Hello) => {
                    write_json_line(
                        stream,
                        &AgentResponse::success(AgentResponseKind::Hello {
                            name: "fixture-machine-794".into(),
                            agent_version: "0.1.1".into(),
                            hostname: "FIXTURE-794".into(),
                            os: "windows".into(),
                            capabilities: vec![],
                            agent_executable: None,
                            onec_executable: None,
                        }),
                    )
                    .expect("hello response");
                }
                (
                    1..=4,
                    AgentRequestKind::JobStart {
                        ref program,
                        ref args,
                        ..
                    },
                ) if program == "onec.exe"
                    && args.first().is_some_and(|arg| arg == "extension") =>
                {
                    write_json_line(
                        stream,
                        &AgentResponse::success(AgentResponseKind::JobStarted {
                            job: hostlink_protocol::AgentJobInfo {
                                job_id: format!("00000000-0000-0000-0000-{step:012}"),
                                state: hostlink_protocol::AgentJobState::Succeeded,
                                worker_pid: None,
                                spawn_owner_pid: None,
                                process_pid: Some(step as u32),
                                exit_code: Some(0),
                                created_unix_ms: step as u64,
                                started_unix_ms: Some(step as u64),
                                finished_unix_ms: Some(step as u64),
                                message: None,
                                stdout_log_truncated: false,
                                stderr_log_truncated: false,
                                result_set: None,
                                run_local: None,
                            },
                        }),
                    )
                    .expect("successful dump JobStart response");
                }
                (
                    6,
                    AgentRequestKind::JobStart {
                        ref program,
                        ref args,
                        ..
                    },
                ) if program == "cmd.exe"
                    && args == &vec!["/c".to_owned(), "mutate".to_owned()] =>
                {
                    // Keep the Agent actively handling the submitted mutation until the target
                    // SSH relay drops its already-open control channel.
                    let mut byte = [0_u8; 1];
                    assert_eq!(
                        stream
                            .read(&mut byte)
                            .expect("channel disconnect reaches Agent"),
                        0,
                        "the Agent observes EOF while serving the one submitted mutation"
                    );
                }
                (_, other) => panic!("unexpected agent request at step {step}: {other:?}"),
            }
        }
    });

    // This is the actual pinned gateway -> target SSH -> reverse listener path used by the client.
    let mut remote = fixture();
    remote.name = "fixture-machine-794".into();
    remote.gateways[0] = crate::GatewayRoute {
        host: "127.0.0.1".into(),
        user: "operator".into(),
        port: gateway_address.port(),
        trust: crate::GatewayTrust::KnownHosts(gateway_known_hosts.clone()),
    };
    remote.remote_port = target_address.port();
    remote.carrier = RemoteCarrier::TargetSsh;
    remote.identity = Some(identity.clone());
    remote.known_hosts = Some(gateway_known_hosts);
    remote.target_user = Some("target-user".into());
    remote.target_known_hosts = Some(target_known_hosts);
    remote.target_host_key_alias = Some(target_host_key_alias.into());
    assert_eq!(remote.gateways.len(), 1, "fixture has no fallback route");

    let initial_client = RemoteAgentClient::new(remote.clone()).expect("initial client");
    let initial = tokio::time::timeout(Duration::from_secs(3), initial_client.hello())
        .await
        .expect("initial managed SSH Hello is bounded")
        .expect("initial managed SSH Hello succeeds");
    assert!(matches!(
        initial,
        AgentResponseKind::Hello { ref name, .. } if name == "fixture-machine-794"
    ));
    assert_eq!(requests.load(std::sync::atomic::Ordering::Acquire), 1);
    wait_for_test_ssh_idle(&target_activity).await;
    wait_for_test_ssh_idle(&gateway_activity).await;

    for index in 0..4 {
        let response = initial_client
            .request(AgentRequestKind::JobStart {
                program: "onec.exe".into(),
                args: vec!["extension".into(), "dump".into(), index.to_string()],
                cwd: None,
                env: Default::default(),
                secret_env: Default::default(),
                stdin: None,
                results: Vec::new(),
                run_local: None,
            })
            .await
            .expect("each preceding dump job is durably accepted");
        assert!(matches!(
            response,
            AgentResponseKind::JobStarted { ref job }
                if job.state == hostlink_protocol::AgentJobState::Succeeded
                    && job.exit_code == Some(0)
        ));
    }
    assert_eq!(
        requests.load(std::sync::atomic::Ordering::Acquire),
        5,
        "four successful JobStart requests follow the initial authenticated Hello"
    );
    wait_for_test_ssh_idle(&target_activity).await;
    wait_for_test_ssh_idle(&gateway_activity).await;

    close_gateway_channel_after_accept.store(true, std::sync::atomic::Ordering::Release);
    let disconnected_client = RemoteAgentClient::new(remote.clone()).expect("disconnected client");
    let started = tokio::time::Instant::now();
    // This 3-second guard checks that the fixture sends an explicit SSH Close after acceptance;
    // the 5-second product handshake deadline is covered by the non-network phase regression.
    let error = tokio::time::timeout(
        Duration::from_secs(3),
        disconnected_client.request(AgentRequestKind::JobStart {
            program: "onec.exe".into(),
            args: vec!["extension".into(), "dump".into(), "fifth".into()],
            cwd: None,
            env: Default::default(),
            secret_env: Default::default(),
            stdin: None,
            results: Vec::new(),
            run_local: None,
        }),
    )
    .await
    .expect("disconnected managed SSH JobStart is bounded")
    .expect_err("closed fixture gateway channel must fail before JobStart submission");
    assert!(started.elapsed() < Duration::from_secs(3));
    let diagnostic = format!("{error:#}");
    assert!(
        diagnostic.contains("target_ssh_handshake/auth: failed"),
        "gateway accepted and then dropped the forwarded SSH channel: {diagnostic}"
    );
    assert!(
        diagnostic.contains("target onec-agent state is unknown"),
        "{diagnostic}"
    );
    assert!(
        diagnostic.contains("before Agent request submission"),
        "{diagnostic}"
    );
    for sensitive in [
        "127.0.0.1",
        "operator",
        "target-user",
        "fixture-control-secret",
        identity.to_str().expect("identity path"),
        "ssh-ed25519",
    ] {
        assert!(
            !diagnostic.contains(sensitive),
            "diagnostic leaked {sensitive}"
        );
    }
    assert_eq!(
        requests.load(std::sync::atomic::Ordering::Acquire),
        5,
        "failed fifth channel establishment must not send or replay a JobStart"
    );
    wait_for_test_ssh_idle(&target_activity).await;
    wait_for_test_ssh_idle(&gateway_activity).await;

    close_gateway_channel_after_accept.store(false, std::sync::atomic::Ordering::Release);
    let recovered_client = RemoteAgentClient::new(remote.clone()).expect("recovered client");
    let recovered = tokio::time::timeout(Duration::from_secs(3), recovered_client.hello())
        .await
        .expect("recovered managed SSH Hello is bounded")
        .expect("fresh Hello succeeds over the same pinned gateway and target keys");
    assert!(matches!(
        recovered,
        AgentResponseKind::Hello { ref name, .. } if name == "fixture-machine-794"
    ));
    assert_eq!(
        requests.load(std::sync::atomic::Ordering::Acquire),
        6,
        "four succeeded jobs are followed only by one read-only recovery Hello"
    );
    wait_for_test_ssh_idle(&target_activity).await;
    wait_for_test_ssh_idle(&gateway_activity).await;

    let submitted_client = recovered_client.clone();
    let mutation = tokio::spawn(async move {
        submitted_client
            .request(AgentRequestKind::JobStart {
                program: "cmd.exe".into(),
                args: vec!["/c".into(), "mutate".into()],
                cwd: None,
                env: Default::default(),
                secret_env: Default::default(),
                stdin: None,
                results: Vec::new(),
                run_local: None,
            })
            .await
    });
    tokio::time::timeout(Duration::from_secs(3), async {
        while requests.load(std::sync::atomic::Ordering::Acquire) != 7 {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .expect("the live Agent receives the mutation before the forced disconnect");
    disconnect_target_channel.store(true, std::sync::atomic::Ordering::Release);
    let error = tokio::time::timeout(Duration::from_secs(3), mutation)
        .await
        .expect("post-auth channel disconnect is bounded")
        .expect("mutation request task completes")
        .expect_err("a lost response leaves the submitted mutation outcome unknown");
    let diagnostic = format!("{error:#}");
    assert!(
        diagnostic.contains("target onec-agent state is unknown"),
        "{diagnostic}"
    );
    assert!(
        !diagnostic.to_ascii_lowercase().contains("offline"),
        "transport loss must not claim that the managed target is offline: {diagnostic}"
    );
    for sensitive in [
        "127.0.0.1",
        "operator",
        "target-user",
        "fixture-control-secret",
        identity.to_str().expect("identity path"),
    ] {
        assert!(
            !diagnostic.contains(sensitive),
            "diagnostic leaked {sensitive}"
        );
    }
    assert_eq!(
        requests.load(std::sync::atomic::Ordering::Acquire),
        7,
        "the live Agent received one mutation and the transport did not replay it"
    );
    wait_for_test_ssh_idle(&target_activity).await;
    wait_for_test_ssh_idle(&gateway_activity).await;

    // Restart the target SSH endpoint under the same pinned host key, then prove that a fresh
    // read-only control channel recovers without replaying the uncertain mutation.
    target_stop.store(true, std::sync::atomic::Ordering::Release);
    target_worker.join().expect("stopped target SSH fixture");
    disconnect_target_channel.store(false, std::sync::atomic::Ordering::Release);
    let restarted_listener = TcpListener::bind(("127.0.0.1", target_address.port()))
        .expect("restarted target listener on the same endpoint");
    let (restarted_target_stop, restarted_target_worker, restarted_target_activity) =
        spawn_test_ssh_server(
            restarted_listener,
            target_key,
            TestGateway {
                expected_user: "target-user".to_owned(),
                expected_key: client_key.public_key().clone(),
                control_redirect: Some(agent_port),
                reject_direct_tcpip: false,
                reject_direct_tcpip_flag: None,
                reject_next_direct_tcpip_flag: None,
                close_direct_tcpip_after_accept_flag: None,
                disconnect_direct_tcpip_flag: Some(disconnect_target_channel.clone()),
                sftp_root: None,
                session_channels: Default::default(),
            },
        );
    let recovered_client = RemoteAgentClient::new(remote).expect("client after target restart");
    let recovered = tokio::time::timeout(Duration::from_secs(3), recovered_client.hello())
        .await
        .expect("read-only Hello after target SSH restart is bounded")
        .expect("read-only Hello recovers after target SSH restart");
    assert!(matches!(
        recovered,
        AgentResponseKind::Hello { ref name, .. } if name == "fixture-machine-794"
    ));
    assert_eq!(
        requests.load(std::sync::atomic::Ordering::Acquire),
        8,
        "recovery submits one read-only Hello and never replays the mutation"
    );
    wait_for_test_ssh_idle(&restarted_target_activity).await;
    wait_for_test_ssh_idle(&gateway_activity).await;
    agent.join().expect("agent fixture");

    restarted_target_stop.store(true, std::sync::atomic::Ordering::Release);
    restarted_target_worker
        .join()
        .expect("restarted target SSH fixture");
    gateway_stop.store(true, std::sync::atomic::Ordering::Release);
    gateway_worker.join().expect("gateway SSH fixture");
}

#[cfg(unix)]
#[tokio::test]
async fn regression_inv_162_ssh_gateway_admission_selects_secondary_before_target_session() {
    let fixture = gateway_admission_fixture(true, false);
    let selected = super::select_managed_ssh_gateway(
        &fixture.gateways,
        &fixture.identity,
        fixture.reverse_port,
    )
    .await
    .expect("secondary reverse listener route");
    assert_eq!(selected, 1);
    fixture.stop();
}

#[cfg(unix)]
#[tokio::test]
async fn regression_inv_162_ssh_gateway_admission_fails_when_all_edges_reject_listener() {
    let fixture = gateway_admission_fixture(true, true);
    let error = super::select_managed_ssh_gateway(
        &fixture.gateways,
        &fixture.identity,
        fixture.reverse_port,
    )
    .await
    .expect_err("no target SSH session may start without an admitted edge");
    let message = error.to_string();
    assert!(message.contains("all approved gateway routes failed managed SSH admission"));
    assert!(message.contains("gateway[0] gateway_direct_tcpip: failed"));
    assert!(message.contains("gateway[1] gateway_direct_tcpip: failed"));
    assert!(!message.contains("127.0.0.1"));
    fixture.stop();
}

#[tokio::test]
async fn agent_tcp_stream_uses_structured_connect_and_preserves_duplex_bytes() {
    use std::io::BufReader;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = TcpListener::bind("127.0.0.1:0").expect("control listener");
    let control = listener.local_addr().expect("control address");
    let expected_secret = fixture().secret().expect("secret").to_owned();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        let mut reader = BufReader::new(stream.try_clone().expect("clone"));
        let request: AgentRequest =
            hostlink_protocol::read_json_line(&mut reader).expect("tcp request");
        drop(reader);
        assert_eq!(request.token, expected_secret);
        assert!(matches!(
            request.request,
            AgentRequestKind::TcpConnect {
                ref host,
                port: 28444,
                timeout_ms: 7_000,
            } if host == "127.0.0.1"
        ));
        write_json_line(
            &mut stream,
            &AgentResponse::success(AgentResponseKind::TcpReady),
        )
        .expect("tcp ready");
        let mut payload = [0_u8; 4];
        stream.read_exact(&mut payload).expect("payload");
        assert_eq!(&payload, b"ping");
        stream.write_all(b"pong").expect("response");
    });

    let client = RemoteAgentClient::new(fixture()).expect("client");
    let mut stream = client
        .tcp_connect_stream_via(control, "127.0.0.1", 28444, Duration::from_secs(7))
        .await
        .expect("tcp stream");
    stream.write_all(b"ping").await.expect("write");
    let mut response = [0_u8; 4];
    stream.read_exact(&mut response).await.expect("read");
    assert_eq!(&response, b"pong");
    server.join().expect("server");
}

#[tokio::test]
async fn agent_tcp_stream_rejects_ambiguous_target_before_transport() {
    let client = RemoteAgentClient::new(fixture()).expect("client");
    let control = "127.0.0.1:9".parse().expect("socket");
    for (host, port, timeout) in [
        ("", 28444, Duration::from_secs(1)),
        ("127.0.0.1", 0, Duration::from_secs(1)),
        ("127.0.0.1", 28444, Duration::ZERO),
    ] {
        let error = client
            .tcp_connect_stream_via(control, host, port, timeout)
            .await
            .expect_err("invalid target must fail before transport");
        assert!(error.to_string().contains("non-empty host"));
    }
}

#[tokio::test]
async fn combined_process_input_requires_each_requested_capability_before_transport() {
    let client = RemoteAgentClient::new(fixture()).expect("client");
    client
        .capabilities
        .set(vec![
            "exec.secret-env-v1".to_owned(),
            "exec.bounded-v1".to_owned(),
            "jobs.secret-env-v1".to_owned(),
            "jobs-v1".to_owned(),
        ])
        .expect("seed capabilities");
    let candidate_error = client
        .require_local_candidate_job_support()
        .await
        .expect_err("old agent must reject durable local candidate before prepare or upload");
    assert!(
        candidate_error
            .to_string()
            .contains("jobs.local-candidate-v1")
    );
    let prepare_error = client
        .prepare_run_local_job("0123456789abcdef0123456789abcdef")
        .await
        .expect_err("old agent must reject durable preparation before remote request");
    assert!(
        prepare_error
            .to_string()
            .contains("jobs.local-candidate-v1")
    );

    let secret_env = hostlink_protocol::SecretEnvironment::new(
        [("ONEC_TEST_SECRET".to_owned(), "not-sent".to_owned())]
            .into_iter()
            .collect(),
    );
    let stdin =
        hostlink_protocol::StdinPayload::try_new(b"not-sent".to_vec()).expect("bounded stdin");

    let exec_error = client
        .exec("cmd.exe")
        .args(vec!["/c".to_owned(), "more".to_owned()])
        .secret_env(secret_env.clone())
        .stdin(stdin.clone())
        .call()
        .await
        .expect_err("combined exec must require stdin capability");
    assert!(
        exec_error.to_string().contains("exec.stdin-v1"),
        "unexpected combined exec capability error: {exec_error:#}"
    );

    let job_error = client
        .start_job("cmd.exe")
        .args(vec!["/c".to_owned(), "more".to_owned()])
        .secret_env(secret_env)
        .stdin(stdin)
        .call()
        .await
        .expect_err("combined job must require stdin capability");
    assert!(
        job_error.to_string().contains("jobs.stdin-v1"),
        "unexpected combined job capability error: {job_error:#}"
    );

    let results = vec![
        hostlink_protocol::ResultArtifactSpec::try_new("report.bin".to_owned(), 1024, None)
            .expect("valid result declaration"),
    ];
    let exec_error = client
        .exec("cmd.exe")
        .args(vec!["/c".to_owned(), "echo ok".to_owned()])
        .results(results.clone())
        .call()
        .await
        .expect_err("result Exec must require its capability before transport");
    assert!(exec_error.to_string().contains("exec.results-v1"));
    let job_error = client
        .start_job("cmd.exe")
        .args(vec!["/c".to_owned(), "echo ok".to_owned()])
        .results(results)
        .call()
        .await
        .expect_err("result JobStart must require its capability before transport");
    assert!(job_error.to_string().contains("jobs.results-v1"));

    let partial_client = RemoteAgentClient::new(fixture()).expect("partial client");
    partial_client
        .capabilities
        .set(vec![
            "exec.results-v1".to_owned(),
            "jobs.results-v1".to_owned(),
        ])
        .expect("seed partial result capabilities");
    let exec_error = partial_client
        .exec("cmd.exe")
        .args(vec!["/c".to_owned(), "echo ok".to_owned()])
        .results(vec![
            hostlink_protocol::ResultArtifactSpec::try_new("report.bin".to_owned(), 1024, None)
                .expect("valid result declaration"),
        ])
        .call()
        .await
        .expect_err("Exec must preflight the download capability");
    assert!(exec_error.to_string().contains("results-v1"));
    let job_error = partial_client
        .start_job("cmd.exe")
        .args(vec!["/c".to_owned(), "echo ok".to_owned()])
        .results(vec![
            hostlink_protocol::ResultArtifactSpec::try_new("report.bin".to_owned(), 1024, None)
                .expect("valid result declaration"),
        ])
        .call()
        .await
        .expect_err("JobStart must preflight the download capability");
    assert!(job_error.to_string().contains("results-v1"));
}

#[cfg(unix)]
#[tokio::test]
async fn gateway_control_round_trips_hello_and_transfer() {
    use super::control::RunLocalPrepareTimingEvent;
    use std::io::BufReader;
    use tempfile::tempdir;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let dir = tempdir().expect("tempdir");
    let source = dir.path().join("source.bin");
    let restored = dir.path().join("restored.bin");
    let payload = b"hub-managed-transfer";
    let payload_sha256 = format!("{:x}", Sha256::digest(payload));
    fs::write(&source, payload).expect("source");

    let listener = TcpListener::bind("127.0.0.1:0").expect("agent listener");
    let port = listener.local_addr().expect("agent address").port();

    let client_key =
        russh::keys::PrivateKey::random(&mut rand::rng(), russh::keys::Algorithm::Ed25519)
            .expect("client key");
    let gateway_key =
        russh::keys::PrivateKey::random(&mut rand::rng(), russh::keys::Algorithm::Ed25519)
            .expect("gateway key");
    let identity = dir.path().join("id_ed25519");
    fs::write(
        &identity,
        client_key
            .to_openssh(russh::keys::ssh_key::LineEnding::LF)
            .expect("private key")
            .as_bytes(),
    )
    .expect("identity");

    let gateway_listener = std::net::TcpListener::bind("127.0.0.1:0").expect("gateway listener");
    let gateway_address = gateway_listener.local_addr().expect("gateway address");
    let known_hosts = dir.path().join("known_hosts");
    let correct_known_hosts = format!(
        "[127.0.0.1]:{} {}\n",
        gateway_address.port(),
        gateway_key
            .public_key()
            .to_openssh()
            .expect("gateway public key")
    );
    let wrong_gateway_key =
        russh::keys::PrivateKey::random(&mut rand::rng(), russh::keys::Algorithm::Ed25519)
            .expect("wrong gateway key");
    fs::write(
        &known_hosts,
        format!(
            "[127.0.0.1]:{} {}\n",
            gateway_address.port(),
            wrong_gateway_key
                .public_key()
                .to_openssh()
                .expect("wrong gateway public key")
        ),
    )
    .expect("wrong known_hosts");

    let expected_key = client_key.public_key().clone();
    let (gateway_stop, gateway, _) = spawn_test_ssh_server(
        gateway_listener,
        gateway_key,
        TestGateway {
            expected_user: "operator".to_owned(),
            expected_key,
            control_redirect: None,
            reject_direct_tcpip: false,
            reject_direct_tcpip_flag: None,
            reject_next_direct_tcpip_flag: None,
            close_direct_tcpip_after_accept_flag: None,
            disconnect_direct_tcpip_flag: None,
            sftp_root: None,
            session_channels: Default::default(),
        },
    );

    let expected_secret = "fixture-control-secret".to_owned();
    let server = thread::spawn(move || {
        for step in 0..14 {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut reader = BufReader::new(stream.try_clone().expect("clone"));
            let request: AgentRequest =
                hostlink_protocol::read_json_line(&mut reader).expect("agent request");
            drop(reader);
            assert_eq!(request.token, expected_secret);
            match (step, request.request) {
                (0 | 2 | 5, AgentRequestKind::Hello) => {
                    write_json_line(
                        stream,
                        &AgentResponse::success(AgentResponseKind::Hello {
                            name: "customer-a".into(),
                            agent_version: "0.1.1".into(),
                            hostname: "SERVER-A".into(),
                            os: "windows".into(),
                            capabilities: vec![
                                "run-local-v1".into(),
                                FILE_TRANSFER_SHA256_CAPABILITY.into(),
                                "exec.env-v1".into(),
                                "exec.secret-env-v1".into(),
                                "exec.stdin-v1".into(),
                                "exec.bounded-v1".into(),
                            ],
                            agent_executable: None,
                            onec_executable: None,
                        }),
                    )
                    .expect("hello response");
                }
                (
                    1 | 3 | 4,
                    AgentRequestKind::RunLocalPrepare {
                        ref run_id,
                        create_mapped_workspace: false,
                    },
                ) => {
                    let root = match run_id.as_str() {
                        "untimed" => "C:\\runs\\untimed",
                        "cold" => "C:\\runs\\cold",
                        "warm" => "C:\\runs\\warm",
                        _ => panic!("unexpected run-local identity"),
                    };
                    write_json_line(
                        stream,
                        &AgentResponse::success(AgentResponseKind::RunLocalPaths {
                            cache_root: "C:\\cache".into(),
                            run_root_parent: "C:\\runs".into(),
                            run_root: root.into(),
                        }),
                    )
                    .expect("run-local paths response");
                }
                (
                    6,
                    AgentRequestKind::Exec {
                        ref program,
                        ref args,
                        ref env,
                        secret_env,
                        stdin: Some(ref stdin),
                        timeout_ms: 5_000,
                        ..
                    },
                ) if program == "cmd.exe" && args == &vec!["/c".to_owned(), "more".to_owned()] => {
                    assert_eq!(env.get("PUBLIC_VALUE").map(String::as_str), Some("visible"));
                    let secret_env = secret_env.into_inner();
                    assert_eq!(
                        secret_env.get("ONEC_TEST_SECRET").map(String::as_str),
                        Some("transport-secret-sentinel")
                    );
                    assert_eq!(stdin.as_bytes(), b"exact-stdin");
                    write_json_line(
                        stream,
                        &AgentResponse::success(AgentResponseKind::Exec {
                            exit_code: Some(0),
                            stdout: "[REDACTED]\n".to_owned(),
                            stderr: String::new(),
                            result_set: None,
                            stdout_base64: None,
                            stderr_base64: None,
                        }),
                    )
                    .expect("exec response");
                }
                (7, AgentRequestKind::Upload { bytes, .. }) => {
                    assert_eq!(bytes, payload.len() as u64);
                    write_json_line(
                        &mut stream,
                        &AgentResponse::success(AgentResponseKind::UploadReady),
                    )
                    .expect("upload ready");
                    let mut uploaded = vec![0_u8; bytes as usize];
                    stream.read_exact(&mut uploaded).expect("upload bytes");
                    assert_eq!(uploaded, payload);
                    write_json_line(
                        stream,
                        &AgentResponse::success(AgentResponseKind::Uploaded { bytes }),
                    )
                    .expect("upload done");
                }
                (8 | 9, AgentRequestKind::PathSha256 { .. }) => {
                    write_json_line(
                        stream,
                        &AgentResponse::success(AgentResponseKind::PathSha256 {
                            bytes: payload.len() as u64,
                            sha256: payload_sha256.clone(),
                        }),
                    )
                    .expect("sha256 response");
                }
                (10, AgentRequestKind::Download { .. }) => {
                    write_json_line(
                        &mut stream,
                        &AgentResponse::success(AgentResponseKind::DownloadReady {
                            bytes: payload.len() as u64,
                        }),
                    )
                    .expect("download ready");
                    stream.write_all(payload).expect("download payload");
                }
                (
                    11,
                    AgentRequestKind::TcpConnect {
                        ref host,
                        port: 28443,
                        timeout_ms: 250,
                    },
                ) if host == "127.0.0.1" => {
                    write_json_line(
                        &mut stream,
                        &AgentResponse::success(AgentResponseKind::TcpReady),
                    )
                    .expect("probe ready");
                }
                (
                    12,
                    AgentRequestKind::TcpConnect {
                        ref host,
                        port: 28442,
                        timeout_ms: 250,
                    },
                ) if host == "127.0.0.1" => {
                    write_json_line(
                        &mut stream,
                        &AgentResponse::failure(
                            "failed to connect to 127.0.0.1:28442: connection refused",
                        ),
                    )
                    .expect("probe failure");
                }
                (
                    13,
                    AgentRequestKind::TcpConnect {
                        ref host,
                        port: 28444,
                        timeout_ms: 5_000,
                    },
                ) if host == "127.0.0.1" => {
                    write_json_line(
                        &mut stream,
                        &AgentResponse::success(AgentResponseKind::TcpReady),
                    )
                    .expect("tcp ready");
                    let mut request = Vec::new();
                    stream
                        .read_to_end(&mut request)
                        .expect("forward request EOF");
                    assert_eq!(request, b"ping");
                    stream.write_all(b"pong").expect("forward response");
                    stream
                        .shutdown(Shutdown::Write)
                        .expect("forward response EOF");
                }
                (_, other) => panic!("unexpected request at step {step}: {other:?}"),
            }
        }
    });

    let mut remote = fixture();
    remote.gateways[0].host = "127.0.0.1".into();
    remote.gateways[0].port = gateway_address.port();
    remote.remote_port = port;
    remote.identity = Some(identity);
    remote.known_hosts = Some(known_hosts.clone());
    remote.gateways[0].trust = crate::GatewayTrust::KnownHosts(known_hosts.clone());
    let mut wrong_secondary = remote.clone();
    wrong_secondary.gateways[0].port = 9;
    wrong_secondary.gateways.push(crate::GatewayRoute {
        host: "127.0.0.1".into(),
        user: "operator".into(),
        port: gateway_address.port(),
        trust: crate::GatewayTrust::PinnedPublicKey(
            wrong_gateway_key
                .public_key()
                .to_openssh()
                .expect("wrong gateway pin"),
        ),
    });
    let error = RemoteAgentClient::new(wrong_secondary)
        .expect("wrong-secondary client")
        .hello()
        .await
        .expect_err("wrong secondary host key must fail closed");
    let message = error.to_string();
    assert!(
        message.contains("gateway[0] gateway_connect: failed"),
        "{message}"
    );
    assert!(
        message.contains("gateway[1] gateway_connect: host_key_rejected"),
        "approved gateway failures must be aggregated without exposing endpoints: {message}"
    );
    assert!(!message.contains("127.0.0.1"), "{message}");
    assert!(!format!("{error:#}").contains("fixture-control-secret"));

    let client = RemoteAgentClient::new(remote).expect("client");
    let trust_error = client
        .hello()
        .await
        .expect_err("changed gateway host key must fail closed");
    assert!(
        trust_error.to_string().contains("host_key_rejected"),
        "unexpected trust error: {trust_error:#}"
    );
    fs::write(&known_hosts, correct_known_hosts).expect("restore known_hosts");

    let untimed = client
        .prepare_run_local_with_timing("untimed".to_owned(), None)
        .await
        .expect("untimed run-local preparation succeeds");
    assert_eq!(untimed.run_root, "C:\\runs\\untimed");

    let timed_client =
        RemoteAgentClient::new(client.server.clone()).expect("timed client construction");
    let mut cold_timing = RunLocalPrepareTimingEvent::new();
    let cold = timed_client
        .prepare_run_local_with_timing("cold".to_owned(), Some(&mut cold_timing))
        .await
        .expect("cold timed preparation succeeds");
    assert_eq!(cold.run_root, "C:\\runs\\cold");
    assert!(cold_timing.is_complete());
    assert_eq!(cold_timing.completed_responses(), (1, 1));
    assert_eq!(cold_timing.successful_route_channels(), 2);

    let mut warm_timing = RunLocalPrepareTimingEvent::new();
    let warm = timed_client
        .prepare_run_local_with_timing("warm".to_owned(), Some(&mut warm_timing))
        .await
        .expect("warm timed preparation succeeds");
    assert_eq!(warm.run_root, "C:\\runs\\warm");
    assert!(warm_timing.is_complete());
    assert_eq!(warm_timing.completed_responses(), (0, 1));
    assert_eq!(warm_timing.successful_route_channels(), 1);

    let mut failover_server = client.server.clone();
    failover_server.gateways.insert(
        0,
        crate::GatewayRoute {
            host: "127.0.0.1".into(),
            user: "operator".into(),
            port: 9,
            trust: crate::GatewayTrust::KnownHosts(known_hosts.clone()),
        },
    );
    let client = RemoteAgentClient::new(failover_server).expect("multi-edge client");
    let result: AppResult<()> = async {
        assert!(matches!(
            client.hello().await?,
            AgentResponseKind::Hello { .. }
        ));
        let mut secret_values = std::collections::BTreeMap::new();
        secret_values.insert("ONEC_TEST_SECRET".to_owned(), "not-sent".to_owned());
        let secret_error = client
            .start_job("cmd.exe")
            .args(vec!["/c".to_owned(), "echo unreachable".to_owned()])
            .secret_env(hostlink_protocol::SecretEnvironment::new(secret_values))
            .call()
            .await
            .expect_err("missing secret-env capability must fail before JobStart");
        assert!(
            secret_error.to_string().contains("jobs.secret-env-v1"),
            "unexpected secret capability error: {secret_error:#}"
        );
        let stdin = hostlink_protocol::StdinPayload::try_new(b"exact-stdin".to_vec())
            .expect("bounded stdin");
        let mut exec_secrets = std::collections::BTreeMap::new();
        exec_secrets.insert(
            "ONEC_TEST_SECRET".to_owned(),
            "transport-secret-sentinel".to_owned(),
        );
        let exec = client
            .exec("cmd.exe")
            .args(vec!["/c".to_owned(), "more".to_owned()])
            .env(std::collections::BTreeMap::from([(
                "PUBLIC_VALUE".to_owned(),
                "visible".to_owned(),
            )]))
            .secret_env(hostlink_protocol::SecretEnvironment::new(exec_secrets))
            .stdin(stdin.clone())
            .timeout_ms(5_000)
            .call()
            .await?;
        let AgentResponseKind::Exec {
            exit_code,
            stdout,
            stderr,
            ..
        } = exec
        else {
            panic!("unexpected combined exec response: {exec:?}");
        };
        assert_eq!(exit_code, Some(0));
        assert_eq!(stdout, "[REDACTED]\n");
        assert!(stderr.is_empty());
        assert!(!stdout.contains("transport-secret-sentinel"));

        let job_stdin_error = client
            .start_job("cmd.exe")
            .args(vec!["/c".to_owned(), "more".to_owned()])
            .stdin(stdin)
            .call()
            .await
            .expect_err("missing job stdin capability must fail before JobStart");
        assert!(
            job_stdin_error.to_string().contains("jobs.stdin-v1"),
            "unexpected job stdin capability error: {job_stdin_error:#}"
        );
        client
            .upload(&source, r"C:\\Temp\\artifact.bin", true)
            .await?;
        client
            .download(r"C:\\Temp\\artifact.bin", &restored, true)
            .await?;
        assert_eq!(fs::read(&restored).expect("restored"), payload);
        assert_eq!(
            client.probe("127.0.0.1", 28443, 250).await?,
            crate::remote::RemoteProbeResult {
                reachable: true,
                error: None,
            }
        );
        let failed_probe = client.probe("127.0.0.1", 28442, 250).await?;
        assert!(!failed_probe.reachable);
        assert!(
            failed_probe
                .error
                .as_deref()
                .is_some_and(|error| error.contains("connection refused"))
        );

        let local_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("forward local listener");
        let local_address = local_listener.local_addr().expect("forward local address");
        let mut local_client = tokio::net::TcpStream::connect(local_address)
            .await
            .expect("forward local connect");
        let local_bridge = local_listener
            .accept()
            .await
            .expect("forward local accept")
            .0;
        let forward_client = client.clone();
        let forward = tokio::spawn(async move {
            forward_client
                .forward_one(local_bridge, "127.0.0.1", 28444)
                .await
        });
        local_client
            .write_all(b"ping")
            .await
            .expect("forward local write");
        local_client
            .shutdown()
            .await
            .expect("forward local request EOF");
        let mut response = Vec::new();
        local_client
            .read_to_end(&mut response)
            .await
            .expect("forward local response");
        assert_eq!(response, b"pong");
        forward.await.expect("forward worker")?;
        Ok(())
    }
    .await;
    result.expect("gateway control protocol");
    server.join().expect("agent server");
    gateway_stop.store(true, std::sync::atomic::Ordering::Release);
    gateway.join().expect("gateway server");
}

#[cfg(unix)]
#[tokio::test]
async fn regression_inv_027_target_ssh_verified_binary_upload_download_preserves_exact_bytes() {
    use std::io::BufReader;
    use tempfile::tempdir;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let dir = tempdir().expect("tempdir");
    let remote_root = dir.path().join("remote");
    let remote_directory = remote_root
        .join("transfer")
        .join("Каталог (тест) & 100%")
        .join("long path segment 012345678901234567890123456789");
    fs::create_dir_all(&remote_directory).expect("remote transfer directory");
    fs::write(remote_root.join(".stall-next-sftp-write"), b"fixture fault")
        .expect("arm one-shot loopback SFTP write stall");
    let upload_source = dir.path().join("upload-source.bin");
    let download_target = dir.path().join("download-target.bin");
    // Exceed russh's default 2 MiB SSH channel window so the loopback fixture
    // exercises window adjustment while an independent control request uses
    // the same managed target concurrently.
    let transfer_payload = b"\x00\xff\r\n\"'\\/\x80\xfe".repeat(320_000);
    fs::write(&upload_source, &transfer_payload).expect("upload source");
    let publication_source = dir.path().join("publication-source.bin");
    let publication_payload = b"publication-acknowledgement-fixture";
    fs::write(&publication_source, publication_payload).expect("publication source");
    let remote_path = r"C:\transfer\Каталог (тест) & 100%\long path segment 012345678901234567890123456789\Артефакт %.bin";
    fs::write(remote_directory.join("Артефакт %.bin"), b"old payload")
        .expect("existing remote destination");
    #[cfg(unix)]
    std::os::unix::fs::symlink(
        remote_directory.join("Артефакт %.bin"),
        remote_directory.join("cache-symlink"),
    )
    .expect("remote symlink fixture");
    let client_key =
        russh::keys::PrivateKey::random(&mut rand::rng(), russh::keys::Algorithm::Ed25519)
            .expect("client key");
    let gateway_key =
        russh::keys::PrivateKey::random(&mut rand::rng(), russh::keys::Algorithm::Ed25519)
            .expect("gateway key");
    let target_key =
        russh::keys::PrivateKey::random(&mut rand::rng(), russh::keys::Algorithm::Ed25519)
            .expect("target key");
    let wrong_target_key =
        russh::keys::PrivateKey::random(&mut rand::rng(), russh::keys::Algorithm::Ed25519)
            .expect("wrong target key");

    let identity = dir.path().join("id_ed25519");
    fs::write(
        &identity,
        client_key
            .to_openssh(russh::keys::ssh_key::LineEnding::LF)
            .expect("private key")
            .as_bytes(),
    )
    .expect("identity");

    let agent_listener = TcpListener::bind("127.0.0.1:0").expect("agent listener");
    let agent_port = agent_listener.local_addr().expect("agent address").port();
    let target_listener = std::net::TcpListener::bind("127.0.0.1:0").expect("target listener");
    let target_address = target_listener.local_addr().expect("target address");
    let gateway_listener = std::net::TcpListener::bind("127.0.0.1:0").expect("gateway listener");
    let gateway_address = gateway_listener.local_addr().expect("gateway address");

    let gateway_known_hosts = dir.path().join("gateway-known-hosts");
    fs::write(
        &gateway_known_hosts,
        format!(
            "[127.0.0.1]:{} {}\n",
            gateway_address.port(),
            gateway_key
                .public_key()
                .to_openssh()
                .expect("gateway public key")
        ),
    )
    .expect("gateway known_hosts");

    let target_host_key_alias = "onec-ops-machine-fixture";
    let target_known_hosts = dir.path().join("target-known-hosts");
    fs::write(
        &target_known_hosts,
        format!(
            "{target_host_key_alias} {}\n",
            wrong_target_key
                .public_key()
                .to_openssh()
                .expect("wrong target public key")
        ),
    )
    .expect("wrong target known_hosts");

    let expected_key = client_key.public_key().clone();
    let (target_stop, target, _) = spawn_test_ssh_server(
        target_listener,
        target_key.clone(),
        TestGateway {
            expected_user: "target-user".to_owned(),
            expected_key: expected_key.clone(),
            control_redirect: Some(agent_port),
            reject_direct_tcpip: false,
            reject_direct_tcpip_flag: None,
            reject_next_direct_tcpip_flag: None,
            close_direct_tcpip_after_accept_flag: None,
            disconnect_direct_tcpip_flag: None,
            sftp_root: Some(remote_root.clone()),
            session_channels: Default::default(),
        },
    );
    let (gateway_stop, gateway, _) = spawn_test_ssh_server(
        gateway_listener,
        gateway_key,
        TestGateway {
            expected_user: "operator".to_owned(),
            expected_key,
            control_redirect: None,
            reject_direct_tcpip: false,
            reject_direct_tcpip_flag: None,
            reject_next_direct_tcpip_flag: None,
            close_direct_tcpip_after_accept_flag: None,
            disconnect_direct_tcpip_flag: None,
            sftp_root: None,
            session_channels: Default::default(),
        },
    );

    let expected_secret = "fixture-control-secret".to_owned();
    let agent_root = remote_root.clone();
    let publish_requests = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let observed_publish_requests = publish_requests.clone();
    let agent = thread::spawn(move || {
        for _ in 0..8 {
            let (mut stream, _) = agent_listener.accept().expect("agent accept");
            let mut reader = BufReader::new(stream.try_clone().expect("clone agent stream"));
            let request: AgentRequest =
                hostlink_protocol::read_json_line(&mut reader).expect("agent request");
            drop(reader);
            assert_eq!(request.token, expected_secret);
            let response = match request.request {
                AgentRequestKind::Hello => AgentResponse::success(AgentResponseKind::Hello {
                    name: "customer-a".into(),
                    agent_version: "0.1.1".into(),
                    hostname: "SERVER-A".into(),
                    os: "windows".into(),
                    capabilities: vec![FILE_TRANSFER_SHA256_CAPABILITY.into()],
                    agent_executable: None,
                    onec_executable: None,
                }),
                AgentRequestKind::PathSha256 { path } => {
                    let path = test_remote_path(&agent_root, &path).expect("remote hash path");
                    let bytes = fs::metadata(&path).expect("remote hash metadata").len();
                    let sha256 = hostlink_core::sha256_file(&path).expect("remote hash");
                    AgentResponse::success(AgentResponseKind::PathSha256 { bytes, sha256 })
                }
                AgentRequestKind::PathRename {
                    from,
                    to,
                    overwrite,
                } => {
                    observed_publish_requests.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
                    assert!(
                        overwrite,
                        "verified SFTP publication must preserve overwrite=true"
                    );
                    let from = test_remote_path(&agent_root, &from).expect("publish staging path");
                    let to = test_remote_path(&agent_root, &to).expect("publish destination path");
                    hostlink_core::replace_file_atomically(&from, &to).expect("atomic publish");
                    if to.ends_with("publish-stall.bin") {
                        // Commit publication, then withhold its acknowledgement past the deadline.
                        thread::sleep(Duration::from_secs(3));
                    }
                    // The atomic move committed, but the acknowledgement was lost.
                    drop(stream);
                    continue;
                }
                other => panic!("unexpected target transfer RPC: {other:?}"),
            };
            write_json_line(&mut stream, &response).expect("agent response");
        }
    });

    let service_listener = TcpListener::bind("127.0.0.1:0").expect("service listener");
    let service_port = service_listener
        .local_addr()
        .expect("service address")
        .port();
    let service = thread::spawn(move || {
        let (probe, _) = service_listener.accept().expect("probe service accept");
        drop(probe);
        let (mut stream, _) = service_listener.accept().expect("service accept");
        let mut request = Vec::new();
        stream
            .read_to_end(&mut request)
            .expect("service request EOF");
        assert_eq!(request, b"ping");
        stream.write_all(b"pong").expect("service response");
        stream
            .shutdown(Shutdown::Write)
            .expect("service response EOF");
    });

    let mut remote = fixture();
    remote.gateways[0].host = "127.0.0.1".into();
    remote.gateways[0].port = gateway_address.port();
    remote.remote_port = target_address.port();
    remote.carrier = RemoteCarrier::TargetSsh;
    remote.identity = Some(identity);
    remote.gateways[0].trust = crate::GatewayTrust::KnownHosts(gateway_known_hosts.clone());
    remote.known_hosts = Some(gateway_known_hosts);
    remote.target_user = Some("target-user".into());
    remote.target_known_hosts = Some(target_known_hosts.clone());
    remote.target_host_key_alias = Some(target_host_key_alias.into());
    remote.gateways.insert(
        0,
        crate::GatewayRoute {
            host: "127.0.0.1".into(),
            user: "operator".into(),
            port: 9,
            trust: crate::GatewayTrust::KnownHosts(
                remote.known_hosts.clone().expect("gateway trust path"),
            ),
        },
    );
    let client = RemoteAgentClient::new(remote).expect("target client");

    let trust_error = client
        .hello()
        .await
        .expect_err("changed target host key must fail closed");
    let trust_message = format!("{trust_error:#}");
    assert!(
        trust_message.contains("target_ssh_handshake/auth: host_key_rejected"),
        "unexpected target trust error: {trust_message}"
    );
    assert!(!trust_message.contains(target_host_key_alias));

    fs::write(
        &target_known_hosts,
        format!(
            "{target_host_key_alias} {}\n",
            target_key
                .public_key()
                .to_openssh()
                .expect("target public key")
        ),
    )
    .expect("target known_hosts");

    assert!(matches!(
        client.hello().await.expect("nested target hello"),
        AgentResponseKind::Hello { .. }
    ));

    // A failed cache-destination check is before the SFTP CREATE request. It must neither
    // issue cleanup for an unowned random staging path nor create an upload artifact.
    let remove_count = remote_root.join(".sftp-remove-count");
    fs::write(&remove_count, b"").expect("enable SFTP remove counter");
    fs::write(remote_root.join(".fail-next-sftp-stat"), b"fixture fault")
        .expect("arm one-shot SFTP destination-check failure");
    let preflight_path = r"C:\transfer\Каталог (тест) & 100%\long path segment 012345678901234567890123456789\preflight-failure.bin";
    let preflight_error = client
        .upload_with_progress_deadline(
            &upload_source,
            preflight_path,
            false,
            |_, _| {},
            // This checks the injected destination-stat failure, not upload timeout.
            // Permit the authenticated nested SSH setup under parallel Nextest load.
            Duration::from_secs(10),
        )
        .await
        .expect_err("failed SFTP destination check must fail closed");
    assert!(preflight_error.to_string().contains("checking SFTP path"));
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        fs::read(&remove_count).expect("read SFTP remove counter"),
        b"",
        "a failed pre-create destination check must not issue fake staging cleanup"
    );
    assert!(
        fs::read_dir(&remote_directory)
            .expect("inspect transfer directory after preflight failure")
            .filter_map(Result::ok)
            .all(|entry| !entry
                .file_name()
                .to_string_lossy()
                .contains(".onec-upload-")),
        "pre-create transport failure must not leave an upload staging path"
    );

    let fault_path = r"C:\transfer\Каталог (тест) & 100%\long path segment 012345678901234567890123456789\stall.bin";
    let started = tokio::time::Instant::now();
    let stalled = client
        .upload_with_progress_deadline(
            &upload_source,
            fault_path,
            true,
            |_, _| {},
            // The deadline must cover SSH/SFTP authentication and setup before
            // exercising the deliberately nonterminating write handler.
            Duration::from_secs(5),
        )
        .await
        .expect_err("a loopback SFTP write stall must hit the short test deadline");
    let diagnostic = stalled.to_string();
    assert!(started.elapsed() < Duration::from_secs(7));
    assert!(diagnostic.contains("phase=total_deadline"), "{diagnostic}");
    assert!(diagnostic.contains("stage=sftp_write"), "{diagnostic}");
    let byte_counts = diagnostic
        .split_once("acknowledged_bytes=")
        .and_then(|(_, tail)| tail.split_whitespace().next())
        .expect("timeout diagnostics include acknowledged and total byte counts");
    let (acknowledged, total) = byte_counts
        .split_once('/')
        .expect("timeout diagnostics delimit acknowledged/total bytes");
    let acknowledged: usize = acknowledged.parse().expect("numeric acknowledged bytes");
    let total: usize = total.parse().expect("numeric total bytes");
    assert_eq!(total, transfer_payload.len(), "{diagnostic}");
    assert!(
        acknowledged < total,
        "the stalled upload must not have reached its full byte count: {diagnostic}"
    );
    assert!(
        diagnostic.contains("publication=not_started remote_state=unknown"),
        "{diagnostic}"
    );
    assert_eq!(
        publish_requests.load(std::sync::atomic::Ordering::Acquire),
        0,
        "a pre-publication timeout must not call or replay publication"
    );
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let has_staging = fs::read_dir(&remote_directory)
                .expect("inspect loopback transfer directory")
                .filter_map(Result::ok)
                .any(|entry| {
                    entry
                        .file_name()
                        .to_string_lossy()
                        .contains(".onec-upload-")
                });
            if !has_staging {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("cancelled SFTP upload cleanup removes its owned staging file");
    let publish_stall_path = r"C:\transfer\Каталог (тест) & 100%\long path segment 012345678901234567890123456789\publish-stall.bin";
    let started = tokio::time::Instant::now();
    let stalled = client
        .upload_with_progress_deadline(
            &publication_source,
            publish_stall_path,
            true,
            |_, _| {},
            Duration::from_secs(1),
        )
        .await
        .expect_err("lost publication acknowledgement must time out without replay");
    let diagnostic = stalled.to_string();
    assert!(started.elapsed() < Duration::from_secs(2));
    assert!(diagnostic.contains("stage=publish"), "{diagnostic}");
    assert!(
        diagnostic.contains(&format!(
            "acknowledged_bytes={}/{}",
            publication_payload.len(),
            publication_payload.len()
        )),
        "{diagnostic}"
    );
    assert!(
        diagnostic.contains("publication=may_have_committed remote_state=unknown"),
        "{diagnostic}"
    );
    assert_eq!(
        fs::read(remote_directory.join("publish-stall.bin")).expect("committed publication"),
        publication_payload,
        "the remote commit may have completed even though its acknowledgement timed out"
    );
    assert_eq!(
        publish_requests.load(std::sync::atomic::Ordering::Acquire),
        1,
        "an ambiguous publication timeout must not replay the rename"
    );
    let refused_ambiguous_existing = client
        .upload(&publication_source, publish_stall_path, false)
        .await
        .expect_err("overwrite=false must refuse already-published identical bytes");
    assert!(
        refused_ambiguous_existing
            .to_string()
            .contains("already exists")
    );
    assert!(
        client
            .target_sftp_path_is_absent(&format!("{remote_path}.cache-miss-fixture"))
            .await
            .expect("pinned SFTP lstat proves exact missing path")
    );
    assert!(
        !client
            .target_sftp_path_is_absent(remote_path)
            .await
            .expect("pinned SFTP lstat observes existing path")
    );
    assert!(client
        .target_sftp_path_is_absent(
            r"C:\transfer\Каталог (тест) & 100%\long path segment 012345678901234567890123456789\cache-symlink",
        )
        .await
        .is_err());
    let refused_different = client
        .upload(&upload_source, remote_path, false)
        .await
        .expect_err("overwrite=false rejects an existing different file");
    assert!(refused_different.to_string().contains("already exists"));
    assert_eq!(
        fs::read(remote_directory.join("Артефакт %.bin")).expect("preserved remote file"),
        b"old payload"
    );
    assert_eq!(
        client
            .probe("127.0.0.1", service_port, 5_000)
            .await
            .expect("native target probe"),
        crate::remote::RemoteProbeResult {
            reachable: true,
            error: None,
        }
    );
    let unavailable_listener = TcpListener::bind("127.0.0.1:0").expect("unavailable listener");
    let unavailable_port = unavailable_listener
        .local_addr()
        .expect("unavailable address")
        .port();
    drop(unavailable_listener);
    let failed_probe = client
        .probe("127.0.0.1", unavailable_port, 250)
        .await
        .expect("failed native target probe remains a typed result");
    assert!(!failed_probe.reachable);
    assert!(failed_probe.error.is_some());

    let local_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("local forward listener");
    let local_address = local_listener.local_addr().expect("local forward address");
    let mut local_client = tokio::net::TcpStream::connect(local_address)
        .await
        .expect("local forward connect");
    let local_bridge = local_listener
        .accept()
        .await
        .expect("local forward accept")
        .0;
    let forward_client = client.clone();
    let forward = tokio::spawn(async move {
        forward_client
            .forward_one(local_bridge, "127.0.0.1", service_port)
            .await
    });
    local_client
        .write_all(b"ping")
        .await
        .expect("local forward write");
    local_client
        .shutdown()
        .await
        .expect("local forward request EOF");
    let mut response = Vec::new();
    local_client
        .read_to_end(&mut response)
        .await
        .expect("local forward response");
    assert_eq!(response, b"pong");
    forward
        .await
        .expect("target forward worker")
        .expect("target forwarding");

    let mut upload_progress = Vec::new();
    fs::write(remote_root.join(".delay-next-sftp-write"), b"fixture delay")
        .expect("arm one-shot loopback SFTP write delay");
    let write_in_progress = remote_root.join(".sftp-write-in-progress");
    let release_write = remote_root.join(".release-sftp-write");
    let concurrent_control = async {
        let started = tokio::time::timeout(Duration::from_secs(5), async {
            while !write_in_progress.exists() {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .is_ok();
        if !started {
            fs::write(&release_write, b"release after write-start timeout")
                .expect("release SFTP write after missing start signal");
            return Err("fixture SFTP write did not signal in-progress before timeout".to_owned());
        }
        let hello = tokio::time::timeout(Duration::from_secs(5), client.hello()).await;
        fs::write(&release_write, b"release after control response")
            .expect("release SFTP write after control response");
        match hello {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(error)) => Err(format!("independent SSH control Hello failed: {error}")),
            Err(_) => {
                Err("independent SSH control Hello timed out; SFTP write released".to_owned())
            }
        }
    };
    let (upload_result, concurrent_control) = tokio::join!(
        client.upload_with_progress(&upload_source, remote_path, true, |position, total| {
            upload_progress.push((position, total));
        }),
        concurrent_control,
    );
    let concurrent_control = concurrent_control
        .expect("concurrent control channel must finish while SFTP WRITE is held");
    assert!(matches!(
        concurrent_control,
        AgentResponseKind::Hello { .. }
    ));
    let uploaded = upload_result.expect("verified multi-MB SFTP upload");
    assert_eq!(uploaded, transfer_payload.len() as u64);
    assert_eq!(
        fs::read(remote_directory.join("Артефакт %.bin")).expect("published remote file"),
        transfer_payload
    );
    let refused_identical = client
        .upload(&upload_source, remote_path, false)
        .await
        .expect_err("overwrite=false rejects an existing identical file");
    assert!(refused_identical.to_string().contains("already exists"));
    assert_eq!(
        upload_progress.last().copied(),
        Some((transfer_payload.len() as u64, transfer_payload.len() as u64))
    );
    assert!(
        fs::read_dir(&remote_directory)
            .expect("remote transfer entries")
            .all(|entry| !entry
                .expect("remote transfer entry")
                .file_name()
                .to_string_lossy()
                .contains(".onec-upload-"))
    );

    let mut download_progress = Vec::new();
    let downloaded = client
        .download_with_progress(remote_path, &download_target, false, |position, total| {
            download_progress.push((position, total));
        })
        .await
        .expect("verified SFTP download");
    assert_eq!(downloaded, transfer_payload.len() as u64);
    assert_eq!(
        fs::read(&download_target).expect("downloaded local file"),
        transfer_payload
    );
    assert_eq!(
        download_progress.last().copied(),
        Some((transfer_payload.len() as u64, transfer_payload.len() as u64))
    );

    agent.join().expect("agent server");
    service.join().expect("service server");
    target_stop.store(true, std::sync::atomic::Ordering::Release);
    gateway_stop.store(true, std::sync::atomic::Ordering::Release);
    target.join().expect("target SSH server");
    gateway.join().expect("gateway SSH server");
}

#[cfg(unix)]
#[tokio::test]
async fn target_ssh_falls_back_to_agent_transfer_when_sftp_subsystem_is_rejected() {
    use std::io::BufReader;
    use tempfile::tempdir;

    let dir = tempdir().expect("tempdir");
    let source = dir.path().join("source.bin");
    let restored = dir.path().join("restored.bin");
    let payload = b"legacy-target-transfer";
    fs::write(&source, payload).expect("source");

    let client_key =
        russh::keys::PrivateKey::random(&mut rand::rng(), russh::keys::Algorithm::Ed25519)
            .expect("client key");
    let gateway_key =
        russh::keys::PrivateKey::random(&mut rand::rng(), russh::keys::Algorithm::Ed25519)
            .expect("gateway key");
    let target_key =
        russh::keys::PrivateKey::random(&mut rand::rng(), russh::keys::Algorithm::Ed25519)
            .expect("target key");
    let identity = dir.path().join("id_ed25519");
    fs::write(
        &identity,
        client_key
            .to_openssh(russh::keys::ssh_key::LineEnding::LF)
            .expect("private key")
            .as_bytes(),
    )
    .expect("identity");

    let agent_listener = TcpListener::bind("127.0.0.1:0").expect("agent listener");
    let agent_port = agent_listener.local_addr().expect("agent address").port();
    let target_listener = std::net::TcpListener::bind("127.0.0.1:0").expect("target listener");
    let target_address = target_listener.local_addr().expect("target address");
    let gateway_listener = std::net::TcpListener::bind("127.0.0.1:0").expect("gateway listener");
    let gateway_address = gateway_listener.local_addr().expect("gateway address");

    let gateway_known_hosts = dir.path().join("gateway-known-hosts");
    fs::write(
        &gateway_known_hosts,
        format!(
            "[127.0.0.1]:{} {}\n",
            gateway_address.port(),
            gateway_key
                .public_key()
                .to_openssh()
                .expect("gateway public key")
        ),
    )
    .expect("gateway known_hosts");
    let target_host_key_alias = "onec-ops-machine-legacy-fixture";
    let target_known_hosts = dir.path().join("target-known-hosts");
    fs::write(
        &target_known_hosts,
        format!(
            "{target_host_key_alias} {}\n",
            target_key
                .public_key()
                .to_openssh()
                .expect("target public key")
        ),
    )
    .expect("target known_hosts");

    let expected_key = client_key.public_key().clone();
    let (target_stop, target, _) = spawn_test_ssh_server(
        target_listener,
        target_key,
        TestGateway {
            expected_user: "target-user".to_owned(),
            expected_key: expected_key.clone(),
            control_redirect: Some(agent_port),
            reject_direct_tcpip: false,
            reject_direct_tcpip_flag: None,
            reject_next_direct_tcpip_flag: None,
            close_direct_tcpip_after_accept_flag: None,
            disconnect_direct_tcpip_flag: None,
            sftp_root: None,
            session_channels: Default::default(),
        },
    );
    let (gateway_stop, gateway, _) = spawn_test_ssh_server(
        gateway_listener,
        gateway_key,
        TestGateway {
            expected_user: "operator".to_owned(),
            expected_key,
            control_redirect: None,
            reject_direct_tcpip: false,
            reject_direct_tcpip_flag: None,
            reject_next_direct_tcpip_flag: None,
            close_direct_tcpip_after_accept_flag: None,
            disconnect_direct_tcpip_flag: None,
            sftp_root: None,
            session_channels: Default::default(),
        },
    );

    let expected_secret = "fixture-control-secret".to_owned();
    let agent = thread::spawn(move || {
        let mut stored = Vec::new();
        for _ in 0..7 {
            let (mut stream, _) = agent_listener.accept().expect("agent accept");
            let mut reader = BufReader::new(stream.try_clone().expect("clone agent stream"));
            let request: AgentRequest =
                hostlink_protocol::read_json_line(&mut reader).expect("agent request");
            drop(reader);
            assert_eq!(request.token, expected_secret);
            match request.request {
                AgentRequestKind::Hello => {
                    write_json_line(
                        stream,
                        &AgentResponse::success(AgentResponseKind::Hello {
                            name: "legacy-target".into(),
                            agent_version: "0.1.1".into(),
                            hostname: "SERVER-LEGACY".into(),
                            os: "windows".into(),
                            capabilities: vec![FILE_TRANSFER_SHA256_CAPABILITY.into()],
                            agent_executable: None,
                            onec_executable: None,
                        }),
                    )
                    .expect("hello response");
                }
                AgentRequestKind::Upload {
                    bytes,
                    overwrite: true,
                    ..
                } => {
                    assert_eq!(bytes, payload.len() as u64);
                    write_json_line(
                        &mut stream,
                        &AgentResponse::success(AgentResponseKind::UploadReady),
                    )
                    .expect("upload ready");
                    stored.resize(bytes as usize, 0);
                    stream.read_exact(&mut stored).expect("upload bytes");
                    // Simulate a committed publication whose final response is lost.
                    drop(stream);
                }
                AgentRequestKind::Upload {
                    overwrite: false, ..
                } => {
                    write_json_line(
                        stream,
                        &AgentResponse::failure("upload target already exists"),
                    )
                    .expect("overwrite refusal");
                }
                AgentRequestKind::PathSha256 { .. } => {
                    write_json_line(
                        stream,
                        &AgentResponse::success(AgentResponseKind::PathSha256 {
                            bytes: stored.len() as u64,
                            sha256: format!("{:x}", Sha256::digest(&stored)),
                        }),
                    )
                    .expect("sha256 response");
                }
                AgentRequestKind::Download { .. } => {
                    write_json_line(
                        &mut stream,
                        &AgentResponse::success(AgentResponseKind::DownloadReady {
                            bytes: stored.len() as u64,
                        }),
                    )
                    .expect("download ready");
                    stream.write_all(&stored).expect("download bytes");
                }
                other => {
                    panic!("unexpected legacy fallback request: {other:?}")
                }
            }
        }
    });

    let mut remote = fixture();
    remote.name = "legacy-target".into();
    remote.gateways[0].host = "127.0.0.1".into();
    remote.gateways[0].port = gateway_address.port();
    remote.remote_port = target_address.port();
    remote.carrier = RemoteCarrier::TargetSsh;
    remote.identity = Some(identity);
    remote.gateways[0].trust = crate::GatewayTrust::KnownHosts(gateway_known_hosts.clone());
    remote.known_hosts = Some(gateway_known_hosts);
    remote.target_user = Some("target-user".into());
    remote.target_known_hosts = Some(target_known_hosts);
    remote.target_host_key_alias = Some(target_host_key_alias.into());
    let client = RemoteAgentClient::new(remote).expect("target client");

    let uploaded = client
        .upload(&source, r"C:\Temp\legacy-fallback.bin", true)
        .await
        .expect("agent upload fallback");
    assert_eq!(uploaded, payload.len() as u64);
    let same_bytes_refusal = client
        .upload(&source, r"C:\Temp\legacy-fallback.bin", false)
        .await
        .expect_err("gateway carrier rejects existing identical bytes");
    assert!(same_bytes_refusal.to_string().contains("already exists"));
    let different_source = dir.path().join("different.bin");
    fs::write(&different_source, b"different payload").expect("different source");
    let different_bytes_refusal = client
        .upload(&different_source, r"C:\Temp\legacy-fallback.bin", false)
        .await
        .expect_err("gateway carrier rejects existing different bytes");
    assert!(
        different_bytes_refusal
            .to_string()
            .contains("already exists")
    );
    let downloaded = client
        .download(r"C:\Temp\legacy-fallback.bin", &restored, false)
        .await
        .expect("agent download fallback");
    assert_eq!(downloaded, payload.len() as u64);
    assert_eq!(fs::read(&restored).expect("restored"), payload);

    agent.join().expect("agent server");
    target_stop.store(true, std::sync::atomic::Ordering::Release);
    gateway_stop.store(true, std::sync::atomic::Ordering::Release);
    target.join().expect("target SSH server");
    gateway.join().expect("gateway SSH server");
}

#[tokio::test]
async fn non_agent_control_bytes_have_actionable_diagnostic() {
    use tokio::io::AsyncWriteExt;
    let (mut stream, mut writer) = tokio::io::duplex(64);
    let writer = tokio::spawn(async move {
        writer
            .write_all(b"SSH-2.0-wrong-listener\r\n")
            .await
            .expect("write");
    });
    let error = read_response_unbuffered(&mut stream)
        .await
        .expect_err("must reject non-agent bytes");
    writer.await.expect("writer");
    let message = error.to_string();
    assert!(message.contains("did not return onec-agent JSON"));
    assert!(message.contains("reverse-listener"));
}

#[tokio::test]
async fn async_control_framing_preserves_exact_limit_crlf_and_eof_behavior() {
    use hostlink_protocol::MAX_CONTROL_LINE_BYTES;
    use tokio::io::AsyncWriteExt;

    let response = AgentResponse::success(AgentResponseKind::TcpReady);
    let json = serde_json::to_vec(&response).expect("response JSON");
    let mut at_limit = vec![b' '; MAX_CONTROL_LINE_BYTES - json.len()];
    at_limit.extend_from_slice(&json);
    at_limit.extend_from_slice(b"\n");
    let (mut reader, mut writer) = tokio::io::duplex(MAX_CONTROL_LINE_BYTES + 16);
    writer
        .write_all(&at_limit)
        .await
        .expect("boundary response");
    drop(writer);
    assert_eq!(
        read_response_unbuffered(&mut reader)
            .await
            .expect("exact cap"),
        response
    );

    let (mut reader, mut writer) = tokio::io::duplex(256);
    writer.write_all(&json).await.expect("CRLF response");
    writer.write_all(b"\r\n").await.expect("CRLF terminator");
    drop(writer);
    assert_eq!(
        read_response_unbuffered(&mut reader)
            .await
            .expect("CRLF trimming"),
        response
    );

    let over_limit = vec![b'x'; MAX_CONTROL_LINE_BYTES + 1];
    let (mut reader, mut writer) = tokio::io::duplex(MAX_CONTROL_LINE_BYTES + 8);
    writer
        .write_all(&over_limit)
        .await
        .expect("oversized response");
    let error = read_response_unbuffered(&mut reader)
        .await
        .expect_err("cap must fail");
    assert!(error.to_string().contains("maximum control message size"));

    let (mut reader, writer) = tokio::io::duplex(8);
    drop(writer);
    let error = read_response_unbuffered(&mut reader)
        .await
        .expect_err("empty EOF must fail");
    assert!(error.to_string().contains("closed before a response"));
}

#[tokio::test]
async fn regression_inv_048_target_ssh_transport_error_keeps_agent_state_unknown() {
    let mut server = fixture();
    server.carrier = RemoteCarrier::TargetSsh;
    let client = RemoteAgentClient {
        server,
        capabilities: Default::default(),
    };
    let error = client.target_ssh_transport_error(
        "reading control response",
        crate::invalid_config("agent connection closed before a response".to_owned()),
    );
    let message = error.to_string();
    assert!(message.contains("hub-target-ssh transport"));
    assert!(message.contains("agent connection closed before a response"));
    assert!(message.contains("target onec-agent state is unknown"));
}

#[test]
fn regression_inv_794_target_ssh_upload_future_stays_below_default_stack_budget() {
    let client = RemoteAgentClient {
        server: fixture(),
        capabilities: Default::default(),
    };
    let future = client.upload_with_progress_deadline(
        "unused-source",
        "unused-destination",
        false,
        |_, _| {},
        std::time::Duration::from_secs(180),
    );

    assert!(
        std::mem::size_of_val(&future) <= 8 * 1024,
        "upload future should keep its large SFTP state heap-backed"
    );
}

#[tokio::test]
async fn transfer_copy_is_exact_and_reports_real_byte_total() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let payload = vec![3_u8; 150_001];
    let (mut input, mut input_writer) = tokio::io::duplex(200_000);
    input_writer
        .write_all(&payload)
        .await
        .expect("input payload");
    let (mut output_reader, mut output_writer) = tokio::io::duplex(200_000);
    let mut samples = Vec::new();
    let copied = copy_exact_with_progress(
        &mut input,
        &mut output_writer,
        150_000,
        &mut |position, total| samples.push((position, total)),
    )
    .await
    .expect("copy");
    assert_eq!(copied, 150_000);
    let mut output = vec![0; copied as usize];
    output_reader
        .read_exact(&mut output)
        .await
        .expect("output payload");
    assert_eq!(output, payload[..150_000]);
    assert_eq!(samples.last(), Some(&(150_000, 150_000)));
    assert!(samples.windows(2).all(|pair| pair[0].0 <= pair[1].0));

    let (mut short, mut short_writer) = tokio::io::duplex(64);
    short_writer
        .write_all(&[5_u8; 31])
        .await
        .expect("short bytes");
    short_writer.shutdown().await.expect("short EOF");
    let (mut sink, _sink_reader) = tokio::io::duplex(64);
    let error = copy_exact_with_progress(&mut short, &mut sink, 32, &mut |_, _| {})
        .await
        .expect_err("short transfer must fail");
    assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
}
