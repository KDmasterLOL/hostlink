//! Typed loopback control protocol server and 1C discovery projection.
//!
//! This module owns request authentication/dispatch and wire responses. Filesystem/network/job
//! primitives remain in their dedicated owners and are invoked here without changing protocol semantics.

use super::*;
use crate::environment::AgentEnvironmentPolicy;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::time::Instant;

mod filesystem;
mod network;
mod result_transfer;
mod runtime;

const MAX_CONTROL_CONNECTIONS: usize = 32;
const CONTROL_REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

struct ConnectionPermit {
    active: Arc<AtomicUsize>,
}

impl ConnectionPermit {
    fn try_acquire(active: &Arc<AtomicUsize>, limit: usize) -> Option<Self> {
        let mut current = active.load(Ordering::Acquire);
        loop {
            if current >= limit {
                return None;
            }
            match active.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(observed) => current = observed,
            }
        }
        Some(Self {
            active: Arc::clone(active),
        })
    }
}

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::AcqRel);
    }
}

#[derive(Debug, Clone)]
/// Resolved control-server runtime state.
pub struct AgentRuntime {
    /// Logical agent name returned by `Hello`.
    pub name: String,
    /// Resolved control authentication secret.
    pub secret: SecretString,
    /// Durable job state/log root.
    pub jobs_dir: PathBuf,
    /// Independently administered digest pin for one approved native suite policy.
    pub native_suite_policy_sha256: Option<String>,
}

/// Serves the authenticated loopback control protocol until listener failure/process shutdown.
///
/// # Errors
///
/// Returns [`std::io::Error`] when runtime secret/jobs resolution or listener setup/accept fails.
pub fn serve(config: &AgentConfig) -> io::Result<()> {
    let runtime = config.runtime()?;
    jobs::recover_stale_jobs(&runtime.jobs_dir)?;
    let environment = AgentEnvironmentPolicy::new(config.secret_env());
    let listener = TcpListener::bind(config.listen())?;
    let async_runtime = control_runtime()?;
    serve_listener(
        listener,
        runtime,
        environment,
        async_runtime.handle().clone(),
    )
}

pub(super) fn serve_listener(
    listener: TcpListener,
    runtime: AgentRuntime,
    environment: AgentEnvironmentPolicy,
    async_handle: tokio::runtime::Handle,
) -> io::Result<()> {
    let mut next_result_gc = Instant::now();
    let active = Arc::new(AtomicUsize::new(0));
    for connection in listener.incoming() {
        if Instant::now() >= next_result_gc {
            crate::results::gc_expired_exec_result_sets(
                &runtime.jobs_dir,
                std::time::SystemTime::now(),
            )?;
            next_result_gc = Instant::now() + Duration::from_secs(60 * 60);
        }
        let stream = connection?;
        let Some(permit) = ConnectionPermit::try_acquire(&active, MAX_CONTROL_CONNECTIONS) else {
            drop(stream);
            continue;
        };
        let runtime = runtime.clone();
        let environment = environment.clone();
        let async_handle = async_handle.clone();
        thread::Builder::new()
            .name("onec-agent-control".to_owned())
            .spawn(move || {
                let _permit = permit;
                let _ = handle_connection_with_environment(
                    stream,
                    &runtime,
                    &environment,
                    &async_handle,
                );
            })?;
    }
    Ok(())
}

/// Handles one already-accepted control connection using the default sanitized child environment.
///
/// Protocol version and control token are checked before dispatch.
/// Calls from an existing Tokio execution context are synchronously dispatched on a scoped OS
/// thread, while Immediate Exec continues to use the shared control runtime.
///
/// # Errors
///
/// Returns [`std::io::Error`] for framing, timeout, transport, dispatched-operation I/O failure,
/// or if the scoped dispatch thread panics.
pub fn handle_connection(stream: TcpStream, runtime: &AgentRuntime) -> io::Result<()> {
    let environment = AgentEnvironmentPolicy::default();
    let async_handle = control_runtime()?.handle().clone();
    let dispatch =
        || handle_connection_with_environment(stream, runtime, &environment, &async_handle);
    if tokio::runtime::Handle::try_current().is_ok() {
        return std::thread::scope(|scope| {
            scope
                .spawn(dispatch)
                .join()
                .map_err(|_| io::Error::other("control connection handler thread panicked"))?
        });
    }
    dispatch()
}

fn handle_connection_with_environment(
    mut stream: TcpStream,
    runtime: &AgentRuntime,
    environment: &AgentEnvironmentPolicy,
    async_handle: &tokio::runtime::Handle,
) -> io::Result<()> {
    let request = match read_initial_request(&mut stream, runtime, CONTROL_REQUEST_TIMEOUT)? {
        Ok(request) => request,
        Err(response) => {
            write_json_line(&mut stream, &response)?;
            return Ok(());
        }
    };
    if request.version != PROTOCOL_VERSION {
        write_json_line(
            &mut stream,
            &AgentResponse::failure(format!(
                "unsupported protocol version {}, expected {}",
                request.version, PROTOCOL_VERSION
            )),
        )?;
        return Ok(());
    }
    if !constant_time_str_eq(&request.token, runtime.secret.expose_secret()) {
        write_json_line(
            &mut stream,
            &AgentResponse::failure("authentication failed"),
        )?;
        return Ok(());
    }

    match request.request {
        request @ (AgentRequestKind::Hello
        | AgentRequestKind::Exec { .. }
        | AgentRequestKind::RunLocalPrepare { .. }
        | AgentRequestKind::RunLocalStatus { .. }
        | AgentRequestKind::JobStart { .. }
        | AgentRequestKind::NativeRunLocalJobStart { .. }
        | AgentRequestKind::JobStatus { .. }
        | AgentRequestKind::JobLogs { .. }
        | AgentRequestKind::JobCancel { .. }
        | AgentRequestKind::RunLocalFinalize { .. }
        | AgentRequestKind::RunLocalAbandon { .. }
        | AgentRequestKind::RunLocalAttest { .. }
        | AgentRequestKind::RunLocalAttestationFetch { .. }
        | AgentRequestKind::RunLocalInvocationObserve { .. }
        | AgentRequestKind::RunLocalInvocationObservationFetch { .. }
        | AgentRequestKind::NativeAttestationPublicKey) => {
            runtime::handle(stream, runtime, environment, async_handle, request)
        }
        request @ AgentRequestKind::TcpConnect { .. } => {
            network::handle(stream, request, async_handle)
        }
        request @ (AgentRequestKind::ResultDownload { .. }
        | AgentRequestKind::ResultCleanup { .. }) => {
            result_transfer::handle(stream, &runtime.jobs_dir, request)
        }
        request @ (AgentRequestKind::Upload { .. }
        | AgentRequestKind::Download { .. }
        | AgentRequestKind::PathSha256 { .. }
        | AgentRequestKind::PathRemoveScoped { .. }
        | AgentRequestKind::PathRename { .. }) => filesystem::handle(stream, request),
    }
}

fn control_runtime() -> io::Result<&'static tokio::runtime::Runtime> {
    static RUNTIME: std::sync::OnceLock<Result<tokio::runtime::Runtime, String>> =
        std::sync::OnceLock::new();
    match RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|error| error.to_string())
    }) {
        Ok(runtime) => Ok(runtime),
        Err(error) => Err(io::Error::other(error.clone())),
    }
}

fn read_initial_request(
    stream: &mut TcpStream,
    runtime: &AgentRuntime,
    timeout: Duration,
) -> io::Result<Result<AgentRequest, AgentResponse>> {
    stream.set_read_timeout(Some(timeout))?;
    // Decode JSON syntax/framing first. A syntax or framing error remains a protocol-level
    // connection failure; a valid Exec request with invalid result declarations gets the stable
    // application response that the dispatch path historically returned.
    let mut reader = BufReader::new(stream.try_clone()?);
    let line =
        onec_core::read_line_bounded(&mut reader, onec_agent_protocol::MAX_CONTROL_LINE_BYTES)?
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "input closed before a JSON line",
                )
            })?;
    let request = decode_initial_request(&line, runtime);
    stream.set_read_timeout(None)?;
    request
}

fn decode_initial_request(
    line: &[u8],
    runtime: &AgentRuntime,
) -> io::Result<Result<AgentRequest, AgentResponse>> {
    match onec_agent_protocol::decode_agent_request(line)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?
    {
        Ok(request) => Ok(Ok(request)),
        Err(error) => {
            // Preserve the established envelope response ordering: version and authentication
            // are checked before operation-specific validation details are returned.
            if error.version() != PROTOCOL_VERSION {
                return Ok(Err(AgentResponse::failure(format!(
                    "unsupported protocol version {}, expected {}",
                    error.version(),
                    PROTOCOL_VERSION
                ))));
            }
            if !error.matches_token(runtime.secret.expose_secret()) {
                return Ok(Err(AgentResponse::failure("authentication failed")));
            }
            let detail = error.message();
            let response = match error.kind() {
                onec_agent_protocol::AgentRequestValidationKind::ExecResults => {
                    AgentResponse::failure_with_code(
                        AgentErrorCode::ExecResultInvalid,
                        format!("exec result declaration is invalid: {detail}"),
                    )
                }
                onec_agent_protocol::AgentRequestValidationKind::JobStartResults => {
                    AgentResponse::failure(format!("failed to start job: {detail}"))
                }
                onec_agent_protocol::AgentRequestValidationKind::JobStartRunLocalIdentity => {
                    AgentResponse::failure(format!("failed to start job: {detail}"))
                }
                onec_agent_protocol::AgentRequestValidationKind::NativeInvocationObservation => {
                    AgentResponse::failure(format!(
                        "native invocation observation unavailable: {detail}"
                    ))
                }
                onec_agent_protocol::AgentRequestValidationKind::ResultDownloadOwner => {
                    AgentResponse::failure_with_code(
                        AgentErrorCode::ResultDownloadFailed,
                        "managed result is unavailable or invalid",
                    )
                }
                onec_agent_protocol::AgentRequestValidationKind::ResultCleanupOwner => {
                    AgentResponse::failure_with_code(
                        AgentErrorCode::ResultCleanupFailed,
                        "managed result set could not be safely removed",
                    )
                }
            };
            Ok(Err(response))
        }
    }
}

#[cfg(test)]
mod connection_tests {
    use super::*;

    #[test]
    fn valid_json_invalid_exec_results_keep_typed_code_and_bad_json_stays_protocol_error() {
        let runtime = AgentRuntime {
            name: "fixture".into(),
            secret: "fixture-secret".into(),
            jobs_dir: std::env::temp_dir(),
            native_suite_policy_sha256: None,
        };
        let malformed_result = br#"{"version":1,"token":"fixture-secret","request":{"type":"exec","program":"unused","results":[{"name":"report.bin","max_bytes":1},{"name":"REPORT.BIN","max_bytes":1}]}}"#;
        let response = decode_initial_request(malformed_result, &runtime)
            .expect("valid JSON has an application result")
            .expect_err("invalid Exec result declaration must be rejected");
        assert_eq!(response.error_code, Some(AgentErrorCode::ExecResultInvalid));
        let Err(validation) = onec_agent_protocol::decode_agent_request(malformed_result)
            .expect("valid JSON has typed semantic failure")
        else {
            panic!("invalid result declaration unexpectedly decoded");
        };
        assert!(
            !format!("{validation:?}").contains("fixture-secret"),
            "semantic decode diagnostics must redact the request token"
        );

        let error = decode_initial_request(b"{invalid json", &runtime)
            .expect_err("malformed JSON stays a protocol-level decode failure");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);

        let duplicate_request = br#"{"version":1,"token":"fixture-secret","request":{"type":"hello"},"request":{"type":"exec","program":"unused","results":[{"name":"bad/relative","max_bytes":1}]}}"#;
        let error = decode_initial_request(duplicate_request, &runtime)
            .expect_err("duplicate request fields must not be disguised as invalid results");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);

        let unrelated_invalid_field = br#"{"version":1,"token":"fixture-secret","request":{"type":"exec","program":"unused","timeout_ms":"not-an-integer","results":[{"name":"bad/relative","max_bytes":1}]}}"#;
        let error = decode_initial_request(unrelated_invalid_field, &runtime)
            .expect_err("an unrelated invalid Exec field cannot become a result-only error");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);

        let marker_in_unrelated_field = br#"{"version":1,"token":"fixture-secret","request":{"type":"exec","program":"unused","timeout_ms":"onec-agent-result-validation: not a result error","results":[{"name":"valid.bin","max_bytes":1}]}}"#;
        let error = decode_initial_request(marker_in_unrelated_field, &runtime)
            .expect_err("user text cannot spoof the internal validation discriminator");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);

        let malformed_job_results = br#"{"version":1,"token":"fixture-secret","request":{"type":"job_start","program":"unused","results":[{"name":"bad/relative","max_bytes":1}]}}"#;
        let response = decode_initial_request(malformed_job_results, &runtime)
            .expect("valid JobStart envelope has application result")
            .expect_err("invalid JobStart result declarations must be rejected");
        assert_eq!(response.error_code, None);
        assert!(
            response
                .error
                .as_deref()
                .is_some_and(|error| { error.starts_with("failed to start job: ") })
        );

        let malformed_download_owner = br#"{"version":1,"token":"fixture-secret","request":{"type":"result_download","owner":{"kind":"exec","result_set_id":""},"name":"report.bin"}}"#;
        let response = decode_initial_request(malformed_download_owner, &runtime)
            .expect("valid result download envelope has application result")
            .expect_err("invalid result owner must be rejected");
        assert_eq!(
            response.error_code,
            Some(AgentErrorCode::ResultDownloadFailed)
        );

        let malformed_cleanup_owner = br#"{"version":1,"token":"fixture-secret","request":{"type":"result_cleanup","owner":{"kind":"job","job_id":"../outside"}}}"#;
        let response = decode_initial_request(malformed_cleanup_owner, &runtime)
            .expect("valid result cleanup envelope has application result")
            .expect_err("invalid cleanup owner must be rejected");
        assert_eq!(
            response.error_code,
            Some(AgentErrorCode::ResultCleanupFailed)
        );

        let unauthenticated_result = br#"{"version":1,"token":"wrong","request":{"type":"exec","program":"unused","results":[{"name":"bad/relative","max_bytes":1}]}}"#;
        let response = decode_initial_request(unauthenticated_result, &runtime)
            .expect("syntactically valid envelope has an application response")
            .expect_err("unauthenticated request is rejected");
        assert_eq!(response.error_code, None);
        assert_eq!(response.error.as_deref(), Some("authentication failed"));

        let unsupported_result = br#"{"version":2,"token":"fixture-secret","request":{"type":"exec","program":"unused","results":[{"name":"bad/relative","max_bytes":1}]}}"#;
        let response = decode_initial_request(unsupported_result, &runtime)
            .expect("syntactically valid envelope has an application response")
            .expect_err("unsupported version is rejected");
        assert_eq!(response.error_code, None);
        assert_eq!(
            response.error.as_deref(),
            Some("unsupported protocol version 2, expected 1")
        );
    }

    #[test]
    fn control_connection_permits_are_bounded_and_released() {
        let active = Arc::new(AtomicUsize::new(0));
        let permits = (0..MAX_CONTROL_CONNECTIONS)
            .map(|_| {
                ConnectionPermit::try_acquire(&active, MAX_CONTROL_CONNECTIONS)
                    .expect("connection slot")
            })
            .collect::<Vec<_>>();
        assert!(
            ConnectionPermit::try_acquire(&active, MAX_CONTROL_CONNECTIONS).is_none(),
            "connection limit must fail closed"
        );
        drop(permits);
        assert!(
            ConnectionPermit::try_acquire(&active, MAX_CONTROL_CONNECTIONS).is_some(),
            "dropping a handler must release its slot"
        );
    }

    #[test]
    fn initial_request_timeout_is_bounded_and_cleared_after_parse() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
        let address = listener.local_addr().expect("address");
        let mut client = TcpStream::connect(address).expect("connect");
        let (mut server, _) = listener.accept().expect("accept");
        write_json_line(
            &mut client,
            &AgentRequest::new("fixture-secret", AgentRequestKind::Hello),
        )
        .expect("request");

        let request = read_initial_request(
            &mut server,
            &AgentRuntime {
                name: "fixture".into(),
                secret: "fixture-secret".into(),
                jobs_dir: std::env::temp_dir(),
                native_suite_policy_sha256: None,
            },
            Duration::from_millis(50),
        )
        .expect("read request")
        .expect("decoded request");
        assert!(matches!(request.request, AgentRequestKind::Hello));
        assert_eq!(
            server.read_timeout().expect("read timeout"),
            None,
            "authenticated operation lifetime must not inherit the handshake timeout"
        );

        let idle_listener = TcpListener::bind("127.0.0.1:0").expect("idle listener");
        let idle_address = idle_listener.local_addr().expect("idle address");
        let _idle_client = TcpStream::connect(idle_address).expect("idle connect");
        let (mut idle_server, _) = idle_listener.accept().expect("idle accept");
        let error = read_initial_request(
            &mut idle_server,
            &AgentRuntime {
                name: "fixture".into(),
                secret: "fixture-secret".into(),
                jobs_dir: std::env::temp_dir(),
                native_suite_policy_sha256: None,
            },
            Duration::from_millis(20),
        )
        .expect_err("idle initial request must time out");
        assert!(
            matches!(
                error.kind(),
                io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
            ),
            "unexpected timeout error: {error}"
        );
    }
}
