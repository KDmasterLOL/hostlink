//! Wire compatibility, legacy-default, and framing regression tests.

use super::*;
use std::collections::BTreeMap;
use std::io::{self, BufReader};

#[test]
fn immediate_exec_timeout_defaults_and_emergency_ceiling_are_distinct() {
    assert_eq!(DEFAULT_EXEC_TIMEOUT_MS, 60_000);
    assert_eq!(MAX_EXEC_TIMEOUT_MS, 10 * 60 * 1000);
}

#[test]
fn regression_inv_069_secret_environment_debug_redacts_values() {
    let mut values = BTreeMap::new();
    values.insert("ONEC_SECRET".to_owned(), "must-not-leak".to_owned());
    let secrets = SecretEnvironment::new(values);
    let debug = format!("{secrets:?}");
    assert!(debug.contains("ONEC_SECRET"));
    assert!(debug.contains("redacted_values"));
    assert!(!debug.contains("must-not-leak"));
}

#[test]
fn agent_request_debug_redacts_control_secret_and_untrusted_nested_payload() {
    let control_secret = "control-token-do-not-log";
    let argument_secret = "opaque-argument-do-not-log";
    let overlay_secret = "unexpected-env-do-not-log";
    let mut env = BTreeMap::new();
    env.insert(
        "CREDENTIAL_IN_WRONG_FIELD".to_owned(),
        overlay_secret.to_owned(),
    );
    let request = AgentRequest::new(
        control_secret,
        AgentRequestKind::Exec {
            program: "tool".into(),
            args: vec![argument_secret.into()],
            cwd: None,
            env,
            secret_env: SecretEnvironment::default(),
            stdin: None,
            result_set_id: None,
            results: Vec::new(),
            timeout_ms: DEFAULT_EXEC_TIMEOUT_MS,
            raw_output: false,
        },
    );

    let debug = format!("{request:?}");
    assert!(debug.contains("AgentRequest"));
    assert!(debug.contains(&format!("version: {}", PROTOCOL_VERSION)));
    assert!(debug.contains("[REDACTED]"));
    for secret in [control_secret, argument_secret, overlay_secret] {
        assert!(!debug.contains(secret), "Debug must not expose {secret:?}");
    }

    let json = serde_json::to_string(&request).expect("wire unchanged");
    assert!(
        json.contains(control_secret),
        "control secret is still sent on wire"
    );
    assert!(
        json.contains(argument_secret),
        "opaque argument is still sent on wire"
    );
    let decoded: AgentRequest = serde_json::from_str(&json).expect("compatible wire decoding");
    assert_eq!(decoded, request);
}

#[test]
fn request_round_trip_is_stable() {
    let request = AgentRequest::new(
        "secret",
        AgentRequestKind::Exec {
            program: "cmd.exe".into(),
            args: vec!["/c".into(), "whoami".into()],
            cwd: None,
            env: BTreeMap::new(),
            secret_env: SecretEnvironment::default(),
            stdin: None,
            result_set_id: None,
            results: Vec::new(),
            timeout_ms: DEFAULT_EXEC_TIMEOUT_MS,
            raw_output: false,
        },
    );
    let mut bytes = Vec::new();
    write_json_line(&mut bytes, &request).expect("write");
    let decoded: AgentRequest = read_json_line(BufReader::new(bytes.as_slice())).expect("read");
    assert_eq!(decoded, request);
}

#[test]
fn run_local_attestation_fetch_is_a_typed_authenticated_request() {
    let request = AgentRequest::new(
        "control-secret",
        AgentRequestKind::RunLocalAttestationFetch {
            job_id: "job-10-20-1".to_owned(),
            challenge: "fresh-challenge".to_owned(),
        },
    );
    let encoded = serde_json::to_vec(&request).expect("encode fetch request");
    let decoded = decode_agent_request(&encoded)
        .expect("decode request")
        .expect("valid request");
    assert_eq!(decoded, request);
    assert!(
        String::from_utf8(encoded)
            .expect("json")
            .contains("run_local_attestation_fetch")
    );

    let response = AgentResponse::success(AgentResponseKind::NativeExecutionAttestationFetched {
        record: AgentTerminalExecutionRecord {
            schema_version: 1,
            challenge: "fresh-challenge".to_owned(),
            job_id: "job-10-20-1".to_owned(),
            run_id: "0123456789abcdef0123456789abcdef".to_owned(),
            candidate_sha256: "ab".repeat(32),
            command_completion: "succeeded".to_owned(),
            command_exit_code: 0,
            cleanup_completion: "complete".to_owned(),
            signer_id: "cd".repeat(32),
        },
        signature_hex: "ef".repeat(64),
    });
    let bytes = serde_json::to_vec(&response).expect("encode fetched response");
    assert_eq!(
        serde_json::from_slice::<AgentResponse>(&bytes).expect("decode response"),
        response
    );
}

#[test]
fn process_terminal_attestation_rejects_suite_outcome_claims() {
    let record = serde_json::json!({
        "schema_version": 1,
        "challenge": "fresh-challenge",
        "job_id": "job-10-20-1",
        "run_id": "0123456789abcdef0123456789abcdef",
        "candidate_sha256": "ab".repeat(32),
        "command_completion": "succeeded",
        "command_exit_code": 0,
        "cleanup_completion": "complete",
        "signer_id": "cd".repeat(32)
    });
    for (field, claim) in [
        ("selected_tests", serde_json::json!(["case"])),
        ("executed_tests", serde_json::json!(["case"])),
        ("terminal_statuses", serde_json::json!({"case": "passed"})),
        ("filtered_tests", serde_json::json!(0)),
        ("ignored_tests", serde_json::json!(0)),
        ("retry_count", serde_json::json!(0)),
        ("runner_signature", serde_json::json!("forged")),
    ] {
        let mut forged = record.clone();
        forged[field] = claim;
        assert!(
            serde_json::from_value::<AgentTerminalExecutionRecord>(forged).is_err(),
            "process terminal attestation must reject caller-authored {field} claims"
        );
    }
}

#[test]
fn stdin_payload_round_trip_preserves_exact_binary_bytes_without_debug_leak() {
    let payload =
        StdinPayload::try_new(vec![0, 0xff, b'\n', b'\r', b'A']).expect("bounded payload");
    let debug = format!("{payload:?}");
    assert!(debug.contains("bytes"));
    assert!(debug.contains('5'));
    assert!(!debug.contains("255"));

    let request = AgentRequest::new(
        "secret",
        AgentRequestKind::Exec {
            program: "tool.exe".into(),
            args: Vec::new(),
            cwd: None,
            env: BTreeMap::new(),
            secret_env: SecretEnvironment::default(),
            stdin: Some(payload.clone()),
            result_set_id: None,
            results: Vec::new(),
            timeout_ms: DEFAULT_EXEC_TIMEOUT_MS,
            raw_output: false,
        },
    );
    let mut bytes = Vec::new();
    write_json_line(&mut bytes, &request).expect("write");
    let decoded: AgentRequest = read_json_line(BufReader::new(bytes.as_slice())).expect("read");
    assert_eq!(decoded, request);
    let AgentRequestKind::Exec { stdin, .. } = decoded.request else {
        panic!("expected exec");
    };
    assert_eq!(stdin.expect("stdin").as_bytes(), payload.as_bytes());
}

#[test]
fn stdin_payload_distinguishes_absent_from_explicit_empty() {
    let absent = br#"{"version":1,"token":"secret","request":{"type":"exec","program":"tool.exe","args":[]}}"#;
    let decoded: AgentRequest =
        read_json_line(BufReader::new(absent.as_slice())).expect("absent stdin");
    let AgentRequestKind::Exec { stdin, .. } = decoded.request else {
        panic!("expected exec");
    };
    assert_eq!(stdin, None);

    let empty = AgentRequest::new(
        "secret",
        AgentRequestKind::JobStart {
            program: "tool.exe".into(),
            args: Vec::new(),
            cwd: None,
            env: BTreeMap::new(),
            secret_env: SecretEnvironment::default(),
            stdin: Some(StdinPayload::try_new(Vec::new()).expect("empty payload")),
            results: Vec::new(),
            run_local: None,
        },
    );
    let mut bytes = Vec::new();
    write_json_line(&mut bytes, &empty).expect("write empty");
    let text = String::from_utf8(bytes.clone()).expect("json");
    assert!(text.contains(r#""stdin":"""#), "{text}");
    let decoded: AgentRequest =
        read_json_line(BufReader::new(bytes.as_slice())).expect("read empty");
    let AgentRequestKind::JobStart { stdin, .. } = decoded.request else {
        panic!("expected job start");
    };
    assert!(stdin.expect("explicit empty").is_empty());
}

#[test]
fn stdin_payload_rejects_raw_and_wire_values_above_protocol_bound() {
    let error = StdinPayload::try_new(vec![0; MAX_STDIN_PAYLOAD_BYTES + 1])
        .expect_err("oversized raw payload");
    assert_eq!(error.actual_bytes(), MAX_STDIN_PAYLOAD_BYTES + 1);
    assert_eq!(error.max_bytes(), MAX_STDIN_PAYLOAD_BYTES);

    let encoded = "A".repeat((MAX_STDIN_PAYLOAD_BYTES.div_ceil(3) * 4) + 1);
    let raw = format!(
        "{{\"version\":1,\"token\":\"secret\",\"request\":{{\"type\":\"exec\",\"program\":\"tool.exe\",\"stdin\":\"{encoded}\"}}}}\n"
    );
    let error = read_json_line::<AgentRequest>(BufReader::new(raw.as_bytes()))
        .expect_err("oversized encoded payload");
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert!(
        error
            .to_string()
            .contains("stdin base64 payload exceeds encoded maximum")
    );
}

#[test]
fn regression_inv_071_scoped_remove_round_trip_preserves_literal_paths() {
    let request = AgentRequest::new(
        "secret",
        AgentRequestKind::PathRemoveScoped {
            root: r#"C:\Temp\onec-toolkit"#.into(),
            path: r#"C:\Temp\onec-toolkit\Каталог 'quoted' \"double\""#.into(),
            recursive: true,
            missing_ok: false,
        },
    );
    let mut bytes = Vec::new();
    write_json_line(&mut bytes, &request).expect("write");
    let decoded: AgentRequest = read_json_line(BufReader::new(bytes.as_slice())).expect("read");
    assert_eq!(decoded, request);
}

#[test]
fn legacy_exec_defaults_environment_and_unicode_round_trip_is_lossless() {
    let legacy = r#"{"version":1,"token":"secret","request":{"type":"exec","program":"tool.exe","args":["Путь"],"cwd":"Каталог Тест"}}
"#;
    let decoded: AgentRequest =
        read_json_line(BufReader::new(legacy.as_bytes())).expect("legacy read");
    let AgentRequestKind::Exec {
        args,
        cwd,
        env,
        timeout_ms,
        ..
    } = decoded.request
    else {
        panic!("expected exec");
    };
    assert_eq!(args, vec!["Путь"]);
    assert_eq!(cwd.as_deref(), Some("Каталог Тест"));
    assert!(env.is_empty());
    assert_eq!(timeout_ms, DEFAULT_EXEC_TIMEOUT_MS);

    let mut environment = BTreeMap::new();
    environment.insert("ONEC_LABEL".to_owned(), "Набор Юникод".to_owned());
    let request = AgentRequest::new(
        "secret",
        AgentRequestKind::JobStart {
            program: "onec.exe".into(),
            args: vec!["--suite".into(), "Проверка Обмена".into()],
            cwd: Some(r"C:РаботаПроект".into()),
            env: environment,
            secret_env: SecretEnvironment::default(),
            stdin: None,
            results: Vec::new(),
            run_local: None,
        },
    );
    let mut bytes = Vec::new();
    write_json_line(&mut bytes, &request).expect("write unicode");
    let round_trip: AgentRequest =
        read_json_line(BufReader::new(bytes.as_slice())).expect("read unicode");
    assert_eq!(round_trip, request);
}

#[test]
fn legacy_path_rename_defaults_to_no_overwrite() {
    let legacy = br#"{"version":1,"token":"secret","request":{"type":"path_rename","from":"C:\\Temp\\stage.tmp","to":"C:\\Temp\\artifact.bin"}}
"#;
    let decoded: AgentRequest =
        read_json_line(BufReader::new(legacy.as_slice())).expect("legacy path rename");
    assert_eq!(
        decoded.request,
        AgentRequestKind::PathRename {
            from: r"C:\Temp\stage.tmp".into(),
            to: r"C:\Temp\artifact.bin".into(),
            overwrite: false,
        }
    );
}

#[test]
fn job_logs_request_uses_bounded_default_tail() {
    let raw = br#"{"version":1,"token":"secret","request":{"type":"job_logs","job_id":"job-1"}}
"#;
    let decoded: AgentRequest = read_json_line(BufReader::new(raw.as_slice())).expect("read");
    assert_eq!(
        decoded.request,
        AgentRequestKind::JobLogs {
            job_id: "job-1".into(),
            tail_bytes: 64 * 1024,
        }
    );
    assert!(AgentJobState::Succeeded.is_terminal());
    assert!(!AgentJobState::Running.is_terminal());
}

#[test]
fn rejects_oversized_control_line() {
    let bytes = vec![b'x'; MAX_CONTROL_LINE_BYTES + 1];
    let error = read_json_line::<AgentRequest>(BufReader::new(bytes.as_slice()))
        .expect_err("oversized line");
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
}

#[test]
fn legacy_failure_response_defaults_error_code_and_typed_code_round_trips() {
    let legacy = br#"{"version":1,"ok":false,"error":"failed"}"#;
    let decoded: AgentResponse =
        read_json_line(BufReader::new(legacy.as_slice())).expect("legacy failure");
    assert_eq!(decoded.error_code, None);

    let response = AgentResponse::failure_with_code(AgentErrorCode::ExecTimeout, "timed out");
    let mut bytes = Vec::new();
    write_json_line(&mut bytes, &response).expect("write typed failure");
    let decoded: AgentResponse =
        read_json_line(BufReader::new(bytes.as_slice())).expect("read typed failure");
    assert_eq!(decoded.error_code, Some(AgentErrorCode::ExecTimeout));
}

#[test]
fn agent_error_code_spellings_remain_wire_compatible() {
    for (code, expected) in [
        (AgentErrorCode::ExecInvalidTimeout, "exec_invalid_timeout"),
        (AgentErrorCode::ExecStartFailed, "exec_start_failed"),
        (AgentErrorCode::ExecIoFailed, "exec_io_failed"),
        (AgentErrorCode::ExecTimeout, "exec_timeout"),
        (AgentErrorCode::ExecOutputLimit, "exec_output_limit"),
        (AgentErrorCode::ExecResultInvalid, "exec_result_invalid"),
        (
            AgentErrorCode::ResultDownloadFailed,
            "result_download_failed",
        ),
        (AgentErrorCode::ResultCleanupFailed, "result_cleanup_failed"),
        (AgentErrorCode::PathNotFound, "path_not_found"),
    ] {
        assert_eq!(code.as_str(), expected);
        assert_eq!(code.to_string(), expected);
        assert_eq!(
            serde_json::to_string(&code).expect("serialize code"),
            format!("\"{expected}\"")
        );
    }
}

#[test]
fn legacy_job_responses_default_new_storage_truncation_fields() {
    let legacy_status = br#"{"version":1,"ok":true,"response":{"type":"job_status","job":{"job_id":"job-1","state":"succeeded","created_unix_ms":1}}}"#;
    let decoded: AgentResponse =
        read_json_line(BufReader::new(legacy_status.as_slice())).expect("legacy job status");
    let Some(AgentResponseKind::JobStatus { job }) = decoded.response else {
        panic!("expected job status");
    };
    assert!(!job.stdout_log_truncated);
    assert!(!job.stderr_log_truncated);
    assert!(job.result_set.is_none());

    let legacy_logs = br#"{"version":1,"ok":true,"response":{"type":"job_logs","job_id":"job-1","stdout":"ok","stderr":"","stdout_truncated":false,"stderr_truncated":false}}"#;
    let decoded: AgentResponse =
        read_json_line(BufReader::new(legacy_logs.as_slice())).expect("legacy job logs");
    let Some(AgentResponseKind::JobLogs {
        stdout_storage_truncated,
        stderr_storage_truncated,
        ..
    }) = decoded.response
    else {
        panic!("expected job logs");
    };
    assert!(!stdout_storage_truncated);
    assert!(!stderr_storage_truncated);
}

#[test]
fn result_specs_are_portable_bounded_and_case_collision_safe() {
    let specs = vec![
        ResultArtifactSpec {
            name: "report.json".into(),
            max_bytes: 16 * 1024 * 1024,
            media_type: Some("application/json".into()),
        },
        ResultArtifactSpec {
            name: "evidence.bin".into(),
            max_bytes: 1,
            media_type: Some("application/octet-stream".into()),
        },
    ];
    validate_result_specs(&specs).expect("valid result specs");
    for bad in [
        "",
        ".",
        "..",
        "../escape",
        "dir/file",
        r"dir\file",
        "отчет.json",
        "NUL",
        "nul.txt",
        "COM1.log",
        "lpt9",
        "CONIN$.txt",
        "report.",
    ] {
        assert!(validate_result_name(bad).is_err(), "{bad:?}");
    }
    for allowed in [
        ".hidden".to_owned(),
        "_private".to_owned(),
        "-draft".to_owned(),
        "a..b".to_owned(),
        "a".repeat(128),
    ] {
        validate_result_name(&allowed).expect("portable filename");
    }
    assert!(validate_result_name(&"a".repeat(MAX_RESULT_NAME_BYTES + 1)).is_err());
    for bad_id in ["NUL", "con", "COM1", "lpt9"] {
        assert!(validate_result_set_id(bad_id).is_err(), "{bad_id:?}");
    }
    assert!(
        validate_result_specs(&[
            ResultArtifactSpec {
                name: "Report.json".into(),
                max_bytes: 1,
                media_type: None,
            },
            ResultArtifactSpec {
                name: "report.json".into(),
                max_bytes: 1,
                media_type: None,
            },
        ])
        .is_err()
    );
    assert!(
        ResultArtifactSpec {
            name: "report.json".into(),
            max_bytes: 0,
            media_type: None,
        }
        .validate()
        .is_err()
    );
    assert!(
        ResultArtifactSpec {
            name: "report.json".into(),
            max_bytes: MAX_RESULT_ARTIFACT_BYTES + 1,
            media_type: None,
        }
        .validate()
        .is_err()
    );
    ResultArtifactSpec {
        name: "report.json".into(),
        max_bytes: MAX_RESULT_ARTIFACT_BYTES,
        media_type: None,
    }
    .validate()
    .expect("maximum artifact size is allowed");
    assert!(
        ResultArtifactSpec {
            name: "report.json".into(),
            max_bytes: 1,
            media_type: Some("not a mime".into()),
        }
        .validate()
        .is_err()
    );
    assert!(
        ResultArtifactSpec {
            name: "report.json".into(),
            max_bytes: 1,
            media_type: Some("a".repeat(MAX_RESULT_MEDIA_TYPE_BYTES + 1)),
        }
        .validate()
        .is_err()
    );
    assert!(
        ResultArtifactSpec {
            name: "report.json".into(),
            max_bytes: 1,
            media_type: Some("application/json".into()),
        }
        .validate()
        .is_ok()
    );

    let too_many = (0..=MAX_RESULT_ARTIFACTS)
        .map(|index| ResultArtifactSpec {
            name: format!("item-{index}"),
            max_bytes: 1,
            media_type: None,
        })
        .collect::<Vec<_>>();
    assert!(validate_result_specs(&too_many).is_err());
    let max_count = (0..MAX_RESULT_ARTIFACTS)
        .map(|index| ResultArtifactSpec {
            name: format!("item-{index}"),
            max_bytes: 1,
            media_type: None,
        })
        .collect::<Vec<_>>();
    validate_result_specs(&max_count).expect("maximum declaration count is allowed");
}

#[test]
fn result_specs_enforce_aggregate_set_bound() {
    let specs = vec![
        ResultArtifactSpec {
            name: "first.bin".into(),
            max_bytes: MAX_RESULT_ARTIFACT_BYTES,
            media_type: None,
        },
        ResultArtifactSpec {
            name: "second.bin".into(),
            max_bytes: MAX_RESULT_ARTIFACT_BYTES,
            media_type: None,
        },
        ResultArtifactSpec {
            name: "third.bin".into(),
            max_bytes: 1,
            media_type: None,
        },
    ];
    assert_eq!(
        MAX_RESULT_SET_BYTES,
        MAX_RESULT_ARTIFACT_BYTES * 2,
        "test fixture assumes the aggregate bound is exactly two maximum artifacts"
    );
    assert!(validate_result_specs(&specs[..2]).is_ok());
    assert!(validate_result_specs(&specs).is_err());
}

#[test]
fn result_info_requires_portable_name_lowercase_sha_and_bounded_metadata() {
    let info = ResultArtifactInfo::try_new(
        "report.json".into(),
        14,
        "a".repeat(64),
        Some("application/json".into()),
    )
    .expect("valid info");
    info.validate().expect("valid info");

    for (bytes, sha256, media_type) in [
        (14, "A".repeat(64), Some("application/json".to_owned())),
        (14, "a".repeat(63), Some("application/json".to_owned())),
        (
            14,
            format!("{}g", "a".repeat(63)),
            Some("application/json".to_owned()),
        ),
        (
            MAX_RESULT_ARTIFACT_BYTES + 1,
            "a".repeat(64),
            Some("application/json".to_owned()),
        ),
        (14, "a".repeat(64), Some("not a mime".to_owned())),
    ] {
        let wire = serde_json::json!({
            "name": "report.json",
            "bytes": bytes,
            "sha256": sha256,
            "media_type": media_type,
        });
        assert!(serde_json::from_value::<ResultArtifactInfo>(wire).is_err());
    }

    let wire = serde_json::json!({
        "name":"report.json",
        "bytes":14,
        "sha256":"a".repeat(64),
        "media_type":"application/json"
    });
    assert_eq!(
        ResultArtifactInfo::try_new(
            "report.json".into(),
            14,
            "a".repeat(64),
            Some("application/json".into()),
        )
        .expect("lowercase digest is accepted"),
        serde_json::from_value::<ResultArtifactInfo>(wire).expect("valid wire round-trip")
    );
    assert_eq!(
        ResultArtifactInfo::try_new("report.json".into(), 14, "A".repeat(64), None)
            .expect_err("uppercase digest is rejected"),
        "result artifact \"report.json\" has invalid lowercase SHA-256"
    );
    assert!(
        ResultArtifactInfo::try_new(
            "report.json".into(),
            14,
            "a".repeat(64),
            Some("not a mime".into()),
        )
        .expect_err("invalid media type is rejected")
        .contains("has invalid media type")
    );
}

#[test]
fn mapped_run_local_file_uses_lowercase_sha256_wire_contract() {
    let mapped = RunLocalMappedFile::try_new("ONEC_INPUT".into(), "a".repeat(64))
        .expect("lowercase digest is accepted");
    let encoded = serde_json::to_vec(&mapped).expect("serialize mapped-file identity");
    let decoded: RunLocalMappedFile =
        serde_json::from_slice(&encoded).expect("round-trip mapped-file identity");
    assert_eq!(decoded, mapped);

    for sha256 in [
        "A".repeat(64),
        "a".repeat(63),
        format!("{}g", "a".repeat(63)),
    ] {
        assert_eq!(
            RunLocalMappedFile::try_new("ONEC_INPUT".into(), sha256)
                .expect_err("invalid digest is rejected"),
            "mapped run-local file has invalid lowercase SHA-256"
        );
    }
    assert_eq!(
        RunLocalMappedFile::try_new("BAD/NAME".into(), "a".repeat(64))
            .expect_err("invalid environment name is rejected"),
        "mapped run-local environment name is invalid"
    );
}

#[test]
fn result_protocol_values_reject_malformed_wire_and_preserve_json_shape() {
    let invalid_spec = [
        serde_json::json!({"name":"../escape","max_bytes":1}),
        serde_json::json!({"name":"report.bin","max_bytes":0}),
        serde_json::json!({"name":"report.bin","max_bytes":MAX_RESULT_ARTIFACT_BYTES + 1}),
        serde_json::json!({"name":"report.bin","max_bytes":1,"media_type":"bad mime"}),
    ];
    for wire in invalid_spec {
        assert!(serde_json::from_value::<ResultArtifactSpec>(wire).is_err());
    }

    let duplicate_specs = serde_json::json!({
        "version":1,"token":"token","request":{"type":"exec","program":"tool",
        "results":[
            {"name":"Report.bin","max_bytes":1},
            {"name":"report.bin","max_bytes":1}
        ]}
    });
    assert!(serde_json::from_value::<AgentRequest>(duplicate_specs.clone()).is_err());
    let mut duplicate_specs = serde_json::to_vec(&duplicate_specs).expect("invalid request JSON");
    duplicate_specs.push(b'\n');
    let error = read_json_line::<AgentRequest>(BufReader::new(duplicate_specs.as_slice()))
        .expect_err("invalid result declaration must fail at the wire boundary");
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    let duplicate_job_specs = serde_json::json!({
        "version":1,"token":"token","request":{"type":"job_start","program":"tool",
        "results":[
            {"name":"Report.bin","max_bytes":1},
            {"name":"report.bin","max_bytes":1}
        ]}
    });
    assert!(serde_json::from_value::<AgentRequest>(duplicate_job_specs).is_err());

    let excessive_set = serde_json::json!({
        "owner":{"kind":"exec","result_set_id":"set-1"},
        "artifacts":[
            {"name":"first.bin","bytes":MAX_RESULT_ARTIFACT_BYTES,"sha256":"{}"},
            {"name":"second.bin","bytes":MAX_RESULT_ARTIFACT_BYTES,"sha256":"{}"},
            {"name":"third.bin","bytes":1,"sha256":"{}"}
        ]
    });
    let excessive_set = serde_json::to_string(&excessive_set)
        .expect("serialize fixture")
        .replace("{}", &"a".repeat(64));
    assert!(serde_json::from_str::<ResultSetInfo>(&excessive_set).is_err());
    let duplicate_published = serde_json::json!({
        "owner":{"kind":"exec","result_set_id":"set-1"},
        "artifacts":[
            {"name":"Report.bin","bytes":1,"sha256":"{}"},
            {"name":"report.bin","bytes":1,"sha256":"{}"}
        ]
    });
    let duplicate_published = serde_json::to_string(&duplicate_published)
        .expect("duplicate published fixture")
        .replace("{}", &"a".repeat(64));
    assert!(serde_json::from_str::<ResultSetInfo>(&duplicate_published).is_err());

    for owner in [
        serde_json::json!({"kind":"exec","result_set_id":"../escape"}),
        serde_json::json!({"kind":"job","job_id":"NUL"}),
    ] {
        assert!(serde_json::from_value::<ResultOwner>(owner).is_err());
    }

    let digest = "a".repeat(64);
    let mapped_digest = "b".repeat(64);
    let candidate_name = format!("sha256-{digest}.exe");
    let invalid_identity = [
        serde_json::json!({"run_id":"../escape","candidate_name":candidate_name,"candidate_sha256":digest}),
        serde_json::json!({"run_id":"0123456789abcdef0123456789abcdef","candidate_name":"candidate.exe","candidate_sha256":digest}),
        serde_json::json!({"run_id":"0123456789abcdef0123456789abcdef","candidate_name":candidate_name,"candidate_sha256":digest,"mapped_files":[{"environment_name":"ONEC_INPUT","sha256":mapped_digest},{"environment_name":"onec_input","sha256":mapped_digest}]}),
        serde_json::json!({"run_id":"0123456789abcdef0123456789abcdef","candidate_name":candidate_name,"candidate_sha256":digest,"mapped_files":[{"environment_name":"BAD/NAME","sha256":mapped_digest}]}),
        serde_json::json!({"run_id":"0123456789abcdef0123456789abcdef","candidate_name":format!("sha256-{}.exe", "A".repeat(64)),"candidate_sha256":"A".repeat(64)}),
        serde_json::json!({"run_id":"0123456789abcdef0123456789abcdef","candidate_name":candidate_name,"candidate_sha256":digest,"mapped_files":[{"environment_name":"ONEC_INPUT","sha256":"B".repeat(64)}]}),
    ];
    for wire in invalid_identity {
        assert!(serde_json::from_value::<RunLocalJobIdentity>(wire).is_err());
    }

    let mismatched_job = serde_json::json!({
        "job_id":"job-1","state":"succeeded","created_unix_ms":1,
        "result_set":{"owner":{"kind":"job","job_id":"job-2"},"artifacts":[]}
    });
    assert!(serde_json::from_value::<AgentJobInfo>(mismatched_job).is_err());

    let path_like_job_id = serde_json::json!({
        "job_id":"../escape","state":"running","created_unix_ms":1
    });
    assert!(serde_json::from_value::<AgentJobInfo>(path_like_job_id).is_err());

    let spec = ResultArtifactSpec::try_new(
        "report.json".to_owned(),
        16,
        Some("application/json".to_owned()),
    )
    .expect("valid spec");
    assert_eq!(
        serde_json::to_value(spec).expect("spec JSON"),
        serde_json::json!({"name":"report.json","max_bytes":16,"media_type":"application/json"})
    );
    let artifact = ResultArtifactInfo::try_new(
        "report.json".to_owned(),
        14,
        "a".repeat(64),
        Some("application/json".to_owned()),
    )
    .expect("valid artifact");
    let set = ResultSetInfo::try_new(
        ResultOwner::exec("set-1").expect("valid owner"),
        vec![artifact],
    )
    .expect("valid set");
    assert_eq!(
        serde_json::to_value(set).expect("result set JSON"),
        serde_json::json!({"owner":{"kind":"exec","result_set_id":"set-1"},"artifacts":[{"name":"report.json","bytes":14,"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","media_type":"application/json"}]})
    );
}

#[test]
fn legacy_exec_and_job_requests_default_to_no_results() {
    let exec = br#"{"version":1,"token":"secret","request":{"type":"exec","program":"tool"}}"#;
    let decoded: AgentRequest =
        read_json_line(BufReader::new(exec.as_slice())).expect("legacy exec");
    let AgentRequestKind::Exec {
        result_set_id,
        results,
        raw_output,
        ..
    } = decoded.request
    else {
        panic!("exec");
    };
    assert_eq!(result_set_id, None);
    assert!(results.is_empty());
    assert!(!raw_output, "legacy Exec must default to text output mode");

    let job = br#"{"version":1,"token":"secret","request":{"type":"job_start","program":"tool"}}"#;
    let decoded: AgentRequest = read_json_line(BufReader::new(job.as_slice())).expect("legacy job");
    let AgentRequestKind::JobStart { results, .. } = decoded.request else {
        panic!("job start");
    };
    assert!(results.is_empty());
}

#[test]
fn legacy_job_json_and_optional_run_local_identity_remain_compatible() {
    let old: AgentJobInfo =
        serde_json::from_str(r#"{"job_id":"job-old","state":"running","created_unix_ms":1}"#)
            .expect("old job metadata remains readable");
    assert_eq!(old.run_local, None);
    assert_eq!(old.spawn_owner_pid, None);

    let identity = RunLocalJobIdentity {
        run_id: "0123456789abcdef0123456789abcdef".to_owned(),
        candidate_name: format!("sha256-{}.exe", "a".repeat(64)),
        candidate_sha256: "a".repeat(64),
        mapped_files: vec![RunLocalMappedFile {
            environment_name: "ONEC_INPUT".to_owned(),
            sha256: "b".repeat(64),
        }],
    };
    assert_eq!(
        serde_json::to_value(&identity).expect("identity JSON"),
        serde_json::json!({
            "run_id":"0123456789abcdef0123456789abcdef",
            "candidate_name":format!("sha256-{}.exe", "a".repeat(64)),
            "candidate_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "mapped_files":[{"environment_name":"ONEC_INPUT","sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}]
        })
    );
    let request = AgentRequest::new(
        "secret",
        AgentRequestKind::JobStart {
            program: "candidate.exe".to_owned(),
            args: Vec::new(),
            cwd: None,
            env: BTreeMap::new(),
            secret_env: SecretEnvironment::default(),
            stdin: None,
            results: Vec::new(),
            run_local: Some(identity.clone()),
        },
    );
    let encoded = serde_json::to_vec(&request).expect("serialize optional identity");
    let decoded: AgentRequest = serde_json::from_slice(&encoded).expect("round-trip identity");
    let AgentRequestKind::JobStart { run_local, .. } = decoded.request else {
        panic!("expected durable job start");
    };
    assert_eq!(run_local, Some(identity.clone()));

    let mut current = old;
    current.run_local = Some(identity.clone());
    let decoded: AgentJobInfo =
        serde_json::from_slice(&serde_json::to_vec(&current).expect("serialize job metadata"))
            .expect("round-trip persisted job metadata");
    assert_eq!(decoded.run_local, Some(identity));
}

#[test]
fn native_invocation_observation_wire_is_typed_and_rejects_test_inventory_claims() {
    let request = AgentRequest::new(
        "control-secret",
        AgentRequestKind::RunLocalInvocationObserve {
            job_id: "job-123-1-1".to_owned(),
            challenge: "c".repeat(64),
            invocation_sha256: "a".repeat(64),
        },
    );
    let encoded = serde_json::to_vec(&request).expect("encode invocation observation");
    let decoded: AgentRequest = serde_json::from_slice(&encoded).expect("decode observation");
    assert_eq!(decoded, request);

    let record = AgentNativeInvocationRecord {
        schema_version: 1,
        challenge: "legacy".to_owned(),
        job_id: "job-123-1-1".to_owned(),
        run_id: "0123456789abcdef0123456789abcdef".to_owned(),
        invocation_sha256: "a".to_owned(),
        requested_exact_testcase: None,
        candidate_sha256: "b".to_owned(),
        declared_effect: NativeExecutionEffect::ReadOnly,
        host_arch: "x86_64".to_owned(),
        host_os: "windows".to_owned(),
        command_exit_code: 0,
        cleanup_completion: "complete".to_owned(),
        signer_id: "agent-key-1".to_owned(),
        observed_windows: None,
        output_logs: None,
        result_set: None,
    };
    let legacy_payload = br#"{"schema_version":1,"challenge":"legacy","job_id":"job-123-1-1","run_id":"0123456789abcdef0123456789abcdef","invocation_sha256":"a","candidate_sha256":"b","declared_effect":"read-only","host_arch":"x86_64","host_os":"windows","command_exit_code":0,"cleanup_completion":"complete","signer_id":"agent-key-1"}"#;
    assert_eq!(
        serde_json::to_vec(&record).expect("encode legacy observation fields"),
        legacy_payload
    );
    let legacy_signing_bytes = record.signing_bytes().expect("legacy signing bytes");
    let domain = b"onec-toolkit:agent:native-invocation:v1\0";
    assert_eq!(&legacy_signing_bytes[..domain.len()], domain);
    assert_eq!(
        &legacy_signing_bytes[domain.len()..domain.len() + 8],
        &(legacy_payload.len() as u64).to_be_bytes()
    );
    assert_eq!(&legacy_signing_bytes[domain.len() + 8..], legacy_payload);
    let wire = serde_json::to_value(record).expect("serialize observation");
    assert!(wire.get("observed_windows").is_none());
    assert!(wire.get("output_logs").is_none());
    let legacy_decoded: AgentNativeInvocationRecord =
        serde_json::from_value(wire.clone()).expect("decode pre-field observation");
    assert_eq!(
        legacy_decoded.signing_bytes().expect("legacy re-encoding"),
        legacy_signing_bytes
    );
    let testcase_bound = AgentNativeInvocationRecord {
        requested_exact_testcase: Some("approved::case".to_owned()),
        ..legacy_decoded.clone()
    };
    assert_ne!(
        testcase_bound
            .signing_bytes()
            .expect("testcase-bound bytes"),
        legacy_signing_bytes,
        "the testcase identity must be covered by the Agent signature"
    );
    assert!(wire.get("requested_exact_testcase").is_none());
    assert!(wire.get("selected_tests").is_none());
    assert!(wire.get("executed_tests").is_none());
    for (field, claim) in [
        ("selected_tests", serde_json::json!(["approved::test_name"])),
        ("executed_tests", serde_json::json!(["approved::test_name"])),
        ("test_names", serde_json::json!(["forged::test_name"])),
        ("suite_outcome", serde_json::json!("passed")),
        ("tests_passed", serde_json::json!(0)),
        ("tests_filtered", serde_json::json!(4)),
        ("tests_ignored", serde_json::json!(2)),
        ("tests_failed", serde_json::json!(0)),
    ] {
        let mut forged = wire.clone();
        forged[field] = claim;
        assert!(
            serde_json::from_value::<AgentNativeInvocationRecord>(forged).is_err(),
            "invocation observation must reject caller-reported {field} claims"
        );
    }

    let malformed = serde_json::json!({
        "version": PROTOCOL_VERSION,
        "token": "control-secret",
        "request": {
            "type": "run_local_invocation_observe",
            "job_id": "job-123-1-1",
            "challenge": "c",
            "invocation_sha256": "A".repeat(64)
        }
    });
    assert!(serde_json::from_value::<AgentRequest>(malformed).is_err());
}

#[test]
fn observed_windows_facts_require_known_architecture_and_consistent_platform() {
    use crate::{ObservedWindowsFacts, WindowsArchitecture};

    let facts = ObservedWindowsFacts {
        os_major: 6,
        os_minor: 1,
        os_build: 7601,
        process_architecture: WindowsArchitecture::X86,
        native_architecture: WindowsArchitecture::X86_64,
        process_is_wow64: true,
    };
    assert!(facts.is_consistent_with_host("windows", "x86"));
    assert!(!facts.is_consistent_with_host("linux", "x86"));
    assert!(!facts.is_consistent_with_host("windows", "x86_64"));

    let malformed = serde_json::json!({
        "os_major": 6,
        "os_minor": 1,
        "os_build": 7601,
        "process_architecture": "mystery",
        "native_architecture": "x86_64",
        "process_is_wow64": true
    });
    assert!(serde_json::from_value::<ObservedWindowsFacts>(malformed).is_err());

    let incomplete = serde_json::json!({
        "os_major": 6,
        "os_minor": 1,
        "os_build": 7601,
        "process_architecture": "x86",
        "native_architecture": "x86_64"
    });
    assert!(serde_json::from_value::<ObservedWindowsFacts>(incomplete).is_err());

    let inconsistent = ObservedWindowsFacts {
        process_is_wow64: false,
        ..facts
    };
    assert!(!inconsistent.is_consistent_with_host("windows", "x86"));
    let zero_build = ObservedWindowsFacts {
        os_build: 0,
        ..facts
    };
    assert!(!zero_build.is_consistent_with_host("windows", "x86"));
}

#[test]
fn native_run_local_job_start_is_opt_in_and_rejects_secret_environment() {
    let identity = RunLocalJobIdentity::try_new(
        "0123456789abcdef0123456789abcdef".to_owned(),
        format!("sha256-{}.exe", "a".repeat(64)),
        "a".repeat(64),
        Vec::new(),
    )
    .expect("valid candidate identity");
    let request = AgentRequest::new(
        "secret",
        AgentRequestKind::NativeRunLocalJobStart {
            program: "candidate.exe".to_owned(),
            args: vec!["--exact".to_owned(), "suite::case".to_owned()],
            cwd: Some("owned-root".to_owned()),
            env: BTreeMap::new(),
            secret_env: SecretEnvironment::default(),
            stdin: None,
            results: Vec::new(),
            run_local: identity,
            native_effect: NativeExecutionEffect::ReadOnly,
            native_suite_policy: None,
        },
    );
    let bytes = serde_json::to_vec(&request).expect("encode opt-in job start");
    assert_eq!(
        serde_json::from_slice::<AgentRequest>(&bytes).expect("decode opt-in job start"),
        request
    );

    let secret_environment = serde_json::json!({
        "version": PROTOCOL_VERSION,
        "token": "secret",
        "request": {
            "type": "native_run_local_job_start",
            "program": "candidate.exe",
            "args": [],
            "env": {},
            "secret_env": {"PASSWORD": "placeholder"},
            "results": [],
            "run_local": {
                "run_id": "0123456789abcdef0123456789abcdef",
                "candidate_name": format!("sha256-{}.exe", "a".repeat(64)),
                "candidate_sha256": "a".repeat(64),
                "mapped_files": []
            },
            "native_effect": "read-only"
        }
    });
    assert!(serde_json::from_value::<AgentRequest>(secret_environment).is_err());
}

#[test]
fn native_suite_policy_is_carried_as_typed_admission_input() {
    let policy = NativeSuitePolicy {
        version: 1,
        runner_sha256: "a".repeat(64),
        args: vec!["run".into()],
        env: BTreeMap::new(),
        expected_tests: vec!["crate::case_a".into(), "crate::case_b".into()],
        effect: NativeExecutionEffect::ReadOnly,
    };
    let identity = RunLocalJobIdentity::try_new(
        "0123456789abcdef0123456789abcdef".to_owned(),
        format!("sha256-{}.exe", "a".repeat(64)),
        "a".repeat(64),
        Vec::new(),
    )
    .expect("candidate identity");
    let request = AgentRequest::new(
        "secret",
        AgentRequestKind::NativeRunLocalJobStart {
            program: "candidate.exe".into(),
            args: policy.args.clone(),
            cwd: Some("owned-root".into()),
            env: policy.env.clone(),
            secret_env: SecretEnvironment::default(),
            stdin: None,
            results: Vec::new(),
            run_local: identity,
            native_effect: policy.effect,
            native_suite_policy: Some(policy.clone()),
        },
    );
    let bytes = serde_json::to_vec(&request).expect("encode suite policy request");
    assert_eq!(
        serde_json::from_slice::<AgentRequest>(&bytes).expect("decode typed suite policy"),
        request
    );
    assert!(
        policy.sha256().is_ok(),
        "well-formed pinned policy has a digest"
    );

    let unknown = serde_json::json!({
        "version": 1,
        "token": "secret",
        "request": {
            "type": "native_run_local_job_start",
            "program": "candidate.exe",
            "args": ["run"],
            "env": {},
            "results": [],
            "run_local": {
                "run_id": "0123456789abcdef0123456789abcdef",
                "candidate_name": format!("sha256-{}.exe", "a".repeat(64)),
                "candidate_sha256": "a".repeat(64),
                "mapped_files": []
            },
            "native_effect": "read-only",
            "native_suite_policy": {
                "version": 1,
                "runner_sha256": "a".repeat(64),
                "args": ["run"],
                "env": {},
                "expected_tests": ["crate::case_a"],
                "effect": "read-only",
                "outcomes": [{"test": "crate::case_a", "result": "passed"}]
            }
        }
    });
    assert!(serde_json::from_value::<AgentRequest>(unknown).is_err());
}

#[test]
fn legacy_run_local_prepare_defaults_to_the_immediate_workspace_shape() {
    let old = br#"{"version":1,"token":"secret","request":{"type":"run_local_prepare","run_id":"0123456789abcdef0123456789abcdef"}}"#;
    let decoded: AgentRequest = serde_json::from_slice(old).expect("legacy run-local prepare");
    let AgentRequestKind::RunLocalPrepare {
        create_mapped_workspace,
        ..
    } = decoded.request
    else {
        panic!("expected run-local prepare");
    };
    assert!(!create_mapped_workspace);
    let immediate = AgentRequestKind::RunLocalPrepare {
        run_id: "0123456789abcdef0123456789abcdef".into(),
        create_mapped_workspace: false,
    };
    assert!(
        !serde_json::to_string(&immediate)
            .expect("serialize immediate prepare")
            .contains("create_mapped_workspace")
    );

    let request = AgentRequest::new(
        "secret",
        AgentRequestKind::RunLocalPrepare {
            run_id: "0123456789abcdef0123456789abcdef".to_owned(),
            create_mapped_workspace: true,
        },
    );
    let encoded = serde_json::to_vec(&request).expect("encode durable prepare");
    let decoded: AgentRequest = serde_json::from_slice(&encoded).expect("decode durable prepare");
    assert!(matches!(
        decoded.request,
        AgentRequestKind::RunLocalPrepare {
            create_mapped_workspace: true,
            ..
        }
    ));
}

#[test]
fn legacy_exec_response_defaults_result_metadata_and_typed_result_requests_have_no_path() {
    let raw = br#"{"version":1,"ok":true,"response":{"type":"exec","exit_code":0,"stdout":"","stderr":""}}"#;
    let decoded: AgentResponse =
        read_json_line(BufReader::new(raw.as_slice())).expect("legacy exec response");
    assert!(matches!(
        decoded.response,
        Some(AgentResponseKind::Exec {
            result_set: None,
            stdout_base64: None,
            stderr_base64: None,
            ..
        })
    ));

    let request = AgentRequest::new(
        "secret",
        AgentRequestKind::ResultDownload {
            owner: ResultOwner::exec("opaque-1").expect("valid result owner"),
            name: "report.json".into(),
        },
    );
    let mut bytes = Vec::new();
    write_json_line(&mut bytes, &request).expect("write typed result request");
    let encoded = String::from_utf8(bytes.clone()).expect("json");
    assert!(encoded.contains(r#""result_set_id":"opaque-1""#));
    assert!(!encoded.contains("path"));
    let decoded: AgentRequest = read_json_line(BufReader::new(bytes.as_slice())).expect("read");
    assert_eq!(decoded, request);
}

#[test]
fn raw_exec_response_at_agent_stream_limits_fits_control_frame_without_text_duplication() {
    let encoded_stream = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        vec![b'x'; 256 * 1024],
    );
    let response = AgentResponse::success(AgentResponseKind::Exec {
        exit_code: Some(0),
        stdout: String::new(),
        stderr: String::new(),
        stdout_base64: Some(encoded_stream.clone()),
        stderr_base64: Some(encoded_stream),
        result_set: None,
    });
    let mut bytes = Vec::new();
    write_json_line(&mut bytes, &response).expect("raw Exec response must fit control frame");
    assert!(
        bytes.len() <= MAX_CONTROL_LINE_BYTES,
        "bounded raw stdout+stderr must fit one control frame: {} > {}",
        bytes.len(),
        MAX_CONTROL_LINE_BYTES
    );
}

#[test]
fn correlation_names_remain_backward_compatible_reexports() {
    assert_eq!(ONEC_PARENT_RUN_ID_ENV, "ONEC_PARENT_RUN_ID");
    assert_eq!(ONEC_JOB_SYSTEM_ENV, "ONEC_JOB_SYSTEM");
    assert_eq!(ONEC_JOB_ID_ENV, "ONEC_JOB_ID");
    assert_eq!(ONEC_RESULT_DIR_ENV, "ONEC_RESULT_DIR");
    assert_eq!(ONEC_AGENT_JOB_SYSTEM, "onec_agent_job");
}

#[test]
fn hello_keeps_protocol_v1_executable_key_while_accepting_canonical_alias() {
    let legacy = br#"{"version":1,"ok":true,"response":{"type":"hello","name":"fixture","agent_version":"0.1.1","hostname":"host","os":"windows","capabilities":[],"onec_ops_executable":"C:\\toolkit\\onec.exe"}}"#;
    let decoded: AgentResponse =
        read_json_line(BufReader::new(legacy.as_slice())).expect("legacy hello executable alias");
    let Some(AgentResponseKind::Hello {
        onec_executable, ..
    }) = decoded.response
    else {
        panic!("expected hello");
    };
    assert_eq!(onec_executable.as_deref(), Some(r"C:\toolkit\onec.exe"));

    let response = AgentResponse::success(AgentResponseKind::Hello {
        name: "fixture".to_owned(),
        agent_version: "0.1.1".to_owned(),
        hostname: "host".to_owned(),
        os: "windows".to_owned(),
        capabilities: Vec::new(),
        agent_executable: None,
        onec_executable: Some(r"C:\toolkit\onec.exe".to_owned()),
    });
    let mut bytes = Vec::new();
    write_json_line(&mut bytes, &response).expect("serialize canonical hello");
    let encoded = String::from_utf8(bytes).expect("response JSON is UTF-8");
    assert!(encoded.contains("\"onec_ops_executable\""), "{encoded}");
    assert!(!encoded.contains("\"onec_executable\""), "{encoded}");

    let canonical = br#"{"version":1,"ok":true,"response":{"type":"hello","name":"fixture","agent_version":"0.1.1","hostname":"host","os":"windows","capabilities":[],"onec_executable":"C:\\toolkit\\onec.exe"}}"#;
    let decoded: AgentResponse =
        read_json_line(BufReader::new(canonical.as_slice())).expect("canonical hello alias");
    let Some(AgentResponseKind::Hello {
        onec_executable, ..
    }) = decoded.response
    else {
        panic!("expected hello");
    };
    assert_eq!(onec_executable.as_deref(), Some(r"C:\toolkit\onec.exe"));
}
