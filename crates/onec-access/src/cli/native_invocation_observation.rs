//! Controller verification and recovery for Agent-native invocation observations.

use super::{mutable_lease, run_local_job, *};
use ed25519_dalek::{Signature, VerifyingKey};
use hostlink_protocol::{
    AgentJobInfo, AgentJobState, AgentNativeInvocationRecord, AgentRequestKind, AgentResponseKind,
    MAX_RESULT_ARTIFACT_BYTES, NativeExecutionEffect,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::{fs, path::Path};

const RECEIPT_DIRECTORY: &str = "native-invocation-observations";
const MAX_RECEIPT_BYTES: u64 = 64 * 1024;
const MAX_SIGNED_OUTPUT_LOG_BYTES: u64 = 8 * 1024 * 1024;

/// Verify existing controller-local receipt and complete local Agent log copies without network access.
pub(super) fn verify_local_logs(
    machine_id: &str,
    run_id: &str,
    challenge: &str,
    trusted_public_key_path: &Path,
    stdout_path: &Path,
    stderr_path: &Path,
) -> AppResult<()> {
    let data_root = run_local_job::controller_data_root()?;
    verify_local_logs_from_root(
        &data_root,
        machine_id,
        run_id,
        challenge,
        trusted_public_key_path,
        stdout_path,
        stderr_path,
    )
}

/// Verify a local result copy against the independently pinned Agent-signed invocation record.
pub(super) fn verify_local_result(
    machine_id: &str,
    run_id: &str,
    challenge: &str,
    trusted_public_key_path: &Path,
    artifact_name: &str,
    artifact_path: &Path,
) -> AppResult<()> {
    let data_root = run_local_job::controller_data_root()?;
    verify_local_result_from_root(
        &data_root,
        machine_id,
        run_id,
        challenge,
        trusted_public_key_path,
        artifact_name,
        artifact_path,
    )
}

fn verify_local_result_from_root(
    data_root: &Path,
    machine_id: &str,
    run_id: &str,
    challenge: &str,
    trusted_public_key_path: &Path,
    artifact_name: &str,
    artifact_path: &Path,
) -> AppResult<()> {
    if challenge.is_empty() || challenge.len() > 128 {
        return Err(crate::invalid_config(
            "native invocation challenge must contain 1..=128 bytes".to_owned(),
        ));
    }
    let (trusted_key, trusted_key_hex) = read_trusted_public_key(trusted_public_key_path)?;
    let job_id = mutable_lease::durable_run_local_recorded_job_id(data_root, machine_id, run_id)?;
    if !safe_job_id(&job_id) {
        return Err(crate::invalid_config(
            "controller reservation contains an invalid Agent job identity".to_owned(),
        ));
    }
    let invocation =
        mutable_lease::durable_native_invocation_reservation(data_root, machine_id, run_id)?;
    let expected = ExpectedInvocation {
        signer_id: signer_id(&trusted_key.to_bytes()),
        machine_id: machine_id.to_owned(),
        run_id: run_id.to_owned(),
        job_id: job_id.clone(),
        candidate_sha256: invocation.candidate_sha256().to_owned(),
        invocation_sha256: invocation.invocation_sha256().to_owned(),
        native_effect: invocation.native_effect(),
        challenge: challenge.to_owned(),
    };
    let receipt_path = data_root
        .join(RECEIPT_DIRECTORY)
        .join(format!("{job_id}.json"));
    let receipt = read_receipt(&receipt_path)?;
    verify_receipt(
        &receipt,
        &trusted_key,
        &trusted_key_hex,
        machine_id,
        &expected,
    )?;
    let result_set = receipt.record.result_set.as_ref().ok_or_else(|| {
        crate::invalid_config(
            "signed invocation receipt has no Agent-published result set".to_owned(),
        )
    })?;
    if result_set.owner().job_id() != Some(job_id.as_str()) {
        return Err(crate::invalid_config(
            "signed result set owner does not match the controller's reserved job".to_owned(),
        ));
    }
    let mut matches = result_set
        .artifacts()
        .iter()
        .filter(|artifact| artifact.name() == artifact_name);
    let artifact = matches.next().ok_or_else(|| {
        crate::invalid_config(
            "requested artifact name is not present in the signed result set".to_owned(),
        )
    })?;
    if matches.next().is_some() {
        return Err(crate::invalid_config(
            "requested artifact name is ambiguous in the signed result set".to_owned(),
        ));
    }
    if artifact.bytes() > MAX_RESULT_ARTIFACT_BYTES {
        return Err(crate::invalid_config(
            "signed result artifact exceeds the protocol byte limit".to_owned(),
        ));
    }
    verify_result_file(artifact_path, artifact.bytes(), artifact.sha256())?;
    println!(
        "invocation result verified as observation_only: machine_id={machine_id} run_id={run_id} job_id={job_id} artifact_name={artifact_name} authenticated_result_bytes:true release_matrix_v2:false\nThe exact local bytes match the independently pinned Agent-signed result commitment; this is not a test-result interpretation or accepted release receipt."
    );
    Ok(())
}

fn verify_result_file(path: &Path, expected_bytes: u64, expected_sha256: &str) -> AppResult<()> {
    if expected_bytes > MAX_RESULT_ARTIFACT_BYTES {
        return Err(crate::invalid_config(
            "signed result artifact exceeds the protocol byte limit".to_owned(),
        ));
    }
    let before = fs::symlink_metadata(path).map_err(|source| {
        anyhow::Error::new(source).context("cannot inspect local result artifact")
    })?;
    if !before.file_type().is_file() || before.len() != expected_bytes {
        return Err(crate::invalid_config(
            "local result artifact must be a regular non-linked file with the signed byte length"
                .to_owned(),
        ));
    }
    hostlink_core::validate_private_file(path).map_err(|source| {
        anyhow::Error::new(source).context("local result artifact is not private")
    })?;
    let file = hostlink_core::RegularFile::open(path).map_err(|source| {
        anyhow::Error::new(source).context("cannot safely open local result artifact")
    })?;
    let first = file.observe_digest().map_err(|source| {
        anyhow::Error::new(source).context("cannot stream-hash local result artifact")
    })?;
    if first.bytes() != expected_bytes || first.sha256() != expected_sha256 {
        return Err(crate::invalid_config(
            "local result artifact bytes do not match the Agent-signed size and SHA-256".to_owned(),
        ));
    }
    let second = file.observe_digest().map_err(|source| {
        anyhow::Error::new(source)
            .context("cannot recheck local result artifact identity and bytes")
    })?;
    let path_identity_after = hostlink_core::RegularFile::open(path).map_err(|source| {
        anyhow::Error::new(source).context("cannot recheck local result artifact file identity")
    })?;
    let after = fs::symlink_metadata(path).map_err(|source| {
        anyhow::Error::new(source).context("cannot recheck local result artifact path")
    })?;
    if before.len() != after.len()
        || before.modified().ok() != after.modified().ok()
        || after.file_type().is_symlink()
        || first != second
        || file != path_identity_after
    {
        return Err(crate::invalid_config(
            "local result artifact changed while it was being verified".to_owned(),
        ));
    }
    hostlink_core::validate_private_file(path).map_err(|source| {
        anyhow::Error::new(source).context("local result artifact is no longer private")
    })?;
    Ok(())
}

fn verify_local_logs_from_root(
    data_root: &Path,
    machine_id: &str,
    run_id: &str,
    challenge: &str,
    trusted_public_key_path: &Path,
    stdout_path: &Path,
    stderr_path: &Path,
) -> AppResult<()> {
    if challenge.is_empty() || challenge.len() > 128 {
        return Err(crate::invalid_config(
            "native invocation challenge must contain 1..=128 bytes".to_owned(),
        ));
    }
    let (trusted_key, trusted_key_hex) = read_trusted_public_key(trusted_public_key_path)?;
    let job_id = mutable_lease::durable_run_local_recorded_job_id(data_root, machine_id, run_id)?;
    if !safe_job_id(&job_id) {
        return Err(crate::invalid_config(
            "controller reservation contains an invalid Agent job identity".to_owned(),
        ));
    }
    // Pin executable identity and declared effect from controller state before signature checks.
    let invocation =
        mutable_lease::durable_native_invocation_reservation(data_root, machine_id, run_id)?;
    let receipt_path = data_root
        .join(RECEIPT_DIRECTORY)
        .join(format!("{job_id}.json"));
    let receipt = read_receipt(&receipt_path)?;
    let expected = ExpectedInvocation {
        signer_id: signer_id(&trusted_key.to_bytes()),
        machine_id: machine_id.to_owned(),
        run_id: run_id.to_owned(),
        job_id: job_id.clone(),
        candidate_sha256: invocation.candidate_sha256().to_owned(),
        invocation_sha256: invocation.invocation_sha256().to_owned(),
        native_effect: invocation.native_effect(),
        challenge: challenge.to_owned(),
    };
    verify_receipt(
        &receipt,
        &trusted_key,
        &trusted_key_hex,
        machine_id,
        &expected,
    )?;
    let signed_logs = signed_output_logs(&receipt)?;
    verify_signed_log_files(signed_logs, stdout_path, stderr_path)?;
    println!(
        "invocation logs verified as observation_only: machine_id={machine_id} run_id={run_id} job_id={job_id} release_matrix_v2:false\nThis cryptographically binds these local bytes to the signed Agent record; it does not prove libtest executed or satisfy the managed release acceptance receipt."
    );
    Ok(())
}

fn verify_signed_log_files(
    signed_logs: &hostlink_protocol::AgentNativeInvocationOutputLogs,
    stdout_path: &Path,
    stderr_path: &Path,
) -> AppResult<()> {
    let stdout = read_stable_private_log(stdout_path, "stdout")?;
    let stderr = read_stable_private_log(stderr_path, "stderr")?;
    if stdout.0 != signed_logs.stdout_bytes
        || stdout.1 != signed_logs.stdout_sha256
        || stderr.0 != signed_logs.stderr_bytes
        || stderr.1 != signed_logs.stderr_sha256
    {
        return Err(crate::invalid_config(
            "local stdout/stderr bytes do not match the Agent-signed invocation log hashes"
                .to_owned(),
        ));
    }
    Ok(())
}

fn signed_output_logs(
    receipt: &InvocationObservationReceipt,
) -> AppResult<&hostlink_protocol::AgentNativeInvocationOutputLogs> {
    receipt.record.output_logs.as_ref().ok_or_else(|| {
        crate::invalid_config(
            "signed invocation receipt predates log binding or contains no signed output logs"
                .to_owned(),
        )
    })
}

fn read_stable_private_log(path: &Path, stream: &str) -> AppResult<(u64, String)> {
    let before = fs::symlink_metadata(path).map_err(|source| {
        anyhow::Error::new(source).context(format!("cannot inspect local {stream} log"))
    })?;
    if !before.file_type().is_file() || before.len() > MAX_SIGNED_OUTPUT_LOG_BYTES {
        return Err(crate::invalid_config(format!(
            "local {stream} log must be a regular non-linked file no larger than 8 MiB"
        )));
    }
    hostlink_core::validate_private_file(path).map_err(|source| {
        anyhow::Error::new(source).context(format!("local {stream} log is not private"))
    })?;
    let file = hostlink_core::RegularFile::open(path).map_err(|source| {
        anyhow::Error::new(source).context(format!("cannot safely open local {stream} log"))
    })?;
    let first = read_log_pass(&file, stream)?;
    let second = read_log_pass(&file, stream)?;
    let path_after = fs::symlink_metadata(path).map_err(|source| {
        anyhow::Error::new(source).context(format!("cannot recheck local {stream} log path"))
    })?;
    if before.len() != path_after.len()
        || before.modified().ok() != path_after.modified().ok()
        || path_after.file_type().is_symlink()
        || first != second
    {
        return Err(crate::invalid_config(format!(
            "local {stream} log changed while it was being verified"
        )));
    }
    hostlink_core::validate_private_file(path).map_err(|source| {
        anyhow::Error::new(source).context(format!("local {stream} log is no longer private"))
    })?;
    let digest = format!("{:x}", Sha256::digest(&first));
    Ok((first.len() as u64, digest))
}

fn read_log_pass(file: &hostlink_core::RegularFile, stream: &str) -> AppResult<Vec<u8>> {
    file.read_bounded(MAX_SIGNED_OUTPUT_LOG_BYTES as usize)
        .map_err(|source| {
            anyhow::Error::new(source).context(format!(
                "cannot read local {stream} log within the 8 MiB verification limit"
            ))
        })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ExpectedInvocation {
    signer_id: String,
    machine_id: String,
    run_id: String,
    job_id: String,
    candidate_sha256: String,
    invocation_sha256: String,
    native_effect: NativeExecutionEffect,
    challenge: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct InvocationObservationReceipt {
    schema_version: u32,
    evidence_class: String,
    protocol: String,
    release_matrix_v2: bool,
    machine_id: String,
    record: AgentNativeInvocationRecord,
    signature_hex: String,
    trusted_public_key_hex: String,
}

pub(super) async fn collect(
    target: &str,
    run_id: &str,
    challenge: &str,
    trusted_public_key_path: &Path,
    recovery_only: bool,
) -> AppResult<()> {
    if challenge.is_empty() || challenge.len() > 128 {
        return Err(crate::invalid_config(
            "native invocation challenge must contain 1..=128 bytes".to_owned(),
        ));
    }
    let (trusted_key, trusted_key_hex) = read_trusted_public_key(trusted_public_key_path)?;
    let trusted_signer_id = signer_id(&trusted_key.to_bytes());
    let data_root = run_local_job::controller_data_root()?;
    let (machine_id, _hub, client) = run_local_job::resolve(target).await?;

    // Status reconnect also binds a pending controller reservation if the start response was lost.
    let job = run_local_job::status_by_run(&client, &data_root, &machine_id, run_id).await?;
    let reserved_job_id =
        mutable_lease::durable_run_local_recorded_job_id(&data_root, &machine_id, run_id)?;
    let invocation =
        mutable_lease::durable_native_invocation_reservation(&data_root, &machine_id, run_id)?;
    let controller_lease =
        mutable_lease::acquire_durable_run_local_operation_lease(&data_root, &machine_id)?;

    require_results_complete(mutable_lease::durable_run_local_results_complete(
        &data_root,
        &machine_id,
        run_id,
    )?)?;
    validate_eligible_job(
        &job,
        run_id,
        &reserved_job_id,
        invocation.candidate_sha256(),
    )?;

    let expected = ExpectedInvocation {
        signer_id: trusted_signer_id.clone(),
        machine_id: machine_id.clone(),
        run_id: run_id.to_owned(),
        job_id: reserved_job_id.clone(),
        candidate_sha256: invocation.candidate_sha256().to_owned(),
        invocation_sha256: invocation.invocation_sha256().to_owned(),
        native_effect: invocation.native_effect(),
        challenge: challenge.to_owned(),
    };
    let receipt_dir = data_root.join(RECEIPT_DIRECTORY);
    hostlink_core::ensure_private_directory(&receipt_dir).map_err(|source| {
        anyhow::Error::new(source).context("cannot secure native invocation receipt directory")
    })?;
    let receipt_path = receipt_dir.join(format!("{reserved_job_id}.json"));
    let pending_path = receipt_dir.join(format!("{reserved_job_id}.pending"));

    match fs::symlink_metadata(&receipt_path) {
        Ok(_) => {
            let receipt = read_receipt(&receipt_path)?;
            verify_receipt(
                &receipt,
                &trusted_key,
                &trusted_key_hex,
                &machine_id,
                &expected,
            )?;
            remove_empty_pending(&pending_path)?;
            drop(controller_lease);
            mutable_lease::release_durable_run_local(
                &data_root,
                &machine_id,
                run_id,
                &reserved_job_id,
            )?;
            print_observation(&receipt_path, true);
            return Ok(());
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(anyhow::Error::new(source)
                .context("cannot inspect native invocation receipt destination"));
        }
    }

    if recovery_only {
        require_empty_pending(&pending_path)?;
    } else {
        match fs::symlink_metadata(&pending_path) {
            Ok(_) => {
                return Err(crate::invalid_config(
                    "a pending invocation observation exists; use `recover-invocation` and do not replay signing"
                        .to_owned(),
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(anyhow::Error::new(source)
                    .context("cannot inspect native invocation pending reservation"));
            }
        }
    }

    let response = if recovery_only {
        client
            .fetch_run_local_invocation_observation(
                expected.job_id.clone(),
                expected.challenge.clone(),
                expected.invocation_sha256.clone(),
            )
            .await
            .map_err(|error| {
                error.context(
                    "read-only invocation recovery fetch failed; keep the pending marker and reservation",
                )
            })?
    } else {
        client.require_capability("native-attestation-v1").await?;
        let public_key_response = client
            .request(AgentRequestKind::NativeAttestationPublicKey)
            .await?;
        let AgentResponseKind::NativeAttestationPublicKey {
            signer_id: agent_signer_id,
            verifying_key_hex: agent_key_hex,
        } = public_key_response
        else {
            return Err(crate::invalid_config(
                "agent returned an unexpected native attestation public-key response".to_owned(),
            ));
        };
        if agent_key_hex != trusted_key_hex || agent_signer_id != trusted_signer_id {
            return Err(crate::invalid_config(
                "agent invocation signer does not match the independently pinned public key"
                    .to_owned(),
            ));
        }
        let pending = hostlink_core::create_new_private_file(&pending_path).map_err(|source| {
            anyhow::Error::new(source)
                .context("cannot create private one-shot invocation observation marker")
        })?;
        pending.sync_all().map_err(|source| {
            anyhow::Error::new(source)
                .context("cannot durably flush invocation observation pending marker")
        })?;
        drop(pending);
        send_observation_once(|| {
            client.observe_run_local_invocation(
                expected.job_id.clone(),
                expected.challenge.clone(),
                expected.invocation_sha256.clone(),
            )
        })
        .await?
    };

    let (record, signature_hex) = match (recovery_only, response) {
        (
            false,
            AgentResponseKind::NativeInvocationObservation {
                record,
                signature_hex,
            },
        )
        | (
            true,
            AgentResponseKind::NativeInvocationObservationFetched {
                record,
                signature_hex,
            },
        ) => (record, signature_hex),
        _ => {
            return Err(crate::invalid_config(
                "agent returned an unexpected invocation observation response; reservation remains active"
                    .to_owned(),
            ));
        }
    };
    verify_record(&record, &signature_hex, &trusted_key, &expected)?;

    let receipt = InvocationObservationReceipt {
        schema_version: 1,
        evidence_class: "observation_only".to_owned(),
        protocol: "agent-native-invocation:v1".to_owned(),
        release_matrix_v2: false,
        machine_id: machine_id.clone(),
        record,
        signature_hex,
        trusted_public_key_hex: trusted_key_hex,
    };
    let bytes = serde_json::to_vec_pretty(&receipt).map_err(|source| {
        crate::invalid_config(format!(
            "cannot encode invocation observation receipt: {source}"
        ))
    })?;
    publish_receipt_create_new(&receipt_dir, &receipt_path, &reserved_job_id, &bytes).map_err(
        |source| {
            anyhow::Error::new(source).context(
                "verified invocation observation was received but its private create-new receipt was not saved; reservation remains active",
            )
        },
    )?;

    remove_empty_pending(&pending_path)?;
    drop(controller_lease);
    mutable_lease::release_durable_run_local(&data_root, &machine_id, run_id, &reserved_job_id)?;
    print_observation(&receipt_path, recovery_only);
    Ok(())
}

fn validate_eligible_job(
    job: &AgentJobInfo,
    run_id: &str,
    job_id: &str,
    expected_candidate_sha256: &str,
) -> AppResult<()> {
    let identity = job
        .run_local
        .as_ref()
        .filter(|identity| identity.run_id() == run_id)
        .ok_or_else(|| {
            crate::invalid_config(
                "Agent job does not match the requested source-exact run identity".to_owned(),
            )
        })?;
    if job.job_id != job_id || !safe_job_id(job_id) {
        return Err(crate::invalid_config(
            "Agent job does not match the controller's exact durable job reservation".to_owned(),
        ));
    }
    if identity.candidate_sha256() != expected_candidate_sha256 {
        return Err(crate::invalid_config(
            "Agent job executable digest differs from the controller's persisted invocation"
                .to_owned(),
        ));
    }
    if job.state != AgentJobState::Succeeded
        || job.exit_code != Some(0)
        || job.finished_unix_ms.is_none()
    {
        return Err(crate::invalid_config(
            "invocation observation requires a terminal succeeded job with exit code 0".to_owned(),
        ));
    }
    Ok(())
}

fn require_results_complete(complete: bool) -> AppResult<()> {
    if !complete {
        return Err(crate::invalid_config(
            "retrieve and clean declared run-local results before observing the invocation"
                .to_owned(),
        ));
    }
    Ok(())
}

fn verify_record(
    record: &AgentNativeInvocationRecord,
    signature_hex: &str,
    key: &VerifyingKey,
    expected: &ExpectedInvocation,
) -> AppResult<()> {
    if record.schema_version != 1
        || record.signer_id != expected.signer_id
        || record.run_id != expected.run_id
        || record.job_id != expected.job_id
        || record.candidate_sha256 != expected.candidate_sha256
        || record.invocation_sha256 != expected.invocation_sha256
        || record.declared_effect != expected.native_effect
        || record.challenge != expected.challenge
        || record.command_exit_code != 0
        || record.cleanup_completion != "complete"
        || record.host_arch.is_empty()
        || record.host_os.is_empty()
        || record
            .observed_windows
            .is_some_and(|facts| !facts.is_consistent_with_host(&record.host_os, &record.host_arch))
        || record.output_logs.as_ref().is_some_and(|logs| {
            !is_lower_sha256(&logs.stdout_sha256)
                || !is_lower_sha256(&logs.stderr_sha256)
                || logs.stdout_bytes > MAX_SIGNED_OUTPUT_LOG_BYTES
                || logs.stderr_bytes > MAX_SIGNED_OUTPUT_LOG_BYTES
        })
    {
        return Err(crate::invalid_config(
            "signed invocation record differs from the pinned machine/run/job/candidate/digest/effect/challenge or successful cleanup"
                .to_owned(),
        ));
    }
    let signature_bytes = hex::decode(signature_hex).map_err(|_| {
        crate::invalid_config(
            "invocation observation signature is not valid hexadecimal".to_owned(),
        )
    })?;
    let signature = Signature::from_slice(&signature_bytes).map_err(|_| {
        crate::invalid_config("invocation observation signature has an invalid length".to_owned())
    })?;
    key.verify_strict(
        &record.signing_bytes().map_err(|source| {
            crate::invalid_config(format!(
                "cannot encode canonical Agent invocation observation: {source}"
            ))
        })?,
        &signature,
    )
    .map_err(|_| {
        crate::invalid_config(
            "Agent invocation observation signature verification failed".to_owned(),
        )
    })
}

fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn verify_receipt(
    receipt: &InvocationObservationReceipt,
    key: &VerifyingKey,
    key_hex: &str,
    machine_id: &str,
    expected: &ExpectedInvocation,
) -> AppResult<()> {
    if receipt.schema_version != 1
        || receipt.evidence_class != "observation_only"
        || receipt.protocol != "agent-native-invocation:v1"
        || receipt.release_matrix_v2
        || receipt.machine_id != machine_id
        || receipt.machine_id != expected.machine_id
        || receipt.trusted_public_key_hex != key_hex
    {
        return Err(crate::invalid_config(
            "existing invocation observation receipt metadata is invalid".to_owned(),
        ));
    }
    verify_record(&receipt.record, &receipt.signature_hex, key, expected)
}

fn read_trusted_public_key(path: &Path) -> AppResult<(VerifyingKey, String)> {
    let metadata = fs::symlink_metadata(path).map_err(|source| {
        anyhow::Error::new(source).context("cannot inspect independently pinned public-key file")
    })?;
    if !metadata.file_type().is_file() || metadata.len() > 256 {
        return Err(crate::invalid_config(
            "trusted public-key input must be a small regular non-linked file".to_owned(),
        ));
    }
    let text = fs::read_to_string(path).map_err(|source| {
        anyhow::Error::new(source).context("cannot read independently pinned public-key file")
    })?;
    let key_hex = text.trim().to_ascii_lowercase();
    let key_bytes = hex::decode(&key_hex).map_err(|_| {
        crate::invalid_config("trusted public key must contain 64 hexadecimal digits".to_owned())
    })?;
    let key_bytes: [u8; 32] = key_bytes.try_into().map_err(|_| {
        crate::invalid_config("trusted public key must contain exactly 32 bytes".to_owned())
    })?;
    let key = VerifyingKey::from_bytes(&key_bytes)
        .map_err(|_| crate::invalid_config("trusted Ed25519 public key is invalid".to_owned()))?;
    Ok((key, key_hex))
}

fn read_receipt(path: &Path) -> AppResult<InvocationObservationReceipt> {
    let metadata = fs::symlink_metadata(path).map_err(|source| {
        anyhow::Error::new(source).context("cannot inspect existing invocation observation")
    })?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_RECEIPT_BYTES {
        return Err(crate::invalid_config(
            "existing invocation receipt is not a bounded regular file".to_owned(),
        ));
    }
    hostlink_core::validate_private_file(path).map_err(|source| {
        anyhow::Error::new(source).context("existing invocation receipt is not private")
    })?;
    let bytes = fs::read(path).map_err(|source| {
        anyhow::Error::new(source).context("cannot read existing invocation observation")
    })?;
    serde_json::from_slice(&bytes).map_err(|source| {
        crate::invalid_config(format!(
            "existing invocation receipt is malformed: {source}"
        ))
    })
}

fn require_empty_pending(path: &Path) -> AppResult<()> {
    let metadata = fs::symlink_metadata(path).map_err(|source| {
        anyhow::Error::new(source).context("pending invocation reservation is unavailable")
    })?;
    if !metadata.file_type().is_file() || metadata.len() != 0 {
        return Err(crate::invalid_config(
            "pending invocation reservation is not an empty regular file".to_owned(),
        ));
    }
    hostlink_core::validate_private_file(path).map_err(|source| {
        anyhow::Error::new(source).context("pending invocation reservation is not private")
    })?;
    Ok(())
}

fn remove_empty_pending(path: &Path) -> AppResult<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => {
            require_empty_pending(path)?;
            fs::remove_file(path).map_err(|source| {
                anyhow::Error::new(source)
                    .context("cannot remove completed invocation pending reservation")
            })?;
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => {
            Err(anyhow::Error::new(source)
                .context("cannot inspect completed invocation reservation"))
        }
    }
}

fn publish_receipt_create_new(
    directory: &Path,
    receipt_path: &Path,
    job_id: &str,
    bytes: &[u8],
) -> std::io::Result<()> {
    let temporary_path = directory.join(format!(".{job_id}.{}.tmp", uuid::Uuid::new_v4()));
    hostlink_core::write_new_private_bytes(&temporary_path, bytes)?;
    match fs::hard_link(&temporary_path, receipt_path) {
        Ok(()) => {
            fs::remove_file(temporary_path)?;
            Ok(())
        }
        Err(error) => {
            let _ = fs::remove_file(temporary_path);
            Err(error)
        }
    }
}

fn signer_id(key: &[u8; 32]) -> String {
    format!("{:x}", Sha256::digest(key))
}

fn safe_job_id(job_id: &str) -> bool {
    job_id.starts_with("job-")
        && job_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

fn print_observation(path: &Path, recovered: bool) {
    let state = if recovered { "recovered" } else { "captured" };
    println!(
        "Agent-native invocation {state} as observation only: {}\nThis process observation does not establish Nextest testcase outcomes or satisfy the managed release acceptance receipt.",
        path.display()
    );
}

async fn send_observation_once<F, Fut>(request: F) -> AppResult<AgentResponseKind>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = AppResult<AgentResponseKind>>,
{
    request().await.map_err(|error| {
        error.context(
            "invocation observation request was sent once; outcome may be unknown, do not replay it, and keep the reservation for recover-invocation",
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn fixture() -> (
        SigningKey,
        AgentNativeInvocationRecord,
        String,
        ExpectedInvocation,
    ) {
        let signing = SigningKey::from_bytes(&[17; 32]);
        let signer = signer_id(&signing.verifying_key().to_bytes());
        let record = AgentNativeInvocationRecord {
            schema_version: 1,
            challenge: "fresh-challenge".to_owned(),
            job_id: "job-170-180-1".to_owned(),
            run_id: "0123456789abcdef0123456789abcdef".to_owned(),
            invocation_sha256: "11".repeat(32),
            requested_exact_testcase: Some("requested::case".to_owned()),
            candidate_sha256: "22".repeat(32),
            declared_effect: NativeExecutionEffect::RunOwned,
            host_arch: "x86_64".to_owned(),
            host_os: "linux".to_owned(),
            command_exit_code: 0,
            cleanup_completion: "complete".to_owned(),
            signer_id: signer.clone(),
            observed_windows: None,
            output_logs: None,
            result_set: None,
        };
        let expected = ExpectedInvocation {
            signer_id: signer,
            machine_id: "machine-a".to_owned(),
            run_id: "0123456789abcdef0123456789abcdef".to_owned(),
            job_id: "job-170-180-1".to_owned(),
            candidate_sha256: "22".repeat(32),
            invocation_sha256: "11".repeat(32),
            native_effect: NativeExecutionEffect::RunOwned,
            challenge: "fresh-challenge".to_owned(),
        };
        let signature = signing.sign(&record.signing_bytes().expect("canonical bytes"));
        (signing, record, hex::encode(signature.to_bytes()), expected)
    }

    #[test]
    fn verifies_pinned_signature_and_rejects_wrong_key_and_bound_fields() {
        let (signing, record, signature, expected) = fixture();
        let key = signing.verifying_key();
        assert!(verify_record(&record, &signature, &key, &expected).is_ok());
        let wrong_key = SigningKey::from_bytes(&[18; 32]).verifying_key();
        assert!(verify_record(&record, &signature, &wrong_key, &expected).is_err());

        for mutate in [
            ("challenge", "wrong"),
            ("candidate_sha256", &"33".repeat(32)),
            ("invocation_sha256", &"44".repeat(32)),
            ("job_id", "job-foreign"),
            ("run_id", "1123456789abcdef0123456789abcdef"),
            ("signer_id", "foreign-signer"),
        ] {
            let mut changed = record.clone();
            match mutate.0 {
                "challenge" => changed.challenge = mutate.1.to_owned(),
                "candidate_sha256" => changed.candidate_sha256 = mutate.1.to_owned(),
                "invocation_sha256" => changed.invocation_sha256 = mutate.1.to_owned(),
                "job_id" => changed.job_id = mutate.1.to_owned(),
                "run_id" => changed.run_id = mutate.1.to_owned(),
                "signer_id" => changed.signer_id = mutate.1.to_owned(),
                _ => unreachable!(),
            }
            assert!(verify_record(&changed, &signature, &key, &expected).is_err());
        }

        let mut changed_effect = record.clone();
        changed_effect.declared_effect = NativeExecutionEffect::Disposable;
        assert!(verify_record(&changed_effect, &signature, &key, &expected).is_err());

        let mut changed_filter = record.clone();
        changed_filter.requested_exact_testcase = Some("different::case".to_owned());
        assert!(verify_record(&changed_filter, &signature, &key, &expected).is_err());

        let mut incomplete = record.clone();
        incomplete.cleanup_completion = "partial".to_owned();
        assert!(verify_record(&incomplete, &signature, &key, &expected).is_err());

        let mut failed = record.clone();
        failed.command_exit_code = 1;
        assert!(verify_record(&failed, &signature, &key, &expected).is_err());
    }

    #[test]
    fn exact_signed_receipt_binds_complete_private_stdout_and_stderr_files() {
        let (signing, mut record, _, expected) = fixture();
        let stdout_bytes = b"test stdout\n";
        let stderr_bytes = b"test stderr\n";
        record.output_logs = Some(hostlink_protocol::AgentNativeInvocationOutputLogs {
            stdout_sha256: format!("{:x}", Sha256::digest(stdout_bytes)),
            stdout_bytes: stdout_bytes.len() as u64,
            stderr_sha256: format!("{:x}", Sha256::digest(stderr_bytes)),
            stderr_bytes: stderr_bytes.len() as u64,
        });
        let signature = signing.sign(&record.signing_bytes().expect("canonical bytes"));
        let public_key_hex = hex::encode(signing.verifying_key().to_bytes());
        let receipt = InvocationObservationReceipt {
            schema_version: 1,
            evidence_class: "observation_only".to_owned(),
            protocol: "agent-native-invocation:v1".to_owned(),
            release_matrix_v2: false,
            machine_id: expected.machine_id.clone(),
            record,
            signature_hex: hex::encode(signature.to_bytes()),
            trusted_public_key_hex: public_key_hex.clone(),
        };
        verify_receipt(
            &receipt,
            &signing.verifying_key(),
            &public_key_hex,
            &expected.machine_id,
            &expected,
        )
        .expect("signed receipt and challenge verify");

        let directory = tempfile::tempdir().expect("local log directory");
        let stdout_path = directory.path().join("stdout.log");
        let stderr_path = directory.path().join("stderr.log");
        hostlink_core::write_new_private_bytes(&stdout_path, stdout_bytes).expect("private stdout");
        hostlink_core::write_new_private_bytes(&stderr_path, stderr_bytes).expect("private stderr");
        let signed = signed_output_logs(&receipt).expect("signed log commitments");
        verify_signed_log_files(signed, &stdout_path, &stderr_path)
            .expect("exact stdout and stderr match signed byte commitments");

        let wrong_stderr = directory.path().join("wrong-stderr.log");
        hostlink_core::write_new_private_bytes(&wrong_stderr, b"altered stderr\n")
            .expect("private wrong stderr");
        assert!(verify_signed_log_files(signed, &stdout_path, &wrong_stderr).is_err());
        let mut old_receipt = receipt;
        old_receipt.record.output_logs = None;
        assert!(signed_output_logs(&old_receipt).is_err());
    }

    fn reserve_result_fixture(root: &Path, expected: &ExpectedInvocation) {
        mutable_lease::reserve_durable_run_local(root, &expected.machine_id, &expected.run_id)
            .expect("persist controller run reservation");
        mutable_lease::persist_durable_native_invocation(
            root,
            &expected.machine_id,
            &expected.run_id,
            &expected.candidate_sha256,
            &expected.invocation_sha256,
            expected.native_effect,
        )
        .expect("persist exact invocation context");
        mutable_lease::bind_durable_run_local_job(
            root,
            &expected.machine_id,
            &expected.run_id,
            &expected.job_id,
        )
        .expect("bind controller reservation to job");
    }

    fn persist_signed_result_receipt(
        root: &Path,
        signing: &SigningKey,
        record: AgentNativeInvocationRecord,
        expected: &ExpectedInvocation,
    ) -> PathBuf {
        let signature = signing.sign(&record.signing_bytes().expect("canonical bytes"));
        let receipt = InvocationObservationReceipt {
            schema_version: 1,
            evidence_class: "observation_only".to_owned(),
            protocol: "agent-native-invocation:v1".to_owned(),
            release_matrix_v2: false,
            machine_id: expected.machine_id.clone(),
            record,
            signature_hex: hex::encode(signature.to_bytes()),
            trusted_public_key_hex: hex::encode(signing.verifying_key().to_bytes()),
        };
        let directory = root.join(RECEIPT_DIRECTORY);
        hostlink_core::ensure_private_directory(&directory).expect("private receipt directory");
        let path = directory.join(format!("{}.json", expected.job_id));
        let bytes = serde_json::to_vec(&receipt).expect("encode signed receipt");
        hostlink_core::write_new_private_bytes(&path, &bytes).expect("private signed receipt");
        path
    }

    fn result_set(job_id: &str, name: &str, bytes: &[u8]) -> hostlink_protocol::ResultSetInfo {
        let artifact = hostlink_protocol::ResultArtifactInfo::try_new(
            name.to_owned(),
            bytes.len() as u64,
            format!("{:x}", Sha256::digest(bytes)),
            None,
        )
        .expect("valid result artifact");
        hostlink_protocol::ResultSetInfo::try_new(
            hostlink_protocol::ResultOwner::job(job_id).expect("valid job owner"),
            vec![artifact],
        )
        .expect("valid result set")
    }

    #[test]
    fn offline_result_verifier_binds_signed_result_to_controller_reservation_and_local_bytes() {
        let directory = tempfile::tempdir().expect("controller data root");
        let root = directory.path();
        let (signing, mut record, _, expected) = fixture();
        let bytes = b"JUnit is just an opaque signed artifact\n";
        record.result_set = Some(result_set(&expected.job_id, "results.xml", bytes));
        reserve_result_fixture(root, &expected);
        let key_path = root.join("trusted-key.hex");
        hostlink_core::write_new_private_bytes(
            &key_path,
            hex::encode(signing.verifying_key().to_bytes()).as_bytes(),
        )
        .expect("private independent key");
        persist_signed_result_receipt(root, &signing, record.clone(), &expected);
        let artifact_path = root.join("results.xml");
        hostlink_core::write_new_private_bytes(&artifact_path, bytes).expect("private result file");
        verify_local_result_from_root(
            root,
            &expected.machine_id,
            &expected.run_id,
            &expected.challenge,
            &key_path,
            "results.xml",
            &artifact_path,
        )
        .expect("exact signed result verifies offline");

        let wrong_same_size = root.join("wrong-same-size.xml");
        let mut changed = bytes.to_vec();
        changed[0] ^= 1;
        hostlink_core::write_new_private_bytes(&wrong_same_size, &changed)
            .expect("private tampered result");
        assert!(
            verify_result_file(
                &wrong_same_size,
                bytes.len() as u64,
                &format!("{:x}", Sha256::digest(bytes))
            )
            .is_err()
        );
        assert!(
            verify_local_result_from_root(
                root,
                &expected.machine_id,
                &expected.run_id,
                &expected.challenge,
                &key_path,
                "missing.xml",
                &artifact_path,
            )
            .is_err()
        );

        let wrong_key_path = root.join("wrong-key.hex");
        hostlink_core::write_new_private_bytes(
            &wrong_key_path,
            hex::encode(SigningKey::from_bytes(&[18; 32]).verifying_key().to_bytes()).as_bytes(),
        )
        .expect("private wrong independent key");
        assert!(
            verify_local_result_from_root(
                root,
                &expected.machine_id,
                &expected.run_id,
                &expected.challenge,
                &wrong_key_path,
                "results.xml",
                &artifact_path,
            )
            .is_err()
        );
        assert!(
            verify_local_result_from_root(
                root,
                &expected.machine_id,
                &expected.run_id,
                "different-challenge",
                &key_path,
                "results.xml",
                &artifact_path,
            )
            .is_err()
        );

        for wrong_field in ["candidate", "invocation", "effect"] {
            let wrong_root = tempfile::tempdir().expect("wrong reservation receipt root");
            reserve_result_fixture(wrong_root.path(), &expected);
            let wrong_key = wrong_root.path().join("trusted-key.hex");
            hostlink_core::write_new_private_bytes(
                &wrong_key,
                hex::encode(signing.verifying_key().to_bytes()).as_bytes(),
            )
            .expect("private independent key");
            let mut wrong_record = record.clone();
            match wrong_field {
                "candidate" => wrong_record.candidate_sha256 = "33".repeat(32),
                "invocation" => wrong_record.invocation_sha256 = "44".repeat(32),
                "effect" => wrong_record.declared_effect = NativeExecutionEffect::Disposable,
                _ => unreachable!(),
            }
            persist_signed_result_receipt(wrong_root.path(), &signing, wrong_record, &expected);
            assert!(
                verify_local_result_from_root(
                    wrong_root.path(),
                    &expected.machine_id,
                    &expected.run_id,
                    &expected.challenge,
                    &wrong_key,
                    "results.xml",
                    &artifact_path,
                )
                .is_err(),
                "wrong signed {wrong_field} must not bind to the controller reservation"
            );
        }

        let mut missing_set = record.clone();
        missing_set.result_set = None;
        // Create-new prevents replacing an existing signed receipt, so exercise the legacy
        // signed record using a separate independently reserved fixture root.
        let legacy = tempfile::tempdir().expect("legacy receipt root");
        reserve_result_fixture(legacy.path(), &expected);
        let legacy_key = legacy.path().join("trusted-key.hex");
        hostlink_core::write_new_private_bytes(
            &legacy_key,
            hex::encode(signing.verifying_key().to_bytes()).as_bytes(),
        )
        .expect("private independent key");
        persist_signed_result_receipt(legacy.path(), &signing, missing_set, &expected);
        assert!(
            verify_local_result_from_root(
                legacy.path(),
                &expected.machine_id,
                &expected.run_id,
                &expected.challenge,
                &legacy_key,
                "results.xml",
                &artifact_path,
            )
            .is_err()
        );

        let mut foreign_owner = record.clone();
        foreign_owner.result_set = Some(result_set("job-foreign", "results.xml", bytes));
        let foreign = tempfile::tempdir().expect("foreign owner receipt root");
        reserve_result_fixture(foreign.path(), &expected);
        let foreign_key = foreign.path().join("trusted-key.hex");
        hostlink_core::write_new_private_bytes(
            &foreign_key,
            hex::encode(signing.verifying_key().to_bytes()).as_bytes(),
        )
        .expect("private independent key");
        persist_signed_result_receipt(foreign.path(), &signing, foreign_owner, &expected);
        assert!(
            verify_local_result_from_root(
                foreign.path(),
                &expected.machine_id,
                &expected.run_id,
                &expected.challenge,
                &foreign_key,
                "results.xml",
                &artifact_path,
            )
            .is_err()
        );

        assert!(
            verify_result_file(
                &artifact_path,
                MAX_RESULT_ARTIFACT_BYTES + 1,
                &"0".repeat(64)
            )
            .is_err()
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::{PermissionsExt as _, symlink};
            let public = root.join("public.xml");
            fs::write(&public, bytes).expect("public result");
            fs::set_permissions(&public, fs::Permissions::from_mode(0o644)).expect("public mode");
            assert!(
                verify_result_file(
                    &public,
                    bytes.len() as u64,
                    &format!("{:x}", Sha256::digest(bytes))
                )
                .is_err()
            );
            let link = root.join("linked.xml");
            symlink(&artifact_path, &link).expect("result symlink");
            assert!(
                verify_result_file(
                    &link,
                    bytes.len() as u64,
                    &format!("{:x}", Sha256::digest(bytes))
                )
                .is_err()
            );
        }
    }

    #[test]
    fn offline_verifier_rejects_valid_signature_for_unreserved_candidate() {
        let directory = tempfile::tempdir().expect("controller data root");
        let data_root = directory.path();
        let (signing, mut record, _, expected) = fixture();
        mutable_lease::reserve_durable_run_local(data_root, &expected.machine_id, &expected.run_id)
            .expect("persist controller run reservation");
        mutable_lease::persist_durable_native_invocation(
            data_root,
            &expected.machine_id,
            &expected.run_id,
            &expected.candidate_sha256,
            &expected.invocation_sha256,
            expected.native_effect,
        )
        .expect("persist exact invocation context");
        mutable_lease::bind_durable_run_local_job(
            data_root,
            &expected.machine_id,
            &expected.run_id,
            &expected.job_id,
        )
        .expect("bind controller reservation to job");

        record.candidate_sha256 = "33".repeat(32);
        let empty_hash = format!("{:x}", Sha256::digest(b""));
        record.output_logs = Some(hostlink_protocol::AgentNativeInvocationOutputLogs {
            stdout_sha256: empty_hash.clone(),
            stdout_bytes: 0,
            stderr_sha256: empty_hash,
            stderr_bytes: 0,
        });
        let signature = signing.sign(&record.signing_bytes().expect("canonical bytes"));
        let public_key_hex = hex::encode(signing.verifying_key().to_bytes());
        let receipt = InvocationObservationReceipt {
            schema_version: 1,
            evidence_class: "observation_only".to_owned(),
            protocol: "agent-native-invocation:v1".to_owned(),
            release_matrix_v2: false,
            machine_id: expected.machine_id.clone(),
            record,
            signature_hex: hex::encode(signature.to_bytes()),
            trusted_public_key_hex: public_key_hex.clone(),
        };
        let receipt_directory = data_root.join(RECEIPT_DIRECTORY);
        hostlink_core::ensure_private_directory(&receipt_directory)
            .expect("private observation receipt directory");
        hostlink_core::write_new_private_bytes(
            &receipt_directory.join(format!("{}.json", expected.job_id)),
            &serde_json::to_vec(&receipt).expect("encode signed receipt"),
        )
        .expect("private observation receipt");

        let key_path = data_root.join("pinned-key.hex");
        hostlink_core::write_new_private_bytes(&key_path, public_key_hex.as_bytes())
            .expect("persist operator-pinned key fixture");
        let stdout_path = data_root.join("stdout.log");
        let stderr_path = data_root.join("stderr.log");
        hostlink_core::write_new_private_bytes(&stdout_path, b"").expect("private stdout fixture");
        hostlink_core::write_new_private_bytes(&stderr_path, b"").expect("private stderr fixture");

        assert!(
            verify_local_logs_from_root(
                data_root,
                &expected.machine_id,
                &expected.run_id,
                &expected.challenge,
                &key_path,
                &stdout_path,
                &stderr_path,
            )
            .is_err()
        );
    }

    #[test]
    fn local_log_reader_rejects_symlinks_oversize_truncation_and_non_private_files() {
        let directory = tempfile::tempdir().expect("local log directory");
        let file = directory.path().join("log");
        hostlink_core::write_new_private_bytes(&file, b"complete").expect("private log");
        assert_eq!(
            read_stable_private_log(&file, "stdout")
                .expect("complete log")
                .0,
            8
        );

        let truncated = directory.path().join("truncated");
        hostlink_core::write_new_private_bytes(&truncated, b"short")
            .expect("private truncated log");
        let signed = hostlink_protocol::AgentNativeInvocationOutputLogs {
            stdout_sha256: format!("{:x}", Sha256::digest(b"complete")),
            stdout_bytes: 8,
            stderr_sha256: format!("{:x}", Sha256::digest(b"")),
            stderr_bytes: 0,
        };
        let empty_stderr = directory.path().join("empty-stderr");
        hostlink_core::write_new_private_bytes(&empty_stderr, b"").expect("private empty stderr");
        assert!(verify_signed_log_files(&signed, &truncated, &empty_stderr).is_err());

        let oversized = directory.path().join("oversized");
        let oversized_file = hostlink_core::create_new_private_file(&oversized)
            .expect("create private oversized file");
        oversized_file
            .set_len(MAX_SIGNED_OUTPUT_LOG_BYTES + 1)
            .expect("grow oversized fixture");
        drop(oversized_file);
        assert!(read_stable_private_log(&oversized, "stdout").is_err());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let public = directory.path().join("public");
            fs::write(&public, b"bytes").expect("write public mode fixture");
            fs::set_permissions(&public, fs::Permissions::from_mode(0o644))
                .expect("set public mode");
            assert!(read_stable_private_log(&public, "stdout").is_err());
            let link = directory.path().join("linked");
            std::os::unix::fs::symlink(&file, &link).expect("create symlink fixture");
            assert!(read_stable_private_log(&link, "stdout").is_err());
        }
    }

    #[test]
    fn rejects_malformed_or_oversized_signed_output_commitments() {
        let (signing, mut record, _, expected) = fixture();
        for output_logs in [
            hostlink_protocol::AgentNativeInvocationOutputLogs {
                stdout_sha256: "A".repeat(64),
                stdout_bytes: 0,
                stderr_sha256: "0".repeat(64),
                stderr_bytes: 0,
            },
            hostlink_protocol::AgentNativeInvocationOutputLogs {
                stdout_sha256: "0".repeat(64),
                stdout_bytes: MAX_SIGNED_OUTPUT_LOG_BYTES + 1,
                stderr_sha256: "0".repeat(64),
                stderr_bytes: 0,
            },
        ] {
            record.output_logs = Some(output_logs);
            let signature = signing.sign(&record.signing_bytes().expect("canonical bytes"));
            assert!(
                verify_record(
                    &record,
                    &hex::encode(signature.to_bytes()),
                    &signing.verifying_key(),
                    &expected,
                )
                .is_err()
            );
        }
    }

    #[test]
    fn rejects_signed_windows_facts_that_conflict_with_host_identity() {
        let (signing, mut record, _, expected) = fixture();
        record.host_os = "windows".to_owned();
        record.observed_windows = Some(hostlink_protocol::ObservedWindowsFacts {
            os_major: 6,
            os_minor: 1,
            os_build: 7601,
            process_architecture: hostlink_protocol::WindowsArchitecture::X86,
            native_architecture: hostlink_protocol::WindowsArchitecture::X86_64,
            process_is_wow64: true,
        });
        let signature = signing.sign(&record.signing_bytes().expect("canonical bytes"));
        assert!(
            verify_record(
                &record,
                &hex::encode(signature.to_bytes()),
                &signing.verifying_key(),
                &expected,
            )
            .is_err()
        );

        record.host_arch = "x86".to_owned();
        record.host_os = "linux".to_owned();
        let signature = signing.sign(&record.signing_bytes().expect("canonical bytes"));
        assert!(
            verify_record(
                &record,
                &hex::encode(signature.to_bytes()),
                &signing.verifying_key(),
                &expected,
            )
            .is_err()
        );
    }

    #[test]
    fn requires_exact_successful_job_and_completed_controller_results() {
        let (_, record, _, expected) = fixture();
        let job = AgentJobInfo {
            job_id: expected.job_id.clone(),
            state: AgentJobState::Succeeded,
            worker_pid: None,
            spawn_owner_pid: None,
            process_pid: None,
            exit_code: Some(0),
            created_unix_ms: 1,
            started_unix_ms: Some(2),
            finished_unix_ms: Some(3),
            message: None,
            stdout_log_truncated: false,
            stderr_log_truncated: false,
            result_set: None,
            run_local: Some(
                hostlink_protocol::RunLocalJobIdentity::try_new(
                    expected.run_id.clone(),
                    format!("sha256-{}.exe", expected.candidate_sha256),
                    expected.candidate_sha256.clone(),
                    Vec::new(),
                )
                .expect("fixture run identity"),
            ),
        };
        validate_eligible_job(
            &job,
            &expected.run_id,
            &expected.job_id,
            &expected.candidate_sha256,
        )
        .expect("exact successful source-bound job");
        require_results_complete(true).expect("controller results cleaned");
        assert!(require_results_complete(false).is_err());

        let mut foreign = job.clone();
        foreign.job_id = "job-foreign".to_owned();
        assert!(
            validate_eligible_job(
                &foreign,
                &expected.run_id,
                &expected.job_id,
                &expected.candidate_sha256
            )
            .is_err()
        );
        let mut failed = job.clone();
        failed.state = AgentJobState::Failed;
        assert!(
            validate_eligible_job(
                &failed,
                &expected.run_id,
                &expected.job_id,
                &expected.candidate_sha256
            )
            .is_err()
        );
        let mut stale_binary = job;
        stale_binary.run_local = Some(
            hostlink_protocol::RunLocalJobIdentity::try_new(
                expected.run_id.clone(),
                format!("sha256-{}.exe", "33".repeat(32)),
                "33".repeat(32),
                Vec::new(),
            )
            .expect("stale but structurally valid candidate identity"),
        );
        assert!(
            validate_eligible_job(
                &stale_binary,
                &expected.run_id,
                &expected.job_id,
                &expected.candidate_sha256
            )
            .is_err()
        );

        let receipt = InvocationObservationReceipt {
            schema_version: 1,
            evidence_class: "observation_only".to_owned(),
            protocol: "agent-native-invocation:v1".to_owned(),
            release_matrix_v2: false,
            machine_id: expected.machine_id.clone(),
            record,
            signature_hex: String::new(),
            trusted_public_key_hex: String::new(),
        };
        let encoded = serde_json::to_string(&receipt).expect("encode observation receipt");
        assert!(encoded.contains("observation_only"));
        assert!(encoded.contains("\"release_matrix_v2\":false"));
        assert!(!encoded.contains("SignedNativePairReport"));
    }

    #[tokio::test]
    async fn ambiguous_observation_request_is_never_replayed() {
        let requests = AtomicUsize::new(0);
        let result = send_observation_once(|| {
            requests.fetch_add(1, Ordering::SeqCst);
            async { Err(crate::invalid_config("connection reset".to_owned())) }
        })
        .await;
        assert!(result.is_err());
        assert_eq!(requests.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn receipt_publication_is_private_create_new_and_does_not_overwrite() {
        let directory = tempfile::tempdir().expect("receipt directory");
        let receipt = directory.path().join("job-170-180-1.json");
        publish_receipt_create_new(
            directory.path(),
            &receipt,
            "job-170-180-1",
            b"first verified receipt",
        )
        .expect("publish first receipt");
        hostlink_core::validate_private_file(&receipt).expect("receipt is private");
        assert_eq!(
            fs::read(&receipt).expect("read receipt"),
            b"first verified receipt"
        );
        assert!(
            publish_receipt_create_new(
                directory.path(),
                &receipt,
                "job-170-180-1",
                b"replacement receipt",
            )
            .is_err()
        );
        assert_eq!(
            fs::read(&receipt).expect("receipt remains unchanged"),
            b"first verified receipt"
        );
    }

    #[test]
    fn recovery_requires_an_existing_private_empty_pending_marker() {
        let directory = tempfile::tempdir().expect("recovery directory");
        let pending = directory.path().join("job-170-180-1.pending");
        assert!(require_empty_pending(&pending).is_err());
        let file = hostlink_core::create_new_private_file(&pending).expect("create private marker");
        drop(file);
        require_empty_pending(&pending).expect("empty private marker enables read-only fetch");
        fs::write(&pending, b"unexpected content").expect("corrupt marker");
        assert!(require_empty_pending(&pending).is_err());
    }
}
