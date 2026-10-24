//! Collection and controller verification of one agent-native terminal observation.

use super::{mutable_lease, run_local_job, *};
use ed25519_dalek::{Signature, VerifyingKey};
use onec_agent_protocol::{
    AgentJobInfo, AgentJobState, AgentRequestKind, AgentResponseKind, AgentTerminalExecutionRecord,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::{fs, path::Path};

const RECEIPT_DIRECTORY: &str = "native-attestation-observations";
const MAX_RECEIPT_BYTES: u64 = 64 * 1024;

#[derive(Clone, Copy)]
struct ExpectedAttestation<'a> {
    signer_id: &'a str,
    run_id: &'a str,
    job_id: &'a str,
    candidate_sha256: &'a str,
    challenge: &'a str,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ObservationReceipt {
    schema_version: u32,
    evidence_class: String,
    protocol: String,
    release_matrix_v2: bool,
    machine_id: String,
    record: AgentTerminalExecutionRecord,
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
            "native attestation challenge must contain 1..=128 bytes".to_owned(),
        ));
    }
    let (trusted_key, trusted_key_hex) = read_trusted_public_key(trusted_public_key_path)?;
    let trusted_signer_id = signer_id(&trusted_key.to_bytes());
    let data_root = super::run_local_job::controller_data_root()?;
    let (machine_id, _hub, client) = run_local_job::resolve(target).await?;
    let controller_lease =
        mutable_lease::acquire_durable_run_local_operation_lease(&data_root, &machine_id)?;

    // Attestation is destructive at the Agent: it removes this run workspace exactly once.
    // Require the controller's already-bound identity and completed result cleanup first.
    let reserved_job_id = mutable_lease::durable_run_local_job_id(&data_root, &machine_id, run_id)?;
    require_results_complete(mutable_lease::durable_run_local_results_complete(
        &data_root,
        &machine_id,
        run_id,
    )?)?;
    let job = match client.run_local_status(run_id.to_owned()).await? {
        AgentResponseKind::JobStatus { job } => job,
        _ => {
            return Err(crate::invalid_config(
                "agent returned an unexpected durable run-local status response".to_owned(),
            ));
        }
    };
    if !job
        .run_local
        .as_ref()
        .is_some_and(|identity| identity.run_id() == run_id)
        || job.job_id != reserved_job_id
    {
        return Err(crate::invalid_config(
            "Agent run status does not match the controller's exact durable job reservation"
                .to_owned(),
        ));
    }
    let candidate_sha256 = validate_eligible_job(&job, run_id, &reserved_job_id)?;
    let expected = ExpectedAttestation {
        signer_id: &trusted_signer_id,
        run_id,
        job_id: &reserved_job_id,
        candidate_sha256: &candidate_sha256,
        challenge,
    };

    let receipt_dir = data_root.join(RECEIPT_DIRECTORY);
    hostlink_core::ensure_private_directory(&receipt_dir).map_err(|source| {
        anyhow::Error::new(source).context("cannot secure native attestation receipt directory")
    })?;
    let receipt_path = receipt_dir.join(format!("{reserved_job_id}.json"));
    let pending_path = receipt_dir.join(format!("{reserved_job_id}.pending.json"));

    // A saved verified observation can finish a previously interrupted local release without
    // another Agent request. Otherwise, the caller chooses one signing request or read-only recovery.
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
            // Finish owned local cleanup before releasing the controller reservation.
            // A failure must remain recoverable without replaying an Agent mutation.
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
                .context("cannot inspect native attestation receipt destination"));
        }
    }

    if recovery_only {
        require_empty_pending(&pending_path)?;
    } else {
        match fs::symlink_metadata(&pending_path) {
            Ok(_) => {
                return Err(crate::invalid_config(
                    "a pending attestation reservation already exists; use `run-local-job recover-attest` and do not replay signing"
                        .to_owned(),
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(anyhow::Error::new(source)
                    .context("cannot inspect native attestation pending reservation"));
            }
        }
    }

    let response = if recovery_only {
        client
            .request(attestation_request(&reserved_job_id, challenge, true))
            .await?
    } else {
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
                "agent native attestation key does not match the independently pinned public key"
                    .to_owned(),
            ));
        }
        // Reserve only after the read-only key check, and before the one-shot cleanup/sign RPC.
        // This keeps harmless preflight failures retryable without making signing replayable.
        let pending = hostlink_core::create_new_private_file(&pending_path).map_err(|source| {
            anyhow::Error::new(source)
                .context("cannot reserve create-new native attestation before one-shot RPC")
        })?;
        pending.sync_all().map_err(|source| {
            anyhow::Error::new(source)
                .context("cannot durably flush native attestation reservation")
        })?;
        drop(pending);
        send_irreversible_attestation_once(|| {
            client.request(attestation_request(&reserved_job_id, challenge, false))
        })
        .await?
    };
    let (record, signature_hex) = match (recovery_only, response) {
        (
            false,
            AgentResponseKind::NativeExecutionAttestation {
                record,
                signature_hex,
            },
        )
        | (
            true,
            AgentResponseKind::NativeExecutionAttestationFetched {
                record,
                signature_hex,
            },
        ) => (record, signature_hex),
        _ => {
            return Err(crate::invalid_config(
                "agent returned an unexpected native execution attestation response; reservation remains active"
                    .to_owned(),
            ));
        }
    };
    verify_record(&record, &signature_hex, &trusted_key, &expected)?;

    let receipt = ObservationReceipt {
        schema_version: 1,
        evidence_class: "observation_only".to_owned(),
        protocol: "agent-native:v1".to_owned(),
        release_matrix_v2: false,
        machine_id: machine_id.clone(),
        record,
        signature_hex,
        trusted_public_key_hex: trusted_key_hex,
    };
    let bytes = serde_json::to_vec_pretty(&receipt).map_err(|source| {
        crate::invalid_config(format!("cannot encode attestation receipt: {source}"))
    })?;
    publish_receipt_create_new(&receipt_dir, &receipt_path, &reserved_job_id, &bytes).map_err(|source| {
        anyhow::Error::new(source).context(
            "verified agent attestation was received but the atomic private receipt was not saved; reservation remains active",
        )
    })?;

    // Do not release mutable-target admission until the verified observation is
    // stored and its pending marker is removed. Otherwise a failed local cleanup
    // would strand the marker after the reservation is irreversibly released.
    remove_empty_pending(&pending_path)?;
    drop(controller_lease);
    mutable_lease::release_durable_run_local(&data_root, &machine_id, run_id, &reserved_job_id)?;
    print_observation(&receipt_path, recovery_only);
    Ok(())
}

fn attestation_request(job_id: &str, challenge: &str, recovery_only: bool) -> AgentRequestKind {
    if recovery_only {
        AgentRequestKind::RunLocalAttestationFetch {
            job_id: job_id.to_owned(),
            challenge: challenge.to_owned(),
        }
    } else {
        AgentRequestKind::RunLocalAttest {
            job_id: job_id.to_owned(),
            challenge: challenge.to_owned(),
        }
    }
}

fn validate_eligible_job(job: &AgentJobInfo, run_id: &str, job_id: &str) -> AppResult<String> {
    if !safe_job_id(job_id) || job.job_id != job_id {
        return Err(crate::invalid_config(
            "durable run-local job identity is invalid or mismatched".to_owned(),
        ));
    }
    let identity = job
        .run_local
        .as_ref()
        .filter(|identity| identity.run_id() == run_id)
        .ok_or_else(|| {
            crate::invalid_config(
                "Agent job does not match the requested source-exact run identity".to_owned(),
            )
        })?;
    if job.state != AgentJobState::Succeeded
        || job.exit_code != Some(0)
        || job.finished_unix_ms.is_none()
    {
        return Err(crate::invalid_config(
            "native attestation requires a terminal succeeded job with exit code 0".to_owned(),
        ));
    }
    Ok(identity.candidate_sha256().to_owned())
}

fn require_results_complete(complete: bool) -> AppResult<()> {
    if !complete {
        return Err(crate::invalid_config(
            "retrieve and clean durable run-local results before requesting native attestation"
                .to_owned(),
        ));
    }
    Ok(())
}

fn verify_record(
    record: &AgentTerminalExecutionRecord,
    signature_hex: &str,
    key: &VerifyingKey,
    expected: &ExpectedAttestation<'_>,
) -> AppResult<()> {
    if record.schema_version != 1
        || record.signer_id != expected.signer_id
        || record.run_id != expected.run_id
        || record.job_id != expected.job_id
        || record.candidate_sha256 != expected.candidate_sha256
        || record.challenge != expected.challenge
        || record.command_completion != "succeeded"
        || record.command_exit_code != 0
        || record.cleanup_completion != "complete"
    {
        return Err(crate::invalid_config(
            "agent terminal attestation fields do not match the verified run, candidate, challenge, and signer"
                .to_owned(),
        ));
    }
    let signature_bytes = hex::decode(signature_hex).map_err(|_| {
        crate::invalid_config("agent attestation signature is not valid hexadecimal".to_owned())
    })?;
    let signature = Signature::from_slice(&signature_bytes).map_err(|_| {
        crate::invalid_config("agent attestation signature has an invalid length".to_owned())
    })?;
    key.verify_strict(
        &record.signing_bytes().map_err(|source| {
            crate::invalid_config(format!(
                "cannot encode canonical agent attestation: {source}"
            ))
        })?,
        &signature,
    )
    .map_err(|_| {
        crate::invalid_config("agent attestation signature verification failed".to_owned())
    })
}

fn verify_receipt(
    receipt: &ObservationReceipt,
    key: &VerifyingKey,
    key_hex: &str,
    machine_id: &str,
    expected: &ExpectedAttestation<'_>,
) -> AppResult<()> {
    if receipt.schema_version != 1
        || receipt.evidence_class != "observation_only"
        || receipt.protocol != "agent-native:v1"
        || receipt.release_matrix_v2
        || receipt.machine_id != machine_id
        || receipt.trusted_public_key_hex != key_hex
    {
        return Err(crate::invalid_config(
            "existing native attestation receipt metadata is invalid".to_owned(),
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

fn read_receipt(path: &Path) -> AppResult<ObservationReceipt> {
    let metadata = fs::symlink_metadata(path).map_err(|source| {
        anyhow::Error::new(source).context("cannot inspect existing attestation observation")
    })?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_RECEIPT_BYTES {
        return Err(crate::invalid_config(
            "existing native attestation receipt is not a bounded regular file".to_owned(),
        ));
    }
    let bytes = fs::read(path).map_err(|source| {
        anyhow::Error::new(source).context("cannot read existing attestation observation")
    })?;
    serde_json::from_slice(&bytes).map_err(|source| {
        crate::invalid_config(format!(
            "existing native attestation receipt is malformed: {source}"
        ))
    })
}

fn require_empty_pending(path: &Path) -> AppResult<()> {
    let metadata = fs::symlink_metadata(path).map_err(|source| {
        anyhow::Error::new(source).context("pending attestation reservation is unavailable")
    })?;
    if !metadata.file_type().is_file() || metadata.len() != 0 {
        return Err(crate::invalid_config(
            "pending attestation reservation is not an empty regular file".to_owned(),
        ));
    }
    hostlink_core::validate_private_file(path).map_err(|source| {
        anyhow::Error::new(source).context("pending attestation reservation is not private")
    })?;
    Ok(())
}

fn remove_empty_pending(path: &Path) -> AppResult<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => {
            require_empty_pending(path)?;
            fs::remove_file(path).map_err(|source| {
                anyhow::Error::new(source)
                    .context("cannot remove completed empty attestation reservation")
            })?;
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => {
            Err(anyhow::Error::new(source)
                .context("cannot inspect completed attestation reservation"))
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
            // The destination is create-new. Never replace an existing receipt, even if malformed.
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
        "Agent-native terminal attestation {state} as observation only: {}\nThis process observation does not establish Nextest testcase outcomes or satisfy the managed release acceptance receipt.",
        path.display()
    );
}

async fn send_irreversible_attestation_once<F, Fut>(request: F) -> AppResult<AgentResponseKind>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = AppResult<AgentResponseKind>>,
{
    request().await.map_err(|error| {
        error.context(
            "native attestation request was sent once; target outcome may be unknown, do not replay it, and keep the controller reservation for recovery",
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use onec_agent_protocol::{RunLocalJobIdentity, RunLocalMappedFile};
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn fixture() -> (SigningKey, AgentTerminalExecutionRecord, String) {
        let signing = SigningKey::from_bytes(&[7; 32]);
        let signer = signer_id(&signing.verifying_key().to_bytes());
        let record = AgentTerminalExecutionRecord {
            schema_version: 1,
            challenge: "challenge-a".to_owned(),
            job_id: "job-10-20-1".to_owned(),
            run_id: "0123456789abcdef0123456789abcdef".to_owned(),
            candidate_sha256: "ab".repeat(32),
            command_completion: "succeeded".to_owned(),
            command_exit_code: 0,
            cleanup_completion: "complete".to_owned(),
            signer_id: signer,
        };
        let signature = signing.sign(&record.signing_bytes().expect("canonical bytes"));
        (signing, record, hex::encode(signature.to_bytes()))
    }

    #[test]
    fn verifies_canonical_record_and_rejects_wrong_signer_key_challenge_and_digest() {
        let (signing, record, signature) = fixture();
        let key = signing.verifying_key();
        let expected = ExpectedAttestation {
            signer_id: &record.signer_id,
            run_id: &record.run_id,
            job_id: &record.job_id,
            candidate_sha256: &record.candidate_sha256,
            challenge: &record.challenge,
        };
        assert!(verify_record(&record, &signature, &key, &expected).is_ok());

        let mut wrong_signer = record.clone();
        wrong_signer.signer_id = "00".repeat(32);
        let wrong_signer_expected = ExpectedAttestation {
            signer_id: &record.signer_id,
            ..expected
        };
        assert!(verify_record(&wrong_signer, &signature, &key, &wrong_signer_expected).is_err());
        let wrong_key = SigningKey::from_bytes(&[8; 32]).verifying_key();
        assert!(verify_record(&record, &signature, &wrong_key, &expected).is_err());
        let wrong_challenge = ExpectedAttestation {
            challenge: "other-challenge",
            ..expected
        };
        assert!(verify_record(&record, &signature, &key, &wrong_challenge).is_err());
        let wrong_digest = ExpectedAttestation {
            candidate_sha256: "cd",
            ..expected
        };
        assert!(verify_record(&record, &signature, &key, &wrong_digest).is_err());
    }

    #[test]
    fn eligibility_requires_succeeded_zero_exit_and_results_cleanup_marker() {
        let identity = RunLocalJobIdentity::try_new(
            "0123456789abcdef0123456789abcdef".to_owned(),
            format!("sha256-{}.exe", "ab".repeat(32)),
            "ab".repeat(32),
            Vec::<RunLocalMappedFile>::new(),
        )
        .expect("valid identity");
        let mut job = AgentJobInfo {
            job_id: "job-10-20-1".to_owned(),
            state: AgentJobState::Succeeded,
            worker_pid: None,
            spawn_owner_pid: None,
            process_pid: None,
            exit_code: Some(0),
            created_unix_ms: 1,
            started_unix_ms: Some(10),
            finished_unix_ms: Some(20),
            message: None,
            stdout_log_truncated: false,
            stderr_log_truncated: false,
            result_set: None,
            run_local: Some(identity),
        };
        assert!(
            validate_eligible_job(&job, "0123456789abcdef0123456789abcdef", "job-10-20-1").is_ok()
        );
        job.state = AgentJobState::Failed;
        assert!(
            validate_eligible_job(&job, "0123456789abcdef0123456789abcdef", "job-10-20-1").is_err()
        );
        job.state = AgentJobState::Running;
        assert!(
            validate_eligible_job(&job, "0123456789abcdef0123456789abcdef", "job-10-20-1").is_err()
        );
        job.state = AgentJobState::Succeeded;
        job.exit_code = Some(1);
        assert!(
            validate_eligible_job(&job, "0123456789abcdef0123456789abcdef", "job-10-20-1").is_err()
        );
        assert!(require_results_complete(false).is_err());
        assert!(require_results_complete(true).is_ok());
    }

    #[test]
    fn receipt_creation_is_create_new_and_preserves_original() {
        let dir = tempfile::tempdir().expect("tempdir");
        hostlink_core::ensure_private_directory(dir.path()).expect("private directory");
        let path = dir.path().join("job-10-20-1.json");
        publish_receipt_create_new(dir.path(), &path, "job-10-20-1", b"first")
            .expect("atomically publish receipt");
        assert!(publish_receipt_create_new(dir.path(), &path, "job-10-20-1", b"second").is_err());
        assert_eq!(fs::read(path).expect("read receipt"), b"first");
    }

    #[test]
    fn recovery_requires_an_existing_empty_private_reservation_and_preserves_foreign_data() {
        let dir = tempfile::tempdir().expect("tempdir");
        hostlink_core::ensure_private_directory(dir.path()).expect("private directory");
        let path = dir.path().join("job-10-20-1.pending.json");
        assert!(
            require_empty_pending(&path).is_err(),
            "missing is not a reservation"
        );
        hostlink_core::write_new_private_bytes(&path, b"").expect("create empty reservation");
        require_empty_pending(&path).expect("empty private reservation is recoverable");
        fs::write(&path, b"foreign evidence").expect("make marker non-empty");
        hostlink_core::restrict_private_file(&path).expect("keep marker private");
        assert!(require_empty_pending(&path).is_err());
        assert!(remove_empty_pending(&path).is_err());
        assert_eq!(
            fs::read(path).expect("foreign evidence preserved"),
            b"foreign evidence"
        );
    }

    #[tokio::test]
    async fn ambiguous_attestation_request_is_never_replayed() {
        let requests = AtomicUsize::new(0);
        let result = send_irreversible_attestation_once(|| {
            requests.fetch_add(1, Ordering::SeqCst);
            async { Err(crate::invalid_config("connection reset".to_owned())) }
        })
        .await;
        assert!(result.is_err());
        assert_eq!(requests.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn recovery_request_is_read_only_and_attest_is_used_only_for_initial_collection() {
        assert!(matches!(
            attestation_request("job-10-20-1", "challenge-a", true),
            AgentRequestKind::RunLocalAttestationFetch { .. }
        ));
        assert!(matches!(
            attestation_request("job-10-20-1", "challenge-a", false),
            AgentRequestKind::RunLocalAttest { .. }
        ));
    }
}
