//! Dedicated host-native execution attestation key and terminal run-local signing.

use ed25519_dalek::{Signature, Signer, SigningKey};
use onec_agent_protocol::{
    AgentJobState, AgentNativeInvocationOutputLogs, AgentNativeInvocationRecord,
    AgentTerminalExecutionRecord,
};
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{self, Read};
use std::path::Path;

const KEY_DIR: &str = "native-attestation-v1";
const KEY_FILE: &str = "ed25519.key";
const MAX_ATTESTATION_BYTES: u64 = 64 * 1024;
const INVOCATION_RECORD_DIR: &str = "native-invocation-observations";

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredAttestation {
    record: AgentTerminalExecutionRecord,
    signature_hex: String,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredInvocationObservation {
    record: AgentNativeInvocationRecord,
    signature_hex: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredInvocationOutputCommitment {
    schema_version: u32,
    job_id: String,
    run_id: String,
    invocation_sha256: String,
    output_logs: AgentNativeInvocationOutputLogs,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    result_set: Option<onec_agent_protocol::ResultSetInfo>,
}

/// Signs an Agent-observed successful run-local invocation after scoped workspace removal.
pub(crate) fn observe_run_local_invocation(
    jobs_root: &Path,
    job_id: &str,
    challenge: &str,
    expected_invocation_sha256: &str,
) -> io::Result<(AgentNativeInvocationRecord, String)> {
    validate_invocation_request(job_id, challenge, expected_invocation_sha256)?;
    let first = super::jobs::status(jobs_root, job_id)?;
    let first_identity = first
        .run_local
        .as_ref()
        .ok_or_else(|| invalid("invocation observation requires run-local job ownership"))?;
    let _ownership = super::jobs::lock_run_local_identity(jobs_root, first_identity.run_id())?;
    let job = super::jobs::status(jobs_root, job_id)?;
    let identity = job
        .run_local
        .as_ref()
        .ok_or_else(|| invalid("invocation observation requires run-local job ownership"))?;
    validate_invocation_job(&first, &job, first_identity.run_id(), challenge)?;
    validate_candidate_bytes(jobs_root, identity)?;
    let commitment = read_invocation_commitment(jobs_root, job_id)?;
    if commitment.version != 1 || commitment.invocation_sha256 != expected_invocation_sha256 {
        return Err(invalid(
            "requested invocation digest differs from the immutable pre-spawn commitment",
        ));
    }
    let requested_exact_testcase = commitment.requested_exact_testcase.clone();
    if job.result_set.is_some() && !super::results::job_result_set_cleaned(jobs_root, job_id)? {
        return Err(invalid(
            "invocation observation requires declared results to be retrieved and cleaned",
        ));
    }
    let output_logs = read_complete_invocation_output_logs(jobs_root, job_id, &job)?;
    let worker_commitment = read_completed_invocation_output_commitment(
        jobs_root,
        &job,
        &commitment.invocation_sha256,
    )?;
    if worker_commitment.output_logs != output_logs {
        return Err(invalid(
            "Agent-owned invocation output logs differ from the worker completion commitment",
        ));
    }
    validate_result_set_commitment(&job, &commitment.results)?;
    if worker_commitment.result_set != job.result_set {
        return Err(invalid(
            "Agent-owned result manifest differs from worker completion commitment",
        ));
    }
    let observed_windows = observed_windows_facts()?;

    let key = load_or_create_key(jobs_root)?;
    let directory = jobs_root.join(KEY_DIR).join(INVOCATION_RECORD_DIR);
    ensure_private_directory(&directory)?;
    let record_path = directory.join(format!("{job_id}.json"));
    match fs::symlink_metadata(&record_path) {
        Ok(_) => {
            return Err(invalid(
                "invocation observation already exists for this job",
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }

    let workspace_parent = jobs_root.join("run-local-runs");
    let workspace = workspace_parent.join(identity.run_id());
    let removed = hostlink_core::remove_path_scoped(&workspace_parent, &workspace, true, false)?;
    if !removed {
        return Err(invalid(
            "invocation observation requires owned workspace cleanup to complete",
        ));
    }
    if read_complete_invocation_output_logs(jobs_root, job_id, &job)? != output_logs {
        return Err(invalid(
            "Agent-owned invocation output logs changed during signing",
        ));
    }

    let verifying_key = key.verifying_key().to_bytes();
    let record = AgentNativeInvocationRecord {
        schema_version: 1,
        challenge: challenge.to_owned(),
        job_id: job.job_id.clone(),
        run_id: identity.run_id().to_owned(),
        invocation_sha256: expected_invocation_sha256.to_owned(),
        requested_exact_testcase,
        candidate_sha256: identity.candidate_sha256().to_owned(),
        declared_effect: commitment.native_effect,
        host_arch: std::env::consts::ARCH.to_owned(),
        host_os: std::env::consts::OS.to_owned(),
        command_exit_code: 0,
        cleanup_completion: "complete".to_owned(),
        signer_id: signer_id(&verifying_key),
        observed_windows,
        output_logs: Some(output_logs.clone()),
        result_set: job.result_set.clone(),
    };
    let signature = key
        .sign(&record.signing_bytes().map_err(io::Error::other)?)
        .to_bytes();
    let signature_hex = hex(&signature);
    if read_complete_invocation_output_logs(jobs_root, job_id, &job)? != output_logs {
        return Err(invalid(
            "Agent-owned invocation output logs changed during signing",
        ));
    }
    let envelope = serde_json::json!({
        "record": &record,
        "signature_hex": &signature_hex,
    });
    hostlink_core::write_new_private_bytes(&record_path, &serde_json::to_vec(&envelope)?)?;
    Ok((record, signature_hex))
}

#[cfg(windows)]
fn observed_windows_facts() -> io::Result<Option<onec_agent_protocol::ObservedWindowsFacts>> {
    use onec_agent_protocol::{ObservedWindowsFacts, WindowsArchitecture};
    use std::mem::size_of;
    use windows_sys::Wdk::System::SystemServices::RtlGetVersion;
    use windows_sys::Win32::System::{
        SystemInformation::{
            GetNativeSystemInfo, GetSystemInfo, OSVERSIONINFOW, PROCESSOR_ARCHITECTURE_AMD64,
            PROCESSOR_ARCHITECTURE_INTEL, SYSTEM_INFO,
        },
        Threading::{GetCurrentProcess, IsWow64Process},
    };

    fn architecture(value: u16) -> io::Result<WindowsArchitecture> {
        match value {
            PROCESSOR_ARCHITECTURE_INTEL => Ok(WindowsArchitecture::X86),
            PROCESSOR_ARCHITECTURE_AMD64 => Ok(WindowsArchitecture::X86_64),
            _ => Err(invalid(
                "Windows reported an unsupported processor architecture",
            )),
        }
    }

    let mut version = OSVERSIONINFOW::default();
    version.dwOSVersionInfoSize =
        u32::try_from(size_of::<OSVERSIONINFOW>()).map_err(io::Error::other)?;
    // SAFETY: `version` is a writable, correctly sized OSVERSIONINFOW as required by RtlGetVersion.
    let status = unsafe { RtlGetVersion(&mut version) };
    if status != 0
        || version.dwPlatformId != 2
        || version.dwMajorVersion < 6
        || version.dwBuildNumber == 0
    {
        return Err(invalid(
            "Windows kernel version could not be read unambiguously",
        ));
    }

    let mut process_info = SYSTEM_INFO::default();
    let mut native_info = SYSTEM_INFO::default();
    // SAFETY: both calls initialize their writable SYSTEM_INFO outputs.
    unsafe {
        GetSystemInfo(&mut process_info);
        GetNativeSystemInfo(&mut native_info);
    }
    // SAFETY: SYSTEM_INFO is initialized by the APIs and this reads its documented union member.
    let process_machine = unsafe { process_info.Anonymous.Anonymous.wProcessorArchitecture };
    // SAFETY: SYSTEM_INFO is initialized by the APIs and this reads its documented union member.
    let native_machine = unsafe { native_info.Anonymous.Anonymous.wProcessorArchitecture };

    let mut wow64 = 0;
    // SAFETY: GetCurrentProcess returns a pseudo-handle valid for this query; `wow64` is writable.
    if unsafe { IsWow64Process(GetCurrentProcess(), &mut wow64) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if wow64 != 0 && wow64 != 1 {
        return Err(invalid("Windows returned an invalid WoW64 status"));
    }

    let facts = ObservedWindowsFacts {
        os_major: version.dwMajorVersion,
        os_minor: version.dwMinorVersion,
        os_build: version.dwBuildNumber,
        process_architecture: architecture(process_machine)?,
        native_architecture: architecture(native_machine)?,
        process_is_wow64: wow64 != 0,
    };
    if !facts.is_consistent_with_host("windows", std::env::consts::ARCH) {
        return Err(invalid("Windows kernel/platform facts are inconsistent"));
    }
    Ok(Some(facts))
}

#[cfg(not(windows))]
fn observed_windows_facts() -> io::Result<Option<onec_agent_protocol::ObservedWindowsFacts>> {
    Ok(None)
}

/// Reads and verifies one persisted invocation observation without creating signing state.
pub(crate) fn fetch_run_local_invocation_observation(
    jobs_root: &Path,
    job_id: &str,
    challenge: &str,
    expected_invocation_sha256: &str,
) -> io::Result<(AgentNativeInvocationRecord, String)> {
    validate_invocation_request(job_id, challenge, expected_invocation_sha256)?;
    let first = super::jobs::status(jobs_root, job_id)?;
    let first_identity = first
        .run_local
        .as_ref()
        .ok_or_else(|| invalid("invocation observation fetch requires run-local ownership"))?;
    let _ownership = super::jobs::lock_run_local_identity(jobs_root, first_identity.run_id())?;
    let job = super::jobs::status(jobs_root, job_id)?;
    let identity = job
        .run_local
        .as_ref()
        .ok_or_else(|| invalid("invocation observation fetch requires run-local ownership"))?;
    validate_invocation_job(&first, &job, first_identity.run_id(), challenge)?;
    validate_candidate_bytes(jobs_root, identity)?;
    let commitment = read_invocation_commitment(jobs_root, job_id)?;
    if commitment.version != 1 || commitment.invocation_sha256 != expected_invocation_sha256 {
        return Err(invalid(
            "stored invocation request does not match the immutable pre-spawn commitment",
        ));
    }
    let requested_exact_testcase = commitment.requested_exact_testcase.clone();
    if job.result_set.is_some() && !super::results::job_result_set_cleaned(jobs_root, job_id)? {
        return Err(invalid(
            "invocation observation fetch requires cleaned results",
        ));
    }

    let directory = jobs_root.join(KEY_DIR);
    require_existing_private_directory(&directory)?;
    let record_directory = directory.join(INVOCATION_RECORD_DIR);
    require_existing_private_directory(&record_directory)?;
    let stored = read_stored_invocation(&record_directory.join(format!("{job_id}.json")))?;
    let key = read_key(&directory.join(KEY_FILE))?;
    let record = &stored.record;
    if record.schema_version != 1
        || record.job_id != job_id
        || record.run_id != identity.run_id()
        || record.challenge != challenge
        || record.invocation_sha256 != expected_invocation_sha256
        || record.requested_exact_testcase != requested_exact_testcase
        || record.candidate_sha256 != identity.candidate_sha256()
        || record.declared_effect != commitment.native_effect
        || record.command_exit_code != 0
        || record.cleanup_completion != "complete"
        || record.signer_id != signer_id(&key.verifying_key().to_bytes())
    {
        return Err(invalid(
            "stored invocation observation does not match the exact job",
        ));
    }
    if let Some(expected_logs) = &record.output_logs {
        let worker_commitment = read_completed_invocation_output_commitment(
            jobs_root,
            &job,
            &commitment.invocation_sha256,
        )?;
        let worker_logs = worker_commitment.output_logs;
        let current_logs = read_complete_invocation_output_logs(jobs_root, job_id, &job)?;
        if worker_logs != *expected_logs || current_logs != *expected_logs {
            return Err(invalid(
                "stored invocation output logs are missing, truncated, or differ from worker and signed commitments",
            ));
        }
    }
    if let Some(signed_result_set) = &record.result_set {
        validate_result_set_commitment(&job, &commitment.results)?;
        let worker_commitment = read_completed_invocation_output_commitment(
            jobs_root,
            &job,
            &commitment.invocation_sha256,
        )?;
        if worker_commitment.result_set.as_ref() != Some(signed_result_set)
            || job.result_set.as_ref() != Some(signed_result_set)
        {
            return Err(invalid(
                "stored invocation result manifest differs from worker or terminal job commitment",
            ));
        }
    }
    let signature_bytes = decode_hex::<64>(&stored.signature_hex)
        .ok_or_else(|| invalid("stored invocation observation signature is malformed"))?;
    let signature = Signature::from_bytes(&signature_bytes);
    key.verifying_key()
        .verify_strict(
            &record.signing_bytes().map_err(io::Error::other)?,
            &signature,
        )
        .map_err(|_| invalid("stored invocation observation signature is invalid"))?;
    Ok((stored.record, stored.signature_hex))
}

pub(crate) fn read_complete_invocation_output_logs(
    jobs_root: &Path,
    job_id: &str,
    job: &onec_agent_protocol::AgentJobInfo,
) -> io::Result<AgentNativeInvocationOutputLogs> {
    if job.stdout_log_truncated || job.stderr_log_truncated {
        return Err(invalid("invocation output logs are truncated"));
    }
    let job_dir = super::jobs::job_dir(jobs_root, job_id)?;
    let job_dir_metadata = fs::symlink_metadata(&job_dir)?;
    if !job_dir_metadata.is_dir() || is_link_or_reparse(&job_dir_metadata) {
        return Err(invalid(
            "Agent-owned invocation job directory is not a regular directory",
        ));
    }
    let stdout_path = job_dir.join("stdout.log");
    let stderr_path = job_dir.join("stderr.log");
    if hostlink_core::RetainedLog::new(stdout_path.clone())?.storage_truncated()?
        || hostlink_core::RetainedLog::new(stderr_path.clone())?.storage_truncated()?
    {
        return Err(invalid(
            "invocation output logs have discarded retained history",
        ));
    }
    let (stdout_sha256, stdout_bytes) = hash_private_bounded_log(&stdout_path)?;
    let (stderr_sha256, stderr_bytes) = hash_private_bounded_log(&stderr_path)?;
    Ok(AgentNativeInvocationOutputLogs {
        stdout_sha256,
        stdout_bytes,
        stderr_sha256,
        stderr_bytes,
    })
}

#[cfg(test)]
pub(crate) fn read_completed_invocation_output_logs(
    jobs_root: &Path,
    job: &onec_agent_protocol::AgentJobInfo,
    expected_invocation_sha256: &str,
) -> io::Result<AgentNativeInvocationOutputLogs> {
    Ok(
        read_completed_invocation_output_commitment(jobs_root, job, expected_invocation_sha256)?
            .output_logs,
    )
}

fn read_completed_invocation_output_commitment(
    jobs_root: &Path,
    job: &onec_agent_protocol::AgentJobInfo,
    expected_invocation_sha256: &str,
) -> io::Result<StoredInvocationOutputCommitment> {
    let identity = job
        .run_local
        .as_ref()
        .ok_or_else(|| invalid("output commitment requires run-local job ownership"))?;
    let commitment = read_invocation_commitment(jobs_root, &job.job_id)?;
    let stored: StoredInvocationOutputCommitment = read_stored_record(
        &super::jobs::job_dir(jobs_root, &job.job_id)?.join("native-output-logs.json"),
    )?;
    if stored.schema_version != 1
        || stored.job_id != job.job_id
        || stored.run_id != identity.run_id()
        || stored.invocation_sha256 != expected_invocation_sha256
        || commitment.invocation_sha256 != expected_invocation_sha256
    {
        return Err(invalid(
            "worker output commitment belongs to a different job, run, or invocation",
        ));
    }
    Ok(stored)
}

pub(crate) fn write_completed_invocation_output_logs(
    jobs_root: &Path,
    job: &onec_agent_protocol::AgentJobInfo,
    expected_invocation_sha256: &str,
    output_logs: AgentNativeInvocationOutputLogs,
    result_set: Option<onec_agent_protocol::ResultSetInfo>,
) -> io::Result<()> {
    let identity = job
        .run_local
        .as_ref()
        .ok_or_else(|| invalid("output commitment requires run-local job ownership"))?;
    let commitment = read_invocation_commitment(jobs_root, &job.job_id)?;
    if commitment.invocation_sha256 != expected_invocation_sha256 {
        return Err(invalid(
            "worker output commitment differs from the immutable invocation commitment",
        ));
    }
    validate_result_set_commitment(job, &commitment.results)?;
    if result_set != job.result_set {
        return Err(invalid(
            "worker result manifest differs from the terminal job result set",
        ));
    }
    let stored = StoredInvocationOutputCommitment {
        schema_version: 1,
        job_id: job.job_id.clone(),
        run_id: identity.run_id().to_owned(),
        invocation_sha256: expected_invocation_sha256.to_owned(),
        output_logs,
        result_set,
    };
    let path = super::jobs::job_dir(jobs_root, &job.job_id)?.join("native-output-logs.json");
    hostlink_core::write_new_private_bytes(&path, &serde_json::to_vec(&stored)?)
}

fn validate_result_set_commitment(
    job: &onec_agent_protocol::AgentJobInfo,
    declared: &[onec_agent_protocol::ResultArtifactSpec],
) -> io::Result<()> {
    match &job.result_set {
        None if declared.is_empty() => Ok(()),
        None => Err(invalid("declared result artifacts were not published")),
        Some(result_set) => {
            result_set.validate().map_err(|error| invalid(&error))?;
            if declared.is_empty()
                || result_set.owner().job_id() != Some(job.job_id.as_str())
                || result_set.artifacts().len() != declared.len()
                || declared
                    .iter()
                    .zip(result_set.artifacts())
                    .any(|(spec, artifact)| {
                        artifact.name() != spec.name()
                            || artifact.bytes() > spec.max_bytes()
                            || artifact.media_type() != spec.media_type()
                    })
            {
                return Err(invalid(
                    "published result manifest does not match the job owner and pre-spawn declarations",
                ));
            }
            Ok(())
        }
    }
}

fn hash_private_bounded_log(path: &Path) -> io::Result<(String, u64)> {
    let path_metadata = fs::symlink_metadata(path)?;
    if !path_metadata.is_file() || is_link_or_reparse(&path_metadata) {
        return Err(invalid(
            "Agent-owned invocation output log is not a regular file",
        ));
    }
    hostlink_core::validate_private_file(path).map_err(io::Error::other)?;
    let mut file = open_private_log_nofollow(path)?;
    let opened_metadata = file.metadata()?;
    if !opened_metadata.is_file()
        || is_link_or_reparse(&opened_metadata)
        || opened_metadata.len() > super::jobs::MAX_DURABLE_JOB_LOG_BYTES
        || opened_metadata.len() != path_metadata.len()
        || !opened_log_matches_path(&file, path)?
    {
        return Err(invalid(
            "Agent-owned invocation output log exceeds its bound or changed while opening",
        ));
    }
    let mut bytes = Vec::with_capacity(opened_metadata.len() as usize);
    file.by_ref()
        .take(super::jobs::MAX_DURABLE_JOB_LOG_BYTES + 1)
        .read_to_end(&mut bytes)?;
    let final_path_metadata = fs::symlink_metadata(path)?;
    let final_opened_metadata = file.metadata()?;
    if bytes.len() as u64 != opened_metadata.len()
        || bytes.len() as u64 > super::jobs::MAX_DURABLE_JOB_LOG_BYTES
        || final_path_metadata.len() != opened_metadata.len()
        || !final_path_metadata.is_file()
        || is_link_or_reparse(&final_path_metadata)
        || !final_opened_metadata.is_file()
        || is_link_or_reparse(&final_opened_metadata)
        || final_opened_metadata.len() != opened_metadata.len()
        || opened_metadata.modified()? != final_opened_metadata.modified()?
        || !opened_log_matches_path(&file, path)?
    {
        return Err(invalid(
            "Agent-owned invocation output log changed while being read",
        ));
    }
    Ok((format!("{:x}", Sha256::digest(&bytes)), bytes.len() as u64))
}

// A no-follow open alone does not prove the pathname still names the same file. This is
// particularly important when an Agent signs a digest that the controller later trusts.
#[cfg(unix)]
fn opened_log_matches_path(file: &fs::File, path: &Path) -> io::Result<bool> {
    use std::os::unix::fs::MetadataExt;

    let opened = file.metadata()?;
    let current = fs::symlink_metadata(path)?;
    Ok(current.is_file()
        && !is_link_or_reparse(&current)
        && opened.dev() == current.dev()
        && opened.ino() == current.ino())
}

#[cfg(windows)]
fn opened_log_matches_path(file: &fs::File, path: &Path) -> io::Result<bool> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
    };

    fn id(file: &fs::File) -> io::Result<(u32, u32, u32)> {
        let mut info = BY_HANDLE_FILE_INFORMATION::default();
        // SAFETY: the handle remains open and `info` is a writable result buffer.
        if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok((
            info.dwVolumeSerialNumber,
            info.nFileIndexHigh,
            info.nFileIndexLow,
        ))
    }

    let other = open_private_log_nofollow(path)?;
    let current = other.metadata()?;
    Ok(current.is_file() && !is_link_or_reparse(&current) && id(file)? == id(&other)?)
}

#[cfg(not(any(unix, windows)))]
fn opened_log_matches_path(file: &fs::File, path: &Path) -> io::Result<bool> {
    let opened = file.metadata()?;
    let current = fs::symlink_metadata(path)?;
    Ok(current.is_file()
        && !is_link_or_reparse(&current)
        && opened.len() == current.len()
        && opened.modified()? == current.modified()?)
}

#[cfg(unix)]
fn open_private_log_nofollow(path: &Path) -> io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;

    fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
}

#[cfg(windows)]
fn open_private_log_nofollow(path: &Path) -> io::Result<fs::File> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ};

    fs::OpenOptions::new()
        .read(true)
        // The completed log must not be opened for writing or removed while it is being signed.
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

#[cfg(not(any(unix, windows)))]
fn open_private_log_nofollow(path: &Path) -> io::Result<fs::File> {
    fs::File::open(path)
}

fn validate_invocation_request(job_id: &str, challenge: &str, digest: &str) -> io::Result<()> {
    if !safe_job_id(job_id)
        || challenge.is_empty()
        || challenge.len() > 128
        || digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid("native invocation observation identity is invalid"));
    }
    Ok(())
}

fn validate_candidate_bytes(
    jobs_root: &Path,
    identity: &onec_agent_protocol::RunLocalJobIdentity,
) -> io::Result<()> {
    let path = jobs_root
        .join("run-local-cache")
        .join(identity.candidate_name());
    let metadata = fs::symlink_metadata(&path)?;
    if !metadata.is_file()
        || is_link_or_reparse(&metadata)
        || hostlink_core::sha256_file(&path)? != identity.candidate_sha256()
    {
        return Err(invalid(
            "run-local candidate bytes do not match the persisted executable digest",
        ));
    }
    Ok(())
}

fn read_invocation_commitment(
    jobs_root: &Path,
    job_id: &str,
) -> io::Result<crate::jobs::NativeInvocationCommitment> {
    let job_dir = super::jobs::job_dir(jobs_root, job_id)?;
    let path = job_dir.join("native-invocation.json");
    let metadata = fs::symlink_metadata(&path)?;
    if !metadata.is_file() || is_link_or_reparse(&metadata) || metadata.len() > 16 * 1024 {
        return Err(invalid(
            "native invocation commitment is not a bounded regular file",
        ));
    }
    hostlink_core::read_json_file_bounded(&path, 16 * 1024).map_err(io::Error::other)
}

fn validate_invocation_job(
    first: &onec_agent_protocol::AgentJobInfo,
    job: &onec_agent_protocol::AgentJobInfo,
    run_id: &str,
    _challenge: &str,
) -> io::Result<()> {
    if first.run_local.as_ref().map(|value| value.run_id()) != Some(run_id)
        || job.job_id != first.job_id
        || job.run_local.as_ref().map(|value| value.run_id()) != Some(run_id)
        || job.state != AgentJobState::Succeeded
        || job.exit_code != Some(0)
        || job.finished_unix_ms.is_none()
        || job.stdout_log_truncated
        || job.stderr_log_truncated
    {
        return Err(invalid(
            "invocation observation requires unchanged successful terminal job, exact invocation, complete bounded logs, and declared effect",
        ));
    }
    Ok(())
}

fn read_stored_invocation(path: &Path) -> io::Result<StoredInvocationObservation> {
    let stored: StoredInvocationObservation = read_stored_record(path)?;
    Ok(stored)
}
/// Returns signer identity and public key without exposing secret key bytes.
pub(crate) fn public_key(jobs_root: &Path) -> io::Result<(String, String)> {
    let key = load_or_create_key(jobs_root)?;
    let verifying_key = key.verifying_key().to_bytes();
    let signer_id = signer_id(&verifying_key);
    Ok((signer_id, hex(&verifying_key)))
}

/// Signs one agent-observed successful run-local job after scoped workspace removal.
pub(crate) fn attest_run_local_success(
    jobs_root: &Path,
    job_id: &str,
    challenge: &str,
) -> io::Result<(AgentTerminalExecutionRecord, String)> {
    if challenge.is_empty() || challenge.len() > 128 {
        return Err(invalid(
            "native attestation challenge must contain 1..=128 bytes",
        ));
    }
    let first = super::jobs::status(jobs_root, job_id)?;
    let identity = first
        .run_local
        .as_ref()
        .ok_or_else(|| invalid("native attestation requires run-local job ownership"))?;
    let _ownership = super::jobs::lock_run_local_identity(jobs_root, identity.run_id())?;
    let job = super::jobs::status(jobs_root, job_id)?;
    let identity = job
        .run_local
        .as_ref()
        .ok_or_else(|| invalid("native attestation requires run-local job ownership"))?;
    if job.job_id != job_id
        || first.run_local.as_ref().map(|run| run.run_id()) != Some(identity.run_id())
        || job.state != AgentJobState::Succeeded
        || job.exit_code != Some(0)
        || job.finished_unix_ms.is_none()
    {
        return Err(invalid(
            "native attestation requires unchanged, normally succeeded terminal job state",
        ));
    }
    if job.result_set.is_some() && !super::results::job_result_set_cleaned(jobs_root, &job.job_id)?
    {
        return Err(invalid(
            "native attestation requires declared results to be retrieved and cleaned",
        ));
    }

    // Resolve durable signing state and reserve this one-job receipt path before removing files.
    // This ensures a missing/corrupt key or duplicate receipt cannot trigger cleanup as a side effect.
    let key = load_or_create_key(jobs_root)?;
    let attestations_dir = jobs_root.join(KEY_DIR).join("records");
    ensure_private_directory(&attestations_dir)?;
    let record_path = attestations_dir.join(format!("{}.json", job.job_id));
    match fs::symlink_metadata(&record_path) {
        Ok(_) => return Err(invalid("native attestation already exists for this job")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }

    let parent = jobs_root.join("run-local-runs");
    let workspace = parent.join(identity.run_id());
    let removed = hostlink_core::remove_path_scoped(&parent, &workspace, true, false)?;
    if !removed {
        return Err(invalid(
            "native attestation requires this request to complete owned workspace cleanup",
        ));
    }

    let verifying_key = key.verifying_key().to_bytes();
    let signer_id = signer_id(&verifying_key);
    let record = AgentTerminalExecutionRecord {
        schema_version: 1,
        challenge: challenge.to_owned(),
        job_id: job.job_id,
        run_id: identity.run_id().to_owned(),
        candidate_sha256: identity.candidate_sha256().to_owned(),
        command_completion: "succeeded".to_owned(),
        command_exit_code: 0,
        cleanup_completion: "complete".to_owned(),
        signer_id,
    };
    let signature = key
        .sign(&record.signing_bytes().map_err(io::Error::other)?)
        .to_bytes();

    let envelope = serde_json::json!({
        "record": &record,
        "signature_hex": hex(&signature),
    });
    // A durable create-new receipt makes signing single-use for each job, including after restart.
    hostlink_core::write_new_private_bytes(&record_path, &serde_json::to_vec(&envelope)?)?;
    Ok((record, hex(&signature)))
}

/// Reads and verifies one previously persisted signed record without creating signing state.
pub(crate) fn fetch_run_local_attestation(
    jobs_root: &Path,
    job_id: &str,
    challenge: &str,
) -> io::Result<(AgentTerminalExecutionRecord, String)> {
    if !safe_job_id(job_id) || challenge.is_empty() || challenge.len() > 128 {
        return Err(invalid("native attestation fetch identity is invalid"));
    }
    let first = super::jobs::status(jobs_root, job_id)?;
    let first_identity = first
        .run_local
        .as_ref()
        .ok_or_else(|| invalid("native attestation fetch requires run-local job ownership"))?;
    let _ownership = super::jobs::lock_run_local_identity(jobs_root, first_identity.run_id())?;
    let job = super::jobs::status(jobs_root, job_id)?;
    let identity = job
        .run_local
        .as_ref()
        .ok_or_else(|| invalid("native attestation fetch requires run-local job ownership"))?;
    if job.job_id != job_id
        || first_identity.run_id() != identity.run_id()
        || job.state != AgentJobState::Succeeded
        || job.exit_code != Some(0)
        || job.finished_unix_ms.is_none()
    {
        return Err(invalid(
            "native attestation fetch job ownership is not eligible",
        ));
    }
    if job.result_set.is_some() && !super::results::job_result_set_cleaned(jobs_root, job_id)? {
        return Err(invalid(
            "native attestation fetch requires cleaned job results",
        ));
    }

    // Read only existing directories and key material. Recovery must never provision a signer.
    let directory = jobs_root.join(KEY_DIR);
    require_existing_private_directory(&directory)?;
    let record_directory = directory.join("records");
    require_existing_private_directory(&record_directory)?;
    let stored: StoredAttestation =
        read_stored_record(&record_directory.join(format!("{job_id}.json")))?;
    let signer_id = read_existing_signer_id(jobs_root)?;
    let record = &stored.record;
    if record.schema_version != 1
        || record.job_id != job_id
        || record.run_id != identity.run_id()
        || record.candidate_sha256 != identity.candidate_sha256()
        || record.challenge != challenge
        || record.signer_id != signer_id
        || record.command_completion != "succeeded"
        || record.command_exit_code != 0
        || record.cleanup_completion != "complete"
    {
        return Err(invalid(
            "stored native attestation does not match the exact job",
        ));
    }
    let signature_bytes = decode_hex::<64>(&stored.signature_hex)
        .ok_or_else(|| invalid("stored native attestation signature is malformed"))?;
    let signature = Signature::from_bytes(&signature_bytes);
    let key = read_key(&directory.join(KEY_FILE))?.verifying_key();
    key.verify_strict(
        &record.signing_bytes().map_err(io::Error::other)?,
        &signature,
    )
    .map_err(|_| invalid("stored native attestation signature is invalid"))?;
    Ok((stored.record, stored.signature_hex))
}

fn read_existing_signer_id(jobs_root: &Path) -> io::Result<String> {
    let directory = jobs_root.join(KEY_DIR);
    require_existing_private_directory(&directory)?;
    let key = read_key(&directory.join(KEY_FILE))?;
    let bytes = key.verifying_key().to_bytes();
    Ok(signer_id(&bytes))
}

fn read_stored_record<T: serde::de::DeserializeOwned>(path: &Path) -> io::Result<T> {
    let path_metadata = fs::symlink_metadata(path)?;
    if !path_metadata.is_file() || is_link_or_reparse(&path_metadata) {
        return Err(invalid(
            "stored native attestation is not a bounded regular file",
        ));
    }
    hostlink_core::validate_private_file(path).map_err(io::Error::other)?;
    let file = fs::File::open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_ATTESTATION_BYTES {
        return Err(invalid(
            "stored native attestation is not a bounded regular file",
        ));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_ATTESTATION_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 != metadata.len() || bytes.len() as u64 > MAX_ATTESTATION_BYTES {
        return Err(invalid(
            "stored native attestation changed while being read",
        ));
    }
    serde_json::from_slice(&bytes).map_err(io::Error::other)
}

fn require_existing_private_directory(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || is_link_or_reparse(&metadata) {
        return Err(invalid(
            "native attestation path is not an existing regular directory",
        ));
    }
    Ok(())
}

fn safe_job_id(job_id: &str) -> bool {
    job_id.starts_with("job-")
        && job_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

fn load_or_create_key(jobs_root: &Path) -> io::Result<SigningKey> {
    let directory = jobs_root.join(KEY_DIR);
    ensure_private_directory(jobs_root)?;
    match fs::symlink_metadata(&directory) {
        Ok(_) => ensure_private_directory(&directory)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            hostlink_core::create_private_directory(&directory)?
        }
        Err(error) => return Err(error),
    }
    let path = directory.join(KEY_FILE);
    match read_key(&path) {
        Ok(key) => return Ok(key),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let key = SigningKey::generate(&mut OsRng);
    let bytes = key.to_bytes();
    match hostlink_core::write_new_private_bytes(&path, &bytes) {
        Ok(()) => Ok(key),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => read_key(&path),
        Err(error) => Err(error),
    }
}

fn read_key(path: &Path) -> io::Result<SigningKey> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || is_link_or_reparse(&metadata) {
        return Err(invalid(
            "native attestation key must be a regular non-linked file",
        ));
    }
    hostlink_core::validate_private_file(path).map_err(io::Error::other)?;
    let bytes = fs::read(path)?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| invalid("native attestation key has an invalid length"))?;
    Ok(SigningKey::from_bytes(&bytes))
}

#[cfg(unix)]
fn is_link_or_reparse(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::FileTypeExt;
    metadata.file_type().is_symlink() || metadata.file_type().is_block_device()
}

#[cfg(windows)]
fn is_link_or_reparse(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    metadata.file_attributes()
        & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
        != 0
}

#[cfg(not(any(unix, windows)))]
fn is_link_or_reparse(metadata: &fs::Metadata) -> bool {
    metadata.file_type().is_symlink()
}

fn signer_id(verifying_key: &[u8; 32]) -> String {
    hex(&Sha256::digest(verifying_key))
}

fn ensure_private_directory(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !is_link_or_reparse(&metadata) => {
            hostlink_core::restrict_private_directory(path).map_err(io::Error::other)
        }
        Ok(_) => Err(invalid(
            "native attestation directory is not a regular directory",
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            hostlink_core::create_private_directory(path)
        }
        Err(error) => Err(error),
    }
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push(HEX[usize::from(byte >> 4)] as char);
        result.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    result
}

fn decode_hex<const N: usize>(value: &str) -> Option<[u8; N]> {
    if value.len() != N.checked_mul(2)? || !value.is_ascii() {
        return None;
    }
    let mut bytes = [0_u8; N];
    for (index, byte) in bytes.iter_mut().enumerate() {
        let start = index.checked_mul(2)?;
        *byte = u8::from_str_radix(value.get(start..start + 2)?, 16).ok()?;
    }
    Some(bytes)
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    use std::path::PathBuf;
    use tempfile::tempdir;

    #[test]
    fn attestation_key_is_stable_and_public_export_does_not_contain_private_bytes() {
        let dir = tempdir().expect("temporary root");
        let first = public_key(dir.path()).expect("create key and export public key");
        let second = public_key(dir.path()).expect("reload key and export public key");
        assert_eq!(first, second);
        assert_eq!(first.0, signer_id(&hex_to_array::<32>(&first.1)));
        assert_eq!(first.1.len(), 64);
    }

    #[test]
    fn record_signing_is_domain_separated_and_key_verifies_it() {
        let dir = tempdir().expect("temporary root");
        let key = load_or_create_key(dir.path()).expect("create key");
        let (public, _) = public_key(dir.path()).expect("public key");
        let challenge = "a".repeat(64);
        let record = AgentTerminalExecutionRecord {
            schema_version: 1,
            challenge,
            job_id: "0123456789abcdef0123456789abcdef".to_owned(),
            run_id: "fedcba9876543210fedcba9876543210".to_owned(),
            candidate_sha256: "0".repeat(64),
            command_completion: "succeeded".to_owned(),
            command_exit_code: 0,
            cleanup_completion: "complete".to_owned(),
            signer_id: public,
        };
        let signature = key.sign(&record.signing_bytes().expect("canonical bytes"));
        let bytes = hex(&key.verifying_key().to_bytes());
        let verifying = VerifyingKey::from_bytes(&hex_to_array::<32>(&bytes)).expect("key");
        verifying
            .verify(
                &record.signing_bytes().expect("canonical bytes"),
                &signature,
            )
            .expect("signature verifies");
        let signature = Signature::from_bytes(&signature.to_bytes());
        verifying
            .verify(
                &record.signing_bytes().expect("canonical bytes"),
                &signature,
            )
            .expect("round trip");
    }

    #[test]
    fn malformed_key_file_fails_closed() {
        let dir = tempdir().expect("temporary root");
        let key_dir = dir.path().join(KEY_DIR);
        hostlink_core::create_private_directory(&key_dir).expect("key directory");
        fs::write(key_dir.join(KEY_FILE), b"short").expect("malformed key fixture");
        hostlink_core::restrict_private_file(&key_dir.join(KEY_FILE)).expect("restrict malformed file");
        assert!(load_or_create_key(dir.path()).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn linked_key_file_fails_closed() {
        use std::os::unix::fs::symlink;

        let dir = tempdir().expect("temporary root");
        let key_dir = dir.path().join(KEY_DIR);
        hostlink_core::create_private_directory(&key_dir).expect("key directory");
        let external = dir.path().join("external.key");
        fs::write(&external, [0_u8; 32]).expect("external key fixture");
        hostlink_core::restrict_private_file(&external).expect("restrict external key fixture");
        symlink(external, key_dir.join(KEY_FILE)).expect("linked key");
        assert!(load_or_create_key(dir.path()).is_err());
    }

    #[test]
    fn invalid_challenge_does_not_create_a_signer_or_receipt() {
        let dir = tempdir().expect("temporary root");
        assert!(attest_run_local_success(dir.path(), "missing-job", "").is_err());
        assert!(!dir.path().join(KEY_DIR).exists());
    }

    #[test]
    fn already_absent_workspace_does_not_count_as_proven_cleanup() {
        let dir = tempdir().expect("temporary root");
        let (job_id, _run_id, workspace) =
            fixture_job(dir.path(), AgentJobState::Succeeded, Some(0));
        fs::remove_dir(&workspace).expect("remove workspace before attestation attempt");
        assert!(attest_run_local_success(dir.path(), &job_id, &"e".repeat(64)).is_err());
        assert!(
            !dir.path()
                .join(KEY_DIR)
                .join("records")
                .join(format!("{job_id}.json"))
                .exists(),
            "missing workspace is ambiguous and cannot yield a success signature"
        );
    }

    #[test]
    fn failed_or_interrupted_jobs_never_produce_success_receipts() {
        for (state, exit_code) in [
            (AgentJobState::Failed, Some(1)),
            (AgentJobState::Interrupted, None),
        ] {
            let dir = tempdir().expect("temporary root");
            let (job_id, run_id, workspace) = fixture_job(dir.path(), state, exit_code);
            assert!(attest_run_local_success(dir.path(), &job_id, &"b".repeat(64)).is_err());
            assert!(
                workspace.is_dir(),
                "unverified cleanup must preserve workspace"
            );
            assert!(
                !dir.path()
                    .join(KEY_DIR)
                    .join("records")
                    .join(format!("{job_id}.json"))
                    .exists(),
                "failed or ambiguous terminal state cannot publish success"
            );
            assert_eq!(run_id.len(), 32);
        }
    }

    #[test]
    fn remote_commit_can_be_recovered_read_only_without_resigning() {
        let dir = tempdir().expect("temporary root");
        let (job_id, _run_id, workspace) =
            fixture_job(dir.path(), AgentJobState::Succeeded, Some(0));
        let challenge = "c".repeat(64);
        let (record, signature_hex) =
            attest_run_local_success(dir.path(), &job_id, &challenge).expect("attest success");
        assert!(
            !workspace.exists(),
            "owned workspace must be removed before receipt"
        );
        assert_eq!(record.command_completion, "succeeded");
        assert_eq!(record.command_exit_code, 0);
        assert_eq!(record.cleanup_completion, "complete");
        let key = load_or_create_key(dir.path()).expect("load signer key");
        let signature = Signature::from_bytes(&hex_to_array::<64>(&signature_hex));
        let verifying_key = key.verifying_key();
        verifying_key
            .verify(
                &record.signing_bytes().expect("canonical bytes"),
                &signature,
            )
            .expect("signature verifies");
        assert!(
            attest_run_local_success(dir.path(), &job_id, &challenge).is_err(),
            "receipt persistence prevents re-signing the job"
        );
        let fetched = fetch_run_local_attestation(dir.path(), &job_id, &challenge)
            .expect("read-only recovery returns the exact stored signature");
        assert_eq!(fetched, (record, signature_hex));
        assert!(
            attest_run_local_success(dir.path(), &job_id, &challenge).is_err(),
            "read-only fetch must not make signing replayable"
        );
    }

    #[test]
    fn read_only_fetch_rejects_missing_record_bad_signature_changed_challenge_and_foreign_job() {
        let dir = tempdir().expect("temporary root");
        let (job_id, _run_id, _workspace) =
            fixture_job(dir.path(), AgentJobState::Succeeded, Some(0));
        let challenge = "f".repeat(64);
        assert!(fetch_run_local_attestation(dir.path(), &job_id, &challenge).is_err());
        assert!(
            !dir.path().join(KEY_DIR).exists(),
            "missing-record recovery must not create signing state"
        );

        attest_run_local_success(dir.path(), &job_id, &challenge).expect("persist one record");
        assert!(fetch_run_local_attestation(dir.path(), &job_id, "changed").is_err());
        assert!(fetch_run_local_attestation(dir.path(), "job-attest-failed", &challenge).is_err());

        let record_path = dir
            .path()
            .join(KEY_DIR)
            .join("records")
            .join(format!("{job_id}.json"));
        let mut envelope: serde_json::Value =
            serde_json::from_slice(&fs::read(&record_path).expect("read receipt"))
                .expect("receipt JSON");
        envelope["record"]["job_id"] = serde_json::Value::String("job-foreign".to_owned());
        fs::write(
            &record_path,
            serde_json::to_vec(&envelope).expect("encode foreign-job fixture"),
        )
        .expect("write foreign-job fixture");
        hostlink_core::restrict_private_file(&record_path).expect("keep fixture private");
        assert!(fetch_run_local_attestation(dir.path(), &job_id, &challenge).is_err());

        envelope["record"]["job_id"] = serde_json::Value::String(job_id.clone());
        envelope["signature_hex"] = serde_json::Value::String("00".repeat(64));
        fs::write(
            &record_path,
            serde_json::to_vec(&envelope).expect("encode corrupt receipt"),
        )
        .expect("replace fixture receipt");
        hostlink_core::restrict_private_file(&record_path).expect("keep fixture private");
        assert!(fetch_run_local_attestation(dir.path(), &job_id, &challenge).is_err());
    }

    #[test]
    fn signed_invocation_binds_exact_job_candidate_effect_target_and_cleanup() {
        let dir = tempdir().expect("temporary root");
        let (job_id, run_id, workspace, candidate_path, invocation) =
            invocation_fixture(dir.path(), false);
        let challenge = "9".repeat(64);
        let (record, signature_hex) =
            observe_run_local_invocation(dir.path(), &job_id, &challenge, &invocation)
                .expect("sign exact successful invocation");
        assert!(!workspace.exists(), "owned run root is cleaned first");
        assert_eq!(record.job_id, job_id);
        assert_eq!(record.run_id, run_id);
        assert_eq!(record.invocation_sha256, invocation);
        assert_eq!(
            record.requested_exact_testcase.as_deref(),
            Some("fixture::approved_case")
        );
        let logs = record.output_logs.as_ref().expect("signed output logs");
        assert_eq!(logs.stdout_bytes, b"[REDACTED] stdout\n".len() as u64);
        assert_eq!(logs.stderr_bytes, b"stderr\n".len() as u64);
        assert_eq!(
            logs.stdout_sha256,
            format!("{:x}", Sha256::digest(b"[REDACTED] stdout\n"))
        );
        assert_eq!(
            logs.stderr_sha256,
            format!("{:x}", Sha256::digest(b"stderr\n"))
        );
        assert_eq!(
            record.candidate_sha256,
            format!(
                "{:x}",
                Sha256::digest(fs::read(candidate_path).expect("candidate bytes"))
            )
        );
        assert_eq!(
            record.declared_effect,
            onec_agent_protocol::NativeExecutionEffect::ReadOnly
        );
        assert_eq!(record.host_arch, std::env::consts::ARCH);
        assert_eq!(record.host_os, std::env::consts::OS);
        #[cfg(windows)]
        assert!(record.observed_windows.is_some());
        #[cfg(not(windows))]
        assert!(record.observed_windows.is_none());
        assert_eq!(record.command_exit_code, 0);
        assert_eq!(record.cleanup_completion, "complete");

        let key = load_or_create_key(dir.path()).expect("signer key");
        key.verifying_key()
            .verify_strict(
                &record.signing_bytes().expect("signing bytes"),
                &Signature::from_bytes(&hex_to_array::<64>(&signature_hex)),
            )
            .expect("signature verifies");
        let signature = Signature::from_bytes(&hex_to_array::<64>(&signature_hex));
        let mut changed_host = record.clone();
        changed_host.host_os.push_str("-other");
        assert!(
            key.verifying_key()
                .verify_strict(
                    &changed_host.signing_bytes().expect("changed host bytes"),
                    &signature,
                )
                .is_err()
        );
        let mut changed_effect = record.clone();
        changed_effect.declared_effect = onec_agent_protocol::NativeExecutionEffect::Disposable;
        assert!(
            key.verifying_key()
                .verify_strict(
                    &changed_effect
                        .signing_bytes()
                        .expect("changed effect bytes"),
                    &signature,
                )
                .is_err()
        );
        let mut changed_testcase = record.clone();
        changed_testcase.requested_exact_testcase = Some("fixture::different_case".to_owned());
        assert!(
            key.verifying_key()
                .verify_strict(
                    &changed_testcase
                        .signing_bytes()
                        .expect("changed testcase bytes"),
                    &signature,
                )
                .is_err()
        );
        let fetched =
            fetch_run_local_invocation_observation(dir.path(), &job_id, &challenge, &invocation)
                .expect("read-only recovery");
        assert_eq!(fetched, (record, signature_hex));
        fs::write(dir.path().join(&job_id).join("stdout.log"), b"tampered")
            .expect("tamper durable output");
        hostlink_core::restrict_private_file(&dir.path().join(&job_id).join("stdout.log"))
            .expect("keep tampered output private");
        assert!(
            fetch_run_local_invocation_observation(dir.path(), &job_id, &challenge, &invocation,)
                .is_err()
        );
    }

    #[test]
    fn invocation_observation_rejects_wrong_binary_argv_claims_truncation_and_ambiguous_cleanup() {
        let challenge = "8".repeat(64);

        let dir = tempdir().expect("missing worker seal root");
        let (job_id, _, _, _, invocation) = invocation_fixture(dir.path(), false);
        fs::remove_file(dir.path().join(&job_id).join("native-output-logs.json"))
            .expect("remove worker completion seal");
        assert!(
            observe_run_local_invocation(dir.path(), &job_id, &challenge, &invocation).is_err()
        );
        assert!(
            !dir.path().join(KEY_DIR).exists(),
            "missing worker completion seal must not create signing state"
        );

        let dir = tempdir().expect("wrong argv root");
        let (job_id, _, _, _, _invocation) = invocation_fixture(dir.path(), false);
        assert!(
            observe_run_local_invocation(dir.path(), &job_id, &challenge, &"f".repeat(64),)
                .is_err()
        );
        assert!(!dir.path().join(KEY_DIR).exists());

        let dir = tempdir().expect("wrong binary root");
        let (job_id, _, _, candidate_path, invocation) = invocation_fixture(dir.path(), false);
        fs::write(candidate_path, b"changed-executable").expect("replace candidate bytes");
        assert!(
            observe_run_local_invocation(dir.path(), &job_id, &challenge, &invocation,).is_err()
        );

        let dir = tempdir().expect("cross-run output root");
        let (job_id, _, _, _, invocation) = invocation_fixture(dir.path(), false);
        let commitment_path = dir.path().join(&job_id).join("native-output-logs.json");
        let mut output_commitment: StoredInvocationOutputCommitment =
            read_stored_record(&commitment_path).expect("worker output commitment");
        output_commitment.run_id = "1123456789abcdef0123456789abcdef".to_owned();
        fs::write(
            &commitment_path,
            serde_json::to_vec(&output_commitment).expect("encode cross-run commitment"),
        )
        .expect("replace worker commitment fixture");
        hostlink_core::restrict_private_file(&commitment_path).expect("keep commitment private");
        assert!(
            observe_run_local_invocation(dir.path(), &job_id, &challenge, &invocation,).is_err(),
            "completion commitments must be bound to the exact run"
        );

        let dir = tempdir().expect("missing output root");
        let (job_id, _, _, _, invocation) = invocation_fixture(dir.path(), false);
        fs::remove_file(dir.path().join(&job_id).join("stderr.log"))
            .expect("remove Agent-owned stderr log");
        assert!(
            observe_run_local_invocation(dir.path(), &job_id, &challenge, &invocation,).is_err()
        );
        assert!(
            !dir.path()
                .join(KEY_DIR)
                .join(INVOCATION_RECORD_DIR)
                .join(format!("{job_id}.json"))
                .exists(),
            "missing logs cannot produce a signature"
        );

        let dir = tempdir().expect("tampered-before-signing root");
        let (job_id, _, _, _, invocation) = invocation_fixture(dir.path(), false);
        fs::write(
            dir.path().join(&job_id).join("stdout.log"),
            b"caller supplied",
        )
        .expect("tamper output before signing");
        hostlink_core::restrict_private_file(&dir.path().join(&job_id).join("stdout.log"))
            .expect("keep tampered output private");
        assert!(
            observe_run_local_invocation(dir.path(), &job_id, &challenge, &invocation,).is_err(),
            "pre-sign tampering must differ from the worker completion commitment"
        );
        assert!(!dir.path().join(KEY_DIR).exists());

        let dir = tempdir().expect("truncated output root");
        let (job_id, _, _, _, invocation) = invocation_fixture(dir.path(), true);
        assert!(
            observe_run_local_invocation(dir.path(), &job_id, &challenge, &invocation,).is_err()
        );

        let dir = tempdir().expect("unclean results root");
        let (job_id, _, workspace, _, invocation) = invocation_fixture(dir.path(), false);
        fs::create_dir(dir.path().join(&job_id).join("results"))
            .expect("unretrieved result set root");
        let state_path = dir.path().join(&job_id).join("state-000000.json");
        let mut state: serde_json::Value =
            serde_json::from_slice(&fs::read(&state_path).expect("read fixture state"))
                .expect("fixture state JSON");
        state["job"]["result_set"] = serde_json::json!({
            "owner": {"kind":"job", "job_id":job_id.clone()},
            "artifacts": []
        });
        fs::write(
            &state_path,
            serde_json::to_vec(&state).expect("encode state"),
        )
        .expect("persist unclean result state");
        assert!(
            observe_run_local_invocation(dir.path(), &job_id, &challenge, &invocation,).is_err()
        );
        assert!(workspace.is_dir(), "unretrieved results preserve run root");

        let dir = tempdir().expect("ambiguous cleanup root");
        let (job_id, _, workspace, _, invocation) = invocation_fixture(dir.path(), false);
        fs::remove_dir(&workspace).expect("external disappearance creates ambiguous cleanup");
        assert!(
            observe_run_local_invocation(dir.path(), &job_id, &challenge, &invocation,).is_err()
        );
        assert!(
            !dir.path()
                .join(KEY_DIR)
                .join(INVOCATION_RECORD_DIR)
                .join(format!("{job_id}.json"))
                .exists()
        );
    }

    #[test]
    fn invocation_observation_keeps_test_summary_text_opaque() {
        let dir = tempdir().expect("test-summary root");
        let (job_id, _, _, _, invocation) = invocation_fixture(dir.path(), false);
        let stdout = concat!(
            r#"{"type":"test_started","test_name":"approved::test"}"#,
            "\n",
            r#"{"type":"test_finished","test_name":"approved::test","result":"passed"}"#,
            "\n",
            r#"{"type":"run_finished","passed":1,"failed":0,"ignored":0,"filtered":0}"#,
            "\n",
            "<?xml version=\"1.0\"?><testsuite tests=\"1\" failures=\"0\"><testcase name=\"approved::test\"/></testsuite>\n",
            "PASS: test result: ok. 0 passed; 0 failed; 3 ignored; 7 filtered out\n",
        )
        .as_bytes();
        let stderr = b"operator supplied summary\n";
        let job_dir = dir.path().join(&job_id);
        fs::write(job_dir.join("stdout.log"), stdout).expect("replace stdout fixture");
        fs::write(job_dir.join("stderr.log"), stderr).expect("replace stderr fixture");
        hostlink_core::restrict_private_file(&job_dir.join("stdout.log")).expect("private stdout");
        hostlink_core::restrict_private_file(&job_dir.join("stderr.log")).expect("private stderr");

        let job = super::super::jobs::status(dir.path(), &job_id).expect("terminal Agent state");
        fs::remove_file(job_dir.join("native-output-logs.json"))
            .expect("replace fixture worker commitment");
        write_completed_invocation_output_logs(
            dir.path(),
            &job,
            &invocation,
            AgentNativeInvocationOutputLogs {
                stdout_sha256: format!("{:x}", Sha256::digest(stdout)),
                stdout_bytes: stdout.len() as u64,
                stderr_sha256: format!("{:x}", Sha256::digest(stderr)),
                stderr_bytes: stderr.len() as u64,
            },
            None,
        )
        .expect("fixture worker completion commitment");

        let (record, _) =
            observe_run_local_invocation(dir.path(), &job_id, &"9".repeat(64), &invocation)
                .expect("observe exact successful process invocation");
        let signed_record = serde_json::to_value(record).expect("signed observation payload");
        assert_eq!(signed_record["command_exit_code"], 0);
        assert_eq!(
            signed_record["output_logs"]["stdout_sha256"],
            format!("{:x}", Sha256::digest(stdout))
        );
        for field in [
            "suite_outcome",
            "selected_tests",
            "executed_tests",
            "test_names",
            "tests_passed",
            "tests_filtered",
            "tests_ignored",
            "tests_failed",
        ] {
            assert!(
                signed_record.get(field).is_none(),
                "Agent must not turn stdout text into signed suite field {field}"
            );
        }
    }

    #[test]
    fn invocation_observation_rejects_failed_and_incomplete_processes() {
        for (job_state, exit_code) in [
            (AgentJobState::Failed, Some(1)),
            (AgentJobState::Succeeded, Some(1)),
            (AgentJobState::Interrupted, None),
        ] {
            let dir = tempdir().expect("failed invocation root");
            let (job_id, _, _, _, invocation) = invocation_fixture(dir.path(), false);
            let state_path = dir.path().join(&job_id).join("state-000000.json");
            let mut terminal: serde_json::Value =
                serde_json::from_slice(&fs::read(&state_path).expect("read terminal state"))
                    .expect("terminal state JSON");
            terminal["job"]["state"] = serde_json::to_value(job_state).expect("encode job state");
            terminal["job"]["exit_code"] = serde_json::json!(exit_code);
            fs::write(
                &state_path,
                serde_json::to_vec(&terminal).expect("encode altered terminal state"),
            )
            .expect("persist failed terminal state");

            assert!(
                observe_run_local_invocation(dir.path(), &job_id, &"a".repeat(64), &invocation,)
                    .is_err()
            );
            assert!(
                !dir.path().join(KEY_DIR).exists(),
                "failed or incomplete process must not create signing state"
            );
        }
    }

    #[test]
    fn invocation_result_manifest_requires_exact_job_owner_and_declarations() {
        use onec_agent_protocol::{
            AgentJobState, ResultArtifactInfo, ResultArtifactSpec, ResultOwner, ResultSetInfo,
        };

        let declaration = ResultArtifactSpec::try_new(
            "report.bin".to_owned(),
            64,
            Some("application/octet-stream".to_owned()),
        )
        .expect("declaration");
        let artifact = ResultArtifactInfo::try_new(
            "report.bin".to_owned(),
            4,
            format!("{:x}", Sha256::digest(b"data")),
            Some("application/octet-stream".to_owned()),
        )
        .expect("artifact metadata");
        let result_set = ResultSetInfo::try_new(
            ResultOwner::job("job-result-owner".to_owned()).expect("job owner"),
            vec![artifact],
        )
        .expect("result set");
        let job = onec_agent_protocol::AgentJobInfo {
            job_id: "job-result-owner".to_owned(),
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
            result_set: Some(result_set.clone()),
            run_local: None,
        };
        validate_result_set_commitment(&job, std::slice::from_ref(&declaration))
            .expect("exact owner and declared result");
        assert!(validate_result_set_commitment(&job, &[]).is_err());
        let mut missing = job.clone();
        missing.result_set = None;
        assert!(
            validate_result_set_commitment(&missing, std::slice::from_ref(&declaration)).is_err()
        );

        let wrong_owner = ResultSetInfo::try_new(
            ResultOwner::job("job-other".to_owned()).expect("other job owner"),
            result_set.artifacts().to_vec(),
        )
        .expect("well-formed foreign result set");
        let mut foreign_job = job;
        foreign_job.result_set = Some(wrong_owner);
        assert!(validate_result_set_commitment(&foreign_job, &[declaration]).is_err());
    }

    #[test]
    fn invocation_observation_requires_a_closed_effect_label_and_no_arbitrary_test_names() {
        let record = serde_json::json!({
            "schema_version": 1,
            "challenge": "c",
            "job_id": "job-test",
            "run_id": "0123456789abcdef0123456789abcdef",
            "invocation_sha256": "a".repeat(64),
            "candidate_sha256": "b".repeat(64),
            "declared_effect": "read-only",
            "host_arch": "x86_64",
            "host_os": "windows",
            "command_exit_code": 0,
            "cleanup_completion": "complete",
            "signer_id": "agent-key",
            "executed_tests": ["forged::passing_test"]
        });
        assert!(serde_json::from_value::<AgentNativeInvocationRecord>(record).is_err());
        let unknown_effect = serde_json::json!({
            "schema_version": 1,
            "challenge": "c",
            "job_id": "job-test",
            "run_id": "0123456789abcdef0123456789abcdef",
            "invocation_sha256": "a".repeat(64),
            "candidate_sha256": "b".repeat(64),
            "declared_effect": "unbounded",
            "host_arch": "x86_64",
            "host_os": "windows",
            "command_exit_code": 0,
            "cleanup_completion": "complete",
            "signer_id": "agent-key"
        });
        assert!(serde_json::from_value::<AgentNativeInvocationRecord>(unknown_effect).is_err());
    }

    fn invocation_fixture(
        root: &Path,
        stdout_truncated: bool,
    ) -> (String, String, PathBuf, PathBuf, String) {
        use sha2::Digest as _;

        hostlink_core::ensure_private_directory(root).expect("jobs root");
        let run_id = "0123456789abcdef0123456789abcdef".to_owned();
        let job_id = "job-native-invocation".to_owned();
        let run_parent = root.join("run-local-runs");
        let workspace = run_parent.join(&run_id);
        hostlink_core::ensure_private_directory(&run_parent).expect("run parent");
        hostlink_core::ensure_private_directory(&workspace).expect("run root");
        let candidate_bytes = b"pinned-native-test-executable";
        let candidate_sha256 = format!("{:x}", Sha256::digest(candidate_bytes));
        let candidate_dir = root.join("run-local-cache");
        hostlink_core::ensure_private_directory(&candidate_dir).expect("candidate cache");
        let candidate_name = format!("sha256-{candidate_sha256}.exe");
        let candidate_path = candidate_dir.join(&candidate_name);
        fs::write(&candidate_path, candidate_bytes).expect("candidate file");
        let identity = onec_agent_protocol::RunLocalJobIdentity::try_new(
            run_id.clone(),
            candidate_name,
            candidate_sha256,
            Vec::new(),
        )
        .expect("run-local identity");
        let job_dir = root.join(&job_id);
        hostlink_core::create_private_directory(&job_dir).expect("job directory");
        let args = vec!["--exact".to_owned(), "fixture::approved_case".to_owned()];
        let program = candidate_path.to_string_lossy().into_owned();
        let effect = onec_agent_protocol::NativeExecutionEffect::ReadOnly;
        let env = std::collections::BTreeMap::new();
        let invocation = onec_agent_protocol::NativeInvocationIdentity {
            program: &program,
            args: &args,
            cwd: None,
            env: &env,
            stdin: None,
            results: &[],
            run_local: &identity,
            native_effect: effect,
            native_suite_policy_sha256: None,
        }
        .sha256()
        .expect("invocation digest");
        hostlink_core::write_new_json_file(
            &job_dir.join("request.json"),
            &serde_json::json!({
                "version": 1,
                "program": &program,
                "args": &args,
                "cwd": null,
                "env": {},
                "stdin": null,
                "results": [],
                "run_local": &identity,
                "invocation_sha256": &invocation,
                "native_effect": effect,
            }),
        )
        .expect("persist immutable invocation request");
        let job = onec_agent_protocol::AgentJobInfo {
            job_id: job_id.clone(),
            state: AgentJobState::Succeeded,
            worker_pid: None,
            spawn_owner_pid: None,
            process_pid: Some(42),
            exit_code: Some(0),
            created_unix_ms: 1,
            started_unix_ms: Some(2),
            finished_unix_ms: Some(3),
            message: None,
            stdout_log_truncated: stdout_truncated,
            stderr_log_truncated: false,
            result_set: None,
            run_local: Some(identity),
        };
        hostlink_core::write_new_json_file(
            &job_dir.join("native-invocation.json"),
            &crate::jobs::NativeInvocationCommitment {
                version: 1,
                invocation_sha256: invocation.clone(),
                requested_exact_testcase: Some("fixture::approved_case".to_owned()),
                native_effect: effect,
                results: Vec::new(),
            },
        )
        .expect("persist invocation commitment");
        fs::write(
            job_dir.join("state-000000.json"),
            serde_json::to_vec(&serde_json::json!({"version": 1, "job": job.clone()}))
                .expect("state encoding"),
        )
        .expect("persist state");
        hostlink_core::write_new_private_bytes(&job_dir.join("stdout.log"), b"[REDACTED] stdout\n")
            .expect("Agent-owned redacted stdout log");
        hostlink_core::write_new_private_bytes(&job_dir.join("stderr.log"), b"stderr\n")
            .expect("Agent-owned stderr log");
        let output_logs = AgentNativeInvocationOutputLogs {
            stdout_sha256: format!("{:x}", Sha256::digest(b"[REDACTED] stdout\n")),
            stdout_bytes: b"[REDACTED] stdout\n".len() as u64,
            stderr_sha256: format!("{:x}", Sha256::digest(b"stderr\n")),
            stderr_bytes: b"stderr\n".len() as u64,
        };
        write_completed_invocation_output_logs(root, &job, &invocation, output_logs, None)
            .expect("Agent-owned immutable worker output commitment");
        (job_id, run_id, workspace, candidate_path, invocation)
    }

    fn fixture_job(
        root: &Path,
        state: AgentJobState,
        exit_code: Option<i32>,
    ) -> (String, String, PathBuf) {
        let jobs = root.to_path_buf();
        hostlink_core::ensure_private_directory(&jobs).expect("private jobs root");
        let run_id = "0123456789abcdef0123456789abcdef".to_owned();
        let job_id = format!(
            "job-attest-{}",
            match state {
                AgentJobState::Succeeded => "success",
                AgentJobState::Failed => "failed",
                AgentJobState::Interrupted => "interrupted",
                _ => "other",
            }
        );
        let run_parent = jobs.join("run-local-runs");
        let workspace = run_parent.join(&run_id);
        fs::create_dir_all(&workspace).expect("owned workspace");
        hostlink_core::ensure_private_directory(&run_parent).expect("private run parent");
        hostlink_core::ensure_private_directory(&workspace).expect("private workspace");
        let job_dir = jobs.join(&job_id);
        fs::create_dir(&job_dir).expect("job directory");
        hostlink_core::ensure_private_directory(&job_dir).expect("private job directory");
        let job = onec_agent_protocol::AgentJobInfo {
            job_id: job_id.clone(),
            state,
            worker_pid: None,
            spawn_owner_pid: None,
            process_pid: Some(123),
            exit_code,
            created_unix_ms: 1,
            started_unix_ms: Some(2),
            finished_unix_ms: Some(3),
            message: None,
            stdout_log_truncated: false,
            stderr_log_truncated: false,
            result_set: None,
            run_local: Some(
                onec_agent_protocol::RunLocalJobIdentity::try_new(
                    run_id.clone(),
                    format!("sha256-{}.exe", "d".repeat(64)),
                    "d".repeat(64),
                    Vec::new(),
                )
                .expect("valid run-local identity"),
            ),
        };
        fs::write(
            job_dir.join("state-000000.json"),
            serde_json::to_vec(&serde_json::json!({"version": 1, "job": job})).expect("state JSON"),
        )
        .expect("persist terminal state");
        (job_id, run_id, workspace)
    }

    #[cfg(unix)]
    #[test]
    fn signed_output_reader_refuses_same_length_replacement_after_open() {
        let dir = tempdir().expect("isolated log directory");
        let path = dir.path().join("stdout.log");
        let replacement = dir.path().join("replacement.log");
        fs::write(&path, b"signed bytes").expect("original output");
        fs::write(&replacement, b"otherd bytes").expect("same-size foreign output");
        hostlink_core::restrict_private_file(&path).expect("private signed output");
        hostlink_core::restrict_private_file(&replacement).expect("private replacement");
        let opened = open_private_log_nofollow(&path).expect("open original inode");
        assert!(opened_log_matches_path(&opened, &path).expect("original inode check"));

        fs::rename(&replacement, &path).expect("atomically replace output path");
        assert_eq!(opened.metadata().expect("old inode").len(), 12);
        assert_eq!(fs::metadata(&path).expect("new inode").len(), 12);
        assert!(
            !opened_log_matches_path(&opened, &path).expect("replacement inode check"),
            "identical file lengths must not conceal pathname replacement after open"
        );
    }

    fn hex_to_array<const N: usize>(value: &str) -> [u8; N] {
        let mut bytes = [0_u8; N];
        for (index, slot) in bytes.iter_mut().enumerate() {
            *slot = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).expect("hex byte");
        }
        bytes
    }
}
