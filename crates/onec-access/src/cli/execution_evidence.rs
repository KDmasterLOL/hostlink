//! Receipts for terminal managed `run-local` process executions.

use onec_core::Sha256Digest;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{fs, io::Read, path::Path, str::FromStr};

pub(crate) const RECEIPT_DIRECTORY_ENV: &str = "ONEC_ACCESS_RUN_LOCAL_EVIDENCE_DIR";
pub(crate) const MAX_RAW_OUTPUT_BYTES: usize = 4 * 1024 * 1024;

pub(crate) fn output_sha256(bytes: &[u8]) -> Sha256Digest {
    // SHA-256 always produces the hexadecimal representation accepted by Sha256Digest.
    Sha256Digest::from_str(&format!("{:x}", Sha256::digest(bytes)))
        .expect("SHA-256 output is a valid digest")
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct RunLocalExecutionEvidence {
    pub(crate) schema_version: u32,
    pub(crate) toolkit_version: String,
    pub(crate) run_id: String,
    pub(crate) observed_controller_worktree_head_sha: String,
    pub(crate) runner_sha256: Sha256Digest,
    pub(crate) test_binary_sha256: Sha256Digest,
    pub(crate) host_id: String,
    pub(crate) host_name: String,
    pub(crate) host_os: String,
    pub(crate) target_triple: String,
    pub(crate) effect: String,
    /// Exact platform selected for the native child, when the caller pinned one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) selected_platform_version: Option<String>,
    pub(crate) test_filter: String,
    pub(crate) parameters_sha256: Sha256Digest,
    /// Digest of the exact raw stdout bytes returned by remote execution, when observed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) stdout_sha256: Option<Sha256Digest>,
    /// Digest of the exact raw stderr bytes returned by remote execution, when observed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) stderr_sha256: Option<Sha256Digest>,
    pub(crate) exit_code: Option<i32>,
    /// Count *reported by the child output*, not a trusted test-run attestation.
    pub(crate) reported_passed_test_count: u32,
    pub(crate) completed_at_unix_ms: u64,
}

/// Interprets one non-empty libtest transcript; child output is not authenticated.
pub(crate) fn reported_passed_test_count(stdout: &[u8], stderr: &[u8]) -> Option<u32> {
    let mut headers = Vec::new();
    let mut summaries = Vec::new();
    for output in [stdout, stderr] {
        let text = std::str::from_utf8(output).ok()?;
        let lines = text.lines().collect::<Vec<_>>();
        for (index, line) in lines.iter().enumerate() {
            let line = line.trim();
            if let Some(rest) = line.strip_prefix("running ") {
                let (count, suffix) = rest.split_once(' ')?;
                if suffix != "test" && suffix != "tests" {
                    return None;
                }
                headers.push(count.parse::<u32>().ok()?);
            } else if let Some(count) = parse_success_summary(line) {
                if lines[index + 1..]
                    .iter()
                    .any(|line| !line.trim().is_empty())
                {
                    return None;
                }
                summaries.push(count);
            } else if line.trim_start().starts_with("test result:") {
                // A failed or malformed summary is never execution evidence.
                return None;
            }
        }
    }
    match (headers.as_slice(), summaries.as_slice()) {
        ([header], [count]) if *count > 0 && *header == *count => Some(*count),
        _ => None,
    }
}

fn parse_success_summary(line: &str) -> Option<u32> {
    let summary = line.strip_prefix("test result: ok. ")?;
    let mut fields = summary.split(';').map(str::trim);
    let passed = fields
        .next()?
        .strip_suffix(" passed")?
        .parse::<u32>()
        .ok()?;
    let failed = fields
        .next()?
        .strip_suffix(" failed")?
        .parse::<u32>()
        .ok()?;
    let _ignored = fields
        .next()?
        .strip_suffix(" ignored")?
        .parse::<u32>()
        .ok()?;
    let _measured = fields
        .next()?
        .strip_suffix(" measured")?
        .parse::<u32>()
        .ok()?;
    let _filtered_out = fields
        .next()?
        .strip_suffix(" filtered out")?
        .parse::<u32>()
        .ok()?;
    let finished = fields.next()?;
    if !finished.starts_with("finished in ") || fields.next().is_some() {
        return None;
    }
    if failed != 0 {
        return None;
    }
    (passed > 0).then_some(passed)
}

pub(crate) fn target_triple(executable: &Path) -> Option<&'static str> {
    executable.components().find_map(|component| {
        let component = component.as_os_str().to_str()?;
        match component {
            "x86_64-pc-windows-msvc" => Some("x86_64-pc-windows-msvc"),
            "x86_64-win7-windows-msvc" => Some("x86_64-win7-windows-msvc"),
            "i686-win7-windows-msvc" => Some("i686-win7-windows-msvc"),
            _ => None,
        }
    })
}

pub(crate) fn write_create_new(
    directory: &Path,
    evidence: &RunLocalExecutionEvidence,
) -> std::io::Result<std::path::PathBuf> {
    onec_core::ensure_private_directory(directory)?;
    let path = directory.join(format!("{}.json", evidence.run_id));
    let bytes = serde_json::to_vec(evidence).map_err(std::io::Error::other)?;
    let digest = format!("{:x}", Sha256::digest(&bytes));
    let checksum_path = path.with_extension("json.sha256");
    onec_core::write_new_private_bytes(&path, &bytes)?;
    let checksum = format!(
        "{digest}  {}\n",
        path.file_name().unwrap_or_default().to_string_lossy()
    );
    if let Err(error) = onec_core::write_new_private_bytes(&checksum_path, checksum.as_bytes()) {
        return match fs::remove_file(&path) {
            Ok(()) => Err(error),
            Err(cleanup) => Err(std::io::Error::new(
                error.kind(),
                format!(
                    "cannot create receipt checksum: {error}; cannot remove partial receipt: {cleanup}"
                ),
            )),
        };
    }
    Ok(path)
}

/// Persist bounded raw output and its receipt as one fail-clean local evidence operation.
pub(crate) fn write_create_new_with_output(
    directory: &Path,
    evidence: &RunLocalExecutionEvidence,
    stdout: &[u8],
    stderr: &[u8],
) -> std::io::Result<std::path::PathBuf> {
    if stdout.len() > MAX_RAW_OUTPUT_BYTES || stderr.len() > MAX_RAW_OUTPUT_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "run-local raw output exceeds the 4 MiB per-stream limit",
        ));
    }
    if evidence.stdout_sha256.as_ref() != Some(&output_sha256(stdout))
        || evidence.stderr_sha256.as_ref() != Some(&output_sha256(stderr))
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "run-local raw output does not match receipt digests",
        ));
    }
    if evidence.run_id.len() != 32
        || !evidence
            .run_id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "run-local evidence run ID is invalid",
        ));
    }

    onec_core::ensure_private_directory(directory)?;
    let stdout_path = directory.join(format!("{}.stdout", evidence.run_id));
    let stderr_path = directory.join(format!("{}.stderr", evidence.run_id));
    write_output_create_new(&stdout_path, stdout)?;
    if let Err(error) = write_output_create_new(&stderr_path, stderr) {
        return Err(remove_owned_file_after_error(&stdout_path, error));
    }
    match write_create_new(directory, evidence) {
        Ok(path) => Ok(path),
        Err(error) => {
            let error = remove_owned_file_after_error(&stderr_path, error);
            Err(remove_owned_file_after_error(&stdout_path, error))
        }
    }
}

fn remove_owned_file_after_error(path: &Path, error: std::io::Error) -> std::io::Error {
    match fs::remove_file(path) {
        Ok(()) => error,
        Err(cleanup) if cleanup.kind() == std::io::ErrorKind::NotFound => error,
        Err(cleanup) => std::io::Error::new(
            error.kind(),
            format!("{error}; cannot remove partial run-local evidence file: {cleanup}"),
        ),
    }
}

fn write_output_create_new(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    write_output_create_new_with(path, bytes, |file, bytes| {
        use std::io::Write as _;
        file.write_all(bytes)?;
        file.sync_all()
    })
}

fn write_output_create_new_with(
    path: &Path,
    bytes: &[u8],
    write: impl FnOnce(&mut fs::File, &[u8]) -> std::io::Result<()>,
) -> std::io::Result<()> {
    let mut file = onec_core::create_new_private_file(path)?;
    if let Err(error) = write(&mut file, bytes) {
        drop(file);
        return Err(remove_owned_file_after_error(path, error));
    }
    Ok(())
}

pub(crate) fn read_verified(path: &Path) -> anyhow::Result<RunLocalExecutionEvidence> {
    const MAX_BYTES: u64 = 128 * 1024;
    let metadata = fs::symlink_metadata(path)?;
    anyhow::ensure!(
        metadata.file_type().is_file(),
        "receipt is not a regular file"
    );
    anyhow::ensure!(metadata.len() <= MAX_BYTES, "receipt exceeds size limit");
    let file = fs::File::open(path)?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_BYTES + 1).read_to_end(&mut bytes)?;
    anyhow::ensure!(
        bytes.len() as u64 <= MAX_BYTES,
        "receipt exceeds size limit"
    );
    let actual = format!("{:x}", Sha256::digest(&bytes));

    let checksum_path = path.with_extension("json.sha256");
    let checksum_metadata = fs::symlink_metadata(&checksum_path)?;
    anyhow::ensure!(
        checksum_metadata.file_type().is_file() && checksum_metadata.len() <= 4096,
        "receipt checksum is not a bounded regular file"
    );
    let checksum = fs::read_to_string(checksum_path)?;
    let expected = format!(
        "{actual}  {}\n",
        path.file_name().unwrap_or_default().to_string_lossy()
    );
    anyhow::ensure!(checksum == expected, "receipt checksum mismatch");

    let evidence: RunLocalExecutionEvidence = serde_json::from_slice(&bytes)?;
    anyhow::ensure!(evidence.schema_version == 3, "unsupported receipt schema");
    anyhow::ensure!(
        !evidence.toolkit_version.is_empty(),
        "receipt toolkit version is missing"
    );
    anyhow::ensure!(
        evidence.observed_controller_worktree_head_sha.len() == 40
            && evidence
                .observed_controller_worktree_head_sha
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
        "receipt source Git SHA is invalid"
    );
    anyhow::ensure!(
        evidence.run_id.len() == 32
            && evidence
                .run_id
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
        "receipt run ID is invalid"
    );
    anyhow::ensure!(
        !evidence.host_id.trim().is_empty(),
        "receipt host identity is missing"
    );
    anyhow::ensure!(
        !evidence.host_name.trim().is_empty(),
        "receipt host name is missing"
    );
    anyhow::ensure!(
        !evidence.host_os.trim().is_empty(),
        "receipt host OS is missing"
    );
    anyhow::ensure!(
        !evidence.test_filter.trim().is_empty(),
        "receipt test filter is missing"
    );
    anyhow::ensure!(
        evidence
            .selected_platform_version
            .as_deref()
            .is_none_or(|version| !version.trim().is_empty()),
        "receipt selected platform version is empty"
    );
    anyhow::ensure!(
        matches!(
            evidence.target_triple.as_str(),
            "x86_64-pc-windows-msvc" | "x86_64-win7-windows-msvc" | "i686-win7-windows-msvc"
        ),
        "receipt target triple is unsupported"
    );
    anyhow::ensure!(
        matches!(
            evidence.effect.as_str(),
            "read-only" | "run-owned" | "disposable"
        ),
        "receipt effect is unsupported"
    );
    anyhow::ensure!(
        evidence.completed_at_unix_ms > 0,
        "receipt completion time is missing"
    );
    anyhow::ensure!(
        evidence.exit_code == Some(0) && evidence.reported_passed_test_count > 0,
        "receipt lacks a successful non-empty reported libtest transcript"
    );
    Ok(evidence)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn digest(char: &str) -> Sha256Digest {
        Sha256Digest::from_str(&char.repeat(64)).expect("valid fixture digest")
    }

    fn evidence(exit_code: Option<i32>) -> RunLocalExecutionEvidence {
        RunLocalExecutionEvidence {
            schema_version: 3,
            toolkit_version: env!("CARGO_PKG_VERSION").to_owned(),
            run_id: "00112233445566778899aabbccddeeff".to_owned(),
            observed_controller_worktree_head_sha: "a".repeat(40),
            runner_sha256: digest("2"),
            test_binary_sha256: digest("3"),
            host_id: "machine-01".to_owned(),
            host_name: "test-host".to_owned(),
            host_os: "windows".to_owned(),
            target_triple: "x86_64-pc-windows-msvc".to_owned(),
            effect: "read-only".to_owned(),
            selected_platform_version: None,
            test_filter: "tests::read_only_case".to_owned(),
            parameters_sha256: digest("4"),
            stdout_sha256: None,
            stderr_sha256: None,
            exit_code,
            reported_passed_test_count: 1,
            completed_at_unix_ms: 1_800_000_000_000,
        }
    }

    #[test]
    fn reported_count_requires_one_matching_nonempty_libtest_transcript() {
        let summary = b"running 2 tests\ntest a ... ok\ntest b ... ok\ntest result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n";
        assert_eq!(reported_passed_test_count(summary, b""), Some(2));
        assert_eq!(
            reported_passed_test_count(
                b"running 1 test\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n",
                b""
            ),
            Some(1)
        );
        assert_eq!(
            reported_passed_test_count(
                b"",
                b"running 1 test\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n"
            ),
            Some(1)
        );
        let positive = b"test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n";
        assert_eq!(reported_passed_test_count(positive, b""), None);
        assert_eq!(
            reported_passed_test_count(&[b"running 0 tests\n".as_slice(), positive].concat(), b""),
            None
        );
        assert_eq!(
            reported_passed_test_count(&[b"running 2 tests\n".as_slice(), positive].concat(), b""),
            None
        );
        assert_eq!(
            reported_passed_test_count(
                &[b"running 1 test\nrunning 1 test\n".as_slice(), positive].concat(),
                b""
            ),
            None
        );
        assert_eq!(
            reported_passed_test_count(
                b"test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n",
                b""
            ),
            None
        );
        assert_eq!(reported_passed_test_count(b"running 0 tests\n", b""), None);
        assert_eq!(
            reported_passed_test_count(b"test result: failed. 1 failed\n", b""),
            None
        );
        assert_eq!(
            reported_passed_test_count(
                b"test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\nextra output\n",
                b""
            ),
            None
        );
        assert_eq!(
            reported_passed_test_count(
                b"test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n",
                b"test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n"
            ),
            None
        );
    }

    #[test]
    fn target_triple_is_observed_from_the_executable_path() {
        assert_eq!(
            target_triple(Path::new(
                "/target/i686-win7-windows-msvc/debug/deps/native.exe"
            )),
            Some("i686-win7-windows-msvc")
        );
        assert_eq!(target_triple(Path::new("/target/debug/native")), None);
    }

    #[test]
    fn terminal_results_write_create_new_checksummed_receipts() {
        let root = tempfile::tempdir().expect("temp directory");
        let zero_exit = evidence(Some(0));
        let path = write_create_new(root.path(), &zero_exit).expect("write terminal receipt");
        let bytes = fs::read(&path).expect("read receipt");
        let decoded: RunLocalExecutionEvidence =
            serde_json::from_slice(&bytes).expect("typed receipt");
        assert_eq!(decoded, zero_exit);
        let json: serde_json::Value = serde_json::from_slice(&bytes).expect("receipt JSON");
        assert_eq!(json["exit_code"], 0);
        assert!(json.get("status").is_none());
        assert!(json.get("stdout_sha256").is_none());
        assert!(json.get("stderr_sha256").is_none());
        let checksum =
            fs::read_to_string(path.with_extension("json.sha256")).expect("checksum sidecar");
        let actual = format!("{:x}", Sha256::digest(&bytes));
        assert!(checksum.starts_with(&actual));
        assert_eq!(read_verified(&path).expect("verified receipt"), zero_exit);
        assert!(write_create_new(root.path(), &zero_exit).is_err());

        fs::write(&path, b"{}").expect("alter receipt");
        assert!(read_verified(&path).is_err());

        let failed = evidence(Some(1));
        assert_eq!(failed.exit_code, Some(1));
        let unknown = evidence(None);
        assert_eq!(unknown.exit_code, None);
        let collision =
            write_create_new(root.path(), &zero_exit).expect_err("receipt already exists");
        assert_eq!(collision.kind(), std::io::ErrorKind::AlreadyExists);
    }

    #[test]
    fn selected_platform_is_recorded_and_legacy_receipts_remain_readable() {
        let root = tempfile::tempdir().expect("temp directory");
        let mut pinned = evidence(Some(0));
        pinned.selected_platform_version = Some("8.3.27.1859".to_owned());
        let path = write_create_new(root.path(), &pinned).expect("write pinned receipt");
        assert_eq!(read_verified(&path).expect("verified receipt"), pinned);

        let mut legacy = evidence(Some(0));
        let bytes = serde_json::to_vec(&legacy).expect("encode receipt");
        let mut value: serde_json::Value = serde_json::from_slice(&bytes).expect("receipt JSON");
        value
            .as_object_mut()
            .expect("receipt object")
            .remove("selected_platform_version");
        let decoded: RunLocalExecutionEvidence =
            serde_json::from_value(value).expect("decode legacy receipt");
        legacy.selected_platform_version = None;
        assert_eq!(decoded, legacy);

        let mut legacy = evidence(Some(0));
        legacy.run_id = "50112233445566778899aabbccddeeff".to_owned();
        let path = write_create_new(root.path(), &legacy).expect("write legacy receipt");
        assert_eq!(read_verified(&path).expect("read legacy receipt"), legacy);

        let mut empty = evidence(Some(0));
        empty.run_id = "40112233445566778899aabbccddeeff".to_owned();
        empty.selected_platform_version = Some("  ".to_owned());
        let path = write_create_new(root.path(), &empty).expect("write invalid fixture");
        assert!(read_verified(&path).is_err());
    }

    #[test]
    fn output_digest_hashes_exact_raw_bytes_and_receipt_stores_no_output_content() {
        let stdout = b"private test output\n\xff";
        let stderr = b"private diagnostic\0";
        let mut value = evidence(Some(0));
        value.stdout_sha256 = Some(output_sha256(stdout));
        value.stderr_sha256 = Some(output_sha256(stderr));

        assert_eq!(
            value.stdout_sha256,
            Some(Sha256Digest::from_str(&format!("{:x}", Sha256::digest(stdout))).unwrap())
        );
        assert_eq!(
            value.stderr_sha256,
            Some(Sha256Digest::from_str(&format!("{:x}", Sha256::digest(stderr))).unwrap())
        );
        let json = serde_json::to_vec(&value).expect("encode receipt");
        let fields: serde_json::Value = serde_json::from_slice(&json).expect("receipt JSON");
        assert_eq!(
            fields["stdout_sha256"],
            value.stdout_sha256.unwrap().to_string()
        );
        assert_eq!(
            fields["stderr_sha256"],
            value.stderr_sha256.unwrap().to_string()
        );
        assert!(!json.windows(stdout.len()).any(|window| window == stdout));
        assert!(!json.windows(stderr.len()).any(|window| window == stderr));
        let decoded: RunLocalExecutionEvidence =
            serde_json::from_slice(&json).expect("typed receipt");
        assert_eq!(decoded.stdout_sha256, value.stdout_sha256);
        assert_eq!(decoded.stderr_sha256, value.stderr_sha256);

        let root = tempfile::tempdir().expect("temp directory");
        let path = write_create_new(root.path(), &value).expect("write receipt");
        let mut invalid: serde_json::Value = serde_json::from_slice(&json).expect("receipt JSON");
        invalid["stdout_sha256"] = serde_json::Value::String("not-a-digest".to_owned());
        let invalid_bytes = serde_json::to_vec(&invalid).expect("encode invalid receipt");
        fs::write(&path, &invalid_bytes).expect("write malformed digest");
        let checksum = format!(
            "{:x}  {}\n",
            Sha256::digest(&invalid_bytes),
            path.file_name()
                .expect("receipt filename")
                .to_string_lossy()
        );
        fs::write(path.with_extension("json.sha256"), checksum).expect("update checksum");
        assert!(read_verified(&path).is_err());
    }

    #[test]
    fn bounded_raw_output_is_written_with_receipt_and_matches_receipt_digests() {
        let root = tempfile::tempdir().expect("temp directory");
        let stdout = b"raw stdout\n\xff";
        let stderr = b"raw stderr\0";
        let mut value = evidence(Some(0));
        value.stdout_sha256 = Some(output_sha256(stdout));
        value.stderr_sha256 = Some(output_sha256(stderr));

        let receipt = write_create_new_with_output(root.path(), &value, stdout, stderr)
            .expect("write output and receipt");
        let stdout_path = root.path().join(format!("{}.stdout", value.run_id));
        let stderr_path = root.path().join(format!("{}.stderr", value.run_id));
        assert_eq!(fs::read(&stdout_path).expect("read raw stdout"), stdout);
        assert_eq!(fs::read(&stderr_path).expect("read raw stderr"), stderr);
        assert_eq!(
            output_sha256(&fs::read(stdout_path).unwrap()),
            value.stdout_sha256.unwrap()
        );
        assert_eq!(
            output_sha256(&fs::read(stderr_path).unwrap()),
            value.stderr_sha256.unwrap()
        );
        assert_eq!(read_verified(&receipt).expect("verify receipt"), value);
    }

    #[test]
    fn oversized_raw_output_creates_no_evidence_files() {
        let root = tempfile::tempdir().expect("temp directory");
        let stdout = vec![b'x'; MAX_RAW_OUTPUT_BYTES + 1];
        let stderr = b"";
        let mut value = evidence(Some(0));
        value.stdout_sha256 = Some(output_sha256(&stdout));
        value.stderr_sha256 = Some(output_sha256(stderr));

        let error = write_create_new_with_output(root.path(), &value, &stdout, stderr)
            .expect_err("oversized output rejected");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(fs::read_dir(root.path()).unwrap().next().is_none());
    }

    #[test]
    fn duplicate_output_path_preserves_existing_file_and_removes_only_owned_output() {
        let root = tempfile::tempdir().expect("temp directory");
        let stdout = b"new stdout";
        let stderr = b"new stderr";
        let mut value = evidence(Some(0));
        value.stdout_sha256 = Some(output_sha256(stdout));
        value.stderr_sha256 = Some(output_sha256(stderr));
        let stdout_path = root.path().join(format!("{}.stdout", value.run_id));
        let stderr_path = root.path().join(format!("{}.stderr", value.run_id));
        fs::write(&stderr_path, b"unrelated pre-existing output").unwrap();

        assert!(write_create_new_with_output(root.path(), &value, stdout, stderr).is_err());
        assert!(!stdout_path.exists());
        assert_eq!(
            fs::read(stderr_path).unwrap(),
            b"unrelated pre-existing output"
        );
        assert!(!root.path().join(format!("{}.json", value.run_id)).exists());
    }

    #[test]
    fn failed_receipt_sidecar_write_removes_outputs_and_partial_receipt_only() {
        let root = tempfile::tempdir().expect("temp directory");
        let stdout = b"new stdout";
        let stderr = b"new stderr";
        let mut value = evidence(Some(0));
        value.stdout_sha256 = Some(output_sha256(stdout));
        value.stderr_sha256 = Some(output_sha256(stderr));
        let receipt = root.path().join(format!("{}.json", value.run_id));
        let checksum = receipt.with_extension("json.sha256");
        fs::write(&checksum, b"preserve existing checksum").unwrap();

        assert!(write_create_new_with_output(root.path(), &value, stdout, stderr).is_err());
        assert!(
            !root
                .path()
                .join(format!("{}.stdout", value.run_id))
                .exists()
        );
        assert!(
            !root
                .path()
                .join(format!("{}.stderr", value.run_id))
                .exists()
        );
        assert!(!receipt.exists());
        assert_eq!(fs::read(checksum).unwrap(), b"preserve existing checksum");
    }

    #[test]
    fn partial_raw_output_write_removes_only_the_new_partial_file() {
        let root = tempfile::tempdir().expect("temp directory");
        let path = root.path().join("partial.stdout");
        let error = write_output_create_new_with(&path, b"complete output", |file, _| {
            use std::io::Write as _;
            file.write_all(b"partial")?;
            Err(std::io::Error::other("injected write failure"))
        })
        .expect_err("partial output write rejected");
        assert_eq!(error.to_string(), "injected write failure");
        assert!(!path.exists());

        let unrelated = root.path().join("unrelated.stdout");
        fs::write(&unrelated, b"keep").unwrap();
        let error = write_output_create_new_with(&unrelated, b"replacement", |_, _| {
            Err(std::io::Error::other("must not run for duplicate"))
        })
        .expect_err("duplicate output rejected");
        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(unrelated).unwrap(), b"keep");
    }

    #[test]
    fn failed_sidecar_creation_removes_only_the_partial_receipt() {
        let root = tempfile::tempdir().expect("temp directory");
        let value = evidence(Some(0));
        let receipt = root.path().join(format!("{}.json", value.run_id));
        let checksum = receipt.with_extension("json.sha256");
        fs::write(&checksum, b"pre-existing sidecar").expect("occupy sidecar");

        assert!(write_create_new(root.path(), &value).is_err());
        assert!(!receipt.exists());
        assert_eq!(
            fs::read(&checksum).expect("existing sidecar preserved"),
            b"pre-existing sidecar"
        );
    }

    #[test]
    fn failed_or_empty_execution_receipts_are_rejected() {
        let root = tempfile::tempdir().expect("temp directory");
        for (run_id, exit_code, count) in [
            ("10112233445566778899aabbccddeeff", Some(1), 1),
            ("20112233445566778899aabbccddeeff", Some(0), 0),
            ("30112233445566778899aabbccddeeff", None, 1),
        ] {
            let mut invalid = evidence(Some(0));
            invalid.run_id = run_id.to_owned();
            invalid.exit_code = exit_code;
            invalid.reported_passed_test_count = count;
            let path = write_create_new(root.path(), &invalid).expect("write fixture");
            assert!(read_verified(&path).is_err());
        }
    }

    #[cfg(unix)]
    #[test]
    fn receipt_directory_and_machine_metadata_files_are_private() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = tempfile::tempdir().expect("temp directory");
        let directory = root.path().join("private");
        let path = write_create_new(&directory, &evidence(Some(0))).expect("write receipt");
        assert_eq!(
            std::fs::metadata(&directory)
                .expect("directory metadata")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(&path)
                .expect("receipt metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(path.with_extension("json.sha256"))
                .expect("checksum metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    #[test]
    fn receipt_consumer_rejects_missing_or_malformed_checksum() {
        let root = tempfile::tempdir().expect("temp directory");
        let path = write_create_new(root.path(), &evidence(Some(0))).expect("write receipt");

        fs::remove_file(path.with_extension("json.sha256")).expect("remove checksum");
        assert!(read_verified(&path).is_err());

        fs::write(path.with_extension("json.sha256"), "not-a-checksum\n")
            .expect("write invalid checksum");
        assert!(read_verified(&path).is_err());
    }

    #[test]
    fn receipt_consumer_rejects_invalid_source_identity_even_with_a_matching_checksum() {
        let root = tempfile::tempdir().expect("temp directory");
        let path = write_create_new(root.path(), &evidence(Some(0))).expect("write receipt");
        let mut value = evidence(Some(0));
        value.observed_controller_worktree_head_sha = "not-a-commit".to_owned();
        let bytes = serde_json::to_vec(&value).expect("encode invalid fixture");
        fs::write(&path, &bytes).expect("replace receipt");
        let checksum = format!(
            "{:x}  {}\n",
            Sha256::digest(&bytes),
            path.file_name()
                .expect("receipt filename")
                .to_string_lossy()
        );
        fs::write(path.with_extension("json.sha256"), checksum).expect("replace checksum");

        assert!(read_verified(&path).is_err());
    }
}
