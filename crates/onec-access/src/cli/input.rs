//! Bounded controller-local input for managed remote execution.

use super::*;
use hostlink_protocol::{MAX_STDIN_PAYLOAD_BYTES, StdinPayload};
use std::io;

pub(super) fn read_stdin_payload(source: Option<PathBuf>) -> AppResult<Option<StdinPayload>> {
    let Some(source) = source else {
        return Ok(None);
    };
    let bytes = if source.as_os_str() == "-" {
        let stdin = io::stdin();
        let mut locked = stdin.lock();
        hostlink_core::read_bounded_bytes(&mut locked, None, MAX_STDIN_PAYLOAD_BYTES)
            .map_err(|error| input_error("<stdin>", error))?
    } else {
        hostlink_core::read_file_bounded(&source, MAX_STDIN_PAYLOAD_BYTES)
            .map_err(|error| input_error(&source.display().to_string(), error))?
    };
    StdinPayload::try_new(bytes)
        .map(Some)
        .map_err(|error| crate::invalid_config(error.to_string()))
}

fn input_error(source: &str, error: io::Error) -> AppError {
    AppError::new(error).context(format!("failed to read bounded remote stdin from {source}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_input_preserves_exact_bytes_and_explicit_empty() {
        let dir = tempfile::tempdir().expect("tempdir");
        let binary = dir.path().join("input.bin");
        std::fs::write(&binary, [0_u8, 0xff, b'\n']).expect("write input");
        let payload = read_stdin_payload(Some(binary))
            .expect("read")
            .expect("payload");
        assert_eq!(payload.as_bytes(), &[0, 0xff, b'\n']);

        let empty = dir.path().join("empty.bin");
        std::fs::write(&empty, []).expect("write empty");
        let payload = read_stdin_payload(Some(empty))
            .expect("read")
            .expect("explicit empty");
        assert!(payload.is_empty());
    }

    #[test]
    fn file_input_rejects_one_byte_over_limit_before_remote_resolution() {
        let dir = tempfile::tempdir().expect("tempdir");
        let input = dir.path().join("too-large.bin");
        std::fs::write(&input, vec![0_u8; MAX_STDIN_PAYLOAD_BYTES + 1]).expect("write input");
        let error = read_stdin_payload(Some(input)).expect_err("oversized input");
        let chain = format!("{error:#}");
        assert!(chain.contains("maximum"), "{chain}");
        assert!(
            chain.contains(&MAX_STDIN_PAYLOAD_BYTES.to_string()),
            "{chain}"
        );
    }
}
