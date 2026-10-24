//! Secret-safe HTTPS enrollment transport used only by a verified installer candidate.

use std::io;
use std::path::Path;
use std::time::Duration;

const MAX_ENROLLMENT_TOKEN_BYTES: usize = 4096;
const MAX_ENROLLMENT_REQUEST_BYTES: usize = 64 * 1024;
const MAX_ENROLLMENT_RESPONSE_BYTES: u64 = 1024 * 1024;
const ENROLLMENT_TIMEOUT: Duration = Duration::from_secs(60);

/// Post one enrollment request without exposing the bearer token in argv or stdout.
///
/// The token must come from a toolkit-private file and the response path must not already exist.
/// Authenticated enrollment is HTTPS-only and follows no redirects.
///
/// # Errors
///
/// Returns `std::io::Error` for unsafe/invalid inputs, transport failures, oversized or invalid
/// JSON responses, or private response publication failure.
pub fn post_enrollment_json(
    url: &str,
    token_file: &Path,
    body_file: &Path,
    output: &Path,
) -> io::Result<()> {
    validate_enrollment_url(url)?;
    validate_secret_file(token_file)?;
    ensure_output_absent(output)?;

    let token = hostlink_core::read_file_bounded(token_file, MAX_ENROLLMENT_TOKEN_BYTES)?;
    let token = std::str::from_utf8(&token)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?
        .trim();
    if token.len() != 64 || !token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "enrollment token must contain exactly 64 hexadecimal characters",
        ));
    }

    let body = hostlink_core::read_file_bounded(body_file, MAX_ENROLLMENT_REQUEST_BYTES)?;
    serde_json::from_slice::<serde_json::Value>(&body).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("enrollment request is not valid JSON: {error}"),
        )
    })?;

    let config = ureq::Agent::config_builder()
        .https_only(true)
        .max_redirects(0)
        .timeout_global(Some(ENROLLMENT_TIMEOUT))
        .build();
    let agent = ureq::Agent::new_with_config(config);
    let mut response = agent
        .post(url)
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .send(body.as_slice())
        .map_err(ureq_io_error)?;
    let response = response
        .body_mut()
        .with_config()
        .limit(MAX_ENROLLMENT_RESPONSE_BYTES)
        .read_to_vec()
        .map_err(ureq_io_error)?;
    serde_json::from_slice::<serde_json::Value>(&response).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("enrollment response is not valid JSON: {error}"),
        )
    })?;

    hostlink_core::write_new_private_bytes(output, &response)
}

fn validate_secret_file(path: &Path) -> io::Result<()> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "enrollment token path must be a regular non-symlink file",
        ));
    }
    hostlink_core::validate_private_file(path).map_err(io::Error::other)
}

fn ensure_output_absent(path: &Path) -> io::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "enrollment response path already exists",
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn validate_enrollment_url(url: &str) -> io::Result<()> {
    let uri = url.parse::<ureq::http::Uri>().map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid enrollment URL: {error}"),
        )
    })?;
    if uri.scheme_str() != Some("https") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "enrollment URL must use https",
        ));
    }
    let authority = uri.authority().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "enrollment URL must contain an authority",
        )
    })?;
    if authority.as_str().contains('@') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "enrollment URL must not contain userinfo",
        ));
    }
    if uri.query().is_some() || !uri.path().ends_with("/v1/enroll") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "enrollment URL must target the /v1/enroll endpoint without a query",
        ));
    }
    Ok(())
}

fn ureq_io_error(error: ureq::Error) -> io::Error {
    io::Error::other(format!("enrollment HTTPS request failed: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enrollment_url_is_https_only_and_credential_free() {
        assert!(validate_enrollment_url("https://hub.example.test/v1/enroll").is_ok());
        assert!(validate_enrollment_url("http://hub.example.test/v1/enroll").is_err());
        let userinfo_url = ["https", "://fixture@hub.example.test/v1/enroll"].concat();
        assert!(validate_enrollment_url(&userinfo_url).is_err());
        assert!(validate_enrollment_url("https://hub.example.test/v1/enroll?mode=test").is_err());
        assert!(validate_enrollment_url("https://hub.example.test/v1/other").is_err());
        assert!(validate_enrollment_url("not a url").is_err());
    }

    #[test]
    fn enrollment_rejects_existing_response_before_network_access() {
        let dir = tempfile::tempdir().expect("tempdir");
        let token = dir.path().join("token.txt");
        let body = dir.path().join("body.json");
        let output = dir.path().join("response.json");
        std::fs::write(&token, "a".repeat(64)).expect("token");
        hostlink_core::restrict_private_file(&token).expect("private token");
        std::fs::write(&body, "{}").expect("body");
        std::fs::write(&output, "{}").expect("existing output");

        let error =
            post_enrollment_json("https://hub.example.test/v1/enroll", &token, &body, &output)
                .expect_err("existing response must fail before network access");
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
    }

    #[cfg(unix)]
    #[test]
    fn enrollment_rejects_dangling_response_symlink_before_network_access() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().expect("tempdir");
        let token = dir.path().join("token.txt");
        let body = dir.path().join("body.json");
        let output = dir.path().join("response.json");
        std::fs::write(&token, "a".repeat(64)).expect("token");
        hostlink_core::restrict_private_file(&token).expect("private token");
        std::fs::write(&body, "{}").expect("body");
        symlink(dir.path().join("missing-response.json"), &output).expect("dangling output link");

        let error =
            post_enrollment_json("https://hub.example.test/v1/enroll", &token, &body, &output)
                .expect_err("dangling response symlink must fail before network access");
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
    }

    #[cfg(unix)]
    #[test]
    fn enrollment_rejects_non_private_token_before_network_access() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let token = dir.path().join("token.txt");
        let body = dir.path().join("body.json");
        let output = dir.path().join("response.json");
        std::fs::write(&token, "a".repeat(64)).expect("token");
        std::fs::write(&body, "{}").expect("body");
        std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o644))
            .expect("open token permissions");

        let error =
            post_enrollment_json("https://hub.example.test/v1/enroll", &token, &body, &output)
                .expect_err("unsafe token permissions must fail before network access");
        assert!(error.to_string().contains("private file"), "{error}");
    }
}
