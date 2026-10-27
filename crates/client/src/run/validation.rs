use super::model::JobSpec;
use crate::connect::SshClientError;

pub(super) fn validate_absolute_path(value: &str) -> Result<(), ()> {
    let absolute = std::path::Path::new(value).is_absolute()
        || (value.as_bytes().get(1) == Some(&b':')
            && value
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphabetic))
        || value.starts_with("\\\\");
    if absolute && !value.is_empty() && !value.as_bytes().contains(&0) {
        Ok(())
    } else {
        Err(())
    }
}
pub(super) fn validate_id(id: &str) -> Result<(), SshClientError> {
    let parsed = uuid::Uuid::parse_str(id)
        .map_err(|_| SshClientError::Invalid("job ID must be a canonical lowercase UUID".into()))?;
    if parsed.to_string() != id {
        return Err(SshClientError::Invalid(
            "job ID must be a canonical lowercase UUID".into(),
        ));
    }
    Ok(())
}

pub(super) fn validate_spec(spec: &JobSpec) -> Result<(), SshClientError> {
    let program = spec.program.as_str();
    let absolute = std::path::Path::new(program).is_absolute()
        || (program.as_bytes().get(1) == Some(&b':')
            && program
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphabetic))
        || program.starts_with("\\\\");
    if !absolute
        || program.as_bytes().contains(&0)
        || spec.args.iter().any(|arg| arg.as_bytes().contains(&0))
    {
        return Err(SshClientError::Invalid(
            "job program must be an absolute path and arguments must not contain NUL".into(),
        ));
    }
    if let Some(cwd) = &spec.cwd {
        let absolute = std::path::Path::new(cwd).is_absolute()
            || (cwd.as_bytes().get(1) == Some(&b':')
                && cwd.as_bytes().first().is_some_and(u8::is_ascii_alphabetic))
            || cwd.starts_with("\\\\");
        if !absolute || cwd.as_bytes().contains(&0) {
            return Err(SshClientError::Invalid(
                "job working directory must be an absolute path".into(),
            ));
        }
    }
    if spec.source_sha256.len() != 64
        || !spec
            .source_sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(SshClientError::Invalid(
            "job source SHA-256 must be 64 lowercase hexadecimal characters".into(),
        ));
    }
    Ok(())
}
