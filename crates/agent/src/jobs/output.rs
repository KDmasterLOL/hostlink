use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum JobOutput {
    Stdout,
    Stderr,
}

impl JobOutput {
    pub(super) fn file_name(self) -> &'static str {
        match self {
            Self::Stdout => "stdout.bin",
            Self::Stderr => "stderr.bin",
        }
    }
}

pub(crate) fn open_output_append(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.create_new(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let file = options.open(path)?;
    restrict_private_path(path, false)?;
    if file.metadata()?.len() > MAX_JOB_OUTPUT_BYTES {
        return Err(invalid("job output exceeds configured limit"));
    }
    Ok(file)
}

pub(super) fn read_bounded_output(path: &Path) -> io::Result<File> {
    validate_private_path(path, false)?;
    let file = File::open(path)?;
    if file.metadata()?.len() > MAX_JOB_OUTPUT_BYTES {
        return Err(invalid("job output exceeds configured limit"));
    }
    Ok(file)
}
