use super::*;

/// Private per-controller upload and sealed-artifact roots, both outside jobs_root.
#[derive(Debug, Clone)]
pub(crate) struct ArtifactStore {
    owner_root: PathBuf,
}

impl ArtifactStore {
    pub(crate) fn open(jobs_root: &Path, owner: &str) -> io::Result<Self> {
        validate_digest(owner)?;
        let install_root = jobs_root
            .parent()
            .ok_or_else(|| invalid("jobs root has no parent"))?;
        #[cfg(unix)]
        validate_source_ancestors(install_root)?;
        validate_private_path(install_root, true)?;
        let artifacts_root = install_root.join("artifacts");
        create_private_directory(&artifacts_root)?;
        let owner_root = artifacts_root.join(owner);
        create_private_directory(&owner_root)?;
        create_private_directory(&owner_root.join("uploads"))?;
        create_private_directory(&owner_root.join("sealed"))?;
        Ok(Self { owner_root })
    }

    pub(crate) fn upload_root(&self) -> PathBuf {
        self.owner_root.join("uploads")
    }

    pub(crate) fn sealed_root(&self) -> PathBuf {
        self.owner_root.join("sealed")
    }

    /// Bind execution to this controller's exact sealed path, never an alias.
    pub(crate) fn authorize_source(&self, program: &str, sha256: &str) -> io::Result<()> {
        validate_digest(sha256)?;
        let artifacts = self
            .owner_root
            .parent()
            .ok_or_else(|| invalid("missing artifact root"))?;
        let install = artifacts
            .parent()
            .ok_or_else(|| invalid("missing install root"))?;
        for directory in [install, artifacts, &self.owner_root, &self.sealed_root()] {
            validate_private_path(directory, true)?;
        }
        let target = self.sealed_root().join(format!("{sha256}.program"));
        #[cfg(unix)]
        validate_source_ancestors(&self.sealed_root())?;
        validate_private_path(&target, false)?;
        let canonical = target.canonicalize()?;
        if Path::new(program).as_os_str() != canonical.as_os_str() {
            return Err(invalid(
                "job executable is not this controller's exact sealed source",
            ));
        }
        Ok(())
    }

    pub(crate) fn seal(
        &self,
        name: &str,
        expected_sha256: &str,
        expected_size: u64,
    ) -> io::Result<PathBuf> {
        validate_digest(expected_sha256)?;
        if expected_size > MAX_ARTIFACT_BYTES || name != format!("{expected_sha256}.upload") {
            return Err(invalid("artifact name, digest, or size is invalid"));
        }
        #[cfg(unix)]
        validate_source_ancestors(&self.sealed_root())?;
        let _lock = exclusive_lock(&self.owner_root.join("seal.lock"))?;
        validate_private_path(
            self.owner_root
                .parent()
                .ok_or_else(|| invalid("controller artifact root has no parent"))?,
            true,
        )?;
        validate_private_path(
            self.owner_root
                .parent()
                .and_then(Path::parent)
                .ok_or_else(|| invalid("artifact root has no install parent"))?,
            true,
        )?;
        validate_private_path(&self.owner_root, true)?;
        let uploads = self.owner_root.join("uploads");
        let sealed = self.owner_root.join("sealed");
        validate_private_path(&uploads, true)?;
        validate_private_path(&sealed, true)?;
        let source = uploads.join(name);
        validate_private_path(&source, false)?;
        let target = sealed.join(format!("{expected_sha256}.program"));

        match fs::symlink_metadata(&target) {
            Ok(_) => {
                validate_private_path(&target, false)?;
                verify_artifact(&target, expected_sha256, expected_size)?;
                return target.canonicalize();
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }

        let mut input_options = OpenOptions::new();
        input_options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            input_options.custom_flags(libc::O_NOFOLLOW);
        }
        let mut input = input_options.open(&source)?;
        let input_meta = input.metadata()?;
        if !input_meta.is_file() || input_meta.len() != expected_size {
            return Err(invalid(
                "uploaded artifact length does not match seal request",
            ));
        }
        if input_meta.len() > MAX_ARTIFACT_BYTES {
            return Err(invalid("uploaded artifact exceeds configured limit"));
        }
        let mut output_options = OpenOptions::new();
        output_options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            output_options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }
        let mut output = output_options.open(&target)?;
        let result = (|| {
            let mut hasher = Sha256::new();
            let mut total = 0_u64;
            let mut buffer = [0_u8; 64 * 1024];
            loop {
                let read = input.read(&mut buffer)?;
                if read == 0 {
                    break;
                }
                total = total
                    .checked_add(read as u64)
                    .ok_or_else(|| invalid("artifact size overflow"))?;
                if total > expected_size || total > MAX_ARTIFACT_BYTES {
                    return Err(invalid("uploaded artifact changed during seal"));
                }
                hasher.update(&buffer[..read]);
                output.write_all(&buffer[..read])?;
            }
            let digest = format!("{:x}", hasher.finalize());
            if total != expected_size || digest != expected_sha256 {
                return Err(invalid(
                    "uploaded artifact digest or length does not match seal request",
                ));
            }
            output.sync_all()?;
            restrict_sealed_artifact(&target, &output)?;
            sync_directory(&sealed)?;
            Ok(())
        })();
        if let Err(error) = result {
            drop(output);
            let _ = fs::remove_file(&target);
            return Err(error);
        }
        target.canonicalize()
    }
}

pub(super) fn create_private_directory(path: &Path) -> io::Result<()> {
    match fs::create_dir(path) {
        Ok(()) => restrict_private_path(path, true),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            validate_private_path(path, true)
        }
        Err(error) => Err(error),
    }
}

pub(super) fn verify_artifact(
    path: &Path,
    expected_sha256: &str,
    expected_size: u64,
) -> io::Result<()> {
    validate_private_path(path, false)?;
    let file = File::open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = file.metadata()?.permissions().mode();
        if mode & 0o222 != 0 || mode & 0o111 == 0 {
            return Err(invalid(
                "sealed artifact permissions are not executable and read-only",
            ));
        }
    }
    if file.metadata()?.len() != expected_size || expected_size > MAX_ARTIFACT_BYTES {
        return Err(invalid("sealed artifact length conflicts with repeat seal"));
    }
    let mut hasher = Sha256::new();
    let total = io::copy(&mut file.take(expected_size + 1), &mut hasher)?;
    if total != expected_size || format!("{:x}", hasher.finalize()) != expected_sha256 {
        return Err(invalid("sealed artifact conflicts with repeat seal"));
    }
    Ok(())
}

pub(super) fn restrict_sealed_artifact(path: &Path, file: &File) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let opened = file.metadata()?;
        let named = fs::symlink_metadata(path)?;
        if !named.is_file() || opened.dev() != named.dev() || opened.ino() != named.ino() {
            return Err(invalid("sealed artifact path changed during publication"));
        }
        file.set_permissions(fs::Permissions::from_mode(0o500))?;
    }
    #[cfg(windows)]
    {
        let _ = file;
        set_private_windows_acl(path, false)?;
    }
    validate_private_path(path, false)
}
