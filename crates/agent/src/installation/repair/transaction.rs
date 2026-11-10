use super::*;

pub(super) struct Transaction {
    root: PathBuf,
    stage: PathBuf,
    source_sha: String,
    original_sha: Option<String>,
    legacy: bool,
}

impl Transaction {
    pub fn prepare(
        root: &Path,
        snapshot: &Snapshot,
        source: &mut RunningExecutable,
    ) -> io::Result<Self> {
        #[cfg(windows)]
        let allowed = legacy_releases();
        #[cfg(not(windows))]
        let allowed = &[];
        Self::prepare_with_releases(root, snapshot, source, allowed)
    }

    #[cfg(all(test, windows))]
    pub(super) fn prepare_test_legacy(
        root: &Path,
        snapshot: &Snapshot,
        source: &mut RunningExecutable,
        allowed: &[(u64, &str)],
    ) -> io::Result<Self> {
        Self::prepare_with_releases(root, snapshot, source, allowed)
    }

    fn prepare_with_releases(
        root: &Path,
        snapshot: &Snapshot,
        source: &mut RunningExecutable,
        allowed: &[(u64, &str)],
    ) -> io::Result<Self> {
        snapshot.assert_unchanged(root)?;
        let stage = root.join(format!(".repair-{}", uuid::Uuid::new_v4()));
        let stage_dir = PrivateDir::ensure(&stage).map_err(io::Error::other)?;
        let result = Self::prepare_stage(root, snapshot, source, allowed, &stage, &stage_dir);
        drop(stage_dir);
        if result.is_err() {
            fs::remove_dir_all(&stage)?;
            enrollment::sync_directory(root)?;
        }
        result
    }

    fn prepare_stage(
        root: &Path,
        snapshot: &Snapshot,
        source: &mut RunningExecutable,
        allowed: &[(u64, &str)],
        stage: &Path,
        stage_dir: &PrivateDir,
    ) -> io::Result<Self> {
        #[cfg(windows)]
        let mut legacy = false;
        #[cfg(not(windows))]
        let legacy = false;
        #[cfg(not(windows))]
        let _ = allowed;
        let original_sha = match fs::symlink_metadata(root.join("bin")) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(error),
            Ok(_) => {
                let _bin = PrivateDir::open(root.join("bin")).map_err(io::Error::other)?;
                let names = fs::read_dir(root.join("bin"))?
                    .map(|entry| entry.map(|entry| entry.file_name()))
                    .collect::<io::Result<Vec<_>>>()?;
                if names.is_empty() {
                    None
                } else if names == [std::ffi::OsString::from(EXECUTABLE_NAME)] {
                    #[cfg(windows)]
                    if let Err(error) = _bin.open_file(EXECUTABLE_NAME) {
                        if !matches!(error, private_fs::Error::InsecureAcl) {
                            return Err(io::Error::other(error));
                        }
                        legacy = true;
                    }
                    let path = root.join("bin").join(EXECUTABLE_NAME);
                    if legacy {
                        #[cfg(windows)]
                        {
                            Some(copy_legacy(&path, stage, stage_dir, allowed)?)
                        }
                        #[cfg(not(windows))]
                        unreachable!()
                    } else {
                        verify_executable(&path)?;
                        Some(hash_file(&path, MAX_EXECUTABLE_BYTES)?)
                    }
                } else {
                    return Err(invalid(
                        "foreign files in Agent bin; preserving installation",
                    ));
                }
            }
        };
        snapshot.assert_unchanged(root)?;
        snapshot.persist_attempt(stage_dir)?;
        let bin = stage_dir.create_dir("bin").map_err(io::Error::other)?;
        let mut image = bin.create(EXECUTABLE_NAME).map_err(io::Error::other)?;
        let copied = io::copy(
            &mut (&mut source.file).take(MAX_EXECUTABLE_BYTES + 1),
            &mut image,
        )?;
        if copied == 0 || copied > MAX_EXECUTABLE_BYTES {
            return Err(invalid("repair executable is empty or oversized"));
        }
        image.sync_all().map_err(io::Error::other)?;
        drop(image);
        let path = stage.join("bin").join(EXECUTABLE_NAME);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
        }
        verify_executable(&path)?;
        if hash_file(&path, MAX_EXECUTABLE_BYTES)? != source.sha256 {
            return Err(invalid(
                "repair executable differs from verified running image",
            ));
        }
        enrollment::sync_directory(&stage.join("bin"))?;
        enrollment::sync_directory(stage)?;
        Ok(Self {
            root: root.to_owned(),
            stage: stage.to_owned(),
            source_sha: source.sha256.clone(),
            original_sha,
            legacy,
        })
    }

    pub fn mark_pending(&self) -> io::Result<()> {
        let marker = format!(
            "Repair or explicit key replacement may have consumed its invite. Reconcile Hub, attempted keys and backup before retry.\n{}\n",
            self.stage.file_name().unwrap().to_string_lossy()
        );
        enrollment::write_private_new(&self.root.join("repair.pending"), marker.as_bytes())?;
        enrollment::sync_directory(&self.root)
    }

    pub async fn write_candidate(
        &self,
        snapshot: &Snapshot,
        response: &EnrollResponse,
        gateway_index: Option<usize>,
    ) -> io::Result<()> {
        let files = snapshot.candidate(response, gateway_index)?;
        let dir = PrivateDir::open(&self.stage)
            .map_err(io::Error::other)?
            .create_dir("state")
            .map_err(io::Error::other)?;
        for (name, bytes) in files {
            let mut file = dir.create(name).map_err(io::Error::other)?;
            file.write_all(&bytes)?;
            file.sync_all().map_err(io::Error::other)?;
        }
        drop(dir);
        enrollment::sync_directory(&self.stage.join("state"))?;
        let mut config: AgentConfig =
            serde_json::from_slice(&fs::read(self.stage.join("state/agent.json"))?)
                .map_err(io::Error::other)?;
        config.resolve_relative_paths(&self.stage.join("state"));
        // No forwarding or Agent RPC is required: authenticate the retained
        // reverse key against at least one exact Hub-approved gateway host pin.
        crate::tunnel::probe(&config).await
    }

    pub fn changed(&self, snapshot: &Snapshot) -> io::Result<bool> {
        if self.legacy || self.original_sha.as_ref() != Some(&self.source_sha) {
            return Ok(true);
        }
        let dir = PrivateDir::open(self.stage.join("state")).map_err(io::Error::other)?;
        let names = fs::read_dir(self.stage.join("state"))?.count();
        if names != snapshot.files.len() {
            return Ok(true);
        }
        for (name, bytes) in &snapshot.files {
            if state::read(&dir, name)? != *bytes {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub fn publish(&self) -> io::Result<()> {
        self.assert_original_binary()?;
        fs::rename(self.root.join("state"), self.stage.join("original-state"))?;
        // Persist both parents of each cross-directory rename before advancing.
        // A power loss must not lose the only directory entry for original state.
        enrollment::sync_directory(&self.stage)?;
        enrollment::sync_directory(&self.root)?;
        fs::rename(self.stage.join("state"), self.root.join("state"))?;
        enrollment::sync_directory(&self.root)?;
        enrollment::sync_directory(&self.stage)?;
        if self.root.join("bin").try_exists()? {
            fs::rename(self.root.join("bin"), self.stage.join("original-bin"))?;
            enrollment::sync_directory(&self.stage)?;
            enrollment::sync_directory(&self.root)?;
        }
        fs::rename(self.stage.join("bin"), self.root.join("bin"))?;
        enrollment::sync_directory(&self.stage)?;
        enrollment::sync_directory(&self.root)?;
        if hash_file(
            &self.root.join("bin").join(EXECUTABLE_NAME),
            MAX_EXECUTABLE_BYTES,
        )? != self.source_sha
        {
            return Err(invalid("published repair executable mismatch"));
        }
        Ok(())
    }

    fn assert_original_binary(&self) -> io::Result<()> {
        let path = self.root.join("bin").join(EXECUTABLE_NAME);
        #[cfg(windows)]
        if self.legacy {
            let mut file = open_legacy(&path)?;
            let mut hasher = Sha256::new();
            let size = io::copy(&mut (&mut file).take(MAX_EXECUTABLE_BYTES + 1), &mut hasher)?;
            if size == 0
                || size > MAX_EXECUTABLE_BYTES
                || self.original_sha.as_ref() != Some(&format!("{:x}", hasher.finalize()))
            {
                return Err(invalid("installed executable changed during repair"));
            }
            return Ok(());
        }
        match &self.original_sha {
            Some(sha) if hash_file(&path, MAX_EXECUTABLE_BYTES)? == *sha => Ok(()),
            None if !path.try_exists()? => Ok(()),
            _ => Err(invalid("installed executable changed during repair")),
        }
    }

    pub fn finish(&self) -> io::Result<()> {
        PrivateDir::open(&self.root)
            .map_err(io::Error::other)?
            .remove_file("repair.pending", Durability::Full)
            .map_err(io::Error::other)
    }

    pub fn retain_pending(&self) -> io::Result<()> {
        // Unlink may succeed before its durability sync fails. Re-establish
        // admission blocking before attempting rollback in that case.
        match fs::symlink_metadata(self.root.join("repair.pending")) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => self.mark_pending(),
            Err(error) => Err(error),
            Ok(_) => Ok(()),
        }
    }

    pub fn finish_unchanged(&self) -> io::Result<()> {
        self.finish()?;
        // This directory contains only this invocation's newly created candidate
        // copies. Original installation directories have never been moved here.
        fs::remove_dir_all(&self.stage)?;
        enrollment::sync_directory(&self.root)
    }

    pub fn rollback(&self) -> io::Result<()> {
        // Never delete a root or original state. Retain both candidate and
        // originals for diagnosis, even after successful rollback/publication.
        if self.legacy {
            // The original file may still have foreign writable handles. Never
            // restore it, even when publication failed before the first rename.
            let trusted = self.stage.join("trusted-original-bin");
            let executable = trusted.join(EXECUTABLE_NAME);
            let dir = PrivateDir::open(&trusted).map_err(io::Error::other)?;
            dir.open_file(EXECUTABLE_NAME).map_err(io::Error::other)?;
            if Some(hash_file(&executable, MAX_EXECUTABLE_BYTES)?) != self.original_sha {
                return Err(invalid("trusted rollback executable changed"));
            }
            if self.root.join("bin").try_exists()? {
                fs::rename(self.root.join("bin"), self.stage.join("failed-bin"))?;
            }
            fs::rename(trusted, self.root.join("bin"))?;
        }
        for name in ["bin", "state"] {
            if self.legacy && name == "bin" {
                continue;
            }
            let backup = self.stage.join(format!("original-{name}"));
            if backup.try_exists()? {
                let current = self.root.join(name);
                if current.try_exists()? {
                    fs::rename(&current, self.stage.join(format!("failed-{name}")))?;
                }
                fs::rename(backup, current)?;
            } else if name == "bin"
                && self.original_sha.is_none()
                && !self.stage.join("bin").try_exists()?
                && self.root.join("bin").try_exists()?
            {
                fs::rename(self.root.join("bin"), self.stage.join("failed-bin"))?;
            }
        }
        enrollment::sync_directory(&self.stage)?;
        enrollment::sync_directory(&self.root)?;
        Ok(())
    }
}

// GitHub immutable release v0.1.2 raw asset metadata, pinned by size and SHA-256.
// https://api.github.com/repos/KDmasterLOL/hostlink/releases/tags/v0.1.2
#[cfg(windows)]
fn legacy_releases() -> &'static [(u64, &'static str)] {
    #[cfg(target_arch = "x86_64")]
    {
        &[
            (
                20_487_680,
                "9246a322627b2c0251d7122df8eacdecb17a99a19bbef45e908a828e2b368952",
            ),
            (
                20_622_336,
                "d2a2f81bd983a3a84db4cac78f3af2ef11d0fcfc2c3642134dd85d20a4cf77dd",
            ),
        ]
    }
    #[cfg(target_arch = "x86")]
    {
        &[(
            17_084_928,
            "3ee0ef347eeb3c01e5b3a30966056d4f115dd3846aff85c7a13765d5965ea84d",
        )]
    }
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    {
        &[]
    }
}

#[cfg(windows)]
fn copy_legacy(
    path: &Path,
    stage: &Path,
    stage_dir: &PrivateDir,
    allowed: &[(u64, &str)],
) -> io::Result<String> {
    let mut old = open_legacy(path)?;
    let backup = stage_dir
        .create_dir("trusted-original-bin")
        .map_err(io::Error::other)?;
    let mut copy = backup.create(EXECUTABLE_NAME).map_err(io::Error::other)?;
    let size = io::copy(&mut (&mut old).take(MAX_EXECUTABLE_BYTES + 1), &mut copy)?;
    if size == 0 || size > MAX_EXECUTABLE_BYTES {
        return Err(invalid("legacy executable is empty or oversized"));
    }
    copy.sync_all().map_err(io::Error::other)?;
    copy.verify().map_err(io::Error::other)?;
    drop(copy);
    let sha = hash_file(
        &stage.join("trusted-original-bin").join(EXECUTABLE_NAME),
        MAX_EXECUTABLE_BYTES,
    )?;
    if !allowed
        .iter()
        .any(|(expected_size, expected_sha)| *expected_size == size && *expected_sha == sha)
    {
        return Err(invalid(
            "installed Agent executable has an insecure ACL and does not match an approved historical release",
        ));
    }
    enrollment::sync_directory(&stage.join("trusted-original-bin"))?;
    Ok(sha)
}

#[cfg(windows)]
fn open_legacy(path: &Path) -> io::Result<fs::File> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    // The foreign-writable file can change; identity, ownership and link count
    // must be checked on each acquired no-follow handle before reading it.
    match private_fs::verify(&file) {
        Err(private_fs::Error::InsecureAcl) | Ok(()) => Ok(file),
        Err(error) => Err(io::Error::other(error)),
    }
}
