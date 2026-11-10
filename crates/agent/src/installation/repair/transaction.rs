use super::*;

pub(super) struct Transaction {
    root: PathBuf,
    stage: PathBuf,
    source_sha: String,
    original_sha: Option<String>,
}

impl Transaction {
    pub fn prepare(
        root: &Path,
        snapshot: &Snapshot,
        source: &mut RunningExecutable,
    ) -> io::Result<Self> {
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
                    _bin.open_file(EXECUTABLE_NAME).map_err(|error| match error {
                        private_fs::Error::InsecureAcl => invalid(
                            "installed Agent executable has an insecure ACL; repair stopped before Hub authorization to avoid executing untrusted bytes",
                        ),
                        error => io::Error::other(error),
                    })?;
                    verify_executable(&root.join("bin").join(EXECUTABLE_NAME))?;
                    Some(hash_file(
                        &root.join("bin").join(EXECUTABLE_NAME),
                        MAX_EXECUTABLE_BYTES,
                    )?)
                } else {
                    return Err(invalid(
                        "foreign files in Agent bin; preserving installation",
                    ));
                }
            }
        };
        snapshot.assert_unchanged(root)?;
        let stage = root.join(format!(".repair-{}", uuid::Uuid::new_v4()));
        let stage_dir = PrivateDir::ensure(&stage).map_err(io::Error::other)?;
        snapshot.persist_attempt(&stage_dir)?;
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
        enrollment::sync_directory(&stage)?;
        Ok(Self {
            root: root.to_owned(),
            stage,
            source_sha: source.sha256.clone(),
            original_sha,
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
        if self.original_sha.as_ref() != Some(&self.source_sha) {
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
        for name in ["bin", "state"] {
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
