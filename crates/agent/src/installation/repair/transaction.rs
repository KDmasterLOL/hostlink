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

// Immutable GitHub Releases raw asset sizes and SHA-256 digests. To extend,
// verify immutable metadata at https://api.github.com/repos/KDmasterLOL/hostlink/releases/tags/<tag>.
#[cfg(any(test, all(windows, target_arch = "x86_64")))]
const LEGACY_X64: &[(u64, &str)] = &[
    // v0.1.0 x86_64-pc-windows-msvc
    (
        20630016,
        "48e9c91aa7b2cdfdb17da91bed601ae0d5be2613ab92aa227c70411a5c9fffe5",
    ),
    // v0.1.0 x86_64-win7-windows-msvc
    (
        20617728,
        "9a037642694f44a6ab3a4edfb7d36f7f188d5b40f8ca0496aba59b4b81f8511e",
    ),
    // v0.1.1 x86_64-pc-windows-msvc
    (
        20465664,
        "c0befbd19766815c53620faac2c2675ab1a8df732c7964cd8e3a360f6063bf59",
    ),
    // v0.1.1 x86_64-win7-windows-msvc
    (
        20633088,
        "89f2db475adfb4805a50bc63c6ac38ac662915a82a4d874b8b4397d81910ac63",
    ),
    // v0.1.2 x86_64-pc-windows-msvc
    (
        20487680,
        "9246a322627b2c0251d7122df8eacdecb17a99a19bbef45e908a828e2b368952",
    ),
    // v0.1.2 x86_64-win7-windows-msvc
    (
        20622336,
        "d2a2f81bd983a3a84db4cac78f3af2ef11d0fcfc2c3642134dd85d20a4cf77dd",
    ),
    // v0.2.0 x86_64-pc-windows-msvc
    (
        21262848,
        "e6d58e0ba5c56a93c27aaa260e71a1f8704da24dd8d6efd496fdc3400617bbe4",
    ),
    // v0.2.0 x86_64-win7-windows-msvc
    (
        21407744,
        "c96271128aab2e80c2e188df2056b547af2a250d4058f847484a0b0cfe8c6303",
    ),
    // v0.2.1 x86_64-pc-windows-msvc
    (
        21255680,
        "5ce5f21904683ee0c279c712dfda59e20e3d45dbfd224d7d8e4c82879863a054",
    ),
    // v0.2.1 x86_64-win7-windows-msvc
    (
        21414400,
        "96c86093d6e94866d73c5038bde5ec2e8e27664b4744a109d755796df0458b3b",
    ),
    // v0.2.2 x86_64-pc-windows-msvc
    (
        21263360,
        "57d6529842e48f2e6ebfa544a6001034de9bace7fe0c1acba0d3c7add9b717c7",
    ),
    // v0.2.2 x86_64-win7-windows-msvc
    (
        21414400,
        "e97c557c3448adbc88044a4451f50f5c1d8df5ef7110cfe3055eb8e4b33e37b9",
    ),
];

#[cfg(any(test, all(windows, target_arch = "x86")))]
const LEGACY_X86: &[(u64, &str)] = &[
    // v0.1.0 i686-win7-windows-msvc
    (
        17071104,
        "99759053062c87f05f3ef1720da7f104681435d676cfbd6aedaaec245fc504a3",
    ),
    // v0.1.1 i686-win7-windows-msvc
    (
        17072640,
        "7d83e4731262bf8855de9f29fcc36387463ed1b4cfcb7ddc56a12b35c525a0d1",
    ),
    // v0.1.2 i686-win7-windows-msvc
    (
        17084928,
        "3ee0ef347eeb3c01e5b3a30966056d4f115dd3846aff85c7a13765d5965ea84d",
    ),
    // v0.2.0 i686-win7-windows-msvc
    (
        17615872,
        "e35387fabf987c578e0ec86832acaa4fceaea4f88301436feb09db19218614c9",
    ),
    // v0.2.1 i686-win7-windows-msvc
    (
        17615872,
        "03686bbb46b1ac123cd9c009e6975241b25ef80389dbdb95f4e01e266275efb5",
    ),
    // v0.2.2 i686-win7-windows-msvc
    (
        17616896,
        "5c0bdfec363881b383fa5f51ed9964b97b201eb27bb238bc07524203560eb471",
    ),
];

#[cfg(windows)]
fn legacy_releases() -> &'static [(u64, &'static str)] {
    #[cfg(target_arch = "x86_64")]
    {
        LEGACY_X64
    }
    #[cfg(target_arch = "x86")]
    {
        LEGACY_X86
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

#[cfg(test)]
mod release_metadata_tests {
    use super::*;

    // Fingerprints cover ordered size:sha256 pairs read from the immutable
    // GitHub release metadata, independently of the table's Rust syntax.
    #[test]
    fn immutable_release_tuples_match_recorded_metadata() {
        for (entries, expected_count, expected_fingerprint) in [
            (
                LEGACY_X64,
                12,
                "2dcc4cca55c38c942b4f7843522e11c93fbf67d04fcc6a101ac545fecd075966",
            ),
            (
                LEGACY_X86,
                6,
                "87ce324261084daf9ccda9281156290a9c4373237b8daa2976070219fedb774c",
            ),
        ] {
            assert_eq!(entries.len(), expected_count);
            let mut receipt = String::new();
            let mut unique = std::collections::HashSet::new();
            for &(size, sha) in entries {
                assert!(size > 0 && size <= MAX_EXECUTABLE_BYTES);
                assert_eq!(sha.len(), 64);
                assert!(
                    sha.bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                );
                assert!(unique.insert((size, sha)));
                receipt.push_str(&format!("{size}:{sha}\n"));
            }
            assert_eq!(
                format!("{:x}", Sha256::digest(receipt.as_bytes())),
                expected_fingerprint
            );
        }
        assert!(LEGACY_X64.contains(&(
            20_487_680,
            "9246a322627b2c0251d7122df8eacdecb17a99a19bbef45e908a828e2b368952"
        )));
    }
}
