use super::*;
use enrollment::{EnrollmentIdentity, EnrollmentManifest, FileDigest};

const MAX_STATE_FILE: u64 = 1024 * 1024;

pub(super) struct Snapshot {
    pub files: BTreeMap<String, Vec<u8>>,
    pub identity: EnrollmentIdentity,
    pub config: AgentConfig,
    pub reverse_key: PrivateKey,
    selected_user: String,
    replacement_keys: Option<(Vec<u8>, Vec<u8>)>,
}

impl Snapshot {
    pub fn persist_attempt(&self, dir: &PrivateDir) -> io::Result<()> {
        // Persist replacement keys before the first request. A lost HTTPS reply
        // must not strand a committed rotation with its only private keys in RAM.
        let attempt = dir.create_dir("attempt").map_err(io::Error::other)?;
        for (name, contents) in [
            (
                "gateway_identity",
                self.reverse_key
                    .to_openssh(russh::keys::ssh_key::LineEnding::LF)
                    .map_err(io::Error::other)?
                    .as_bytes()
                    .to_vec(),
            ),
            (
                "host_key",
                match &self.replacement_keys {
                    Some((_, host)) => host.clone(),
                    None => bytes(&self.files, "host_key")?.to_vec(),
                },
            ),
            (
                "machine.json",
                serde_json::to_vec(&self.identity).map_err(io::Error::other)?,
            ),
        ] {
            let mut file = attempt.create(name).map_err(io::Error::other)?;
            file.write_all(&contents)?;
            file.sync_all().map_err(io::Error::other)?;
        }
        #[cfg(unix)]
        attempt.sync_all().map_err(io::Error::other)?;
        Ok(())
    }

    pub fn read(root: &Path, expected: &MachineId, name: &str, user: &str) -> io::Result<Self> {
        Self::read_inner(root, expected, name, user, false)
    }

    pub fn read_replacement(
        root: &Path,
        expected: &MachineId,
        name: &str,
        user: &str,
    ) -> io::Result<Self> {
        Self::read_inner(root, expected, name, user, true)
    }

    fn read_inner(
        root: &Path,
        expected: &MachineId,
        name: &str,
        user: &str,
        replace_keys: bool,
    ) -> io::Result<Self> {
        PrivateDir::open(root).map_err(io::Error::other)?;
        crate::installation::ensure_ready(root)?;
        let state = PrivateDir::open(root.join("state")).map_err(io::Error::other)?;
        let manifest_bytes = read(&state, "manifest.json")?;
        let manifest: EnrollmentManifest =
            serde_json::from_slice(&manifest_bytes).map_err(|_| damaged())?;
        if manifest.format != 1
            || &manifest.machine_id != expected
            || manifest.name != name
            || !(6..=21).contains(&manifest.files.len())
        {
            return Err(damaged());
        }
        if [
            "agent.json",
            "authorized_keys",
            "gateway_host_key",
            "gateway_identity",
            "host_key",
            "machine.json",
        ]
        .iter()
        .any(|name| !manifest.files.contains_key(*name))
        {
            return Err(damaged());
        }
        let mut files = BTreeMap::new();
        for (name, digest) in &manifest.files {
            if !allowed_file(name) {
                return Err(damaged());
            }
            let replacing =
                replace_keys && matches!(name.as_str(), "host_key" | "gateway_identity");
            if replacing {
                match fs::symlink_metadata(root.join("state").join(name)) {
                    Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                    Err(error) => return Err(error),
                    Ok(_) => {}
                }
            }
            let bytes = read(&state, name)?;
            if !replacing
                && (bytes.len() as u64 != digest.size
                    || hex::encode(Sha256::digest(&bytes)) != digest.sha256)
            {
                return Err(damaged());
            }
            files.insert(name.clone(), bytes);
        }
        files.insert("manifest.json".into(), manifest_bytes);
        // Every state file must be understood and integrity-bound; never copy foreign extras.
        if fs::read_dir(root.join("state"))?.count() != files.len() {
            return Err(damaged());
        }
        let mut identity: EnrollmentIdentity = json(&files, "machine.json")?;
        let config: AgentConfig = json(&files, "agent.json")?;
        config.validate()?;
        if identity.format != 1
            || &identity.machine_id != expected
            || identity.name != name
            || config.jobs_root != root.join("jobs")
            || config.host_key != Path::new("host_key")
            || config.authorized_keys != Path::new("authorized_keys")
        {
            return Err(damaged());
        }
        identity.gateway.validate().map_err(|_| damaged())?;
        hostlink_hub::validate_ed25519_public_key(&identity.ssh_public_key)
            .map_err(|_| damaged())?;
        hostlink_hub::validate_ed25519_public_key(&identity.ssh_host_public_key)
            .map_err(|_| damaged())?;
        let (reverse_key, host_key) = if replace_keys {
            (
                PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519)
                    .map_err(io::Error::other)?,
                PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519)
                    .map_err(io::Error::other)?,
            )
        } else {
            (
                PrivateKey::from_openssh(bytes(&files, "gateway_identity")?)
                    .map_err(|_| damaged())?,
                PrivateKey::from_openssh(bytes(&files, "host_key")?).map_err(|_| damaged())?,
            )
        };
        let replacement_keys = if replace_keys {
            identity.ssh_public_key = enrollment::public_key(&reverse_key)?;
            identity.ssh_host_public_key = enrollment::public_key(&host_key)?;
            Some((
                reverse_key
                    .to_openssh(russh::keys::ssh_key::LineEnding::LF)
                    .map_err(io::Error::other)?
                    .as_bytes()
                    .to_vec(),
                host_key
                    .to_openssh(russh::keys::ssh_key::LineEnding::LF)
                    .map_err(io::Error::other)?
                    .as_bytes()
                    .to_vec(),
            ))
        } else {
            None
        };
        if reverse_key.algorithm() != Algorithm::Ed25519
            || host_key.algorithm() != Algorithm::Ed25519
            || enrollment::public_key(&reverse_key)? != identity.ssh_public_key
            || enrollment::public_key(&host_key)? != identity.ssh_host_public_key
            || identity.ssh_public_key == identity.ssh_host_public_key
        {
            return Err(damaged());
        }
        let primary = config.gateway.as_ref().ok_or_else(damaged)?;
        if manifest.files.len() != 6 + config.gateway_alternates.len() {
            return Err(damaged());
        }
        if primary.host != identity.gateway.host
            || primary.port != identity.gateway.port
            || primary.user != identity.gateway.user
        {
            return Err(damaged());
        }
        let routes = config.gateway.iter().chain(&config.gateway_alternates);
        for (index, route) in routes.enumerate() {
            let pin = pin_name(index);
            if route.identity != Path::new("gateway_identity")
                || route.host_public_key != Path::new(&pin)
                || route.remote_port != identity.remote_port
            {
                return Err(damaged());
            }
            let public = std::str::from_utf8(bytes(&files, &pin)?).map_err(|_| damaged())?;
            let key = hostlink_hub::canonical_ed25519_public_key(public).map_err(|_| damaged())?;
            if index == 0
                && key
                    != hostlink_hub::canonical_ed25519_public_key(&identity.gateway.host_public_key)
                        .map_err(|_| damaged())?
            {
                return Err(damaged());
            }
        }
        // Apalis owns its schema and jobs. Validate the private container and the
        // existing database without opening/migrating/truncating any SQLite data.
        let jobs = PrivateDir::open(root.join("jobs")).map_err(io::Error::other)?;
        verify_sqlite_file(&jobs, "jobs.db")?;
        for name in ["jobs.db-wal", "jobs.db-shm", "runner.lock"] {
            match fs::symlink_metadata(root.join("jobs").join(name)) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
                Ok(_) => {
                    if name == "runner.lock" {
                        jobs.open_file(name).map_err(io::Error::other)?;
                    } else {
                        verify_sqlite_file(&jobs, name)?;
                    }
                }
            }
        }
        Ok(Self {
            files,
            identity,
            config,
            reverse_key,
            selected_user: user.to_owned(),
            replacement_keys,
        })
    }

    pub fn assert_unchanged(&self, root: &Path) -> io::Result<()> {
        let dir = PrivateDir::open(root.join("state")).map_err(io::Error::other)?;
        for (name, expected) in &self.files {
            if &read(&dir, name)? != expected {
                return Err(invalid("Agent state changed during repair"));
            }
        }
        if fs::read_dir(root.join("state"))?.count() != self.files.len() {
            return Err(invalid("Agent state changed during repair"));
        }
        Ok(())
    }

    pub fn request(&self, token: secrecy::SecretString) -> io::Result<EnrollRequest> {
        Ok(EnrollRequest {
            token,
            machine_id: self.identity.machine_id.clone(),
            name: self.identity.name.clone(),
            hostname: enrollment::local_hostname(),
            os: std::env::consts::OS.into(),
            arch: std::env::consts::ARCH.into(),
            agent_version: env!("CARGO_PKG_VERSION").into(),
            ssh_public_key: self.identity.ssh_public_key.clone(),
            ssh_host_public_key: self.identity.ssh_host_public_key.clone(),
            repair_signature: None,
        })
    }

    pub fn candidate(
        &self,
        response: &EnrollResponse,
        gateway_index: Option<usize>,
    ) -> io::Result<BTreeMap<String, Vec<u8>>> {
        let gateways = enrollment::validate_response(
            response,
            &self.identity.machine_id,
            &self.identity.name,
            &self.identity.ssh_public_key,
            &self.identity.ssh_host_public_key,
            gateway_index,
        )?;
        if response.host.remote_port != self.identity.remote_port {
            return Err(invalid("Hub changed the assigned repair port"));
        }
        let mut files = self.files.clone();
        if let Some((reverse, host)) = &self.replacement_keys {
            files.insert("gateway_identity".into(), reverse.clone());
            files.insert("host_key".into(), host.clone());
        }
        files.retain(|name, _| !name.starts_with("gateway_host_key"));
        // The bootstrap-selected protocol login is published only with the
        // Hub-validated candidate; the manifest below binds the new bytes.
        let mut config = self.config.clone();
        config.user.clone_from(&self.selected_user);
        let mut routes = Vec::new();
        for (index, gateway) in gateways.iter().enumerate() {
            let pin = pin_name(index);
            files.insert(
                pin.clone(),
                format!("{}\n", gateway.host_public_key).into_bytes(),
            );
            routes.push(ReverseGateway {
                host: gateway.host.clone(),
                port: gateway.port,
                user: gateway.user.clone(),
                identity: "gateway_identity".into(),
                host_public_key: pin.into(),
                remote_port: self.identity.remote_port,
            });
        }
        config.gateway = Some(routes.remove(0));
        config.gateway_alternates = routes;
        config.validate()?;
        let mut identity = self.identity.clone();
        identity.gateway = gateways[0].clone();
        files.insert(
            "agent.json".into(),
            serde_json::to_vec(&config).map_err(io::Error::other)?,
        );
        files.insert(
            "machine.json".into(),
            serde_json::to_vec(&identity).map_err(io::Error::other)?,
        );
        let manifest = EnrollmentManifest {
            format: 1,
            machine_id: identity.machine_id,
            name: identity.name,
            files: files
                .iter()
                .filter(|(name, _)| name.as_str() != "manifest.json")
                .map(|(name, bytes)| {
                    (
                        name.clone(),
                        FileDigest {
                            size: bytes.len() as u64,
                            sha256: hex::encode(Sha256::digest(bytes)),
                        },
                    )
                })
                .collect(),
        };
        files.insert(
            "manifest.json".into(),
            serde_json::to_vec(&manifest).map_err(io::Error::other)?,
        );
        Ok(files)
    }
}

fn verify_sqlite_file(dir: &PrivateDir, name: &str) -> io::Result<()> {
    #[cfg(windows)]
    dir.verify_file_with_inherited_owner_acl(name)
        .map_err(io::Error::other)?;
    #[cfg(not(windows))]
    dir.open_file(name).map_err(io::Error::other)?;
    Ok(())
}

fn bytes<'a>(files: &'a BTreeMap<String, Vec<u8>>, name: &str) -> io::Result<&'a [u8]> {
    files.get(name).map(Vec::as_slice).ok_or_else(damaged)
}
fn json<T: serde::de::DeserializeOwned>(
    files: &BTreeMap<String, Vec<u8>>,
    name: &str,
) -> io::Result<T> {
    serde_json::from_slice(bytes(files, name)?).map_err(|_| damaged())
}
pub(super) fn read(dir: &PrivateDir, name: &str) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    dir.open_file(name)
        .map_err(io::Error::other)?
        .take(MAX_STATE_FILE + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_STATE_FILE {
        return Err(damaged());
    }
    Ok(bytes)
}
fn allowed_file(name: &str) -> bool {
    matches!(
        name,
        "agent.json"
            | "authorized_keys"
            | "gateway_identity"
            | "host_key"
            | "machine.json"
            | "gateway_host_key"
    ) || (1..16).any(|index| name == pin_name(index))
}
pub(super) fn pin_name(index: usize) -> String {
    if index == 0 {
        "gateway_host_key".into()
    } else {
        format!("gateway_host_key_{index}")
    }
}
fn damaged() -> io::Error {
    invalid(
        "Agent identity/manifest is damaged or mismatched; preserved root cannot be adopted; authenticated operator-approved identity reconciliation is required",
    )
}
