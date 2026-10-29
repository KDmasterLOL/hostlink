use super::*;

pub(super) fn load_config(path: &Path) -> io::Result<crate::AgentConfig> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || is_reparse(&metadata) || metadata.len() > 64 * 1024 {
        return Err(invalid("Agent config is unsafe or exceeds size limit"));
    }
    verify_private_acl(path)?;
    let bytes = fs::read(path)?;
    let mut config: crate::AgentConfig =
        serde_json::from_slice(&bytes).map_err(io::Error::other)?;
    let base = path.parent().unwrap_or_else(|| Path::new("."));
    config.resolve_relative_paths(base);
    let state = path.parent().unwrap_or_else(|| Path::new("."));
    let root = state
        .parent()
        .ok_or_else(|| invalid("Agent config is outside its install root"))?;
    let expected_host_key = canonical_regular(&state.join("host_key"))?;
    let expected_authorized_keys = canonical_regular(&state.join("authorized_keys"))?;
    let expected_jobs_root = canonical_private_dir(&root.join("jobs"))?;
    config.host_key = canonical_regular(&config.host_key)?;
    config.authorized_keys = canonical_regular(&config.authorized_keys)?;
    config.jobs_root = canonical_private_dir(&config.jobs_root)?;
    if config.host_key != expected_host_key
        || config.authorized_keys != expected_authorized_keys
        || config.jobs_root != expected_jobs_root
    {
        return Err(invalid(
            "service config credentials and durable jobs must remain in the fresh Agent root",
        ));
    }
    for (index, gateway) in config
        .gateway
        .iter_mut()
        .chain(config.gateway_alternates.iter_mut())
        .enumerate()
    {
        let expected_host_key = if index == 0 {
            state.join("gateway_host_key")
        } else {
            state.join(format!("gateway_host_key_{index}"))
        };
        let expected_identity = canonical_regular(&state.join("gateway_identity"))?;
        let expected_host_key = canonical_regular(&expected_host_key)?;
        gateway.identity = canonical_regular(&gateway.identity)?;
        gateway.host_public_key = canonical_regular(&gateway.host_public_key)?;
        if gateway.identity != expected_identity || gateway.host_public_key != expected_host_key {
            return Err(invalid(
                "service gateway credentials must remain in the fresh Agent root",
            ));
        }
    }
    config.validate()?;
    Ok(config)
}
pub(super) fn verify_enrollment_root(root: &Path) -> io::Result<()> {
    let state = root.join("state");
    canonical_private_dir(&state)?;
    for name in [
        "agent.json",
        "machine.json",
        "manifest.json",
        "authorized_keys",
        "gateway_host_key",
        "gateway_identity",
        "host_key",
    ] {
        canonical_regular(&state.join(name))?;
    }
    let manifest_bytes = read_private(&state.join("manifest.json"), 64 * 1024)?;
    let machine_bytes = read_private(&state.join("machine.json"), 16 * 1024)?;
    let manifest: crate::enrollment::EnrollmentManifest =
        serde_json::from_slice(&manifest_bytes)
            .map_err(|_| invalid("Agent enrollment manifest is invalid"))?;
    let machine: crate::enrollment::EnrollmentIdentity = serde_json::from_slice(&machine_bytes)
        .map_err(|_| invalid("Agent enrollment identity is invalid"))?;
    if manifest.format != 1
        || machine.format != 1
        || manifest.machine_id != machine.machine_id
        || manifest.name != machine.name
        || machine.name.is_empty()
        || machine.ssh_public_key.is_empty()
        || machine.ssh_host_public_key.is_empty()
    {
        return Err(invalid(
            "Agent enrollment identity and manifest do not match",
        ));
    }
    let files = manifest.files;
    for required in [
        "agent.json",
        "machine.json",
        "authorized_keys",
        "gateway_host_key",
        "gateway_identity",
        "host_key",
    ] {
        if !files.contains_key(required) {
            return Err(invalid("Agent enrollment manifest is incomplete"));
        }
    }
    for (name, expected) in files {
        if name.contains('/') || name.contains('\\') || name == "." || name == ".." {
            return Err(invalid("Agent enrollment manifest contains unsafe path"));
        }
        let path = state.join(name);
        canonical_regular(&path)?;
        let bytes = read_private(&path, 1024 * 1024)?;
        let digest = format!("{:x}", Sha256::digest(&bytes));
        if expected.size != bytes.len() as u64 || expected.sha256 != digest {
            return Err(invalid("Agent enrollment file does not match its manifest"));
        }
    }
    Ok(())
}
