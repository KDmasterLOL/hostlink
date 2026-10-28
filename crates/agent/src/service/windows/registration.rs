use super::*;

pub(super) fn prepare_record(root: &Path, config: &Path) -> io::Result<InstallRecord> {
    let owner = current_sid()?;
    let root = verify_install_root(root)?;
    let config = canonical_regular(config)?;
    if config != root.join("state/agent.json") {
        return Err(invalid(
            "service install requires the fresh enrollment config at ROOT/state/agent.json",
        ));
    }
    verify_enrollment_root(&root)?;
    canonical_private_dir(&root.join("bin"))?;
    let _config = load_config(&config)?;
    let executable = std::env::current_exe()?.canonicalize()?;
    if executable != agent_executable(&root) {
        return Err(invalid(
            "hostlink-agent executable must be ROOT/bin/hostlink-agent for this fresh install root",
        ));
    }
    canonical_regular(&executable)?;
    let executable_sha256 = sha256_file(&executable)?;
    let digest = hex(&Sha256::digest(root.as_os_str().to_string_lossy().as_bytes())[..12]);
    let token = random_token();
    let pipe_name = format!(r"\\.\pipe\hostlink-agent-{digest}-{}", &token[..16]);
    let startup_script = root.join(".hostlink-agent-start.vbs");
    let launcher_executable = system_wscript()?;
    let launcher_metadata = fs::symlink_metadata(&launcher_executable)?;
    if !launcher_metadata.is_file() || is_reparse(&launcher_metadata) {
        return Err(invalid(
            "system Windows Script Host executable is missing or unsafe",
        ));
    }
    let mut record = InstallRecord {
        format: MARKER_FORMAT,
        owner_sid: owner,
        root,
        executable,
        executable_sha256,
        config,
        launcher_executable,
        startup_script,
        startup_script_sha256: String::new(),
        pipe_name,
        control_token: token,
        run_value: String::new(),
        maintenance: false,
        maintenance_previous_sha256: None,
    };
    record.startup_script_sha256 =
        format!("{:x}", Sha256::digest(render_script(&record).as_bytes()));
    record.run_value = run_value_name(&record.root);
    let command = render_command(&record);
    if command.encode_utf16().count() + 1 > 260 {
        return Err(invalid(
            "HostLink startup command exceeds the Windows HKCU Run 260-character limit; choose a shorter private install root",
        ));
    }
    Ok(record)
}
pub(super) fn owned_record(root: &Path) -> io::Result<InstallRecord> {
    let root = verify_install_root(root)?;
    let path = root.join(MARKER);
    let metadata = fs::symlink_metadata(&path)?;
    if !metadata.is_file() || is_reparse(&metadata) {
        return Err(invalid("service marker must be a regular non-reparse file"));
    }
    verify_private_acl(&path)?;
    let mut bytes = Vec::new();
    File::open(path)?
        .take((MAX_MARKER + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_MARKER {
        return Err(invalid("service marker exceeds size limit"));
    }
    let record: InstallRecord =
        serde_json::from_slice(&bytes).map_err(|_| invalid("service marker is invalid"))?;
    if record.format != MARKER_FORMAT || record.owner_sid != current_sid()? || record.root != root {
        return Err(invalid(
            "service marker owner or root does not match the current user",
        ));
    }
    Ok(record)
}
pub(super) fn verify_record(record: &InstallRecord) -> io::Result<()> {
    if record.owner_sid != current_sid()?
        || record.run_value != run_value_name(&record.root)
        || record.executable != agent_executable(&record.root)
        || record.config != record.root.join("state/agent.json")
        || record.launcher_executable != system_wscript()?
        || record.startup_script != record.root.join(".hostlink-agent-start.vbs")
        || !record.pipe_name.starts_with(r"\\.\pipe\hostlink-agent-")
        || record.control_token.len() != 64
        || !record.control_token.bytes().all(|b| b.is_ascii_hexdigit())
        || record.maintenance != record.maintenance_previous_sha256.is_some()
    {
        return Err(invalid(
            "service marker paths or current-user identity are inconsistent",
        ));
    }
    if let Some(previous) = &record.maintenance_previous_sha256 {
        validate_sha256(previous)?;
    }
    validate_sha256(&record.executable_sha256)?;
    if canonical_regular(&record.executable)? != record.executable
        || canonical_regular(&record.config)? != record.config
    {
        return Err(invalid(
            "service executable or config path is not canonical",
        ));
    }
    verify_enrollment_root(&record.root)?;
    canonical_private_dir(&record.root.join("bin"))?;
    if sha256_file(&record.executable)? != record.executable_sha256 {
        return Err(invalid(
            "installed Agent executable SHA-256 changed; service will not be controlled",
        ));
    }
    canonical_regular(&record.startup_script)?;
    let script = fs::read(&record.startup_script)?;
    if format!("{:x}", Sha256::digest(&script)) != record.startup_script_sha256
        || script != render_script(record).as_bytes()
    {
        return Err(invalid(
            "current-user startup launcher differs from the owned record",
        ));
    }
    if render_command(record).encode_utf16().count() + 1 > 260 {
        return Err(invalid(
            "owned startup command exceeds the Windows HKCU Run limit",
        ));
    }
    let launcher_metadata = fs::symlink_metadata(&record.launcher_executable)?;
    if !launcher_metadata.is_file() || is_reparse(&launcher_metadata) {
        return Err(invalid("Windows Script Host launcher path is unsafe"));
    }
    Ok(())
}
pub(super) fn validate_record_paths(record: &InstallRecord) -> io::Result<()> {
    if record.owner_sid != current_sid()?
        || record.root != verify_install_root(&record.root)?
        || record.run_value != run_value_name(&record.root)
        || record.executable != agent_executable(&record.root)
        || record.config != record.root.join("state/agent.json")
        || record.launcher_executable != system_wscript()?
        || record.startup_script != record.root.join(".hostlink-agent-start.vbs")
    {
        return Err(invalid("service maintenance owner paths are inconsistent"));
    }
    verify_enrollment_root(&record.root)?;
    canonical_regular(&record.config)?;
    canonical_regular(&record.startup_script)?;
    Ok(())
}
pub(super) fn validate_sha256(value: &str) -> io::Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid("executable digest must be lowercase SHA-256"));
    }
    Ok(())
}
pub(super) fn active_jobs(record: &InstallRecord) -> io::Result<Vec<String>> {
    jobs::active_ids(&load_config(&record.config)?.jobs_root)
}
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
    if config.host_key.is_relative() {
        config.host_key = base.join(config.host_key);
    }
    if config.authorized_keys.is_relative() {
        config.authorized_keys = base.join(config.authorized_keys);
    }
    if config.jobs_root.is_relative() {
        config.jobs_root = base.join(config.jobs_root);
    }
    if let Some(gateway) = &mut config.gateway {
        if gateway.identity.is_relative() {
            gateway.identity = base.join(&gateway.identity);
        }
        if gateway.host_public_key.is_relative() {
            gateway.host_public_key = base.join(&gateway.host_public_key);
        }
    }
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
    let manifest: serde_json::Value = serde_json::from_slice(&manifest_bytes)
        .map_err(|_| invalid("Agent enrollment manifest is invalid"))?;
    let machine: serde_json::Value = serde_json::from_slice(&machine_bytes)
        .map_err(|_| invalid("Agent enrollment identity is invalid"))?;
    if manifest["format"].as_u64() != Some(1)
        || machine["format"].as_u64() != Some(1)
        || manifest["machine_id"] != machine["machine_id"]
        || machine["machine_id"].as_str().is_none_or(str::is_empty)
        || machine["name"].as_str().is_none_or(str::is_empty)
        || machine["ssh_public_key"].as_str().is_none_or(str::is_empty)
        || machine["ssh_host_public_key"]
            .as_str()
            .is_none_or(str::is_empty)
    {
        return Err(invalid(
            "Agent enrollment identity and manifest do not match",
        ));
    }
    let files = manifest["files"]
        .as_object()
        .ok_or_else(|| invalid("Agent enrollment manifest files are missing"))?;
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
        if expected["size"].as_u64() != Some(bytes.len() as u64)
            || expected["sha256"].as_str() != Some(&digest)
        {
            return Err(invalid("Agent enrollment file does not match its manifest"));
        }
    }
    Ok(())
}
pub(super) fn run_value_name(root: &Path) -> String {
    format!(
        "HostLinkAgent-{}",
        hex(&Sha256::digest(root.as_os_str().to_string_lossy().as_bytes())[..12])
    )
}
pub(super) fn agent_executable(root: &Path) -> PathBuf {
    root.join("bin/hostlink-agent.exe")
}
pub(super) fn registry_value(name: &str) -> io::Result<Option<String>> {
    let key_name = wide(RUN_KEY);
    let value_name = wide(name);
    let mut key: HKEY = std::ptr::null_mut();
    // SAFETY: registry handles and buffers follow the documented Win32 API contracts.
    let status = unsafe {
        RegOpenKeyExW(
            HKEY_CURRENT_USER,
            key_name.as_ptr(),
            0,
            KEY_QUERY_VALUE,
            &mut key,
        )
    };
    if status != ERROR_SUCCESS {
        return if status == 2 {
            Ok(None)
        } else {
            Err(io::Error::from_raw_os_error(status as i32))
        };
    }
    let mut kind = 0;
    let mut bytes = 0;
    let status = unsafe {
        RegQueryValueExW(
            key,
            value_name.as_ptr(),
            std::ptr::null(),
            &mut kind,
            std::ptr::null_mut(),
            &mut bytes,
        )
    };
    if status != ERROR_SUCCESS {
        unsafe {
            RegCloseKey(key);
        }
        return if status == 2 {
            Ok(None)
        } else {
            Err(io::Error::from_raw_os_error(status as i32))
        };
    }
    if kind != REG_SZ || bytes < 2 || bytes as usize > 64 * 1024 {
        unsafe {
            RegCloseKey(key);
        }
        return Err(invalid(
            "HKCU startup value has an unexpected registry type or size",
        ));
    }
    let mut data = vec![0u16; bytes as usize / 2];
    let status = unsafe {
        RegQueryValueExW(
            key,
            value_name.as_ptr(),
            std::ptr::null(),
            &mut kind,
            data.as_mut_ptr().cast(),
            &mut bytes,
        )
    };
    unsafe {
        RegCloseKey(key);
    }
    if status != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    let end = data.iter().position(|ch| *ch == 0).unwrap_or(data.len());
    String::from_utf16(&data[..end])
        .map(Some)
        .map_err(io::Error::other)
}
pub(super) fn set_registry_value(name: &str, value: &str) -> io::Result<()> {
    let key_name = wide(RUN_KEY);
    let value_name = wide(name);
    let data = wide(value);
    let mut key: HKEY = std::ptr::null_mut();
    let mut disposition = 0;
    let status = unsafe {
        RegCreateKeyExW(
            HKEY_CURRENT_USER,
            key_name.as_ptr(),
            0,
            std::ptr::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE,
            std::ptr::null(),
            &mut key,
            &mut disposition,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    let status = unsafe {
        RegSetValueExW(
            key,
            value_name.as_ptr(),
            0,
            REG_SZ,
            data.as_ptr().cast(),
            (data.len() * 2) as u32,
        )
    };
    unsafe {
        RegCloseKey(key);
    }
    if status == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(status as i32))
    }
}
pub(super) fn delete_registry_value(name: &str) -> io::Result<()> {
    let key_name = wide(RUN_KEY);
    let value_name = wide(name);
    let mut key: HKEY = std::ptr::null_mut();
    let status = unsafe {
        RegOpenKeyExW(
            HKEY_CURRENT_USER,
            key_name.as_ptr(),
            0,
            KEY_SET_VALUE,
            &mut key,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    let status = unsafe { RegDeleteValueW(key, value_name.as_ptr()) };
    unsafe {
        RegCloseKey(key);
    }
    if status == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(status as i32))
    }
}
pub(super) fn has_enrollment(root: &Path) -> bool {
    fs::symlink_metadata(root.join("state/machine.json"))
        .is_ok_and(|m| m.is_file() && !is_reparse(&m))
}
