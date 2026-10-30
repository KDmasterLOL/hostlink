use super::*;

/// Inputs that must be supplied intentionally by the user or the installer.
#[derive(Clone, Debug)]
pub struct EnrollmentOptions {
    pub hub_url: String,
    pub token_file: PathBuf,
    pub install_root: PathBuf,
    pub name: String,
    pub user: String,
    /// Keep the reconciliation marker until the bootstrap installer validates publication.
    pub retain_pending: bool,
    /// Required when the Hub approves more than one gateway. This is the zero-based
    /// index from the exact v2 response, not a hostname or a TOFU selection.
    pub gateway_index: Option<usize>,
}

/// Non-secret facts published with the generated Agent configuration.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentIdentity {
    pub format: u32,
    pub machine_id: MachineId,
    pub name: String,
    pub ssh_public_key: String,
    pub ssh_host_public_key: String,
    pub gateway: GatewayEndpoint,
    pub remote_port: u16,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EnrollmentManifest {
    pub(crate) format: u32,
    pub(crate) machine_id: MachineId,
    pub(crate) name: String,
    pub(crate) files: std::collections::BTreeMap<String, FileDigest>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FileDigest {
    pub(crate) size: u64,
    pub(crate) sha256: String,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AttemptIdentity {
    format: u32,
    machine_id: MachineId,
    name: String,
    ssh_public_key: String,
    ssh_host_public_key: String,
}

/// Paths to a successfully published fresh enrollment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnrollmentResult {
    pub install_root: PathBuf,
    pub config_path: PathBuf,
    pub machine_id: String,
}

/// Generate keys, enroll once over HTTPS, validate the complete v2 reply and publish privately.
///
/// A transport failure after the request is sent is reported as reconciliation required. This
/// function never retries the one-use invite token.
pub async fn prepare_enrollment(options: &EnrollmentOptions) -> io::Result<EnrollmentResult> {
    prepare_enrollment_with_ca(options, None).await
}

/// Enroll using the normal TLS validation plus one explicitly supplied CA certificate.
/// This supports private Hub PKI without an insecure TLS mode or HTTP fallback.
pub async fn prepare_enrollment_with_ca(
    options: &EnrollmentOptions,
    ca_certificate: Option<&Path>,
) -> io::Result<EnrollmentResult> {
    let hub_url = options.hub_url.clone();
    let ca_certificate = ca_certificate.map(Path::to_path_buf);
    let result = prepare_enrollment_using(options, move |_, request| {
        let hub_url = hub_url.clone();
        let ca_certificate = ca_certificate.clone();
        async move { enroll_once(&hub_url, request, ca_certificate.as_deref()).await }
    })
    .await;
    if let Err(error) = result {
        if options.install_root.join("enrollment.pending").is_file() {
            return Err(io::Error::other(format!(
                "enrollment has a pending reconciliation marker; do not retry this one-use invite; reconcile the Hub record first ({error})"
            )));
        }
        return Err(error);
    }
    result
}

pub(super) async fn prepare_enrollment_using<F, Fut>(
    options: &EnrollmentOptions,
    enroll: F,
) -> io::Result<EnrollmentResult>
where
    F: FnOnce(&str, EnrollRequest) -> Fut,
    Fut: std::future::Future<Output = io::Result<EnrollResponse>>,
{
    validate_inputs(options)?;
    #[cfg(unix)]
    if unsafe { libc::geteuid() } == 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "enrollment must not run as root",
        ));
    }
    ensure_fresh_root_parent(&options.install_root)?;
    let token = read_token(&options.token_file)?;

    let machine_id = MachineId::parse(Uuid::new_v4().to_string()).map_err(invalid_data)?;
    let reverse_key =
        PrivateKey::random(&mut rng(), Algorithm::Ed25519).map_err(io::Error::other)?;
    let host_key = PrivateKey::random(&mut rng(), Algorithm::Ed25519).map_err(io::Error::other)?;
    let reverse_public = public_key(&reverse_key)?;
    let host_public = public_key(&host_key)?;
    if reverse_public == host_public {
        return Err(invalid("generated SSH key pairs must be distinct"));
    }

    // The root and pending marker make a second invocation fail closed even if publication or
    // the Hub acknowledgement was interrupted. The invite is never sent a second time.
    let agent_dir = PrivateDir::ensure(&options.install_root).map_err(io::Error::other)?;
    let pending = options.install_root.join("enrollment.pending");
    write_private_new(
        &pending,
        b"Hub enrollment may have committed; reconcile before retrying\n",
    )?;
    let stage_name = format!(".stage-{}", Uuid::new_v4());
    let stage_dir = agent_dir
        .create_dir(&stage_name)
        .map_err(io::Error::other)?;
    let stage = options.install_root.join(stage_name);

    let reverse_private = reverse_key
        .to_openssh(LineEnding::LF)
        .map_err(io::Error::other)?;
    let host_private = host_key
        .to_openssh(LineEnding::LF)
        .map_err(io::Error::other)?;
    write_private_new(&stage.join("gateway_identity"), reverse_private.as_bytes())?;
    write_private_new(&stage.join("host_key"), host_private.as_bytes())?;
    write_private_new(
        &stage.join("enrollment-attempt.json"),
        &serde_json::to_vec(&AttemptIdentity {
            format: 1,
            machine_id: machine_id.clone(),
            name: options.name.clone(),
            ssh_public_key: reverse_public.clone(),
            ssh_host_public_key: host_public.clone(),
        })
        .map_err(io::Error::other)?,
    )?;
    sync_directory(&stage)?;

    let request = EnrollRequest {
        token,
        machine_id: machine_id.clone(),
        name: options.name.clone(),
        hostname: local_hostname(),
        os: std::env::consts::OS.to_owned(),
        arch: std::env::consts::ARCH.to_owned(),
        agent_version: env!("CARGO_PKG_VERSION").to_owned(),
        ssh_public_key: reverse_public.clone(),
        ssh_host_public_key: host_public.clone(),
    };
    let response = match enroll(&options.hub_url, request).await {
        Ok(response) => response,
        Err(error) => {
            return Err(io::Error::other(format!(
                "Hub enrollment outcome is uncertain; reconcile the invite before retrying ({error})"
            )));
        }
    };
    let gateways = validate_response(
        &response,
        &machine_id,
        &options.name,
        &reverse_public,
        &host_public,
        options.gateway_index,
    )?;

    write_private_new(
        &stage.join("authorized_keys"),
        format!("{}\n", response.operator_ssh_public_keys.join("\n")).as_bytes(),
    )?;

    // The durable-job store must be the same install_root/jobs inspected by
    // update::apply and its active-job interlock. Keeping it below state/
    // would let a running managed job evade update deferral.
    let jobs_root = options.install_root.join("jobs");
    agent_dir.create_dir("jobs").map_err(io::Error::other)?;
    jobs::JobStore::initialize_fresh(&jobs_root)
        .await?
        .close()
        .await;
    let gateway = gateways[0].clone();
    let alternates = gateways
        .iter()
        .skip(1)
        .enumerate()
        .map(|(index, endpoint)| ReverseGateway {
            host: endpoint.host.clone(),
            port: endpoint.port,
            user: endpoint.user.clone(),
            identity: PathBuf::from("gateway_identity"),
            host_public_key: PathBuf::from(format!("gateway_host_key_{}", index + 1)),
            remote_port: response.host.remote_port,
        })
        .collect::<Vec<_>>();
    let listen = available_loopback_addr()?;
    // The board is a separate localhost-only HTTP endpoint. Assign a distinct
    // available address during fresh enrollment so users can open it without
    // modifying the manifest-bound installed configuration.
    let mut board_listen = None;
    for _ in 0..LISTENER_PORT_ATTEMPTS {
        let candidate = available_loopback_addr()?;
        if candidate != listen {
            board_listen = Some(candidate);
            break;
        }
    }
    let board_listen = board_listen.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "could not allocate a distinct board port",
        )
    })?;
    let config = AgentConfig {
        listen,
        user: options.user.clone(),
        host_key: PathBuf::from("host_key"),
        authorized_keys: PathBuf::from("authorized_keys"),
        jobs_root,
        board_listen: Some(board_listen),
        gateway: Some(ReverseGateway {
            host: gateway.host.clone(),
            port: gateway.port,
            user: gateway.user.clone(),
            identity: PathBuf::from("gateway_identity"),
            host_public_key: PathBuf::from("gateway_host_key"),
            remote_port: response.host.remote_port,
        }),
        gateway_alternates: alternates,
    };
    config.validate()?;
    write_private_new(
        &stage.join("gateway_host_key"),
        format!("{}\n", gateway.host_public_key).as_bytes(),
    )?;
    for (index, endpoint) in gateways.iter().skip(1).enumerate() {
        write_private_new(
            &stage.join(format!("gateway_host_key_{}", index + 1)),
            format!("{}\n", endpoint.host_public_key).as_bytes(),
        )?;
    }
    write_private_new(
        &stage.join("agent.json"),
        &serde_json::to_vec(&config).map_err(io::Error::other)?,
    )?;
    let identity = EnrollmentIdentity {
        format: 1,
        machine_id: response.host.machine_id,
        name: response.host.name,
        ssh_public_key: response.host.ssh_public_key,
        ssh_host_public_key: response.host.ssh_host_public_key,
        gateway,
        remote_port: response.host.remote_port,
    };
    write_private_new(
        &stage.join("machine.json"),
        &serde_json::to_vec(&identity).map_err(io::Error::other)?,
    )?;
    stage_dir
        .remove_file("enrollment-attempt.json", private_fs::Durability::None)
        .map_err(io::Error::other)?;
    let mut files = vec![
        "agent.json".to_owned(),
        "authorized_keys".to_owned(),
        "gateway_host_key".to_owned(),
        "gateway_identity".to_owned(),
        "host_key".to_owned(),
        "machine.json".to_owned(),
    ];
    files.extend((1..gateways.len()).map(|index| format!("gateway_host_key_{index}")));
    let files = files
        .into_iter()
        .map(|name| {
            let mut bytes = Vec::new();
            stage_dir
                .open_file(&name)
                .map_err(io::Error::other)?
                .read_to_end(&mut bytes)?;
            Ok((
                name.to_owned(),
                FileDigest {
                    size: bytes.len() as u64,
                    sha256: format!("{:x}", Sha256::digest(&bytes)),
                },
            ))
        })
        .collect::<io::Result<std::collections::BTreeMap<_, _>>>()?;
    write_private_new(
        &stage.join("manifest.json"),
        &serde_json::to_vec(&EnrollmentManifest {
            format: 1,
            machine_id: identity.machine_id.clone(),
            name: identity.name.clone(),
            files,
        })
        .map_err(io::Error::other)?,
    )?;
    // Release stage directory handles before renaming on Windows.
    drop(stage_dir);
    sync_directory(&stage)?;

    // Publish the complete set with one same-filesystem directory rename.
    let state = options.install_root.join("state");
    fs::rename(&stage, &state)?;
    sync_directory(&options.install_root)?;
    if !options.retain_pending {
        fs::remove_file(&pending)?;
        sync_directory(&options.install_root)?;
    }
    Ok(EnrollmentResult {
        install_root: options.install_root.clone(),
        config_path: state.join("agent.json"),
        machine_id: identity.machine_id.to_string(),
    })
}

pub(super) async fn enroll_once(
    hub_url: &str,
    request: EnrollRequest,
    ca_certificate: Option<&Path>,
) -> io::Result<EnrollResponse> {
    let mut url = parse_hub_url(hub_url)?;
    url.set_path(ENROLLMENT_PATH);
    let mut builder = Client::builder()
        .use_rustls_tls()
        .https_only(true)
        .redirect(Policy::none())
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT);
    if let Some(path) = ca_certificate {
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            options.custom_flags(0x0020_0000);
        }
        let file = options
            .open(path)
            .map_err(|_| invalid("Hub CA certificate is unavailable"))?;
        let metadata = file
            .metadata()
            .map_err(|_| invalid("Hub CA certificate is unavailable"))?;
        if !metadata.is_file() || metadata.len() > 64 * 1024 {
            return Err(invalid("Hub CA certificate is unsafe or oversized"));
        }
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        file.take(64 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| invalid("Hub CA certificate is unavailable"))?;
        if bytes.len() > 64 * 1024 {
            return Err(invalid("Hub CA certificate is unsafe or oversized"));
        }
        let certificate = reqwest::Certificate::from_pem(&bytes)
            .map_err(|_| invalid("Hub CA certificate is invalid"))?;
        builder = builder.add_root_certificate(certificate);
    }
    let client = builder
        .build()
        .map_err(|_| invalid("cannot initialize HTTPS client"))?;
    let response = client
        .post(url)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .json(&request)
        .send()
        .await
        .map_err(|_| invalid("HTTPS request failed"))?;
    if response.status() != reqwest::StatusCode::CREATED {
        return Err(invalid(
            "Hub rejected enrollment or returned an unexpected status",
        ));
    }
    if response
        .content_length()
        .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
    {
        return Err(invalid("Hub enrollment response exceeds size limit"));
    }
    if !response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(';')
                .next()
                .is_some_and(|mime| mime.trim() == "application/json")
        })
    {
        return Err(invalid("Hub enrollment response is not JSON"));
    }
    let mut response = response;
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| invalid("cannot read Hub response"))?
    {
        if body.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
            return Err(invalid("Hub enrollment response exceeds size limit"));
        }
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body).map_err(|_| invalid("Hub enrollment response is invalid"))
}
