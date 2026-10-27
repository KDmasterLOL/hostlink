//! Explicit, one-shot enrollment of a fresh user-owned Agent root.

use crate::{AgentConfig, ReverseGateway, jobs};
use hostlink_hub::{EnrollRequest, EnrollResponse, GatewayEndpoint, MachineId};
use rand::{RngExt, rng};
use reqwest::{Client, Url, redirect::Policy};
use russh::keys::{Algorithm, PrivateKey, ssh_key::LineEnding};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    net::{SocketAddr, TcpListener},
    path::{Path, PathBuf},
    time::Duration,
};
use uuid::Uuid;

const MAX_TOKEN_BYTES: u64 = 4096;
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const ENROLLMENT_PATH: &str = "/v2/enroll";
// This range avoids the commonly used dynamic client-port ranges on Linux and Windows,
// but operating-system port-range configuration is not universal.
const AGENT_LISTENER_PORTS: std::ops::RangeInclusive<u16> = 20_000..=29_999;
const LISTENER_PORT_ATTEMPTS: usize = 32;

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

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct EnrollmentManifest {
    format: u32,
    machine_id: MachineId,
    name: String,
    files: std::collections::BTreeMap<String, FileDigest>,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct FileDigest {
    size: u64,
    sha256: String,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct AttemptIdentity {
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

async fn prepare_enrollment_using<F, Fut>(
    options: &EnrollmentOptions,
    enroll: F,
) -> io::Result<EnrollmentResult>
where
    F: FnOnce(&str, EnrollRequest) -> Fut,
    Fut: std::future::Future<Output = io::Result<EnrollResponse>>,
{
    validate_inputs(options)?;
    reject_elevated_user()?;
    ensure_fresh_root_parent(&options.install_root)?;
    jobs::validate_private_path(&options.token_file, false)?;
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
    fs::create_dir(&options.install_root)?;
    jobs::restrict_private_path(&options.install_root, true)?;
    let pending = options.install_root.join("enrollment.pending");
    write_private_new(
        &pending,
        b"Hub enrollment may have committed; reconcile before retrying\n",
    )?;
    let stage = options
        .install_root
        .join(format!(".stage-{}", Uuid::new_v4()));
    fs::create_dir(&stage)?;
    jobs::restrict_private_path(&stage, true)?;

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
    fs::create_dir(&jobs_root)?;
    jobs::restrict_private_path(&jobs_root, true)?;
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
    let config = AgentConfig {
        listen: available_loopback_addr()?,
        user: options.user.clone(),
        host_key: PathBuf::from("host_key"),
        authorized_keys: PathBuf::from("authorized_keys"),
        jobs_root,
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
    fs::remove_file(stage.join("enrollment-attempt.json"))?;
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
            let path = stage.join(&name);
            let bytes = fs::read(&path)?;
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
    // Files are already flushed by write_private_new. Windows cannot open a
    // directory with File::open for sync_all; use the platform-aware barrier.
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

async fn enroll_once(
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

fn parse_hub_url(value: &str) -> io::Result<Url> {
    let url = Url::parse(value).map_err(|_| invalid("Hub URL must be an HTTPS origin"))?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "/" | "")
    {
        return Err(invalid(
            "Hub URL must be an HTTPS origin without credentials, path, query or fragment",
        ));
    }
    Ok(url)
}

fn validate_response(
    response: &EnrollResponse,
    machine_id: &MachineId,
    name: &str,
    reverse_public: &str,
    host_public: &str,
    gateway_index: Option<usize>,
) -> io::Result<Vec<GatewayEndpoint>> {
    if &response.host.machine_id != machine_id
        || response.host.name != name
        || response.host.remote_port == 0
        || response.host.ssh_public_key != reverse_public
        || response.host.ssh_host_public_key != host_public
    {
        return Err(invalid(
            "Hub enrollment response does not match the submitted identity and keys",
        ));
    }
    if response.operator_ssh_public_keys.is_empty() || response.operator_ssh_public_keys.len() > 32
    {
        return Err(invalid(
            "Hub returned no authorized Controller keys or too many keys",
        ));
    }
    let mut seen_keys = std::collections::BTreeSet::new();
    for key in &response.operator_ssh_public_keys {
        hostlink_hub::validate_ed25519_public_key(key).map_err(invalid_data)?;
        let canonical = hostlink_hub::canonical_ed25519_public_key(key).map_err(invalid_data)?;
        if !seen_keys.insert(canonical) {
            return Err(invalid("Hub returned duplicate authorized Controller keys"));
        }
    }
    if response.gateways.is_empty() || response.gateways.len() > 16 {
        return Err(invalid(
            "Hub returned no approved gateway routes or too many routes",
        ));
    }
    let mut seen_routes = std::collections::BTreeSet::new();
    for endpoint in &response.gateways {
        endpoint.validate().map_err(invalid_data)?;
        let pin = hostlink_hub::canonical_ed25519_public_key(&endpoint.host_public_key)
            .map_err(invalid_data)?;
        if !seen_routes.insert((
            endpoint.host.to_ascii_lowercase(),
            endpoint.user.clone(),
            endpoint.port,
            pin,
        )) {
            return Err(invalid("Hub returned duplicate gateway routes"));
        }
    }
    let selected_index = match (response.gateways.as_slice(), gateway_index) {
        ([_], None) => 0,
        (routes, Some(index)) if index < routes.len() => index,
        (_, None) => {
            return Err(invalid(
                "Hub approved multiple gateways; rerun with an explicit --gateway-index",
            ));
        }
        (_, Some(_)) => return Err(invalid("selected gateway index is not in Hub response")),
    };
    let mut selected = Vec::with_capacity(response.gateways.len());
    selected.push(response.gateways[selected_index].clone());
    selected.extend(
        response
            .gateways
            .iter()
            .enumerate()
            .filter(|(index, _)| *index != selected_index)
            .map(|(_, endpoint)| endpoint.clone()),
    );
    Ok(selected)
}

fn validate_inputs(options: &EnrollmentOptions) -> io::Result<()> {
    parse_hub_url(&options.hub_url)?;
    if !canonical_name(&options.name) {
        return Err(invalid("Agent name must be canonical lowercase ASCII"));
    }
    if options.user.is_empty()
        || options.user.len() > 128
        || options.user.chars().any(char::is_whitespace)
    {
        return Err(invalid("Agent SSH user is invalid"));
    }
    if !options.install_root.is_absolute() {
        return Err(invalid("Agent install root must be absolute"));
    }
    Ok(())
}

fn canonical_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value.as_bytes()[value.len() - 1].is_ascii_alphanumeric()
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"-_.".contains(&byte)
        })
}

fn read_token(path: &Path) -> io::Result<SecretString> {
    jobs::validate_private_path(path, false)?;
    let mut bytes = Vec::new();
    File::open(path)?
        .take(MAX_TOKEN_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_TOKEN_BYTES {
        return Err(invalid("enrollment token file exceeds size limit"));
    }
    while bytes.last().is_some_and(u8::is_ascii_whitespace) {
        bytes.pop();
    }
    let token =
        String::from_utf8(bytes).map_err(|_| invalid("enrollment token file is not UTF-8"))?;
    if token.len() != 64
        || !token
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(invalid("enrollment token file has invalid format"));
    }
    Ok(SecretString::from(token))
}

fn public_key(key: &PrivateKey) -> io::Result<String> {
    let mut public = key.public_key().clone();
    public.set_comment(String::new());
    public.to_openssh().map_err(io::Error::other)
}

fn write_private_new(path: &Path, contents: &[u8]) -> io::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!(
                "cannot create private enrollment file {}: {error}",
                path.display()
            ),
        )
    })?;
    jobs::restrict_private_path(path, false).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!(
                "private enrollment file validation failed for {}: {error}",
                path.display()
            ),
        )
    })?;
    file.write_all(contents)?;
    file.sync_all()
}

fn ensure_fresh_root_parent(root: &Path) -> io::Result<()> {
    if root.exists() || fs::symlink_metadata(root).is_ok() {
        return Err(invalid(
            "Agent install root already exists; enrollment never adopts an existing root",
        ));
    }
    let parent = root
        .parent()
        .ok_or_else(|| invalid("Agent install root has no parent"))?;
    #[cfg(not(windows))]
    {
        let canonical = fs::canonicalize(parent)?;
        if canonical != parent {
            return Err(invalid(
                "Agent install root parent path contains a symlink or traversal alias",
            ));
        }
    }
    // On Windows canonicalize() rewrites ordinary C:\ paths into \\?\C:\
    // extended-length paths. Their PathBuf values differ even in the absence
    // of a junction. Inspect each ancestor without following reparse points
    // rather than treating that benign prefix conversion as an alias.
    #[cfg(windows)]
    reject_windows_parent_reparse_components(parent)?;
    let metadata = fs::symlink_metadata(parent)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(invalid("Agent install root parent is not a real directory"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        // SAFETY: geteuid reads the current process identity and has no preconditions.
        if metadata.uid() != unsafe { libc::geteuid() } {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Agent install root parent is not user-owned",
            ));
        }
        if metadata.permissions().mode() & 0o022 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Agent install root parent is writable by another user",
            ));
        }
    }
    #[cfg(windows)]
    jobs::validate_private_path(parent, true)?;
    Ok(())
}

#[cfg(windows)]
fn reject_windows_parent_reparse_components(parent: &Path) -> io::Result<()> {
    use std::os::windows::fs::MetadataExt;
    use std::path::{Component, Prefix};
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    if !parent.is_absolute() {
        return Err(invalid("Agent install root parent must be absolute"));
    }
    let mut ancestor = PathBuf::new();
    for component in parent.components() {
        match component {
            Component::Prefix(prefix) => {
                if !matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_)) {
                    return Err(invalid(
                        "Agent install root must be on a local Windows drive",
                    ));
                }
                ancestor.push(component.as_os_str());
            }
            Component::RootDir => ancestor.push(component.as_os_str()),
            Component::CurDir | Component::ParentDir => {
                return Err(invalid("Agent install root parent contains path traversal"));
            }
            Component::Normal(_) => {
                ancestor.push(component.as_os_str());
                let metadata = fs::symlink_metadata(&ancestor)?;
                if metadata.file_type().is_symlink()
                    || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
                {
                    return Err(invalid(
                        "Agent install root parent contains a symlink or reparse point",
                    ));
                }
            }
        }
    }
    Ok(())
}

fn reject_elevated_user() -> io::Result<()> {
    #[cfg(unix)]
    {
        // SAFETY: geteuid reads the current process identity and has no preconditions.
        if unsafe { libc::geteuid() } == 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "enrollment must run as a normal user",
            ));
        }
    }
    #[cfg(windows)]
    windows_elevation::reject_elevated_user()?;
    Ok(())
}

#[cfg(windows)]
mod windows_elevation {
    use std::{io, mem::size_of};
    use windows_sys::Win32::{
        Foundation::{CloseHandle, GetLastError, HANDLE},
        Security::{GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation},
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    };

    pub fn reject_elevated_user() -> io::Result<()> {
        let current_sid =
            windows_permissions::utilities::current_process_sid().map_err(io::Error::other)?;
        let system_sid: windows_permissions::LocalBox<windows_permissions::Sid> =
            "S-1-5-18".parse().map_err(io::Error::other)?;
        if current_sid.as_ref() == system_sid.as_ref() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "enrollment must not run as SYSTEM",
            ));
        }
        // SAFETY: all handles and output buffers follow the Win32 token API contracts.
        unsafe {
            let mut token: HANDLE = std::ptr::null_mut();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                return Err(io::Error::from_raw_os_error(GetLastError() as i32));
            }
            let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
            let mut returned = 0;
            let result = GetTokenInformation(
                token,
                TokenElevation,
                (&mut elevation as *mut TOKEN_ELEVATION).cast(),
                size_of::<TOKEN_ELEVATION>() as u32,
                &mut returned,
            );
            let last_error = GetLastError();
            CloseHandle(token);
            if result == 0 {
                return Err(io::Error::from_raw_os_error(last_error as i32));
            }
            if elevation.TokenIsElevated != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "enrollment must not run elevated or as SYSTEM",
                ));
            }
        }
        Ok(())
    }
}

fn local_hostname() -> String {
    ["COMPUTERNAME", "HOSTNAME"]
        .iter()
        .find_map(|key| std::env::var(key).ok())
        .filter(|v| !v.is_empty() && v.len() <= 128)
        .unwrap_or_else(|| "unknown-host".into())
}

fn available_loopback_addr() -> io::Result<SocketAddr> {
    available_loopback_addr_from(std::iter::repeat_with(|| {
        rng().random_range(AGENT_LISTENER_PORTS.clone())
    }))
}

fn available_loopback_addr_from(candidates: impl Iterator<Item = u16>) -> io::Result<SocketAddr> {
    for port in candidates.take(LISTENER_PORT_ATTEMPTS) {
        let address = SocketAddr::from(([127, 0, 0, 1], port));
        match TcpListener::bind(address) {
            Ok(listener) => {
                let address = listener.local_addr()?;
                // Enrollment publishes the address before a separate Agent process starts.
                // Releasing this probe leaves an unavoidable TOCTOU window in which another
                // process can claim the port; Agent startup still fails closed if that happens.
                drop(listener);
                return Ok(address);
            }
            Err(error) if error.kind() == io::ErrorKind::AddrInUse => {}
            Err(error) => return Err(error),
        }
    }

    Err(io::Error::new(
        io::ErrorKind::AddrNotAvailable,
        format!(
            "could not find an available loopback port in {}-{} after {} attempts; retry enrollment",
            AGENT_LISTENER_PORTS.start(),
            AGENT_LISTENER_PORTS.end(),
            LISTENER_PORT_ATTEMPTS
        ),
    ))
}

fn sync_directory(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    File::open(path)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
fn invalid_data(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

#[cfg(test)]
mod tests;
