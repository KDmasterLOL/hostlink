//! HTTPS management client for the authoritative HostLink Hub v2 registry.

use std::{
    fs::{self, OpenOptions},
    io::Read,
    net::SocketAddr,
    path::{Path, PathBuf},
    time::Duration,
};

use hostlink_hub::{GatewayEndpoint, InviteRequest, InviteResponse, RegisteredHost};
use reqwest::{Method, StatusCode, Url};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{GatewayHop, HostSpec};

const MAX_BODY_BYTES: usize = 64 * 1024;
const MAX_CREDENTIAL_BYTES: u64 = 64 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

/// Controller-local settings needed to turn authoritative Hub records into pinned SSH targets.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HubConfig {
    /// HTTPS origin of the Hub, without a path, query, or credentials.
    pub hub_url: String,
    /// Owner-only file containing the operator bearer token.
    pub token_file: PathBuf,
    /// Explicit SSH account accepted by the Agent; never inferred from host metadata.
    pub ssh_user: String,
    /// Owner-only Ed25519 controller identity.
    pub identity: PathBuf,
    /// Owner-only Ed25519 identity used for the approved gateway.
    pub gateway_identity: PathBuf,
}

/// Confirmed result of Hub revocation.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RevokeReceipt {
    /// Hub revoked authorization for new connections.
    pub revoked_new_connections: bool,
    /// Hub cannot confirm termination of already established SSH sessions.
    pub confirmed_session_terminated: bool,
    /// Hub does not uninstall the remote Agent.
    pub remote_uninstall: bool,
    /// Gateway authorized key projection result.
    pub authorized_key_projection: String,
}

/// Safe errors from the Hub client. HTTP bodies and credential values are never rendered.
#[derive(Debug, Error)]
pub enum HubClientError {
    /// Hub configuration or host metadata is invalid.
    #[error("invalid Hub configuration or registry record: {0}")]
    Invalid(String),
    /// No host matched the supplied canonical name or machine ID.
    #[error("Hub host was not found")]
    NotFound,
    /// More than one host matched a short selector.
    #[error("Hub host selector is ambiguous; use a canonical name or full machine ID")]
    Ambiguous,
    /// Hub rejected the operator credential.
    #[error("Hub authorization failed")]
    Unauthorized,
    /// Hub returned a non-success response; status only is included.
    #[error("Hub request failed with HTTP status {0}")]
    HttpStatus(StatusCode),
    /// Hub request failed or exceeded its deadline.
    #[error("Hub request failed or timed out")]
    Request,
    /// Hub response exceeded the fixed size bound or did not match v2.
    #[error("Hub response is oversized or invalid")]
    Response,
    /// Local credential files are unsafe or inaccessible.
    #[error("Hub credential file is unsafe or inaccessible")]
    Credential,
    /// DNS lookup did not produce exactly one approved route address in time.
    #[error("gateway DNS lookup failed, timed out, or returned multiple addresses")]
    GatewayDns,
}

/// Authenticated bounded Hub v2 client. Construction performs no network I/O.
pub struct HubClient {
    base: Url,
    token: SecretString,
    client: reqwest::Client,
}

impl HubClient {
    /// Reads a bounded owner-only controller config file and validates its token source.
    pub fn read_config(path: &Path) -> Result<HubConfig, HubClientError> {
        let value = read_private_credential(path)?;
        let config: HubConfig =
            serde_json::from_str(&value).map_err(|_| HubClientError::Credential)?;
        // Constructor validation is deliberately local-only; callers may choose when to connect.
        let _ = Self::from_config(&config)?;
        Ok(config)
    }

    /// Loads the owner-only token and creates a strict HTTPS client without proxies or redirects.
    pub fn from_config(config: &HubConfig) -> Result<Self, HubClientError> {
        let base = parse_origin(&config.hub_url)?;
        if config.ssh_user.is_empty()
            || config.ssh_user.len() > 128
            || config.ssh_user.chars().any(char::is_whitespace)
        {
            return Err(HubClientError::Invalid("SSH user is invalid".into()));
        }
        let token = read_private_credential(&config.token_file)?;
        if token.is_empty() || token.len() > 4096 || token.contains(['\r', '\n']) {
            return Err(HubClientError::Credential);
        }
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .connect_timeout(Duration::from_secs(5))
            .timeout(REQUEST_TIMEOUT)
            .build()
            .map_err(|_| HubClientError::Request)?;
        Ok(Self {
            base,
            token: SecretString::from(token),
            client,
        })
    }

    /// Returns one authoritative inventory snapshot without probing any Agent.
    pub async fn list_hosts(&self) -> Result<Vec<RegisteredHost>, HubClientError> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Response {
            hosts: Vec<RegisteredHost>,
        }
        Ok(self.get_json::<Response>("/v2/hosts").await?.hosts)
    }

    /// Selects an exact canonical name/full ID or a unique machine-ID prefix.
    pub async fn resolve_host(&self, selector: &str) -> Result<RegisteredHost, HubClientError> {
        let selector = selector.trim();
        if selector.is_empty() || selector.len() > 128 {
            return Err(HubClientError::Invalid("host selector is invalid".into()));
        }
        let hosts = self.list_hosts().await?;
        select_host(&hosts, selector)
    }

    /// Reads and validates Hub v2 management capabilities and its approved gateway routes.
    pub async fn info(&self) -> Result<Vec<GatewayEndpoint>, HubClientError> {
        let value: serde_json::Value = self.get_json("/v2/info").await?;
        if value.get("api_version").and_then(|v| v.as_u64()) != Some(2)
            || value.get("management").and_then(|v| v.as_bool()) != Some(true)
            || value.get("execution_transport").and_then(|v| v.as_str()) != Some("russh")
            || value.get("hosts_endpoint").and_then(|v| v.as_str()) != Some("/v2/hosts")
        {
            return Err(HubClientError::Response);
        }
        let gateways: Vec<GatewayEndpoint> = serde_json::from_value(
            value
                .get("gateways")
                .cloned()
                .ok_or(HubClientError::Response)?,
        )
        .map_err(|_| HubClientError::Response)?;
        for gateway in &gateways {
            gateway.validate().map_err(HubClientError::Invalid)?;
        }
        Ok(gateways)
    }

    /// Creates a bounded one-use enrollment invitation. The caller controls the explicit token display boundary.
    pub async fn invite(
        &self,
        name: Option<String>,
        ttl_seconds: u64,
    ) -> Result<InviteResponse, HubClientError> {
        self.request_json(
            Method::POST,
            "/v2/invites",
            Some(&InviteRequest {
                ttl_seconds,
                name,
                rotate_machine_id: None,
            }),
        )
        .await
    }

    /// Sets a display-only label on a registered host.
    pub async fn set_display_name(
        &self,
        host: &RegisteredHost,
        display_name: &str,
    ) -> Result<RegisteredHost, HubClientError> {
        #[derive(Serialize)]
        struct Body<'a> {
            display_name: &'a str,
        }
        self.request_json(
            Method::PATCH,
            &format!("/v2/hosts/{}/display-name", host.machine_id),
            Some(&Body { display_name }),
        )
        .await
    }

    /// Revokes new managed access and requires an explicit truthful reconciliation receipt.
    pub async fn revoke(&self, host: &RegisteredHost) -> Result<RevokeReceipt, HubClientError> {
        let receipt: RevokeReceipt = self
            .request_json::<serde_json::Value, ()>(
                Method::DELETE,
                &format!("/v2/hosts/{}", host.machine_id),
                None,
            )
            .await
            .and_then(|value| {
                serde_json::from_value(value).map_err(|_| HubClientError::Response)
            })?;
        if !receipt.revoked_new_connections
            || receipt.confirmed_session_terminated
            || receipt.remote_uninstall
            || receipt.authorized_key_projection != "reconciled"
        {
            return Err(HubClientError::Response);
        }
        Ok(receipt)
    }

    /// Resolves a fresh authoritative host and its single approved gateway into the existing pinned SSH type.
    pub async fn resolve_host_spec(
        &self,
        selector: &str,
        config: &HubConfig,
    ) -> Result<HostSpec, HubClientError> {
        let host = self.resolve_host(selector).await?;
        let gateways = self.info().await?;
        let gateway = match gateways.as_slice() {
            [gateway] => gateway,
            [] => {
                return Err(HubClientError::Invalid(
                    "Hub has no approved gateway".into(),
                ));
            }
            _ => {
                return Err(HubClientError::Invalid(
                    "Hub advertises multiple gateways; explicit route selection is not supported"
                        .into(),
                ));
            }
        };
        host_spec_from(host, gateway, config).await
    }

    async fn get_json<T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
    ) -> Result<T, HubClientError> {
        self.request_json(Method::GET, path, None::<&()>).await
    }

    async fn request_json<T: for<'de> Deserialize<'de>, B: Serialize + ?Sized>(
        &self,
        method: Method,
        path: &str,
        body: Option<&B>,
    ) -> Result<T, HubClientError> {
        let url = self
            .base
            .join(path)
            .map_err(|_| HubClientError::Invalid("invalid Hub endpoint".into()))?;
        let mut request = self
            .client
            .request(method, url)
            .bearer_auth(self.token.expose_secret());
        if let Some(body) = body {
            request = request.json(body);
        }
        let response = request.send().await.map_err(|_| HubClientError::Request)?;
        let status = response.status();
        if !status.is_success() {
            return Err(
                if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
                    HubClientError::Unauthorized
                } else {
                    HubClientError::HttpStatus(status)
                },
            );
        }
        if response
            .content_length()
            .is_some_and(|length| length > MAX_BODY_BYTES as u64)
        {
            return Err(HubClientError::Response);
        }
        let mut response = response;
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| HubClientError::Request)?
        {
            if bytes.len().saturating_add(chunk.len()) > MAX_BODY_BYTES {
                return Err(HubClientError::Response);
            }
            bytes.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&bytes).map_err(|_| HubClientError::Response)
    }
}

fn parse_origin(value: &str) -> Result<Url, HubClientError> {
    if value.len() > 2048 {
        return Err(HubClientError::Invalid("Hub URL is too long".into()));
    }
    let url = Url::parse(value)
        .map_err(|_| HubClientError::Invalid("Hub URL must be an HTTPS origin".into()))?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(HubClientError::Invalid(
            "Hub URL must be an HTTPS origin without credentials, path, query, or fragment".into(),
        ));
    }
    Ok(url)
}

fn select_host(hosts: &[RegisteredHost], selector: &str) -> Result<RegisteredHost, HubClientError> {
    let exact: Vec<_> = hosts
        .iter()
        .filter(|host| host.name == selector || host.machine_id.as_str() == selector)
        .collect();
    match exact.as_slice() {
        [host] => return Ok((*host).clone()),
        [] => {}
        _ => return Err(HubClientError::Ambiguous),
    }
    let prefix: Vec<_> = hosts
        .iter()
        .filter(|host| host.machine_id.as_str().starts_with(selector))
        .collect();
    match prefix.as_slice() {
        [host] => Ok((*host).clone()),
        [] => Err(HubClientError::NotFound),
        _ => Err(HubClientError::Ambiguous),
    }
}

fn read_private_credential(path: &Path) -> Result<String, HubClientError> {
    let before = fs::symlink_metadata(path).map_err(|_| HubClientError::Credential)?;
    if !before.is_file() || before.file_type().is_symlink() || before.len() > MAX_CREDENTIAL_BYTES {
        return Err(HubClientError::Credential);
    }
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
    let file = options.open(path).map_err(|_| HubClientError::Credential)?;
    let metadata = file.metadata().map_err(|_| HubClientError::Credential)?;
    if !metadata.is_file() || metadata.len() > MAX_CREDENTIAL_BYTES {
        return Err(HubClientError::Credential);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // SAFETY: geteuid has no pointer arguments or memory-safety preconditions.
        let uid = unsafe { libc::geteuid() };
        if metadata.uid() != uid || metadata.mode() & 0o077 != 0 {
            return Err(HubClientError::Credential);
        }
    }
    #[cfg(windows)]
    crate::connect::validate_private_file(&file).map_err(|_| HubClientError::Credential)?;
    #[cfg(not(any(unix, windows)))]
    return Err(HubClientError::Credential);
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_CREDENTIAL_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| HubClientError::Credential)?;
    if bytes.is_empty() || bytes.len() as u64 > MAX_CREDENTIAL_BYTES {
        return Err(HubClientError::Credential);
    }
    String::from_utf8(bytes)
        .map(|value| value.trim().to_owned())
        .map_err(|_| HubClientError::Credential)
}

fn validate_pin(value: &str) -> Result<(), HubClientError> {
    let key: russh::keys::PublicKey = value
        .parse()
        .map_err(|_| HubClientError::Invalid("Hub supplied an invalid SSH host key".into()))?;
    if key.algorithm().to_string() != "ssh-ed25519" {
        return Err(HubClientError::Invalid(
            "Hub SSH host key must be Ed25519".into(),
        ));
    }
    Ok(())
}

/// Resolves one registry record and an already-selected approved route into the existing SSH type.
pub async fn host_spec_from(
    host: RegisteredHost,
    gateway: &GatewayEndpoint,
    config: &HubConfig,
) -> Result<HostSpec, HubClientError> {
    let address = resolve_gateway(gateway).await?;
    validate_pin(&host.ssh_host_public_key)?;
    validate_pin(&gateway.host_public_key)?;
    Ok(HostSpec {
        endpoint: SocketAddr::from(([127, 0, 0, 1], host.remote_port)),
        user: config.ssh_user.clone(),
        identity: config.identity.clone(),
        host_public_key: host.ssh_host_public_key,
        gateway: Some(GatewayHop {
            address,
            user: gateway.user.clone(),
            identity: config.gateway_identity.clone(),
            host_public_key: gateway.host_public_key.clone(),
            reverse_port: host.remote_port,
        }),
    })
}

async fn resolve_gateway(gateway: &GatewayEndpoint) -> Result<SocketAddr, HubClientError> {
    let mut addresses = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::net::lookup_host((gateway.host.as_str(), gateway.port)),
    )
    .await
    .map_err(|_| HubClientError::GatewayDns)?
    .map_err(|_| HubClientError::GatewayDns)?;
    let first = addresses.next().ok_or(HubClientError::GatewayDns)?;
    if addresses.next().is_some() {
        return Err(HubClientError::GatewayDns);
    }
    Ok(first)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, http::StatusCode, response::IntoResponse, routing::get};
    use hostlink_hub::{
        EnrollRequest, EnrollResponse, HubConfig as ServerConfig, HubService, MachineId, router,
    };
    use russh::keys::{Algorithm, PrivateKey};
    use secrecy::SecretString;
    use std::{collections::BTreeSet, net::SocketAddr};
    use tokio::task::JoinHandle;

    const OPERATOR_TOKEN: &str = "operator-token-for-hub-client-test-012345";
    const EDGE_TOKEN: &str = "gateway-token-for-hub-client-test-012345";

    fn host(id: &str, name: &str, display_name: Option<&str>) -> RegisteredHost {
        RegisteredHost {
            machine_id: MachineId::parse(id).expect("valid fixture ID"),
            name: name.into(),
            display_name: display_name.map(str::to_owned),
            hostname: "fixture-host".into(),
            os: "linux".into(),
            arch: "x86_64".into(),
            agent_version: "0.1.0".into(),
            ssh_public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeOperatorKey".into(),
            ssh_host_public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeHostKey".into(),
            remote_port: 23001,
            enrolled_at: 1,
            updated_at: 1,
        }
    }

    fn public_key() -> String {
        PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519)
            .expect("generate disposable Ed25519 key")
            .public_key()
            .to_openssh()
            .expect("encode Ed25519 public key")
    }

    fn local_client(base: &str, token: &str, timeout: Duration) -> HubClient {
        HubClient {
            base: Url::parse(base).expect("valid local fixture URL"),
            token: SecretString::from(token.to_owned()),
            client: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .no_proxy()
                .timeout(timeout)
                .build()
                .expect("build fixture HTTP client"),
        }
    }

    async fn serve(app: Router) -> (String, JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind disposable local Hub fixture");
        let address = listener.local_addr().expect("read fixture address");
        let task = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("serve disposable Hub fixture");
        });
        (format!("http://{address}"), task)
    }

    async fn hub_router(root: &Path) -> Router {
        let gateway_public_key = public_key();
        let operator_public_key = public_key();
        let gateway_dir = root.join("gateway");
        fs::create_dir_all(&gateway_dir).expect("create disposable gateway fixture dir");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&gateway_dir, fs::Permissions::from_mode(0o700))
                .expect("make gateway fixture dir private");
        }
        let service = HubService::new(ServerConfig {
            listen: SocketAddr::from(([127, 0, 0, 1], 1)),
            public_url: "https://hub.fixture".into(),
            state_root: root.join("hostlink-hub-v2"),
            authorized_keys: gateway_dir.join("hostlink-v2-authorized_keys"),
            gateways: vec![GatewayEndpoint {
                host: "127.0.0.1".into(),
                user: "gateway-user".into(),
                port: 22,
                host_public_key: gateway_public_key,
            }],
            operator_ssh_public_keys: vec![operator_public_key],
            operator_token: SecretString::from(OPERATOR_TOKEN),
            gateway_lookup_token: SecretString::from(EDGE_TOKEN),
            port_from: 41000,
            port_to: 41010,
            reserved_ports: BTreeSet::from([41000]),
        })
        .expect("build isolated Hub service");
        router(service)
    }

    #[test]
    fn selector_accepts_canonical_name_full_id_and_unique_id_prefix_only() {
        let hosts = vec![
            host("machine-001", "lab-win7", Some("Windows Lab")),
            host("machine-002", "lab-linux", Some("Linux Lab")),
        ];
        assert_eq!(select_host(&hosts, "lab-win7").unwrap().name, "lab-win7");
        assert_eq!(select_host(&hosts, "machine-001").unwrap().name, "lab-win7");
        assert_eq!(
            select_host(&hosts, "machine-00").unwrap_err().to_string(),
            HubClientError::Ambiguous.to_string()
        );
        assert!(matches!(
            select_host(&hosts, "Windows Lab"),
            Err(HubClientError::NotFound)
        ));
    }

    #[test]
    fn hub_url_requires_a_credential_free_https_origin() {
        assert!(parse_origin("https://hub.example").is_ok());
        for value in [
            "http://hub.example",
            "https://user:secret@hub.example",
            "https://hub.example/v2",
            "https://hub.example/?token=x",
        ] {
            assert!(parse_origin(value).is_err(), "accepted {value}");
        }
    }

    #[tokio::test]
    async fn manages_hosts_through_the_in_process_hub_v2_router() {
        let root = tempfile::tempdir().expect("temp Hub root");
        let app = hub_router(root.path()).await;
        let (base, server) = serve(app).await;
        let client = local_client(&base, OPERATOR_TOKEN, Duration::from_secs(3));

        let gateways = client.info().await.expect("authenticated Hub info");
        assert_eq!(gateways.len(), 1);
        assert!(
            client
                .list_hosts()
                .await
                .expect("empty inventory")
                .is_empty()
        );

        let invite = client
            .invite(Some("fixture-machine".into()), 900)
            .await
            .expect("create invitation through v2 API");
        let agent_key = public_key();
        let host_key = public_key();
        let enrolled: EnrollResponse = client
            .request_json(
                Method::POST,
                "/v2/enroll",
                Some(&EnrollRequest {
                    token: invite.token,
                    machine_id: MachineId::parse("machine-001").expect("machine ID"),
                    name: "fixture-machine".into(),
                    hostname: "fixture-host".into(),
                    os: "windows".into(),
                    arch: "x86_64".into(),
                    agent_version: "0.1.0".into(),
                    ssh_public_key: agent_key,
                    ssh_host_public_key: host_key.clone(),
                }),
            )
            .await
            .expect("enroll disposable host through v2 API");
        assert_eq!(enrolled.host.machine_id.as_str(), "machine-001");

        let selected = client
            .resolve_host("fixture-machine")
            .await
            .expect("resolve by canonical name");
        let spec = client
            .resolve_host_spec(
                "machine-001",
                &HubConfig {
                    hub_url: "https://hub.fixture".into(),
                    token_file: PathBuf::from("unused-in-fixture"),
                    ssh_user: "agent-user".into(),
                    identity: PathBuf::from("controller_ed25519"),
                    gateway_identity: PathBuf::from("gateway_ed25519"),
                },
            )
            .await
            .expect("resolve pinned HostSpec");
        assert_eq!(spec.user, "agent-user");
        assert_eq!(spec.host_public_key, host_key);
        assert_eq!(
            spec.gateway.as_ref().unwrap().reverse_port,
            selected.remote_port
        );

        let receipt = client.revoke(&selected).await.expect("revoke managed host");
        assert!(receipt.revoked_new_connections);
        assert!(!receipt.confirmed_session_terminated);
        assert!(!receipt.remote_uninstall);
        assert!(matches!(
            client.resolve_host("fixture-machine").await,
            Err(HubClientError::NotFound)
        ));
        server.abort();
    }

    #[tokio::test]
    async fn hub_http_errors_do_not_follow_redirects_or_expose_response_bodies() {
        let root = tempfile::tempdir().expect("temp Hub root");
        let app = hub_router(root.path()).await;
        let (base, server) = serve(app).await;
        let denied = local_client(&base, "wrong-token", Duration::from_secs(2));
        let error = denied
            .list_hosts()
            .await
            .expect_err("wrong bearer is rejected");
        assert!(matches!(error, HubClientError::Unauthorized));
        assert!(!error.to_string().contains("wrong-token"));
        server.abort();

        let redirect_app = Router::new().route(
            "/v2/hosts",
            get(|| async {
                (
                    StatusCode::TEMPORARY_REDIRECT,
                    [(
                        axum::http::header::LOCATION,
                        "https://elsewhere.invalid/v2/hosts",
                    )],
                )
                    .into_response()
            }),
        );
        let (base, server) = serve(redirect_app).await;
        let redirect = local_client(&base, OPERATOR_TOKEN, Duration::from_secs(2));
        assert!(matches!(
            redirect.list_hosts().await,
            Err(HubClientError::HttpStatus(StatusCode::TEMPORARY_REDIRECT))
        ));
        server.abort();

        for body in [
            "{".to_owned(),
            format!("{{\"hosts\":[]}}{}", " ".repeat(MAX_BODY_BYTES)),
        ] {
            let body = body.to_owned();
            let app = Router::new().route(
                "/v2/hosts",
                get(move || {
                    let body = body.clone();
                    async move { (StatusCode::OK, body) }
                }),
            );
            let (base, server) = serve(app).await;
            let malformed = local_client(&base, OPERATOR_TOKEN, Duration::from_secs(2));
            assert!(matches!(
                malformed.list_hosts().await,
                Err(HubClientError::Response)
            ));
            server.abort();
        }

        let slow_app = Router::new().route(
            "/v2/hosts",
            get(|| async {
                tokio::time::sleep(Duration::from_millis(100)).await;
                (StatusCode::OK, "{\"hosts\":[]}")
            }),
        );
        let (base, server) = serve(slow_app).await;
        let timed = local_client(&base, OPERATOR_TOKEN, Duration::from_millis(10));
        assert!(matches!(
            timed.list_hosts().await,
            Err(HubClientError::Request)
        ));
        server.abort();
    }
}
