//! Pinned russh connection, with optional authenticated gateway hop.

use std::{
    fs::{self, File, OpenOptions},
    io::Read,
    net::SocketAddr,
    path::Path,
    sync::Arc,
    time::Duration,
};

use russh::{
    client::{self, Handle},
    keys::{self, PrivateKeyWithHashAlg, PublicKey, PublicKeyBase64},
};
use thiserror::Error;

use crate::{GatewayHop, HostSpec};

pub(crate) const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
pub(crate) const OPERATION_TIMEOUT: Duration = Duration::from_secs(60);
pub(crate) const MAX_TRANSFER_BYTES: usize = 64 * 1024 * 1024;
const MAX_IDENTITY_BYTES: usize = 64 * 1024;

/// Errors returned by the pure Rust SSH client.
#[derive(Debug, Error)]
pub enum SshClientError {
    /// A target pin, user name, key, or command is invalid.
    #[error("invalid SSH configuration: {0}")]
    Invalid(String),
    /// SSH protocol or transport failed.
    #[error("SSH transport failed: {0}")]
    Russh(#[from] russh::Error),
    /// SSH key material could not be read or decoded.
    #[error("SSH key failed: {0}")]
    Key(#[from] russh::keys::Error),
    /// File or stream I/O failed.
    #[error("I/O failed: {0}")]
    Io(#[from] std::io::Error),
    /// SFTP operation failed.
    #[error("SFTP failed: {0}")]
    Sftp(#[from] russh_sftp::client::error::Error),
    /// An SSH operation exceeded its bounded deadline.
    #[error("SSH operation timed out")]
    Timeout,
    /// Remote data exceeded the configured byte bound.
    #[error("remote transfer exceeded {MAX_TRANSFER_BYTES} bytes")]
    TransferTooLarge,
    /// The server closed the command channel without an exit status.
    #[error("remote command closed without an exit status")]
    MissingExitStatus,
    /// The server closed an exec channel before all standard input was sent.
    #[error("remote command closed before all standard input was sent")]
    EarlyChannelClose,
    /// A russh session did not stop within its cleanup deadline.
    #[error("SSH session cleanup could not be confirmed")]
    CleanupUnconfirmed,
}

pub(crate) struct PinHandler {
    expected_key: PublicKey,
}

impl client::Handler for PinHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &keys::PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        let russh::keys::PublicKeyOrCertificate::PublicKey { key, .. } = server_public_key else {
            return Ok(false);
        };
        Ok(key.public_key_bytes() == self.expected_key.public_key_bytes())
    }
}

/// An authenticated SSH connection to the selected host.
///
/// In gateway mode this value retains both session handles. Call
/// [`HostConnection::close`] to await bounded russh session cleanup.
pub struct HostConnection {
    pub(crate) session: Handle<PinHandler>,
    pub(crate) _gateway_session: Option<Handle<PinHandler>>,
}

impl HostConnection {
    #[cfg(test)]
    pub(crate) fn from_authenticated_session(session: Handle<PinHandler>) -> Self {
        Self {
            session,
            _gateway_session: None,
        }
    }

    /// Connects to a pinned host, optionally through an approved gateway.
    ///
    /// # Errors
    /// Returns an error for missing or malformed pins, invalid users, failed
    /// public-key authentication, rejected gateway forwarding, or timeout.
    pub async fn connect(spec: &HostSpec) -> Result<Self, SshClientError> {
        validate_user(&spec.user)?;
        let host_key = parse_pin(&spec.host_public_key)?;
        let identity = load_identity(&spec.identity)?;

        if let Some(gateway) = &spec.gateway {
            let routes = validate_gateway_routes(gateway)?;
            let mut connected = None;
            for (index, (address, user, identity, key)) in routes.into_iter().enumerate() {
                match connect_authenticated(address, &user, identity, key).await {
                    Ok(session) => {
                        connected = Some(session);
                        break;
                    }
                    Err(error)
                        if index + 1 < 1 + gateway.alternates.len()
                            && is_transient_gateway_connect_error(&error) => {}
                    Err(error) => return Err(error),
                }
            }
            let gateway_session = connected.ok_or_else(|| {
                SshClientError::Invalid("no approved gateway route connected".into())
            })?;

            // The gateway's configured reverse listener is explicitly loopback-only.
            let channel = match tokio::time::timeout(
                CONNECT_TIMEOUT,
                gateway_session.channel_open_direct_tcpip(
                    "127.0.0.1",
                    u32::from(gateway.reverse_port),
                    "127.0.0.1",
                    0,
                ),
            )
            .await
            {
                Ok(Ok(channel)) => channel,
                Ok(Err(error)) => {
                    close_session(gateway_session, "gateway forwarding rejected").await?;
                    return Err(error.into());
                }
                Err(_) => {
                    close_session(gateway_session, "gateway forwarding timed out").await?;
                    return Err(SshClientError::Timeout);
                }
            };

            let target_session = match connect_stream_authenticated(
                channel.into_stream(),
                &spec.user,
                identity,
                host_key,
            )
            .await
            {
                Ok(session) => session,
                Err(error) => {
                    close_session(gateway_session, "target connection failed").await?;
                    return Err(error);
                }
            };

            Ok(Self {
                session: target_session,
                _gateway_session: Some(gateway_session),
            })
        } else {
            let session =
                connect_authenticated(spec.endpoint, &spec.user, identity, host_key).await?;
            Ok(Self {
                session,
                _gateway_session: None,
            })
        }
    }

    /// Closes the target session and then its gateway session within a fixed deadline.
    ///
    /// # Errors
    /// Returns an error when russh cannot confirm that a session task stopped.
    pub async fn close(self) -> Result<(), SshClientError> {
        let target_result = close_session(self.session, "controller connection closed").await;
        let gateway_result = match self._gateway_session {
            Some(session) => close_session(session, "gateway connection closed").await,
            None => Ok(()),
        };
        target_result.and(gateway_result)
    }
}

async fn connect_authenticated(
    address: SocketAddr,
    user: &str,
    identity: russh::keys::PrivateKey,
    expected_key: PublicKey,
) -> Result<Handle<PinHandler>, SshClientError> {
    let config = Arc::new(client::Config::default());
    let deadline = tokio::time::Instant::now() + CONNECT_TIMEOUT;
    let mut session = tokio::time::timeout_at(
        deadline,
        client::connect(config, address, PinHandler { expected_key }),
    )
    .await
    .map_err(|_| SshClientError::Timeout)??;
    authenticate_with_cleanup(&mut session, user, identity, deadline).await?;
    Ok(session)
}

pub(crate) async fn connect_stream_authenticated<S>(
    stream: S,
    user: &str,
    identity: russh::keys::PrivateKey,
    expected_key: PublicKey,
) -> Result<Handle<PinHandler>, SshClientError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let config = Arc::new(client::Config::default());
    let deadline = tokio::time::Instant::now() + CONNECT_TIMEOUT;
    let mut session = tokio::time::timeout_at(
        deadline,
        client::connect_stream(config, stream, PinHandler { expected_key }),
    )
    .await
    .map_err(|_| SshClientError::Timeout)??;
    authenticate_with_cleanup(&mut session, user, identity, deadline).await?;
    Ok(session)
}

async fn authenticate_with_cleanup(
    session: &mut Handle<PinHandler>,
    user: &str,
    identity: russh::keys::PrivateKey,
    deadline: tokio::time::Instant,
) -> Result<(), SshClientError> {
    let result = tokio::time::timeout_at(deadline, authenticate(session, user, identity)).await;
    match result {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => {
            close_session_from_ref(session, "SSH authentication failed").await?;
            Err(error)
        }
        Err(_) => {
            close_session_from_ref(session, "SSH authentication timed out").await?;
            Err(SshClientError::Timeout)
        }
    }
}

async fn close_session(
    mut session: Handle<PinHandler>,
    description: &str,
) -> Result<(), SshClientError> {
    close_session_from_ref(&mut session, description).await
}

async fn close_session_from_ref(
    session: &mut Handle<PinHandler>,
    description: &str,
) -> Result<(), SshClientError> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let _ = tokio::time::timeout_at(
        deadline,
        session.disconnect(russh::Disconnect::ByApplication, description, "en"),
    )
    .await;
    if tokio::time::timeout_at(deadline, session).await.is_err() {
        return Err(SshClientError::CleanupUnconfirmed);
    }
    Ok(())
}

async fn authenticate(
    session: &mut Handle<PinHandler>,
    user: &str,
    identity: russh::keys::PrivateKey,
) -> Result<(), SshClientError> {
    let result = session
        .authenticate_publickey(
            user.to_owned(),
            PrivateKeyWithHashAlg::new(Arc::new(identity), None),
        )
        .await?;
    if !result.success() {
        return Err(SshClientError::Invalid(
            "public-key authentication rejected".into(),
        ));
    }
    Ok(())
}

fn load_identity(path: &Path) -> Result<russh::keys::PrivateKey, SshClientError> {
    if path.as_os_str().is_empty() {
        return Err(SshClientError::Invalid("identity path is empty".into()));
    }
    let mut file = open_identity(path)?;
    validate_identity_file(&file)?;
    let mut contents = Vec::new();
    file.by_ref()
        .take((MAX_IDENTITY_BYTES + 1) as u64)
        .read_to_end(&mut contents)?;
    if contents.len() > MAX_IDENTITY_BYTES {
        return Err(SshClientError::Invalid(format!(
            "SSH identity exceeds {MAX_IDENTITY_BYTES} bytes"
        )));
    }
    let contents = std::str::from_utf8(&contents)
        .map_err(|_| SshClientError::Invalid("SSH identity is not UTF-8 OpenSSH text".into()))?;
    let identity = keys::decode_secret_key(contents, None)?;
    if identity.public_key().algorithm().to_string() != "ssh-ed25519" {
        return Err(SshClientError::Invalid(
            "controller identity must be an Ed25519 private key".into(),
        ));
    }
    Ok(identity)
}

fn open_identity(path: &Path) -> Result<File, SshClientError> {
    let before = fs::symlink_metadata(path)?;
    if before.file_type().is_symlink() || !before.is_file() {
        return Err(SshClientError::Invalid(
            "SSH identity must be a regular non-link file".into(),
        ));
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
        // FILE_FLAG_OPEN_REPARSE_POINT opens a reparse point itself instead of following it.
        options.custom_flags(0x0020_0000);
    }
    #[cfg(not(any(unix, windows)))]
    {
        return Err(SshClientError::Invalid(
            "identity path safety is unsupported on this platform".into(),
        ));
    }

    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(SshClientError::Invalid(
            "SSH identity must be a regular non-reparse file".into(),
        ));
    }
    Ok(file)
}

pub(crate) fn validate_private_file(file: &File) -> Result<(), SshClientError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = file.metadata()?;
        // SAFETY: geteuid has no pointer arguments or memory-safety preconditions.
        let effective_uid = unsafe { libc::geteuid() };
        let mode = metadata.mode() & 0o777;
        if metadata.uid() != effective_uid || mode & 0o077 != 0 {
            return Err(SshClientError::Invalid(format!(
                "SSH identity must be owned by the current user and owner-only (mode {mode:03o})"
            )));
        }
    }
    #[cfg(windows)]
    validate_windows_identity_acl(file)?;
    #[cfg(not(any(unix, windows)))]
    {
        let _ = file;
        return Err(SshClientError::Invalid(
            "identity permission validation is unsupported on this platform".into(),
        ));
    }
    Ok(())
}

fn validate_identity_file(file: &File) -> Result<(), SshClientError> {
    validate_private_file(file)
}

#[cfg(windows)]
fn validate_windows_identity_acl(file: &File) -> Result<(), SshClientError> {
    use windows_permissions::constants::{AceType, SeObjectType, SecurityInformation};
    use windows_permissions::wrappers::{
        ConvertSecurityDescriptorToStringSecurityDescriptor, GetSecurityInfo,
    };
    use windows_permissions::{LocalBox, Sid};

    // Owner is not included when only DACL is requested from Windows.
    let descriptor = GetSecurityInfo(
        file,
        SeObjectType::SE_FILE_OBJECT,
        SecurityInformation::Dacl | SecurityInformation::Owner,
    )?;
    let current = windows_permissions::utilities::current_process_sid()?;
    if descriptor.owner() != Some(current.as_ref()) {
        return Err(SshClientError::Invalid(
            "SSH identity must be owned by the current Windows user".into(),
        ));
    }
    let sddl = ConvertSecurityDescriptorToStringSecurityDescriptor(
        &descriptor,
        SecurityInformation::Dacl,
    )?;
    if !sddl.to_string_lossy().starts_with("D:P") {
        return Err(SshClientError::Invalid(
            "SSH identity Windows ACL must be protected from inheritance".into(),
        ));
    }
    let dacl = descriptor.dacl().ok_or_else(|| {
        SshClientError::Invalid("SSH identity has no verifiable Windows DACL".into())
    })?;
    let system: LocalBox<Sid> = "S-1-5-18"
        .parse()
        .map_err(|error: std::io::Error| SshClientError::Io(error))?;
    let administrators: LocalBox<Sid> = "S-1-5-32-544"
        .parse()
        .map_err(|error: std::io::Error| SshClientError::Io(error))?;
    for index in 0..dacl.len() {
        let ace = dacl.get_ace(index).ok_or_else(|| {
            SshClientError::Invalid("SSH identity has an unreadable Windows ACL entry".into())
        })?;
        let is_allow = matches!(
            ace.ace_type(),
            AceType::ACCESS_ALLOWED_ACE_TYPE
                | AceType::ACCESS_ALLOWED_CALLBACK_ACE_TYPE
                | AceType::ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE
                | AceType::ACCESS_ALLOWED_OBJECT_ACE_TYPE
        );
        if !is_allow {
            continue;
        }
        let sid = ace.sid().ok_or_else(|| {
            SshClientError::Invalid("SSH identity has an unverifiable allow ACL entry".into())
        })?;
        if sid != current.as_ref() && sid != system.as_ref() && sid != administrators.as_ref() {
            return Err(SshClientError::Invalid(
                "SSH identity ACL grants access to an unexpected Windows principal".into(),
            ));
        }
    }
    Ok(())
}

fn parse_pin(pin: &str) -> Result<PublicKey, SshClientError> {
    let fields: Vec<_> = pin.split_whitespace().collect();
    if !(2..=3).contains(&fields.len())
        || !fields[0].starts_with("ssh-") && !fields[0].starts_with("ecdsa-")
    {
        return Err(SshClientError::Invalid(
            "host pin must be one OpenSSH public-key line".into(),
        ));
    }
    let key = keys::parse_public_key_base64(fields[1])?;
    if key.algorithm().to_string() != fields[0] {
        return Err(SshClientError::Invalid(
            "host pin algorithm does not match its key blob".into(),
        ));
    }
    Ok(key)
}

pub(crate) fn validate_user(user: &str) -> Result<(), SshClientError> {
    if user.is_empty()
        || user.len() > 64
        || !user
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
    {
        return Err(SshClientError::Invalid("SSH user name is invalid".into()));
    }
    Ok(())
}

fn validate_gateway(gateway: &GatewayHop) -> Result<(), SshClientError> {
    validate_user(&gateway.user)?;
    if gateway.reverse_port == 0 {
        return Err(SshClientError::Invalid(
            "gateway reverse port must be nonzero".into(),
        ));
    }
    Ok(())
}

fn validate_gateway_routes(
    primary: &GatewayHop,
) -> Result<Vec<(SocketAddr, String, russh::keys::PrivateKey, PublicKey)>, SshClientError> {
    if primary.alternates.len() > 15 {
        return Err(SshClientError::Invalid(
            "at most 16 approved gateway routes are allowed".into(),
        ));
    }
    let mut routes = Vec::with_capacity(primary.alternates.len() + 1);
    let mut identities = std::collections::BTreeSet::new();
    let mut pins = std::collections::BTreeSet::new();
    let mut append =
        |address: SocketAddr, user: &str, identity_path: &std::path::Path, pin: &str| {
            validate_user(user)?;
            if !identities.insert((address, user.to_owned())) || !pins.insert(pin.to_owned()) {
                return Err(SshClientError::Invalid(
                    "duplicate approved gateway route or host pin".into(),
                ));
            }
            let key = parse_pin(pin)?;
            let identity = load_identity(identity_path)?;
            if key.algorithm().to_string() != "ssh-ed25519" {
                return Err(SshClientError::Invalid(
                    "gateway pin must be Ed25519".into(),
                ));
            }
            routes.push((address, user.to_owned(), identity, key));
            Ok(())
        };
    validate_gateway(primary)?;
    append(
        primary.address,
        &primary.user,
        &primary.identity,
        &primary.host_public_key,
    )?;
    for alternate in &primary.alternates {
        append(
            alternate.address,
            &alternate.user,
            &alternate.identity,
            &alternate.host_public_key,
        )?;
    }
    Ok(routes)
}

fn is_transient_gateway_connect_error(error: &SshClientError) -> bool {
    match error {
        SshClientError::Timeout => true,
        SshClientError::Io(error) => matches!(
            error.kind(),
            std::io::ErrorKind::ConnectionRefused
                | std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::ConnectionAborted
                | std::io::ErrorKind::TimedOut
                | std::io::ErrorKind::BrokenPipe
                | std::io::ErrorKind::UnexpectedEof
        ),
        SshClientError::Russh(
            russh::Error::ConnectionTimeout | russh::Error::HUP | russh::Error::Disconnect,
        ) => true,
        SshClientError::Russh(russh::Error::IO(error)) => matches!(
            error.kind(),
            std::io::ErrorKind::ConnectionRefused
                | std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::ConnectionAborted
                | std::io::ErrorKind::TimedOut
                | std::io::ErrorKind::BrokenPipe
                | std::io::ErrorKind::UnexpectedEof
        ),
        _ => false,
    }
}

#[cfg(test)]
mod tests;
