use crate::server::{App, HubError};
use axum::{Json, extract::State as AxumState, http::HeaderMap};
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use ssh_key::authorized_keys::Entry;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LookupRequest {
    pub key_type: String,
    pub key_blob: String,
}
#[derive(Serialize)]
pub(crate) struct LookupResponse {
    pub authorized: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorized_key: Option<String>,
}

pub(crate) async fn lookup(
    AxumState(app): AxumState<App>,
    headers: HeaderMap,
    Json(request): Json<LookupRequest>,
) -> Result<Json<LookupResponse>, HubError> {
    if !crate::server::authorized(&headers, app.config.gateway_lookup_token.expose_secret()) {
        return Err(HubError::Unauthorized);
    }
    let host = tokio::task::spawn_blocking(move || {
        let key = format!("{} {}", request.key_type, request.key_blob);
        let key: ssh_key::PublicKey = key
            .parse()
            .map_err(|_| HubError::bad("invalid public key"))?;
        if key.algorithm() != ssh_key::Algorithm::Ed25519 {
            return Err(HubError::bad("gateway key must be Ed25519"));
        }
        let locked = app
            .store
            .lock()
            .map_err(|_| HubError::internal("Hub state unavailable"))?;
        let host = locked
            .state
            .hosts
            .values()
            .find(|h| {
                h.ssh_public_key
                    .parse::<ssh_key::PublicKey>()
                    .is_ok_and(|registered| {
                        registered.fingerprint(ssh_key::HashAlg::Sha256)
                            == key.fingerprint(ssh_key::HashAlg::Sha256)
                    })
            })
            .cloned();
        Ok::<_, HubError>(host)
    })
    .await
    .map_err(|_| HubError::internal("Hub state lookup failed"))??;
    match host {
        Some(host) => Ok(Json(LookupResponse {
            authorized: true,
            authorized_key: Some(render_key(&host)?),
        })),
        None => Ok(Json(LookupResponse {
            authorized: false,
            authorized_key: None,
        })),
    }
}
fn render_key(host: &crate::RegisteredHost) -> Result<String, HubError> {
    Ok(format!(
        "command=\"/bin/false\",no-agent-forwarding,no-X11-forwarding,no-pty,no-user-rc,permitopen=\"127.0.0.1:9\",permitlisten=\"127.0.0.1:{}\" {} hostlink-agent:{}",
        host.remote_port, host.ssh_public_key, host.machine_id
    ))
}

pub(crate) fn reconcile(app: &App) -> std::io::Result<()> {
    use std::{
        fs::{self, OpenOptions},
        io::{Read, Write},
        path::Path,
    };
    let locked = app.store.lock()?;
    let path = &app.config.authorized_keys;
    let parent = path.parent().unwrap_or(Path::new("."));
    for component in parent.ancestors().filter(|p| !p.as_os_str().is_empty()) {
        if let Ok(metadata) = fs::symlink_metadata(component)
            && metadata.file_type().is_symlink()
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "authorized_keys path must not traverse symlinks",
            ));
        }
    }
    if !parent.exists() {
        fs::create_dir_all(parent)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
        }
    }
    let parent_meta = fs::symlink_metadata(parent)?;
    if !parent_meta.is_dir() || parent_meta.file_type().is_symlink() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "authorized_keys parent must be a real directory",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if parent_meta.permissions().mode() & 0o077 != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "authorized_keys parent permissions must be private",
            ));
        }
    }
    let existing = match fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(e),
        Ok(m) if !m.is_file() || m.file_type().is_symlink() || m.len() > 4 * 1024 * 1024 => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "unsafe authorized_keys file",
            ));
        }
        #[cfg(unix)]
        Ok(m)
            if {
                use std::os::unix::fs::PermissionsExt;
                m.permissions().mode() & 0o077 != 0
            } =>
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "authorized_keys permissions must be private",
            ));
        }
        Ok(_) => {
            let mut v = Vec::new();
            OpenOptions::new()
                .read(true)
                .open(path)?
                .take(4 * 1024 * 1024 + 1)
                .read_to_end(&mut v)?;
            v
        }
    };
    let mut output = Vec::new();
    for line in existing.split_inclusive(|b| *b == b'\n') {
        let logical = line.strip_suffix(b"\n").unwrap_or(line);
        let raw = logical.strip_suffix(b"\r").unwrap_or(logical);
        let managed = std::str::from_utf8(raw)
            .ok()
            .and_then(|s| s.parse::<Entry>().ok())
            .and_then(|e| e.public_key().comment().as_str().ok().map(str::to_owned))
            .is_some_and(|c| c.starts_with("hostlink-agent:"));
        if !managed {
            output.extend_from_slice(line);
        }
    }
    for host in locked.state.hosts.values() {
        if !output.is_empty() && !output.ends_with(b"\n") {
            output.push(b'\n');
        }
        output.extend_from_slice(
            render_key(host)
                .map_err(|e| std::io::Error::other(format!("{e:?}")))?
                .as_bytes(),
        );
        output.push(b'\n');
    }
    if output.len() > 4 * 1024 * 1024 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "authorized_keys projection exceeds limit",
        ));
    }
    let mut nonce = [0u8; 8];
    getrandom::fill(&mut nonce).map_err(std::io::Error::other)?;
    let temp = parent.join(format!(".hostlink-authorized-{}.tmp", hex::encode(nonce)));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temp)?;
    let result = (|| {
        file.write_all(&output)?;
        file.sync_all()?;
        fs::rename(&temp, path)?;
        #[cfg(unix)]
        OpenOptions::new().read(true).open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}
