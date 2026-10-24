//! Strict gateway and target SSH identity validation.

use crate::{AppResult, invalid_config, not_found_error};
use anyhow::{Context, bail};
use russh::client;
use russh::keys::ssh_key::PublicKey;
use russh::keys::{PrivateKeyWithHashAlg, PublicKeyOrCertificate};
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub(super) struct StrictKnownHost {
    pub(super) host: String,
    pub(super) port: u16,
    pub(super) trust: StrictTrust,
}

pub(super) enum StrictTrust {
    KnownHosts(PathBuf),
    Pinned(PublicKey),
}

impl client::Handler for StrictKnownHost {
    type Error = anyhow::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        if server_public_key.certificate().is_some() {
            return Ok(false);
        }
        let public_key = server_public_key.public_key();
        Ok(match &self.trust {
            StrictTrust::KnownHosts(path) => {
                russh::keys::check_known_hosts_path(&self.host, self.port, &public_key, path)?
            }
            StrictTrust::Pinned(expected) => &public_key == expected,
        })
    }
}
pub(super) async fn authenticate(
    session: &mut client::Handle<StrictKnownHost>,
    user: &str,
    private_key: Arc<russh::keys::PrivateKey>,
    endpoint: String,
) -> anyhow::Result<()> {
    let auth = session
        .authenticate_publickey(
            user.to_owned(),
            PrivateKeyWithHashAlg::new(private_key, None),
        )
        .await
        .with_context(|| format!("authenticating {user} on {endpoint}"))?;
    if !auth.success() {
        bail!("public-key authentication rejected for {user} on {endpoint}");
    }
    Ok(())
}

pub(super) fn required_file(path: Option<&Path>, purpose: &str) -> AppResult<PathBuf> {
    let path = path.ok_or_else(|| {
        invalid_config(format!(
            "embedded {purpose} is required; refresh managed SSH projection/configuration"
        ))
    })?;
    if !path.is_file() {
        return Err(not_found_error(format!("{purpose}: {}", path.display())));
    }
    Ok(path.to_path_buf())
}

pub(super) fn required_text<'a>(value: Option<&'a str>, purpose: &str) -> AppResult<&'a str> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid_config(format!("embedded {purpose} is required")))
}
