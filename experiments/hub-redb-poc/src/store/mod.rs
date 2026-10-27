mod json;
mod redb_store;
#[cfg(test)]
mod tests;

use serde::{Deserialize, Serialize};
#[cfg(test)]
use std::path::Path;
use std::{collections::BTreeMap, io};

pub use json::JsonStore;
pub use redb_store::RedbStore;

const SCHEMA_VERSION: u32 = 2;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub version: u32,
    pub hosts: BTreeMap<String, Host>,
    pub invites: BTreeMap<String, Invite>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Host {
    pub name: String,
    pub port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Invite {
    pub expires_at: i64,
    pub used: bool,
    pub machine_id: Option<String>,
}

impl Snapshot {
    pub fn empty() -> Self {
        Self {
            version: SCHEMA_VERSION,
            hosts: BTreeMap::new(),
            invites: BTreeMap::new(),
        }
    }

    pub fn validate(&self) -> io::Result<()> {
        if self.version != SCHEMA_VERSION {
            return Err(invalid("unsupported schema version"));
        }
        let mut names = std::collections::BTreeSet::new();
        let mut ports = std::collections::BTreeSet::new();
        for (id, host) in &self.hosts {
            if id.is_empty()
                || host.name.is_empty()
                || host.port == 0
                || !names.insert(host.name.to_ascii_lowercase())
                || !ports.insert(host.port)
            {
                return Err(invalid("duplicate or invalid host identity"));
            }
        }
        for (digest, invite) in &self.invites {
            if digest.len() != 64
                || !digest
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
                || invite
                    .machine_id
                    .as_ref()
                    .is_some_and(|id| !self.hosts.contains_key(id))
            {
                return Err(invalid("invalid invite digest or host reference"));
            }
        }
        Ok(())
    }
}

pub trait HubStore {
    fn snapshot(&self) -> io::Result<Snapshot>;
    fn register_host(&self, id: &str, name: &str, port: u16) -> io::Result<()>;
    fn create_invite(&self, digest: &str, expires_at: i64) -> io::Result<()>;
    fn redeem_invite(&self, digest: &str, machine_id: &str, now: i64) -> io::Result<()>;
}

pub(super) fn apply_host(state: &mut Snapshot, id: &str, name: &str, port: u16) -> io::Result<()> {
    if id.is_empty()
        || name.is_empty()
        || port == 0
        || state.hosts.contains_key(id)
        || state
            .hosts
            .values()
            .any(|host| host.name.eq_ignore_ascii_case(name) || host.port == port)
    {
        return Err(invalid("host identity, name, or port conflicts"));
    }
    state.hosts.insert(
        id.to_owned(),
        Host {
            name: name.to_owned(),
            port,
        },
    );
    Ok(())
}

pub(super) fn apply_invite(state: &mut Snapshot, digest: &str, expires_at: i64) -> io::Result<()> {
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        || state.invites.contains_key(digest)
    {
        return Err(invalid("invalid or duplicate invite digest"));
    }
    state.invites.insert(
        digest.to_owned(),
        Invite {
            expires_at,
            used: false,
            machine_id: None,
        },
    );
    Ok(())
}

pub(super) fn apply_redeem(
    state: &mut Snapshot,
    digest: &str,
    machine_id: &str,
    now: i64,
) -> io::Result<()> {
    if !state.hosts.contains_key(machine_id) {
        return Err(invalid("unknown host identity"));
    }
    let invite = state
        .invites
        .get_mut(digest)
        .ok_or_else(|| invalid("invite not found"))?;
    if invite.used || invite.expires_at <= now {
        return Err(invalid("invite already used or expired"));
    }
    invite.used = true;
    invite.machine_id = Some(machine_id.to_owned());
    Ok(())
}

pub(super) fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
pub(super) fn read_json(path: &Path) -> io::Result<Snapshot> {
    let bytes = std::fs::read(path)?;
    let state: Snapshot =
        serde_json::from_slice(&bytes).map_err(|_| invalid("Hub JSON is malformed"))?;
    state.validate()?;
    Ok(state)
}
