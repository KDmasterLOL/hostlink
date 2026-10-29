use crate::{
    server::{App, CommitAdmission, HubError, ensure_unique_name, validate_name},
    state::{AuditEntry, InviteRecord, allocate_port},
    *,
};
use secrecy::ExposeSecret;
use sha2::{Digest, Sha256};

pub(crate) fn create_invite(
    app: &App,
    request: InviteRequest,
    admission: CommitAdmission,
) -> Result<InviteResponse, HubError> {
    if !(30..=86400).contains(&request.ttl_seconds) {
        return Err(HubError::bad(
            "invite TTL must be between 30 and 86400 seconds",
        ));
    }
    let name = request.name.map(|n| validate_name(&n)).transpose()?;
    let mut locked = app
        .store
        .lock()
        .map_err(|_| HubError::internal("Hub state unavailable"))?;
    if let Some(id) = &request.rotate_machine_id
        && !locked.state.hosts.contains_key(id)
    {
        return Err(HubError::NotFound);
    }
    if let Some(name) = name.as_deref() {
        ensure_unique_name(
            &locked.state.hosts,
            name,
            request.rotate_machine_id.as_ref(),
        )?;
    }
    let mut raw = [0u8; 32];
    getrandom::fill(&mut raw)
        .map_err(|_| HubError::internal("secure random source unavailable"))?;
    let token = hex::encode(raw);
    let digest = hex::encode(Sha256::digest(token.as_bytes()));
    let expires_at = super::server::now() + request.ttl_seconds as i64;
    locked
        .state
        .invites
        .retain(|_, invite| !invite.used && invite.expires_at > super::server::now());
    if locked.state.invites.len() >= 10_000 {
        return Err(HubError::Unavailable("invite capacity reached".into()));
    }
    locked.state.invites.insert(
        digest.clone(),
        InviteRecord {
            digest,
            expires_at,
            used: false,
            name,
            rotate_machine_id: request.rotate_machine_id,
        },
    );
    locked.state.audit.push(AuditEntry {
        at: super::server::now(),
        action: "invite_created".into(),
        machine_id: None,
    });
    admission.commit(locked)?;
    Ok(InviteResponse {
        token: secrecy::SecretString::from(token),
        expires_at,
    })
}

pub(crate) fn enroll(
    app: &App,
    request: EnrollRequest,
    admission: CommitAdmission,
) -> Result<EnrollResponse, HubError> {
    let id = request.machine_id.clone();
    let name = validate_name(&request.name)?;
    for (field, value) in [
        ("hostname", &request.hostname),
        ("os", &request.os),
        ("arch", &request.arch),
        ("agent_version", &request.agent_version),
    ] {
        if value.is_empty() || value.len() > 128 || value.chars().any(char::is_control) {
            return Err(HubError::bad(format!("invalid {field}")));
        }
    }
    let reverse_key =
        canonical_ed25519_public_key(&request.ssh_public_key).map_err(HubError::bad)?;
    let host_key =
        canonical_ed25519_public_key(&request.ssh_host_public_key).map_err(HubError::bad)?;
    if reverse_key == host_key {
        return Err(HubError::bad(
            "reverse identity and SSH host key must be distinct",
        ));
    }
    let token = request.token.expose_secret();
    if token.len() != 64
        || !token
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(HubError::Unauthorized);
    }
    let digest = hex::encode(Sha256::digest(token.as_bytes()));
    let mut locked = app
        .store
        .lock()
        .map_err(|_| HubError::internal("Hub state unavailable"))?;
    let invite = locked
        .state
        .invites
        .get(&digest)
        .cloned()
        .ok_or(HubError::Unauthorized)?;
    if invite.used || invite.expires_at <= super::server::now() {
        return Err(HubError::Unauthorized);
    }
    let existing = locked.state.hosts.contains_key(&id);
    if invite.rotate_machine_id.as_ref() != if existing { Some(&id) } else { None } {
        return Err(HubError::Conflict(
            "invite does not authorize this identity".into(),
        ));
    }
    if invite
        .name
        .as_ref()
        .is_some_and(|n| !n.eq_ignore_ascii_case(&name))
    {
        return Err(HubError::Conflict(
            "enrollment name does not match invite".into(),
        ));
    }
    ensure_unique_name(&locked.state.hosts, &name, Some(&id))?;
    if locked.state.hosts.values().any(|h| {
        h.machine_id != id
            && (h.ssh_public_key == reverse_key
                || h.ssh_host_public_key == host_key
                || h.ssh_public_key == host_key
                || h.ssh_host_public_key == reverse_key)
    }) {
        return Err(HubError::Conflict("SSH key is already registered".into()));
    }
    let old = locked.state.hosts.get(&id).cloned();
    let port = match old {
        Some(ref host) => host.remote_port,
        None => allocate_port(
            &locked.state,
            app.config.port_from,
            app.config.port_to,
            &app.config.reserved_ports,
            &id,
        )
        .ok_or_else(|| HubError::Unavailable("no unique reverse port is available".into()))?,
    };
    let at = super::server::now();
    let host = RegisteredHost {
        machine_id: id.clone(),
        name,
        display_name: old.as_ref().and_then(|h| h.display_name.clone()),
        hostname: request.hostname,
        os: request.os,
        arch: request.arch,
        agent_version: request.agent_version,
        ssh_public_key: reverse_key,
        ssh_host_public_key: host_key,
        remote_port: port,
        enrolled_at: old.as_ref().map_or(at, |h| h.enrolled_at),
        updated_at: at,
    };
    locked.state.hosts.insert(id.clone(), host.clone());
    locked
        .state
        .invites
        .get_mut(&digest)
        .expect("validated invite")
        .used = true;
    locked.state.audit.push(AuditEntry {
        at,
        action: if invite.rotate_machine_id.is_some() {
            "key_rotated"
        } else {
            "enrolled"
        }
        .into(),
        machine_id: Some(id),
    });
    admission.commit(locked)?;
    if super::ssh_authorization::reconcile(app).is_err() {
        return Err(HubError::Unavailable(
            "enrollment committed; gateway authorization projection needs reconciliation".into(),
        ));
    }
    Ok(EnrollResponse {
        host,
        gateways: app.config.gateways.clone(),
        operator_ssh_public_keys: app.config.operator_ssh_public_keys.clone(),
    })
}
