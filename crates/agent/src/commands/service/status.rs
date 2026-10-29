use std::{io, path::PathBuf};

pub(super) fn execute(root: PathBuf) -> io::Result<()> {
    let status = hostlink_agent::service::status(&root)?;
    println!("{}", status.detail);
    println!(
        "installed={} active={} owner_uid={} owner_sid={} pid={} executable_sha256={} ssh_banner={} local_enrollment_metadata={} hub_reachability=not_checked",
        status.installed,
        status.active,
        status
            .owner_uid
            .map_or_else(|| "-".into(), |uid| uid.to_string()),
        status.owner_sid.as_deref().unwrap_or("-"),
        status.pid.map_or_else(|| "-".into(), |p| p.to_string()),
        status.executable_sha256.as_deref().unwrap_or("-"),
        status.ssh_banner,
        status.local_enrollment
    );
    if !status.installed || !status.active || !status.ssh_banner {
        return Err(io::Error::other("Agent service is not healthy"));
    }
    Ok(())
}
