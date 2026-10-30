use std::{io, path::PathBuf};

pub(super) fn execute(root: PathBuf) -> io::Result<()> {
    let status = hostlink_agent::service::status(&root)?;
    println!("installed={} active={}", status.installed, status.active);
    if !status.installed || !status.active {
        return Err(io::Error::other("Agent user service is not running"));
    }
    Ok(())
}
