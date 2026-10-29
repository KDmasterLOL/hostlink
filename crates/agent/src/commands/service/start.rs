use std::{io, path::PathBuf};

pub(super) fn execute(root: PathBuf) -> io::Result<()> {
    hostlink_agent::service::start(&root)
}
