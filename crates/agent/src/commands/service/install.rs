use std::{io, path::PathBuf};

pub(super) fn execute(root: PathBuf, config: PathBuf) -> io::Result<()> {
    hostlink_agent::service::install(&root, &config)
}
