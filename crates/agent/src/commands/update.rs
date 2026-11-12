use clap::Args as ClapArgs;
use hostlink_agent::installation::InstallationRoot;
#[cfg(not(windows))]
use hostlink_agent::update::update;
use std::io;

#[derive(ClapArgs)]
pub(crate) struct Args {
    /// Exact release version (allows downgrade); defaults to latest stable on GitHub.
    #[arg(long)]
    version: Option<semver::Version>,
    #[cfg(windows)]
    #[arg(long, hide = true)]
    supervisor: Option<uuid::Uuid>,
}

pub(crate) fn execute(args: Args) -> io::Result<()> {
    let root = InstallationRoot::open(None)?;
    #[cfg(windows)]
    if let Some(operation) = args.supervisor {
        return hostlink_agent::update::run_managed_update(&root, operation, args.version.as_ref());
    }
    #[cfg(windows)]
    {
        hostlink_agent::update::start_managed_update(&root, args.version.as_ref())?;
        println!("Agent update started; reconnect to verify the version");
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let updated = update(&root, args.version.as_ref())?;
        if updated {
            println!("Agent binary verified and installed");
        } else {
            println!("Agent binary already current");
        }
        Ok(())
    }
}
