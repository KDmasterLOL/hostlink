use clap::Args as ClapArgs;
use hex::FromHex;
use hostlink_agent::update::{default_update_root, update, update_from_github};
use std::{env, io, path::PathBuf};

#[derive(ClapArgs)]
pub(crate) struct Args {
    /// Installed Agent root; defaults to the domain's verified installation location.
    #[arg(long)]
    root: Option<PathBuf>,
    /// Explicit pinned package URL instead of a GitHub release.
    #[arg(long, requires_all = ["sha256", "version", "target"])]
    url: Option<reqwest::Url>,
    /// Independently trusted SHA-256 for the explicit package URL.
    #[arg(long, requires = "url", value_parser = |value: &str| <[u8; 32]>::from_hex(value))]
    sha256: Option<[u8; 32]>,
    /// Exact target required for an explicit package URL.
    #[arg(long, requires = "url")]
    target: Option<String>,
    /// Exact release version (allows downgrade); defaults to latest stable on GitHub.
    #[arg(long)]
    version: Option<semver::Version>,
}

pub(crate) fn execute(args: Args) -> io::Result<()> {
    let root = match args.root {
        Some(root) => root,
        None => default_update_root()?,
    };
    let updated = match (args.url, args.sha256, args.version, args.target) {
        (Some(url), Some(sha256), Some(version), Some(target)) => {
            update(&root, &url, sha256, &target, &version)?
        }
        (None, None, version, None) => {
            let token = env::var("GH_TOKEN")
                .or_else(|_| env::var("GITHUB_TOKEN"))
                .ok();
            update_from_github(&root, version.as_ref(), token.as_deref())?
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "manual update requires --url, --sha256, --version and --target",
            ));
        }
    };
    if updated {
        println!("Agent package verified and installed");
    } else {
        println!("Agent package already current");
    }
    Ok(())
}
