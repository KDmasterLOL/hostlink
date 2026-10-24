use clap::Args as ClapArgs;

#[derive(Debug, ClapArgs)]
pub(crate) struct Args {
    #[arg(long)]
    pub(crate) name: Option<String>,
    #[arg(long, default_value_t = 900, value_parser = clap::value_parser!(u64).range(60..=86400))]
    pub(crate) ttl_seconds: u64,
    #[arg(long, value_enum, default_value_t = crate::cli::values::Persistence::UserSession)]
    pub(crate) persistence: crate::cli::values::Persistence,
    /// Render the explicit embedded-russh canary installer path instead of the default carrier.
    #[arg(long)]
    pub(crate) embedded_ssh_candidate: bool,
    /// Exact HTTPS URL for the pinned installer script.
    #[arg(long, value_name = "URL", required = true)]
    pub(crate) direct_installer_url: String,
    /// Trusted SHA-256 of the installer script; it must match the script embedded in this binary.
    #[arg(long, value_name = "SHA256", required = true)]
    pub(crate) direct_installer_sha256: String,
    /// Exact target ZIP URL for the pinned direct artifact.
    #[arg(long, value_name = "URL", required = true)]
    pub(crate) direct_package_url: String,
    /// Trusted SHA-256 supplied by the artifact publisher/operator, never fetched from the ZIP host.
    #[arg(long, value_name = "SHA256", required = true)]
    pub(crate) direct_package_sha256: String,
    /// Exact package version expected from onec.exe --version after extraction.
    #[arg(long, value_name = "VERSION", required = true)]
    pub(crate) direct_package_version: String,
    /// Exact supported Windows target triple bound to the package URL and local architecture.
    #[arg(long, value_name = "TARGET", required = true)]
    pub(crate) direct_package_target: String,
}

pub(super) async fn run(args: Args) -> hostlink_access::AppResult<()> {
    super::super::bootstrap::invite(args).await
}
