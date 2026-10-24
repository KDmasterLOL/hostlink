use clap::Args as ClapArgs;

#[derive(Debug, ClapArgs)]
pub(crate) struct Args {
    /// Canonical managed host name or identity; display names are not selectors.
    pub(crate) target: String,
    /// New Unicode display name; omit when using --clear.
    #[arg(required_unless_present = "clear", conflicts_with = "clear")]
    pub(crate) label: Option<String>,
    /// Clear the existing display label.
    #[arg(long)]
    pub(crate) clear: bool,
}

pub(super) async fn run(args: Args) -> hostlink_access::AppResult<()> {
    super::super::display_name::set(args.target, args.label, args.clear).await
}
