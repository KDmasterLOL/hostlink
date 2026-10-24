use clap::Args as ClapArgs;

#[derive(Debug, ClapArgs)]
pub(crate) struct Args {}

pub(super) async fn run(_: Args) -> hostlink_access::AppResult<()> {
    super::super::config::check().await
}
