use clap::Args as ClapArgs;

#[derive(Debug, ClapArgs)]
pub(crate) struct Args {}

pub(super) fn run(_: Args) -> onec_access::AppResult<()> {
    super::super::config::show()
}
