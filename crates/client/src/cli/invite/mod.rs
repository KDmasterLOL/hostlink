//! Digest-pinned raw binary selection and copyable bootstrap rendering.

mod github;
mod inline;
mod validate;

pub use github::{resolve_github_family, resolve_github_selection};
pub use inline::prepare_inline;
pub use validate::{ArtifactSelection, BootstrapError, OsFamily, Target};

#[cfg(test)]
mod tests;
