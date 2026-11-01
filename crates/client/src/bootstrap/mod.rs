//! Source-pinned invitation installer selection and copyable bootstrap rendering.

mod github;
mod render;
mod validate;
mod verify;

pub use github::resolve_github_selection;
pub use render::render_command;
pub use validate::{ArtifactSelection, BootstrapError, Target, VerifiedInstaller};
pub use verify::verify_installer;

/// Deliberately render a credential-bearing bootstrap only for the explicit
/// CLI opt-in. Never use this for a normal invitation or log the result.
///
/// # Errors
/// Returns an error when the Controller credential is absent, insecure, or
/// too long for the target-side provisioner.
pub fn render_command_embedded(
    selection: &ArtifactSelection,
    installer: &VerifiedInstaller,
) -> Result<String, BootstrapError> {
    use secrecy::ExposeSecret;

    let token = github::read_token()?;
    if token.expose_secret().len() > 1024 {
        return Err(BootstrapError::Source(
            "GitHub credential exceeds target bootstrap limit".into(),
        ));
    }
    Ok(render::render_command_with_token(
        selection,
        installer,
        Some(token.expose_secret()),
    ))
}

#[cfg(test)]
mod tests;
