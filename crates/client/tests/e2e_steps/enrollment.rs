use super::*;

pub(super) struct EnrollmentContext<'a> {
    pub(super) root: &'a Path,
    pub(super) artifact_root: &'a Path,
    pub(super) tls_url: &'a str,
    pub(super) ca_cert: &'a Path,
    pub(super) enrollment_token: &'a Path,
    pub(super) controller_config: &'a HubConfig,
    pub(super) client_bin: &'a Path,
    pub(super) cli_config: &'a Path,
    pub(super) agent_bin: &'a Path,
    pub(super) hub_client: &'a HubClient,
    pub(super) children: &'a mut Children,
}

pub(super) async fn enroll_agent(
    mut context: EnrollmentContext<'_>,
    installer_flow: bool,
) -> (PathBuf, Option<String>) {
    if installer_flow {
        let plan = installer::prepare(&context);
        let (token, command) = installer_enrollment::invite_for_installer(&context, &plan);
        installer_enrollment::verify_bootstrap_rejections(&mut context, &plan, &token, &command);
        let agent_root =
            installer_enrollment::run_interactive_installer(&mut context, &plan, &token, &command);
        (agent_root, Some(token))
    } else {
        (enroll_directly(&context).await, None)
    }
}

async fn enroll_directly(context: &EnrollmentContext<'_>) -> PathBuf {
    let invite = context
        .hub_client
        .invite(Some("managed-fixture".into()), 900)
        .await
        .expect("create one-use invite over HTTPS");
    private_write(context.enrollment_token, invite.token.expose_secret());
    let mut enroll = Command::new(context.agent_bin);
    enroll
        .args(["enroll", "--hub-url", context.tls_url, "--hub-ca-cert"])
        .arg(context.ca_cert)
        .args(["--token-file"])
        .arg(context.enrollment_token)
        .args(["--root"])
        .arg(context.root.join("agent-root"))
        .args(["--name", "managed-fixture", "--user"])
        .arg(std::env::var("USER").unwrap());
    run_ok(&mut enroll, "enroll actual Agent over trusted HTTPS");
    context.root.join("agent-root/state")
}

pub(super) fn assert_invite_replay(
    agent_bin: &Path,
    tls_url: &str,
    ca_cert: &Path,
    enrollment_token: &Path,
    root: &Path,
) {
    let replay = Command::new(agent_bin)
        .args(["enroll", "--hub-url", tls_url, "--hub-ca-cert"])
        .arg(ca_cert)
        .args(["--token-file"])
        .arg(enrollment_token)
        .args(["--root"])
        .arg(root.join("agent-replay"))
        .args(["--name", "managed-fixture-replay", "--user"])
        .arg(std::env::var("USER").unwrap())
        .status()
        .expect("attempt one-use token replay");
    assert!(!replay.success(), "an enrollment invite is one-use");
}
