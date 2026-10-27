use super::enrollment::EnrollmentContext;
use super::*;

pub(super) struct InstallerPlan {
    pub(super) version: &'static str,
    pub(super) target: &'static str,
    pub(super) sidecar: PathBuf,
    pub(super) archive: PathBuf,
    pub(super) installer_sha: String,
    pub(super) agent_sha: String,
    pub(super) archive_sha: String,
    pub(super) args: Vec<String>,
}

pub(super) fn prepare(context: &enrollment::EnrollmentContext<'_>) -> InstallerPlan {
    let EnrollmentContext {
        root,
        artifact_root,
        tls_url,
        ca_cert,
        controller_config,
        client_bin,
        cli_config,
        ..
    } = context;
    let version = "0.1.0";
    let target = "x86_64-unknown-linux-gnu";
    let installer = artifact_root
        .join(version)
        .join("install-hostlink-agent.sh");
    let sidecar = artifact_root
        .join(version)
        .join(target)
        .join("hostlink-agent");
    let archive = artifact_root
        .join(version)
        .join(format!("hostlink-agent-{target}.zip"));
    let installer_url = format!("{tls_url}/{version}/install-hostlink-agent.sh");
    let agent_url = format!("{tls_url}/{version}/{target}/hostlink-agent");
    let archive_url = format!("{tls_url}/{version}/hostlink-agent-{target}.zip");
    let installer_sha = file_sha256(&installer);
    let agent_sha = file_sha256(&sidecar);
    let archive_sha = file_sha256(&archive);
    let mut args = invite_args(
        &installer_url,
        &installer_sha,
        &agent_url,
        &agent_sha,
        &archive_url,
        &archive_sha,
    );
    args.extend([
        "--bootstrap-hub-ca-cert".into(),
        ca_cert.to_string_lossy().into_owned(),
    ]);

    let wrong_ca_config = root.join("wrong-ca-controller.json");
    private_write(
        &wrong_ca_config,
        serde_json::to_vec_pretty(&HubConfig {
            hub_ca_cert: Some(root.join("wrong-ca.pem")),
            ..(**controller_config).clone()
        })
        .unwrap(),
    );
    let mut wrong_ca_invite = Command::new(client_bin);
    cli_env(&mut wrong_ca_invite, &wrong_ca_config);
    assert!(
        !wrong_ca_invite
            .args(&args)
            .status()
            .expect("wrong artifact CA")
            .success(),
        "installer preflight must reject an untrusted HTTPS CA before invitation"
    );

    let mut wrong_installer_pin = args.clone();
    let installer_pin_index = wrong_installer_pin
        .iter()
        .position(|value| value == "--installer-sha256")
        .unwrap()
        + 1;
    wrong_installer_pin[installer_pin_index] = "0".repeat(64);
    let mut bad_pin_invite = Command::new(client_bin);
    cli_env(&mut bad_pin_invite, cli_config);
    let bad_pin = bad_pin_invite
        .args(&wrong_installer_pin)
        .output()
        .expect("wrong installer digest preflight");
    assert!(!bad_pin.status.success());
    assert!(!String::from_utf8_lossy(&bad_pin.stdout).contains("token:"));

    let wrong_host_url = installer_url.replace("localhost", "127.0.0.1");
    let mut wrong_host_args = args.clone();
    let installer_url_index = wrong_host_args
        .iter()
        .position(|value| value == "--installer-url")
        .unwrap()
        + 1;
    let sidecar_url_index = wrong_host_args
        .iter()
        .position(|value| value == "--agent-url")
        .unwrap()
        + 1;
    let archive_url_index = wrong_host_args
        .iter()
        .position(|value| value == "--archive-url")
        .unwrap()
        + 1;
    wrong_host_args[installer_url_index] = wrong_host_url.clone();
    wrong_host_args[sidecar_url_index] = agent_url.replace("localhost", "127.0.0.1");
    wrong_host_args[archive_url_index] = archive_url.replace("localhost", "127.0.0.1");
    let mut wrong_host_invite = Command::new(client_bin);
    cli_env(&mut wrong_host_invite, cli_config);
    assert!(
        !wrong_host_invite
            .args(&wrong_host_args)
            .status()
            .expect("wrong artifact hostname")
            .success(),
        "installer preflight must reject a hostname mismatch before invitation"
    );

    let mut redirected_args = args.clone();
    redirected_args[installer_url_index] = format!("{tls_url}/redirect");
    let mut redirected_invite = Command::new(client_bin);
    cli_env(&mut redirected_invite, cli_config);
    assert!(
        !redirected_invite
            .args(&redirected_args)
            .status()
            .expect("redirected installer source")
            .success(),
        "installer preflight must refuse HTTPS redirects before invitation"
    );

    InstallerPlan {
        version,
        target,
        sidecar,
        archive,
        installer_sha,
        agent_sha,
        archive_sha,
        args,
    }
}
