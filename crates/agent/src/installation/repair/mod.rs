//! Existing-root repair, or explicitly confirmed SSH key replacement. Jobs are never migrated.

use super::*;
use crate::{AgentConfig, ReverseGateway, enrollment, service, update};
use hostlink_hub::{EnrollRequest, EnrollResponse, MachineId, REPAIR_NAMESPACE};
use russh::keys::{Algorithm, PrivateKey, ssh_key::HashAlg};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, io::Write, time::Duration};

mod state;
mod transaction;
use state::Snapshot;
use transaction::Transaction;

pub(super) async fn repair(
    options: &InstallOptions,
    ca: Option<&Path>,
    root: &Path,
) -> io::Result<EnrollmentResult> {
    let installation = InstallationRoot::open(Some(root))?;
    let root = installation.as_path();
    super::ensure_ready(root)?;
    let expected = options.machine_id.as_ref().ok_or_else(|| invalid(
        "Agent root already exists; existing Agent requires an identity-bound invite from the operator; a fresh invite cannot adopt this root",
    ))?;
    enrollment::validate_inputs(&enrollment_options(options, root.to_owned()))?;
    #[cfg(windows)]
    crate::runtime::ensure_limited_windows_token()?;
    let snapshot = if options.replace_identity {
        confirm_replacement(expected)?;
        Snapshot::read_replacement(root, expected, &options.name, &options.user)?
    } else {
        Snapshot::read(root, expected, &options.name, &options.user)?
    };
    // Discover identity before creating even a lock in a foreign/invalid root,
    // then revalidate the snapshot under the updater's shared mutation lock.
    let update_lock = update::lock(root, "update.lock")?;
    super::ensure_ready(root)?;
    snapshot.assert_unchanged(root)?;
    // Query ownership before any Hub request, marker or OS mutation. A merely
    // existing task/unit is not evidence that HostLink may replace it.
    let original_service = service::status(root)?;
    let mut source = RunningExecutable::open()?;
    let transaction = Transaction::prepare(root, &snapshot, &mut source)?;
    let mut request = snapshot.request(enrollment::read_token(&options.token_file)?)?;
    if !options.replace_identity {
        let signature = snapshot
            .reverse_key
            .sign(REPAIR_NAMESPACE, HashAlg::Sha256, &request.repair_message())
            .map_err(io::Error::other)?;
        request.repair_signature = Some(signature.to_string());
    }
    transaction.mark_pending()?;
    // Any error after send (including an invalid reply) retains the marker.
    // Neither a fresh invite nor this token is automatically retried.
    let response = enrollment::enroll_once(&options.hub_url, request, ca).await
        .map_err(|_| invalid("repair Hub outcome uncertain; preserve repair.pending and reconcile the exact Hub identity before retrying"))?;
    transaction
        .write_candidate(&snapshot, &response, options.gateway_index)
        .await?;
    if !transaction.changed(&snapshot)? {
        transaction.finish_unchanged()?;
        return Ok(result(root, expected));
    }
    // Publication and service removal share update.lock. Windows requires a
    // separate verified image (this process) and no owned Scheduler task.
    let mut runner_lock = None;
    let publication = async {
        if original_service.installed {
            service::remove_for_repair(root)?;
        }
        runner_lock = Some(wait_for_runner(root).await?);
        #[cfg(windows)]
        service::ensure_repair_offline(root)?;
        // A concurrent manual edit must not get silently published over.
        snapshot.assert_unchanged(root)?;
        transaction.publish()?;
        transaction.finish()?;
        Ok::<(), io::Error>(())
    }
    .await;
    // OS registration calls take update.lock themselves. The bootstrap performs
    // registration/start after success; rollback restores the original service.
    if let Err(error) = publication {
        transaction.retain_pending()?;
        if let Err(rollback) = transaction.rollback() {
            return Err(io::Error::other(format!(
                "repair failed; rollback incomplete; preserve repair.pending and backup ({error}; {rollback})"
            )));
        }
        if options.replace_identity {
            return Err(io::Error::other(format!(
                "Hub key rotation committed; original local files restored but repair.pending and the new keys are retained for authenticated reconciliation ({error})"
            )));
        }
        transaction.finish()?;
        drop(runner_lock);
        drop(update_lock);
        if original_service.installed {
            restore_service(root, original_service.active).await?;
        }
        return Err(io::Error::other(format!(
            "repair failed; original files restored ({error})"
        )));
    }
    drop(runner_lock);
    drop(update_lock);
    Ok(result(root, expected))
}

fn confirm_replacement(expected: &MachineId) -> io::Result<()> {
    use std::io::{BufRead, IsTerminal};
    let input = io::stdin();
    if !input.is_terminal() {
        return Err(invalid(
            "SSH key replacement requires an interactive local/RDP session and typed full machine ID",
        ));
    }
    eprintln!(
        "Replace BOTH SSH keys for {expected}? Existing Controller host pins will change. Machine ID, port and jobs are retained. Type the full machine ID to confirm:"
    );
    let mut answer = String::new();
    io::BufReader::new(input.lock().take(130)).read_line(&mut answer)?;
    if answer.trim_end_matches(['\r', '\n']) != expected.as_str() {
        return Err(invalid(
            "SSH identity replacement was not confirmed; installation preserved",
        ));
    }
    Ok(())
}

fn result(root: &Path, machine_id: &MachineId) -> EnrollmentResult {
    EnrollmentResult {
        install_root: root.to_owned(),
        config_path: root.join("state/agent.json"),
        machine_id: machine_id.to_string(),
    }
}

async fn wait_for_runner(root: &Path) -> io::Result<std::fs::File> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        match update::lock(&root.join("jobs"), "runner.lock") {
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock
                    && tokio::time::Instant::now() < deadline =>
            {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            result => return result,
        }
    }
}

async fn restore_service(root: &Path, active: bool) -> io::Result<()> {
    let executable = root.join("bin").join(EXECUTABLE_NAME);
    // Only our retained original image is used, never PATH or a caller-selected binary.
    for action in ["install", "start"]
        .into_iter()
        .take(if active { 2 } else { 1 })
    {
        let mut command = processkit::Command::new(&executable)
            .args(["service", action, "--root"])
            .arg(root);
        if action == "install" {
            command = command.arg("--config").arg(root.join("state/agent.json"));
        }
        command.timeout(Duration::from_secs(20))
            .output_buffer(processkit::OutputBufferPolicy::fail_loud(4).with_max_bytes(4096))
            .run().await.map_err(|_| invalid("original files restored but original service restoration failed; use the preserved installed Agent to reconcile service"))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
