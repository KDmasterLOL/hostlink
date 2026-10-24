//! Deterministic projection of managed OpenSSH authorized-key entries.

use super::*;
use ssh_key::authorized_keys::Entry;

const AUTHORIZED_KEYS_MAX_BYTES: usize = 4 * 1024 * 1024;

pub(super) fn authorized_key_line(record: &AgentRecord) -> io::Result<String> {
    let marker = format!("onec-agent:{}", record.machine_id);
    let key = normalize_public_key(&record.ssh_public_key)?;
    Ok(format!(
        "command=\"/bin/false\",no-agent-forwarding,no-X11-forwarding,no-pty,no-user-rc,permitopen=\"127.0.0.1:9\",permitlisten=\"127.0.0.1:{}\" {} {}",
        record.remote_port, key, marker
    ))
}

pub(super) fn reconcile_authorized_keys(path: &Path, state: &HubState) -> io::Result<()> {
    ensure_authorized_keys_parent(path)?;
    let existing = read_authorized_keys(path)?;
    let mut output = without_managed_entries(&existing);
    for record in state.agents.values() {
        if !output.is_empty() && !output.ends_with(b"\n") {
            output.push(b'\n');
        }
        output.extend_from_slice(authorized_key_line(record)?.as_bytes());
        output.push(b'\n');
    }
    if output.len() > AUTHORIZED_KEYS_MAX_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "reconciled authorized_keys exceeds {AUTHORIZED_KEYS_MAX_BYTES} byte limit: {} bytes",
                output.len()
            ),
        ));
    }
    hostlink_core::write_private_file_atomically(path, &output)
}

fn without_managed_entries(existing: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(existing.len());
    for line in existing.split_inclusive(|byte| *byte == b'\n') {
        let logical = line.strip_suffix(b"\n").unwrap_or(line);
        let logical = logical.strip_suffix(b"\r").unwrap_or(logical);
        if !is_managed_entry(logical) {
            output.extend_from_slice(line);
        }
    }
    output
}

fn is_managed_entry(line: &[u8]) -> bool {
    let Ok(line) = std::str::from_utf8(line) else {
        return false;
    };
    line.parse::<Entry>().ok().is_some_and(|entry| {
        entry
            .public_key()
            .comment()
            .as_str()
            .ok()
            .is_some_and(|comment| comment.starts_with("onec-agent:"))
    })
}

pub(super) fn ensure_authorized_keys_parent(path: &Path) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    if !path.exists() {
        return hostlink_core::write_new_private_bytes(path, b"");
    }
    restrict_private_file(path)
}

fn read_authorized_keys(path: &Path) -> io::Result<Vec<u8>> {
    hostlink_core::read_file_bounded(path, AUTHORIZED_KEYS_MAX_BYTES)
}

fn restrict_private_file(path: &Path) -> io::Result<()> {
    hostlink_core::restrict_private_file(path).map_err(io::Error::other)
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_KEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILM+rvN+ot98qgEN796jTiQfZfG1KaT0PtFDJ/XFSqti";

    #[test]
    fn managed_entry_matching_is_structural_and_comment_exact() {
        let marker = "onec-agent:machine-a";
        let managed = format!("{VALID_KEY} {marker}");
        let collision = format!("{VALID_KEY} prefix-{marker}-suffix");
        let option_collision = format!(r#"command="echo {marker}" {VALID_KEY} unrelated"#);
        let unknown_option_collision =
            format!(r#"future-option="contains-{marker}" {VALID_KEY} unrelated"#);

        assert!(is_managed_entry(managed.as_bytes()));
        assert!(!is_managed_entry(collision.as_bytes()));
        assert!(!is_managed_entry(option_collision.as_bytes()));
        assert!(!is_managed_entry(unknown_option_collision.as_bytes()));
        assert!(!is_managed_entry(b"malformed onec-agent:machine-a"));
    }

    #[test]
    fn filtering_preserves_unmanaged_bytes_and_line_endings() {
        let marker = "onec-agent:machine-a";
        let existing = format!(
            "# comment\r\n{VALID_KEY} unrelated\r\nmalformed {marker}\n{VALID_KEY} {marker}\r\n"
        );
        let expected = format!("# comment\r\n{VALID_KEY} unrelated\r\nmalformed {marker}\n");
        assert_eq!(
            without_managed_entries(existing.as_bytes()),
            expected.as_bytes()
        );
    }

    #[test]
    fn filtering_removes_all_duplicate_managed_entries_only() {
        let marker = "onec-agent:machine-a";
        let existing =
            format!("{VALID_KEY} {marker}\n{VALID_KEY} unrelated\n{VALID_KEY} {marker}\n");
        assert_eq!(
            without_managed_entries(existing.as_bytes()),
            format!("{VALID_KEY} unrelated\n").as_bytes()
        );
    }

    #[test]
    fn filtering_preserves_non_utf8_unmanaged_bytes() {
        let mut existing = b"comment \xff\n".to_vec();
        existing.extend_from_slice(format!("{VALID_KEY} onec-agent:machine-a\n").as_bytes());

        assert_eq!(without_managed_entries(&existing), b"comment \xff\n");
    }

    #[test]
    fn reconciliation_rejects_oversized_projection_before_publication() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("authorized_keys");
        let existing = vec![b'#'; AUTHORIZED_KEYS_MAX_BYTES - 1];
        fs::write(&path, &existing).expect("near-limit authorized_keys");

        let mut state = HubState::default();
        state.agents.insert(
            "agent-a".into(),
            AgentRecord {
                id: "id-agent-a".into(),
                machine_id: "agent-a".into(),
                name: "agent-a".into(),
                display_name: None,
                hostname: "agent-a".into(),
                username: None,
                os: "windows".into(),
                arch: "x86_64".into(),
                agent_version: "0.1.0".into(),
                transport: "open_ssh".into(),
                persistence_mode: None,
                remote_port: 41000,
                ssh_public_key: VALID_KEY.into(),
                ssh_host_public_key: None,
                control_credential_nonce: None,
                enrolled_at: 1,
                updated_at: 1,
            },
        );

        let error = reconcile_authorized_keys(&path, &state)
            .expect_err("projection larger than the reader limit must fail before publication");

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            fs::read(&path).expect("original authorized_keys"),
            existing,
            "failed reconciliation must preserve the previous projection bytes"
        );
    }
}
