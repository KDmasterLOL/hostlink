//! Public SSH host synchronization result models.

use super::*;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
/// Result of synchronizing hub-managed hosts into generated SSH configuration.
pub struct SshHostSyncReport {
    /// Generated managed SSH config path.
    pub ssh_config: PathBuf,
    /// Generated pinned target-host known_hosts path.
    pub target_known_hosts: PathBuf,
    /// User ~/.ssh/config path when it was discovered/updated.
    pub user_ssh_config: Option<PathBuf>,
    /// Managed host aliases successfully written.
    pub configured_hosts: Vec<String>,
    /// Hub agents omitted from managed SSH projection with explicit reasons.
    pub skipped_hosts: Vec<SshHostSkip>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
/// One hub-managed agent skipped during SSH configuration synchronization.
pub struct SshHostSkip {
    /// Agent name.
    pub name: String,
    /// Human-readable non-secret skip reason.
    pub reason: String,
}
