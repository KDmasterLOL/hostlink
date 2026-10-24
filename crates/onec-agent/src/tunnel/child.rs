//! Managed tunnel child ownership over the shared whole-process-tree primitive.

use super::*;

/// RAII owner of one managed SSH or sshd process tree.
pub struct TunnelChild {
    pub(super) child: OwnedProcess,
    #[cfg(windows)]
    pub(super) _sshd_start_gate: Option<super::sshd_host::StartGate>,
}

impl TunnelChild {
    /// Waits for complete owned-process-tree termination.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when process-tree wait or reaping fails.
    pub fn wait(&mut self) -> io::Result<ExitStatus> {
        self.child.wait()
    }

    /// Polls for complete owned-process-tree termination without blocking.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when process status cannot be queried.
    pub fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        self.child.try_wait()
    }

    /// Terminates and reaps the managed SSH or sshd process tree.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when process-tree termination or reaping fails.
    pub fn terminate(&mut self) -> io::Result<()> {
        self.child.terminate()
    }
}
