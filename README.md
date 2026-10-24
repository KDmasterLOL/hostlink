# HostLink

A standalone, generic managed-machine access product: a controller, a Hub/gateway,
an outbound reverse-SSH Agent, SFTP, process execution and port forwarding.

Status: extraction work in progress. Initial code is a verified, unchanged
source snapshot of the four access-related Rust crates from OneC Toolkit.
Crate names, bundled installers and the legacy protocol have not yet been migrated.
The snapshot is not a production-ready independent release.

- No dependency on 1C domain concepts in the target architecture.
- Existing installed Agent configurations, protocol fields, SSH keys and signed
  observations must not be silently renamed or invalidated.
- Source extraction does not authorize installation, service takeover, release,
  deployment or modifications to the upstream OneC Toolkit checkout.
- Windows 7 compatibility and Cargo/Nextest target runner parity are release
  requirements, not assumptions.

Tracking: Huly 1C-944. See docs/extraction.md for baseline and gates.
