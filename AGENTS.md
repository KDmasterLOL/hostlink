# Managed HostLink with one russh execution transport

The russh rewrite has explicit user authorization for development integration into
HostLink `dev` for testing under Huly 1C-987. This authorization is limited to
that dev testing integration; it does not authorize changes to `main`, tags,
releases, deployed infrastructure, installed agents, or production data. The
main coordinator performs a controlled fast-forward only after independent tests.
The former Agent JSONL TCP listener, Win32 OpenSSH/sshd, legacy Toolkit release engine,
and legacy Nextest attestation are excluded. **Hub registration/inventory/invitation/revocation
are REQUIRED product functions**: implement them under a separate HostLink Hub management owner,
without restoring the old Agent RPC or a second execution transport. The target workspace includes
Agent, Client and a focused Hub; see docs/MANAGED_FLEET_ARCHITECTURE.md. Keep russh + russh-sftp
as the sole Agent/Controller execution and file-transfer carrier.

Short SSH exec cancels on channel close; durable jobs are a different lifetime
owned by the Agent process. Reconnect must NEVER silently replay a started job.
Use exact host key pins, controller authorized Ed25519 keys, private owned paths,
bounded concurrency and byte streams, fail-closed security and Windows 7 PS2 support.
No unmanaged background processes, false success or unbounded retries.
A minimal Agent-only updater is REQUIRED: exact version/target/SHA, private
staging, an exclusive update lock, installed-file integrity, active-job deferral,
recovery on failed publication and explicit safe handoff on Windows. It is NOT
another SSH transport, not a general release engine and not the Toolkit updater.
Changes to real servers require independently verified disposable scope; do not
alter 1C production databases, running services or original OneC Toolkit.
