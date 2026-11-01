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

Short SSH exec cancels on channel close. Agent-local commands are independent
Apalis SQLite jobs, managed through upstream apalis-board (loopback HTTP UI/API),
not through SSH/SFTP jobs commands. The user approved replacing the old remote
jobs carrier on 2026-10-29. Never reintroduce a bespoke SSH jobs protocol,
local scheduler, start-claim ledger or duplicate result store. Apalis may
automatically replay commands after a crash, repeating side effects. Board
HTTP accepts arbitrary commands with Agent user privileges: bind only to a
nonzero loopback port, reject unsafe hosts/origins, and use authenticated SSH
forwarding for remote browser access. No unauthenticated public bind.
Use exact host key pins, controller authorized Ed25519 keys, private owned paths,
bounded concurrency and byte streams, fail-closed security and Windows 7 PS2 support.
No unmanaged background processes, false success or unbounded retries.
A minimal Agent-only updater is REQUIRED: exact version/target/SHA,
self_update-managed nonsecret archive/bundle staging (native permissions/ACL),
an exclusive updater lock, Agent process shutdown before Linux publication,
installed-file integrity, upstream in-process rollback on failed publication,
and offline stopped-only Windows update after removal of the current-user
Task Scheduler task. Apalis alone owns its SQLite job state; service and
updater must not inspect its tables.
Under user authorization for 1C-1159, GitHub Releases in the fixed private
`KDmasterLOL/hostlink` repository are the SOLE production artifact source for
fresh invites and installed updates. Both Controller and target use separate
current-user, private `hostlink/credentials/github-token` files; on first
target bootstrap the credential is securely prompted by default. Under
explicit 1C-1160 user authorization, `hostlink invite --embed-github-token`
may instead print the Controller's PAT in the bootstrap command and provision
the target credential without prompting. Treat printed commands and any
saved PowerShell helper as secret material and dispose of them after use.
Without this explicit opt-in no PAT is included. PATs are never committed
in source, binaries, Hub records, download URLs or release bundles. No
arbitrary-site `invite` or `update` flags and no alternate publisher fallback.
GitHub-digest checks do not replace HostLink ZIP, manifest, filesystem, locks
or stopped-Agent checks; native Windows 7/11 acceptance remains a release gate.
Under the explicit 2026-10-31 user trade-off for 1C-1147, no bespoke Windows
staging ACL hardening or durable update journal is required. Sudden kill/power loss
may leave bin missing; there is no automatic crash recovery. Persistent
state/jobs/keys and the install root remain private-fs protected.
Queued tasks may resume after the Agent restarts. It is NOT
another SSH transport, not a general release engine and not the Toolkit updater.
Changes to real servers require independently verified disposable scope; do not
alter 1C production databases, running services or original OneC Toolkit.

For multi-file Rust modules use `module/mod.rs` with sibling source files, never
both `module.rs` and `module/mod.rs`. Target ~200 lines per cohesive file;
exceptions for protocol/security contracts and E2E tests are documented in
`docs/SOURCE_LAYOUT.md`. Move private unit tests into sibling test modules.
