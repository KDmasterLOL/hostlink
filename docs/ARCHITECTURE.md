# HostLink russh execution plane and mandatory Hub management plane

Huly 1C-987. This describes the development architecture after the three-crate
russh + Hub v2 rewrite. The older 5a1f80b SHA was its historical design baseline;
see [SOURCE_LAYOUT.md](SOURCE_LAYOUT.md) for the current modular source tree.
This is not a claim of release or deployed-fleet acceptance.

One controller SSH client and one unprivileged Agent embedded SSH server use
russh. An optional already approved gateway handles reverse SSH/TCP loopback
forwarding. The Agent does not need external ssh.exe/sshd.exe and neither
product owns a second TCP RPC protocol.

Short exec follows RFC4254: one shell command string, separate stdout/stderr,
exit status, EOF/close, cancellation on channel close. Windows PS2 raw stdin
requires -InputFormat None and a non-elevated non-System user. The server
rejects interactive shell and PTY unless a separate feature accepts them.

Durable job is distinct: the client generates an opaque job ID and stages
source-exact manifest/artifacts under an Agent-owned private directory. The
Agent atomically accepts the exact request ID+digest, then launches an owned
job worker with persisted status, stdout/stderr and exit code. The job worker
is independent of the SSH channel: link loss does not cancel it. Reconnect
reuses the same ID and reads status and byte offsets; duplicate request
with a different digest is an error. Lost acknowledgment is UNKNOWN, not
permission for blind re-execution. If Agent itself dies, mark nonterminal
jobs interrupted/unknown; never automatically replay side effects.

Agent-only updater (required): independently selected exact package digest,
version and target architecture, bounded archive inventory, no symlink/reparse
paths, source-exact package manifest and private update staging. Under an
exclusive update lock the Agent checks for active/uncertain durable jobs and
returns DeferredActiveJobs instead of interrupting them. Use a mature
self-update publication library where it is safer and smaller, keeping
verified installed-file state, rollback/recovery and honest failures. Windows
needs a proven out-of-process handoff with the old Agent quiesced rather than
attempting to overwrite its running EXE. This update engine is Agent-only,
not a general package manager, a second network service or old Toolkit updater.

Use the small `hostlink-jobs` subsystem over the SAME authenticated SSH
connection, not a second listener or a custom network carrier. Preserve
strict known-host pins, authorized users, file ownership and path safety,
bounded storage, timeouts, transparent errors and process cleanup.

Caller owns test policy/side effects. The `hostlink jobs run --binary LOCAL` API stages a
pinned test binary through SFTP, uses typed argv in a durable manifest (not
SSH exec-string quoting), supports test --list and normal execution, and
retrieves raw outputs and actual exit statuses after reconnect.

The historical **first two-crate execution milestone** excluded Hub only temporarily.
The current development source contains all three crates. The final product
requires authoritative Hub inventory, short-lived invitations, fresh Agent enrollment,
named-host selection and revocation. These management functions use a separate Hub HTTPS
control plane and do not revive the removed Agent TCP JSONL execution carrier. See
[MANAGED_FLEET_ARCHITECTURE.md](MANAGED_FLEET_ARCHITECTURE.md) for the binding public API and
security/operational requirements. The retired generic Nextest attestation/Toolkit release
engine and unauthorized Windows service ownership remain excluded.
Migration of deployed Agents, main/tag/release and production network writes still require
separate explicit authorization.
Native Windows11 and Win7 x64/x86 source-exact acceptance needed separately,
including active-job update deferral, stopped-runtime handoff and rollback.


Agent jobs have one owner, `crates/agent/src/jobs/`: one Apalis SQLite sink and
WorkerBuilder with 100 ms polling, ProcessKit execution, authenticated
`hostlink-jobs` framing, private output and artifacts. Lifecycle/result lives in
native Apalis columns; an immutable one-use claim prevents orphan/reconnect
replay. UNKNOWN blocks Agent updates. See the [jobs contract](AGENT_MINIMAL_JOBS.md)
for native result publication, fresh-only schemas and cancellation semantics.
