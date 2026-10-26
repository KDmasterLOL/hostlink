# HostLink — complete parallel operation and release plan

Status: 2026-10-26. Parent Huly 1C-987, parallel rollout 1C-1037.
Baseline: experimental rewrite/russh-minimal@7b771b75034ba63f6f6278187ccfb65d39fce23d.

## Non-negotiable scope

The user requires all new HostLink functions, not a shortened pilot:
- New independent Hub v2: HTTPS management, inventory, one-use invite, source-pinned enrollment, machine identity, rename and revoke.
- New hostlink CLI: hub configure/check, invite, list/info/verify, named check/exec/SFTP upload/download, durable job start/status/output/cancel and binary run, port forwarding/RDP/probe.
- New user-owned Agent: separate root, keys, loopback port, reverse SSH, multiple pinned gateway routes, limited reconnect/jitter, service install/start/stop/status/remove, private log output.
- Reproducible packages: Linux, Windows11, actual Windows7 x64 and x86, manifest, ZIP, sidecar SHA, installer, immutable HTTPS artifacts and operator commands.
- Real gateway enforcement of the distinct hostlink-v2-authorized_keys set, exact permitlisten and revocation; correct TLS trust on Hub and artifact hosting.
- Windows stopped-runtime Agent updater: shared job lock, active/unknown job deferral, verified helper, crash journal, restart and rollback.
- Full native Windows11 and Windows7 NT6.1 x64 and true 32-bit x86 with PowerShell 2, correct ACLs, source digests and owned process cleanup.
- Final combined source-exact regression suite, documented rollout and release.

Parallel operation is a topology for troubleshooting, comparison and rollback. Old ONEC Agent, Hub, SSH keys, service, data and reverse-port allocation must remain untouched and independently usable. No silent adoption, common process, key, local job store, listener port or service identity. Hub revoke of new connections is NOT physical uninstall or termination of already authenticated SSH channels. Legacy dev/main/tags and old production services remain unchanged until explicit cutover authorization.

## Implementation ownership (mandatory, not optional)

| Huly | Work package | Acceptance |
| --- | --- | --- |
| 1C-1038 | Reproducible Linux/Win11/Win7 packages, missing PowerShell2 run/update scripts and source-pinned invite URLs | Manifest verified by same-source bootstrap-verify and negative malicious ZIP tests |
| 1C-1039 | Actual independent HTTPS Hub v2 plus sshd/russh gateway route, exact key projection and revocation | Real HTTPS client+enroll, nested SSH, SFTP/job/forward, deny wrong keys/reused invite, old route untouched |
| 1C-1040 | Agent user service install/start/stop/status/remove and rollback | Only marker-owned new process and root controlled; old services untouched; active jobs not killed |
| 1C-1035 / 1C-1025 | Jittered transient reconnect, gateway failover and safe telemetry | Real signed gateway test, wrong pin/auth permanent stop, single live reverse mapping |
| 1C-1003 / 1C-1008 | Windows11/Win7 x64+x86 native execution/PowerShell2 | Exact Agent/client binaries and PE hashes, verified runtime, owner/private ACLs, durable jobs |
| 1C-1004 | Windows stopped-runtime self-update and rollback | Exact installed SHA, exclusive update lock, complete native failure recovery |
| 1C-1023 / 1C-1024 | Scoped cleanup and actual physical Agent uninstall | No unrelated files, jobs or old Agent touched |
| 1C-1011 | Combined candidate and release | One final SHA across Linux, Win11, Win7 NT6.1, real HTTPS Hub/gateway; source-bound receipts |

All items are required before declaring COMPLETE. Runtime development, packaging and verification proceed concurrently through isolated task worktrees; independent gates may reach PASS earlier.

## Progress / evidence

2026-10-26: HOME Linux source exact 7b771b7 (binary Agent SHA256 aee3ad51b673f51e2db1f0a4f3dd1f36c1b71b986b1974868b275a6f3dae9789; Controller SHA256 6d88ef895ab4e19525363883293e39953389e06ef2044c7f1471a2b54368e5e5). A real external process hostlink-agent run with fresh user-owned TempDir and generated Ed25519 keys was checked using real hostlink CLI. Seven passed tests: check, wrong-host-key denied, wrong-controller-key denied, binary exec and exit7, SFTP create-only+roundtrip, durable start/status/output reattach, stop owned process and closed listener. Fixture disposed. This is DIRECT UNMANAGED mode only. An old Agent was not simultaneously running on this HOME fixture; no real HTTPS Hub/sshd acceptance resulted.

WORK Windows11 GNU source f3a0862 previously passed its full workspace tests. Both Win7 cross-compiled PE targets x86/x64 are available at older source f3a0862 with SHA receipt; no actual NT6.1 execution and no current combined-release receipt. Windows updater still returns Unsupported. This evidence must not be silently applied to a newer source SHA.

## Gate A: independent direct parallel CLI

Select authorized test host and capture old Agent service PID/root/port/state before change (read only). Provision only NEW root/host key/reverse identity/Controller key and free loopback port. Run new Agent under test owner, check exact key pins, binary exec exit7, SFTP upload/Seal, durable job cancel/reattach and network recovery. Verify old Agent remains healthy before and after. Stop only new instance; confirm port closed and no owned job remains. Save source and executable SHA and sanitized receipt. The direct user-level test is verified on HOME with no old Agent; true same-machine co-existence on an installed old Agent target remains OPEN.

## Gate B: managed Hub/installer/gateway

Use separate Hub v2 state root and TLS endpoint, separate independent operator/gateway tokens, source-pinned immutable artifacts. The Hub itself only binds loopback HTTP, so use actual TLS reverse proxy and strictly validated certificate. Gateway must actually use the Hub's separate authorized key projection or a documented user-scope equivalent; do not overwrite old sshd authorized_keys. Build full strict ZIP inventory/manifest. Operator runs:
hostlink hub configure; hostlink hub check;
hostlink invite --name NAME --target TARGET --version VERSION --installer-url HTTPS --installer-sha256 SHA --agent-url HTTPS --agent-sha256 SHA --archive-url HTTPS --archive-sha256 SHA
target: install verified Agent, enter invite token privately, start new user-scoped service;
hostlink list; hostlink list --check; hostlink info NAME; hostlink verify NAME;
hostlink exec --host NAME --command ...; hostlink upload/download; hostlink run/job; hostlink forward/rdp/probe;
hostlink remove NAME --yes (Hub revocation only);
target: hostlink-agent service stop/remove (independent physical uninstall after jobs reconciled).

Verify real HTTPS+SSH, private Agent ACLs, exact identity, wrong keys, expired tokens, no duplicate enrollment, no public reverse bind, denied new connections after revoke and old route untouched.

## Gate C: operational and cross-platform acceptance

Repeat entire managed workflow with permanent user service on Linux, Windows11, then Win7 NT6.1 x64 and true 32-bit x86. Exercise reverse gateway failover and SSH rate recovery without false online state, prompt secure token handling in Win7 PowerShell2, Windows Job Object cleanup and owner-only startup. Complete Windows safe stopped-runtime updater including crash recovery and active-job deferral. Execute source-exact final Linux and Windows test suites, packages and PE/CRT imports; compare actual old/new Agent behavior and restore old route after new pilot teardown.

## Source / acceptance safeguards

- Status PILOT_DIRECT_PASS does not imply MANAGED_HTTPS_GATEWAY_PASS.
- Windows11 GNU binary is not Windows7 MSVC proof; Win7 PE compile is not NT6.1 runtime.
- No assumed SSH availability from Hub inventory. Do not repeat job start on lost acknowledgment.
- Do not treat revoke as remote uninstall or an updater Unsupported result as successful update.
- Keep raw tokens, private keys, usernames and endpoints out of public receipts.
- Fail clearly if a selected native host/TLS identity/gateway authority is unavailable; requirements remain in Huly and unblock as soon as real external prerequisites exist.
- Production rollout, main/tag and old service removal are distinct explicitly authorized actions after final acceptance.
