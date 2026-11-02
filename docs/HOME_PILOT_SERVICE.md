# HOME HostLink v2 user-managed pilot (1C-1011)

This documents the **isolated HOME development pilot**, not an internet-facing
Hub or an installed fleet. The source used for the working pilot on 2026-11-02
is exactly `0c195d760be295bc4b75952aa12e1f8a5834b923`; the working `dev`
branch may advance independently. No GitHub Actions, tag, release or production
deployment is involved.

## Runtime and ownership

The HOME user has `Linger=yes`. It retains the source in a clean, detached,
fixed-SHA Git worktree at
`$HOME/.local/share/hostlink-v2-operational/source-0c195d760be2`.
The existing pilot runtime remains
`$HOME/.local/share/hostlink-v2-pilot-0c195d` (owned, `0700`).
No Hub credentials or private SSH keys are copied into Git or systemd units.

Three HOME user units were installed under `~/.config/systemd/user/`:

| Unit | Role |
| --- | --- |
| `hostlink-v2-owned-pilot.service` | `Type=oneshot`, `RemainAfterExit=yes`; runs the source-pinned `scripts/hostlink-v2-pilot.sh up`, then `check`; runs `down` on orderly stop |
| `hostlink-v2-owned-pilot-check.service` | Separate authenticated `check`; `Requisite` dependency fails if the pilot was manually stopped, rather than restarting it |
| `hostlink-v2-owned-pilot-check.timer` | Periodic health check, with `OnBootSec=3min`, `OnUnitActiveSec=4min` |

The service and timer are enabled under `default.target` and
`timers.target` respectively. Units use `UMask=0077`,
`NoNewPrivileges=true`, an explicit
`PATH=$HOME/.local/bin:/usr/local/bin:/usr/bin:/bin`, and run only under
the HOME user. The fixed PATH is essential: the interactive/systemd
environments otherwise resolve `caddy` and `sshd` through different
`mise` shims, which the source-pinned pilot correctly rejects as a
binary-identity mismatch. **Never repair this by changing saved binary
digests without verifying the binaries.** The pilot creates
its own loopback-bound Hub, Caddy HTTPS proxy, separate-port sshd and test
Agent. It never edits the existing system Caddy, SSH, FRP, OneC Hub/Agent,
client installations or 1C databases.

Check the actual status after boot or a code change:

```sh
systemctl --user status hostlink-v2-owned-pilot.service
systemctl --user list-timers hostlink-v2-owned-pilot-check.timer
systemctl --user start hostlink-v2-owned-pilot-check.service
systemctl --user show hostlink-v2-owned-pilot-check.service --property=Result,ExecMainStatus
journalctl --user -u hostlink-v2-owned-pilot.service --no-pager -n 30
```

The check runs **inside the user systemd unit**. On this HOME system,
an ordinary unrelated process may lack Linux `/proc/<pid>/exe` and
`environ` inspection rights for processes owned by systemd despite
matching UID. Therefore calling the pilot script's `check` or `status`
directly from an interactive shell can report a false identity failure;
it is not an alternative to the verified unit check. The application-level
Hub and pinned SSH probes are independently available from HOME:

```sh
HOSTLINK_HUB_CONFIG="$HOME/.local/share/hostlink-v2-pilot-0c195d/controller/hub.json" hostlink list --check --json
HOSTLINK_HUB_CONFIG="$HOME/.local/share/hostlink-v2-pilot-0c195d/controller/hub.json" hostlink verify home-v2-pilot
```

Expected authenticated observations from the 2026-11-02 run:
`HUB_API=PASS`, `SSHD_PINNED=PASS`,
`AGENT_AUTHENTICATED_SSH=PASS`. The enrolled, disposable
`home-v2-pilot` reports `online`; short SSH exec preserves exit code `7`.
These results are **local-loopback** evidence, not remote-host acceptance.

For a deliberate controlled stop, disable the check timer before stopping
the pilot. The runtime ledger validates the exact process identity and active
Apalis Board queue before signaling any child:

```sh
systemctl --user stop hostlink-v2-owned-pilot-check.timer
systemctl --user stop hostlink-v2-owned-pilot.service
```

To resume the same pinned pilot, enable/start the service and then the timer.
An unclean host shutdown may leave an uncertain process ledger and prevent
automatic restart: **inspect the ledger and ownership** and reconcile
explicitly rather than deleting it or forcing child termination. The systemd
health timer is diagnostic, not a watchdog that replaces failed processes.

The controlled restart test on 2026-11-02 stopped the source-pinned service
only after confirming zero pending/running Agent jobs, then started it with
the existing state: `HUB_API`, `SSHD_PINNED` and
`AGENT_AUTHENTICATED_SSH` all passed. The Hub continued to identify the
same `home-v2-pilot` machine ID
`8a1bbb5c-32ca-43dc-84c5-18e99b3c09cc`.
The first attempt to restart services originally launched **outside**
systemd could not prove their PID ownership, then left a fail-closed
partial ledger. An explicit one-time reconciliation verified the recorded
PIDs were absent, all four pilot ports were free, and the Agent jobs path
was owner-private before resetting the stopped ledger; no unrelated
processes were signaled and no Agent state or keys were replaced.
This does not constitute a power-loss recovery or guaranteed automatic
repair of a stale ledger.

## Deployment gates not satisfied by the pilot

- The pilot listens on `127.0.0.1` only. It has no external HTTPS domain
  or externally reachable reverse SSH gateway. The existing edge's
  `https://ops.bulzavr.ru/v2/info` returned HTTP 404 on 2026-11-02.
  The HOME FRP client also logged `port not allowed` for existing routes;
  adding a public HostLink route requires an independently approved and
  source-checked edge configuration. Never reuse or overwrite the old
  `/v1` Hub routes.
- HOME and WORK have the `hostlink` Client binaries installed. WORK has an
  independent, ACL-protected pilot Ed25519 key and verified CA connection
  over a temporary SSH forward; however **WORK has not been enrolled as an
  authorized Controller**. Its test with a deliberately wrong token was
  correctly refused, and the temporary token/config and forward were
  removed. Do not copy HOME private keys or operator secrets.
- Actual server Agents must enroll through the approved Hub and an
  individually authorized server-side disposable scope. Verify OS/arch,
  least-privileged owner, private root, distinct keypins, Hub enrollment,
  pinned Agent SSH, exit status, SFTP, rollback and coexistence before a
  fleet rollout. No customer server, existing OneC Agent or 1C database
  may be changed merely because this pilot is healthy.
- Production fresh bootstrap/update requires the separately authorized
  fixed private GitHub Release and its four source-exact raw Agent assets.
  Local MSVC cross-compiles and Windows 7 x86 under WOW64 are not proof of
  real 32-bit Windows 7 OS, native update, or production readiness.

See [parallel-pilot operations](PARALLEL_PILOT_OPERATIONS.md),
[managed-fleet architecture](MANAGED_FLEET_ARCHITECTURE.md),
[Agent installation](AGENT_INSTALLATION.md) and
[Win7 acceptance](WIN7_REWRITE_ACCEPTANCE.md).
