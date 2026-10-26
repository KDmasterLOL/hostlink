# HostLink Agent user lifecycle

The Hub and local Agent have separate lifecycles. `hostlink remove NAME --yes`
revokes Hub managed access. It does not contact or uninstall the Agent. The
commands below manage only a new HostLink Agent installed under the current
user's private root; they never adopt the legacy Agent, its process, ports,
keys, authorized keys, SSH account, or token.

## Linux systemd user service

Enrollment remains a one-shot operation. Keep the executable, config, keys,
jobs, and upload data in a new private root. The package executable is
`ROOT/bin/hostlink-agent`; check the config and then register that exact fresh
enrollment root:

```sh
hostlink-agent check --config ROOT/state/agent.json
hostlink-agent service install --root ROOT --config ROOT/state/agent.json
hostlink-agent service start --root ROOT
hostlink-agent service status --root ROOT
hostlink-agent service stop --root ROOT
hostlink-agent service remove --root ROOT
```

`install` requires systemd 254 or newer, which provides the bounded exponential
restart delay used by the unit. It validates the enrollment `machine.json` and
manifest and refuses arbitrary config paths, then records the current uid,
canonical root, config path and executable SHA-256 in a private ownership marker,
writes one root-derived unit under
`$XDG_CONFIG_HOME/systemd/user` (default `~/.config/systemd/user`), reloads the
user manager and enables login startup. It does not start the Agent. `start` is
explicit. The unit uses bounded restart throttling and exponential delay (15 s
to 240 s, at most five starts per five minutes). It does not enable login
lingering, use the system manager, require root, or run as SYSTEM. If no user
systemd session is available, lifecycle commands fail with that condition;
they do not silently switch to a system service.

The selected root must be an existing current-user-owned private directory.
The executable and config must be regular non-symlink files owned by that user
inside that root. The service marker and generated unit are checked before
management actions; the unit contents, process uid, `/proc` executable path,
command line and executable digest are verified before status is reported.
Different roots get distinct unit names. A unit collision, wrong owner, root
symlink, changed executable, edited unit, missing enrollment config, or unsafe
job record fails closed.

`status` reports the unit state, owning uid, exact main PID when active, source
executable SHA-256, and whether the loopback listener returns an SSH 2.0 banner. It also
reports whether local enrollment metadata exists. It never claims Hub
reachability: use `hostlink list --check` for fresh Hub inventory plus bounded
pinned SSH checks. Enrollment metadata alone does not mean the Agent is online.

`stop` and `remove` refuse while any durable job is `Prepared`, `Running`, or
`Interrupted`. Interrupted jobs remain unresolved and are never replayed.
`remove` stops and disables only the exact owned user unit, removes the exact
verified Agent executable, and deletes its unit and service marker. It
deliberately retains the Agent root, credentials, enrollment metadata and jobs
for recovery or a separately reviewed data deletion. If shutdown races with
new job admission, it restarts the service and returns a deferred error.

Reinstalling is idempotent only when root, config and executable hash match.
Replacing the Agent binary is not performed while registered as a service;
remove the user service after jobs are terminal, then use the source-exact
Agent-only update workflow and install the updated executable before registering
the service again. Hub revocation and local service removal are independent
operations.

## Windows 7 and Windows 11 current-user startup

Windows uses only the current interactive user's
`HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run` entry. It does not
create a Windows service, scheduled task, SYSTEM process, machine-wide
registration, or legacy Agent integration. Login startup runs only after that
user signs in; no process is claimed to be running while the user is logged
out. Windows does not restart the Agent after a crash during that login
session; status reports it inactive and an explicit `start` is required. The
Run command is capped at 260 UTF-16 characters, so install fails
before writing either marker or registry value when the selected root cannot
fit safely.

```powershell
hostlink-agent.exe check --config ROOT\state\agent.json
hostlink-agent.exe service install --root ROOT --config ROOT\state\agent.json
hostlink-agent.exe service start --root ROOT
hostlink-agent.exe service status --root ROOT
hostlink-agent.exe service stop --root ROOT
hostlink-agent.exe service remove --root ROOT
```

`ROOT` must be a bounded private descendant of the current user's OS-resolved
`FOLDERID_LocalAppData` directory, including the official installer layout
`LocalAppData\HostLink\Agent`. The resolver uses `SHGetKnownFolderPath`,
not `%LOCALAPPDATA%` or another environment variable. The profile boundary
must be owned by the current SID and its DACL may grant access only to that SID,
SYSTEM, and local Administrators; every intermediate directory and the install
root itself require protected current-user-only DACLs. Both profile and
installed-root paths are canonicalized to avoid ordinary DOS vs verbatim aliases.
The path chain rejects reparse points. Shared roots such
as `C:\Temp` are refused even if the final directory appears private.

`install` requires a non-elevated, non-SYSTEM user, the exact executable at
`ROOT\\bin\\hostlink-agent.exe`, the fresh enrollment config and matching
manifest, a LocalAppData-contained root with current-user-owned protected ACLs,
and non-reparse input paths. It stores a private marker with the current SID,
root, config, binary SHA-256, a
root-specific named-pipe endpoint, and a random 256-bit control token. It also
writes a private, source-derived VBScript launcher under `ROOT` so the Run
entry stays below the registry's command limit even when the executable and
config paths are long. The launcher is pinned by its content hash and invokes
the system Windows Script Host with hidden-window settings. The matching
startup value is written only if the HKCU value is vacant; reinstall or
collision never overwrites another value. The launcher command line contains
only `--config` and `--managed-service`; the 256-bit control token stays in the
private marker and is loaded by the Agent after it verifies its executable,
marker, root, and config. `install` registers login startup
but does not start the Agent. `start` verifies the marker, enrollment and exact
binary hash, then starts one detached current-user process and waits for its
authenticated pipe handshake. The handshake reports the real process PID;
status also checks the configured loopback SSH banner and does not claim Hub
reachability.

The named-pipe listener creates its next protected instance before serving a
connected client, so it remains available across requests with at most two
instances. `stop` authenticates to that root's local named pipe, opens a
synchronized process handle for the reported PID, and verifies its owner SID,
image path, and executable SHA-256 before requesting shutdown. It waits on that
handle with the Windows 7-compatible `WaitForSingleObject`; a missing pipe alone
never proves process exit. Unknown PID, identity mismatch, or failed handle open
leaves the registration in place. If the pipe is already absent, `stop` and
`remove` fail closed because no authenticated live PID is available; start the
owned Agent and invoke `remove` while its lifecycle endpoint is available.
It refuses any durable job
that is Prepared, Running, Interrupted or unreadable, and asks the Agent to
shut down through its normal cancellation path. It waits at most ten seconds
and never terminates a PID or process tree by guesswork. It rechecks durable
jobs after shutdown and restarts the Agent if a job was admitted in the narrow
shutdown race. `remove` performs the same stop/interlock, then removes only the
exact HKCU value and ownership marker after process exit is proven. Windows
keeps the executable, config, credentials, enrollment record and jobs in place
for recovery; Hub revocation remains independent. Remove the lifecycle registration before applying an
Agent update; the Windows update command refuses to replace a binary while its
service marker is present. A changed binary, marker, registry value, SID, ACL, or
reparse path fails closed.

This implementation has not yet passed native Windows 11 disposable-user
acceptance or Windows 7 NT6.1 x64/x86 acceptance. Linux tests and a Windows
cross-check do not establish those runtime results. PowerShell 2 is not used
by the lifecycle implementation. A native Windows test is present but ignored
by default because it creates a current-user startup entry. Run it only from a
disposable, non-elevated Windows profile:

```powershell
$env:HOSTLINK_WINDOWS_LIFECYCLE_DISPOSABLE = '1'
cargo test --locked -p hostlink-agent --test agent_lifecycle_windows -- --ignored
```

The test creates a private LocalAppData Agent root with spaces in its path, checks
idempotent install and update refusal, rejects a changed binary and launcher,
checks active-job stop/remove refusal, then starts the real copied Agent,
verifies its PID-bound lifecycle response and SSH banner, gracefully stops it,
checks that the listener is closed, removes the startup entry, and retains the
Agent files. It is not a Windows 7 test and is not run from this Linux worktree.
