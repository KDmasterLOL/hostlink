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
symlink, changed executable, edited unit, or missing enrollment config
fails closed.

`status` reports the unit state, owning uid, exact main PID when active, source
executable SHA-256, and whether the loopback listener returns an SSH 2.0 banner. It also
reports whether local enrollment metadata exists. It never claims Hub
reachability: use `hostlink list --check` for fresh Hub inventory plus bounded
pinned SSH checks. Enrollment metadata alone does not mean the Agent is online.

`stop` cancels the Agent process; Apalis owns its queue and does not require
jobs to be terminal before stopping. Pending records remain durable, while
interrupted commands may replay after restart, including side effects.
`remove` stops and disables only the exact owned user unit, removes the exact
verified Agent executable, and deletes its unit and service marker. It
deliberately retains the Agent root, credentials, enrollment metadata and jobs
for recovery or a separately reviewed data deletion.

Reinstalling is idempotent only when root, config and executable hash match.
Replacing the Agent binary is not performed while it is running;
stop and remove the user service, then use the source-exact Agent-only
update workflow and install the updated executable before registering
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
It asks the Agent to shut down through its normal cancellation path, without
inspecting its private Apalis database. It waits at most ten seconds and
never terminates a PID or process tree by guesswork. `remove` performs the same
authenticated stop, then removes only the
exact HKCU value and ownership marker after process exit is proven. Windows
keeps the executable, config, credentials, enrollment record and jobs in place
for recovery; pending jobs remain in Apalis and interrupted commands may
replay after restart. Hub revocation remains independent. Managed Windows
updates use the owner-authenticated stopped-runtime maintenance handoff;
the updater does not replace a loaded executable. A changed binary, marker, registry value, SID, ACL, or
reparse path fails closed.

During the separately owned Windows Agent update, maintenance startup is admitted
only by a one-use capability issued after the old authenticated process handle
has signaled exit and the published candidate digest has been verified. The
capability is delivered over the spawned candidate's inherited private stdin
pipe; it is never placed in the command line, output, or a listener. The
candidate atomically consumes a current-user-private admission record bound to
its exact root, SID, executable SHA-256, and unique maintenance transaction.
Missing, early, stale, replayed, or competing claims fail closed. Normal login
startup remains disabled by the owner maintenance marker and absent exact HKCU
Run value; ordinary `service start` continues to refuse maintenance. This
admission is independent of updater journal formats and does not authorize
process termination.

## Native Windows 11 acceptance gate

Native lifecycle acceptance has **not** passed yet. The integration test is
ignored by default because install writes one value to the current user's HKCU
Run key. Run the positive gate only from a separately created, standard (not
Administrators) Windows 11 user account after signing into that account. Never
run it in the WORK profile, from SYSTEM, or in an elevated shell. Windows 7
NT6.1 x64/x86 is a separate future native gate; neither this script nor a
cross-compile proves it.

The script defaults to preflight-only and does not set the test opt-in or invoke
the lifecycle test. Supply independently recorded disposable SID/profile and
protected WORK SID/profile to the explicit acceptance mode:

```powershell
.\scripts\verify-windows-agent-lifecycle.ps1 `
  -ExpectedDisposableSid 'S-1-5-21-...-...' `
  -ExpectedDisposableProfile 'C:\Users\HostLinkLifecycleTest' `
  -ProtectedWorkSid 'S-1-5-21-...-...' `
  -ProtectedWorkProfile 'C:\Users\WORK' `
  -RunAcceptance
```

Before setting the opt-in, the script verifies the current token SID and
OS-resolved profile, excludes SYSTEM and Administrators membership/elevation,
requires a loaded profile and Windows 11 build 22000+, and confirms the
disposable identity differs from WORK. It builds the locked Agent and ignored
integration test, records the exact Agent SHA-256, and passes that hash plus
identity to the test. The test checks its `CARGO_BIN_EXE` hash and the installed
copy against that value. Only then does the script set
`HOSTLINK_WINDOWS_LIFECYCLE_DISPOSABLE=1` for the one targeted ignored test.
It verifies the source hash stayed fixed, the exact root-derived Run value is
gone, no test Agent remains under the disposable profile, and all other HKCU
Run values match the pre-run snapshot. The opt-in is cleared/restored on exit.

Preflight-only invocation (omit `-RunAcceptance`) and a WORK-profile attempt
must leave the HKCU Run snapshot unchanged. Any identity mismatch aborts before
the test opt-in is set. The positive fixture tests a LocalAppData root with
spaces and shell metacharacters, protected ACLs, unrelated-root refusal,
shared-ancestor rejection, install/reinstall/update refusal, binary and
launcher tampering, an unrelated process reusing a stale lifecycle PID,
preservation of Apalis jobs without direct SQL interlocks, repeated
authenticated status, SSH banner, graceful stop, exact Run-value removal and
enrollment-file retention. Its fixture path includes spaces and shell
metacharacters to exercise Windows command quoting. It never refers to or
adopts the old OneC Agent. A passing Linux compile or cross-target check is not
native acceptance.

If native acceptance fails before confirmed removal, the test cleanup never
starts an Agent or recursively removes an installed root with an unresolved
owner marker. Investigate the disposable user's exact HKCU Run value, owner
marker and process handle before any manual recovery or directory deletion.
