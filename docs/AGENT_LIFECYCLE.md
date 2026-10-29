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

## Windows 7 and Windows 11 current-user Task Scheduler task

Windows uses Task Scheduler 2.0 through Microsoft's `windows` COM bindings.
It creates one SID/root-derived `HostLinkAgent-v2-...` task with a current-user
logon trigger, `InteractiveToken`, `LeastPrivilege`, no password, one direct
Agent executable action and `IgnoreNew` instance policy. It requires an
interactive sign-in, does not restart on failure and has no execution time
limit. `install` registers without starting; `start` explicitly runs the task.
No administrator, SYSTEM, Windows service, HKCU Run writer, VBS launcher,
private service marker, lifecycle named pipe or PID owner is used.

The public commands above and `ServiceStatus` are retained. Windows `pid` is
`None`; `active` means Scheduler running/queued state or an extant task instance.
The SSH banner is a separate health probe, not authenticated process identity.
`start` waits up to ten seconds for Scheduler activation; it does not certify
SSH/Hub readiness. `status` fails if the exact expected task XML differs,
including SID, action/config path, trigger, settings and executable SHA-256 in
the task description. Both expected and registered XML are normalized through
the Scheduler's own schema before structural comparison. `TASK_CREATE` refuses
an occupied task name atomically; install never overwrites a foreign definition.
Unknown state, COM errors and access denial fail closed without localized text
parsing. `stop`/`remove` also work when the task is already stopped.

**Task Scheduler stop is OS termination, not guaranteed graceful shutdown.**
`AllowHardTerminate=true` permits Scheduler termination. No bespoke IPC is
retained to promise grace. Foreground `run` still supports Ctrl+C cancellation.
Scheduler termination may interrupt commands and their descendants; native
containment/cleanup must be verified separately. Apalis retains queued state
and may replay interrupted work with repeated side effects. `remove` stops all
task instances and deletes only the verified task, preserving the executable,
enrollment, keys, jobs and every other Agent file.

Roots remain protected current-user-only descendants of OS-resolved LocalAppData,
with protected private ancestors, no reparse points and verified enrollment.
The installed executable must be `ROOT/bin/hostlink-agent.exe` and config
`ROOT/state/agent.json`. Legacy `.hostlink-user-service.json`, VBS,
maintenance/admission/temporary-marker files and the old root-derived HKCU Run
value are rejected and preserved. Use the matching legacy executable under a
separately authorized migration to remove the old registration; this version
cannot adopt or uninstall it. Hidden `run --managed-service` and
`--maintenance-start` flags are removed and rejected.

Windows updates are offline only: stop/remove the task, run the separate private
updater, then explicitly install/start the task again. See
[Windows updater](AGENT_UPDATE_WINDOWS.md). Service mutations share the updater
lock; startup refuses a pending update journal after taking the runtime lock.
Neither lifecycle nor updater reads Apalis tables.

## Native Windows acceptance gate

Native Windows 11 and Windows 7 SP1 x64/x86 acceptance is **NOT RUN** for this
replacement. Generic MSVC cross-checks do not prove NT6.1 compatibility, actual
task XML normalization, logon activation, task termination, child containment,
sharing/ACL behavior or offline update/recovery. Exact Win7 target builds and
PE import inspection remain mandatory before Win7 release acceptance.

The integration test is ignored by default and requires a disposable standard
Windows user, matching SID/profile and exact Agent binary SHA. Never run it
in WORK, SYSTEM, an elevated shell or on a real installed Agent. The Windows 11
runner defaults to preflight only:

```powershell
.\scripts\verify-windows-agent-lifecycle.ps1 `
  -ExpectedDisposableSid 'S-1-5-21-...-...' `
  -ExpectedDisposableProfile 'C:\Users\HostLinkLifecycleTest' `
  -ProtectedWorkSid 'S-1-5-21-...-...' `
  -ProtectedWorkProfile 'C:\Users\WORK' `
  -RunAcceptance
```

The fixture checks exact task XML, collision/tamper/legacy refusal, idempotent
install/start, stopped stop/remove, running removal, SSH readiness and enrollment
retention. The runner checks unchanged HKCU Run values and root-task snapshots.
A failed cleanup preserves the fixture root and unresolved task for diagnosis.
Win7 logon and offline update/recovery require separately authorized disposable
native execution; the Windows 11 runner does not satisfy that gate.

API references: [current-user task security](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks),
[Stop](https://learn.microsoft.com/en-us/windows/win32/api/taskschd/nf-taskschd-iregisteredtask-stop),
[AllowHardTerminate](https://learn.microsoft.com/en-us/windows/win32/taskschd/tasksettings-allowhardterminate).
