# HostLink Agent user lifecycle

The Hub and local Agent have separate lifecycles. `hostlink remove NAME --yes`
revokes Hub managed access. It does not contact or uninstall the Agent. The
commands below manage only a new HostLink Agent installed under the current
user's private root; they never adopt the legacy Agent, its process, ports,
keys, authorized keys, SSH account, or token.

## Linux systemd user service

The Agent uses `service-manager 0.11.0` with `SystemdServiceManager::user()`.
This delegates installation, enabling, start, stop, status and removal to the
current user's systemd, not a HostLink PID or service-marker subsystem.

```sh
hostlink-agent check --config ROOT/state/agent.json
hostlink-agent service install --root ROOT --config ROOT/state/agent.json
hostlink-agent service start --root ROOT
hostlink-agent service status --root ROOT
hostlink-agent service stop --root ROOT
hostlink-agent service remove --root ROOT
```

Installation requires the user-owned private root, the exact
`ROOT/bin/hostlink-agent` executable and `ROOT/state/agent.json` config.
Each canonical root has a deterministic service name
`hostlink-agent-<root-hash>.service`, under the user systemd directory
(`$XDG_CONFIG_HOME/systemd/user` or `~/.config/systemd/user`).
The unit runs `run --config=...`, is enabled on login but **not started**
by install, and uses `Restart=on-failure`, a fixed 15-second retry delay
and systemd's five-starts-per-five-minutes throttle. No root privilege,
systemd system unit, `loginctl enable-linger` or version-254-only exponential
restart feature is required.

There is **no HostLink JSON ownership marker**, internal PID registry,
custom process supervisor or executable-hash attestation. The unit's
identity and command must match before modifying its registration; conflicting or modified units,
symlinked/private-ownership-invalid roots are refused. A legacy
`.hostlink-user-service.json` marker blocks **new installation**, not
status, stop or removal of an already verified user unit.
Legacy registrations need an explicit reviewed migration using their matching
old Agent; they are never automatically adopted or deleted.

`service status` reports **only** installed/running state from systemd.
It makes no SSH connection and does not assert enrollment, package integrity,
or Hub reachability. `hostlink-agent check` validates the Agent configuration;
`hostlink list --check` separately checks authenticated remote SSH access.

`stop` asks systemd to stop the unit. The Agent now handles **SIGTERM**
as well as Ctrl+C, cancelling SSH, Apalis and outbound tunnel through
`runtime.rs`. Pending Apalis jobs are preserved; interrupted jobs can
replay side effects. `remove` stops/disables and unregisters **only**
the matching unit. It **preserves** the Agent executable, config, keys,
enrollment, transfers and jobs; deletion of those user-owned files is a
separate explicit operation.

For a local Linux Agent update, first stop the user unit, apply the verified
update while the `runner.lock` is free, and then start the unit again.
Hub revocation and the local service lifecycle are separate operations.

## Windows 7 and Windows 11 current-user Task Scheduler task

Windows uses Task Scheduler 2.0 through Microsoft's `windows` COM bindings.
The direct API remains deliberately small: `schtasks.exe` would introduce
interactive password handling and locale-sensitive status parsing; `planif`
only covers task construction/registration, not the complete lifecycle.
It creates one SID/root-derived `HostLinkAgent-v2-...` task with a current-user
logon trigger, `InteractiveToken`, `LeastPrivilege`, no password, one direct
Agent executable action and `IgnoreNew` instance policy. It requires an
interactive sign-in, does not restart on failure and has no execution time
limit. `install` uses `TASK_CREATE` for a new task and `TASK_UPDATE` for a
verified existing task; it stops a running owned task before refreshing its
registration, without starting it again. `start` explicitly runs the task.
No administrator privilege is required for registration, and the service
lifecycle no longer checks whether the installer process is elevated.
No SYSTEM service, HKCU Run writer, VBS launcher, private service marker,
lifecycle named pipe or PID owner is used.

The public commands above remain, with a minimal `ServiceStatus` containing
`installed` and `active` only. `active` means the Task Scheduler reports a
running/queued task or an extant instance, **not** that SSH/Hub is healthy.
`start` waits up to ten seconds for Scheduler activation. Ownership checks
before dangerous operations compare the registered current-user identity,
action and Agent root/config and essential task policy; no executable SHA
attestation or full XML-comparison engine is part of the service lifecycle.
`TASK_CREATE` refuses an occupied task name; `TASK_UPDATE` is used only
after verifying an owned registration. Install never intentionally
overwrites a foreign definition.
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

The Windows service accepts an Agent root and immediate parent with protected
owner-only ACLs, even outside LocalAppData. Vendored `private-fs` opens
these via retained file handles and rejects symlink/reparse redirection.
Its strict Windows policy requires exactly one non-inheritable full-control
ACE for the current user (no `OICI` inheritance); the installer uses that
policy for newly created directories and files. Existing Agent roots with
older inheritable ACLs require a deliberate stopped-state migration and are
not silently repaired. Other readable ancestor directories are not by
themselves an automatic failure.
Read-only service status does not inspect filesystem ACLs. Install, start,
stop and remove serialize through the protected `update.lock`; installation
and explicit start check private root permissions. Enrollment validates
secrets separately, and the Agent runtime refuses elevated Windows execution
before launching SSH, Apalis jobs and its reverse tunnel.
The installed executable must be `ROOT/bin/hostlink-agent.exe` and config
`ROOT/state/agent.json`. Historical marker/VBS files are inert and do not
block installing or refreshing the verified Task Scheduler registration.
However, an existing root-derived legacy HKCU Run registration still blocks
install, start and offline update: deleting it without first stopping the old
process can start two independent Agents. The Run value and old files are
preserved. Stop/remove the old registration using its matching old Agent
before reinstallation; a verified automatic migration has not been implemented.
Hidden `run --managed-service` and
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

The fixture checks task ownership and execution fields, collision/tamper
refusal, owned-task refresh, stale legacy markers, foreign HKCU Run refusal,
install/start, stopped stop/remove, running removal, SSH readiness and
enrollment retention. The runner checks unchanged foreign HKCU Run values and
root-task snapshots.
A failed cleanup preserves the fixture root and unresolved task for diagnosis.
Win7 logon and offline update/recovery require separately authorized disposable
native execution; the Windows 11 runner does not satisfy that gate.

API references: [current-user task security](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks),
[Stop](https://learn.microsoft.com/en-us/windows/win32/api/taskschd/nf-taskschd-iregisteredtask-stop),
[AllowHardTerminate](https://learn.microsoft.com/en-us/windows/win32/taskschd/tasksettings-allowhardterminate).
