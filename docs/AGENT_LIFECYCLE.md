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

## Windows

`hostlink-agent service` currently returns `Unsupported` outside Linux. No
PowerShell 2 compatible, owner-bound Windows login startup and process control
implementation is included yet. In particular, a scheduled task is not assumed
to be available without administrator credentials. Windows 11 and Windows 7
must remain explicit foreground `hostlink-agent run --config ...` sessions
until a separately verified current-user startup owner is implemented. Do not
use SYSTEM, a machine-wide service, or the legacy Agent service.

This work has no native Windows acceptance result. Linux unit-fixture tests do
not establish Windows 11 or Windows 7 / PowerShell 2 behavior.
