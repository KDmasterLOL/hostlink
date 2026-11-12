# Agent user service lifecycle

HostLink services run under the current user rather than as privileged system services.

## Commands

Use the installed Agent executable and its actual root/configuration:

```text
hostlink-agent service install --root ROOT --config ROOT/state/agent.json
hostlink-agent service start --root ROOT
hostlink-agent service status --root ROOT
hostlink-agent service stop --root ROOT
hostlink-agent service remove --root ROOT
```

`service install` registers the service but does not start it. `service remove` removes only the owned registration, retaining private Agent state, keys and jobs. Service status reports OS registration/running state; it is not an SSH health check.

An exact matching registration is reused by `service install`; it does not stop an already running Agent. A pending enrollment/repair transaction blocks service install/start. The [local invite repair](AGENT_INSTALLATION.md#local-repair-through-the-same-invite) workflow owns stopped publication and invokes the same lifecycle commands after success.

## Linux

Linux uses a root-bound `systemd --user` unit through `service-manager`. The service runs as the current user. Login lingering is not automatically enabled. The Agent handles systemd SIGTERM and coordinates shutdown with its worker and tunnel.

## Windows

Windows uses a current-user Task Scheduler logon task, with a limited interactive-user token and no stored password. The task is scoped to the Agent installation root. The Agent refuses to run with elevated privileges.

Ownership verification accepts Scheduler's SID or fully qualified account form for the logon trigger only when it resolves to the current user's exact SID. The principal must retain that SID, and the live Scheduler principal must report a limited run level, including when Scheduler omits its default from XML. Foreign, ambiguous, group and elevated registrations are rejected.

Windows requires an interactive sign-in for the logon task. Stopping a task is not a guarantee that every child process completed gracefully, so operations must tolerate interrupted jobs.

## Updates

Windows updates stop the Agent and attempt to restore its owned task automatically. Preserve the installation root and enrollment state. See [Windows Agent update](AGENT_UPDATE_WINDOWS.md) and [installation](AGENT_INSTALLATION.md).
