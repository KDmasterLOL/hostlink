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

## Linux

Linux uses a root-bound `systemd --user` unit through `service-manager`. The service runs as the current user. Login lingering is not automatically enabled. The Agent handles systemd SIGTERM and coordinates shutdown with its worker and tunnel.

## Windows

Windows uses a current-user Task Scheduler logon task, with a limited interactive-user token and no stored password. The task is scoped to the Agent installation root. The Agent refuses to run with elevated privileges.

Windows requires an interactive sign-in for the logon task. Stopping a task is not a guarantee that every child process completed gracefully, so operations must tolerate interrupted jobs.

## Updates

Stop the Agent and remove its owned task before replacing a Windows executable. Updates do not recreate service registrations automatically. Preserve the installation root and enrollment state. See [Windows offline update](AGENT_UPDATE_WINDOWS.md) and [installation](AGENT_INSTALLATION.md).
