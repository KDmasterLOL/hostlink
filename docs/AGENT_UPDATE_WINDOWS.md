# Windows Agent update

`hostlink-agent update [--version X.Y.Z]` starts an independent
helper from a private copy of the installed Agent. When invoked through
`hostlink exec`, pass `--allow-child-breakaway` so Windows permits the helper
to survive the SSH command's Job Object. The helper removes the owned Agent task, uses the existing verified raw-binary
updater, and registers and starts the Agent again. It attempts to restore the
task even if the update fails. Active commands and jobs are interrupted. The
command confirms helper launch; reconnect and check the Agent version to confirm
completion. The private helper copy remains under the Agent root. The Agent task
requires an interactive user session.

This path has not yet been accepted on native Windows 7 or Windows Server 2008
R2. Previously installed Agents need a separately verified first upgrade.

For the one-time transition from 0.2.4, the repository contains
[`upgrade-0.2.4-windows.ps1`](../migrations/upgrade-0.2.4-windows.ps1).
It is an operator tool, not a release asset. Supply the reviewed raw Agent,
its exact version and SHA-256. It schedules an independent worker to replace
the stopped Agent and attempts to restore the old binary if installation fails.
The worker writes its result under the private Agent root; verify the actual
connection and version after it runs. Native end-to-end acceptance is pending.

From a POSIX Controller shell, for an Agent that already supports managed
updates and child breakaway:

```sh
hostlink exec --host HOST --allow-child-breakaway --command '& "$env:LOCALAPPDATA\HostLink\Agent\bin\hostlink-agent.exe" update'
```

The helper enforces private-root identity, exclusive `update.lock` and
`jobs/runner.lock`, no active installed Agent image, and no registered task
before publication. The `self_update` GitHub RAW backend verifies the selected
version, target and SHA-256 before publication.

Release metadata comes from the GitHub API for this repository. The download URL is constructed from the exact selected version and target, rather than taken from the asset's API URL. HTTPS redirects to GitHub's asset delivery infrastructure remain enabled. Redirect hosts are not pinned: their TLS connections and the SHA-256 published in GitHub metadata are trusted, so this digest provides integrity rather than an independent signature. No authorization headers are forwarded on redirects.

All enrollment keys, private configuration, `state/manifest.json`, and Apalis SQLite jobs remain in place. Task removal does not uninstall the Agent files. An interrupted update or power loss can require manual recovery; no automatic journal replay is implemented.

See [Agent lifecycle](AGENT_LIFECYCLE.md) and [installation](AGENT_INSTALLATION.md).
