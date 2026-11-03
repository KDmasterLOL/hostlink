# Windows offline Agent update

Windows Agent binaries are updated only while their user service is offline. The updater never replaces the running executable.

## Procedure

1. Stop the Agent through its owned user Task Scheduler registration.
2. Remove that task with `hostlink-agent service remove --root ROOT`.
3. Confirm the installed Agent image is no longer running.
4. From a verified **separate** `hostlink-agent.exe` outside `ROOT/bin`, execute `update --root ROOT` or `update --root ROOT --version X.Y.Z`.
5. Reinstall the owned task with `service install --root ROOT --config ROOT/state/agent.json`, then `service start --root ROOT`.

The updater enforces private-root identity, exclusive `update.lock` and `jobs/runner.lock`, no active installed Agent image, and no registered task. The `self_update` GitHub RAW backend verifies the selected version, target and SHA-256 before publication.

All enrollment keys, private configuration, `state/manifest.json`, and Apalis SQLite jobs remain in place. Task removal does not uninstall the Agent files. An interrupted update or power loss can require manual recovery; no automatic journal replay or restart is implemented.

See [Agent lifecycle](AGENT_LIFECYCLE.md) and [installation](AGENT_INSTALLATION.md).
