# Windows raw Agent offline update (1C-1164)

The only installation root is the current user's OS-resolved
`%LOCALAPPDATA%\HostLink\Agent`. Stop the Agent and remove its current-user
Task Scheduler task before publication. Run a verified separate
`hostlink-agent.exe` updater outside installed `bin`; never replace a running
Agent image. The updater does not kill processes or change task registrations.

```text
hostlink-agent.exe update
hostlink-agent.exe update --version 1.2.3
```

The updater holds exclusive `update.lock` and `jobs/runner.lock`, checks no
registered task or running installed Agent image, and fails closed when offline
admission is uncertain. It uses the `self_update` GitHub RAW backend with the
exact target asset, version and published SHA-256 from private
`KDmasterLOL/hostlink`. No ZIP extraction or wrapper script is involved.
The target's `%APPDATA%\HostLink\credentials\github-token` remains a private
current-user-only protected-DACL file; updates never take a token from argv,
environment variables or Hub records.

Keep `state/manifest.json` for enrollment-key integrity, other private keys,
config and Apalis jobs. Do not publish or preserve release manifests,
`archive.sha256`, bootstrap receipts or installed PS1 wrappers. Apalis alone
owns its SQLite tables. Upstream in-process rollback handles ordinary failed
publication; there is no durable journal, automatic crash recovery or restart.
Sudden kill/power loss can require manual executable recovery.

Controller-generated PowerShell 2 bootstrap is disposable. By default it prompts
for the target PAT without echo. Explicit `--embed-github-token` prints a
secret-bearing helper; protect it and delete after use. Bootstrap downloads one
raw Agent binary and verifies SHA-256 before consuming the Hub invite, then
invokes Rust install for enrollment and executable publication. It never
installs Git or default commands.

Native Windows 7 x86/x64, Windows 11, PowerShell 2, ACL and Task Scheduler
acceptance is **NOT RUN by this packaging lane**. The retired ZIP harness
cannot supply that evidence. See [Win7 gates](WIN7_REWRITE_ACCEPTANCE.md),
[release contract](GITHUB_RELEASES.md) and [installation](AGENT_INSTALLATION.md).
