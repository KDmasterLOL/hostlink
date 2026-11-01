# Binary-only Agent installation and update (1C-1164)

Use only raw executable assets from the fixed private
`KDmasterLOL/hostlink` GitHub Releases repository. The full asset/credential
contract is [GitHub Releases](GITHUB_RELEASES.md).

## One stable installation root

| Platform | Root |
| --- | --- |
| Linux | absolute `$XDG_DATA_HOME/hostlink/Agent`, otherwise `$HOME/.local/share/hostlink/Agent` |
| Windows | current-user OS-resolved `%LOCALAPPDATA%\HostLink\Agent` |

No randomized installation directories or second roots. Temporary download
staging does not become an installation root. Private credentials remain in
the user's config location, separate from the Agent root.

The Rust Agent install operation enrolls and publishes the executable in
`ROOT/bin`. Controller renders disposable Win7 PowerShell 2 or POSIX bootstrap;
no installer/run/update wrappers remain installed. No Git or other default
tools are installed. Verify the single downloaded binary's SHA-256 before
consuming the one-use Hub invitation. Do not replay uncertain enrollment.

`ROOT/state/manifest.json` is the private enrollment-key identity manifest
and **must remain**. It is distinct from the removed release manifest.
Keys, config, jobs and Apalis SQLite state persist outside the executable.
There is no installed release `manifest.json`, `archive.sha256` or
`bootstrap-receipt.json`.

## Installed update

```text
hostlink-agent update
hostlink-agent update --version 1.2.3
```

The updater reads the target-owned private GitHub credential. The upstream
`self_update` GitHub backend selects RAW bytes from the exact named target
asset and verifies the published SHA-256 for the selected release version.
It uses only the fixed repository, without arbitrary artifact URLs, token
CLI/env overrides or a second publisher.

Hold exclusive `ROOT/update.lock` and `ROOT/jobs/runner.lock` for publication;
the Agent must be stopped. Windows additionally requires removal of the
current-user Task Scheduler task and a verified separate updater outside
installed `bin`. See [Windows offline update](AGENT_UPDATE_WINDOWS.md).
No updater reads Apalis tables or rewrites its state. No automatic restart.
Upstream in-process rollback handles failed publication; sudden kill/power
loss can require manual recovery. There is no durable update journal.

## Verification status

Packaging/staging tests prove exact local raw bytes and provenance bindings.
They do not prove the separate Rust/Controller implementation, a real private
release download, native Windows ACLs, service/task lifecycle or update.
Those gates run after lane integration. See [source layout](SOURCE_LAYOUT.md)
and [Win7 acceptance](WIN7_REWRITE_ACCEPTANCE.md).
