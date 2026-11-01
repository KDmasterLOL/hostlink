# Windows Agent offline URL update (1C-1147)

Use a fully stopped, unregistered Agent. Stop/remove its current-user Task Scheduler
task with the existing service commands, then invoke a verified separate copy of
hostlink-agent.exe beneath the private root, **outside bin**, with:

```text
hostlink-agent.exe update --root ROOT --url EXACT_HTTPS_URL --sha256 INDEPENDENT_SHA256 --target EXACT_TARGET --version EXACT_VERSION
```

The updater does not stop/remove/register/start a task or change HKCU. An installed
task (even stopped), held runner/update lock or active
installed Agent image is an error. It never kills a PID. The root remains the exact
OS-resolved LocalAppData/HostLink/Agent, with private-fs protected root and parent,
without symlink/reparse aliases. Win7 uses SHGetFolderPathW and existing process
snapshot APIs. `same-file 1.0.6` compares file identities for the separate updater
and matching running images, avoiding a second hand-written Windows file-ID API.

Only one installed updater exists: high-level self_update custom::Update, pinned to
1.3.1. Its ReleaseSource contains exactly the supplied URL/version/target. SHA-256,
bounded ZIP/member/manifest checks and installed inventory are mandatory. Redirects
and retries are disabled; the download timeout is 30 seconds. There is no remote
release discovery, local ZIP fallback, provider fallback or "latest" selection.

Downloaded archives, temporary bundles and installed bin are **nonsecret**, using
upstream native temporary filesystem permissions/ACLs. No private-fs ACL hardening
is applied to those updater files. Persistent root, state, jobs, keys, configuration
and OS lock files retain their existing private-fs protection. The updater does not
open SQLite or interpret job state; pending tasks survive for the next Agent start.

The verify_binary hook verifies extracted source manifest/file identities
and writes a 64-character independently pinned `archive.sha256` beside the
**unchanged** `manifest.json` in the staged bundle. It then validates
the entire inventory before the library swaps `bin/`. On startup/update the
installed source manifest and digest are both read back and verified;
no obsolete install.json compatibility reader exists.

On an ordinary publication error self_update attempts to restore the old bundle.
Rollback is best-effort; a failed restoration is logged upstream and the original
error is returned. **There is no durable journal or automatic recovery after kill
or power loss. A kill between renames can leave bin absent and an unnamed stash.**
Stop and reconcile the installation manually in that case; do not claim the
Agent was updated. There is no legacy journal compatibility engine or
automatic restart.
After success explicitly reinstall/start the owned task. Service status is OS
registration/running state, not binary SHA or SSH health attestation.

The PowerShell 2-compatible Update-HostLink-Agent.ps1 wrapper forwards the URL pins
to the supplied separate updater and propagates failure. Run-HostLink-Agent.ps1
accepts a native-ACL bundle while retaining private root/config checks. The
first-install scripts and bootstrap-verify/bootstrap-finalize commands are retained.

Native Windows11/Win7 x64/x86, PowerShell 2, Scheduler concurrency and actual process
checks remain separate acceptance gates. Cross checks are compile/static evidence.
See [implementation and verification](SELF_UPDATE_REWRITE.md).
