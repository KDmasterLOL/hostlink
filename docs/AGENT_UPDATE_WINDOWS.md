# Windows Agent stopped-runtime updater

## Current implementation status

`update::apply` keeps exact local archive SHA, target/version, strict raw ZIP
central-directory and duplicate-entry validation, manifest/content digests,
private-root checks, the shared job update lock, and active/unknown job
deferral. After the complete archive inventory and bounded member contents have
been checked, `self_update::Extract` performs extraction into a private
same-volume staging directory. The extracted file set, normalized ACL or mode,
sizes, and digests are read back before publication. No HTTP release selection
or download API is called; the source remains the exact local archive supplied
to `AgentUpdateRequest`.

Windows publication now uses `self_update::MoveAll` for the executable and
`install.json` as one ordered move transaction. Its stash is the private
transaction directory on the install volume. HostLink retains verified old-file
copies and its identity journal for startup fencing, service coordination,
interruption recovery, and post-error inventory checks because `MoveAll` only
offers best-effort rollback for an in-process move failure; it does not promise
power-loss recovery. HostLink checks both installed digests and the full package
manifest after a library error and fails closed if the old or new inventory is
not exactly proven. It never publishes package support files, jobs, enrollment
state, keys, configuration, or Hub state.

The registered current-user path composes the existing `service.rs` maintenance
receipt and health APIs. It keeps the owner marker and journal through
cooperative stop, publication, candidate health readback, and restoration of the
exact login registration. `Installed` is returned only after those APIs report
the authenticated new executable healthy. The updater must be a separate
verified executable beneath the same install root; a loaded Agent image is not
replaced. On Linux, the existing publication and recovery path remains in
place.

Dependency tradeoff: `self_update 1.3.1` fails to compile with only
`archive-zip` and `compression-zip-deflate`, because its library has a compile
error unless an HTTP client feature is selected. This crate enables `ureq` plus
its TLS support solely to satisfy that dependency build; HostLink does not call
the network client. This is additional dependency surface and must be reconsidered
if a later maintained release exposes the local archive primitives without an
HTTP backend.

The user-scope lifecycle owner in `service.rs` binds the current SID, install
root, executable digest, named pipe, and login registration. Maintenance
startup uses an owner-validated launch mode while the marker remains set and
login startup remains disabled. On interruption, a maintenance marker plus
validated journal is recovered conservatively: a running owner process is
stopped through its authenticated pipe, exact old backups are restored, and
only then is old registration restored. If registration was already restored,
recovery commits only a `RESTARTED` journal whose registered candidate passes a
fresh owner-bound health readback. An orphan marker, foreign Run value, unknown
process, or mismatched journal is preserved and fails closed.

`update_handoff.rs` remains the HostLink-specific bounded identity journal and
recovery model. Its deterministic ID covers old/new target, version, package,
executable and metadata digests; readback recomputes the ID. It is not a second
file publication engine.

Windows service start and ordinary managed login refuse to launch when
`.updates/handoff.json` exists or is malformed. The narrow maintenance launch
is coordinated only through the existing service owner API. Native Windows
runtime acceptance remains separate from Linux checks and source inspection.

## Slice A change size

Baseline at `0d4ab7d597c111c6c4ab87273cd5ef6d1fbfe56c`: 2,151 production lines
in `update.rs` and 588 in `update_handoff.rs` (2,739 combined), with 51 function
definitions. Slice A has 2,189 and 588 (2,777 combined), with 50 function
definitions. This adds 38 lines of production validation/orchestration while
removing one generic helper and the custom `ReplaceFileW` publish/rollback path.
The journal's `MoveFileExW` write-through persistence remains because the
library does not provide crash-durable journal phases. The dependency adds one
direct crate and 62 new package entries to `Cargo.lock`; most of that lockfile
delta is optional platform/feature metadata, while the selected local build
also compiles the required `ureq` backend and `self-replace` dependency.

## Current implementation boundary

`service.rs` now owns a crate-private maintenance receipt and coordinator
primitives. The caller must hold the existing `jobs::acquire_update_lock` for
the full transaction. Entry verifies the current SID/root, marker, exact Run
command, executable digest, and durable job state, then records maintenance in
the owner marker. Managed login startup refuses that marker before it can start
a listener. The exact current-user Run value is removed, the Agent is asked to
stop over its owner-authenticated pipe, and the updater waits on the verified
process handle. No PID is accepted from an argument and no process is
force-terminated.

The opaque receipt supports updating only the marker executable digest after
the coordinator has verified the new file, starting a candidate under the
maintenance fence, restoring the exact Run command after authenticated health
readback, and restoring old marker/registration only after exact old inventory
verification. The marker retains the prior digest across interruption. The
shared update lock remains held throughout the update and rollback paths.

The managed path is implemented but not yet accepted as a Windows runtime
feature. The disposable Windows lifecycle test remains ignored and requires
the documented separately verified standard-user profile harness. Linux
checks and cross-target builds do not prove actual HKCU, process-handle,
concurrent login, restart, or rollback behavior. No native managed maintenance
transaction was run in this profile.

## Required helper protocol

The installed executable cannot replace its own loaded image. The updater must
be a separate, private, verified process on the install volume. It must use the
existing owner-bound stop path and shared job lock, prove that no durable job
is Prepared, Running, Interrupted, corrupt, or unknown, and wait for the
authenticated Agent process handle to signal before publication. Reconnect
must never replay a started job.

The managed-live helper validates archive SHA, target, semantic version, complete
manifest and old installed inventory before service mutation. It durably records
`STAGED`, `BACKED_UP`, `PUBLISHED`, `VERIFIED`, and `RESTARTED`, with exact old
and new package, executable and metadata identities. Every journal transition
must be atomic and recoverable; transaction IDs must be recomputed from the
validated journal contents. It must verify the backup before publication,
verify the full new installed inventory before restart, and verify the new
Agent's authenticated lifecycle response before reporting `Installed`. A
failed publication or bounded restart must restore and verify the old
executable and metadata. Ambiguous states preserve all candidates and the
journal and return an error.

The recovery planner maps validated journal phases plus observed old/new/backup
executable and metadata hashes to one action. File-level tests exercise exact
hash observations and fail-closed recovery decisions, but the planner must not
be treated as having performed filesystem publication. Active, interrupted,
unreadable, or unknown durable jobs must defer
before staging, journal recovery, or publication. The update lock must remain
held across the full operation and startup must not race login registration.

## Windows filesystem and wait constraints

`self_update::MoveAll` uses same-volume filesystem renames and retains displaced
files in its private stash. HostLink sets and verifies the current-user-only ACL
on extracted, staged, installed, backup, and journal files because rename does
not merge the destination ACL. The source file must be closed before moving.
`WaitForSingleObject` can
wait on a process handle with `SYNCHRONIZE` and is supported by Windows 7
([Microsoft API reference](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobject)).
Do not infer process exit from a missing pipe. Reject reparse points in the
root, stage, backup, metadata, and journal paths. The staged executable and
stash must be on the same volume as the installed binary. Reboot-delayed
replacement, admin/SYSTEM elevation, guessed PID
termination, and a second execution transport are forbidden.

## Acceptance still required

Run source-exact, disposable-profile tests on Windows 11 and Windows 7 x64 and
x86 separately. The tests must cover owner/SID/path/hash mismatch, foreign or
stale PID, active/Interrupted/unknown jobs with no preceding mutation, reparse
paths, backup hash mismatch, locked file, every journal transition and crash
recovery, failed restart and rollback, idempotent recovery, and no login
auto-run race or job replay. Windows update tests must never use the real WORK
profile or an installed service. Cross-compilation and Linux recovery-planner
tests do not prove Windows publication behavior.

## Windows 11 live registered-Agent acceptance

`scripts/verify-windows-agent-updater-native.ps1` runs the real Agent CLI in a
disposable, standard, interactive Windows 11 x64 user profile. It writes only
the OS-resolved `LocalAppData\HostLink\Agent` tree and its one derived
`HKCU\...\Run` value. It refuses the ordinary WORK profile, elevated/Admin/
SYSTEM identities, existing HostLink roots or registration, missing or
mismatched owner sentinel, reparse paths, foreign allow ACEs, and unreadable
pre-existing OneC registry/service inventories. LocalAppData comes from
`SHGetFolderPathW`; `LOCALAPPDATA` is checked only for disagreement. The harness
does not create or control an SCM service.

This gate requires **two distinct source commits and two distinct executable
SHA-256 values**. Both artifacts use `x86_64-win7-windows-msvc`; each package
receipt must bind its own clean source/build receipt. The harness also requires
all package support files except `hostlink-agent.exe` to have identical bytes,
so the Agent-only update does not accidentally test unsupported support-file
changes. Package A is installed and started. The separate updater executable
is copied from package B's verified sidecar, then performs the live A-to-B
update. The installed executable SHA must change from A's source-bound SHA to
B's source-bound SHA, and B must pass registered status and authenticated
loopback health.

Prepare a separate, owner-only disposable standard user profile. It must not be
`ALEXROVICH\TIS` and must not belong to local Administrators. Sign in
interactively as that user and create this sentinel directly in the OS-resolved
profile directory, binding both full lowercase source SHAs:

```powershell
$sourceShaA = 'FULL_LOWERCASE_40_CHARACTER_SOURCE_A_SHA'
$sourceShaB = 'FULL_LOWERCASE_40_CHARACTER_SOURCE_B_SHA'
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$sentinel = Join-Path ([Environment]::GetFolderPath('UserProfile')) '.hostlink-disposable-profile'
Set-Content -LiteralPath $sentinel -Encoding ASCII -NoNewline -Value "HOSTLINK-NATIVE-UPDATER-DISPOSABLE|SID=$sid|SOURCE_A=$sourceShaA|SOURCE_B=$sourceShaB"
icacls.exe $sentinel /inheritance:r /grant:r "${sid}:(F)"
```

Build and package each source from its own clean committed checkout. Choose a
valid B semantic version different from A. Keep the harness from the tested
revision alongside the copied artifacts; run the build and package commands in
each exact source checkout. Copy both resulting build roots and package roots
into private evidence directories owned by the disposable user. Example from
each checkout (set `VERSION` to that checkout's crate version):

```sh
SOURCE_SHA="$(git rev-parse HEAD)"
VERSION="$(python3 -c 'import tomllib; print(tomllib.load(open("crates/agent/Cargo.toml", "rb"))["package"]["version"])')"
scripts/build-win7-candidate.sh \
  --source-sha "$SOURCE_SHA" \
  --output-dir "target/native-updater-$SOURCE_SHA"
scripts/package-hostlink-agent.py \
  --source-sha "$SOURCE_SHA" \
  --target x86_64-win7-windows-msvc \
  --version "$VERSION" \
  --binary "target/native-updater-$SOURCE_SHA/x86_64-win7-windows-msvc/hostlink-agent.exe" \
  --build-receipt "target/native-updater-$SOURCE_SHA/receipt.json" \
  --output-dir "target/native-updater-$SOURCE_SHA/package-$VERSION"
```

Copy the committed harness into the disposable evidence directory, and obtain
the protected WORK SID/profile values from a separately verified inventory.
Do not infer or substitute them. Run unelevated in Windows PowerShell 5 or
newer, using exact copied paths and actual package versions:

```powershell
.\verify-windows-agent-updater-native.ps1 `
  -SourceShaA FULL_LOWERCASE_40_CHARACTER_SOURCE_A_SHA `
  -SourceShaB FULL_LOWERCASE_40_CHARACTER_SOURCE_B_SHA `
  -Target x86_64-win7-windows-msvc `
  -ExpectedDisposableSid S-1-5-21-... `
  -ExpectedDisposableProfile 'C:\Users\hostlink-disposable' `
  -ProtectedWorkSid S-1-5-21-... `
  -ProtectedWorkProfile 'C:\Users\PROTECTED-WORK-PROFILE' `
  -SentinelPath 'C:\Users\hostlink-disposable\.hostlink-disposable-profile' `
  -BuildRootA 'C:\HostLinkEvidence\build-A' `
  -BuildRootB 'C:\HostLinkEvidence\build-B' `
  -PackageARoot 'C:\HostLinkEvidence\package-A' `
  -PackageBRoot 'C:\HostLinkEvidence\package-B'
```

Assertions cover real install/start/status/update/remove CLI operations; distinct
source and executable hashes; B as the separate updater; old PID exit and a new
healthy PID; exact package metadata and Run-value readback; unchanged terminal
job bytes; bad digest rejection; and distinct negative diagnostics for
Prepared/Running/Interrupted jobs (`jobs not terminal`) versus malformed job
records (`job record is invalid or incomplete`). Both negative classes must
leave installed files and authenticated B health unchanged. The harness compares
pre-existing HKCU Run values, OneC registry state, and the Windows service
inventory before and after.

**Candidate health-failure rollback is explicitly `NOT_TESTED`.** This harness
does not stop A before update and does not claim that restarting the old binary
proves rollback. A deterministic candidate-health failure and rollback proof
remain a separate native acceptance item. Cleanup removes registration and the
test tree only when source/SID/candidate-hash ownership matches and every
remaining path matches the expected inventory. Unknown files, directories,
journal state, reparse points, or ambiguous fixture content cause the harness
to preserve the root and fail for manual evidence recovery.

This procedure has not run in the ordinary WORK profile or in this development
environment. Static tests and a PowerShell parse do not count as live
acceptance. Preserve both source SHAs, build/package receipt hashes and
executable SHAs, target, Windows build/architecture, PowerShell version,
disposable SID, CLI output, and cleanup result with the evidence. Windows 11
x64 does not satisfy either native Windows 7 runtime gate.
