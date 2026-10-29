# 1C-1114 Windows replacement evidence — 2026-10-29

Scope: only `hostlink-1114-windows`, branch
`task/1c-1114-windows-task-scheduler`, base HEAD
`77aad550d73224fa9dc444576d5d9fb776c8811e`.
No main/dev ref, tag, release, deployed machine, Windows profile or installed
Agent was modified. Linux service and Linux updater source files are unchanged.

Windows lifecycle now uses Task Scheduler 2.0 COM through Microsoft's existing
`windows 0.62.2` dependency. `roxmltree 0.21.1` handles structural XML identity
comparison. No new scheduler, process owner, IPC, marker or result store exists.
The old Run/VBS/pipe/maintenance/admission implementation and hidden run flags
are removed. Legacy state is detected read-only and refused. Public service
entrypoints, status fields and visible command syntax remain.

Updater is offline only, requiring task removal, runtime lock and stopped-image
checks. Archive SHA/manifest/inventory/private filesystem validation,
self_update publication, backup readback, rollback and journal recovery remain.
It never starts or registers a candidate. Retired RESTARTED journals are rejected.

## Executed verification

Toolchain: cargo 1.99.1. All Rust commands used `--locked --offline`.

| Check | Result |
| --- | --- |
| `cargo fmt --all -- --check` | PASS |
| `cargo check --workspace --all-targets` | PASS |
| `cargo clippy --workspace --all-targets -- -D warnings` | PASS |
| `cargo xwin check --workspace --target x86_64-pc-windows-msvc --all-targets` | PASS |
| `cargo xwin clippy --workspace --target x86_64-pc-windows-msvc --all-targets -- -D warnings` | PASS |
| Same xwin check/clippy for `i686-pc-windows-msvc` | PASS |
| Agent-only xwin check/clippy with `--lib --tests` on both architectures | PASS |
| XML identity/escaping unit tests | 2 PASS |
| Offline journal/recovery unit tests | 10 PASS |
| CLI argument/retired-flag tests | 3 PASS |
| Updater integration suite | 27 PASS |
| `cargo test --workspace --no-fail-fast -- --test-threads=1` | 135 passed, 19 failed, 2 ignored; exit 101 |
| `python3 -m unittest discover -s scripts/tests` | 35 tests: 34 passed, 1 skipped |
| `git diff --check` | PASS |

The 19 workspace failures are loopback fixture failures under sandbox `EPERM`
(9 test targets). Two enrollment assertions also fail because zero candidate
ports can be reserved. No failing network test is counted as PASS. Logs are
`/tmp/hostlink-1114-{linux-check,linux-clippy,linux-tests-all,x64-check,x64-clippy,x86-check,x86-clippy,xml-tests,recovery-tests,cli-tests,script-tests}.log`.

The first xwin attempt failed because the shared cache was read-only. Successful
runs used an independent writable SDK copy at `/tmp/hostlink-1114-xwin` via
`XWIN_CACHE_DIR`; the shared cache was not modified.

## Outstanding gates and commit blocker

Native Windows 11, Windows 7 SP1 x64/x86, PowerShell harness execution, actual
Scheduler XML normalization/logon/termination, process-tree cleanup and offline
update/recovery/rollback are NOT RUN. Generic MSVC checking does not establish
Win7 imports or runtime acceptance. The mutating native lifecycle test remains
ignored and requires explicit disposable SID/profile/binary-hash guards.
Task Scheduler stop may terminate the Agent: graceful shutdown and descendant
cleanup are not guaranteed. Apalis commands may replay side effects.

No commit was created. Scoped `git add` failed with:

```text
fatal: Unable to create '/home/kd_master/Documents/PARA/2. Projects/hostlink/.git/worktrees/hostlink-1114-windows/index.lock': Read-only file system
```

HEAD remains the base SHA above; all source, test and documentation changes are
retained as an unstaged worktree diff. No push was attempted.
