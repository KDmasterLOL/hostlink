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

## Outstanding native Windows acceptance gates

Native Windows 11, Windows 7 SP1 x64/x86, PowerShell harness execution, actual
Scheduler XML normalization/logon/termination, process-tree cleanup and offline
update/recovery/rollback are NOT RUN. Generic MSVC checking does not establish
Win7 imports or runtime acceptance. The mutating native lifecycle test remains
ignored and requires explicit disposable SID/profile/binary-hash guards.
Task Scheduler stop may terminate the Agent: graceful shutdown and descendant
cleanup are not guaranteed. Apalis commands may replay side effects.

## Source integration and unrestricted workspace verification

The isolated Windows branch's sandbox did not permit writing its Git index.
The main coordinator subsequently committed the exact source diff outside
that sandbox as `603349d7fb9ea5e817a7bc3d4c590d854a349271` and merged it
with the separately verified Linux service-manager commit
`cd574957f7557ba58f53f52a4979fb9c4dbece5c`.

On the combined integration source, **outside the restricted Codex sandbox**,
the following checks all PASS:

* `cargo fmt --all -- --check`;
* `cargo check --offline --locked --workspace --all-targets`;
* `cargo clippy --offline --locked --workspace --all-targets -- -D warnings`;
* `cargo xwin check` + `cargo xwin clippy -- -D warnings` for the entire
  workspace on both `x86_64-pc-windows-msvc` and `i686-pc-windows-msvc`;
* `cargo test --offline --locked --workspace -- --test-threads=1` —
  **PASS**: 43 Agent unit tests, 4 binary CLI tests, 3 Linux lifecycle
  tests (including legacy-registration refusal), 27 updater tests,
  18 Hub tests and all Client/SSH/SFTP/gateway integration tests.
  Two external Caddy/OpenSSH fixtures remain intentionally ignored.

This clears the isolated Linux sandbox `EPERM` failures, but does not
constitute native Windows test execution. Windows 7/11 Scheduler state,
COM XML normalization, logon activation and service stop/child containment
remain untested on a native Windows host. No Windows registration was
created or removed by these Linux-hosted tests.
