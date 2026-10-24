# Vendored ProcessKit

Upstream: https://github.com/ZelAnton/ProcessKit-rs
Crates.io version: `3.3.4`
Upstream VCS base: `ba1a6fe77cedad7e1ceeb9f30b158c94b5dc1bb6`
Crates.io checksum: `1549b59abbe4fc78aa39860e36c81da89262c1278679b8f7299ef4ad7668c004`

The vendored tree is the published 3.3.4 crate snapshot, excluding only Cargo's local `.cargo-ok` marker.

Local generic patch:

- `1C-605` — expose a read-only `RunningProcess::owned_tree_probe()` for runs that
  own a private ProcessKit group. The returned `OwnedProcessTreeProbe` exposes only
  point-in-time membership diagnostics and no signal/termination capability. This lets
  higher-level domains observe exact contained-tree identity without duplicating process
  ownership or exposing raw Job/cgroup handles.
- `1C-438` — add explicit fallible raw stdout/stderr sink factories
  (`Command::stdout_raw_sink` / `stderr_raw_sink`) with byte-preserving,
  backpressured writes and a fallible EOF finalization hook. Sink failures surface
  as `ErrorReason::RawSink` only after ProcessKit has confirmed the ordinary
  process/tree completion path; abnormal pump destruction is also fail-visible so
  callers cannot mistake a non-finalized raw stream for durable success.
  Timeout/cancellation teardown failures remain authoritative. Existing
  `*_raw_tee` behavior stays best-effort and unchanged.
  Also add `Command::fail_on_stdin_broken_pipe()` so exact-delivery consumers can
  make an early stdin close fail-visible as `ErrorReason::Stdin` without changing
  ProcessKit's default broken-pipe behavior. In exact-delivery mode the stdin
  failure outranks any ordinary `Exited(code)` disposition, while retaining that
  code on the structured error; signal/timeout/cancellation/teardown precedence is
  unchanged.
- `1C-374` — add a non-consuming `RunningProcess::wait_for_tree_exit(within)` probe. It waits for a privately owned process tree to drain, background-drains output, and returns `ErrorReason::NotReady` on its independent deadline without arming the command timeout or changing terminal disposition. Private-group completion uses platform-owned live-tree evidence rather than reaping the root early: Job Object active-process accounting on Windows, cgroup membership on Linux cgroup v2, zombie-aware group enumeration on Linux/macOS pgroup fallbacks, and reaper zombie flags on FreeBSD. Shared-group handles wait only for their root child; BSD pgroup targets without a process-state/member reader remain conservatively `NotReady` for a zombie-only group.
- `1C-463` — expose non-consuming root-child outcome observation through `RunningProcess::try_wait_outcome()` and bounded async `wait_for_root_exit(within)`. The async API uses ProcessKit's gated root reap, reports wait errors, and leaves the owned process-tree handle available for later teardown; root outcome and whole-tree emptiness remain separate evidence.
- `1C-368` — add a typed `Command::raw_arg` builder seam for Windows programs with non-standard command-line grammars. Raw and ordinary arguments preserve insertion order. Raw lowering happens inside ProcessKit's normal `build_tokio` path so high-level `run` / `start`, whole-tree containment, bounded capture, timeout and cancellation ownership are retained. Non-Windows launch fails explicitly with `ErrorReason::Unsupported`.

The patches are domain-neutral; they contain no 1C-specific logic. 1C keeps its own `/IBConnectionString` grammar in the appropriate domain owner.

Remove each local patch when upstream ProcessKit ships an equivalent high-level API/behavior.

When updating upstream:

1. import the new published/upstream source snapshot;
2. reapply only the local patches that upstream still lacks;
3. regenerate/check `public-api.txt`;
4. run ProcessKit tests plus standard Windows and pinned Win7 x64/x86 gates;
5. run the full onec-toolkit validation matrix.
