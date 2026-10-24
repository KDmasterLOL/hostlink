# Vendored process-wrap

Upstream: https://github.com/watchexec/process-wrap
Version: `10.0.0`
Annotated tag: `v10.0.0`
Base commit: `d02486b8d1e393a4ac27023d591b6f35c6417ffb`

The preceding toolkit commit `efb15be` is the byte-for-byte upstream tag snapshot.
Subsequent toolkit changes are intentionally small generic process-tree completion patches:

### Windows Job Objects

- use `QueryInformationJobObject(JobObjectBasicAccountingInformation)` / `ActiveProcesses` as the authoritative whole-Job completion condition;
- treat completion-port packets only as wake-ups and periodically re-query because ordinary Job lifecycle notifications are not guaranteed;
- make `try_wait()` return `None` while any Job member remains;
- carry deterministic std/Tokio launcher-exits-before-descendant regressions.

### Unix process groups

- treat process-group existence, probed with `killpg(pgid, 0)`, as the authoritative whole-group completion condition;
- retain `waitpid(-pgid, ...)` for reaping waitable children, but do not interpret `ECHILD` as proof that reparented group members are gone;
- make both std and Tokio `try_wait()` return `None` while any group member remains, even after the launcher has exited;
- make both std and Tokio `wait()` continue until the process group is empty;
- carry deterministic launcher-exits-before-orphaned-descendant regressions.

### Kill on drop

- add a std `KillOnDrop` child wrapper instead of requiring downstream owners to implement RAII termination;
- make Tokio `KillOnDrop` wrap the returned lifecycle as well as setting Tokio's native command flag;
- allow std `JobObject` to observe `KillOnDrop` and set `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, matching the existing Tokio composition;
- preserve either registration order for Windows Job policy discovery, while recommending tree-owner-then-`KillOnDrop` so the child wrapper targets the fully composed lifecycle on every platform;
- carry Unix std/Tokio whole-process-group drop regressions and a Windows std Job descendant regression.

### Test feature gating

- `1C-271` — gate the concrete-wrapper lookup test macro with the same optional `std`/`tokio1` frontend features as its invocations, so default-feature strict Clippy does not report an unused macro.

The local patches should be deleted when upstream ships equivalent whole-tree completion and std/Tokio kill-on-drop lifecycle behavior or equivalent strict-Clippy test gating.

When updating upstream, diff/rebase the commits after `efb15be` onto the new upstream snapshot. Do not count the upstream snapshot itself as toolkit-maintained implementation LOC.
