# HostLink controller commands

This catalog lists the executable's current command leaves. `job`, `run-local-job`, and `run-local-evidence` are command families.

## Top-level leaves

`check`, `configure`, `display-name`, `download`, `exec`, `forward`, `info`, `invite`, `list`, `migrate-runtime`, `migration-report`, `probe`, `rdp`, `remove`, `remove-scoped`, `run-local`, `show`, `ssh`, `sync-ssh`, `upload`, and `verify`.

## Nested leaves

- `job`: `start`, `status`, `result`, `logs`, `cancel`, `wait`.
- `run-local-evidence`: `verify`.
- `run-local-job`: `start`, `status`, `logs`, `cancel`, `results`, `attest`, `recover-attest`, `observe-invocation`, `recover-invocation`, `verify-invocation-logs`, `verify-invocation-result`, `cleanup`, `list-reservations`.

Effects and authorization rules are implemented by the controller owners under `src/cli/`; this catalog is navigation only.
