# Native HostLink smoke harness

`hostlink-native-smoke.nu` runs a narrow pinned-SSH and SFTP smoke against an explicitly selected **disposable test host**. It requires Nushell and a HostLink Controller binary:

```sh
nu tests/support/hostlink-native-smoke.nu --self-test
nu tests/support/hostlink-native-smoke.nu --host disposable-linux --hostlink ./target/debug/hostlink
```

The harness generates one random `qa-<32-hex>.bin` basename and passes only that basename to SFTP `--remote`. Its self-test rejects absolute paths, `/`, `\\`, and traversal. Agent SFTP stores the file in its private `transfers/<controller-ed25519-hex-fingerprint>/` directory. The harness does not access or infer that local path, execute the uploaded file, or remove the artifact. Each successful run leaves one test-owned file; the Agent bounds the transfer count, so repeated runs require cleanup when the fixture approaches its configured limit. Failed runs may also leave their unique upload and controller-local temporary directory behind.

There is no harness or CLI cleanup command. For manual cleanup, use an owner-reviewed target-local procedure: resolve the Agent install root from its actual service configuration, resolve the Controller fingerprint from the Controller's actual Ed25519 public identity, and construct only `<verified-install-root>/transfers/<verified-fingerprint>/<printed-basename>`. Confirm the file is regular, inside that exact owner directory, and its SHA-256 equals the run's printed digest; then unlink only that exact file. If any identity, root, ownership, or digest check is ambiguous, retain the artifact and stop. Do not search for matching files or use wildcard cleanup.

The run performs `verify HOST`, `check --host HOST`, a read-only `exec --host HOST --command ...`, then `upload --host HOST --local FILE --remote BASENAME` and `download --host HOST --remote BASENAME --local FILE`, checking the downloaded SHA-256. The host name must resolve through the configured Hub to the intended disposable test Agent. The script does not discover or infer host ownership, so do not point it at a customer or shared production host.

This harness does not test SSH-channel disconnection/reconnection, detached jobs or their Job IDs, Agent crashes, reboot recovery, Board access, or Linux/Windows service lifecycle. Detached job flags/status are not part of the `830f13a` CLI. It makes no claim about Windows acceptance. Run destructive lifecycle and controlled-disconnect scenarios only on separately isolated, owner-controlled fixtures.

## Deferred controlled-disconnect scenario

After a detached-job CLI and status reader are available, use an isolated disposable Agent plus an isolated test gateway or network namespace. Submit one idempotent task that only waits briefly and writes a nonce marker inside that same dedicated test directory. Record the acknowledged Job ID, then sever only that test Controller-to-test-gateway path (never a shared gateway or Agent process). Restore the test route, reconnect with the pinned identity, query the same Job ID, and download the marker over SFTP. Record status, exit code, and marker hash. Keep ordinary SSH exec, Agent termination/restart, and OS service lifecycle as separate experiments; this harness does not claim their behavior.
