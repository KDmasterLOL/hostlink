# Native HostLink smoke harness

`hostlink-native-smoke.nu` runs a narrow pinned-SSH and SFTP smoke against an explicitly selected **disposable test host**. It requires Nushell and a HostLink Controller binary:

```sh
nu tests/support/hostlink-native-smoke.nu --self-test
nu tests/support/hostlink-native-smoke.nu --host disposable-linux --hostlink ./target/debug/hostlink
nu tests/support/hostlink-native-smoke.nu --host disposable-linux --hostlink ./target/debug/hostlink --job --board-port 39123 --job-os linux
```

The harness generates one random `qa-<32-hex>.bin` basename and passes only that basename to SFTP `--remote`. Its self-test rejects absolute paths, `/`, `\\`, and traversal. Agent SFTP stores the file in its private `transfers/<controller-ed25519-hex-fingerprint>/` directory. The harness does not access or infer that local path, execute the uploaded file, or remove the artifact. Each successful run leaves one test-owned file; the Agent bounds the transfer count, so repeated runs require cleanup when the fixture approaches its configured limit. Failed runs may also leave their unique upload and controller-local temporary directory behind.

There is no harness or CLI cleanup command. For manual cleanup, use an owner-reviewed target-local procedure: resolve the Agent install root from its actual service configuration, resolve the Controller fingerprint from the Controller's actual Ed25519 public identity, and construct only `<verified-install-root>/transfers/<verified-fingerprint>/<printed-basename>`. Confirm the file is regular, inside that exact owner directory, and its SHA-256 equals the run's printed digest; then unlink only that exact file. If any identity, root, ownership, or digest check is ambiguous, retain the artifact and stop. Do not search for matching files or use wildcard cleanup.

The run performs `verify HOST`, `check --host HOST`, a read-only `exec --host HOST --command ...`, then `upload --host HOST --local FILE --remote BASENAME` and `download --host HOST --remote BASENAME --local FILE`, checking the downloaded SHA-256. The host name must resolve through the configured Hub to the intended disposable test Agent. The script does not discover or infer host ownership, so do not point it at a customer or shared production host.

The detached-job smoke is opt-in. `--job`, `--board-port INT`, and `--job-os linux|windows` must be supplied together; otherwise the base smoke runs without job submission. Set `--job-os` to match the disposable host. Before connecting to the host, it checks that the selected Controller exposes `exec --host --detach --board-port` and `job status --host --board-port JOB_ID`; older binaries fail locally without running the remote smoke. Linux uses only `sleep 8`; Windows uses only `Start-Sleep -Seconds 8`. The script accepts exactly one strict ULID from the submit response, requires the response within six seconds, then polls the same ID for up to 60 seconds using a new Controller invocation and SSH connection for each status query. Only an unambiguous `Done` is success; `Failed`, `Killed`, unknown states, malformed IDs and timeout fail the smoke. It does not assert job stdout or exit code. The short-lived detached submitter exiting before the eight-second task completes checks client-close preservation. It does **not** simulate physical network loss, Agent crash/restart, reboot, or service lifecycle.

Without `--job`, this harness does not test detached jobs or their Job IDs. In all modes it does not test physical SSH-channel disconnection/reconnection, Agent crashes, reboot recovery, Board UI access, or Linux/Windows service lifecycle. The optional job path requires the newer detached-job CLI; omitting the option remains compatible with older Controller builds. Run destructive lifecycle and controlled-disconnect scenarios only on separately isolated, owner-controlled fixtures.

## Separate physical-network outage test

This harness does not cut the network. To test an actual outage separately, use a disposable Agent and an isolated Controller-to-test-gateway network namespace. Submit only the same sleep-only detached task, record its acknowledged Job ID, sever that namespace's test route, wait past the task duration, restore the route, and poll the same ID over pinned SSH. Do not interrupt a shared gateway, kill the Agent, or involve production/customer workloads. This experiment remains separate from this harness and requires its own native evidence.
