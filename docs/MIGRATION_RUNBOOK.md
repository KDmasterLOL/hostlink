# HostLink offline migration preflight and side-by-side runbook

This procedure inventories one legacy host and an explicit new russh Agent / HostSpec pair. It is an offline read-only inspection; it does not contact the old Hub, connect to SSH, convert credentials, write configs, install binaries, or change services. A `READY` result means only that local static checks passed. `REVIEW` requires the listed human checks. `BLOCKED` means do not use the desired config until every blocker is resolved and preflight is rerun.

## Preflight inputs

Keep snapshots and credentials in owner-only storage. Supply the old Hub JSON, old Controller JSON, the host's old Agent JSON, and explicit desired new Agent and HostSpec JSON:

```sh
hostlink migration preflight \
  --old-hub /private/snapshots/hub.json \
  --old-controller /private/snapshots/controller.json \
  --old-agent /private/snapshots/agent.json \
  --new-agent /private/desired/agent.json \
  --new-host /private/desired/host.json
```

The command reads bounded regular files, rejects symlinked snapshots and reports stable blockers without echoing config values, names, tokens, keys, or environment contents. Exit status is 0 for READY/REVIEW and 2 for BLOCKED; malformed or unsafe inputs return an error. `writes_performed` and `network_attempted` are always false. Reports use synthetic host IDs; run once per host and retain reports in the same private operator workspace as the snapshots.

The inspector compares the old Hub, Controller, and Agent gateway route where those fields are explicit. It blocks unsupported/malformed/multiple routes, gateway port reuse, TLS wrappers, missing old SSH identity/trust, old API token used as SSH identity, incomplete desired pins, unsafe local key paths, and conflicting new Agent/HostSpec reverse ports. This one-route preflight rejects uninspected desired gateway alternates, even though the current runtime supports explicitly approved multi-edge routes. The Agent's reverse-tunnel SSH private identity and the Controller's gateway SSH private identity are **different credentials**: their paths are independently checked, never required to match. It cannot prove remote filesystem owner/ACL, gateway-side authorization of both accounts, gateway pin-file equivalence, or that a desired host pin matches the target's installed host key. Those are mandatory target-side reviews.

## Legacy capability disposition

| Legacy function | New path or disposition |
| --- | --- |
| Old Agent JSONL control listener, old per-Agent RPC/control token | Retired; no compatibility listener or token conversion. New HostLink Hub **registry/enrollment/revocation** remains REQUIRED as a separate HTTPS management plane (1C-1019/1020/1021). |
| Pinned SSH target check/exec | `hostlink check` / `hostlink exec` with explicit `HostSpec`. |
| File transfer | `hostlink upload` / `hostlink download` over Agent SFTP. |
| Durable task start/readback | Agent-local **Apalis SQLite** queue with stock loopback-only Board UI/API, accessed locally or via authenticated SSH forwarding. There is no `hostlink jobs` CLI or SSH jobs protocol. After a worker crash Apalis can replay a started command and repeat its side effects; plan idempotence accordingly. |
| Reverse SSH gateway | One explicit pinned Agent `ReverseGateway` plus Controller `GatewayHop`; multiple routes need manual redesign. |
| TLS proxy wrapper, arbitrary old forwarding, legacy enrollment | No automatic equivalent; blocked or requires a separate manual design. |
| Old Toolkit updater or managed release engine | Retired from this rewrite; do not invoke it for migration. |

## Manual side-by-side cutover

1. Choose one disposable host and record its owner, OS/architecture, current service identity, old listener, old process root, and old Controller commands. Do not stop, edit, or reconfigure the old Agent or Hub.
2. Create a distinct new Agent root owned by the intended non-elevated account. Keep it separate from every old install, jobs, and upload root. Provision an Agent-only reverse-tunnel gateway identity and a distinct Controller gateway identity, independently approved at the same pinned gateway, plus an Agent host key, authorized controller Ed25519 key and loopback SSH port. Set restrictive ownership/ACLs and record intended values without copying old tokens.
3. Prepare explicit desired `AgentConfig` and `HostSpec`; pin the target and gateway public keys independently. Run offline preflight, resolve blockers, and perform all REVIEW checks on that disposable host before connecting.
4. Start only the new Agent on its separate loopback port and root. Verify actual owner/ACL, key fingerprints, both independently authorized gateway identities, reverse route and service isolation. Use the current `hostlink check --config PATH` (or `--host NAME` after managed enrollment), a bounded disposable `exec`, and binary `upload`/`download`. For durable jobs, inspect the Agent's loopback-only Apalis Board UI/API and its worker state through an authenticated SSH forward; do not run a retired Client jobs CLI. Record source hashes and exact exit status. Never treat preflight as runtime acceptance.
5. Keep the old Controller config and old Agent untouched while proving the new Controller path. Verify a submitted disposable Apalis task reaches a terminal state before shutdown; avoid non-idempotent commands because worker crash recovery can repeat side effects.

## Rollback

1. Verify the new Agent-local Apalis Board reports no queued, running or otherwise active tasks. Stop the new Agent using the disposable host's documented owner-controlled process procedure. Confirm its process is stopped and its SSH port is closed; do not remove its root while any process or job may still own it.
2. Confirm the old Agent, old process root, and old Hub/Controller configuration remain unchanged. Use the existing approved old-controller check/operation to verify the old route still works.
3. Preserve new Agent logs and any unresolved job state for review. Remove the new root only after the owner confirms there are no active jobs and artifacts are disposable. Record rollback result and retain both configs privately.

There is no automatic rollback or fleet wave operation in this tool. Proceed host by host only after the separate native gateway, Windows 7, Windows ownership, updater, and release gates have their required evidence and a separate cutover authorization exists.

For the source-pinned, current-user HOME pilot lifecycle foundation and its
current limits, see [PARALLEL_PILOT_OPERATIONS.md](PARALLEL_PILOT_OPERATIONS.md).
