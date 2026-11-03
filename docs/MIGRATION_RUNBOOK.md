# Migration from an older Agent

HostLink can be introduced alongside an existing management Agent. The `migration preflight` command is read-only and offline; it inspects supplied snapshots and desired configurations, not remote hosts.

## Preflight

```sh
hostlink migration preflight \
  --old-hub /private/snapshots/hub.json \
  --old-controller /private/snapshots/controller.json \
  --old-agent /private/snapshots/agent.json \
  --new-agent /private/desired/agent.json \
  --new-host /private/desired/host.json
```

The command checks configuration shapes, trust pins, gateway routes and local key paths. `READY` indicates only that static inspection passed; `REVIEW` means additional human verification is required; `BLOCKED` means stop and correct the configuration.

## Side-by-side verification

1. Use a disposable host with separately owned Agent roots and SSH identities. Keep the previous Agent and Controller working.
2. Provision and pin the Hub/gateway/Agent identities, then run the offline preflight.
3. Enroll the new Agent and validate its owner, private storage, independent service, reverse route, SSH execution and SFTP transfer.
4. Test a local Apalis job through the loopback Board or pinned SSH forward. Tasks may be retried after a crash, so use idempotent test work.
5. Verify the previous Agent remains reachable before considering any cutover.

## Rollback

Stop only the new Agent's owned user service and verify the old route remains available. Preserve unresolved jobs and enrollment state for diagnosis. Remove disposable Agent files only when no process or job is using them.

Migration does not implicitly uninstall or modify a legacy Agent, convert credentials, or operate customer databases. See [enrollment](ENROLLMENT.md), [Agent lifecycle](AGENT_LIFECYCLE.md), and [architecture](ARCHITECTURE.md).
