# Agent enrollment

New Agents register using a one-use Hub invitation over HTTPS. The Controller creates the invitation; the Agent consumes it through `POST /v2/enroll`.

## Install flow

1. The Controller resolves a release asset and SHA-256, then creates a one-use invitation.
2. The target bootstrap downloads the exact executable and verifies its digest.
3. `hostlink-agent install` consumes the invitation and creates a fresh installation root.
4. Enrollment creates independent machine, SSH host and reverse-tunnel identities, the Agent configuration, and private persistent state.

The Hub provides approved gateway public-key pins and route information. If multiple gateways are available, pass `--gateway-index N` to the invite or installer. No gateway is selected implicitly.

An enrollment request may succeed on the Hub before local publication finishes. When `enrollment.pending` remains, inspect the Hub inventory and reconcile the attempt; do not replay the original one-use token.

## Trust and storage

All bootstrap and enrollment HTTPS connections validate certificate chains and hostnames. An optional `--hub-ca-cert` adds an operator-controlled CA without disabling ordinary validation.

Linux installs use a user-owned private root and keys. Windows installs use protected current-user-only ACLs and an unelevated interactive bootstrap. The Agent refuses an elevated runtime even if enrollment was completed by another authorized workflow.

`state/manifest.json` records enrollment-key identity and persists across executable updates.

See [Agent installation](AGENT_INSTALLATION.md), [GitHub Releases](GITHUB_RELEASES.md) and [Controller/Hub](CLIENT_HUB.md).
