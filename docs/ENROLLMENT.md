# Agent enrollment

New Agents register using a one-use Hub invitation over HTTPS. The Controller creates the invitation; the Agent consumes it through `POST /v2/enroll`.

## Install flow

1. The Controller obtains the public release metadata and SHA-256 for each eligible executable, then creates a one-use invitation. A missing digest stops the flow.
2. The target bootstrap selects its platform, downloads the executable from the public release URL and verifies its SHA-256 before executing it. No GitHub PAT or separate installer script is used.
3. `hostlink-agent install` consumes the invitation and creates a fresh installation root.
4. Enrollment creates independent machine, SSH host and reverse-tunnel identities, the Agent configuration, and private persistent state. The bootstrap invokes the installed Agent to register and start its service.

The Hub provides approved gateway public-key pins and route information. If multiple gateways are available, pass `--gateway-index N` to the invite or installer. No gateway is selected implicitly.

An enrollment request may succeed on the Hub before local publication finishes. When `enrollment.pending` remains, inspect the Hub inventory and reconcile the attempt; do not replay the original one-use token.

## Trust and storage

The digest is supplied by GitHub release metadata over HTTPS; it is not an independent publisher signature. All bootstrap and enrollment HTTPS connections validate certificate chains and hostnames. An optional `--hub-ca-cert` adds an operator-controlled CA without disabling ordinary validation.

Linux installs use a user-owned private root and keys. Windows installs use protected current-user-only ACLs and an unelevated interactive bootstrap. The Agent refuses an elevated runtime even if enrollment was completed by another authorized workflow.

`state/manifest.json` records enrollment-key identity and persists across executable updates.

See [Agent installation](AGENT_INSTALLATION.md), [GitHub Releases](GITHUB_RELEASES.md) and [Controller/Hub](CLIENT_HUB.md).
