# Agent enrollment

New Agents register using a one-use Hub invitation over HTTPS. The Controller creates the invitation; the Agent consumes it through `POST /v2/enroll`.

## Install flow

1. The Controller obtains the public release metadata and SHA-256 for each eligible executable, then creates a one-use invitation. A missing digest stops the flow.
2. The target bootstrap selects its platform, downloads the executable from the public release URL and verifies its SHA-256 before executing it. No GitHub PAT or separate installer script is used.
3. For an absent canonical inventory name, `hostlink-agent install` consumes a fresh invitation and creates a fresh installation root. For an existing name, the Controller embeds its exact machine ID and requests a repair invitation.
4. Fresh enrollment creates independent machine, SSH host and reverse-tunnel identities, the Agent configuration, and private persistent state. Existing-host repair preserves those identities and the assigned port. The bootstrap invokes the installed Agent to register and start its service.

Before issuing a runnable bootstrap invitation, the Controller reads the authenticated Hub's approved gateway routes and pins. It selects the sole route, or the exact `preferred_gateway` configured as `host:port` when multiple routes exist. An explicit `--gateway-index N` overrides the preference and must be in range. If no preferred route matches, configure one or supply an index before retrying. Token-only invitations skip route selection for manual installation. The selected index is embedded in the bootstrap; the Agent still validates the approved pins during enrollment.

The bootstrap uses the Controller Hub configuration's `ssh_user` as the Agent's SSH protocol login, independently of the target Windows or Linux OS account. An explicit `--ssh-user` must match that configured login; a mismatch is rejected before any Hub or GitHub request and before an invitation is created. `--token-only` remains a manual flow and cannot be combined with `--ssh-user`.

An identity-preserving repair may update an older Agent's SSH protocol login to this selected value. The installer validates the old state and proves possession of its reverse key, then stages the selected login with refreshed manifest hashes after the Hub response. The existing service account and SSH keys remain unchanged.

An enrollment request may succeed on the Hub before local publication finishes. When `enrollment.pending` remains, inspect the Hub inventory and reconcile the attempt; do not replay the original one-use token.

## Existing-host authorization

The same authenticated `POST /v2/invites` endpoint accepts three mutually exclusive purposes: fresh (neither identity field), repair (`repair_machine_id`), or explicit SSH key rotation (`rotate_machine_id`). Repair requires the exact canonical existing name and captures both registered SSH public keys at issuance. Display labels and ID selectors cannot select a repair target. Manual `--token-only` issuance retains fresh semantics.

Repair uses `POST /v2/enroll` with an OpenSSH `repair_signature` by the existing Ed25519 reverse key. The `hostlink-repair-v1` namespace and length-prefixed transcript bind the signature to the one-use token, exact machine ID/name, both SSH keys, and submitted inventory fields. The Hub checks the captured keys against the current registration and the request, verifies possession, and consumes the token in the same existing state commit. A later key rotation invalidates an outstanding repair invitation. Fresh invites and rotation invites cannot use a repair proof. Successful repair updates inventory metadata and reconciles the gateway authorization projection without allocating a new port or creating another host.

Existing registry records remain readable by this implementation. Registry records containing repair-purpose fields require a Hub reader that understands them; older readers reject them. A separately authorized Hub rollback must preserve consumed-invite history and current identity. Dropping purpose fields or restoring a pre-consumption registry snapshot is not a safe downgrade.

The installer validates the response and approved routes over the Controller-configured HTTPS Hub, independently of stale installed routes. All route pins are checked before a bounded outbound SSH authentication probe; pin mismatch or identity denial fails permanently, while transient connection failures may advance to another approved route. No reverse port is claimed by this probe. See [local repair and interrupted transactions](AGENT_INSTALLATION.md#local-repair-through-the-same-invite).

## Trust and storage

The digest is supplied by GitHub release metadata over HTTPS; it is not an independent publisher signature. All bootstrap and enrollment HTTPS connections validate certificate chains and hostnames. An optional `--hub-ca-cert` adds an operator-controlled CA without disabling ordinary validation.

Linux installs use a user-owned private root and keys. Windows installs use protected current-user-only ACLs and an interactive bootstrap. An elevated Agent runs remote commands with administrator rights.

`state/manifest.json` records enrollment-key identity and persists across executable updates.

See [Agent installation](AGENT_INSTALLATION.md), [GitHub Releases](GITHUB_RELEASES.md) and [Controller/Hub](CLIENT_HUB.md).
