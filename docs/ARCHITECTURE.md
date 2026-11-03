# Architecture

HostLink uses three independently installed components.

| Component | Responsibility |
| --- | --- |
| Hub | HTTPS enrollment, one-use invitations, inventory, revocation and approved gateway keys/routes |
| Controller | Managed host selection, pinned SSH `exec`, SFTP and TCP forwarding |
| Agent | Embedded SSH server, outbound reverse SSH, Agent-local jobs, installation and updates |

```text
Controller ── HTTPS ──> Hub <── HTTPS ── Agent
    │                                │
    └── pinned SSH ──> gateway ──────┘
                                       Agent loopback
                                       ├── SSH/SFTP
                                       └── Apalis Board + SQLite jobs
```

## Transport and identity

The Controller resolves current machine identity and approved gateways from the Hub, then uses `russh` with pinned Ed25519 keys. The Hub is not a second command transport. Controller and Agent private keys are distinct. An Agent registers using a one-use Hub invitation.

HostLink can be installed alongside an existing management Agent. Enrollment is separate from migration or removal of an older Agent.

## Jobs and Board

Short interactive commands use SSH `exec`. Durable commands are queued locally through Apalis SQLite and the upstream Apalis Board; there is no separate Client jobs protocol. The Board is bound to loopback and can be exposed to an authorized Controller through pinned SSH forwarding.

Apalis may retry an interrupted job. Job handlers must tolerate duplicate side effects. ProcessKit owns child-process groups; it does not guarantee survival of an Agent crash.

## Installation and updates

The Controller currently resolves an exact Agent executable from GitHub Releases and renders a disposable PowerShell 2 or POSIX bootstrap. The bootstrap verifies the raw executable digest before passing the one-use invitation to Rust `hostlink-agent install`.

Agent installs use a stable, per-user root. Services are managed through systemd user units on Linux or user Task Scheduler tasks on Windows. Updates preserve enrollment keys and jobs; on Windows the Agent must be stopped and its owned task removed before replacing the executable.

See [installation](AGENT_INSTALLATION.md), [GitHub releases](GITHUB_RELEASES.md), [Windows lifecycle](AGENT_LIFECYCLE.md) and [source layout](SOURCE_LAYOUT.md).
