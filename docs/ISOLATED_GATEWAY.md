# Isolated HTTPS Hub and OpenSSH gateway fixture

This opt-in Linux fixture runs the built v2 Hub, a local Caddy TLS proxy, an
enrolled Agent, a real OpenSSH server, and the normal HostLink Controller
client. It uses only loopback sockets and a new private temporary directory.
It does not edit `~/.ssh`, system Caddy/SSH configuration, services, legacy Hub
state, or an installed gateway. It refuses to run as root.

Run it from this worktree:

```sh
scripts/hostlink-managed-gateway-fixture.sh
```

Requirements are Rust/Cargo dependencies already available offline, OpenSSH
client and server, Caddy, OpenSSL, `pgrep`, and `ss`. The script builds only the three current
worktree binaries before running the ignored process-level integration test.
The test creates Ed25519 identities, a one-use invite, a private TLS CA and
leaf certificate, a temporary OpenSSH host key, private Hub state, and the
Hub-owned `gateway/hostlink-v2-authorized_keys` file. The temporary root is
removed after every exit; child processes are terminated and reaped.

The custom CA option adds that PEM certificate to the normal TLS trust set.
Hostname verification, certificate validation, redirect denial, and
HTTPS-only behavior remain enabled. The HubClient test rejects an unrelated
CA and a certificate hostname mismatch; Agent enrollment repeats both
negative checks before using the trusted endpoint.

The temporary `sshd` config names two separate authorized-key files: one for
the disposable Controller key and the exact Hub v2 projection path. It uses a
new high loopback port, a new host key, `GatewayPorts no`, and the Hub-projected
`permitlisten="127.0.0.1:PORT"` key restriction. The actual reverse Agent
login and nested russh Controller connection verify that OpenSSH consumes the
projection directly. A wildcard reverse-listen attempt and a second daemon on
the occupied port must fail.

The scenario exercises one-use invitation and real Agent enrollment; Hub
inventory and name-based Client CLI selection; nested SSH raw exec (including
exit 7), SFTP upload/download, durable job start and reattachment, and
loopback TCP forwarding. Negative cases cover wrong TLS CA, wrong TLS
hostname, wrong gateway key, stale Agent host-key pin, expired invitation,
wildcard reverse listening, and port collision. Finally, Hub revocation
removes the host from new managed resolution and reports that existing
sessions were not confirmed terminated; an already-established session is
shown to remain alive until explicitly closed.

The test output intentionally omits tokens and private key contents. The
test prints a redacted authorization receipt with the source revision and
accepted/denied key categories; SSH fingerprints are checked against private
sshd logs but are not printed. The fixture tests the isolated local gateway
only; it is not evidence for an external pilot, deployment, Windows, or the
old gateway.

When loopback TCP is denied by a sandbox (for example, `TcpListener::bind`
returns `EPERM`), the process-level test cannot run there. The existing
`gateway_interop` test remains an in-process russh gateway fallback for the
Agent/Client data path only; it does not prove HTTPS or OpenSSH authorization.
