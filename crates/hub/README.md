# HostLink Hub

`hostlink-hub` owns the managed fleet registry, one-use enrollment invitations,
approved gateway routes, and new-connection SSH authorization. It is a management
plane only; execution, SFTP, forwarding, and jobs continue over the existing
`russh` transport.

The HTTP server binds only to a loopback address. Put an operator-controlled TLS
reverse proxy in front of it when remote management access is needed. The Hub
does not enable TLS itself or bind to a public interface.

## Configuration

Pass a bounded JSON file to `hostlink-hub check --config PATH` or
`hostlink-hub serve --config PATH`:

```json
{
  "version": 2,
  "listen": "127.0.0.1:27400",
  "public_url": "https://hub.example",
  "state_root": "./hostlink-hub-v2",
  "authorized_keys": "./gateway/hostlink-v2-authorized_keys",
  "gateways": [
    {
      "host": "gateway.example",
      "user": "hostlink-gateway",
      "port": 22,
      "host_public_key": "ssh-ed25519 AAAA..."
    }
  ],
  "operator_ssh_public_keys": ["ssh-ed25519 AAAA..."],
  "operator_token_env": "HOSTLINK_HUB_OPERATOR_TOKEN",
  "gateway_lookup_token_env": "HOSTLINK_HUB_GATEWAY_LOOKUP_TOKEN",
  "port_from": 41000,
  "port_to": 41999,
  "reserved_ports": []
}
```

Provide distinct operator and gateway lookup bearer tokens through the named
environment variables. Each must contain at least 32 bytes. The state root must
be a private directory named `hostlink-hub-v2`; its `registry-v2.json` is a new
schema and is never an old Hub state file. The optional authorized-keys
projection owns only entries marked `hostlink-agent:` and preserves unrelated
and `onec-agent:` lines.

## API

The operator bearer token protects `GET /v2/info`, host inventory and mutation
routes, and invite creation. `POST /v2/enroll` consumes a short-lived one-use
invite token. The gateway uses its separate bearer token for
`POST /internal/v2/ssh/authorized-key`. `GET /healthz` reports only Hub process
health.

The reverse identity and embedded Agent SSH host key must be distinct Ed25519
keys. A fresh invitation cannot claim an enrolled machine ID; an operator must
create an invite explicitly bound to that ID to authorize key rotation. Revoking
a host denies future gateway lookups and reports projection reconciliation
separately; it does not terminate established SSH channels or uninstall an Agent.
Canonical host names are lowercase ASCII slugs; display names are separate
labels and may contain Unicode.
