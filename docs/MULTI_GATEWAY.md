# Agent multi-edge reverse SSH routing

Fresh enrollment accepts the Hub v2 ordered `gateways` list only after the
operator chooses an explicit `--gateway-index`. The chosen endpoint becomes
the primary route; the other validated endpoints are stored, in Hub order, as
approved alternates in the private `agent.json`. Legacy configs with one
`gateway` and no `gateway_alternates` keep their existing behavior.

The Agent loads every Ed25519 gateway host-key pin and the shared reverse SSH
identity before opening a network connection. It connects to one route at a
time and requests only `127.0.0.1:<assigned remote_port>`. A refused,
disconnected, or timed-out connection advances to the next approved endpoint.
After the last endpoint it returns to the primary. Retry delays grow from one
second to a sixty-second ceiling. Shutdown interrupts both an attempt and its
backoff. Host-key mismatch, rejected identity, rejected reverse-forward
request, malformed pin, and configuration errors stop immediately without
trying another edge.

All edges for one Agent must authorize the same Ed25519 reverse identity and
the same assigned remote port. Each edge needs its own exact pinned SSH host
key. Hub operators must provision that identity and port on every approved
gateway before adding it to enrollment policy; a route that is merely
reachable is not trusted. The Agent does not discover gateways, resolve
fallback names, or infer approval from connectivity.

The route list is bounded to sixteen endpoints and checked for duplicate
gateway identities, conflicting pin paths, inconsistent assigned ports, and
shared-identity path mismatches before network activity. Gateway pin files
must be private, regular, non-symlink files containing an OpenSSH Ed25519
public key. No public reverse listener is requested.

Linux fixture tests exercise real russh gateway authentication, the approved
fallback path, permanent pin failure, route validation, and shutdown. Native
Windows 11 and Windows 7 acceptance remains a separate platform gate.

## Controller behavior

For Hub-managed commands, the controller requires an exact
`preferred_gateway: "host:port"` in its local Hub config whenever `/v2/info`
contains multiple routes. It validates the entire bounded route list and every
Ed25519 host pin before connecting. The selected primary is tried first; other
approved edges are attempted only after transient gateway connection failures.
Authentication denial, pin mismatch, reverse-port refusal, and nested Agent
pin mismatch are permanent. A started command or durable job is never replayed
after route loss. See [CLIENT_HUB.md](CLIENT_HUB.md) for the Client CLI and
configuration details.
