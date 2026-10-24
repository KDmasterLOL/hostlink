# onec-hub

`onec-hub` is the authoritative enrollment/discovery service for `onec-agent` fleets.
Controller-side managed-machine access is owned by `onec-access`; local 1C mechanics belong to
their focused domain/backend crates and are composed by `onec-cli`.

## Architecture

The hub may be colocated with one SSH gateway or run on a separate stateful host. The latter is preferred when several interchangeable stateless gateways front one fleet:

```text
Windows server            stateless SSH edge                  stateful hub / operator
-------------             ------------------                  -----------------------
onec-agent -- SSH ------> onec-agent SSH account
                              | 127.0.0.1:41xxx <------------ onec-access embedded SSH
                              |
                              +-- AuthorizedKeysCommand ----> onec-hub internal lookup

onec-agent -- HTTPS --------------------------------------> onec-hub enrollment API
                                                             |
                                                             +-- fleet state
                                                             +-- key/port policy
```

The hub allocates a stable reverse port per `machine_id` and exposes the fleet through `/v1/agents`. `state.json` is the single durable authority for enrollment and invitations: every writer serializes through a persistent kernel-backed sibling lock, reloads the durable state while holding that lock, and atomically publishes the new state before changing any derived SSH projection. Reads used for inventory and SSH authorization load that atomically published state rather than relying on a process-local snapshot, so multiple hub processes sharing one state path cannot retain an authoritative stale cache. In a colocated deployment, the hub maintains a local restricted `authorized_keys` projection and repairs the complete reserved `onec-agent:*` namespace from committed state on startup and after enrollment/revocation. Unmanaged and malformed lines are preserved byte-for-byte. If projection publication fails after state commit, the state transition remains committed and the request reports `reconciliation_required`; the next startup/reconciliation repairs the projection instead of rolling the state back. For revocation, this degraded state can leave the old local SSH key effective until that repair succeeds, so the revoke request never reports success while the projection is stale. If atomic state publication itself reports an error after replacement may already have occurred, the hub read-backs the exact intended state bytes under the writer lock; an indeterminate/visible-new-state outcome is reported as `state_commit_uncertain`, and the SSH projection is left untouched until restart/reconciliation. In a split deployment set `probe_gateway_ports_locally` to `false`; the hub keeps no local `authorized_keys` projection, and each edge uses the authenticated `POST /internal/v1/ssh/authorized-key` lookup to obtain the exact restricted key line from the authoritative hub state. `onec-hub check` is read-only and never creates or repairs the projection. `reserved_ports` still excludes compatibility/static listeners from allocation. `onec-access list` consumes the same authoritative state regardless of where the hub process runs.

The hub does **not** persist per-agent control secrets. New enrollments persist only a non-secret 256-bit per-agent credential nonce; the control secret is derived with domain-separated HMAC-SHA256 from the fleet master key, stable machine ID, and that nonce. Every successful fresh re-enrollment generates a new nonce, so one compromised agent credential can be recovered independently without rotating the fleet master key. Legacy records without a nonce retain the historical v1 derivation until re-enrollment. State remains schema v1 while only legacy records/invites exist; the first nonce-bearing enrollment atomically promotes it to schema v2, after which pre-v2 hub binaries reject the state rather than silently deriving the wrong credential. Enrollment tokens are random, short-lived, one-use values; only their SHA-256 digests are persisted. Keep the fleet master key stable: changing it still changes every derived control credential and requires an intentional fleet migration.

The API compatibility transition requires current controllers before a current server. Current controllers accept the legacy bulk `control_secret` field from older servers as a redacted input; the current server advertises `agents.secret-free-inventory-v1` and `agents.control-credential-v1` from `/v1/info`, removes secrets from bulk `/v1/agents`, and serves only the exact per-agent credential endpoint. Old controllers require the bulk field and are incompatible with the current server; the server does not re-expose fleet secrets for compatibility.

Cryptographic construction is delegated to maintained primitives: RustCrypto `hmac` implements HMAC-SHA256 and `subtle` provides constant-time secret comparison. The HTTP daemon uses Axum/Hyper for HTTP parsing and routing, Tower for bounded concurrency/load shedding/timeouts, and tower-http for the request-body and no-store response policies. Hub code owns authentication, state transitions, allocation, audit and endpoint validation behind those transport layers.

The server process exposes only `check` and `serve`; only `serve` creates the application Tokio runtime used by Axum. Controller-side transport lives in the separate `onec-access` process and therefore cannot be pulled into the server runtime accidentally.

## Security model

- The HTTP listener must stay on loopback; terminate HTTPS in Caddy/nginx/another reverse proxy.
- Hub/controller/public/release URLs are parsed into one typed HTTPS model: a host is required; userinfo, query and fragment are rejected; trailing slash is normalized; non-root path prefixes and explicit ports are preserved. CLI URL arguments are strings only until this parse boundary.
- The hub operator token, agent-secret master key, and optional edge SSH-lookup token come from environment variables, never from `hub.json`. After resolution they are held as `secrecy::SecretString`; runtime Debug output is redacted and generic serialization is unavailable. Invite/control secrets use the same type, and plaintext is exposed only at bearer/HMAC/agent-request or explicit wire-response boundaries.
- Server `hub.json` is a toolkit-owned versioned schema and rejects unknown fields; controller-side configuration is owned independently by `onec-access`.
- The internal SSH lookup endpoint must remain private to trusted gateways. It returns only the restricted authorized-key line for an enrolled Ed25519 key and fails closed for unknown keys.
- Agent SSH keys are per-machine Ed25519 keys.
- Generated `authorized_keys` entries disable shell/PTY/X11/agent forwarding and use `permitlisten` to allow only that agent's allocated loopback reverse port.
- The remote port is never exposed on a public gateway interface.
- `state.json` and the generated `authorized_keys` file are written with mode `0600` on Unix.
- Invite creation, enrollment/re-enrollment, and decommission emit schema-versioned JSON audit events to stderr/systemd journal. They use stable event codes plus explicit typed fields and never log enrollment tokens or control secrets.

## Configuration and gateway integration contract

Server provisioning, credential management and rollout follow the [source and infrastructure boundary](../../docs/remote-agent-testing.md#source-and-infrastructure-ownership). `assets/hub.example.json` documents the versioned configuration shape. `onec-hub check` validates that configuration without repairing state or projections; `serve` owns the daemon lifecycle.

`gateway_host_public_key` contains a complete Ed25519 public host-key line. A colocated hub can own the restricted agent account's `AuthorizedKeysFile`; split deployments use the authenticated internal lookup endpoint through OpenSSH `AuthorizedKeysCommand`. The gateway account permits public-key-authenticated remote loopback forwarding only, with no shell, PTY, X11, password or agent forwarding. Per-key `permitlisten="127.0.0.1:<port>"` further restricts each machine to its assigned listener. The separate operator SSH projection belongs to `onec-access`.

## API

- `GET /healthz` — unauthenticated health probe.
- `POST /v1/invites` — operator token; creates a short-lived one-use enrollment token.
- `POST /v1/enroll` — enrollment token; registers/re-registers one machine and returns its runtime config.
- `GET /v1/agents` — operator token; returns the authoritative secret-free fleet inventory used by `onec-access`.
- `GET /v1/agents/<machine_id>/control-credential` — operator token; returns the derived control credential for exactly one enrolled machine at the controller connection boundary.
- `DELETE /v1/agents/<machine_id>` — operator token; decommissions a machine and revokes its managed gateway key.

`onec-hub` is the only supported managed-host inventory. Controller-side access operations do not maintain a second local server registry.
