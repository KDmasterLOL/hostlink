# TCP forwarding, RDP and probe

These commands use the configured Controller identity and exact SSH host key pin. When a gateway is configured, both gateway and target remain independently pinned. The data path is an authenticated `russh` direct-tcpip channel; the Client does not start OpenSSH or send Agent command RPC.

```text
hostlink forward --config host.json --listen 127.0.0.1:18080 --target 10.20.0.15:8080
hostlink rdp --config host.json                 # local 127.0.0.1:13389 -> remote 127.0.0.1:3389
hostlink rdp --config host.json --listen-port 13390
hostlink probe --config host.json --target 10.20.0.15:443 --timeout-ms 1500
```

`forward` and `rdp` run until Ctrl-C. They bind only to loopback, allow at most 16 active local connections, bound SSH channel opening, cancel active streams on shutdown, join their workers and close the SSH session. Failed channel opens and stream errors are reported to stderr. A local listener is not a firewall or target authorization boundary; Agent-side direct-tcpip policy remains authoritative.

`probe` opens and closes one SSH direct-tcpip channel to the requested target and exits zero only when the channel is accepted. Refused, timed-out, unauthenticated or pin-mismatched probes exit nonzero with an error on stderr. It checks TCP reachability from the SSH peer, not an application protocol or service health.

RDP support is only the local-to-remote socket mapping above. Automated tests use disposable echo sockets and do not connect to a real RDP service. `--config` remains the explicit HostSpec selection until managed Hub host selection is added separately.
