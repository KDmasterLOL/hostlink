# TCP forwarding, RDP and probe

These operations use pinned authenticated SSH. Select a managed host with `--host NAME` or a separately configured `HostSpec` with `--config PATH`.

```sh
hostlink forward --host lab-host --listen 127.0.0.1:18080 --target 127.0.0.1:8080
hostlink rdp --host lab-host --listen-port 13390
hostlink probe --host lab-host --target 127.0.0.1:443 --timeout-ms 1500
```

`forward` and `rdp` bind only to the Controller's loopback interface and run until interrupted. The Agent's direct-TCP policy still decides which remote targets are allowed.

`probe` tests TCP channel admission from the SSH peer, not application-level service health. It returns a nonzero status for refused, timed-out or unauthenticated connections.
