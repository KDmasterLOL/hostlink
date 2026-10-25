# HostLink — SSH-only rewrite

Experimental parallel rewrite. Not a drop-in replacement, release, deployment
or installed fleet cutover. Source baseline: dev 5a1f80b4c44c393dd8cc83faacf0a3ebc49de342.

Target packages:
- hostlink-agent: embedded SSH server, optional outbound reverse tunnel,
  SFTP, short exec, durable job lifecycle and a minimal Agent-only updater.
- hostlink: pinned SSH client, exec, transfer, forwarding and job-based
  test execution/reconnect.

Updates must pin the exact Agent artifact SHA-256/version/target, defer active
jobs and reject unsafe roots. Source-exact Windows stopped-process handoff and
rollback are required gates, not currently working features.

The original HostLink dev tree remains unchanged. The target contract and
milestones are in docs/ARCHITECTURE.md; current scaffold is not runnable.
