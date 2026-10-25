# SSH-only parallel rewrite

Branch rewrite/russh-minimal is experimental and independent of current HostLink dev.
Do not modify, merge or promote dev/main, tags or deployed infrastructure.
The former Agent JSONL TCP listener, Win32 OpenSSH/sshd, legacy Toolkit release engine,
legacy Nextest attestation, Hub and source dependencies are excluded from this
compiled workspace. Keep only russh as SSH transport, russh-sftp and a bounded
process execution primitive.

Short SSH exec cancels on channel close; durable jobs are a different lifetime
owned by the Agent process. Reconnect must NEVER silently replay a started job.
Use exact host key pins, controller authorized Ed25519 keys, private owned paths,
bounded concurrency and byte streams, fail-closed security and Windows 7 PS2 support.
No unmanaged background processes, false success or unbounded retries.
A minimal Agent-only updater is REQUIRED: exact version/target/SHA, private
staging, an exclusive update lock, installed-file integrity, active-job deferral,
recovery on failed publication and explicit safe handoff on Windows. It is NOT
another SSH transport, not a general release engine and not the Toolkit updater.
Changes to real servers require independently verified disposable scope; do not
alter 1C production databases, running services or original OneC Toolkit.
