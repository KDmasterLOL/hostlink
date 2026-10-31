# HostLink Agent artifact packaging and invites

`scripts/package-hostlink-agent.py` builds a local immutable candidate layout for one exact source SHA, target, and semantic version. It does not publish files, select an HTTPS host, or contact the Hub. Choose an output path that does not exist under a current-user-owned directory.

```sh
SOURCE_SHA="$(git rev-parse HEAD)"
cargo build --offline --locked --release -p hostlink-agent
scripts/package-hostlink-agent.py \
  --source-sha "$SOURCE_SHA" \
  --target x86_64-unknown-linux-gnu \
  --version 0.1.0 \
  --binary target/release/hostlink-agent \
  --output-dir target/agent-artifacts-0.1.0
```

For Win7, build the current source with `scripts/build-win7-candidate.sh` first and pass the matching `receipt.json` using `--build-receipt`. The packager checks its source SHA and executable digest and validates the PE Machine (`x86_64`/AMD64 or `i686`/x86). A stale receipt or a binary from another source is rejected. Native Windows 7 and Windows 11 PowerShell acceptance remains a separate gate.

The resulting structure is:

```text
OUTPUT/
  artifact-receipt.json
  invite-inputs.json                 # hashes only; artifact URLs are operator-selected
  VERSION/
    hostlink-agent-TARGET.zip
    hostlink-agent-TARGET.zip.sha256
    Install-HostLink-Agent.ps1       # Windows; Linux uses install-hostlink-agent.sh
    TARGET/
      hostlink-agent.exe             # Windows; Linux uses hostlink-agent
      hostlink-agent.exe.sha256      # Linux name omits .exe
```

The ZIP contains only the required `hostlink-agent-TARGET/<contract files>` set. The packager emits a deterministic order, but the Agent verifier does not depend on that order. Its manifest is stable JSON with current `format: 2`, component, target, version, and sorted file identities. ZIP timestamps are fixed, files are regular entries with executable mode only on the binary, and compression is DEFLATE. Archive and sidecar SHA-256 pins are recorded separately. Outputs are created under a private directory; an existing output is never replaced.

Before using the values in `invite-inputs.json`, copy the candidate into an immutable HTTPS artifact directory under a URL you control. Preserve the exact bytes and pins. The expected URL paths are:

```text
https://ARTIFACT_ORIGIN/VERSION/Install-HostLink-Agent.ps1
https://ARTIFACT_ORIGIN/VERSION/TARGET/hostlink-agent.exe
https://ARTIFACT_ORIGIN/VERSION/hostlink-agent-TARGET.zip
```

The configured optional `--hub-ca-cert` is also added to the Client's normal TLS roots for the installer preflight. Certificate and hostname validation stay enabled. For a Linux target using a private CA, pass `--bootstrap-hub-ca-cert /path/on/target/hub-ca.pem` to `hostlink invite` and make that exact PEM available at that target path. The generated command uses it with curl for the installer; the installer uses it for the sidecar, ZIP, and Agent enrollment. The option does not bypass certificate or hostname validation. Windows targets use their normal trusted certificate store.

For Linux use `install-hostlink-agent.sh` and `hostlink-agent`. Keep all three URLs on the same HTTPS origin. Do not use redirects, URL credentials, TLS bypasses, mutable aliases, or a URL that embeds an invite token. The invite command checks the installer bytes and its contract before asking the Hub to create an invite; the installer separately verifies the binary sidecar and ZIP before prompting for the one-use token.

Example command template (replace every `ARTIFACT_ORIGIN`, `TARGET`, digest, and host-specific value with independently verified values):

```sh
hostlink invite --name lab-win7 --ssh-user hostlink --ttl-seconds 900 \
  --target TARGET --version VERSION \
  --installer-url https://ARTIFACT_ORIGIN/VERSION/Install-HostLink-Agent.ps1 \
  --installer-sha256 INSTALLER_SHA256 \
  --agent-url https://ARTIFACT_ORIGIN/VERSION/TARGET/hostlink-agent.exe \
  --agent-sha256 AGENT_SHA256 \
  --archive-url https://ARTIFACT_ORIGIN/VERSION/hostlink-agent-TARGET.zip \
  --archive-sha256 ARCHIVE_SHA256
```

Use `--help` for platform-specific output and shell quoting. `invite-inputs.json` intentionally has no URL fields: the packager cannot establish control of an HTTPS origin and never invents one. Keep the generated one-use token separate from the copyable installer command.

## HOME end-to-end fixture

Run `scripts/hostlink-managed-gateway-fixture.sh` from a clean, committed task revision. It packages the Linux release Agent from that exact `HEAD`, publishes the immutable package directory with Caddy on the fixture's HTTPS origin, and runs both ignored process-level tests. The installer scenario invokes the actual `hostlink hub configure` and source-pinned `hostlink invite` commands, executes the exact rendered POSIX command in a PTY, and enters the token only after the script, sidecar, and ZIP have passed their pins. It then checks the running enrolled Agent through Hub inventory, verify, exec (including exit 7), SFTP, durable jobs, replay denial, gateway authorization, and revocation. A disposable Caddy redirect, unrelated CA, hostname mismatch, wrong installer pin, modified sidecar, and modified ZIP are rejected before the token prompt; the same unconsumed token is used for the successful run.

All fixture processes, keys, Hub state, Caddy data, SSH authorization projection, and package files live in fresh temporary roots and are removed on exit. This is Linux HOME evidence only; native Windows 11 and Windows 7 PowerShell 2 gates remain separate.

## Windows package scripts

`Run-HostLink-Agent.ps1` starts the installed executable unelevated with the root's private `state/agent.json`. Root/config retain owner-only checks; the nonsecret bundle rejects reparse points and uses native permissions/ACLs. `Update-HostLink-Agent.ps1 -Url ... -Sha256 ... -Target ... -Version ... -Updater ...` invokes the real high-level updater after the operator stops/removes the current-user task and supplies a verified separate executable beneath the root, outside bin. It performs no task registration/removal or automatic restart. See [the updater contract](SELF_UPDATE_REWRITE.md).

The scripts use Windows PowerShell 2 syntax. A source review or modern PowerShell parser does not replace a native PS2 run on Windows 7 x64 and true 32-bit Windows 7 x86.
