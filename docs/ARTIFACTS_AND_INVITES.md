# HostLink Agent artifacts and invitations — GitHub Releases only

The only production artifact origin is the private
`KDmasterLOL/hostlink` GitHub Releases repository. There is **no**
artifact website, mutable download mirror, operator-specified URL, or
alternate release provider. GitHub must have a published stable release
for latest selection; a private inaccessible or absent Release fails.

## Local package build (no publication)

`scripts/package-hostlink-agent.py` still produces a deterministic,
source-bound package for one supported target:

```sh
SOURCE_SHA="$(git rev-parse HEAD)"
cargo build --offline --locked --release -p hostlink-agent
python3 scripts/package-hostlink-agent.py \
  --source-sha "$SOURCE_SHA" \
  --target x86_64-unknown-linux-gnu \
  --version 0.1.0 \
  --binary target/release/hostlink-agent \
  --output-dir target/agent-package-linux-x64
```

For Windows7 x64/x86, produce the exact matching build receipt from
`scripts/build-win7-candidate.sh` and supply `--build-receipt`.
Validate the PE machine/subsystem/native compatibility independently.
Each package includes exact `manifest.json`, individual file SHA-256
and an external ZIP SHA pin. The ZIP contains
`hostlink-agent-TARGET/<member>` and is never repacked by the updater.

After all target builds pass the required source/build evidence, create
a **flat uniquely named** upload directory:

```sh
python3 scripts/stage-hostlink-github-release.py \
  --package-dir target/agent-package-linux-x64 \
  --package-dir target/agent-package-win11-x64 \
  --package-dir target/agent-package-win7-x64 \
  --package-dir target/agent-package-win7-x86 \
  --output-dir target/hostlink-release-v0.1.0 \
  --require-all-targets
```

The stage script checks each source revision/version/target receipt,
verifies packaged ZIP manifest, sidecar identity and every archive/file
SHA-256, and rejects duplicate/conflicting assets or incomplete targets.
The result contains exactly the flat assets documented in
[GitHub Releases](GITHUB_RELEASES.md): one target ZIP and one verifier
executable per target, plus a shared POSIX installer and PowerShell 2
installer. The hidden `.release-receipt.json` is local evidence only;
it is not an Agent download or replacement for GitHub's asset digest.
**Neither script creates or uploads a GitHub Release.**

A separately approved immutable release must publish those unchanged
assets with an exact `vX.Y.Z` tag. The GitHub API must expose each
asset's `sha256:<hex>` digest. Hashes prove content integrity relative to
GitHub's authenticated metadata, not an independent publisher signature.

## Managed invitation

```sh
hostlink invite --name lab-win7 --target x86_64-win7-windows-msvc
hostlink invite --name lab-win7 --target x86_64-win7-windows-msvc --version 0.1.0
```

The Controller reads its current user's separate private
`hostlink/credentials/github-token`, accesses the **fixed** GitHub
release API, selects the matching published release, demands exact
installer, verifier and archive names/digests, and downloads/verifies the
installer **before POST /v2/invites**. Caller-supplied
`--installer-url`, `--agent-url`, `--archive-url`, and independent
SHA CLI flags were removed from the managed production flow.

The generated target bootstrap command contains ONLY selected GitHub API
asset URLs/digests, Hub endpoint, target/name and nonsecret metadata. On
the target it prompts without echoing for a GitHub Fine-grained PAT
(repository-scoped `Contents: Read`) or reuses an existing verified,
user-owned credential file. Neither the token nor the secret's path is
sent to the Hub or embedded in release files.

After the installer and sidecar/ZIP hashes and manifest validate, the
**different, one-use Hub invitation token** is prompted and consumed.
All such installations are unprivileged and limited to the user's own
private root. A failed or uncertain enrollment is not retried
automatically because the Hub may have committed it.

`--token-only` remains for explicit manual enrollment and does not
create a runnable installer command. The old
`scripts/hostlink-managed-gateway-fixture.sh` Caddy source origin is
**historical** for the pre-1C-1159 manual URL interface; it must be
migrated to GitHub API fixture semantics before it can assert the new
managed invitation end-to-end.

## Security / validation

- No token is compiled into binary, put in command arguments or URLs,
  written to Hub, or printed in logs.
- The target credential uses `0600` with owner-only directory permissions
  (Linux) or protected current-user DACL (Windows). Stolen credentials
  expose the private repository's **source as well as binaries**.
- Auth is sent to `api.github.com` only; the one bounded HTTPS GitHub
  CDN follow-up never receives Authorization.
- The exact source SHA, ZIP digest, target, version and file identities
  are validated. Missing assets/digests or invalid metadata fail closed.
- No real GitHub release, Windows native deployment, or production
  Agent change is performed by this staging documentation.

See [GitHub lifecycle](GITHUB_RELEASES.md),
[Agent identity and installed updater](AGENT_INSTALLATION.md), and
[Fresh enrollment](ENROLLMENT.md).
