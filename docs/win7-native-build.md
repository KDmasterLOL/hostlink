# Windows 7 x64 MSVC test candidate

`.github/workflows/win7-native-candidate.yml` builds an isolated Windows 7 x64
Agent candidate for disposable native testing. It runs only when this task
branch receives a push. It does not run in the regular `dev` CI lane and does
not publish a release, tag, or deployment package.

The job checks out the exact pushed commit, verifies the branch and target,
installs `nightly-2026-08-22` with `rust-src`, and builds the Tier-3 standard
library and Agent for `x86_64-win7-windows-msvc` with `crt-static`. The build
also fails if PE imports still depend on dynamic UCRT or VCRuntime DLLs, which
were missing from the inspected NT 6.1 target. It does not install a CRT on
the target. It runs Agent tests and the
candidate's `--version` command on the current `windows-latest` host. The job
also inspects the resulting x64 PE headers and imports with MSVC `dumpbin`,
then packages only the Agent executable and its three bundled PowerShell
scripts.

The job uploads the verified ZIP and its checksum, plus the same executable
and a checksum sidecar at
`x86_64-win7-windows-msvc/hostlink-agent.exe`. The target-specific path is
preserved for consumers that fetch the Agent directly. Artifacts expire after
three days. The job requires read-only repository permissions and does not use
secrets.

Passing this workflow proves a source-exact cross-build, packaging checks, and
execution on the current Windows CI host. It does not prove Windows 7 / NT 6.1
loader or runtime compatibility. That requires separate testing on an owned,
disposable Windows 7 environment; it does not authorize service changes or
tests against original Toolkit hosts.
