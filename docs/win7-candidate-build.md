# Win7 x64 MSVC Tier-3 candidate build

`.github/workflows/win7-candidate.yml` is a manually dispatched, source-exact
candidate build for the x64 Agent only. It checks out the dispatch commit,
requires the installed Windows MSVC linker/compiler and SDK, and attempts
`x86_64-win7-windows-msvc` with `nightly-2026-08-22`. It does not run on tags or
releases, has only `contents: read`, and uploads a three-day GitHub Actions test
artifact. It has no managed-host or release side effects.

Rust lists `x86_64-win7-windows-msvc` and `i686-win7-windows-msvc` as Tier 3.
Rust does not distribute prebuilt target libraries for these triples. Cargo's
unstable `build-std` requires nightly Cargo and rustc plus the `rust-src`
component; the workflow uses `-Z build-std=std,panic_abort` for that reason.
The pinned nightly is an explicit experiment: the Rust target documentation
reports the last known x64 host-tools success as 1.91.0, so a newer nightly may
fail while building the target standard library. Such a failure is recorded as
a failed workflow run; there is no ordinary `x86_64-pc-windows-msvc` fallback.
The build requests `+crt-static` because the real NT 6.1 fixture lacks the
modern UCRT redistributable and the initial MinGW candidate failed to load
with `0xC0000135`. This requirement is validated from the candidate's
`dumpbin /dependents` output; dynamic UCRT/VCRuntime imports fail the job.
Static-CRT linkage alone does not prove Win7 compatibility: the native loader
check is still mandatory.

On success, the workflow records the checkout commit and rustc version, evidence
that `std`/`panic_abort` were compiled by the pinned `-Z build-std` invocation,
PE machine, manifest extraction result, imported DLLs, and SHA-256 values. A
previous attempt incorrectly assumed Cargo always placed target std rlibs in
`target/<triple>/release/deps` and failed after the executable was built. It
packages the binary and exactly the three existing Agent PowerShell scripts
with `scripts/package_hostlink.py agent x86_64-win7-windows-msvc`. It verifies
the four ZIP members, package and raw-binary SHA-256 sidecars, and absence of a
`onec.exe` member. The raw `hostlink-agent.exe` is a separate artifact entry;
it is not injected into the ZIP a second time. The artifact name includes the
source commit and must be treated as a disposable test candidate, not a release.

## Evidence required before any Win7 claim

A successful Actions build proves only that this source commit produced and
packaged a PE candidate with the attempted toolchain. It does **not** prove
that the executable loads or works on NT 6.1. Before claiming native Win7
compatibility, the coordinator must transfer this exact artifact to an owned,
disposable Win7 x64 fixture and record all of the following:

- workflow URL/run ID, artifact name, source commit, target triple, and pinned
  rustc version;
- candidate SHA-256 checked against `hostlink-agent.exe.sha256`, plus ZIP
  SHA-256 checked against the ZIP sidecar;
- PE machine, embedded-manifest inspection result, and imported DLL/CRT list;
- NT 6.1 fixture identity and isolation, `hostlink-agent.exe --version`
  result with a finite timeout, and exit status;
- cleanup result confirming only the owned temporary candidate was removed.

The loader gate requires the hash-matched candidate to start on the owned NT
6.1 fixture and print its version before timeout. Import/CRT review must also
show that every required runtime dependency is available on the fixture. A
failed, timed-out, or unrun loader check leaves Win7 runtime support unproven.
Native loader acceptance should use a disposable NT 6.1 fixture. Where the user has
explicitly authorized a narrowly scoped test on an existing 1C server, limit
operations to SHA-verified binaries inside a uniquely owned private user
temporary directory, a finite non-interactive `--version` probe, read-only
import diagnostics and ownership-verified cleanup. Never install the Agent
persistently, enroll the production Hub, restart/replace services, or alter
1C data. A timeout or missing import is a failed native gate, not acceptance.

The x86 lane `i686-win7-windows-msvc` is a separate outstanding build and native
acceptance task. An x64 candidate does not provide evidence for it. Neither
workflow success nor package verification is release acceptance.

References: [Rust Win7 MSVC target support](https://doc.rust-lang.org/rustc/platform-support/win7-windows-msvc.html)
and [Cargo `build-std`](https://doc.rust-lang.org/cargo/reference/unstable.html#build-std).
