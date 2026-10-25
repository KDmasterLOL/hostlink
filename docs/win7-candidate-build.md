# Win7 MSVC Tier-3 candidate build

`.github/workflows/win7-candidate.yml` is a manually dispatched, source-exact
candidate build for either `x86_64-win7-windows-msvc` (default) or
`i686-win7-windows-msvc`. The choice is restricted to those exact triples. It
checks out the dispatch commit and requires the installed Windows MSVC
linker/compiler and SDK. The x64 path retains `vcvars64.bat`; the x86 path calls
VS 2022 `vcvarsall.bat x64_x86` and verifies the x64 compiler host, x86 target,
and x86 MSVC, Windows SDK UM and UCRT libraries. Missing tools or libraries
fail the selected build. It does not run on tags or releases, has only
`contents: read`, and uploads a three-day GitHub Actions test artifact. It has
no managed-host or release side effects.

Rust lists `x86_64-win7-windows-msvc` and `i686-win7-windows-msvc` as Tier 3.
Rust does not distribute prebuilt target libraries for these triples. Cargo's
unstable `build-std` requires nightly Cargo and rustc plus the `rust-src`
component; the workflow uses the pinned `nightly-2026-08-22` and
`-Z build-std=std,panic_abort`. The Rust target documentation says both targets
support `core`, `alloc`, `std` and `test`, and that host tools may work but are
not guaranteed; its last known x64 host-tools success is 1.91.0. The pinned
nightly is therefore an explicit experiment and can fail while compiling the
standard library. Such a failure is recorded as a failed workflow run. There
is no fallback to ordinary `*-pc-windows-msvc` targets.

Both target builds request `+crt-static` because the real NT 6.1 fixture may
lack the modern UCRT redistributable and the initial MinGW candidate failed to
load with `0xC0000135`. `dumpbin /dependents` rejects dynamic UCRT/VCRuntime
imports. The PE check requires machine `0x8664` for x64 and `0x14C` for x86.
Static-CRT linkage alone does not prove Win7 compatibility: native loader
checks remain mandatory. The Agent source already contains explicit Windows
x86 managed-update branches; successful cross-compilation and PE inspection
still do not prove runtime behavior on a 32-bit Win7 fixture.

On success, the workflow records the checkout commit/tree SHA and rustc
version, selected target, MSVC architecture/library evidence, evidence that
`std`/`panic_abort` were compiled by the pinned `-Z build-std` invocation, PE
machine, manifest extraction result, imported DLLs, static CRT setting and
SHA-256 values. It packages the binary and exactly the three existing Agent
PowerShell scripts with `scripts/package_hostlink.py agent <target>`. It
verifies the four ZIP members, package and raw-binary SHA-256 sidecars, and
absence of a `onec.exe` member. The raw binary is at
`.dist/out/<target>/hostlink-agent.exe` with its sidecar beside it, matching the
Controller's `/<target>/hostlink-agent.exe` sidecar URL contract. The ZIP is
named `hostlink-agent-<target>.zip`; the uploaded artifact name includes the
target and source commit. Each run produces only the selected architecture and
must be treated as a disposable test candidate, not a release.

## Evidence required before any Win7 claim

A successful Actions build proves only that this source commit produced and
packaged a PE candidate with the attempted toolchain. It does **not** prove
that the executable loads or works on NT 6.1. Before claiming native Win7
compatibility, the coordinator must transfer this exact artifact to an owned,
disposable Win7 x64 fixture and record all of the following:

- workflow URL/run ID, artifact name, source commit/tree SHA, target triple, and pinned
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
Native loader acceptance should use a disposable NT 6.1 fixture of the selected
architecture; for x86 on x64 Windows, WOW64 execution must be recorded
separately from native x86 execution. Where the user has
explicitly authorized a narrowly scoped test on an existing 1C server, limit
operations to SHA-verified binaries inside a uniquely owned private user
temporary directory, a finite non-interactive `--version` probe, read-only
import diagnostics and ownership-verified cleanup. Never install the Agent
persistently, enroll the production Hub, restart/replace services, or alter
1C data. A timeout or missing import is a failed native gate, not acceptance.

An x64 candidate does not provide evidence for x86, or vice versa. Neither
workflow success nor package verification is release acceptance. Native x86
acceptance remains outstanding until the matching artifact is loader-tested
on an owned fixture and its runtime behavior is verified.

References: [Rust Win7 MSVC target support](https://doc.rust-lang.org/rustc/platform-support/win7-windows-msvc.html)
and [Cargo `build-std`](https://doc.rust-lang.org/cargo/reference/unstable.html#build-std).
