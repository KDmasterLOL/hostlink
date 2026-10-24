# Cargo and Nextest runner parity

This document freezes the external `hostlink run-local` interface for callers
that already use Cargo and Nextest. It does not migrate or modify the original
OneC Toolkit caller. That cutover requires a separate authorization and native
acceptance.

## Runner command and discovery

Cargo supplies the selected target executable and its arguments after the
configured runner command. Keep `--` as the boundary between HostLink options
and that child argv. For example, a Windows MSVC target can be configured as:

```sh
export CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_RUNNER='hostlink run-local --target windows-current-x64 --required-effect disposable --map-file-env NEXTEST_BIN_EXE_onec --'
cargo nextest run --target x86_64-pc-windows-msvc -p onec-cli --test native_disposable
```

The effective invocation is:

```text
hostlink run-local --target windows-current-x64 \
  --required-effect disposable \
  --map-file-env NEXTEST_BIN_EXE_onec -- \
  <cargo-built-test-executable> <cargo/nextest-supplied-arguments...>
```

The target runner receives the executable first. HostLink forwards all
subsequent arguments, including Nextest's `--list` discovery arguments, as the
child command arguments. The caller keeps its existing `cargo nextest run`
command, package/test selection, filters, scheduling, and per-test timeouts.
The runner does not replace Nextest or reinterpret its discovery output.

The syntax above is an interface example, not a deployed Toolkit setting. The
caller must choose an enrolled target whose identity and effect policy match
the run. There is no fallback from a missing or ambiguous target to DNS, SSH,
or another enrolled machine.

## Pin and verify the external runner

Install HostLink separately from the caller's source checkout. Pin both an
accepted release version and the SHA-256 of the downloaded controller binary;
do not use a floating `latest` artifact. The extraction baseline
`eac77fabd5038613ef17e5f67e3e23aa9d43e840` is source identity, not an accepted
binary release or a substitute for the release pin.

```sh
HOSTLINK_VERSION='<accepted-version>'
HOSTLINK_SHA256='<accepted-controller-sha256>'
curl --fail --location "$HOSTLINK_ARTIFACT_URL/$HOSTLINK_VERSION/hostlink" -o ./hostlink
printf '%s  %s\n' "$HOSTLINK_SHA256" ./hostlink | sha256sum --check --status
```

The release process supplies the concrete version, artifact URL, and digest.
Do not enable the caller until these values refer to a reviewed, accepted
controller artifact. Record the version, SHA-256, target triple, and source
revision with the test receipt.

HostLink content-addresses the local test executable and each file named by
`--map-file-env` using SHA-256, verifies staged bytes on the Agent, and uses the
content digest in its remote cache name. A caller maps a local test asset by
exporting its path in the environment variable expected by the test and naming
that variable to HostLink:

```sh
export NEXTEST_BIN_EXE_onec="$PWD/target/x86_64-pc-windows-msvc/debug/onec.exe"
```

```text
--map-file-env NEXTEST_BIN_EXE_onec
```

The child receives that variable rewritten to the staged remote path. Mapped
assets must be caller-owned regular files. HostLink rejects a missing,
directory, or symlink candidate/mapped path before remote execution.

## Output, status, and effect boundary

- Standard output is reserved for raw child stdout. HostLink diagnostics and
  errors go to standard error; it does not prepend progress text to child
  stdout.
- The child exit code is the local runner exit code and is authoritative for
  Cargo/Nextest. A missing remote exit status is an error, not success.
- `--required-effect` is supplied by the caller for each invocation:
  `read-only`, `run-owned`, or `disposable`. The label describes the maximum
  effect permitted by the caller's owned fixture. HostLink does not infer test
  success or approve effects from a test name.
- If the result after submission is unknown (for example, a disconnect before
  the terminal result is received), keep it unknown and investigate its
  evidence. Do not automatically replay the invocation: it may have mutated a
  caller-owned fixture already.
- Use a unique enrolled machine identity and a dedicated disposable fixture
  when the test can write state. Never target a customer or production host
  from runner acceptance tests.

## Native receipt matrix

No native runner acceptance receipt is claimed by this source-level contract
change. Each row remains a separate required test on an owned disposable
fixture:

| Target | Native runner receipt | State |
|---|---|---|
| Current Windows x64 | Exact HostLink version/SHA, target triple, source revision, selected machine identity, mapped asset digests, `--list` discovery, bounded test results, stdout/stderr, exit code, effect, and cleanup evidence | Deferred; not run here |
| Windows 7 x64 (`x86_64-win7-windows-msvc`) | Same receipt fields plus source-exact toolchain/loader evidence and NT 6.1 runtime identity | Deferred; not run here |
| Windows 7 x86 (`i686-win7-windows-msvc`) | Same receipt fields plus source-exact toolchain/loader evidence and NT 6.1 runtime identity | Deferred; not run here |

For every row, retain both successful `--list` discovery and the bounded
caller-selected test result. The receipt must bind the actual executable and
mapped-asset SHA-256 values, exact runner version, machine identity, effect,
raw stdout/stderr, exit code, and verified cleanup. Windows 7 targets require
dedicated source-exact toolchains and real NT 6.1 fixtures; a cross-build or
current-Windows run cannot establish their runtime behavior.

## Deferred Toolkit and infrastructure migration

The initial deliverable tests the external CLI contract against owned local
fixtures and documents the remaining native matrix. It does not change the
original Toolkit's `Justfile`, Nextest configuration/tests, release assets,
installed services, or infrastructure automation. Keep the current Agent RPC
run-local backend until SSH exec independently passes its end-to-end native
parity gate. After the native receipts are accepted, a separately authorized
Toolkit/infra task can pin the external binary and migrate the caller while
preserving its test discovery and filters.
