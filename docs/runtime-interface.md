# HostLink transport and runner ABI

## Responsibility boundary

HostLink owns remote-host connectivity, authenticated host selection, reverse SSH
and SFTP, exact process execution and lifecycle. It does not know or validate
OneC configurations, local Toolkit profiles, business databases, Python
dependencies, BSL payloads or test-framework success conditions.

A caller creates/owns scripts and chooses the interpreter (PowerShell on Windows,
sh/bash on Unix) and expected outcome; Hub does not execute user scripts.

## Existing transport constraints to preserve

- Existing Agent control RPC is how current Nextest run-local dispatches a
  cached executable and gets stdout/stderr/exit status.
- Embedded target russh currently offers SFTP and TCP forwarding, but explicitly
  refuses SSH exec and shell requests. Do not route run-local over SSH exec
  before the independent SSH-exec phase passes end-to-end native tests.
- Outbound Agent-to-gateway tunnel, Hub enrollment/identity, and pinned
  target host keys are owned by the new product, never by its callers.
- No inferred fallback from a missing/ambiguous Hub alias to direct DNS SSH.

## External Cargo/Nextest runner contract

Controller is installed separately and pinned to an exact accepted version/hash.
The originating project (such as OneC Toolkit) performs its OWN builds on its
own source checkout and invokes the external runner:

    CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_RUNNER="hostlink run-local ..."
    cargo nextest run --target x86_64-pc-windows-msvc -p onec-cli --test native_disposable

The renamed controller CLI exists in the independent workspace; the original
Toolkit runner/infra cutover has not been authorized or natively accepted.

The runner accepts the executable as the first trailing argument, then passes
following arguments byte-for-byte to the remote process including Nextest
discovery flags. It must:
- content-address stage the executable and caller-declared mapped files using
  a trusted SHA-256 and verify the remote bytes;
- select one exact enrolled managed host and avoid reusing unknown identities;
- send no progress text to stdout; forward raw child stdout/stderr unmodified;
- surface the child exit code locally for Nextest, reject missing exit status;
- preserve exact selection, run ID, target, source digest, scope/effect and
  verified cleanup, including recovery after timeout or disconnected controller;
- treat an unknown post-send result as unknown, never blindly replay mutations;
- permit run-owned disposable fixtures but never infer permission to alter a
  preexisting customer/prod resource.

Keep exact platform inventories, selection of Windows x64/legacy x64/legacy
x86, XWin build toolchain and Nextest filters in the CALLER, not HostLink.

## Hooks

Hooks are caller-created scripts. The caller decides when to run them and
whether pre/post failures abort its operation. HostLink provides SFTP/SSH,
explicit interpreter execution, timeout, output and exit code. No new package
manager, no embedded bootstrap magic and no executable arbitrary PowerShell
from unauthenticated Hub metadata.

Windows non-admin user-session scripts execute under their own user; service
mode must not accidentally grant them LocalSystem. For Windows NT 6.1, the
selected shell must actually exist on the host and be compatible with old
PowerShell. Pre-SSH bootstrap cannot be implemented using SSH hooks.

An SSH exec implementation must retain channel stdout/stderr ordering and
exit-status semantics, guard argument quoting/argv round trips, and scope
subprocess teardown including errors and cancellation. A pure SFTP service is
not a substitute for command execution.
