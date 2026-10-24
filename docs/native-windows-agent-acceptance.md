# Native Windows Agent acceptance harness

This harness exercises the current x64 MSVC Agent ZIP and the standalone manual
installer on an owned Windows 11 x64 user session. It is an acceptance aid for
Huly 1C-948. It does not enroll a real Hub, contact any gateway, install a
service, change `PATH`, or use an elevated token.

The harness and this document are source only, not acceptance evidence. Proof
exists only after the coordinator runs the script on WORK with source-exact CI
artifacts and retains the resulting receipt.

## Inputs and prerequisites

- Windows 11 x64, interactive unelevated normal user, Windows PowerShell 5.1.
- No existing `%LOCALAPPDATA%\HostLink\Agent` path. The script stops before
  creating fixtures if that path exists.
- The exact `x86_64-pc-windows-msvc` Agent ZIP from source-exact Windows CI.
- The matching installer script from that same source SHA. The harness also
  compares its bytes to the installer member in the ZIP.
- The SHA-256 copied from the trusted CI checksum sidecar and the exact 40 digit
  source commit SHA. The harness checks the ZIP digest; the coordinator must
  preserve the CI provenance that ties the artifact and installer to the source
  commit.
- `ssh-keygen.exe` from Windows OpenSSH, for native Ed25519 fixture keys.
- .NET `ZipArchive`, available on the supported Windows PowerShell 5.1 runtime.

Do not substitute GNU binaries, rebuild the ZIP locally, use a floating/latest
download, point this at another machine, or provide a real Hub enrollment
token. The package target is fixed to `x86_64-pc-windows-msvc`.

## Run

Use a new receipt filename under the current user's `%TEMP%` directory. The
script creates the receipt with create-new semantics and excludes usernames,
machine names, paths, key material, and control secrets.

```powershell
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File .\scripts\native_windows_agent_acceptance.ps1 `
  -SourceSha 0123456789abcdef0123456789abcdef01234567 `
  -AgentArchive 'C:\path\from-ci\hostlink-agent-x86_64-pc-windows-msvc.zip' `
  -ArchiveSha256 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef `
  -Installer 'C:\path\from-ci\Install-HostLink-Agent.ps1' `
  -ReceiptFile "$env:TEMP\hostlink-1c948-receipt-unique.json"
```

Use the real source SHA and digest from the CI run in place of the examples.
The receipt path must be absolute, inside the current user's temporary
directory, not a reparse path, and must not already exist. The script never
prints CI paths, Windows usernames, hostnames, test keys, or secrets.

## Checks performed

The script emits `PASS` markers and an optional JSON receipt containing the
source SHA, archive SHA-256, extracted Agent executable SHA-256, Windows build
and edition, PowerShell/CLR versions, subcheck results, and cleanup result.
Negative cases must fail before the install root appears:

- archive digest mismatch;
- missing manual config;
- unsupported foreign target;
- reparse-point config (explicitly `SKIP` only when Windows denies symlink
  creation to the current user).

Positive checks validate the exact four-file ZIP inventory, match the supplied
installer bytes to the ZIP member, create private disposable config/secret and
OpenSSH Ed25519 fixtures, run the source-exact installer in manual mode, run
`hostlink-agent.exe check --config`, invoke the installed updater with the
identical archive digest, compare installed file inventory before and after,
and run `check` again. The fixture pins only a generated fake host key to
`gateway.example.test` (RFC-reserved); this harness makes no network connection.
The `jobs_dir` value is exactly the fresh install root's `jobs` directory.

On success, the harness removes the install root only after verifying its
unique ownership sentinel, checking that no reparse point appeared, comparing
the installed files against the post-install inventory, and confirming the
root is absent after deletion. On any failure, or any cleanup ownership or
inventory uncertainty, it retains an existing install root for investigation
and removes only the verified owned temporary workspace. Inspect and resolve a
retained root before any retry. A temporary workspace cleanup failure is
reported as a warning.

The harness deliberately does not create an active durable-job fixture because
the public installer path creates a fresh empty jobs store and does not expose
a supported way to seed a live owned job. Active-job refusal remains covered
by the Agent's existing managed-update tests.

This run is not Windows 7 evidence. In particular, it does not establish
PowerShell 2 / CLR 2 compatibility or availability of `ZipArchive` on Windows 7.
