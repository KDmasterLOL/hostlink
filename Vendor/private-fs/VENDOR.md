# Vendored private-fs

- Upstream: https://github.com/orielhaim/private-fs
- Release: `v0.2.1`
- Pinned source commit: `07d542518b76d4eef6200523b6a7a57dd401b0e7`
- License: MIT OR Apache-2.0 (see `LICENSE-MIT` and `LICENSE-APACHE`)
- Use: HostLink Agent private filesystem capabilities; Win7 x86/x64 adaptation
  remains subject to native acceptance.

Source files were copied from the exact upstream Git revision, excluding the
inner `.git` repository. The nested `[workspace]` block was removed from
`Cargo.toml` so Cargo can include this path dependency in the HostLink
workspace. Local Windows 7 compatibility changes should be restricted to
the native Windows backend and documented in this file.

When updating, review upstream diffs and preserve all HostLink-specific
compatibility changes. Do not blindly replace this directory with `main`.

The Windows bindings generator is an isolated Cargo workspace so its
`windows-bindgen = 0.100` build-time dependency never enters the Agent
dependency graph. Verify the generated bindings match this checked-in source:

```sh
cargo run --locked --manifest-path Vendor/private-fs/tools/windows-bindings/Cargo.toml -- --check
```

This source-parity check also runs in HostLink's Linux dev CI. The generator
emits Win32 constants `FILE_DEVICE_DISK` and `FILE_REMOTE_DEVICE` as `i32`,
while the queried device fields are `u32`; the Windows backend casts the
positive constants at the comparison boundary rather than altering generated
ABI bindings by hand.

## HostLink integration and test-environment compatibility

HostLink now uses `PrivateDir`/`PrivateFile` for Agent enrollment, SSH keys,
SFTP, private locks, updater staging and durable journals. Remaining Agent
`private_fs/` code only bridges a validated handle to `std::fs::File` for
OS locks/Tokio and resolves Windows LocalAppData through a Win7-compatible API.
The former bespoke `cap-std` traversal and ACL validation are removed.

The HostLink fork intentionally uses protected, owner-only `OICI` on Windows
**directories**, while Windows **regular files** keep a noninheritable,
protected owner-only DACL. SQLite/Apalis creates `jobs.db`, `jobs.db-wal`,
and `jobs.db-shm` through its Windows VFS without supplying a security
descriptor: noninheritable directory ACLs would leave their access rights
dependent on the token's default DACL. The inherited ACE grants only the
already-authorized current user; no other SID is accepted. Directory
acquisition, creation and explicit hardening consistently require/publish
`OICI`. Existing directories with an otherwise owner-only noninheritable
ACL are not silently modified. A non-ignored Windows integration regression
(`crates/agent/tests/private_fs_windows_sqlite.rs`) checks actual SQLite
file ACLs and a default-DACL file in a disposable temporary directory.
It is included in Windows CI but has not yet run natively for this change.
The existing ignored lifecycle acceptance checks the same invariant in
a guarded disposable Windows profile; Windows 7 remains a separate gate.

On Linux, upstream's named-user POSIX ACL test originally hard-coded UID 12345,
which produces `EINVAL` inside user namespaces where that UID is not mapped.
The vendored test uses the mapped effective UID to exercise named-user and ACL
mask inheritance; its minimal default-ACL probe skips only mounts rejecting
the standard minimal ACL with `EINVAL`/`EOPNOTSUPP`. This is a test-only
portability change, not a relaxed production permission check. Native
non-owner named-UID ACL tests remain best exercised on a host with mapped UIDs.

HostLink source acceptance: Linux Agent library 54/54, Agent updater lifecycle
27/27, Linux service lifecycle 6/6, vendored `private-fs` Linux 91/91.
Generic Windows MSVC x86/x64 Agent all-target check and strict Clippy pass.
Pinned nightly `build-std` checks pass for `private-fs` on both true Win7
target triples; the full Agent `x86_64-win7-windows-msvc` `cargo-xwin check`
also passes with static CRT target flags. Full Agent Win7 i686 `cargo-xwin`
check is **not verified**: the needed x86 SDK/CRT cache was incomplete and
setup timed out. Windows 7/11 native runtime and protected disposable-profile
acceptance have **not** been run. These checks never deploy an Agent.

## HostLink 1C-1141: Windows 7 identity fallback

`nt::metadata` and `nt::identity_matches` share the same identity query. The
first query remains `GetFileInformationByHandleEx(FileIdInfo)`. Only
`ERROR_INVALID_PARAMETER` (87), `ERROR_NOT_SUPPORTED` (50), and
`ERROR_INVALID_FUNCTION` (1) permit the legacy path. Access denial and all
other failures propagate unchanged. This is capability detection, not an OS
version guess.

The fallback queries the same retained handle with
`GetVolumeInformationByHandleW` and
`NtQueryVolumeInformationFile(FileFsDeviceInformation)`. It requires all of:

- `FILE_PERSISTENT_ACLS`;
- the exact UTF-16 filesystem name `NTFS`;
- `FILE_DEVICE_DISK` and no `FILE_REMOTE_DEVICE` characteristic;
- a complete native device-information result.

Only then does `GetFileInformationByHandle` supply the full high/low 64-bit
file index and 32-bit volume serial. `Identity::Legacy` and
`Identity::Extended` are distinct variants. Equality compares the variant,
whole file ID, and whole volume serial. A change of representation fails
closed; there is no padding, truncation, or cross-variant coercion. Successful
extended queries retain the original 128-bit ID and 64-bit serial, including
on ReFS. ReFS, remote devices, other/unknown filesystems, missing ACL support,
and failed volume queries cannot use the legacy path.

The original kind/reparse checks, `FileStandardInfo` directory/delete-pending
and hard-link checks, protected owner-only ACL validation, retained-handle
scope, and publication/replacement checks remain in force. Pure policy lives
in inline modules in `nt.rs`; tests stay in `tests.rs`. The upstream large native
module layout is retained to keep the security-sensitive patch focused.

## No-reparse opens and trusted drive anchors

The first `NtCreateFile` attempt uses `OBJ_DONT_REPARSE`. Exactly
`STATUS_INVALID_PARAMETER` (0xC000000D) and `STATUS_INVALID_INFO_CLASS`
(0xC0000003) permit one retry without that object attribute. This follows the
single-component strategy in [Go's `openatFallback`, issue 78131](https://go.dev/src/internal/syscall/windows/at_windows.go),
which records that even Windows 10 build 10240 lacks the flag. Access denial,
reparse encounters, `STATUS_NOT_SUPPORTED`, and every other error do not
trigger this retry. The FileIdInfo fallback uses its separate Win32 error
allowlist above; neither fallback is selected by an OS-version guess.

Before either open attempt, the native layer restricts requests to:

- One nonempty normal component relative to a retained parent handle: no
  separators, colon/stream, NUL, `.` or `..`.
- An empty name only for an existing-handle reopen, with a retained parent,
  `FILE_OPEN`, an explicit access mask, and no creation descriptor. It names
  that exact object, not a path to resolve again.
- The dedicated drive-root acquisition described below. Arbitrary absolute
  or multi-component native requests are rejected before the syscall.

Both attempts retain `FILE_OPEN_REPARSE_POINT`, share flags, noninheritance,
the original parent handle and, when creating, the same protected descriptor.
Only `FILE_OPEN`, `FILE_CREATE`, and `FILE_OPEN_IF` are permitted: no overwrite,
truncation, or delete-on-close is requested. After a retry, `kind()` checks
the acquired handle for disk type, reparse attributes and expected kind before
returning it. Failure closes the handle. Newly created objects can remain on
failure, but were created with the protected descriptor. Any subsequent
truncation, write, ACL change or disposition remains after handle validation.

The retry requests `FILE_READ_ATTRIBUTES` even for a security-only reopen,
because the acquired handle must be inspectable. For an empty security reopen,
`FileStandardInfo` on the retained original supplies the directory/file kind.
If the DACL forbids the additional attribute access, reopening/hardening fails
closed before modifying the ACL; there is no privileged bypass or unchecked
handle return. The supported-flag path retains its original access mask.

The public root-acquisition code supplies exactly `\??\X:\`. The native layer
does **not** retry that DOS path without `OBJ_DONT_REPARSE`. It resolves `X:`
once using [QueryDosDeviceW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-querydosdevicew)
(available since XP / Server 2003). Only the first, current mapping is used;
prior mappings are never tried. Its target must be exactly
`\Device\HarddiskVolume` followed by nonempty ASCII decimal digits. The native
open uses that fixed target plus the root separator, including on its first
attempt; the drive alias is not resolved a second time. SUBST paths, UNC/MUP,
named pipes, other device prefixes, shadow-copy names, suffix components and
malformed results are rejected. The acquired root must pass `kind(true)`, a
complete device query proving `FILE_DEVICE_DISK` without `FILE_REMOTE_DEVICE`,
and the persistent-ACL check before a child can be acquired or created.

**Deployment trust assumption:** the OS-owned `\Device` namespace and the
process's drive mapping at acquisition are trusted. Kernel/administrator and
same-TokenUser attacks are already outside `SECURITY.md`'s boundary. The
checked device spelling is a deliberately narrow HostLink policy, not a
claim that every valid Windows drive mapping has this spelling. Other mapping
forms fail closed. The fixed device pathname avoids a drive-alias replacement
race; subsequent filesystem components are resolved only through retained
handles, with final-component nofollow and post-open checks on every retry.

## Windows API audit and remaining runtime gates

| API / boundary | Source audit and limitation |
| --- | --- |
| `FileIdInfo` | [Unsupported before Windows 8 / Server 2012](https://learn.microsoft.com/en-us/windows/win32/api/minwinbase/ne-minwinbase-file_info_by_handle_class); this patch handles the known unsupported-class errors. |
| Legacy file ID | [Microsoft documents the volume/index comparison and nonunique ReFS 64-bit IDs](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/ns-fileapi-by_handle_file_information). The fallback is restricted to local NTFS and live retained handles. |
| `GetFileInformationByHandle` | [Available since XP / Server 2003](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfileinformationbyhandle). Native validation of security-handle hardening and denied attribute access is still required. |
| `GetVolumeInformationByHandleW` | [Available since Vista / Server 2008](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getvolumeinformationbyhandlew). A failed query remains an error; no pathname-based volume lookup is substituted. |
| `NtQueryVolumeInformationFile` | [Available since XP; the documented user-mode name is `NtQueryVolumeInformationFile`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntqueryvolumeinformationfile). Device type/characteristics are queried through the original handle. Native Win7 completion and result reporting remain unverified. |
| `NtCreateFile`, `OBJ_DONT_REPARSE` | [The object-attribute contract rejects reparses](https://learn.microsoft.com/en-us/windows/win32/api/ntdef/ns-ntdef-_object_attributes); old kernels use the bounded fallback and trusted-anchor contract above. Native Win7 drive mapping, empty-name reopen, symlink/junction, protected creation and replacement behavior remain acceptance gates. |
| `FileIdBothDirectoryInfo` / restart | [The structure/classes are available since Vista / Server 2008](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_id_both_dir_info). Enumeration uses filenames, not these 64-bit IDs for identity. Independent cursor and buffer bounds checks remain. |
| `FileRenameInformationEx` | Existing code retries only the three known unsupported NTSTATUS values with classic `FileRenameInformation`, using the same source/parent handles. It never unlinks to emulate replacement. Classic replacement can refuse an open destination; test this on Win7. |
| Handles / ACLs / flush | Kernel handles remain noninheritable; directories now have owner-only `OICI` ACEs for SQLite's native child creation, while private files remain noninheritable. TokenUser ownership, protected DACLs, exact-handle disposition and writable-directory flush remain enforced. Test creation, inheritance, hardening, deletion, listing and flush on native x86/x64 NTFS. Unsupported flushes remain errors. |

An additional integration gate is the RNG/toolchain selection. The cached
`getrandom 0.4.3` source selects `ProcessPrng` for ordinary Windows targets;
its documented Win7 targets or `getrandom_backend="windows_legacy"` select
`RtlGenRandom` instead (see the dependency's `README.md` backend table).
The requested `*-pc-windows-msvc` checks do not establish Win7-loadable
standard-library/RNG imports. Target/backend selection and full Agent import
inspection belong to the coordinator, outside this patch's ownership.

## Verification recorded on 2026-10-30 (follow-up security fix)

Linux host, `rustc 1.99.1 (58cf8f9c3 2026-10-13)`. No native Windows machine
was available. No deployed Agent or production state was accessed. Only the
five approved vendor files were changed; the root manifests/lockfile and
HostLink consumer code were not modified.

| Check | Result |
| --- | --- |
| `cargo fmt --all -- --check` | PASS. |
| `git diff --check` | PASS. |
| `cargo xwin check --offline --locked -p private-fs --all-targets --target x86_64-pc-windows-msvc` | PASS, exit 0, original repository manifest and lockfile. |
| Same check, `i686-pc-windows-msvc` | PASS, exit 0. |
| `cargo xwin clippy --offline --locked -p private-fs --all-targets --target x86_64-pc-windows-msvc -- -D warnings` | PASS, exit 0; no new lint suppressions. |
| Same Clippy command, `i686-pc-windows-msvc` | PASS, exit 0. |
| `cargo test --offline --locked -p private-fs --lib path::` | PASS: 7 tests; 84 filtered out. No workspace-wide test run. |
| Linux pure policy harness | PASS: 7 exact-source tests of identity variants/bits, legacy metadata/ABI, error allowlists, local-device/ACL scope, normal components and trusted-anchor spelling. |
| Bindings generator `--check` | PASS on HostLink 1C-1141 QA: isolated workspace, locked `windows-bindgen 0.100`, byte-for-byte generated source matches tracked `bindings.rs`. |
| Native Win7 SP1 / Server 2008 R2 and modern Windows / ReFS | NOT RUN. No native runtime, reparse/race, hardening, publication, durability or ReFS acceptance PASS is claimed. |

The coordinator populated the original Cargo cache with `windows-link 0.100`,
`proptest 1.12` and `rstest 0.27`. The old missing-dependency blockers and
cached-version diagnostic workarounds are superseded by the exact locked
checks above. cargo-xwin used a writable existing cache at
`/tmp/hostlink-1c1141-xwin`; build outputs used
`/tmp/hostlink-1c1141-exact-target`.

The pure harness at `/tmp/hostlink-1c1141-open-policy/Cargo.toml` extracts the
unchanged `identity`, `open_policy`, `identity_tests` and `open_policy_tests`
modules and includes the actual bindings. It uses the actual vendored library
for error types, `windows-link 0.100.0` and `proptest 1.12.0`. Its executed
command was `cargo test --offline --locked --manifest-path
/tmp/hostlink-1c1141-open-policy/Cargo.toml --lib`. No syscalls are mocked;
this harness proves only pure policy behavior on Linux.

Thread-local hooks are test-only: one injects the unsupported FileIdInfo
Win32 error; the other injects the initial NtCreateFile NTSTATUS. The retry
executes the real native API with the production flags/descriptor. Windows
all-target checks compile the complete test suite, including the new tests
for both unsupported flag statuses, simultaneous legacy identity, private
creation/noninheritance, component-by-component root acquisition, junctions,
replacement races, error non-retry and file symlinks before truncation.
The file-symlink regression is explicitly ignored by default because native
creation needs SeCreateSymbolicLinkPrivilege (or Developer Mode on newer
Windows). It requires an explicit privileged native run; it is not a PASS.

**Remaining acceptance gates:** native Win7
x86/x64 root acquisition under the actual OS drive mapping; normal and forced
fallback creation/acquisition/reopens; junction and privileged file-symlink
regressions; permitted/denied attribute access during hardening; classic
publication, directory listing/deletion/flush; modern Windows/ReFS retaining
128-bit identity and refusing legacy ReFS identity; and the coordinator-owned
Win7 toolchain/RNG/import inspection. Cross-checks do not establish loader or
runtime support on Win7.
