# Vendored file-rotate

Upstream: https://github.com/kstrafe/file-rotate
Crates.io version: `0.8.0`
Upstream VCS base: `8ee371fd0e50d281e87d8a755aaeaa2c824f86b1`
Upstream subject: `Issue 29: Consistent number of arguments across OSes`

The toolkit commit `249f1b39` is the byte-for-byte upstream Git tree snapshot
(excluding only the upstream `.git` directory). The crates.io package's
`.cargo_vcs_info.json` points to the same VCS base.

Local generic patches are intentionally isolated:

- `da4385c6` — make active-file/directory lifecycle fallible, add
  `FileRotate::try_new`, fallible suffix scanning, and `sync_all`;
- `daa214a4` — add a caller-provided active-file opener used for initial
  creation and every post-rotation active file;
- `baffeabb` — add a pre-eviction hook so callers can durably record history
  loss before retention deletes an old segment;
- `1C-268` — use Chrono's non-deprecated `DateTime::date_naive()` for the
  daily rotation comparison without changing date-order semantics;
- `1C-270` — keep upstream behavior while making OpenOptions intent explicit
  and applying semantics-preserving syntax/import cleanups required by strict Clippy.

The patches are domain-neutral and contain no onec-toolkit/1C policy. The
toolkit uses them to compose its existing private-file and durable
history-loss policies around upstream rotation/retention mechanics.

When updating upstream:

1. import the new upstream Git tree as a byte-for-byte snapshot commit;
2. rebase/reapply only the local commits after the snapshot;
3. run upstream tests plus the patch-specific failure/opener/eviction tests;
4. run the onec-toolkit Linux and maintained Windows/Win7 acceptance matrix.

Remove each local patch when upstream provides an equivalent fail-visible
constructor/lifecycle, active-file opener hook, pre-eviction retention
notification, non-deprecated Chrono date comparison, or equivalent strict-Clippy
cleanup.
