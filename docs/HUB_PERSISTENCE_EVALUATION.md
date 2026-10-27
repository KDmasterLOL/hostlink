# Hub persistence evaluation: JSON v2 and redb 4.4.0

Status: **isolated native Windows 11 PoC executed and verified** on 2026-10-27.
The HOME machine could not resolve crates.io, so dependency download and actual
tests were performed on WORK Windows 11 with Rust 1.99.0. The production Hub
still uses JSON; no state was migrated. The executable PoC source is retained
separately on branch `task/1c-1062-redb-poc@140a49403a72a94a1b1be707f13935674246fd36`;
it is not included in the default development workspace or compiled runtime. This is a nonproduction experiment under
`experiments/hub-redb-poc/`. It does not change Hub runtime code, import deployed
data, or alter the root Cargo workspace.

## Scope and evidence

The baseline was derived by reading `crates/hub/src/state.rs`. Current JSON v2
loads and validates a bounded complete state while holding an OS file lock,
then serializes the complete state, writes a private same-directory temporary
file, syncs it, atomically renames it, and syncs the parent directory on Unix.
It reads back after publication errors to distinguish committed/uncertain
outcomes. The PoC exercises this full-snapshot atomic-publication shape and
compares it with redb tables for schema version, hosts, normalized host names,
ports, and digest-indexed invites.

Both backends model unique host ID/name/port, an invitation keyed by a
lowercase 64-character digest, expiry and one-use redemption, restart/readback,
rollback, and concurrent readers. JSON decoding and domain validation reject
malformed or inconsistent snapshots. The migration test is a parser/validator
probe only; it does not perform a production migration or write a destination.

redb's transaction commits storage atomically and supports concurrent readers
with a writer, but it does not enforce the Hub's identity or invitation rules.
Those checks and secondary indexes still need explicit application code. The
PoC does not reproduce the production path's complete symlink, ACL/permission,
record-size, lock-timeout, or commit-uncertainty contract. In particular, a
redb commit error must be treated as uncertain until a production design proves
how it can be reconciled; the PoC does not claim that redb eliminates this
behavioral requirement. Neither backend tests operator/gateway authentication,
one-shot secret response behavior, or revoke/API semantics.

## Execution and measurements

The executable accepts an optional record count (default 50, maximum 500),
performs three transactions for each host (register, invite, redeem), then
measures reading the final complete snapshot. All data live in disposable
temporary directories. A **full 500-record comparison did not finish** within
the initial 150-second native run, because the PoC redb implementation
reconstructs every table and index in every write transaction. This is a
limitation of this adapter, not a benchmark of optimized redb.

Verified on WORK Windows 11, Rust 1.99.0, `redb = 4.4.0`, with the
standalone `experiments/hub-redb-poc/Cargo.lock` (26 packages):

| Operation | JSON snapshot backend | redb full-table-rebuild backend |
| --- | ---: | ---: |
| 50 hosts × 3 writes | 1.519 s | 2.724 s |
| Snapshot with 50 hosts / 50 invites | 11.362 ms | 0.816 ms |
| 100 hosts × 3 writes | 3.647 s | 8.048 s |
| Snapshot with 100 hosts / 100 invites | 11.263 ms | 2.167 ms |

`cargo test --offline --manifest-path experiments/hub-redb-poc/Cargo.toml`
passed **6/6** on WORK Windows 11: domain invariants, duplicate rejection,
one-use/expiry, failed redemption rollback, uncommitted redb rollback,
reopen/readback, malformed and inconsistent JSON rejection, and parallel
readers during writes. The PoC has four direct dependencies (redb, serde,
serde_json, tempfile) and produced a **33,365,518-byte debug executable** on
that test host. Debug binary bytes are not comparable to the production Hub
without a like-for-like release build.

The current PoC redb adapter itself is roughly 220 lines, plus a common
domain/schema layer and explicit indexes; the JSON adapter is roughly 190.
The running Hub's original `crates/hub/src/state.rs` is 374 lines including
security policy and reconciliation. Adding a database does not remove the
application's private ownership, identity/port uniqueness, registration,
migrations, and uncertain-commit requirements. An optimized redb adapter would
need incremental table/index updates and independent failure tests, changing
both implementation and measurement characteristics.

HOME cannot reproduce the PoC offline until redb 4.4.0 is available in its
Cargo cache. The Windows test is a valid execution of the standalone PoC, but
is not native Windows 7 or production Hub acceptance.

## Decision gate

**Do not migrate the Hub to redb yet.** The proof shows working ACID/MVCC
mechanics and faster reads with this small snapshot, but the initial adapter
adds source code and is slower on writes because it rebuilds secondary indexes
rather than applying incremental changes. There is no demonstrated net LOC
reduction or production-equivalent failure guarantee.

If fleet scale or concurrent read requirements justify a database later,
repeat this experiment with incremental updates, realistic concurrency and
a source-exact migration plan. Production adoption also needs owned-private
database file/directory and symlink checks, JSON-v2 import validation,
schema migration/backup, crash recovery, and honest commit-uncertainty
reconciliation. This experiment does not modify Hub runtime state or authorize
any deployed database migration.

The PoC can be checked out from that exact task branch to reproduce the
standalone `experiments/hub-redb-poc` tests; the locked root workspace does
not gain a redb dependency.

## JSON Hub request cancellation and lost acknowledgements (1C-1062)

The async I/O candidate at `0a78f729d34b692bd527bcdd2838634701bcb6f9`
detached a running `spawn_blocking` operation when its HTTP future was dropped.
A regression with a held registry writer lock, a polled `POST /v2/invites`,
request cancellation, lock release and blocking-worker drain reproduced an
unacknowledged persisted invite on that baseline. The same regression now
requires no snapshot publication, then exactly one invite/audit entry for a
subsequent explicitly authorized request.

All four mutations (invite, enroll, display-name update, revoke) now require a
one-use `CommitAdmission`. The HTTP future owns a Tokio oneshot receiver across
the worker await. Immediately before `LockedState::commit`, while still holding
the registry lock, the worker sends to that receiver. The existing Tokio
`Sender::send` atomically orders admission against receiver drop; no new
dependency, state engine, HTTP endpoint or token readback is needed.

- If the server request future was dropped before admission, the send fails
  and the local locked snapshot is discarded. In particular, cancellation
  before obtaining the writer lock cannot publish state or reconcile keys.
- If admission wins the race, publication is irrevocably attempted. The
  synchronous commit and subsequent enroll/revoke projection reconciliation
  finish even if the request disappears. The send only admits publication;
  it is neither a successful commit receipt nor an HTTP acknowledgement.
- Storage `NotCommitted`/`Uncertain` handling is unchanged. Projection failure
  after a committed enrollment or revocation still returns reconciliation
  required (503), never a successful receipt. Revoke success still requires a
  reconciled gateway projection and makes no session-termination/uninstall claim.

A client timeout, disconnect or missing response remains **UNKNOWN**: the
client cannot observe server admission, and a transport disconnect need not
immediately drop the server future. There is no automatic application replay
in the existing Client/Agent enrollment paths. Do not infer rollback or retry
a mutating request from a transport failure. Manually reconcile authoritative
host identity/keys/routes, audit and gateway authorization before deciding a
new action. The Agent's existing pending enrollment marker preserves the
attempt identity and prevents blind one-use-token reuse.

For an invite with a lost response, only its digest is persisted. Its plaintext
cannot be recovered. Retain UNKNOWN, wait out the original bounded TTL
(30..86400 seconds; at most 24 hours if the original expiry is unavailable),
and authorize a fresh invite only after reconciliation. Expired/used records
are pruned by the next legal invite; capacity remains bounded at 10,000. For
enrollment, a lost response does not unconsume the token: lookup may show a
committed host and replay remains unauthorized. For revoke, authoritative
absence and gateway projection/lookup must be checked separately; a lost
response does not restore either host or gateway key.

The API regressions use real Hub handlers, private disposable files and OS
locks. Cancellation tests poll the request behind the lock (worker queued or
waiting), drop its future, release the lock and drain the dedicated Tokio
runtime before inspecting persistence. They cover all four mutations and
locked `/healthz` responsiveness. Lost-response tests discard the actual
prepared HTTP response without reading its body, then verify invite expiry,
enrollment one-use/replay and revoke registry/projection/lookup. They do not
inject cancellation inside fsync/rename, simulate a storage crash, or claim
native Windows acceptance. Already-running blocking lock waits are not
interrupted; the existing five-second lock acquisition timeout remains.

Local verification on Linux with Rust/Cargo 1.99.1 (all Cargo commands used
`--offline --locked`):

| Check | Result |
| --- | --- |
| Scoped rustfmt, workspace `cargo fmt --all -- --check`, `git diff --check` | PASS |
| `cargo check -p hostlink-hub -p hostlink --all-targets` | PASS |
| `cargo clippy -p hostlink-hub -p hostlink --all-targets -- -D warnings` | PASS |
| `cargo check -p hostlink-hub --no-default-features` | PASS |
| `cargo test -p hostlink-hub --test api` | 18 passed, including baseline-red cancellation regression |
| `cargo test -p hostlink --test hub_client` | 2 passed |
| `cargo test -p hostlink-hub --lib` | Completed; no unit tests in this target |
| Client library unit tests | 30 passed; 2 failed at loopback listener setup with sandbox `EPERM`, not accepted as passing |
| Agent enrollment unit tests | 1 passed; 5 failed because the sandbox prohibits loopback bind/reservation, not accepted as passing |
| Native Windows / full workspace runtime acceptance | NOT RUN for this change |

The expiry scenario advances the disposable snapshot to an expired timestamp,
as existing API expiry tests do; it does not sleep for the real token TTL.
Client loopback and Agent runtime checks require an environment permitting
disposable listeners before the coordinator can accept those evidence tiers.
