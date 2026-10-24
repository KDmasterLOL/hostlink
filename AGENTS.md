# HostLink engineering contract

HostLink is a stand-alone, general-purpose managed-host SSH and reverse-tunnel product.
It must not depend on OneC Toolkit source, 1C binaries, infobase models or project policy.

Read README.md and docs/extraction.md before edits. Use task branches and clean
worktrees for independent slices; do not overwrite another agent's work. Preserve exact
protocol compatibility and host identities until migration is separately accepted.
Prefer Rust standard-library and established crates to new generic abstractions.

All target mutations, deployments, service migration, production host operations,
main/tag/release publication and deletion from the original Toolkit are outside the
initial extraction authorization. Test on owned disposable fixtures only.

Verify fmt, Clippy, tests, executable/API parity, including Windows 7 where possible.
Do not report acceptance of native scenarios unless actually run.
