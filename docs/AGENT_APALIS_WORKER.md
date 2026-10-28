# Agent worker

The current owner is `crates/agent/src/jobs/`. See the
[1C-1081 minimal jobs contract](AGENT_MINIMAL_JOBS.md) for queue, native
lifecycle/result, execution fence, private files and fresh-only roots.

Executed checks and acceptance limits are recorded in the
[1C-1081 evidence](AGENT_MINIMAL_JOBS_EVIDENCE.md). Earlier 1C-1073 evidence
is historical and does not certify the current breaking protocol/schema.
