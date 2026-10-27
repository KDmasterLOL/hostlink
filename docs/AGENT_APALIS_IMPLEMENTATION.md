# 1C-1073 implementation context

Source: clean `dev@4570a45c5ba53f5440a8265906393cbcf629c033`.
Scope: task/1c-1073-apalis-production only. No deployment or promotion.

1. Replace `jobs/` with `durable/`: real Apalis SQLite Jobs payloads,
   validated owner/UUID/spec, FULL on every connection, transactional one-use
   started claims and conservative restart recovery. Keep private filesystem,
   sealed artifact and raw bounded output ownership here. No JSON record backend.
2. Replace SSH job_* files with cohesive `ssh/jobs/` modules; preserve jobs-v1
   bytes, processkit tree cancellation, source verification and channel lifetime.
3. Update updater/service/enrollment and all tests/imports to the new owner.
   Synchronous service/update safety scans may bridge to a private Tokio runtime
   on a scoped thread; the store itself stays async. Lock order: update lock,
   then SQLite transaction. Started/Interrupted always blocks replacement.
4. Refuse legacy UUID directories without modifying them, with an actionable
   migration diagnostic. Never silently initialize around existing records.
5. Port regressions; add FULL/reconnect, ACK loss, immutable identity, orphan
   recovery, output/legacy corruption and update interlock negative cases.
6. Run format, workspace checks/tests, strict Clippy and Agent/Client SSH tests;
   obtain independent source-exact negative review. Record actual evidence and
   commit only on the task branch if Git metadata permissions permit.

Frozen jobs-v1 has no scheduling input; do not add untrusted scheduling or cron.
Apalis automatic orphan fetching/retry is deliberately not used: claim eligibility
and lifecycle remain tied to the immutable Apalis payload and StartedClaims.

The runtime-open fail-open correction is a focused follow-up: explicit fresh
initialization is separate from strict existing-store opening. It preserves the
coordinator's missing-DB updater guard and updates provisioning fixtures.
Broader WorkerBuilder, output, native and handoff findings are separate work;
this follow-up does not certify the whole migration. Executed checks are
recorded in [the evidence receipt](AGENT_APALIS_EVIDENCE.md).
