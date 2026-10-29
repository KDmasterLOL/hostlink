# Agent command queue

The Agent owns an Apalis SQLite queue using upstream migrations only. Existing v5 databases are opened without HostLink schema scans or automatic migrations; missing jobs.db causes Agent startup to fail rather than create a replacement. Older jobs layouts are not imported or deleted. The optional board binds only to a nonzero loopback address; Tower HTTP validates the exact `Host` header before dispatch, while a small middleware checks `Origin`. All task lifecycle headers, priorities, schedules and retry limits are passed directly to the upstream Apalis Board API without HostLink policy overrides. `/new` submits a program and JSON argument array to the official board API. Commands do not invoke a shell implicitly. Anyone with local access to the board can run commands with the Agent's privileges.

Shared owner-private filesystem and Windows DACL operations live in
`crates/agent/src/private_fs/`. They are not an independent jobs store.

The service and updater do not query Apalis's Jobs table. On Linux the Agent holds a process-lifetime `jobs/runner.lock`; the updater requires that lock to be free before publication, while `update.lock` serializes concurrent updaters. On Windows managed updates use the authenticated control pipe to stop and wait for the owner process. Apalis retains pending and interrupted jobs; restarting a worker can replay commands and their side effects.

Apalis may replay work after a worker or Agent crash, including commands that already started; side effects can therefore occur more than once. The upstream API accepts an idempotency key for repeated submissions. Process execution requires a ProcessKit containment backend capable of tracking the process tree. Shutdown requests stop active process groups.
