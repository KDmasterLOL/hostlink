# Agent command queue

The Agent owns a fresh-only v5 Apalis SQLite queue. Schema v4 is incompatible and is never migrated automatically. The optional board binds only to a nonzero loopback address; Tower HTTP validates the exact `Host` header before dispatch, while a small middleware checks `Origin`. All task lifecycle headers, priorities, schedules and retry limits are passed directly to the upstream Apalis Board API without HostLink policy overrides. `/new` submits a program and JSON argument array to the official board API. Commands do not invoke a shell implicitly. Anyone with local access to the board can run commands with the Agent's privileges.

The Board no longer locks new task admission while the Agent updater is inspecting active jobs. The updater still checks native Apalis tasks under its own update lock, but it cannot rule out a new task being admitted after that check. Coordinated quiescence of the HTTP Board/worker before an Agent update remains a separate lifecycle issue.

Apalis may replay work after a worker or Agent crash, including commands that already started; side effects can therefore occur more than once. The upstream API accepts an idempotency key for repeated submissions. Process execution requires a ProcessKit containment backend capable of tracking the process tree. Shutdown requests stop active process groups.
