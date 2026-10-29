# Agent command queue

The Agent owns a fresh-only v5 Apalis SQLite queue. Schema v4 is incompatible and is never migrated automatically. The optional board binds only to a nonzero loopback address; `/new` submits a program and JSON argument array to the official board API. Commands do not invoke a shell implicitly. Anyone with local access to the board can run commands with the Agent's privileges.

Apalis may replay work after a worker or Agent crash, including commands that already started; side effects can therefore occur more than once. The upstream API accepts an idempotency key for repeated submissions. Process execution requires a ProcessKit containment backend capable of tracking the process tree. Shutdown requests stop active process groups.
