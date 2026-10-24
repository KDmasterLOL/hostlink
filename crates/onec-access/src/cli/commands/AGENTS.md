# onec-access command adapters

- Each user-visible leaf owns its Clap `Args`, argument conversion, handler call, and command-specific presentation.
- Family `mod.rs` files declare modules, define a small `Subcommand` enum, and dispatch with short calls only.
- Shared controller policy and operation logic belongs in a specifically named module under `src/cli/`, outside `commands/`.
- Do not add an aggregate schema, dispatcher/engine module, forwarding facade, or duplicate parser model.
- Preserve existing command names, help text, defaults, JSON fields, stdout/stderr behavior, exit codes, authorization checks, and secret redaction.
- Update this command catalog when a command is added, removed, or renamed.
