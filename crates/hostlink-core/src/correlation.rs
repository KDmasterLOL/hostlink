//! Transport-neutral runtime context environment names.
//!
//! Values identify toolkit runtime/evidence context or carry bounded execution context.

/// Optional parent operation/run correlation identifier.
pub const ONEC_PARENT_RUN_ID_ENV: &str = "ONEC_PARENT_RUN_ID";

/// Optional job-system namespace for a remotely owned job.
pub const ONEC_JOB_SYSTEM_ENV: &str = "ONEC_JOB_SYSTEM";

/// Optional job identifier within the selected job-system namespace.
pub const ONEC_JOB_ID_ENV: &str = "ONEC_JOB_ID";

/// Agent-owned directory where a remotely launched child may publish declared result files.
pub const ONEC_RESULT_DIR_ENV: &str = "ONEC_RESULT_DIR";

/// Agent-owned Unix timestamp deadline for one immediate managed execution.
pub const ONEC_EXEC_DEADLINE_UNIX_MS_ENV: &str = "ONEC_EXEC_DEADLINE_UNIX_MS";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn correlation_environment_names_are_stable() {
        assert_eq!(ONEC_PARENT_RUN_ID_ENV, "ONEC_PARENT_RUN_ID");
        assert_eq!(ONEC_JOB_SYSTEM_ENV, "ONEC_JOB_SYSTEM");
        assert_eq!(ONEC_JOB_ID_ENV, "ONEC_JOB_ID");
        assert_eq!(ONEC_RESULT_DIR_ENV, "ONEC_RESULT_DIR");
        assert_eq!(ONEC_EXEC_DEADLINE_UNIX_MS_ENV, "ONEC_EXEC_DEADLINE_UNIX_MS");
    }
}
