//! Runtime-neutral wall-clock helpers for persisted timestamps.

use std::time::{SystemTime, UNIX_EPOCH};

/// Current Unix epoch time in milliseconds, clamped to zero before the epoch.
pub fn unix_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_unix_time_is_nonzero_on_supported_runtime() {
        assert!(unix_time_ms() > 0);
    }
}
