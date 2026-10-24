//! Runtime-neutral secret comparison primitives.

use subtle::ConstantTimeEq;

/// Compare byte slices in constant time with respect to their contents.
pub fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    left.ct_eq(right).unwrap_u8() == 1
}

/// Compare UTF-8 strings by their exact bytes using constant-time comparison.
pub fn constant_time_str_eq(left: &str, right: &str) -> bool {
    constant_time_eq(left.as_bytes(), right.as_bytes())
}
