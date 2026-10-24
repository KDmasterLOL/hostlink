//! Small runtime-neutral primitives shared by HostLink crates.

mod json_lines;
mod secret;

pub use json_lines::{read_json_line_bounded, write_json_line};
pub use secret::{constant_time_eq, constant_time_str_eq};

#[cfg(test)]
mod tests;
