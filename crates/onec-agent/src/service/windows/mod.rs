//! Windows SCM implementation.
//!
//! `manager` owns install/start/stop/status/delete operations, `runtime` owns the
//! ServiceMain callback and tunnel lifetime, and `support` owns shared SCM error
//! translation/state waiting.

mod manager;
mod runtime;
mod support;

pub(super) use manager::{install, start, status, stop, uninstall};
pub(super) use runtime::dispatch;
