//! Durable jobs over the authenticated `hostlink-jobs` SSH subsystem.

mod client;
mod model;
mod protocol;
mod upload;
mod validation;

pub use model::{Cancel, JobId, JobOutput, JobState, JobStatus, JobStream, Output, Status};
pub(crate) use model::{JobSpec, Seal, Start};
pub use protocol::sealed_artifact_name;
pub use validation::validate_id;

#[cfg(test)]
use protocol::{MAX_FRAME_BYTES, SUBSYSTEM, decode_frame};

#[cfg(test)]
#[path = "../../tests/support/job_client.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/protocol.rs"]
mod tests_protocol;
