//! Durable jobs over the authenticated `hostlink-jobs-v1` SSH subsystem.

mod client;
mod model;
mod protocol;
mod validation;

pub use model::{
    Cancel, JobId, JobOutput, JobSpec, JobState, JobStatus, JobStream, Output, Seal,
    SealedArtifact, Start, Status,
};
pub use protocol::sealed_artifact_name;

#[cfg(test)]
use protocol::{MAX_FRAME_BYTES, SUBSYSTEM, decode_frame};

#[cfg(test)]
#[path = "../../tests/support/job_client.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/protocol.rs"]
mod tests_protocol;
