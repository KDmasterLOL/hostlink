use super::ServiceStatus;
use crate::durable;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    process::{Command, Output},
};
use std::{
    io,
    path::{Path, PathBuf},
};

const MARKER: &str = ".hostlink-user-service.json";
const MARKER_FORMAT: u32 = 1;

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct InstallRecord {
    format: u32,
    uid: u32,
    root: PathBuf,
    executable: PathBuf,
    executable_sha256: String,
    config: PathBuf,
    unit_name: String,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct EnrollmentManifest {
    format: u32,
    machine_id: String,
    files: std::collections::BTreeMap<String, EnrollmentFile>,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct EnrollmentFile {
    size: u64,
    sha256: String,
}

mod lifecycle;
mod private_fs;
mod record;
pub(super) mod systemd;

pub use lifecycle::{install, remove, start, status, stop};
use private_fs::*;
use record::*;
use systemd::*;
