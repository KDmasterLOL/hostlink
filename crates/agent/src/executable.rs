//! Identity comes from the installed executable, never a release sidecar or updater version.

use crate::{
    agent_files::hash_file,
    package::{EXECUTABLE_NAME, MAX_EXECUTABLE_BYTES, invalid, verify_executable},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::{self, Read, Seek, SeekFrom},
    path::Path,
    time::Duration,
};

/// Build identity reported by an Agent executable.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BinaryIdentity {
    /// Semantic release version compiled into this executable.
    pub version: String,
    /// Exact Cargo target, including the Windows 7 distinction.
    pub target: String,
}

/// Return this executable's build identity without accessing credentials or the network.
pub fn current_binary_identity() -> BinaryIdentity {
    BinaryIdentity {
        version: env!("CARGO_PKG_VERSION").into(),
        target: self_update::get_target().into(),
    }
}

pub(crate) fn asset_name(target: &str) -> io::Result<String> {
    if !matches!(
        target,
        "x86_64-pc-windows-msvc"
            | "x86_64-win7-windows-msvc"
            | "i686-win7-windows-msvc"
            | "x86_64-unknown-linux-gnu"
    ) {
        return Err(invalid("unsupported Agent target"));
    }
    Ok(format!(
        "hostlink-agent-{target}{}",
        if target.contains("windows") {
            ".exe"
        } else {
            ""
        }
    ))
}

pub(crate) fn read_identity(path: &Path) -> io::Result<BinaryIdentity> {
    verify_executable(path)?;
    let path = path.to_owned();
    // Run the existing bounded process owner on a separate runtime thread: this
    // synchronous verifier is also called from inside the Agent's Tokio CLI.
    let output = std::thread::spawn(move || -> io::Result<String> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        runtime
            .block_on(
                processkit::Command::new(path)
                    .arg("binary-info")
                    .output_buffer(
                        processkit::OutputBufferPolicy::fail_loud(4).with_max_bytes(1024),
                    )
                    .timeout(Duration::from_secs(10))
                    .timeout_grace(Duration::from_secs(2))
                    .run(),
            )
            .map_err(|_| invalid("Agent binary identity command failed or exceeded its bounds"))
    })
    .join()
    .map_err(|_| invalid("Agent binary identity verifier thread failed"))??;
    let identity: BinaryIdentity = serde_json::from_str(&output).map_err(io::Error::other)?;
    semver::Version::parse(&identity.version).map_err(io::Error::other)?;
    asset_name(&identity.target)?;
    let compatible = match self_update::get_target() {
        "x86_64-pc-windows-msvc" | "x86_64-win7-windows-msvc" => matches!(
            identity.target.as_str(),
            "x86_64-pc-windows-msvc" | "x86_64-win7-windows-msvc"
        ),
        target => identity.target == target,
    };
    if !compatible {
        return Err(invalid(
            "installed Agent target does not match this runtime",
        ));
    }
    Ok(identity)
}

pub(crate) fn read_installed(root: &Path) -> io::Result<(BinaryIdentity, String)> {
    match fs::symlink_metadata(root.join("enrollment.pending")) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
        Ok(_) => return Err(invalid("Agent enrollment is pending reconciliation")),
    }
    let bin = root.join("bin");
    private_fs::PrivateDir::open(&bin).map_err(io::Error::other)?;
    let names = fs::read_dir(&bin)?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<io::Result<Vec<_>>>()?;
    if names != [std::ffi::OsString::from(EXECUTABLE_NAME)] {
        return Err(invalid(
            "Agent bin must contain only the installed executable",
        ));
    }
    let path = bin.join(EXECUTABLE_NAME);
    Ok((
        read_identity(&path)?,
        hash_file(&path, MAX_EXECUTABLE_BYTES)?,
    ))
}

/// Retain the running image through enrollment so a staging pathname cannot change its bytes.
pub(crate) struct RunningExecutable {
    pub(crate) file: File,
    pub(crate) sha256: String,
}

impl RunningExecutable {
    pub(crate) fn open() -> io::Result<Self> {
        let path = std::env::current_exe()?;
        verify_executable(&path)?;
        #[cfg(target_os = "linux")]
        let file = File::open("/proc/self/exe")?;
        #[cfg(not(target_os = "linux"))]
        let file = File::open(&path)?;
        let mut image = Self {
            file,
            sha256: String::new(),
        };
        let mut hash = Sha256::new();
        let size = io::copy(
            &mut (&mut image.file).take(MAX_EXECUTABLE_BYTES + 1),
            &mut hash,
        )?;
        if size == 0 || size > MAX_EXECUTABLE_BYTES {
            return Err(invalid("running Agent executable is empty or oversized"));
        }
        image.sha256 = hex::encode(hash.finalize());
        if hash_file(&path, MAX_EXECUTABLE_BYTES)? != image.sha256 {
            return Err(invalid("running Agent image differs from its staging path"));
        }
        image.file.seek(SeekFrom::Start(0))?;
        Ok(image)
    }
}
