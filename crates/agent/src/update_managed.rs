//! Run a Windows update outside the Agent's process tree.

use crate::{
    agent_files::hash_file,
    executable::RunningExecutable,
    installation::{InstallationRoot, ensure_ready},
    package::{EXECUTABLE_NAME, MAX_EXECUTABLE_BYTES, invalid},
    service, update,
};
use private_fs::PrivateDir;
use std::{io, io::Read, time::Duration};

/// Launch a detached updater. Active Agent commands are interrupted.
/// A successful return confirms launch, not completion.
///
/// # Errors
/// Refuses unsafe installations, changed images and process launch failures.
pub fn start_managed_update(
    root: &InstallationRoot,
    version: Option<&semver::Version>,
) -> io::Result<()> {
    let root = root.as_path().canonicalize()?;
    ensure_ready(&root)?;
    let installed = root.join("bin").join(EXECUTABLE_NAME);
    if !same_file::is_same_file(std::env::current_exe()?, &installed)? {
        return Err(invalid("managed update requires the installed Agent"));
    }
    if !service::status(&root)?.installed {
        return Err(invalid("managed update requires the registered Agent task"));
    }
    let mut image = RunningExecutable::open()?;
    let operation = uuid::Uuid::new_v4();
    let stage_name = format!(".update-supervisor-{operation}");
    let stage = PrivateDir::open(&root)
        .and_then(|dir| dir.create_dir(&stage_name))
        .map_err(io::Error::other)?;
    let mut copy = stage.create(EXECUTABLE_NAME).map_err(io::Error::other)?;
    let bytes = io::copy(
        &mut (&mut image.file).take(MAX_EXECUTABLE_BYTES + 1),
        &mut copy,
    )?;
    if bytes == 0 || bytes > MAX_EXECUTABLE_BYTES {
        return Err(invalid("update helper image is empty or oversized"));
    }
    copy.sync_all().map_err(io::Error::other)?;
    drop(copy);
    if hash_file(
        &root.join(stage_name).join(EXECUTABLE_NAME),
        MAX_EXECUTABLE_BYTES,
    )? != image.sha256
    {
        return Err(invalid("update helper differs from installed Agent"));
    }
    use std::os::windows::process::CommandExt;
    use windows_sys::Win32::System::Threading::{CREATE_BREAKAWAY_FROM_JOB, CREATE_NO_WINDOW};
    let mut command = std::process::Command::new(
        root.join(format!(".update-supervisor-{operation}"))
            .join(EXECUTABLE_NAME),
    );
    command.args(["update", "--supervisor", &operation.to_string()]);
    if let Some(version) = version {
        command.arg("--version").arg(version.to_string());
    }
    command
        .creation_flags(CREATE_BREAKAWAY_FROM_JOB | CREATE_NO_WINDOW)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map(|_| ())
}

/// Execute a detached update and restart the Agent.
///
/// # Errors
/// Returns an error when publication or service restoration fails.
pub fn run_managed_update(
    root: &InstallationRoot,
    operation: uuid::Uuid,
    version: Option<&semver::Version>,
) -> io::Result<()> {
    let root_path = root.as_path().canonicalize()?;
    let root_path = &root_path;
    let stage_path = root_path.join(format!(".update-supervisor-{operation}"));
    let executable = stage_path.join(EXECUTABLE_NAME);
    PrivateDir::open(&stage_path)
        .and_then(|stage| stage.open_file(EXECUTABLE_NAME))
        .map_err(io::Error::other)?;
    if !same_file::is_same_file(std::env::current_exe()?, &executable)?
        || hash_file(&executable, MAX_EXECUTABLE_BYTES)?
            != hash_file(
                &root_path.join("bin").join(EXECUTABLE_NAME),
                MAX_EXECUTABLE_BYTES,
            )?
    {
        return Err(invalid("update helper does not match the installed Agent"));
    }
    // The helper was created outside the SSH Job, so it survives stopping the Agent.
    std::thread::sleep(Duration::from_secs(2));
    service::remove(root_path)?;
    let result = update::update(root, version);
    let executable = root_path.join("bin").join(EXECUTABLE_NAME);
    let installed = std::process::Command::new(executable)
        .args(["service", "install", "--root"])
        .arg(root_path)
        .arg("--config")
        .arg(root_path.join("state/agent.json"))
        .status()?;
    if !installed.success() {
        return Err(io::Error::other(
            "failed to restore Agent task after update",
        ));
    }
    service::start(root_path)?;
    result.map(|_| ())
}
