use super::{scheduler::Scheduler, *};

fn root(root: &Path) -> io::Result<PathBuf> {
    ensure_user_scope()?;
    let root = verify_install_root(root)?;
    legacy::reject(&root)?;
    Ok(root)
}
fn definition(root: &Path) -> io::Result<String> {
    verify_enrollment_root(root)?;
    canonical_private_dir(&root.join("bin"))?;
    canonical_regular(&agent_executable(root))?;
    load_config(&root.join("state/agent.json"))?;
    task_xml::render(root)
}
fn mutation_lock(root: &Path) -> io::Result<File> {
    let lock = crate::private_fs::open_lock(&root.join("update.lock"))?;
    lock.try_lock().map_err(io::Error::other)?;
    Ok(lock)
}
fn owned(
    scheduler: &Scheduler,
    root: &Path,
) -> io::Result<windows::Win32::System::TaskScheduler::IRegisteredTask> {
    let task = scheduler.task(&task_name(root)?)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "Agent Task Scheduler task is not installed",
        )
    })?;
    scheduler.verify(&task, &definition(root)?)?;
    Ok(task)
}

/// Register a logon task with the current user's limited interactive token.
/// Does not start the Agent or overwrite an occupied task name.
/// # Errors
/// Refuses unsafe roots, legacy state, changed identity or unavailable Task Scheduler.
pub fn install(path: &Path, config: &Path) -> io::Result<()> {
    let root = root(path)?;
    let _lock = mutation_lock(&root)?;
    crate::update::ensure_no_pending_windows_handoff(&root)?;
    if canonical_regular(config)? != root.join("state/agent.json")
        || std::env::current_exe()?.canonicalize()? != agent_executable(&root)
    {
        return Err(invalid(
            "service install requires ROOT/bin/hostlink-agent.exe and ROOT/state/agent.json",
        ));
    }
    let xml = definition(&root)?;
    let scheduler = Scheduler::connect()?;
    let name = task_name(&root)?;
    if let Some(task) = scheduler.task(&name)? {
        scheduler.verify(&task, &xml)?;
    } else {
        let task = scheduler.create(&name, &xml)?;
        // On failed readback preserve the task for investigation; never delete unverified state.
        scheduler.verify(&task, &xml)?;
    }
    Ok(())
}
/// Start the exact registered task and wait for Scheduler activation.
/// # Errors
/// Refuses changed identity, pending updates or Scheduler failure/timeout.
pub fn start(path: &Path) -> io::Result<()> {
    let root = root(path)?;
    let _lock = mutation_lock(&root)?;
    crate::update::ensure_no_pending_windows_handoff(&root)?;
    let scheduler = Scheduler::connect()?;
    let task = owned(&scheduler, &root)?;
    // IgnoreNew is enforced by Scheduler, including concurrent logon/demand starts.
    scheduler::start(&task)
}
/// Stop all instances through Task Scheduler. Termination is not graceful.
/// # Errors
/// Refuses changed identity or an unconfirmed Scheduler stop.
pub fn stop(path: &Path) -> io::Result<()> {
    let root = root(path)?;
    let _lock = mutation_lock(&root)?;
    let scheduler = Scheduler::connect()?;
    scheduler::stop(&owned(&scheduler, &root)?)
}
/// Stop and delete only the exact task, retaining all Agent files and jobs.
/// # Errors
/// Refuses changed identity or an unconfirmed Scheduler stop/deletion.
pub fn remove(path: &Path) -> io::Result<()> {
    let root = root(path)?;
    let _lock = mutation_lock(&root)?;
    let scheduler = Scheduler::connect()?;
    let task = owned(&scheduler, &root)?;
    scheduler::stop(&task)?;
    scheduler.delete(&task_name(&root)?)?;
    if scheduler.task(&task_name(&root)?)?.is_some() {
        return Err(invalid("Agent task still exists after deletion"));
    }
    Ok(())
}
/// Read OS task state and separately probe the configured SSH banner.
/// PID is unavailable: Task Scheduler owns process identity.
/// # Errors
/// Refuses unsafe roots, legacy state, changed task definitions and unknown OS state.
pub fn status(path: &Path) -> io::Result<ServiceStatus> {
    let root = root(path)?;
    let scheduler = Scheduler::connect()?;
    let task = scheduler.task(&task_name(&root)?)?;
    let installed = task.is_some();
    let active = if let Some(task) = task {
        scheduler.verify(&task, &definition(&root)?)?;
        scheduler::active(&task)?
    } else {
        false
    };
    let ssh_banner = active && ssh_banner(load_config(&root.join("state/agent.json"))?.listen)?;
    Ok(ServiceStatus {
        installed,
        active,
        owner_uid: None,
        owner_sid: Some(current_sid()?),
        pid: None,
        executable_sha256: if installed {
            Some(sha256_file(&agent_executable(&root))?)
        } else {
            None
        },
        ssh_banner,
        local_enrollment: root.join("state/machine.json").is_file(),
        detail: format!(
            "current-user Task Scheduler: installed={installed}, active_or_queued={active}; stop uses OS termination, not graceful shutdown; Hub reachability not queried"
        ),
    })
}
