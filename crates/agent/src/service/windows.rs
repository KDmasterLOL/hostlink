//! Current-user Task Scheduler 2.0 lifecycle. Scheduler alone owns execution.
//! 1C-1124: keep direct COM. schtasks adds password/locale/overwrite handling;
//! planif 1.0 only builds registrations, leaving lifecycle ownership here.
//! windows 0.62's typed property out-parameters exceed this XML identity check.
use super::ServiceStatus;
use crate::private_fs::PrivateFileExt;
use private_fs::{FileAccess, FileCreation, OpenOptions, PrivateDir};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io,
    marker::PhantomData,
    path::{Path, PathBuf},
    time::Duration,
};
use windows::{
    Win32::System::{
        Com::{
            CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx,
            CoUninitialize,
        },
        TaskScheduler::{
            IRegisteredTask, ITaskFolder, ITaskService, TASK_CREATE, TASK_LOGON_INTERACTIVE_TOKEN,
            TASK_STATE_DISABLED, TASK_STATE_QUEUED, TASK_STATE_READY, TASK_STATE_RUNNING,
            TASK_UPDATE, TaskScheduler,
        },
        Variant::VARIANT,
    },
    core::BSTR,
};

/// Register or refresh an owned task without starting it.
/// # Errors
/// Refuses unsafe inputs, legacy registrations, pending updates and foreign tasks.
pub fn install(root: &Path, config: &Path) -> io::Result<()> {
    let directory = PrivateDir::open(root).map_err(io::Error::other)?;
    let absolute = std::path::absolute(root)?;
    let parent = absolute
        .parent()
        .ok_or_else(|| invalid("Agent root has no parent"))?;
    let _parent = PrivateDir::open(parent).map_err(io::Error::other)?;
    let root = root.canonicalize()?;
    if legacy_run_present(&root)? {
        return Err(invalid(
            "old HKCU Run startup is still registered; stop/remove that legacy Agent before installing Task Scheduler",
        ));
    }
    let _lock = mutation_lock(&root)?;
    crate::update_handoff::ensure_no_pending_windows_handoff(&root)?;
    let (command, arguments) = action(&root)?;
    let executable = root.join("bin/hostlink-agent.exe");
    directory
        .open_file("bin/hostlink-agent.exe")
        .map_err(io::Error::other)?;
    let config_parent = config
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let config_name = config
        .file_name()
        .ok_or_else(|| invalid("config has no file name"))?;
    PrivateDir::open(std::path::absolute(config_parent)?)
        .and_then(|directory| directory.open_file(config_name))
        .map_err(io::Error::other)?;
    if config.canonicalize()? != root.join("state/agent.json")
        || std::env::current_exe()?.canonicalize()? != executable
    {
        return Err(invalid(
            "service install requires ROOT/bin/hostlink-agent.exe and ROOT/state/agent.json",
        ));
    }
    let _apartment = Apartment::new()?;
    let folder = task_folder()?;
    let name = task_name(&root)?;
    let flags = if let Some(task) = registered(&folder, &name)? {
        verify_task(&task, &root)?;
        stop_task(&task)?;
        owned(&folder, &root)?;
        TASK_UPDATE
    } else {
        TASK_CREATE
    };
    let xml = definition(&command, &arguments, &current_sid()?);
    let empty = VARIANT::default();
    // SAFETY: CREATE never replaces an occupied name; UPDATE follows
    // verification of our registered task, including its executable and SID.
    let task = unsafe {
        folder.RegisterTask(
            &BSTR::from(name),
            &BSTR::from(xml),
            flags.0,
            &empty,
            &empty,
            TASK_LOGON_INTERACTIVE_TOKEN,
            &empty,
        )
    }
    .map_err(com_error)?;
    verify_task(&task, &root)?;
    Ok(())
}

/// Start the verified task and wait at most ten seconds for OS activation.
/// # Errors
/// Refuses pending updates, foreign tasks and unconfirmed activation.
pub fn start(root: &Path) -> io::Result<()> {
    let _directory = PrivateDir::open(root).map_err(io::Error::other)?;
    let absolute = std::path::absolute(root)?;
    let parent = absolute
        .parent()
        .ok_or_else(|| invalid("Agent root has no parent"))?;
    let _parent = PrivateDir::open(parent).map_err(io::Error::other)?;
    let root = root.canonicalize()?;
    let _lock = mutation_lock(&root)?;
    crate::update_handoff::ensure_no_pending_windows_handoff(&root)?;
    if legacy_run_present(&root)? {
        return Err(invalid(
            "old HKCU Run startup must be removed before starting Task Scheduler",
        ));
    }
    let _apartment = Apartment::new()?;
    let folder = task_folder()?;
    let task = owned(&folder, &root)?;
    // SAFETY: ownership checked; IgnoreNew handles logon/concurrent starts.
    unsafe { task.Run(&VARIANT::default()).map_err(com_error)? };
    wait(&task, true)
}

/// Stop all verified task instances. OS termination is not graceful shutdown.
/// # Errors
/// Refuses missing/foreign tasks and unconfirmed termination.
pub fn stop(root: &Path) -> io::Result<()> {
    let root = root.canonicalize()?;
    let _lock = mutation_lock(&root)?;
    let _apartment = Apartment::new()?;
    let folder = task_folder()?;
    stop_task(&owned(&folder, &root)?)
}

/// Stop and unregister only the verified task, retaining every Agent file.
/// # Errors
/// Refuses missing/foreign tasks and unconfirmed termination or deletion.
pub fn remove(root: &Path) -> io::Result<()> {
    let root = root.canonicalize()?;
    let _lock = mutation_lock(&root)?;
    let _apartment = Apartment::new()?;
    let folder = task_folder()?;
    stop_task(&owned(&folder, &root)?)?;
    // Recheck ownership after waiting, before deleting the named registration.
    owned(&folder, &root)?;
    let name = task_name(&root)?;
    // SAFETY: the exact named task was verified and all instances stopped.
    unsafe {
        folder
            .DeleteTask(&BSTR::from(&name), 0)
            .map_err(com_error)?
    };
    if registered(&folder, &name)?.is_some() {
        return Err(invalid("Agent task still exists after deletion"));
    }
    Ok(())
}

/// Read registration and OS execution state without probing Agent protocols.
/// # Errors
/// Refuses unsafe roots, foreign definitions and unknown Scheduler state.
pub fn status(root: &Path) -> io::Result<ServiceStatus> {
    // A read-only Scheduler query does not inspect Agent files or need their ACLs.
    let root = root.canonicalize()?;
    let _apartment = Apartment::new()?;
    let folder = task_folder()?;
    let task = registered(&folder, &task_name(&root)?)?;
    let active = if let Some(task) = &task {
        verify_task(task, &root)?;
        active(task)?
    } else {
        false
    };
    Ok(ServiceStatus {
        installed: task.is_some(),
        active,
    })
}

/// Read-only updater guard; the updater holds update.lock for its transaction.
pub(crate) fn ensure_update_unregistered(root: &Path) -> io::Result<()> {
    // The updater validates its install root before calling this read-only guard.
    let root = root.canonicalize()?;
    if legacy_run_present(&root)? {
        return Err(invalid(
            "old HKCU Run startup must be removed before an offline update",
        ));
    }
    let _apartment = Apartment::new()?;
    let folder = task_folder()?;
    if registered(&folder, &task_name(&root)?)?.is_some() {
        return Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "offline Windows update requires service stop and service remove before update; reinstall the task afterwards",
        ));
    }
    Ok(())
}

fn mutation_lock(root: &Path) -> io::Result<File> {
    let file = PrivateDir::open(std::path::absolute(root)?)
        .map_err(io::Error::other)?
        .open_file_with(
            "update.lock",
            OpenOptions {
                access: FileAccess::ReadWrite,
                creation: FileCreation::OpenOrCreate,
                ..OpenOptions::default()
            },
        )
        .map_err(io::Error::other)?
        .try_clone_std()?;
    file.try_lock().map_err(io::Error::other)?;
    Ok(file)
}
fn current_sid() -> io::Result<String> {
    Ok(windows_permissions::utilities::current_process_sid()
        .map_err(io::Error::other)?
        .to_string())
}
fn root_digest(root: &Path) -> String {
    format!("{:x}", Sha256::digest(root.to_string_lossy().as_bytes()))[..24].into()
}
fn task_name(root: &Path) -> io::Result<String> {
    Ok(format!(
        "HostLinkAgent-v2-{}-{}",
        current_sid()?,
        root_digest(root)
    ))
}
fn action(root: &Path) -> io::Result<(String, String)> {
    let unicode = |path: PathBuf| {
        path.into_os_string()
            .into_string()
            .map_err(|_| invalid("Agent task path is not Unicode"))
    };
    // Both fixed filenames end in a non-backslash and Windows forbids quotes
    // in path components, so quoting the complete config path is sufficient.
    Ok((
        unicode(root.join("bin/hostlink-agent.exe"))?,
        format!(
            "run --config=\"{}\"",
            unicode(root.join("state/agent.json"))?
        ),
    ))
}

// This guard cannot leave its thread. All COM interfaces are declared after it
// and released before Drop; S_OK and S_FALSE both require CoUninitialize.
struct Apartment(bool, PhantomData<*mut ()>);
impl Apartment {
    fn new() -> io::Result<Self> {
        // SAFETY: initializes only the calling thread, without raw pointers.
        let result = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
        if result.0 as u32 == 0x80010106 {
            return Ok(Self(false, PhantomData)); // Existing STA, owned by caller.
        }
        result.ok().map_err(com_error)?;
        Ok(Self(true, PhantomData))
    }
}
impl Drop for Apartment {
    fn drop(&mut self) {
        if self.0 {
            // SAFETY: balances this thread's successful CoInitializeEx.
            unsafe { CoUninitialize() };
        }
    }
}
fn com_error(error: windows::core::Error) -> io::Error {
    io::Error::other(format!(
        "Task Scheduler COM failed (HRESULT {:#010x})",
        error.code().0
    ))
}
fn task_folder() -> io::Result<ITaskFolder> {
    // SAFETY: every caller holds a COM apartment until all interfaces drop.
    unsafe {
        let service: ITaskService =
            CoCreateInstance(&TaskScheduler, None, CLSCTX_INPROC_SERVER).map_err(com_error)?;
        let empty = VARIANT::default();
        service
            .Connect(&empty, &empty, &empty, &empty)
            .map_err(com_error)?;
        service.GetFolder(&BSTR::from("\\")).map_err(com_error)
    }
}
fn registered(folder: &ITaskFolder, name: &str) -> io::Result<Option<IRegisteredTask>> {
    // SAFETY: live local interface and owned task name.
    match unsafe { folder.GetTask(&BSTR::from(name)) } {
        Ok(task) => Ok(Some(task)),
        Err(error) if error.code().0 as u32 == 0x80070002 => Ok(None),
        Err(error) => Err(com_error(error)),
    }
}
fn owned(folder: &ITaskFolder, root: &Path) -> io::Result<IRegisteredTask> {
    let task = registered(folder, &task_name(root)?)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "Agent Task Scheduler task is not installed",
        )
    })?;
    verify_task(&task, root)?;
    Ok(task)
}
fn verify_task(task: &IRegisteredTask, root: &Path) -> io::Result<()> {
    let (command, arguments) = action(root)?;
    // SAFETY: read-only query of a live registered task.
    let xml = unsafe { task.Xml().map_err(com_error)?.to_string() };
    verify_definition(&xml, &command, &arguments, &current_sid()?)
}
fn active(task: &IRegisteredTask) -> io::Result<bool> {
    // SAFETY: read-only OS state/instance queries on a live interface.
    unsafe {
        match task.State().map_err(com_error)? {
            TASK_STATE_RUNNING | TASK_STATE_QUEUED => Ok(true),
            TASK_STATE_DISABLED | TASK_STATE_READY => Ok(task
                .GetInstances(0)
                .map_err(com_error)?
                .Count()
                .map_err(com_error)?
                != 0),
            _ => Err(invalid("Task Scheduler cannot establish Agent state")),
        }
    }
}
fn stop_task(task: &IRegisteredTask) -> io::Result<()> {
    if active(task)? {
        // SAFETY: caller verified the task; Stop terminates all its instances.
        unsafe { task.Stop(0).map_err(com_error)? };
    }
    wait(task, false)
}
fn wait(task: &IRegisteredTask, running: bool) -> io::Result<()> {
    for _ in 0..100 {
        let ready = if running {
            // SAFETY: read-only queries; queued alone does not confirm start.
            unsafe {
                task.State().map_err(com_error)? == TASK_STATE_RUNNING
                    && task
                        .GetInstances(0)
                        .map_err(com_error)?
                        .Count()
                        .map_err(com_error)?
                        > 0
            }
        } else {
            !active(task)?
        };
        if ready {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        "Task Scheduler did not reach the requested state within 10 seconds",
    ))
}

const TASK_NAMESPACE: &str = "http://schemas.microsoft.com/windows/2004/02/mit/task";
fn definition(command: &str, arguments: &str, sid: &str) -> String {
    // Scheduler validates the XML schema and characters when registering it.
    let escape = |value: &str| {
        value
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
    };
    let (command, arguments, sid) = (escape(command), escape(arguments), escape(sid));
    format!(
        r#"<Task version="1.2" xmlns="{TASK_NAMESPACE}">
<RegistrationInfo><Description>HostLink Agent v2</Description></RegistrationInfo>
<Triggers><LogonTrigger><Enabled>true</Enabled><UserId>{sid}</UserId></LogonTrigger></Triggers>
<Principals><Principal id="Agent"><UserId>{sid}</UserId><LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>
<Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><AllowHardTerminate>true</AllowHardTerminate><StartWhenAvailable>false</StartWhenAvailable><RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable><IdleSettings><StopOnIdleEnd>false</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings><AllowStartOnDemand>true</AllowStartOnDemand><Enabled>true</Enabled><Hidden>false</Hidden><RunOnlyIfIdle>false</RunOnlyIfIdle><WakeToRun>false</WakeToRun><ExecutionTimeLimit>PT0S</ExecutionTimeLimit><Priority>7</Priority></Settings>
<Actions Context="Agent"><Exec><Command>{command}</Command><Arguments>{arguments}</Arguments></Exec></Actions>
</Task>"#
    )
}

/// Check execution ownership fields, not Scheduler serialization or file hashes.
fn verify_definition(xml: &str, command: &str, arguments: &str, sid: &str) -> io::Result<()> {
    let document = roxmltree::Document::parse(xml).map_err(io::Error::other)?;
    let task = document.root_element();
    if !task.has_tag_name((TASK_NAMESPACE, "Task")) {
        return Err(invalid("foreign Task Scheduler XML namespace"));
    }
    let principals = child(task, "Principals")?;
    let principal = child(principals, "Principal")?;
    let triggers = child(task, "Triggers")?;
    let trigger = child(triggers, "LogonTrigger")?;
    let actions = child(task, "Actions")?;
    let exec = child(actions, "Exec")?;
    let settings = child(task, "Settings")?;
    for container in [principals, triggers, actions] {
        if container.children().filter(|n| n.is_element()).count() != 1 {
            return Err(invalid(
                "Agent task must have one principal, logon trigger and exec action",
            ));
        }
    }
    if principal.attribute("id").is_none()
        || actions.attribute("Context") != principal.attribute("id")
        || principal
            .children()
            .any(|n| n.has_tag_name((TASK_NAMESPACE, "GroupId")))
        || exec.children().any(|n| {
            n.has_tag_name((TASK_NAMESPACE, "WorkingDirectory"))
                && n.text().is_some_and(|s| !s.is_empty())
        })
        || settings
            .children()
            .any(|n| n.is_element() && n.tag_name().name() == "RestartOnFailure")
    {
        return Err(invalid(
            "foreign Agent task principal, trigger, action or restart policy",
        ));
    }
    for (parent, name, expected) in [
        (principal, "UserId", sid),
        (principal, "LogonType", "InteractiveToken"),
        (principal, "RunLevel", "LeastPrivilege"),
        (trigger, "UserId", sid),
        (exec, "Command", command),
        (exec, "Arguments", arguments),
        (settings, "MultipleInstancesPolicy", "IgnoreNew"),
    ] {
        let field = child(parent, name)?;
        if field.children().any(|n| n.is_element())
            || field.children().filter(|n| n.is_text()).count() != 1
            || field.text() != Some(expected)
        {
            return Err(invalid(
                "foreign or changed Agent task; registration preserved",
            ));
        }
    }
    Ok(())
}
fn child<'a>(parent: roxmltree::Node<'a, 'a>, name: &str) -> io::Result<roxmltree::Node<'a, 'a>> {
    let mut matching = parent
        .children()
        .filter(|n| n.has_tag_name((TASK_NAMESPACE, name)));
    let node = matching
        .next()
        .ok_or_else(|| invalid("Agent task is missing an ownership field"))?;
    if matching.next().is_some() {
        return Err(invalid("Agent task has duplicate ownership fields"));
    }
    Ok(node)
}

fn legacy_run_present(root: &Path) -> io::Result<bool> {
    use windows_sys::Win32::System::Registry::{
        HKEY_CURRENT_USER, RRF_NOEXPAND, RRF_RT_ANY, RegGetValueW,
    };
    let wide = |value: &str| value.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
    let key_name = wide(r"Software\Microsoft\Windows\CurrentVersion\Run");
    let value_name = wide(&format!("HostLinkAgent-{}", root_digest(root)));
    // SAFETY: terminated names; current user, existence-only query with no data
    // buffers or environment expansion. RegGetValueW is available since Vista.
    let result = unsafe {
        RegGetValueW(
            HKEY_CURRENT_USER,
            key_name.as_ptr(),
            value_name.as_ptr(),
            RRF_RT_ANY | RRF_NOEXPAND,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    match result {
        2 => Ok(false),
        0 | 234 => Ok(true),
        _ => Err(io::Error::from_raw_os_error(result as i32)),
    }
}
fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
