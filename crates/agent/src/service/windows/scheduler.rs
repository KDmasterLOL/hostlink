//! Thin RAII adapter over the Windows 7 Task Scheduler 2.0 COM API.
use super::*;
use windows::{
    Win32::System::{
        Com::{
            CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx,
            CoUninitialize,
        },
        TaskScheduler::{
            IRegisteredTask, ITaskFolder, ITaskService, TASK_CREATE, TASK_LOGON_INTERACTIVE_TOKEN,
            TASK_STATE_QUEUED, TASK_STATE_RUNNING, TASK_STATE_UNKNOWN, TaskScheduler,
        },
        Variant::VARIANT,
    },
    core::BSTR,
};

struct Apartment(bool);
impl Drop for Apartment {
    fn drop(&mut self) {
        // SAFETY: created only after successful CoInitializeEx, on the same thread.
        if self.0 {
            unsafe { CoUninitialize() };
        }
    }
}
pub(super) struct Scheduler {
    folder: ITaskFolder,
    service: ITaskService,
    // Interfaces must be released before the COM apartment.
    _apartment: Apartment,
}
fn error(error: windows::core::Error) -> io::Error {
    // Numeric HRESULT works regardless of Windows display language.
    io::Error::other(format!(
        "Task Scheduler COM failed (HRESULT {:#010x})",
        error.code().0
    ))
}
impl Scheduler {
    pub(super) fn connect() -> io::Result<Self> {
        // SAFETY: initializes this thread; no raw pointers are passed.
        unsafe {
            let initialized = CoInitializeEx(None, COINIT_MULTITHREADED);
            // RPC_E_CHANGED_MODE means the caller already owns a valid STA.
            // Use that apartment without balancing somebody else's initialization.
            let apartment = if initialized.0 as u32 == 0x80010106 {
                Apartment(false)
            } else {
                initialized.ok().map_err(error)?;
                Apartment(true)
            };
            let service: ITaskService =
                CoCreateInstance(&TaskScheduler, None, CLSCTX_INPROC_SERVER).map_err(error)?;
            let empty = VARIANT::default();
            service
                .Connect(&empty, &empty, &empty, &empty)
                .map_err(error)?;
            let folder = service.GetFolder(&BSTR::from("\\")).map_err(error)?;
            Ok(Self {
                folder,
                service,
                _apartment: apartment,
            })
        }
    }
    pub(super) fn task(&self, name: &str) -> io::Result<Option<IRegisteredTask>> {
        // SAFETY: live COM interface with owned string argument.
        match unsafe { self.folder.GetTask(&BSTR::from(name)) } {
            Ok(task) => Ok(Some(task)),
            Err(e) if e.code().0 as u32 == 0x80070002 => Ok(None),
            Err(e) => Err(error(e)),
        }
    }
    pub(super) fn create(&self, name: &str, xml: &str) -> io::Result<IRegisteredTask> {
        let empty = VARIANT::default();
        // SAFETY: all arguments are owned; TASK_CREATE refuses an occupied name atomically.
        unsafe {
            self.folder
                .RegisterTask(
                    &BSTR::from(name),
                    &BSTR::from(xml),
                    TASK_CREATE.0,
                    &empty,
                    &empty,
                    TASK_LOGON_INTERACTIVE_TOKEN,
                    &empty,
                )
                .map_err(error)
        }
    }
    pub(super) fn verify(&self, task: &IRegisteredTask, expected: &str) -> io::Result<()> {
        // SAFETY: live COM interfaces and initialized BSTR output. Windows normalizes
        // the expected XML using the same schema as its registered task definition.
        let (actual, normalized) = unsafe {
            let definition = self.service.NewTask(0).map_err(error)?;
            definition
                .SetXmlText(&BSTR::from(expected))
                .map_err(error)?;
            let mut normalized = BSTR::new();
            definition.XmlText(&mut normalized).map_err(error)?;
            (
                task.Xml().map_err(error)?.to_string(),
                normalized.to_string(),
            )
        };
        if !task_xml::equal(&actual, &normalized)? {
            return Err(invalid(
                "Task Scheduler definition differs from the exact current-user Agent task (including executable SHA-256); foreign or changed task preserved",
            ));
        }
        Ok(())
    }
    pub(super) fn delete(&self, name: &str) -> io::Result<()> {
        // SAFETY: caller has verified the exact named task and stopped all its instances.
        unsafe { self.folder.DeleteTask(&BSTR::from(name), 0).map_err(error) }
    }
}

pub(super) fn active(task: &IRegisteredTask) -> io::Result<bool> {
    // SAFETY: live registered-task interface; only OS-managed state is read.
    unsafe {
        let state = task.State().map_err(error)?;
        if state == TASK_STATE_UNKNOWN {
            return Err(invalid("Task Scheduler cannot establish Agent state"));
        }
        Ok(state == TASK_STATE_RUNNING
            || state == TASK_STATE_QUEUED
            || task
                .GetInstances(0)
                .map_err(error)?
                .Count()
                .map_err(error)?
                != 0)
    }
}
pub(super) fn start(task: &IRegisteredTask) -> io::Result<()> {
    // SAFETY: exact task verified by caller; no custom process spawning.
    unsafe {
        task.Run(&VARIANT::default()).map_err(error)?;
    }
    wait(task, true)
}
pub(super) fn stop(task: &IRegisteredTask) -> io::Result<()> {
    if active(task)? {
        // SAFETY: exact task verified by caller; Windows stops all instances.
        unsafe {
            task.Stop(0).map_err(error)?;
        }
    }
    wait(task, false)
}
fn wait(task: &IRegisteredTask, running: bool) -> io::Result<()> {
    for _ in 0..100 {
        let ready = if running {
            // SAFETY: read-only queries on the live task; queued alone is not a successful start.
            unsafe {
                task.State().map_err(error)? == TASK_STATE_RUNNING
                    && task
                        .GetInstances(0)
                        .map_err(error)?
                        .Count()
                        .map_err(error)?
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
