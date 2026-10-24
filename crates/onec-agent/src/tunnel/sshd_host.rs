//! Windows-only private-desktop host for toolkit-managed user-mode sshd.
//!
//! Win32-OpenSSH owns remote shell/PTY/SFTP process creation. The toolkit changes only the
//! desktop inherited by sshd and its descendants, keeping any console/window created by a
//! non-PTY remote command off the interactive desktop.

use std::io;
use std::path::Path;

#[cfg(any(windows, test))]
const START_EVENT_PREFIX: &str = "Local\\onec_toolkit_sshd_start_";

#[cfg(windows)]
mod windows {
    use super::*;
    use std::ffi::OsStr;
    use std::fs::{File, OpenOptions};
    use std::mem::{size_of, size_of_val};
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::AsRawHandle;
    use std::ptr;
    use std::sync::atomic::{AtomicU64, Ordering};
    use windows_sys::Win32::Foundation::{
        CloseHandle, DUPLICATE_SAME_ACCESS, DuplicateHandle, ERROR_ALREADY_EXISTS, GENERIC_ALL,
        GetLastError, HANDLE, INVALID_HANDLE_VALUE, WAIT_OBJECT_0, WAIT_TIMEOUT,
    };
    use windows_sys::Win32::System::Console::{
        GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
    };
    use windows_sys::Win32::System::StationsAndDesktops::{
        CloseDesktop, CreateDesktopW, GetProcessWindowStation, GetUserObjectInformationW, UOI_NAME,
    };
    use windows_sys::Win32::System::Threading::{
        CREATE_NO_WINDOW, CreateEventW, CreateProcessW, DeleteProcThreadAttributeList,
        EXTENDED_STARTUPINFO_PRESENT, GetCurrentProcess, GetExitCodeProcess, INFINITE,
        InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST, OpenEventW,
        PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROCESS_INFORMATION, STARTF_USESTDHANDLES,
        STARTUPINFOEXW, SYNCHRONIZATION_SYNCHRONIZE, SetEvent, TerminateProcess,
        UpdateProcThreadAttribute, WaitForSingleObject,
    };

    static DESKTOP_SEQUENCE: AtomicU64 = AtomicU64::new(1);
    static START_GATE_SEQUENCE: AtomicU64 = AtomicU64::new(1);

    pub(crate) struct StartGate {
        handle: OwnedHandle,
        name: String,
    }

    impl StartGate {
        pub(crate) fn create() -> io::Result<Self> {
            let sequence = START_GATE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let name = format!("{START_EVENT_PREFIX}{}_{}", std::process::id(), sequence);
            let wide = wide_null(OsStr::new(&name));
            // SAFETY: the name is a valid live NUL-terminated UTF-16 buffer; default security is
            // sufficient because parent and helper run under the same Windows identity/session.
            let handle = unsafe { CreateEventW(ptr::null(), 0, 0, wide.as_ptr()) };
            if handle.is_null() {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: CreateEventW succeeded; GetLastError distinguishes a new event from an
            // unexpected pre-existing object with the same internal name.
            if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
                // SAFETY: handle was just returned by CreateEventW and has not been wrapped yet.
                let _ = unsafe { CloseHandle(handle) };
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "toolkit sshd start event name collision",
                ));
            }
            Ok(Self {
                handle: OwnedHandle::new(handle),
                name,
            })
        }

        pub(crate) fn name(&self) -> &str {
            &self.name
        }

        pub(crate) fn signal(&self) -> io::Result<()> {
            // SAFETY: handle is the live event created by `create` and remains owned by this guard.
            if unsafe { SetEvent(self.handle.raw()) } == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }
    }

    pub(super) fn run(program: &Path, config: &Path, start_event: &str) -> io::Result<u32> {
        if !program.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("sshd executable does not exist: {}", program.display()),
            ));
        }
        if !config.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("sshd config does not exist: {}", config.display()),
            ));
        }
        validate_start_event_name(start_event)?;
        wait_for_start_event(start_event)?;

        let station = current_window_station_name()?;
        let desktop = HiddenDesktop::create()?;
        let desktop_path = format!("{station}\\{}", desktop.name);
        let mut desktop_path_wide = wide_null(OsStr::new(&desktop_path));
        let application = wide_null(program.as_os_str());
        let mut command_line = sshd_command_line(program, config)
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();

        let std_handles = InheritedStdHandles::new()?;
        let inherited_handles = std_handles.raw_handles();
        let mut attributes = ProcessAttributeList::with_handle_list(&inherited_handles)?;
        let mut startup = STARTUPINFOEXW::default();
        startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
        startup.StartupInfo.lpDesktop = desktop_path_wide.as_mut_ptr();
        startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        startup.StartupInfo.hStdInput = std_handles.stdin.raw();
        startup.StartupInfo.hStdOutput = std_handles.stdout.raw();
        startup.StartupInfo.hStdError = std_handles.stderr.raw();
        startup.lpAttributeList = attributes.raw();

        let mut process_info = PROCESS_INFORMATION::default();
        // SAFETY: all pointers refer to live buffers/structures for the call. The explicit handle
        // list limits inheritance to the three owned std-handle duplicates. The helper is signaled
        // only after the supervisor has attached it to the kill-on-close Job Object, so this child
        // is created inside the already-owned process tree.
        let created = unsafe {
            CreateProcessW(
                application.as_ptr(),
                command_line.as_mut_ptr(),
                ptr::null(),
                ptr::null(),
                1,
                CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT,
                ptr::null(),
                ptr::null(),
                ptr::addr_of!(startup.StartupInfo),
                &mut process_info,
            )
        };
        if created == 0 {
            return Err(io::Error::last_os_error());
        }

        let mut process = OwnedProcessHandle::new(process_info.hProcess);
        let thread = OwnedHandle::new(process_info.hThread);
        drop(thread);

        // SAFETY: process is a live process handle; INFINITE mirrors the sshd supervisor lifetime.
        let wait = unsafe { WaitForSingleObject(process.raw(), INFINITE) };
        if wait != WAIT_OBJECT_0 {
            return Err(io::Error::last_os_error());
        }
        let mut exit_code = 0u32;
        // SAFETY: process is signaled and the output pointer is valid.
        if unsafe { GetExitCodeProcess(process.raw(), &mut exit_code) } == 0 {
            return Err(io::Error::last_os_error());
        }

        process.completed = true;
        Ok(exit_code)
    }

    fn wait_for_start_event(name: &str) -> io::Result<()> {
        let wide = wide_null(OsStr::new(name));
        // SAFETY: name is a live NUL-terminated UTF-16 buffer and the event was created by the
        // parent under the same identity/session.
        let handle = unsafe { OpenEventW(SYNCHRONIZATION_SYNCHRONIZE, 0, wide.as_ptr()) };
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        let event = OwnedHandle::new(handle);
        // A healthy parent assigns the helper to its Job Object immediately after spawn. Keep this
        // wait bounded so a malformed/manual invocation cannot leave an internal helper hanging.
        // SAFETY: event is a live synchronization handle.
        match unsafe { WaitForSingleObject(event.raw(), 10_000) } {
            WAIT_OBJECT_0 => Ok(()),
            WAIT_TIMEOUT => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "timed out waiting for sshd process-tree ownership gate",
            )),
            _ => Err(io::Error::last_os_error()),
        }
    }

    fn current_window_station_name() -> io::Result<String> {
        // SAFETY: GetProcessWindowStation returns a borrowed handle owned by the process.
        let station = unsafe { GetProcessWindowStation() };
        if station.is_null() {
            return Err(io::Error::last_os_error());
        }
        let mut needed = 0u32;
        // The sizing call is expected to fail with ERROR_INSUFFICIENT_BUFFER and set `needed`.
        unsafe {
            GetUserObjectInformationW(station as HANDLE, UOI_NAME, ptr::null_mut(), 0, &mut needed);
        }
        if needed < 2 {
            return Err(io::Error::last_os_error());
        }
        let mut buffer = vec![0u16; needed.div_ceil(2) as usize];
        // SAFETY: buffer has at least `needed` bytes and `station` remains live.
        if unsafe {
            GetUserObjectInformationW(
                station as HANDLE,
                UOI_NAME,
                buffer.as_mut_ptr().cast(),
                (buffer.len() * size_of::<u16>()) as u32,
                &mut needed,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let len = buffer
            .iter()
            .position(|value| *value == 0)
            .unwrap_or(buffer.len());
        String::from_utf16(&buffer[..len])
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
    }

    struct HiddenDesktop {
        handle: *mut core::ffi::c_void,
        name: String,
    }

    impl HiddenDesktop {
        fn create() -> io::Result<Self> {
            let sequence = DESKTOP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let name = format!("onec_toolkit_sshd_{}_{}", std::process::id(), sequence);
            let wide = wide_null(OsStr::new(&name));
            // SAFETY: the name is a live NUL-terminated UTF-16 buffer. Null device/devmode/security
            // create a private desktop in the helper's existing window station.
            let handle = unsafe {
                CreateDesktopW(
                    wide.as_ptr(),
                    ptr::null(),
                    ptr::null(),
                    0,
                    GENERIC_ALL,
                    ptr::null(),
                )
            };
            if handle.is_null() {
                return Err(io::Error::last_os_error());
            }
            Ok(Self { handle, name })
        }
    }

    impl Drop for HiddenDesktop {
        fn drop(&mut self) {
            // SAFETY: handle is owned by this guard and closed exactly once.
            let _ = unsafe { CloseDesktop(self.handle) };
        }
    }

    struct InheritedStdHandles {
        stdin: OwnedHandle,
        stdout: OwnedHandle,
        stderr: OwnedHandle,
    }

    impl InheritedStdHandles {
        fn new() -> io::Result<Self> {
            Ok(Self {
                stdin: inheritable_std_handle(STD_INPUT_HANDLE, false)?,
                stdout: inheritable_std_handle(STD_OUTPUT_HANDLE, true)?,
                stderr: inheritable_std_handle(STD_ERROR_HANDLE, true)?,
            })
        }

        fn raw_handles(&self) -> [HANDLE; 3] {
            [self.stdin.raw(), self.stdout.raw(), self.stderr.raw()]
        }
    }

    fn inheritable_std_handle(kind: u32, writable: bool) -> io::Result<OwnedHandle> {
        // SAFETY: kind is one of the documented STD_* selectors.
        let inherited = unsafe { GetStdHandle(kind) };
        if inherited.is_null() || inherited == INVALID_HANDLE_VALUE {
            let fallback = if writable {
                OpenOptions::new().write(true).open("NUL")?
            } else {
                File::open("NUL")?
            };
            duplicate_inheritable(fallback.as_raw_handle() as HANDLE)
        } else {
            duplicate_inheritable(inherited)
        }
    }

    fn duplicate_inheritable(source: HANDLE) -> io::Result<OwnedHandle> {
        // SAFETY: GetCurrentProcess returns a pseudo-handle valid in this process; source is a live
        // standard/fallback handle. DuplicateHandle writes one owned inheritable duplicate.
        let current = unsafe { GetCurrentProcess() };
        let mut duplicate: HANDLE = ptr::null_mut();
        if unsafe {
            DuplicateHandle(
                current,
                source,
                current,
                &mut duplicate,
                0,
                1,
                DUPLICATE_SAME_ACCESS,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(OwnedHandle::new(duplicate))
    }

    struct ProcessAttributeList {
        storage: Vec<usize>,
        initialized: bool,
    }

    impl ProcessAttributeList {
        fn with_handle_list(handles: &[HANDLE]) -> io::Result<Self> {
            let mut bytes = 0usize;
            // SAFETY: null sizing call is the documented way to obtain required storage size.
            unsafe {
                InitializeProcThreadAttributeList(ptr::null_mut(), 1, 0, &mut bytes);
            }
            if bytes == 0 {
                return Err(io::Error::last_os_error());
            }
            let words = bytes.div_ceil(size_of::<usize>());
            let mut list = Self {
                storage: vec![0usize; words],
                initialized: false,
            };
            // SAFETY: storage is suitably aligned and at least the requested number of bytes.
            if unsafe { InitializeProcThreadAttributeList(list.raw(), 1, 0, &mut bytes) } == 0 {
                return Err(io::Error::last_os_error());
            }
            list.initialized = true;
            // SAFETY: list is initialized, handles points to the exact owned inheritable handles,
            // and no previous/return value buffers are requested.
            if unsafe {
                UpdateProcThreadAttribute(
                    list.raw(),
                    0,
                    PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                    handles.as_ptr().cast(),
                    size_of_val(handles),
                    ptr::null_mut(),
                    ptr::null(),
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(list)
        }

        fn raw(&mut self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
            self.storage.as_mut_ptr().cast()
        }
    }

    impl Drop for ProcessAttributeList {
        fn drop(&mut self) {
            if self.initialized {
                // SAFETY: `initialized` is set only after InitializeProcThreadAttributeList
                // succeeds and this guard owns that list until drop.
                unsafe { DeleteProcThreadAttributeList(self.raw()) };
            }
        }
    }

    struct OwnedProcessHandle {
        handle: HANDLE,
        completed: bool,
    }

    impl OwnedProcessHandle {
        fn new(handle: HANDLE) -> Self {
            Self {
                handle,
                completed: false,
            }
        }

        fn raw(&self) -> HANDLE {
            self.handle
        }
    }

    impl Drop for OwnedProcessHandle {
        fn drop(&mut self) {
            if self.handle.is_null() || self.handle == INVALID_HANDLE_VALUE {
                return;
            }
            if !self.completed {
                // SAFETY: handle is a live process handle. This is an error-path orphan guard; in
                // normal operation the process is additionally inside the supervisor's Job Object.
                let _ = unsafe { TerminateProcess(self.handle, 1) };
                let _ = unsafe { WaitForSingleObject(self.handle, 5_000) };
            }
            // SAFETY: handle is owned by this guard and closed exactly once.
            let _ = unsafe { CloseHandle(self.handle) };
        }
    }

    struct OwnedHandle(HANDLE);

    impl OwnedHandle {
        fn new(handle: HANDLE) -> Self {
            Self(handle)
        }

        fn raw(&self) -> HANDLE {
            self.0
        }
    }

    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
                // SAFETY: handle is owned by this guard and closed exactly once.
                let _ = unsafe { CloseHandle(self.0) };
            }
        }
    }

    fn wide_null(value: &OsStr) -> Vec<u16> {
        value.encode_wide().chain(std::iter::once(0)).collect()
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn regression_inv_090_named_start_gate_round_trips() {
            let gate = StartGate::create().expect("create start gate");
            gate.signal().expect("signal start gate");
            wait_for_start_event(gate.name()).expect("consume signaled start gate");
        }
    }
}

#[cfg(windows)]
pub(super) use windows::StartGate;

#[cfg(windows)]
pub(crate) fn run(program: &Path, config: &Path, start_event: &str) -> io::Result<u32> {
    windows::run(program, config, start_event)
}

#[cfg(not(windows))]
pub(crate) fn run(_program: &Path, _config: &Path, _start_event: &str) -> io::Result<u32> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "the internal sshd host is Windows-only",
    ))
}

#[cfg(any(windows, test))]
fn validate_start_event_name(name: &str) -> io::Result<()> {
    let suffix = name.strip_prefix(START_EVENT_PREFIX).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "sshd start event is outside the toolkit-owned Local namespace",
        )
    })?;
    if suffix.is_empty()
        || suffix.len() > 128
        || suffix
            .chars()
            .any(|character| character.is_control() || character == '\\')
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid toolkit sshd start event name",
        ));
    }
    Ok(())
}

#[cfg(any(windows, test))]
fn sshd_command_line(program: &Path, config: &Path) -> String {
    onec_core::windows_command_line([
        program.as_os_str().to_string_lossy().into_owned(),
        "-D".to_owned(),
        "-e".to_owned(),
        "-f".to_owned(),
        config.as_os_str().to_string_lossy().into_owned(),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn regression_inv_090_sshd_command_line_preserves_windows_paths() {
        let command = sshd_command_line(
            Path::new(r"C:\Program Files\OpenSSH\sshd.exe"),
            Path::new(r"C:\Users\Example User\agent\sshd_config"),
        );
        assert_eq!(
            command,
            r#""C:\Program Files\OpenSSH\sshd.exe" -D -e -f "C:\Users\Example User\agent\sshd_config""#
        );
    }

    #[test]
    fn regression_inv_090_start_event_is_toolkit_scoped() {
        assert!(validate_start_event_name("Local\\onec_toolkit_sshd_start_123_7").is_ok());
        for invalid in [
            "onec_toolkit_sshd_start_123_7",
            "Global\\onec_toolkit_sshd_start_123_7",
            "Local\\onec_toolkit_sshd_start_",
            "Local\\onec_toolkit_sshd_start_123\\7",
            "Local\\onec_toolkit_sshd_start_123\n7",
        ] {
            assert!(validate_start_event_name(invalid).is_err(), "{invalid:?}");
        }
    }
}
