//! Read-only legacy detection. Never migrate or delete old registrations.
use super::*;
use windows_sys::Win32::System::Registry::{
    HKEY_CURRENT_USER, KEY_QUERY_VALUE, RegCloseKey, RegOpenKeyExW, RegQueryValueExW,
};

pub(super) fn reject(root: &Path) -> io::Result<()> {
    for entry in fs::read_dir(root)? {
        let name = entry?.file_name();
        let name = name.to_string_lossy().to_ascii_lowercase();
        if name == ".hostlink-user-service.json"
            || name == ".hostlink-agent-start.vbs"
            || name == ".hostlink-maintenance-admission.json"
            || name.starts_with(".hostlink-service-marker-")
        {
            return Err(invalid(
                "legacy Windows service files found; use the matching old Agent to remove its registration in a separately authorized migration; files preserved",
            ));
        }
    }
    let key_name = wide(r"Software\Microsoft\Windows\CurrentVersion\Run");
    let value_name = wide(&format!("HostLinkAgent-{}", root_digest(root)));
    let mut key = std::ptr::null_mut();
    // SAFETY: NUL-terminated name and writable handle; query-only access to current user.
    let result = unsafe {
        RegOpenKeyExW(
            HKEY_CURRENT_USER,
            key_name.as_ptr(),
            0,
            KEY_QUERY_VALUE,
            &mut key,
        )
    };
    if result == 2 {
        return Ok(());
    }
    if result != 0 {
        return Err(io::Error::from_raw_os_error(result as i32));
    }
    // SAFETY: live read-only handle; null buffers query existence without parsing any value.
    let result = unsafe {
        RegQueryValueExW(
            key,
            value_name.as_ptr(),
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    // SAFETY: uniquely owned registry handle, no longer used.
    unsafe { RegCloseKey(key) };
    match result {
        2 => Ok(()),
        0 | 234 => Err(invalid(
            "legacy HKCU Run registration found; it was not changed; remove it with the matching legacy Agent before Task Scheduler installation or offline update",
        )),
        _ => Err(io::Error::from_raw_os_error(result as i32)),
    }
}
