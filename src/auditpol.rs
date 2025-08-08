use std::ffi::c_void;
use std::mem;
use windows::Win32::System::Threading::GetCurrentProcess;
use windows::Win32::System::Threading::OpenProcessToken;
use windows::{Win32::Foundation::*, Win32::Security::*, Win32::System::LibraryLoader::*, core::*};

/** Audit subcategory GUIDs */
/// "Other Logon/Loff Events", including screen lock, screen unlock, etc
///
/// https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-other-logonlogoff-events
///
///    4649(S): A replay attack was detected.
///
///    4778(S): A session was reconnected to a Window Station.
///
///    4779(S): A session was disconnected from a Window Station.
///
///    4800(S): The workstation was locked.
///
///    4801(S): The workstation was unlocked.
///
///    4802(S): The screen saver was invoked.
///
///    4803(S): The screen saver was dismissed.
///
///    5378(F): The requested credentials delegation was disallowed by policy.
///
///    5632(S): A request was made to authenticate to a wireless network.
///
///    5633(S): A request was made to authenticate to a wired network.
const AUDIT_OTHER_LOGON_LOGOFF_EVENTS_GUID: windows::core::GUID = windows::core::GUID {
    data1: 0x0cce921c,
    data2: 0x69ae,
    data3: 0x11d9,
    data4: [0xbe, 0xd3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30],
};

/// "Account Logon"
///
/// https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-logon
///
///    4624(S): An account was successfully logged on.
///
///    4625(F): An account failed to log on.
///
///    4648(S): A logon was attempted using explicit credentials.
///
///    4675(S): SIDs were filtered.
const AUDIT_LOGON_GUID: windows::core::GUID = windows::core::GUID {
    data1: 0x0cce9215,
    data2: 0x69ae,
    data3: 0x11d9,
    data4: [0xbe, 0xd3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30],
};

/// "Account Logoff"
///
/// https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-logoff
///
///    4634(S): An account was logged off.
///
///    4647(S): User initiated logoff.
const AUDIT_LOGOFF_GUID: windows::core::GUID = windows::core::GUID {
    data1: 0x0cce9216,
    data2: 0x69ae,
    data3: 0x11d9,
    data4: [0xbe, 0xd3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30],
};

#[repr(C)]
#[derive(Copy, Clone)]
#[allow(non_camel_case_types)]
struct AUDIT_POLICY_INFORMATION {
    audit_subcategory_guid: windows::core::GUID,
    auditing_information: u32,
    audit_category_guid: windows::core::GUID,
}

type AuditSetSystemPolicyFn =
    unsafe extern "system" fn(*const AUDIT_POLICY_INFORMATION, u32) -> BOOL;

type AuditQuerySystemPolicyFn = unsafe extern "system" fn(
    *const windows::core::GUID,
    u32,
    *mut *mut AUDIT_POLICY_INFORMATION,
) -> BOOL;

/// Extern function for system `free()`
type AuditFreeFn = unsafe extern "system" fn(*mut c_void);

/// Enables the `SE_SECURITY_PRIVILEGE` for the process, which lets us change audit policies
fn enable_security_privilege() -> Result<()> {
    unsafe {
        let mut token: HANDLE = HANDLE::default();

        /* Get current process token */
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        )?;

        /* Look up the LUID for SE_SECURITY_PRIVILEGE */
        let mut luid = LUID::default();
        LookupPrivilegeValueW(
            None,
            crate::win32::WidePcwstr::new("SeSecurityPrivilege").as_pcwstr(),
            &mut luid,
        )?;

        /* Enable the privilege */
        let mut token_privileges = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };

        AdjustTokenPrivileges(token, false, Some(&mut token_privileges), 0, None, None)?;

        /* Check if the privilege was actually granted */
        let last_error = GetLastError();
        if last_error.0 == 1300 {
            /* ERROR_NOT_ALL_ASSIGNED */
            log::error!(
                "SE_SECURITY_PRIVILEGE was not assigned. Make sure to run as Administrator and that the user has 'Manage auditing and security log' rights."
            );
            CloseHandle(token).ok();
            return Err(Error::from_win32());
        }

        CloseHandle(token).ok();
        log::info!("SE_SECURITY_PRIVILEGE enabled successfully");
        Ok(())
    }
}

fn get_audit_policy(advapi32: HMODULE, guid: &windows::core::GUID, name: &str) -> Result<u32> {
    // Query current policy
    log::info!("Querying current audit policy for '{}'...", name);
    unsafe {
        let audit_query_system_policy = GetProcAddress(advapi32, s!("AuditQuerySystemPolicy"))
            .ok_or_else(|| Error::from_win32())?;
        let audit_free =
            GetProcAddress(advapi32, s!("AuditFree")).ok_or_else(|| Error::from_win32())?;

        let audit_query_system_policy: AuditQuerySystemPolicyFn =
            mem::transmute(audit_query_system_policy);
        let audit_free: AuditFreeFn = mem::transmute(audit_free);

        let mut policy_array: *mut AUDIT_POLICY_INFORMATION = std::ptr::null_mut();

        let query_result = audit_query_system_policy(guid, 1, &mut policy_array);

        if query_result.as_bool() && !policy_array.is_null() {
            let current_policy = *policy_array;
            let info = current_policy.auditing_information;
            log::info!(
                "Current audit setting: 0x{:x}",
                current_policy.auditing_information
            );
            audit_free(policy_array as *mut c_void);
            Ok(info)
        } else {
            Err(Error::from_win32())
        }
    }
}

/// Sets the audit policy of the `guid`. Can audit on success, or on failure, or on both.
///
/// `name` is just for display and logging purposes
fn set_audit_policy(
    advapi32: HMODULE,
    guid: &windows::core::GUID,
    name: &str,
    enable_success: bool,
    enable_failure: bool,
) -> Result<()> {
    unsafe {
        let audit_set_system_policy = GetProcAddress(advapi32, s!("AuditSetSystemPolicy"))
            .ok_or_else(|| Error::from_win32())?;
        let audit_set_system_policy: AuditSetSystemPolicyFn =
            mem::transmute(audit_set_system_policy);

        match get_audit_policy(advapi32, guid, name) {
            Ok(info) => {
                log::info!("Current audit setting: 0x{:x}", info);
            }
            Err(e) => {
                log::error!("Failed to query current policy. Error: {}", e,);
                Err(e)?
            }
        };

        /* Set new policy */
        let mut auditing_flags = 0u32;
        if enable_success {
            auditing_flags |= 0x1; /* POLICY_AUDIT_EVENT_SUCCESS */
        }
        if enable_failure {
            auditing_flags |= 0x2; /* POLICY_AUDIT_EVENT_FAILURE */
        }

        let policy_info = AUDIT_POLICY_INFORMATION {
            audit_subcategory_guid: *guid,
            auditing_information: auditing_flags,
            audit_category_guid: windows::core::GUID::zeroed(),
        };

        log::info!("Setting audit policy for '{}'...", name);

        let result = audit_set_system_policy(&policy_info, 1);

        if result.as_bool() {
            log::info!("Successfully enabled '{}' policy", name);
            if enable_success {
                log::info!("   - Success events: Enabled");
            }
            if enable_failure {
                log::info!("   - Failure events: Enabled");
            }
        } else {
            let error = GetLastError();
            log::error!(
                "Failed to set audit policy for '{}'. Error code: {}",
                name,
                error.0
            );

            match error.0 {
                5 => log::error!("   Access denied. Please run as Administrator."),
                87 => log::error!("   Invalid parameter."),
                _ => log::error!("   Unknown error occurred."),
            }
            return Err(Error::from_win32());
        }

        /* Verify the change */
        log::info!("Verifying the change for '{}'...", name);
        let updated_policy = match get_audit_policy(advapi32, guid, name) {
            Ok(info) => {
                log::info!("New audit setting: 0x{:x}", info);
                info
            }
            Err(e) => {
                log::error!("Failed to query new policy. Error: {}", e,);
                Err(e)?
            }
        };
        if updated_policy & 0x1 != 0 {
            log::info!("Success auditing is enabled");
        }
        if updated_policy & 0x2 != 0 {
            log::info!("Failure auditing is enabled");
        }
    }

    Ok(())
}

pub fn enable_audit_policies() -> Result<()> {
    log::info!("Setting up audit policies for Logon/Logoff events...");

    /* First, enable the required privilege */
    match enable_security_privilege() {
        Ok(()) => log::info!("Security privilege enabled successfully."),
        Err(e) => {
            log::error!("Failed to enable security privilege: {}", e);
            log::error!(
                "Make sure you're running as Administrator and have 'Manage auditing and security log' rights."
            );
            return Err(e);
        }
    }

    let advapi32 = load_advapi()?;
    /* Enable Audit Logon */
    if let Err(e) = enable_audit_logon(advapi32, true, false) {
        log::error!("Failed to set Audit Logon: {}", e);
    }

    /* Enable Audit Logoff */
    if let Err(e) = enable_audit_logoff(advapi32, true, false) {
        log::error!("Failed to set Audit Logoff: {}", e);
    }

    /* Enable Audit Other Logon/Logoff Events */
    if let Err(e) = enable_audit_other_logon_logoff_events(advapi32, true, false) {
        log::error!("Failed to set Audit Other Logon/Logoff Events: {}", e);
    }
    unsafe { FreeLibrary(advapi32) }?;

    log::info!("All audit policies have been configured");

    Ok(())
}

/* Individual helper functions for each audit type */

/// Sets Audit Policy for the "Logon" event
pub fn enable_audit_logon(
    advapi32: HMODULE,
    enable_success: bool,
    enable_failure: bool,
) -> Result<()> {
    set_audit_policy(
        advapi32,
        &AUDIT_LOGON_GUID,
        "Audit Logon",
        enable_success,
        enable_failure,
    )
}

/// Sets Audit Policy for the "Logoff" event
pub fn enable_audit_logoff(
    advapi32: HMODULE,
    enable_success: bool,
    enable_failure: bool,
) -> Result<()> {
    set_audit_policy(
        advapi32,
        &AUDIT_LOGOFF_GUID,
        "Audit Logoff",
        enable_success,
        enable_failure,
    )
}

/// Sets Audit Policy for the "Other Logon/Logoff" events, which also include Screen Locking / Unlocking
pub fn enable_audit_other_logon_logoff_events(
    advapi32: HMODULE,
    enable_success: bool,
    enable_failure: bool,
) -> Result<()> {
    set_audit_policy(
        advapi32,
        &AUDIT_OTHER_LOGON_LOGOFF_EVENTS_GUID,
        "Audit Other Logon/Logoff Events",
        enable_success,
        enable_failure,
    )
}

/// Convenience function to enable all logon/logoff auditing
pub fn enable_all_logon_logoff_auditing() -> Result<()> {
    let advapi32 = load_advapi()?;
    enable_audit_logon(advapi32, true, true)?;
    enable_audit_logoff(advapi32, true, true)?;
    enable_audit_other_logon_logoff_events(advapi32, true, true)?;
    unsafe { FreeLibrary(advapi32) }?;
    Ok(())
}

fn load_advapi() -> Result<windows::Win32::Foundation::HMODULE> {
    unsafe { LoadLibraryA(s!("advapi32.dll")) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enable_all_audit_policies() {
        let result = enable_all_logon_logoff_auditing();
        match result {
            Ok(()) => println!("Test passed: All audit policies enabled successfully"),
            Err(e) => println!("Test note: {}", e),
        }
    }
}
