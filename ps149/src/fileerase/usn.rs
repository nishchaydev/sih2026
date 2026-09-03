//! Opt-in USN change journal (`$UsnJrnl`) deletion.
//!
//! **Volume-wide, not scoped to any particular file or folder.** Callers
//! must only invoke `delete_usn_journal` behind an explicit, clearly-labeled
//! opt-in — see `fileerase::mod` and the CLI confirmation prompt in
//! `main.rs`. Requires administrator privileges, same as opening
//! `\\.\PhysicalDriveN` does elsewhere in this tool.
//!
//! FSCTL codes and structs are hand-rolled rather than pulled from the
//! `windows` crate, matching this codebase's existing convention for
//! well-known FSCTL codes (see `sanitize::volume_ops`'s
//! `FSCTL_LOCK_VOLUME`/`FSCTL_DISMOUNT_VOLUME`).

use anyhow::Result;
use serde::Serialize;
use std::ffi::{c_void, OsStr};
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use tracing::{info, warn};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, GENERIC_READ, GENERIC_WRITE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAGS_AND_ATTRIBUTES, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows::Win32::System::IO::DeviceIoControl;

const FSCTL_QUERY_USN_JOURNAL: u32 = 0x000900F4;
const FSCTL_DELETE_USN_JOURNAL: u32 = 0x000900F8;
const USN_DELETE_FLAG_DELETE: u32 = 0x00000001;
const USN_DELETE_FLAG_NOTIFY: u32 = 0x00000002;

#[repr(C)]
#[derive(Default)]
struct UsnJournalDataV0 {
    usn_journal_id: u64,
    first_usn: i64,
    next_usn: i64,
    lowest_valid_usn: i64,
    max_usn: i64,
    maximum_size: u64,
    allocation_delta: u64,
}

#[repr(C)]
struct DeleteUsnJournalData {
    usn_journal_id: u64,
    delete_flags: u32,
}

#[derive(Debug, Clone, Serialize)]
pub enum UsnJournalOutcome {
    Deleted,
    NoActiveJournal,
}

/// Deletes the USN change journal for an entire volume.
pub fn delete_usn_journal(volume_root: &Path) -> Result<UsnJournalOutcome> {
    let drive_letter = volume_root
        .to_string_lossy()
        .chars()
        .next()
        .ok_or_else(|| anyhow::anyhow!("Cannot determine drive letter for {}", volume_root.display()))?;
    let path = format!("\\\\.\\{}:", drive_letter);
    let path_u16: Vec<u16> = OsStr::new(&path).encode_wide().chain(std::iter::once(0)).collect();

    let handle = unsafe {
        // SAFETY: path_u16 is a valid null-terminated UTF-16 string.
        CreateFileW(
            PCWSTR(path_u16.as_ptr()),
            GENERIC_READ.0 | GENERIC_WRITE.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_FLAGS_AND_ATTRIBUTES(0),
            None,
        )
    }
    .map_err(|e| anyhow::anyhow!("Failed to open volume {} (requires Administrator): {}", path, e))?;

    let mut query_out = UsnJournalDataV0::default();
    let mut bytes_returned: u32 = 0;
    // SAFETY: handle is valid; query_out is a valid, correctly-sized output buffer.
    let query_result = unsafe {
        DeviceIoControl(
            handle,
            FSCTL_QUERY_USN_JOURNAL,
            None,
            0,
            Some(&mut query_out as *mut _ as *mut c_void),
            std::mem::size_of::<UsnJournalDataV0>() as u32,
            Some(&mut bytes_returned),
            None,
        )
    };

    if let Err(e) = query_result {
        unsafe {
            let _ = CloseHandle(handle);
        }
        // No active journal on this volume — nothing to delete, not an error.
        warn!("No active USN journal on {} ({}) — treating as no-op", path, e);
        return Ok(UsnJournalOutcome::NoActiveJournal);
    }

    let delete_in = DeleteUsnJournalData {
        usn_journal_id: query_out.usn_journal_id,
        delete_flags: USN_DELETE_FLAG_DELETE | USN_DELETE_FLAG_NOTIFY,
    };

    // SAFETY: handle is valid; delete_in is a fully-initialized, sized struct.
    let delete_result = unsafe {
        DeviceIoControl(
            handle,
            FSCTL_DELETE_USN_JOURNAL,
            Some(&delete_in as *const _ as *const c_void),
            std::mem::size_of::<DeleteUsnJournalData>() as u32,
            None,
            0,
            Some(&mut bytes_returned),
            None,
        )
    };

    unsafe {
        let _ = CloseHandle(handle);
    }

    delete_result.map_err(|e| anyhow::anyhow!("FSCTL_DELETE_USN_JOURNAL failed for {}: {}", path, e))?;

    info!("USN journal deleted for volume {}", path);
    Ok(UsnJournalOutcome::Deleted)
}
