use crate::model::device::PhysicalDisk;
use anyhow::Result;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAGS_AND_ATTRIBUTES, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows::Win32::System::IO::DeviceIoControl;
use tracing::info;

const FSCTL_LOCK_VOLUME: u32 = 0x00090018;
const FSCTL_DISMOUNT_VOLUME: u32 = 0x00090020;

/// Holds open volume handles to keep FSCTL_LOCK_VOLUME alive.
/// The lock is handle-based — it releases when the handle closes.
/// This struct must stay alive during the entire sanitization operation.
pub struct VolumeGuard {
    handles: Vec<HANDLE>,
}

impl Drop for VolumeGuard {
    fn drop(&mut self) {
        for &handle in &self.handles {
            // SAFETY: These handles were opened by us and are valid.
            unsafe {
                let _ = CloseHandle(handle);
            }
        }
        if !self.handles.is_empty() {
            info!("Released {} volume lock(s)", self.handles.len());
        }
    }
}

/// Locks and dismounts all volumes on a physical disk.
///
/// Returns a `VolumeGuard` that holds the lock handles open.
/// **The guard MUST be kept alive** until raw disk I/O is complete.
/// Dropping the guard releases all volume locks.
pub fn lock_and_dismount_volumes(disk: &PhysicalDisk) -> Result<VolumeGuard> {
    let drive_letters: Vec<String> = disk
        .partitions
        .iter()
        .flat_map(|p| p.volumes.iter())
        .filter_map(|v| v.drive_letter.clone())
        .collect();

    let mut handles = Vec::new();

    if drive_letters.is_empty() {
        info!("No mounted volumes found on Disk {} — skipping lock/dismount", disk.index);
        return Ok(VolumeGuard { handles });
    }

    for letter in &drive_letters {
        let path = format!("\\\\.\\{}", letter);
        info!("Locking and dismounting volume {}", path);

        let path_u16: Vec<u16> = OsStr::new(&path)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        // SAFETY: Valid null-terminated UTF-16 path.
        let handle = unsafe {
            CreateFileW(
                PCWSTR(path_u16.as_ptr()),
                0xC0000000, // GENERIC_READ | GENERIC_WRITE
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                FILE_FLAGS_AND_ATTRIBUTES(0),
                None,
            )
        };

        let handle = match handle {
            Ok(h) if !h.is_invalid() => h,
            Ok(_) | Err(_) => {
                tracing::warn!("Could not open volume {} — skipping", letter);
                continue;
            }
        };

        fsctl_no_io(handle, FSCTL_LOCK_VOLUME, letter, "lock");
        fsctl_no_io(handle, FSCTL_DISMOUNT_VOLUME, letter, "dismount");

        // DO NOT close the handle — keep it alive to hold the lock!
        handles.push(handle);
    }

    info!(
        "Locked {} volume(s) — handles held open for raw I/O",
        handles.len()
    );

    Ok(VolumeGuard { handles })
}

/// Sends a no-I/O DeviceIoControl command.
fn fsctl_no_io(handle: HANDLE, code: u32, label: &str, verb: &str) {
    let mut bytes_returned: u32 = 0;
    // SAFETY: Valid handle, no input/output buffers needed.
    let result = unsafe {
        DeviceIoControl(
            handle,
            code,
            None,
            0,
            None,
            0,
            Some(&mut bytes_returned),
            None,
        )
    };
    match result {
        Ok(()) => info!("Successfully {}ed volume {}", verb, label),
        Err(e) => tracing::warn!("Failed to {} volume {}: {}", verb, label, e),
    }
}
