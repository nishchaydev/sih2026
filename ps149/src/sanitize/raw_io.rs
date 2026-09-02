use anyhow::Result;
use windows::core::{HSTRING, PCWSTR};
use windows::Win32::Foundation::{
    CloseHandle, GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE,
};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FlushFileBuffers, SetFilePointerEx, FILE_BEGIN,
    FILE_FLAGS_AND_ATTRIBUTES, FILE_FLAG_NO_BUFFERING, FILE_FLAG_WRITE_THROUGH,
    FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};

pub struct DiskHandle(HANDLE);

impl Drop for DiskHandle {
    fn drop(&mut self) {
        unsafe {
            if self.0 != INVALID_HANDLE_VALUE {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

impl DiskHandle {
    pub fn as_raw(&self) -> HANDLE {
        self.0
    }

    /// Flushes all buffered writes to physical media.
    /// Call this after all write passes complete, before verification.
    pub fn flush(&self) -> Result<()> {
        unsafe {
            FlushFileBuffers(self.as_raw())?;
        }
        Ok(())
    }
}

/// Opens a physical disk for writing.
///
/// Opens a physical disk for writing with maximum throughput.
///
/// No special I/O flags — the OS can pipeline writes through the USB
/// controller's buffer, batch I/O requests, and manage the transfer
/// asynchronously. This gives 5-15x better throughput on USB drives.
///
/// Data integrity is guaranteed by:
/// 1. `FlushFileBuffers()` after all writes (forces to physical media)
/// 2. Verification read-back with `FILE_FLAG_NO_BUFFERING` (bypasses cache)
pub fn open_disk_write(disk_index: u32) -> Result<DiskHandle> {
    let path = format!("\\\\.\\PhysicalDrive{}", disk_index);
    let hstring = HSTRING::from(path);
    let handle = unsafe {
        CreateFileW(
            PCWSTR(hstring.as_ptr()),
            GENERIC_WRITE.0 | GENERIC_READ.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            // Direct write-through to prevent Windows OS from buffering gigabytes in RAM
            // and freezing when the slow USB controller cannot keep up.
            FILE_FLAGS_AND_ATTRIBUTES(FILE_FLAG_WRITE_THROUGH.0),
            None,
        )
    }?;

    if handle.is_invalid() {
        return Err(anyhow::anyhow!(
            "Failed to open physical drive {} for writing",
            disk_index
        ));
    }

    Ok(DiskHandle(handle))
}

/// Opens a physical disk for reading (verification).
pub fn open_disk_read(disk_index: u32) -> Result<DiskHandle> {
    let path = format!("\\\\.\\PhysicalDrive{}", disk_index);
    let hstring = HSTRING::from(path);
    let handle = unsafe {
        CreateFileW(
            PCWSTR(hstring.as_ptr()),
            GENERIC_READ.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_FLAGS_AND_ATTRIBUTES(FILE_FLAG_NO_BUFFERING.0),
            None,
        )
    }?;

    if handle.is_invalid() {
        return Err(anyhow::anyhow!(
            "Failed to open physical drive {} for reading",
            disk_index
        ));
    }

    Ok(DiskHandle(handle))
}

/// Seeks to a sector position.
pub fn seek_to_sector(handle: &DiskHandle, sector: u64, bytes_per_sector: u32) -> Result<()> {
    let offset = (sector * bytes_per_sector as u64) as i64;
    unsafe {
        SetFilePointerEx(handle.as_raw(), offset, None, FILE_BEGIN)?;
    }
    Ok(())
}
