use crate::sanitize::patterns::{self, FillPattern, SanitizeMethod};
use anyhow::{Context, Result};
use tracing::info;
use windows::core::HSTRING;
use windows::Win32::Foundation::{GENERIC_WRITE, HANDLE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, DeleteFileW, FlushFileBuffers, WriteFile,
    CREATE_ALWAYS, FILE_FLAGS_AND_ATTRIBUTES, FILE_FLAG_WRITE_THROUGH,
    FILE_SHARE_NONE,
};

use super::FreeSpaceWipeResult;

/// Wipe all free space on a volume using the SDelete technique:
/// 1. Create a temporary file on the volume
/// 2. Keep writing pattern data until the disk is full (ERROR_DISK_FULL)
/// 3. Delete the temporary file
///
/// This overwrites all previously-deleted file clusters, stale MFT slack,
/// and orphaned metadata fragments.
pub fn wipe_free_space(
    volume_letter: char,
    method: SanitizeMethod,
    progress_callback: &impl Fn(&str, f64),
) -> Result<FreeSpaceWipeResult> {
    let start = std::time::Instant::now();
    let temp_path = format!("{}:\\ps149_freespace_wipe.tmp", volume_letter);
    let hstring = HSTRING::from(&temp_path);

    progress_callback("Creating wipe file...", 0.0);

    let handle = unsafe {
        CreateFileW(
            &hstring,
            GENERIC_WRITE.0,
            FILE_SHARE_NONE,
            None,
            CREATE_ALWAYS,
            FILE_FLAGS_AND_ATTRIBUTES(FILE_FLAG_WRITE_THROUGH.0),
            None,
        )
    }
    .with_context(|| format!("Failed to create temp file on {}:", volume_letter))?;

    let _guard = HandleGuard(handle);

    // Get volume free space for progress estimation
    let total_free = get_volume_free_space(volume_letter).unwrap_or(1);

    let buf_size: usize = 1_048_576; // 1 MB
    let mut buf = vec![0u8; buf_size];
    let pattern = patterns::get_pattern(0, method);
    patterns::fill_buffer(&mut buf, &pattern);

    let mut total_written: u64 = 0;
    let is_random = matches!(pattern, FillPattern::Random);

    loop {
        if is_random {
            patterns::fill_buffer(&mut buf, &pattern);
        }

        let mut written: u32 = 0;
        let result = unsafe {
            WriteFile(handle, Some(&buf), Some(&mut written), None)
        };

        match result {
            Ok(_) => {
                total_written += written as u64;
                let pct = (total_written as f64 / total_free as f64).min(0.99);
                if total_written % (100 * 1_048_576) == 0 {
                    let mb = total_written / 1_048_576;
                    progress_callback(&format!("Wiping free space... {} MB written", mb), pct);
                }
            }
            Err(_) => {
                // ERROR_DISK_FULL or similar — volume is full, we're done
                info!(
                    "Free space wipe complete: {} bytes written to {}",
                    total_written, temp_path
                );
                break;
            }
        }
    }

    // Flush and close handle
    unsafe {
        let _ = FlushFileBuffers(handle);
    }
    drop(_guard);

    // Delete the temporary file
    progress_callback("Cleaning up temp file...", 0.99);
    let del_h = HSTRING::from(&temp_path);
    if unsafe { DeleteFileW(&del_h) }.is_err() {
        let _ = std::fs::remove_file(&temp_path);
    }

    progress_callback("Free space wipe complete", 1.0);

    Ok(FreeSpaceWipeResult {
        volume: format!("{}:", volume_letter),
        bytes_wiped: total_written,
        method,
        duration: start.elapsed(),
    })
}

struct HandleGuard(HANDLE);
impl Drop for HandleGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = windows::Win32::Foundation::CloseHandle(self.0);
        }
    }
}

fn get_volume_free_space(letter: char) -> Option<u64> {
    let root = format!("{}:\\", letter);
    let hstring = HSTRING::from(&root);

    use windows::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;
    let mut free_bytes: u64 = 0;

    let ok = unsafe {
        GetDiskFreeSpaceExW(
            &hstring,
            Some(&mut free_bytes),
            None,
            None,
        )
    };

    match ok {
        Ok(_) => Some(free_bytes),
        Err(_) => None,
    }
}
