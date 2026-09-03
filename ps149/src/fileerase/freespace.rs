//! Opt-in free-space wipe: fills a volume's free space with the erasure
//! pattern, then deletes the filler file. Best-effort mitigation for
//! `$MFT` slack and previously-deleted file remnants — not a guarantee
//! (see the compliance note in `report::file_certificate`).

use crate::sanitize::patterns::{fill_buffer, get_pattern, FillPattern, SanitizeMethod};
use anyhow::Result;
use serde::Serialize;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::time::Instant;
use tracing::info;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, GENERIC_WRITE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FlushFileBuffers, GetDiskFreeSpaceExW, WriteFile, CREATE_ALWAYS,
    FILE_FLAGS_AND_ATTRIBUTES, FILE_FLAG_WRITE_THROUGH, FILE_SHARE_READ, FILE_SHARE_WRITE,
};

const SAFETY_MARGIN_MIN_BYTES: u64 = 500 * 1024 * 1024; // 500 MB
const SAFETY_MARGIN_FRACTION: f64 = 0.01; // 1% of volume capacity
const CHUNK_SIZE: usize = 4 * 1024 * 1024; // 4 MB

#[derive(Debug, Clone, Serialize)]
pub struct FreeSpaceWipeResult {
    pub volume: String,
    pub bytes_written: u64,
    pub duration: std::time::Duration,
}

/// Fills a volume's free space with the erasure pattern, then deletes the
/// filler file. Deliberately leaves `max(500 MB, 1% of volume capacity)` of
/// free space untouched rather than driving the volume to zero free space —
/// filling a volume completely (especially the system/boot volume) risks OS
/// instability (page file growth failures, temp file failures).
pub fn wipe_free_space(
    volume_root: &Path,
    method: SanitizeMethod,
    progress_cb: impl Fn(u64, u64),
) -> Result<FreeSpaceWipeResult> {
    let start = Instant::now();
    let volume_str = volume_root.to_string_lossy().to_string();

    let (free_bytes, total_bytes) = query_disk_free_space(&volume_str)?;
    let margin = SAFETY_MARGIN_MIN_BYTES.max((total_bytes as f64 * SAFETY_MARGIN_FRACTION) as u64);
    let target_bytes = free_bytes.saturating_sub(margin);

    let filler_name = format!("ps149_fswipe_{}.tmp", crate::fileerase::random_name(8));
    let filler_path = volume_root.join(&filler_name);
    let filler_str = filler_path.to_string_lossy().to_string();

    let result = write_filler(&filler_str, target_bytes, method, &progress_cb);

    // Always attempt to remove the filler file, even if the write loop
    // errored partway through — never leave it behind on failure.
    let _ = std::fs::remove_file(&filler_path);

    let bytes_written = result?;

    Ok(FreeSpaceWipeResult {
        volume: volume_str,
        bytes_written,
        duration: start.elapsed(),
    })
}

fn query_disk_free_space(volume_str: &str) -> Result<(u64, u64)> {
    let path_u16: Vec<u16> = OsStr::new(volume_str)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut free_bytes_available: u64 = 0;
    let mut total_bytes: u64 = 0;
    let mut total_free_bytes: u64 = 0;

    unsafe {
        // SAFETY: path_u16 is a valid null-terminated UTF-16 string; the
        // three out-params are valid stack variables.
        GetDiskFreeSpaceExW(
            PCWSTR(path_u16.as_ptr()),
            Some(&mut free_bytes_available),
            Some(&mut total_bytes),
            Some(&mut total_free_bytes),
        )
    }
    .map_err(|e| anyhow::anyhow!("GetDiskFreeSpaceExW failed for {}: {}", volume_str, e))?;

    Ok((free_bytes_available, total_bytes))
}

fn write_filler(
    filler_str: &str,
    target_bytes: u64,
    method: SanitizeMethod,
    progress_cb: &impl Fn(u64, u64),
) -> Result<u64> {
    let path_u16: Vec<u16> = OsStr::new(filler_str)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let handle = unsafe {
        // SAFETY: path_u16 is a valid null-terminated UTF-16 string.
        CreateFileW(
            PCWSTR(path_u16.as_ptr()),
            GENERIC_WRITE.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            CREATE_ALWAYS,
            FILE_FLAGS_AND_ATTRIBUTES(FILE_FLAG_WRITE_THROUGH.0),
            None,
        )
    }
    .map_err(|e| anyhow::anyhow!("CreateFileW failed for filler file: {}", e))?;

    // Free-space wipe only needs one pass — there's no existing file content
    // to defeat repeated overwrites for, just raw free clusters — so use the
    // selected method's first-pass pattern.
    let pattern = get_pattern(0, method);
    let is_random = matches!(pattern, FillPattern::Random);
    let mut buf = vec![0u8; CHUNK_SIZE];
    if !is_random {
        fill_buffer(&mut buf, &pattern);
    }

    let mut written_total: u64 = 0;
    while written_total < target_bytes {
        let remaining = (target_bytes - written_total) as usize;
        let chunk_len = remaining.min(buf.len());
        if is_random {
            fill_buffer(&mut buf[..chunk_len], &pattern);
        }

        let mut written: u32 = 0;
        // SAFETY: handle is valid; buf is sized for chunk_len bytes.
        let ok = unsafe { WriteFile(handle, Some(&buf[..chunk_len]), Some(&mut written), None) };
        match ok {
            Ok(()) if written > 0 => {
                written_total += written as u64;
                progress_cb(written_total, target_bytes);
            }
            _ => {
                // Disk full (or any other write failure) before reaching the
                // computed target is expected near the safety margin — stop
                // cleanly rather than erroring the whole operation.
                info!(
                    "Free-space wipe stopped after {} bytes (target was {})",
                    written_total, target_bytes
                );
                break;
            }
        }
    }

    unsafe {
        let _ = FlushFileBuffers(handle);
        let _ = CloseHandle(handle);
    }

    Ok(written_total)
}
