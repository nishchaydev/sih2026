//! Per-file secure delete: overwrite every data stream, truncate, rename to
//! a random name (to strip the original filename from the directory entry),
//! then remove it.

use crate::fileerase::streams;
use crate::sanitize::patterns::{fill_buffer, get_pattern, FillPattern, SanitizeMethod};
use anyhow::Result;
use serde::Serialize;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, GENERIC_WRITE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FlushFileBuffers, GetFileSizeEx, SetEndOfFile, SetFilePointerEx, WriteFile,
    FILE_BEGIN, FILE_FLAGS_AND_ATTRIBUTES, FILE_FLAG_WRITE_THROUGH, FILE_SHARE_READ,
    FILE_SHARE_WRITE, OPEN_EXISTING,
};

const CHUNK_SIZE: usize = 1_048_576; // 1 MB — matches sanitize::pass's write chunk size

#[derive(Debug, Clone, Serialize)]
pub struct FileWipeRecord {
    pub original_path: String,
    pub size_bytes: u64,
    pub streams_wiped: usize,
    pub passes: usize,
    pub renamed_to: Option<String>,
    pub deleted: bool,
    pub errors: Vec<String>,
}

/// Securely deletes a single file: overwrites every data stream (including
/// alternate data streams) for `method.pass_count()` passes, truncates,
/// renames to a random name, then removes it. Never returns `Err` for a
/// per-file failure — problems are recorded in `FileWipeRecord.errors` so a
/// locked/in-use file doesn't abort a larger batch.
pub fn secure_delete_file(path: &Path, method: SanitizeMethod) -> FileWipeRecord {
    let original_path = path.to_string_lossy().to_string();
    let mut errors = Vec::new();
    let mut streams_wiped = 0usize;
    let mut size_bytes = 0u64;

    let stream_paths = match streams::list_stream_open_paths(path) {
        Ok(s) => s,
        Err(e) => {
            errors.push(format!(
                "Stream enumeration failed: {} — falling back to main stream only",
                e
            ));
            vec![original_path.clone()]
        }
    };

    for stream_path in &stream_paths {
        match overwrite_stream(stream_path, method) {
            Ok(len) => {
                streams_wiped += 1;
                if stream_path == &original_path {
                    size_bytes = len;
                }
            }
            Err(e) => errors.push(format!("Failed to overwrite stream {}: {}", stream_path, e)),
        }
    }

    if let Err(e) = truncate_file(&original_path) {
        errors.push(format!("Failed to truncate: {}", e));
    }

    let renamed_to: Option<PathBuf> = match rename_to_random(path) {
        Ok(new_path) => Some(new_path),
        Err(e) => {
            errors.push(format!("Failed to rename before delete: {}", e));
            None
        }
    };

    let delete_target: PathBuf = renamed_to.clone().unwrap_or_else(|| path.to_path_buf());

    let deleted = match std::fs::remove_file(&delete_target) {
        Ok(()) => true,
        Err(e) => {
            errors.push(format!("Failed to delete: {}", e));
            false
        }
    };

    FileWipeRecord {
        original_path,
        size_bytes,
        streams_wiped,
        passes: method.pass_count(),
        renamed_to: renamed_to.map(|p| p.to_string_lossy().to_string()),
        deleted,
        errors,
    }
}

fn overwrite_stream(stream_path: &str, method: SanitizeMethod) -> Result<u64> {
    let path_u16: Vec<u16> = OsStr::new(stream_path)
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
            OPEN_EXISTING,
            FILE_FLAGS_AND_ATTRIBUTES(FILE_FLAG_WRITE_THROUGH.0),
            None,
        )
    }
    .map_err(|e| anyhow::anyhow!("CreateFileW failed for {}: {}", stream_path, e))?;

    let mut size: i64 = 0;
    // SAFETY: handle is valid; size is a valid stack variable.
    if unsafe { GetFileSizeEx(handle, &mut size) }.is_err() {
        unsafe {
            let _ = CloseHandle(handle);
        }
        anyhow::bail!("GetFileSizeEx failed for {}", stream_path);
    }
    let len = size.max(0) as u64;

    let passes = method.pass_count();
    let mut buf = vec![0u8; CHUNK_SIZE.min(len.max(1) as usize)];

    for pass_index in 0..passes {
        let pattern = get_pattern(pass_index, method);
        let is_random = matches!(pattern, FillPattern::Random);
        if !is_random {
            fill_buffer(&mut buf, &pattern);
        }

        // SAFETY: handle is valid.
        if unsafe { SetFilePointerEx(handle, 0, None, FILE_BEGIN) }.is_err() {
            unsafe {
                let _ = CloseHandle(handle);
            }
            anyhow::bail!("Seek failed for {}", stream_path);
        }

        let mut written_total: u64 = 0;
        while written_total < len {
            let remaining = (len - written_total) as usize;
            let chunk_len = remaining.min(buf.len());
            if is_random {
                fill_buffer(&mut buf[..chunk_len], &pattern);
            }
            let mut written: u32 = 0;
            // SAFETY: handle is valid; buf is sized for chunk_len bytes.
            let ok = unsafe { WriteFile(handle, Some(&buf[..chunk_len]), Some(&mut written), None) };
            if ok.is_err() {
                unsafe {
                    let _ = CloseHandle(handle);
                }
                anyhow::bail!("WriteFile failed for {} at offset {}", stream_path, written_total);
            }
            written_total += written as u64;
            if written == 0 {
                break; // avoid an infinite loop on an unexpected zero-length write
            }
        }

        unsafe {
            let _ = FlushFileBuffers(handle);
        }
    }

    unsafe {
        let _ = CloseHandle(handle);
    }

    Ok(len)
}

fn truncate_file(path: &str) -> Result<()> {
    let path_u16: Vec<u16> = OsStr::new(path)
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
            OPEN_EXISTING,
            FILE_FLAGS_AND_ATTRIBUTES(0),
            None,
        )
    }
    .map_err(|e| anyhow::anyhow!("CreateFileW failed for truncate {}: {}", path, e))?;

    let result = unsafe {
        // SAFETY: handle is valid.
        if SetFilePointerEx(handle, 0, None, FILE_BEGIN).is_err() {
            Err(anyhow::anyhow!("Seek failed for truncate {}", path))
        } else if SetEndOfFile(handle).is_err() {
            Err(anyhow::anyhow!("SetEndOfFile failed for {}", path))
        } else {
            Ok(())
        }
    };

    unsafe {
        let _ = CloseHandle(handle);
    }
    result
}

fn rename_to_random(path: &Path) -> Result<PathBuf> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("No parent directory for {}", path.display()))?;
    let new_path = parent.join(crate::fileerase::random_name(12));
    std::fs::rename(path, &new_path).map_err(|e| anyhow::anyhow!("rename failed: {}", e))?;
    Ok(new_path)
}
