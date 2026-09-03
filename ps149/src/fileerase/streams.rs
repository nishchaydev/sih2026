//! NTFS Alternate Data Stream (ADS) enumeration.
//!
//! A file can carry more than one named data stream beyond its primary
//! content (`::$DATA`). A secure-delete tool that only overwrites the
//! primary stream leaves named streams' content fully intact on disk, so
//! this module enumerates every stream and hands back a directly-openable
//! path for each one.

use anyhow::Result;
use std::ffi::{c_void, OsStr};
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use windows::core::PCWSTR;
use windows::Win32::Foundation::INVALID_HANDLE_VALUE;
use windows::Win32::Storage::FileSystem::{
    FindClose, FindFirstStreamW, FindNextStreamW, FindStreamInfoStandard, WIN32_FIND_STREAM_DATA,
};

/// Enumerates NTFS alternate data streams on a file and returns the
/// fully-qualified, individually-openable path for each stream (including
/// the unnamed default stream, mapped to `file_path` itself). Falls back to
/// `[file_path]` on any enumeration failure — e.g. non-NTFS volumes
/// (FAT32/exFAT don't support ADS) — so callers always get at least the
/// main stream and every filesystem this tool supports keeps working.
pub fn list_stream_open_paths(file_path: &Path) -> Result<Vec<String>> {
    let base = file_path.to_string_lossy().to_string();

    let path_u16: Vec<u16> = OsStr::new(&base)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let mut data = WIN32_FIND_STREAM_DATA::default();
    let find_handle = unsafe {
        // SAFETY: path_u16 is a valid null-terminated UTF-16 string; data is
        // a valid, correctly-sized output buffer.
        FindFirstStreamW(
            PCWSTR(path_u16.as_ptr()),
            FindStreamInfoStandard,
            &mut data as *mut _ as *mut c_void,
            None,
        )
    };

    let find_handle = match find_handle {
        Ok(h) if h != INVALID_HANDLE_VALUE => h,
        _ => {
            // Not NTFS, or some other enumeration failure — treat the file
            // as single-stream rather than failing the whole operation.
            return Ok(vec![base]);
        }
    };

    let mut streams = vec![stream_open_path(&base, &data)];

    loop {
        let mut next_data = WIN32_FIND_STREAM_DATA::default();
        // SAFETY: find_handle is a valid search handle from FindFirstStreamW above.
        let result =
            unsafe { FindNextStreamW(find_handle, &mut next_data as *mut _ as *mut c_void) };
        match result {
            Ok(()) => streams.push(stream_open_path(&base, &next_data)),
            // ERROR_HANDLE_EOF (no more streams) or any other failure — stop
            // here rather than trying to distinguish the two; worst case we
            // just stop enumerating remaining streams, we never error out.
            Err(_) => break,
        }
    }

    unsafe {
        let _ = FindClose(find_handle);
    }

    Ok(streams)
}

fn stream_open_path(base: &str, data: &WIN32_FIND_STREAM_DATA) -> String {
    let name_end = data
        .cStreamName
        .iter()
        .position(|&c| c == 0)
        .unwrap_or(data.cStreamName.len());
    let name = String::from_utf16_lossy(&data.cStreamName[..name_end]);

    if name == "::$DATA" || name.is_empty() {
        base.to_string()
    } else {
        let trimmed = name.strip_suffix(":$DATA").unwrap_or(&name);
        format!("{}{}", base, trimmed)
    }
}
