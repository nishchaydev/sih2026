use anyhow::{Context, Result};
use serde::Serialize;
use std::path::Path;
use tracing::info;
use windows::core::HSTRING;
use windows::Win32::Foundation::{FILETIME, GENERIC_WRITE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, DeleteFileW, MoveFileW, SetFileAttributesW, SetFileTime,
    FILE_ATTRIBUTE_NORMAL, FILE_FLAGS_AND_ATTRIBUTES, FILE_SHARE_NONE, OPEN_EXISTING,
};

#[derive(Debug, Clone, Serialize)]
pub struct MetadataCleanseResult {
    pub timestamps_zeroed: bool,
    pub attributes_cleared: bool,
    pub filename_obfuscated: bool,
    pub rename_count: usize,
    pub deleted: bool,
}

/// SDelete-inspired metadata cleansing pipeline:
/// 1. Clear file attributes (remove read-only, hidden, system)
/// 2. Zero all timestamps (creation, modification, access)
/// 3. Rename file repeatedly to overwrite MFT filename entries
/// 4. Delete the file
pub fn cleanse_and_delete(path: &Path) -> Result<MetadataCleanseResult> {
    let mut result = MetadataCleanseResult {
        timestamps_zeroed: false,
        attributes_cleared: false,
        filename_obfuscated: false,
        rename_count: 0,
        deleted: false,
    };

    // Phase 1: Clear attributes
    let path_h = HSTRING::from(path.to_string_lossy().as_ref());
    match unsafe { SetFileAttributesW(&path_h, FILE_ATTRIBUTE_NORMAL) } {
        Ok(_) => result.attributes_cleared = true,
        Err(e) => info!("Could not clear attributes on {:?}: {}", path, e),
    }

    // Phase 2: Zero timestamps
    result.timestamps_zeroed = zero_timestamps(path).is_ok();

    // Phase 3: Filename obfuscation (SDelete technique)
    // Rename the file multiple times to overwrite MFT directory index entries
    let parent = path.parent().unwrap_or(Path::new("."));
    let mut current_path = path.to_path_buf();

    let rename_patterns = [
        "AAAAAAAAAA.AAA",
        "BBBBBBBBBB.BBB",
        "CCCCCCCCCC.CCC",
        "DDDDDDDDDD.DDD",
        "EEEEEEEEEE.EEE",
    ];

    for pattern in &rename_patterns {
        let new_path = parent.join(pattern);
        let old_h = HSTRING::from(current_path.to_string_lossy().as_ref());
        let new_h = HSTRING::from(new_path.to_string_lossy().as_ref());

        match unsafe { MoveFileW(&old_h, &new_h) } {
            Ok(_) => {
                result.rename_count += 1;
                current_path = new_path;
            }
            Err(e) => {
                info!("Rename {} failed: {}", pattern, e);
                break;
            }
        }
    }
    result.filename_obfuscated = result.rename_count >= 3;

    // Phase 4: Delete
    let final_h = HSTRING::from(current_path.to_string_lossy().as_ref());
    match unsafe { DeleteFileW(&final_h) } {
        Ok(_) => result.deleted = true,
        Err(e) => {
            info!("DeleteFileW failed: {}, trying std::fs", e);
            result.deleted = std::fs::remove_file(&current_path).is_ok();
        }
    }

    info!(
        "Metadata cleansed {:?}: timestamps={}, attrs={}, renames={}, deleted={}",
        path, result.timestamps_zeroed, result.attributes_cleared,
        result.rename_count, result.deleted
    );

    Ok(result)
}

fn zero_timestamps(path: &Path) -> Result<()> {
    let path_h = HSTRING::from(path.to_string_lossy().as_ref());
    let handle = unsafe {
        CreateFileW(
            &path_h,
            GENERIC_WRITE.0,
            FILE_SHARE_NONE,
            None,
            OPEN_EXISTING,
            FILE_FLAGS_AND_ATTRIBUTES(0),
            None,
        )
    }
    .with_context(|| format!("Failed to open {:?} for timestamp zeroing", path))?;

    // Windows FILETIME epoch: 1601-01-01. Set to a very early time.
    let zero_time = FILETIME {
        dwLowDateTime: 1,
        dwHighDateTime: 0,
    };

    unsafe {
        SetFileTime(
            handle,
            Some(&zero_time), // creation
            Some(&zero_time), // access
            Some(&zero_time), // modification
        )?;
        let _ = windows::Win32::Foundation::CloseHandle(handle);
    }

    Ok(())
}

/// Clean up an empty directory by obfuscating its name and removing it.
pub fn cleanse_and_delete_dir(path: &Path) -> Result<()> {
    let parent = path.parent().unwrap_or(Path::new("."));
    let mut current = path.to_path_buf();

    // Rename directory to obscure name
    let obfuscated = parent.join("ZZZZZZZZZZ");
    let old_h = HSTRING::from(current.to_string_lossy().as_ref());
    let new_h = HSTRING::from(obfuscated.to_string_lossy().as_ref());
    if unsafe { MoveFileW(&old_h, &new_h) }.is_ok() {
        current = obfuscated;
    }

    std::fs::remove_dir(&current)
        .with_context(|| format!("Failed to remove directory {:?}", current))?;

    Ok(())
}
