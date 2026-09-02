use anyhow::{Context, Result};
use std::path::Path;
use tracing::info;
use windows::core::HSTRING;
use windows::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE, HANDLE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, GetFileSizeEx, SetFilePointerEx, WriteFile, FlushFileBuffers,
    FILE_BEGIN, FILE_FLAGS_AND_ATTRIBUTES, FILE_FLAG_WRITE_THROUGH,
    FILE_SHARE_NONE, OPEN_EXISTING,
};

/// Wipe the slack space at the end of a file.
///
/// On NTFS, files are allocated in clusters (typically 4096 bytes).
/// If a file is 5000 bytes, it occupies 2 clusters (8192 bytes), and
/// the 3192 bytes between 5000-8192 contain stale data from whatever
/// was previously stored in those clusters. This function zeros that gap.
pub fn wipe_file_slack(path: &Path) -> Result<u64> {
    let path_str = path.to_string_lossy().to_string();
    let hstring = HSTRING::from(&path_str);

    let handle = unsafe {
        CreateFileW(
            &hstring,
            GENERIC_WRITE.0 | GENERIC_READ.0,
            FILE_SHARE_NONE,
            None,
            OPEN_EXISTING,
            FILE_FLAGS_AND_ATTRIBUTES(FILE_FLAG_WRITE_THROUGH.0),
            None,
        )
    }
    .with_context(|| format!("Failed to open {:?} for slack wipe", path))?;

    let _guard = HandleGuard(handle);

    // Get logical file size
    let file_size = unsafe {
        let mut size: i64 = 0;
        GetFileSizeEx(handle, &mut size)?;
        size as u64
    };

    if file_size == 0 {
        return Ok(0);
    }

    // Determine cluster size (default NTFS = 4096)
    let cluster_size = get_cluster_size_for_file(path).unwrap_or(4096);

    // Calculate slack: gap from EOF to next cluster boundary
    let remainder = file_size % cluster_size;
    if remainder == 0 {
        // File perfectly fills its clusters — no slack
        return Ok(0);
    }

    let slack_size = cluster_size - remainder;

    // Seek to end of logical file
    unsafe {
        SetFilePointerEx(handle, file_size as i64, None, FILE_BEGIN)?;
    }

    // Write zeros to fill up to cluster boundary
    let zeros = vec![0u8; slack_size as usize];
    let mut written: u32 = 0;
    unsafe {
        WriteFile(handle, Some(&zeros), Some(&mut written), None)?;
        FlushFileBuffers(handle)?;
    }

    info!(
        "Wiped {} bytes of slack space for {:?} (file_size={}, cluster={})",
        written, path, file_size, cluster_size
    );

    Ok(written as u64)
}

struct HandleGuard(HANDLE);
impl Drop for HandleGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = windows::Win32::Foundation::CloseHandle(self.0);
        }
    }
}

/// Try to determine the cluster size from the volume containing the file.
/// Falls back to 4096 (NTFS default) on failure.
fn get_cluster_size_for_file(path: &Path) -> Option<u64> {
    // Get the volume root (e.g., "C:\")
    let path_str = path.to_string_lossy();
    if path_str.len() < 3 {
        return None;
    }

    let volume_root = format!("{}\\", &path_str[..2]);
    let hstring = HSTRING::from(&volume_root);

    use windows::Win32::Storage::FileSystem::GetDiskFreeSpaceW;
    let mut sectors_per_cluster: u32 = 0;
    let mut bytes_per_sector: u32 = 0;
    let mut free_clusters: u32 = 0;
    let mut total_clusters: u32 = 0;

    let ok = unsafe {
        GetDiskFreeSpaceW(
            &hstring,
            Some(&mut sectors_per_cluster),
            Some(&mut bytes_per_sector),
            Some(&mut free_clusters),
            Some(&mut total_clusters),
        )
    };

    match ok {
        Ok(_) => {
            let cluster_size = (sectors_per_cluster as u64) * (bytes_per_sector as u64);
            info!("Volume {} cluster size: {} bytes", volume_root, cluster_size);
            Some(cluster_size)
        }
        Err(e) => {
            info!("GetDiskFreeSpaceW failed for {}: {}", volume_root, e);
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_cluster_size_detection() {
        let temp = std::env::temp_dir().join("ps149_slack_test.txt");
        {
            let mut f = std::fs::File::create(&temp).unwrap();
            f.write_all(b"hello").unwrap();
        }

        let cs = get_cluster_size_for_file(&temp);
        // Should be some power of 2 (512, 4096, etc.)
        if let Some(size) = cs {
            assert!(size >= 512 && size.is_power_of_two());
        }

        let _ = std::fs::remove_file(&temp);
    }
}
