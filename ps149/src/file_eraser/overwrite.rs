use crate::sanitize::patterns::{self, FillPattern, SanitizeMethod};
use anyhow::{Context, Result};
use std::path::Path;
use tracing::info;
use windows::core::HSTRING;
use windows::Win32::Foundation::{CloseHandle, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FlushFileBuffers, GetFileSizeEx, SetEndOfFile, SetFilePointerEx, WriteFile,
    FILE_BEGIN, FILE_FLAGS_AND_ATTRIBUTES, FILE_FLAG_WRITE_THROUGH, FILE_SHARE_NONE,
    OPEN_EXISTING,
};

struct FileHandle(HANDLE);
impl Drop for FileHandle {
    fn drop(&mut self) {
        unsafe {
            if self.0 != INVALID_HANDLE_VALUE {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

/// Overwrite a file's contents with sanitization patterns.
/// Handles multi-pass overwriting based on the selected method.
pub fn overwrite_file(path: &Path, method: SanitizeMethod) -> Result<u64> {
    let path_str = path.to_string_lossy().to_string();
    let hstring = HSTRING::from(&path_str);

    let handle = unsafe {
        CreateFileW(
            &hstring,
            GENERIC_WRITE.0,
            FILE_SHARE_NONE,
            None,
            OPEN_EXISTING,
            FILE_FLAGS_AND_ATTRIBUTES(FILE_FLAG_WRITE_THROUGH.0),
            None,
        )
    }
    .with_context(|| format!("Failed to open file for writing: {:?}", path))?;

    let fh = FileHandle(handle);

    let file_size = unsafe {
        let mut size: i64 = 0;
        GetFileSizeEx(fh.0, &mut size)?;
        size as u64
    };

    if file_size == 0 {
        info!("File {:?} is empty, skipping overwrite", path);
        return Ok(0);
    }

    let total_passes = method.pass_count();
    let buf_size: usize = 1_048_576; // 1 MB chunks
    let mut buf = vec![0u8; buf_size];
    let mut total_written: u64 = 0;

    for pass_index in 0..total_passes {
        let pattern = patterns::get_pattern(pass_index, method);
        let is_random = matches!(pattern, FillPattern::Random);

        // Fill buffer with pattern
        patterns::fill_buffer(&mut buf, &pattern);

        // Seek to start
        unsafe {
            SetFilePointerEx(fh.0, 0, None, FILE_BEGIN)?;
        }

        let mut remaining = file_size;
        while remaining > 0 {
            let chunk = remaining.min(buf_size as u64) as usize;

            // Refill for random on every chunk
            if is_random {
                patterns::fill_buffer(&mut buf[..chunk], &pattern);
            }

            let mut written: u32 = 0;
            unsafe {
                WriteFile(fh.0, Some(&buf[..chunk]), Some(&mut written), None)?;
            }
            remaining -= written as u64;
            total_written += written as u64;
        }

        // Flush after each pass
        unsafe {
            FlushFileBuffers(fh.0)?;
        }
    }

    // Truncate the file to zero length after overwriting
    unsafe {
        SetFilePointerEx(fh.0, 0, None, FILE_BEGIN)?;
        SetEndOfFile(fh.0)?;
    }

    info!(
        "Overwritten {:?}: {} bytes × {} passes = {} bytes total",
        path, file_size, total_passes, total_written
    );

    Ok(total_written)
}

/// Push resident file data out of MFT by padding to > 1024 bytes.
/// Small NTFS files (< ~700 bytes) are stored directly in the MFT record.
/// Writing padding forces NTFS to allocate external clusters, pushing
/// the data out of the MFT where it can be properly overwritten.
#[allow(dead_code)]
pub fn force_non_resident(path: &Path) -> Result<()> {
    let meta = std::fs::metadata(path)?;
    if meta.len() < 1024 {
        let path_str = path.to_string_lossy().to_string();
        let hstring = HSTRING::from(&path_str);
        let handle = unsafe {
            CreateFileW(
                &hstring,
                GENERIC_WRITE.0,
                FILE_SHARE_NONE,
                None,
                OPEN_EXISTING,
                FILE_FLAGS_AND_ATTRIBUTES(FILE_FLAG_WRITE_THROUGH.0),
                None,
            )
        }?;
        let fh = FileHandle(handle);

        // Write 2KB of padding to force non-resident allocation
        let padding = vec![0x41u8; 2048];
        let mut written: u32 = 0;
        unsafe {
            WriteFile(fh.0, Some(&padding), Some(&mut written), None)?;
            FlushFileBuffers(fh.0)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_overwrite_temp_file() {
        let dir = std::env::temp_dir();
        let test_file = dir.join("ps149_test_overwrite.bin");

        // Create file with known content
        {
            let mut f = std::fs::File::create(&test_file).unwrap();
            f.write_all(b"SECRET DATA THAT MUST BE DESTROYED").unwrap();
        }

        // Overwrite with zero fill
        let result = overwrite_file(&test_file, SanitizeMethod::NistClear);
        assert!(result.is_ok());

        // File should be truncated to 0
        let meta = std::fs::metadata(&test_file).unwrap();
        assert_eq!(meta.len(), 0);

        let _ = std::fs::remove_file(&test_file);
    }
}
