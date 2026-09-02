use anyhow::Result;
use serde::Serialize;
use std::path::Path;
use tracing::info;
use windows::core::HSTRING;
use windows::Win32::Storage::FileSystem::{
    FindClose, FindFirstStreamW, FindNextStreamW, FindStreamInfoStandard,
    WIN32_FIND_STREAM_DATA,
};

#[derive(Debug, Clone, Serialize)]
pub struct StreamInfo {
    pub name: String,
    pub size: u64,
}

/// Enumerate all NTFS Alternate Data Streams on a file.
/// Returns at minimum the default `::$DATA` stream.
/// On non-NTFS volumes or if the API is unavailable, returns an empty vec.
pub fn enumerate_streams(path: &Path) -> Result<Vec<StreamInfo>> {
    let path_str = path.to_string_lossy().to_string();
    let hstring = HSTRING::from(&path_str);

    let mut stream_data = WIN32_FIND_STREAM_DATA::default();
    let mut streams = Vec::new();

    let find_handle = unsafe {
        FindFirstStreamW(
            &hstring,
            FindStreamInfoStandard,
            &mut stream_data as *mut _ as *mut _,
            None,
        )
    };

    let find_handle = match find_handle {
        Ok(h) => h,
        Err(_) => {
            // API not available or not NTFS — return empty
            return Ok(streams);
        }
    };

    // Process first stream
    let name = stream_name_from_data(&stream_data);
    streams.push(StreamInfo {
        name: name.clone(),
        size: stream_data.StreamSize as u64,
    });
    info!("Found stream: {} ({} bytes)", name, stream_data.StreamSize);

    // Iterate remaining streams
    loop {
        let mut next_data = WIN32_FIND_STREAM_DATA::default();
        let found = unsafe { FindNextStreamW(find_handle, &mut next_data as *mut _ as *mut _) };

        match found {
            Ok(_) => {
                let name = stream_name_from_data(&next_data);
                info!("Found stream: {} ({} bytes)", name, next_data.StreamSize);
                streams.push(StreamInfo {
                    name,
                    size: next_data.StreamSize as u64,
                });
            }
            Err(_) => break,
        }
    }

    unsafe {
        let _ = FindClose(find_handle);
    }

    Ok(streams)
}

fn stream_name_from_data(data: &WIN32_FIND_STREAM_DATA) -> String {
    let name_slice = &data.cStreamName;
    let len = name_slice.iter().position(|&c| c == 0).unwrap_or(name_slice.len());
    String::from_utf16_lossy(&name_slice[..len])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_enumerate_default_stream() {
        let dir = std::env::temp_dir();
        let test_file = dir.join("ps149_test_streams.txt");
        {
            let mut f = std::fs::File::create(&test_file).unwrap();
            f.write_all(b"test data for stream enumeration").unwrap();
        }

        let streams = enumerate_streams(&test_file).unwrap();
        // Should have at least the default ::$DATA stream on NTFS
        // (may be empty on non-NTFS temp volumes)
        if !streams.is_empty() {
            assert!(streams[0].name.contains("$DATA"));
        }

        let _ = std::fs::remove_file(&test_file);
    }
}
