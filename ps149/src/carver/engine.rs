/// Core file carving engine — scans raw disk sectors or image files
/// to detect and extract deleted/hidden files using magic byte signatures.

use crate::carver::signatures::{self, FileCategory, FileSignature};
use anyhow::{Context, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::time::Instant;
use tracing::{info, warn};

/// A single carved (recovered) file.
#[derive(Debug, Clone, Serialize)]
pub struct CarvedFile {
    pub file_type: String,
    pub extension: String,
    pub category: FileCategory,
    pub offset: u64,
    pub size: u64,
    pub sha256: String,
    pub output_path: String,
    pub confidence: f64,
}

/// Summary of an entire carving operation.
#[derive(Debug, Clone, Serialize)]
pub struct CarvingResult {
    pub source: String,
    pub total_bytes_scanned: u64,
    pub files_found: usize,
    pub carved_files: Vec<CarvedFile>,
    pub duration_secs: f64,
    pub categories: std::collections::HashMap<String, usize>,
}

/// Progress callback data.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct CarvingProgress {
    pub bytes_scanned: u64,
    pub total_bytes: u64,
    pub files_found: usize,
}

/// Carve files from a raw disk, partition, or image file.
///
/// `source_path` can be:
/// - A raw disk path: `\\.\PhysicalDrive1`
/// - A volume: `\\.\D:`
/// - A disk image file: `C:\evidence\disk.dd`
///
/// `output_dir` is where recovered files are saved.
pub fn carve_from_source(
    source_path: &str,
    output_dir: &Path,
    total_size: Option<u64>,
    progress_callback: impl Fn(CarvingProgress),
) -> Result<CarvingResult> {
    let start = Instant::now();
    let signatures = signatures::all_signatures();

    // Create output directory structure
    fs::create_dir_all(output_dir)
        .with_context(|| format!("Failed to create output directory: {:?}", output_dir))?;

    // Open source for reading
    let mut reader = open_source(source_path)?;
    let source_size = total_size.unwrap_or_else(|| {
        reader.seek(SeekFrom::End(0)).unwrap_or(0)
    });
    reader.seek(SeekFrom::Start(0))?;

    info!(
        "Starting file carving: source={}, size={} bytes, signatures={}",
        source_path,
        source_size,
        signatures.len()
    );

    let scan_chunk = 4096u64; // Read 4KB at a time (sector-aligned)
    let mut position: u64 = 0;
    let mut header_buf = vec![0u8; 4096];
    let mut carved_files: Vec<CarvedFile> = Vec::new();
    let mut file_counter: usize = 0;

    while position < source_size {
        let bytes_read = reader.read(&mut header_buf)?;
        if bytes_read == 0 {
            break;
        }

        // Check if this sector contains a known file header
        if let Some(sig) = signatures::match_header(&header_buf[..bytes_read], &signatures) {
            info!(
                "Found {} header at offset 0x{:X} ({:.2} MB)",
                sig.name,
                position,
                position as f64 / (1024.0 * 1024.0)
            );

            // Try to extract the complete file
            match extract_file(&mut reader, sig, position, source_size, output_dir, file_counter) {
                Ok(carved) => {
                    info!(
                        "Carved: {} ({} bytes, confidence: {:.0}%)",
                        carved.output_path, carved.size, carved.confidence * 100.0
                    );
                    carved_files.push(carved);
                    file_counter += 1;
                }
                Err(e) => {
                    warn!("Failed to extract {} at offset 0x{:X}: {}", sig.name, position, e);
                }
            }

            // Seek back to continue scanning after the header
            // (we might have read ahead during extraction)
            reader.seek(SeekFrom::Start(position + scan_chunk))?;
        }

        position += scan_chunk;

        // Progress callback every 10 MB
        if position % (10 * 1024 * 1024) == 0 {
            progress_callback(CarvingProgress {
                bytes_scanned: position,
                total_bytes: source_size,
                files_found: carved_files.len(),
            });
        }
    }

    // Build category counts
    let mut categories = std::collections::HashMap::new();
    for cf in &carved_files {
        *categories.entry(cf.category.to_string()).or_insert(0) += 1;
    }

    let result = CarvingResult {
        source: source_path.to_string(),
        total_bytes_scanned: position,
        files_found: carved_files.len(),
        carved_files,
        duration_secs: start.elapsed().as_secs_f64(),
        categories,
    };

    info!(
        "Carving complete: {} files found in {:.1}s",
        result.files_found, result.duration_secs
    );

    Ok(result)
}

/// Extract a single file starting at `offset` using the signature's footer
/// or max_size constraint.
fn extract_file(
    reader: &mut Box<dyn ReadSeek>,
    sig: &FileSignature,
    offset: u64,
    source_size: u64,
    output_dir: &Path,
    file_index: usize,
) -> Result<CarvedFile> {
    reader.seek(SeekFrom::Start(offset))?;

    // Determine how much data to read (bounded by max_size and source_size)
    let max_read = std::cmp::min(sig.max_size, source_size - offset);
    let read_chunk = 64 * 1024; // 64 KB read chunks for extraction
    let mut file_data: Vec<u8> = Vec::with_capacity(std::cmp::min(max_read as usize, 10 * 1024 * 1024));
    let mut total_read: u64 = 0;

    loop {
        if total_read >= max_read {
            break;
        }
        let to_read = std::cmp::min(read_chunk, (max_read - total_read) as usize);
        let mut chunk = vec![0u8; to_read];
        let bytes_read = reader.read(&mut chunk)?;
        if bytes_read == 0 {
            break;
        }
        file_data.extend_from_slice(&chunk[..bytes_read]);
        total_read += bytes_read as u64;

        // If we have a footer, check if we've found it
        if let Some(footer) = sig.footer {
            if let Some(end_pos) = signatures::find_footer(&file_data, footer) {
                file_data.truncate(end_pos);
                break;
            }
        }

        // Cap in-memory buffer at 100 MB to prevent OOM on huge files
        if file_data.len() > 100 * 1024 * 1024 {
            break;
        }
    }

    // Validate minimum size
    if (file_data.len() as u64) < sig.min_size {
        anyhow::bail!(
            "Extracted data too small ({} bytes < {} min)",
            file_data.len(),
            sig.min_size
        );
    }

    // Compute SHA-256 hash
    let mut hasher = Sha256::new();
    hasher.update(&file_data);
    let sha256 = format!("{:x}", hasher.finalize());

    // Calculate confidence score
    let confidence = calculate_confidence(sig, &file_data);

    // Save to output directory
    let category_dir = output_dir.join(sig.category.to_string().to_lowercase());
    fs::create_dir_all(&category_dir)?;

    let filename = format!("carved_{:04}_{}.{}", file_index, &sha256[..8], sig.extension);
    let output_path = category_dir.join(&filename);

    let mut output_file = fs::File::create(&output_path)?;
    output_file.write_all(&file_data)?;

    Ok(CarvedFile {
        file_type: sig.name.to_string(),
        extension: sig.extension.to_string(),
        category: sig.category,
        offset,
        size: file_data.len() as u64,
        sha256,
        output_path: output_path.to_string_lossy().to_string(),
        confidence,
    })
}

/// Calculates a confidence score (0.0 - 1.0) for a carved file.
/// Higher scores indicate more likely valid files.
fn calculate_confidence(sig: &FileSignature, data: &[u8]) -> f64 {
    let mut score: f64 = 0.5; // Base: we found the header

    // Bonus: file has valid footer
    if let Some(footer) = sig.footer {
        if data.len() >= footer.len() && &data[data.len() - footer.len()..] == footer {
            score += 0.3;
        }
    } else {
        score += 0.1; // No footer to check, slight bump
    }

    // Bonus: file size is reasonable (not suspiciously tiny or at max_size cap)
    let size = data.len() as u64;
    if size > sig.min_size * 2 && size < sig.max_size / 2 {
        score += 0.1;
    }

    // Bonus: entropy check for certain types
    if matches!(sig.category, FileCategory::Image | FileCategory::Video | FileCategory::Audio) {
        // Compressed media should have high entropy (close to 8.0)
        let entropy = calculate_shannon_entropy(data);
        if entropy > 6.0 {
            score += 0.1;
        }
    }

    score.min(1.0)
}

/// Shannon entropy of a byte buffer (0.0 = all same, 8.0 = perfectly random).
fn calculate_shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u64; 256];
    for &byte in data {
        freq[byte as usize] += 1;
    }
    let len = data.len() as f64;
    let mut entropy = 0.0;
    for &count in &freq {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

// ── Source reader abstraction ───────────────────────────────

/// Trait combining Read + Seek for polymorphic source handling.
pub trait ReadSeek: Read + Seek {}
impl<T: Read + Seek> ReadSeek for T {}

/// Opens a source for reading — handles both files and raw disk paths.
fn open_source(path: &str) -> Result<Box<dyn ReadSeek>> {
    if path.starts_with("\\\\.\\") {
        // Raw disk / volume path — use Win32 API
        open_raw_device(path)
    } else {
        // Regular file (disk image)
        let file = fs::File::open(path)
            .with_context(|| format!("Failed to open source: {}", path))?;
        Ok(Box::new(file))
    }
}

/// Opens a raw disk or volume for reading using Win32 CreateFileW.
#[cfg(windows)]
fn open_raw_device(path: &str) -> Result<Box<dyn ReadSeek>> {
    use std::os::windows::io::FromRawHandle;
    use windows::core::{HSTRING, PCWSTR};
    use windows::Win32::Foundation::GENERIC_READ;
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAGS_AND_ATTRIBUTES, FILE_FLAG_NO_BUFFERING,
        FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    };

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
        anyhow::bail!("Failed to open raw device: {}", path);
    }

    let std_handle = unsafe { std::fs::File::from_raw_handle(handle.0 as *mut std::ffi::c_void) };
    Ok(Box::new(std_handle))
}

#[cfg(not(windows))]
fn open_raw_device(path: &str) -> Result<Box<dyn ReadSeek>> {
    let file = fs::File::open(path)?;
    Ok(Box::new(file))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_carve_from_image_file() {
        // Create a temp file with an embedded JPEG
        let dir = std::env::temp_dir().join("ps149_carve_test");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let image_path = dir.join("test_image.raw");
        let output_dir = dir.join("recovered");

        // Build a fake raw image: garbage + JPEG header + data + JPEG footer + garbage
        let mut raw_data = Vec::new();
        raw_data.extend_from_slice(&[0x00; 4096]); // 4KB garbage (first sector)
        // JPEG at offset 4096
        raw_data.extend_from_slice(&[0xFF, 0xD8, 0xFF, 0xE0]); // JPEG header
        raw_data.extend_from_slice(&[0x42; 500]); // Fake JPEG data
        raw_data.extend_from_slice(&[0xFF, 0xD9]); // JPEG footer
        raw_data.extend_from_slice(&[0x00; 4096 - 506]); // Pad to sector boundary
        raw_data.extend_from_slice(&[0x00; 4096]); // More garbage

        let mut f = fs::File::create(&image_path).unwrap();
        f.write_all(&raw_data).unwrap();

        // Run carving
        let result = carve_from_source(
            image_path.to_str().unwrap(),
            &output_dir,
            Some(raw_data.len() as u64),
            |_| {},
        )
        .unwrap();

        assert!(result.files_found >= 1, "Should find at least 1 JPEG");
        assert_eq!(result.carved_files[0].extension, "jpg");
        assert!(result.carved_files[0].confidence > 0.5);

        // Cleanup
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_shannon_entropy() {
        // All zeros → entropy ~0
        let zeros = vec![0u8; 1024];
        let e = calculate_shannon_entropy(&zeros);
        assert!(e < 0.01, "All zeros should have ~0 entropy, got {}", e);

        // Random data → entropy ~8
        let mut rng_data = vec![0u8; 10000];
        for (i, byte) in rng_data.iter_mut().enumerate() {
            *byte = (i * 7 + 13) as u8; // Pseudo-spread
        }
        let e2 = calculate_shannon_entropy(&rng_data);
        assert!(e2 > 5.0, "Spread data should have high entropy, got {}", e2);
    }
}
