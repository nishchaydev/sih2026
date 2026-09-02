use crate::sanitize::pass::SanitizeProgress;
use crate::sanitize::patterns::FillPattern;
use crate::sanitize::raw_io::{open_disk_read, seek_to_sector};
use crate::verify::hash::DiskHasher;
use serde::Serialize;
use std::time::Instant;
use tracing::{info, warn};
use windows::Win32::Storage::FileSystem::ReadFile;

#[derive(Debug, Clone, Serialize)]
pub struct VerifyResult {
    pub total_sectors: u64,
    pub sectors_verified: u64,
    pub sectors_failed: u64,
    pub first_failure_sector: Option<u64>,
    pub passed: bool,
    pub duration: std::time::Duration,
    pub disk_hash: String,
}

pub fn verify_pass(
    disk_index: u32,
    expected_pattern: &FillPattern,
    total_sectors: u64,
    bytes_per_sector: u32,
    method: crate::sanitize::patterns::SanitizeMethod,
    progress_callback: &impl Fn(SanitizeProgress),
) -> anyhow::Result<VerifyResult> {
    let is_smart_secure = matches!(method, crate::sanitize::patterns::SanitizeMethod::SmartSecure);

    if is_smart_secure {
        verify_zones(disk_index, expected_pattern, total_sectors, bytes_per_sector, progress_callback)
    } else {
        verify_sequential(disk_index, expected_pattern, total_sectors, bytes_per_sector, method, progress_callback)
    }
}

/// Zone-based verification for SmartSecure — only reads back the zones that were written.
fn verify_zones(
    disk_index: u32,
    expected_pattern: &FillPattern,
    total_sectors: u64,
    bytes_per_sector: u32,
    progress_callback: &impl Fn(SanitizeProgress),
) -> anyhow::Result<VerifyResult> {
    let start_time = Instant::now();
    let buf_size: u32 = 1_048_576; // 1 MB — match SmartSecure write buffer
    let sectors_per_chunk = (buf_size / bytes_per_sector) as u64;

    let handle = open_disk_read(disk_index)?;

    let mut read_buf = vec![0u8; buf_size as usize];
    let mut expected_buf = vec![0u8; buf_size as usize];
    crate::sanitize::patterns::fill_buffer(&mut expected_buf, expected_pattern);

    let is_random = matches!(expected_pattern, FillPattern::Random);

    let zones = crate::sanitize::patterns::smart_secure_zones(total_sectors, bytes_per_sector);
    let zone_total_sectors: u64 = zones.iter().map(|(_, count)| *count).sum();

    info!("Starting zone-based verification ({} zones, {} sectors)", zones.len(), zone_total_sectors);

    let mut sectors_failed: u64 = 0;
    let mut sectors_verified: u64 = 0;
    let mut first_failure_sector: Option<u64> = None;
    let mut hasher = DiskHasher::new();

    for (zone_start, zone_count) in &zones {
        seek_to_sector(&handle, *zone_start, bytes_per_sector)?;
        let mut read_in_zone: u64 = 0;

        while read_in_zone < *zone_count {
            let remaining = *zone_count - read_in_zone;
            let sectors_to_read = std::cmp::min(sectors_per_chunk, remaining);
            let bytes_to_read = (sectors_to_read * bytes_per_sector as u64) as usize;

            if is_random {
                crate::sanitize::patterns::fill_buffer(&mut expected_buf[..bytes_to_read], expected_pattern);
            }

            let mut bytes_read = 0u32;
            let result = unsafe {
                ReadFile(
                    handle.as_raw(),
                    Some(&mut read_buf[..bytes_to_read]),
                    Some(&mut bytes_read),
                    None,
                )
            };

            match result {
                Ok(()) => {
                    hasher.update(&read_buf[..bytes_read as usize]);

                    if !is_random {
                        if read_buf[..bytes_to_read] != expected_buf[..bytes_to_read] {
                            for i in 0..sectors_to_read {
                                let offset = (i * bytes_per_sector as u64) as usize;
                                let end = offset + bytes_per_sector as usize;
                                if read_buf[offset..end] != expected_buf[offset..end] {
                                    sectors_failed += 1;
                                    if first_failure_sector.is_none() {
                                        first_failure_sector = Some(zone_start + read_in_zone + i);
                                    }
                                } else {
                                    sectors_verified += 1;
                                }
                            }
                        } else {
                            sectors_verified += sectors_to_read;
                        }
                    } else {
                        sectors_verified += sectors_to_read;
                    }
                }
                Err(e) => {
                    warn!("Failed to read at sector {}: {}", zone_start + read_in_zone, e);
                    sectors_failed += sectors_to_read;
                    if first_failure_sector.is_none() {
                        first_failure_sector = Some(zone_start + read_in_zone);
                    }
                }
            }

            read_in_zone += sectors_to_read;

            progress_callback(SanitizeProgress {
                pass_index: 0,
                total_passes: 1,
                sectors_done: sectors_verified + sectors_failed,
                work_completed_sectors: sectors_verified + sectors_failed,
            });
        }
    }

    Ok(VerifyResult {
        total_sectors: zone_total_sectors,
        sectors_verified,
        sectors_failed,
        first_failure_sector,
        passed: sectors_failed == 0,
        duration: start_time.elapsed(),
        disk_hash: hasher.finalize(),
    })
}

/// Sequential verification for full-disk methods (and FastWipe with margin skipping).
fn verify_sequential(
    disk_index: u32,
    expected_pattern: &FillPattern,
    total_sectors: u64,
    bytes_per_sector: u32,
    method: crate::sanitize::patterns::SanitizeMethod,
    progress_callback: &impl Fn(SanitizeProgress),
) -> anyhow::Result<VerifyResult> {
    let start_time = Instant::now();
    let buf_size: u32 = 16_777_216; // 16 MB
    let sectors_per_chunk = (buf_size / bytes_per_sector) as u64;

    let handle = open_disk_read(disk_index)?;

    let mut read_buf = vec![0u8; buf_size as usize];
    let mut expected_buf = vec![0u8; buf_size as usize];

    crate::sanitize::patterns::fill_buffer(&mut expected_buf, expected_pattern);

    let is_random = matches!(expected_pattern, FillPattern::Random);

    info!("Starting verification pass");

    // Seek once, then read sequentially — no per-chunk seek
    seek_to_sector(&handle, 0, bytes_per_sector)?;

    let mut current_sector: u64 = 0;
    let mut sectors_failed: u64 = 0;
    let mut sectors_verified: u64 = 0;
    let mut first_failure_sector: Option<u64> = None;
    let mut hasher = DiskHasher::new();

    let is_fast_wipe = matches!(method, crate::sanitize::patterns::SanitizeMethod::FastWipe);
    let wipe_margin_sectors = (16 * 1024 * 1024) / bytes_per_sector as u64; // 16 MB at start/end
    let threshold_end_sectors = total_sectors.saturating_sub(wipe_margin_sectors);

    let mut total_sectors_processed: u64 = 0;

    while current_sector < total_sectors {
        let remaining = total_sectors - current_sector;
        let sectors_to_read = std::cmp::min(sectors_per_chunk, remaining);
        let bytes_to_read = (sectors_to_read * bytes_per_sector as u64) as usize;

        // If Random, re-generate the expected chunk for comparison
        if is_random {
            crate::sanitize::patterns::fill_buffer(&mut expected_buf[..bytes_to_read], expected_pattern);
        }

        // Direct read — no per-chunk seek
        let mut bytes_read = 0u32;
        let result = unsafe {
            ReadFile(
                handle.as_raw(),
                Some(&mut read_buf[..bytes_to_read]),
                Some(&mut bytes_read),
                None,
            )
        };

        match result {
            Ok(()) => {
                hasher.update(&read_buf[..bytes_read as usize]);

                let check_mismatch = if is_fast_wipe {
                    current_sector < wipe_margin_sectors || current_sector >= threshold_end_sectors
                } else {
                    true
                };

                if !is_random && check_mismatch {
                    // Compare chunk-level first for speed, then drill into sectors on mismatch
                    if read_buf[..bytes_to_read] != expected_buf[..bytes_to_read] {
                        // Mismatch — find which sectors failed
                        for i in 0..sectors_to_read {
                            let offset = (i * bytes_per_sector as u64) as usize;
                            let end = offset + bytes_per_sector as usize;
                            if read_buf[offset..end] != expected_buf[offset..end] {
                                sectors_failed += 1;
                                if first_failure_sector.is_none() {
                                    first_failure_sector = Some(current_sector + i);
                                }
                            } else {
                                sectors_verified += 1;
                            }
                        }
                    } else {
                        // Entire 16 MB chunk matches — skip sector-by-sector
                        sectors_verified += sectors_to_read;
                    }
                } else {
                    sectors_verified += sectors_to_read;
                }
            }
            Err(e) => {
                warn!("Failed to read at sector {}: {}", current_sector, e);
                sectors_failed += sectors_to_read;
                if first_failure_sector.is_none() {
                    first_failure_sector = Some(current_sector);
                }
            }
        }

        current_sector += sectors_to_read;
        total_sectors_processed += sectors_to_read;

        if is_fast_wipe && current_sector >= wipe_margin_sectors && current_sector < threshold_end_sectors {
            current_sector = threshold_end_sectors;
            seek_to_sector(&handle, current_sector, bytes_per_sector)?;
        }

        progress_callback(SanitizeProgress {
            pass_index: 0,
            total_passes: 1,
            sectors_done: current_sector,
            work_completed_sectors: total_sectors_processed,
        });
    }

    Ok(VerifyResult {
        total_sectors,
        sectors_verified,
        sectors_failed,
        first_failure_sector,
        passed: sectors_failed == 0,
        duration: start_time.elapsed(),
        disk_hash: hasher.finalize(),
    })
}
