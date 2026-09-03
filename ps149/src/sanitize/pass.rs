use crate::model::device_type::DeviceType;
use crate::sanitize::patterns::FillPattern;
use crate::sanitize::raw_io::{DiskHandle, seek_to_sector};
use serde::Serialize;
use std::time::Instant;
use tracing::{info, warn};
use windows::Win32::Storage::FileSystem::WriteFile;

#[derive(Debug, Clone, Serialize)]
pub struct PassResult {
    pub pass_index: usize,
    pub pattern_description: String,
    pub sectors_written: u64,
    pub total_sectors: u64,
    pub bytes_written: u64,
    pub duration: std::time::Duration,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct SanitizeProgress {
    pub pass_index: usize,
    pub total_passes: usize,
    pub sectors_done: u64,
    pub work_completed_sectors: u64, // Actual sectors read/written
}

/// Returns optimal write buffer size tuned per device class.
/// - Flash drives: 1 MB (prevents Windows dirty-page stall at ~50% RAM)
/// - HDDs: 8 MB (fewer syscalls, mechanical heads stay in sequential mode)
/// - SSDs/NVMe/others: 4 MB (good balance for NAND controllers)
fn optimal_buffer_size(device_type: &DeviceType) -> u32 {
    match device_type {
        DeviceType::UsbFlashDrive | DeviceType::SdCard | DeviceType::Emmc => 1_048_576, // 1 MB
        DeviceType::InternalHdd | DeviceType::ExternalHdd => 8_388_608,                  // 8 MB
        _ => 4_194_304,                                                                   // 4 MB
    }
}

pub fn write_pass(
    handle: &DiskHandle,
    pattern: &FillPattern,
    total_sectors: u64,
    bytes_per_sector: u32,
    pass_index: usize,
    total_passes: usize,
    method: crate::sanitize::patterns::SanitizeMethod,
    device_type: &DeviceType,
    progress_callback: &impl Fn(SanitizeProgress),
) -> anyhow::Result<PassResult> {
    let start_time = Instant::now();
    let buf_size = optimal_buffer_size(device_type);
    let sectors_per_chunk = (buf_size / bytes_per_sector) as u64;

    info!(
        "I/O engine: {} MB buffer (tuned for {})",
        buf_size / 1_048_576,
        device_type
    );

    let mut buf = vec![0u8; buf_size as usize];

    let is_zero_fill = matches!(pattern, FillPattern::Fixed(0));
    let is_random = matches!(pattern, FillPattern::Random);

    // Fill buffer once at the start for all non-zero patterns
    if !is_zero_fill {
        crate::sanitize::patterns::fill_buffer(&mut buf, pattern);
    }

    let pattern_desc = match pattern {
        FillPattern::Fixed(val) => format!("Fixed(0x{:02X})", val),
        FillPattern::Random => "Random".to_string(),
        FillPattern::ThreeByteRepeating(a, b, c) => format!("Repeating(0x{:02X},0x{:02X},0x{:02X})", a, b, c),
    };

    info!(
        "Starting pass {}/{} with pattern {}",
        pass_index + 1,
        total_passes,
        pattern_desc
    );

    // Seek to start ONCE — then write sequentially without seeking.
    // WriteFile advances the file pointer automatically.
    seek_to_sector(handle, 0, bytes_per_sector)?;

    let mut sectors_written: u64 = 0;
    let mut bytes_written: u64 = 0;
    let mut errors = Vec::new();
    let mut current_sector: u64 = 0;

    let is_fast_wipe = matches!(method, crate::sanitize::patterns::SanitizeMethod::FastWipe);
    let is_smart_secure = matches!(method, crate::sanitize::patterns::SanitizeMethod::SmartSecure);
    let wipe_margin_sectors = (16 * 1024 * 1024) / bytes_per_sector as u64; // 16 MB (FastWipe)
    let threshold_end_sectors = total_sectors.saturating_sub(wipe_margin_sectors);

    if is_smart_secure {
        // SmartSecure: zone-based write strategy (shared zone definition)
        let bps = bytes_per_sector as u64;
        let zones = crate::sanitize::patterns::smart_secure_zones(total_sectors, bytes_per_sector);

        for (zone_start, zone_count) in &zones {
            seek_to_sector(handle, *zone_start, bytes_per_sector)?;
            let mut written_in_zone: u64 = 0;

            while written_in_zone < *zone_count {
                let remaining = *zone_count - written_in_zone;
                let sectors_to_write = std::cmp::min(sectors_per_chunk, remaining);
                let bytes_to_write = (sectors_to_write * bps) as usize;

                if is_random {
                    crate::sanitize::patterns::fill_buffer(&mut buf[..bytes_to_write], pattern);
                }

                let mut written = 0u32;
                let result = unsafe {
                    WriteFile(handle.as_raw(), Some(&buf[..bytes_to_write]), Some(&mut written), None)
                };

                match result {
                    Ok(()) => {
                        sectors_written += sectors_to_write;
                        bytes_written += written as u64;
                    }
                    Err(e) => {
                        let err_msg = format!("Failed to write at sector {}: {}", zone_start + written_in_zone, e);
                        warn!("{}", err_msg);
                        errors.push(err_msg);
                    }
                }

                written_in_zone += sectors_to_write;

                progress_callback(SanitizeProgress {
                    pass_index,
                    total_passes,
                    sectors_done: *zone_start + written_in_zone,
                    work_completed_sectors: sectors_written,
                });
            }
        }
    } else {
        // Standard sequential write (used by all other methods including FastWipe)
        while current_sector < total_sectors {
            let remaining = total_sectors - current_sector;
            let sectors_to_write = std::cmp::min(sectors_per_chunk, remaining);
            let bytes_to_write = (sectors_to_write * bytes_per_sector as u64) as usize;

            if is_random {
                crate::sanitize::patterns::fill_buffer(&mut buf[..bytes_to_write], pattern);
            }

            let mut written = 0u32;
            let result = unsafe {
                WriteFile(handle.as_raw(), Some(&buf[..bytes_to_write]), Some(&mut written), None)
            };

            match result {
                Ok(()) => {
                    sectors_written += sectors_to_write;
                    bytes_written += written as u64;
                }
                Err(e) => {
                    let err_msg = format!("Failed to write at sector {}: {}", current_sector, e);
                    warn!("{}", err_msg);
                    errors.push(err_msg);
                }
            }

            current_sector += sectors_to_write;

            if is_fast_wipe && current_sector >= wipe_margin_sectors && current_sector < threshold_end_sectors {
                current_sector = threshold_end_sectors;
                seek_to_sector(handle, current_sector, bytes_per_sector)?;
            }

            progress_callback(SanitizeProgress {
                pass_index,
                total_passes,
                sectors_done: current_sector,
                work_completed_sectors: sectors_written,
            });
        }
    }

    Ok(PassResult {
        pass_index,
        pattern_description: pattern_desc,
        sectors_written,
        total_sectors,
        bytes_written,
        duration: start_time.elapsed(),
        errors,
    })
}
