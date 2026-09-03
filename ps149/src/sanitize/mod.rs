pub mod volume_ops;
pub mod raw_io;
pub mod patterns;
pub mod pass;
pub mod initialize;

use crate::model::device::PhysicalDisk;
use patterns::SanitizeMethod;
use pass::{PassResult, SanitizeProgress};
use serde::Serialize;
use std::time::Instant;
use tracing::info;

#[derive(Debug, Serialize)]
pub struct SanitizeResult {
    pub method: SanitizeMethod,
    pub passes: Vec<PassResult>,
    pub total_duration: std::time::Duration,
}

pub fn execute_sanitization(
    disk: &PhysicalDisk,
    method: SanitizeMethod,
    progress_callback: impl Fn(SanitizeProgress),
) -> anyhow::Result<SanitizeResult> {
    let start_time = Instant::now();

    info!(
        "Device: {} | Type: {} | Capacity: {}",
        disk.model.as_deref().unwrap_or("Unknown"),
        disk.device_type,
        disk.capacity_display()
    );
    
    // CRITICAL: _guard holds the volume lock handles open.
    // If dropped early, the OS re-mounts the filesystem and raw writes hang.
    let _guard = volume_ops::lock_and_dismount_volumes(disk)?;
    let handle = raw_io::open_disk_write(disk.index, &disk.device_type)?;
    
    let total_passes = method.pass_count();
    let mut passes = Vec::new();
    
    for pass_index in 0..total_passes {
        let pattern = patterns::get_pattern(pass_index, method);
        let result = pass::write_pass(
            &handle,
            &pattern,
            disk.total_sectors,
            disk.bytes_per_sector,
            pass_index,
            total_passes,
            method,
            &disk.device_type,
            &progress_callback,
        )?;
        passes.push(result);
    }

    // Flush all buffered writes to physical media before verification
    tracing::info!("Flushing writes to physical media...");
    handle.flush()?;

    Ok(SanitizeResult {
        method,
        passes,
        total_duration: start_time.elapsed(),
    })
}

