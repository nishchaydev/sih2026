pub mod readback;
pub mod hash;
pub mod entropy;
pub mod sampling;

use crate::model::device::PhysicalDisk;
use crate::sanitize::patterns::FillPattern;
use crate::sanitize::pass::SanitizeProgress;

pub fn verify_disk(
    disk: &PhysicalDisk,
    expected_pattern: &FillPattern,
    method: crate::sanitize::patterns::SanitizeMethod,
    progress_callback: impl Fn(SanitizeProgress),
) -> anyhow::Result<readback::VerifyResult> {
    readback::verify_pass(
        disk.index,
        expected_pattern,
        disk.total_sectors,
        disk.bytes_per_sector,
        method,
        &progress_callback,
    )
}
