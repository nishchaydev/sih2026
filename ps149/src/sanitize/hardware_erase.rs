//! NVMe hardware crypto-erase — a fast alternative to pattern-overwrite for
//! internal, non-boot NVMe SSDs, issued via `IOCTL_STORAGE_REINITIALIZE_MEDIA`.
//!
//! Deliberately narrow in scope: ATA/SATA Secure Erase is not attempted here
//! because Windows's own AHCI driver stack sends `SECURITY FREEZE LOCK` at
//! init on a normal desktop session (not just a BIOS thing — there's no
//! in-OS API to undo it; it only works booted into WinPE). USB-attached
//! drives (including USB-enclosed NVMe/SSD) are also excluded — they
//! enumerate as generic USB mass storage and the bridge chip rarely forwards
//! hardware erase commands even when it forwards reads/writes. See `probe()`.

use crate::model::device::{PhysicalDisk, StorageBusType};
use crate::sanitize::{raw_io, volume_ops};
use crate::verify::entropy::{self, EntropyVerdict};
use crate::verify::hash::DiskHasher;
use crate::verify::readback::VerifyResult;
use anyhow::{Context, Result};
use std::ffi::c_void;
use std::time::{Duration, Instant};
use tracing::{info, warn};
use windows::Win32::Storage::FileSystem::ReadFile;
use windows::Win32::System::IO::DeviceIoControl;
use windows::Win32::System::Ioctl::{
    IOCTL_STORAGE_REINITIALIZE_MEDIA, STORAGE_REINITIALIZE_MEDIA, STORAGE_REINITIALIZE_MEDIA_0,
    StorageSanitizeMethodCryptoErase,
};

/// Whether hardware crypto-erase can be attempted for this disk.
#[derive(Debug, Clone)]
pub enum HwEraseCapability {
    Available,
    Unsupported(String),
}

/// Gate check — never attempt hardware erase on a disk this returns
/// `Unsupported` for; route it to the normal pattern-overwrite menu instead.
pub fn probe(disk: &PhysicalDisk) -> HwEraseCapability {
    if disk.is_boot_disk {
        return HwEraseCapability::Unsupported(
            "system/boot disk — Windows restricts hardware reinitialize to data disks".into(),
        );
    }
    match disk.bus_type {
        StorageBusType::Nvme => HwEraseCapability::Available,
        StorageBusType::Usb => HwEraseCapability::Unsupported(
            "USB-attached — the bridge chip does not forward hardware erase commands".into(),
        ),
        StorageBusType::Sata | StorageBusType::Ata => HwEraseCapability::Unsupported(
            "SATA/ATA secure erase requires booting into WinPE — not available from a normal Windows session".into(),
        ),
        _ => HwEraseCapability::Unsupported("not an internal NVMe device".into()),
    }
}

pub struct HwEraseResult {
    pub duration: Duration,
    pub capacity: u64,
}

/// Issues a hardware crypto-erase via `IOCTL_STORAGE_REINITIALIZE_MEDIA`.
///
/// This is a single blocking `DeviceIoControl` call handled entirely by the
/// drive controller/firmware — there is no pass-by-pass write loop, and
/// (unlike pattern-overwrite methods) no predictable resulting byte pattern
/// to verify against afterward. See `post_erase_spot_check` for what
/// verification looks like here instead.
pub fn execute_nvme_crypto_erase(disk: &PhysicalDisk, timeout_secs: u32) -> Result<HwEraseResult> {
    let start = Instant::now();

    // CRITICAL: keep the volume lock guard alive for the duration of the
    // IOCTL — same requirement as the pattern-overwrite path in
    // sanitize::execute_sanitization.
    let _guard = volume_ops::lock_and_dismount_volumes(disk)?;
    let handle =
        raw_io::open_disk_write(disk.index).context("Failed to open disk for hardware erase")?;

    // Attempt 1: bare IOCTL (NULL input buffer). This is the more broadly
    // supported form (Windows 10 1607+) and defaults to crypto erase on
    // current drivers/drives per Microsoft's own documentation.
    info!(
        "Issuing IOCTL_STORAGE_REINITIALIZE_MEDIA (bare) to Disk {}",
        disk.index
    );
    let mut bytes_returned: u32 = 0;
    let bare_result = unsafe {
        // SAFETY: handle is valid; no input/output buffers needed for this form.
        DeviceIoControl(
            handle.as_raw(),
            IOCTL_STORAGE_REINITIALIZE_MEDIA,
            None,
            0,
            None,
            0,
            Some(&mut bytes_returned),
            None,
        )
    };

    if let Err(e) = bare_result {
        warn!(
            "Bare IOCTL_STORAGE_REINITIALIZE_MEDIA failed: {} — retrying with explicit CryptoErase option",
            e
        );

        // Attempt 2: explicit struct requesting Crypto Erase (documented
        // back to Server 2022; client-SKU support unverified — this is the
        // fallback, not the primary path). SanitizeMethod occupies bits 0-3
        // of the packed bitfield per the ntddstor.h STORAGE_REINITIALIZE_MEDIA
        // layout.
        let sanitize_method_bits = (StorageSanitizeMethodCryptoErase.0 as u32) & 0xF;
        let input = STORAGE_REINITIALIZE_MEDIA {
            Version: std::mem::size_of::<STORAGE_REINITIALIZE_MEDIA>() as u32,
            Size: std::mem::size_of::<STORAGE_REINITIALIZE_MEDIA>() as u32,
            TimeoutInSeconds: timeout_secs,
            SanitizeOption: STORAGE_REINITIALIZE_MEDIA_0 {
                _bitfield: sanitize_method_bits,
            },
        };

        let struct_result = unsafe {
            // SAFETY: handle is valid; input is a fully-initialized, sized struct.
            DeviceIoControl(
                handle.as_raw(),
                IOCTL_STORAGE_REINITIALIZE_MEDIA,
                Some(&input as *const _ as *const c_void),
                std::mem::size_of::<STORAGE_REINITIALIZE_MEDIA>() as u32,
                None,
                0,
                Some(&mut bytes_returned),
                None,
            )
        };

        struct_result.map_err(|e2| {
            anyhow::anyhow!(
                "Hardware crypto-erase not supported by this drive/driver \
                 (bare attempt: {}; explicit CryptoErase attempt: {}). \
                 Use a pattern-overwrite method instead.",
                e,
                e2
            )
        })?;
    }

    // Best-effort — some controllers reset the link after sanitize, which can
    // make a post-completion flush fail even though the erase itself succeeded.
    let _ = handle.flush();

    Ok(HwEraseResult {
        duration: start.elapsed(),
        capacity: disk.capacity,
    })
}

/// Lightweight, informational post-erase check.
///
/// A hardware crypto-erase has no predictable resulting byte pattern to
/// compare against (the drive controller decides), so this does NOT attempt
/// a full-disk readback like `verify::verify_disk` — it samples a handful of
/// sectors from the head, middle, and tail and checks that they no longer
/// look like readable plaintext (Shannon entropy), purely as a sanity
/// signal. The real correctness guarantee is the IOCTL's own completion
/// status in `execute_nvme_crypto_erase`, not this readback.
pub fn post_erase_spot_check(disk: &PhysicalDisk) -> Result<VerifyResult> {
    let start = Instant::now();
    let handle = raw_io::open_disk_read(disk.index)?;

    let bps = disk.bytes_per_sector as u64;
    let sample_sectors_per_zone: u64 = 8;
    let mut zone_starts = vec![0u64];
    if disk.total_sectors > sample_sectors_per_zone * 2 {
        zone_starts.push(disk.total_sectors / 2);
        zone_starts.push(disk.total_sectors.saturating_sub(sample_sectors_per_zone));
    }

    let mut sample = Vec::new();
    let mut hasher = DiskHasher::new();
    let mut sectors_read: u64 = 0;

    for &zone_start in &zone_starts {
        let count = std::cmp::min(
            sample_sectors_per_zone,
            disk.total_sectors.saturating_sub(zone_start),
        );
        if count == 0 {
            continue;
        }
        raw_io::seek_to_sector(&handle, zone_start, disk.bytes_per_sector)?;
        let mut buf = vec![0u8; (count * bps) as usize];
        let mut read = 0u32;
        // SAFETY: handle is valid; buf is sized for `count` sectors.
        let result = unsafe { ReadFile(handle.as_raw(), Some(&mut buf), Some(&mut read), None) };
        match result {
            Ok(()) => {
                hasher.update(&buf[..read as usize]);
                sample.extend_from_slice(&buf[..read as usize]);
                sectors_read += count;
            }
            Err(e) => warn!("Spot-check read failed at sector {}: {}", zone_start, e),
        }
    }

    // is_random_method=true: post-crypto-erase content is expected to look
    // like high-entropy ciphertext garbage, not a known fixed pattern.
    let verdict = entropy::analyze(&sample, true);
    let passed = !matches!(verdict.verdict, EntropyVerdict::Fail);

    if passed {
        info!("Post-erase spot check: sampled sectors look erased ({})", verdict.description);
    } else {
        warn!(
            "Post-erase spot check: sampled sectors still look like readable data ({})",
            verdict.description
        );
    }

    Ok(VerifyResult {
        total_sectors: disk.total_sectors,
        sectors_verified: if passed { sectors_read } else { 0 },
        sectors_failed: if passed { 0 } else { sectors_read },
        first_failure_sector: None,
        passed,
        duration: start.elapsed(),
        disk_hash: hasher.finalize(),
    })
}
