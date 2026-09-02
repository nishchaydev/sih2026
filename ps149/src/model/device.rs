use serde::Serialize;

use super::device_type::DeviceType;
use super::safety_status::SafetyStatus;

/// A logical volume (drive letter) on a partition.
#[derive(Debug, Clone, Serialize)]
pub struct Volume {
    /// Drive letter, e.g. "C:" or "E:".
    pub drive_letter: Option<String>,
    /// Volume label, e.g. "Windows" or "USBDRIVE".
    pub label: Option<String>,
    /// Filesystem type, e.g. "NTFS", "exFAT", "FAT32".
    pub filesystem: Option<String>,
    /// Total capacity in bytes.
    pub capacity: Option<u64>,
    /// Free space in bytes.
    pub free_space: Option<u64>,
    /// Windows drive type (Fixed, Removable, etc.).
    pub drive_type: Option<u32>,
}

/// A partition on a physical disk.
#[derive(Debug, Clone, Serialize)]
pub struct Partition {
    /// Partition index on the disk (0-based).
    pub index: u32,
    /// Size in bytes.
    pub size: u64,
    /// Whether this is a boot partition.
    pub is_boot: bool,
    /// Whether this is a primary partition.
    pub is_primary: bool,
    /// Partition type string from WMI.
    pub partition_type: Option<String>,
    /// Volumes mounted on this partition.
    pub volumes: Vec<Volume>,
}

/// A physical disk device.
#[derive(Debug, Clone, Serialize)]
pub struct PhysicalDisk {
    /// Windows disk index (0, 1, 2, ...).
    pub index: u32,
    /// Device path, e.g. `\\.\PHYSICALDRIVE1`.
    pub device_id: String,
    /// Manufacturer/model string.
    pub model: Option<String>,
    /// Serial number.
    pub serial_number: Option<String>,
    /// Total capacity in bytes.
    pub capacity: u64,
    /// WMI MediaType string.
    pub media_type: Option<String>,
    /// Interface type: USB, SCSI, IDE, etc.
    pub interface_type: Option<String>,
    /// PnP device ID (contains USB VID/PID for USB devices).
    pub pnp_device_id: Option<String>,
    /// Bytes per sector (physical).
    pub bytes_per_sector: u32,
    /// Total number of sectors.
    pub total_sectors: u64,
    /// Classified device type.
    pub device_type: DeviceType,
    /// Whether this disk contains the OS boot partition.
    pub is_boot_disk: bool,
    /// Safety status for erasure operations.
    pub safety_status: SafetyStatus,
    /// Partitions on this disk.
    pub partitions: Vec<Partition>,
}

#[allow(dead_code)]
impl PhysicalDisk {
    /// Human-readable capacity string (e.g. "14.9 GB").
    pub fn capacity_display(&self) -> String {
        format_bytes(self.capacity)
    }

    /// Returns the first volume's drive letter, if any.
    pub fn primary_drive_letter(&self) -> Option<&str> {
        self.partitions
            .iter()
            .flat_map(|p| p.volumes.iter())
            .find_map(|v| v.drive_letter.as_deref())
    }

    /// Returns the first volume's filesystem, if any.
    pub fn primary_filesystem(&self) -> Option<&str> {
        self.partitions
            .iter()
            .flat_map(|p| p.volumes.iter())
            .find_map(|v| v.filesystem.as_deref())
    }
}

/// Format a byte count into a human-readable string.
pub fn format_bytes(bytes: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    const GB: f64 = MB * 1024.0;
    const TB: f64 = GB * 1024.0;

    let b = bytes as f64;
    if b >= TB {
        format!("{:.1} TB", b / TB)
    } else if b >= GB {
        format!("{:.1} GB", b / GB)
    } else if b >= MB {
        format!("{:.1} MB", b / MB)
    } else if b >= KB {
        format!("{:.1} KB", b / KB)
    } else {
        format!("{} B", bytes)
    }
}
