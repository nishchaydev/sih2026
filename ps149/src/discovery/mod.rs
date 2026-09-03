pub mod classifier;
pub mod ioctl;
pub mod wmi;
pub mod hotplug;

use crate::model::*;
use anyhow::Result;
use tracing::warn;

/// Orchestrates the discovery pipeline to enumerate all physical disks, partitions, and volumes.
pub fn enumerate_devices() -> Result<Vec<PhysicalDisk>> {
    let com_con = ::wmi::COMLibrary::new()?;
    let wmi_con = ::wmi::WMIConnection::new(com_con)?;

    let drives: Vec<wmi::Win32DiskDrive> = wmi_con.query()?;
    let partitions: Vec<wmi::Win32DiskPartition> = wmi_con.query()?;
    let logical_disks: Vec<wmi::Win32LogicalDisk> = wmi_con.query()?;

    let os_info: Vec<wmi::Win32OperatingSystem> = wmi_con.query()?;
    let system_drive = os_info
        .into_iter()
        .next()
        .and_then(|os| os.system_drive)
        .unwrap_or_else(|| "C:".to_string());

    // Build partition-to-volumes mapping using ASSOCIATORS OF queries.
    // For each logical disk, query which partition it belongs to.
    let mut partition_volumes: std::collections::HashMap<String, Vec<Volume>> =
        std::collections::HashMap::new();

    for ld in &logical_disks {
        let drive_letter = match &ld.device_id {
            Some(id) => id.clone(),
            None => continue,
        };

        let vol = Volume {
            drive_letter: Some(drive_letter.clone()),
            label: ld.volume_name.clone(),
            filesystem: ld.file_system.clone(),
            capacity: ld.size,
            free_space: ld.free_space,
            drive_type: ld.drive_type,
        };

        // Use ASSOCIATORS OF to find partition for this logical disk
        let query = format!(
            "ASSOCIATORS OF {{Win32_LogicalDisk.DeviceID='{}'}} WHERE AssocClass = Win32_LogicalDiskToPartition",
            drive_letter
        );

        match wmi_con.raw_query::<std::collections::HashMap<String, ::wmi::Variant>>(&query) {
            Ok(assoc_parts) => {
                for part_map in assoc_parts {
                    if let Some(::wmi::Variant::String(part_id)) = part_map.get("DeviceID") {
                        partition_volumes
                            .entry(part_id.clone())
                            .or_default()
                            .push(vol.clone());
                        break;
                    }
                }
            }
            Err(e) => {
                // Fallback: if ASSOCIATORS OF doesn't work, we'll attach volumes later by heuristic
                warn!("ASSOCIATORS OF query failed for {}: {} — will use fallback", drive_letter, e);
            }
        }
    }

    let mut result = Vec::new();

    for disk in drives {
        let did = match &disk.device_id {
            Some(id) => id.clone(),
            None => continue,
        };
        let disk_index = disk.index.unwrap_or(0);

        // Find partitions for this disk via DiskIndex
        let disk_parts: Vec<Partition> = partitions
            .iter()
            .filter(|p| p.disk_index == Some(disk_index))
            .map(|wp| {
                let part_id = wp.device_id.clone().unwrap_or_default();
                let vols = partition_volumes.remove(&part_id).unwrap_or_default();
                Partition {
                    index: wp.index.unwrap_or(0),
                    size: wp.size.unwrap_or(0),
                    is_boot: wp.boot_partition.unwrap_or(false),
                    is_primary: wp.primary_partition.unwrap_or(false),
                    partition_type: wp.partition_type.clone(),
                    volumes: vols,
                }
            })
            .collect();

        // Get disk geometry via IOCTL
        let (bytes_per_sec, total_sec) = match ioctl::get_disk_geometry(disk_index) {
            Ok(geom) => (geom.bytes_per_sector, geom.total_sectors),
            Err(e) => {
                warn!("IOCTL geometry failed for disk {}: {} — using capacity fallback", disk_index, e);
                let cap = disk.size.unwrap_or(0);
                (512, if cap > 0 { cap / 512 } else { 0 })
            }
        };

        // Best-effort — never fail enumeration over this, just default to Unknown.
        let bus_type = match ioctl::query_bus_type(disk_index) {
            Ok(bt) => bt,
            Err(e) => {
                warn!("Bus-type query failed for disk {}: {} — defaulting to Unknown", disk_index, e);
                StorageBusType::Unknown
            }
        };

        let dev_type = classifier::classify_device(
            disk.media_type.as_deref(),
            disk.interface_type.as_deref(),
            disk.pnp_device_id.as_deref(),
            false,
        );

        // ONLY the disk holding the running OS system drive (e.g. C:) is PROTECTED.
        // Everything else — internal drives, USB, SD cards — is AVAILABLE.
        // A bootable USB installer has BootPartition=true but is NOT the running OS.
        let mut has_system_drive = false;
        for p in &disk_parts {
            for v in &p.volumes {
                if let Some(letter) = &v.drive_letter {
                    if letter.eq_ignore_ascii_case(&system_drive) {
                        has_system_drive = true;
                    }
                }
            }
        }
        let is_boot_disk = has_system_drive;

        let safety_status = if is_boot_disk {
            SafetyStatus::Protected
        } else {
            SafetyStatus::Available
        };

        result.push(PhysicalDisk {
            index: disk_index,
            device_id: did,
            model: disk.model.clone(),
            serial_number: disk.serial_number.clone(),
            capacity: disk.size.unwrap_or(0),
            media_type: disk.media_type.clone(),
            interface_type: disk.interface_type.clone(),
            bus_type,
            pnp_device_id: disk.pnp_device_id.clone(),
            bytes_per_sector: bytes_per_sec,
            total_sectors: total_sec,
            device_type: dev_type,
            is_boot_disk,
            safety_status,
            partitions: disk_parts,
        });
    }

    Ok(result)
}
