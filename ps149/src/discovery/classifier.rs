use crate::model::DeviceType;

/// Classifies a device based on its WMI properties.
///
/// Detects: HDD, SSD, NVMe, UFS, eMMC, USB Flash, SD Card, and external drives.
pub fn classify_device(
    media_type: Option<&str>,
    interface_type: Option<&str>,
    pnp_id: Option<&str>,
    _is_removable: bool,
) -> DeviceType {
    let interface = interface_type.unwrap_or("").to_uppercase();
    let media = media_type.unwrap_or("").to_lowercase();
    let pnp = pnp_id.unwrap_or("").to_uppercase();

    // UFS detection — UFS devices often appear as SCSI with "UFS" in PnP ID
    if pnp.contains("UFS") || pnp.contains("UNIVERSAL FLASH STORAGE") {
        return DeviceType::Ufs;
    }

    // eMMC detection — eMMC devices have "EMMC" or "MMC" in PnP ID
    if pnp.contains("EMMC") || (pnp.contains("MMC") && !pnp.contains("SDMMC")) {
        return DeviceType::Emmc;
    }

    // USB devices
    if interface == "USB" {
        if media.contains("removable") {
            return DeviceType::UsbFlashDrive;
        }
        return DeviceType::UsbStorageDevice;
    }

    // Internal drives (SCSI/IDE/NVMe)
    if interface == "SCSI" || interface == "IDE" || interface == "NVME" {
        // NVMe — distinct from SATA SSD
        if pnp.contains("NVME") || interface == "NVME" {
            return DeviceType::InternalNvme;
        }
        // SSD detection via PnP or media strings
        if pnp.contains("SSD") || media.contains("ssd") {
            return DeviceType::InternalSsd;
        }
        if media.contains("fixed") {
            return DeviceType::InternalHdd;
        }
        return DeviceType::Unknown;
    }

    // SD/Memory card
    if media.contains("sd") || pnp.contains("SD") || pnp.contains("SDMMC") {
        return DeviceType::SdCard;
    }

    DeviceType::Unknown
}
