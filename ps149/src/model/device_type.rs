use serde::Serialize;
use std::fmt;

/// Classification of a storage device's physical type and transport.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[allow(dead_code)]
pub enum DeviceType {
    InternalHdd,
    InternalSsd,
    InternalNvme,
    ExternalHdd,
    ExternalSsd,
    UsbFlashDrive,
    UsbStorageDevice,
    SdCard,
    Ufs,
    Emmc,
    Unknown,
}

impl fmt::Display for DeviceType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InternalHdd => write!(f, "Internal HDD"),
            Self::InternalSsd => write!(f, "Internal SSD"),
            Self::InternalNvme => write!(f, "Internal NVMe SSD"),
            Self::ExternalHdd => write!(f, "External HDD"),
            Self::ExternalSsd => write!(f, "External SSD"),
            Self::UsbFlashDrive => write!(f, "USB Flash Drive"),
            Self::UsbStorageDevice => write!(f, "USB Storage Device"),
            Self::SdCard => write!(f, "SD / Memory Card"),
            Self::Ufs => write!(f, "UFS (Universal Flash Storage)"),
            Self::Emmc => write!(f, "eMMC"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}
