use serde::Deserialize;

#[derive(Deserialize, Debug)]
#[serde(rename = "Win32_DiskDrive")]
#[serde(rename_all = "PascalCase")]
pub struct Win32DiskDrive {
    #[serde(rename = "DeviceID")]
    pub device_id: Option<String>,
    pub model: Option<String>,
    pub serial_number: Option<String>,
    pub size: Option<u64>,
    pub media_type: Option<String>,
    pub interface_type: Option<String>,
    pub index: Option<u32>,
    #[allow(dead_code)]
    pub partitions: Option<u32>,
    #[serde(rename = "PNPDeviceID")]
    pub pnp_device_id: Option<String>,
}

#[derive(Deserialize, Debug)]
#[serde(rename = "Win32_DiskPartition")]
#[serde(rename_all = "PascalCase")]
pub struct Win32DiskPartition {
    #[serde(rename = "DeviceID")]
    pub device_id: Option<String>,
    pub disk_index: Option<u32>,
    pub index: Option<u32>,
    pub size: Option<u64>,
    #[serde(rename = "Type")]
    pub partition_type: Option<String>,
    pub boot_partition: Option<bool>,
    pub primary_partition: Option<bool>,
}

#[derive(Deserialize, Debug)]
#[serde(rename = "Win32_LogicalDisk")]
#[serde(rename_all = "PascalCase")]
pub struct Win32LogicalDisk {
    #[serde(rename = "DeviceID")]
    pub device_id: Option<String>,
    pub volume_name: Option<String>,
    pub file_system: Option<String>,
    pub size: Option<u64>,
    pub free_space: Option<u64>,
    pub drive_type: Option<u32>,
}

#[derive(Deserialize, Debug)]
#[serde(rename = "Win32_OperatingSystem")]
#[serde(rename_all = "PascalCase")]
pub struct Win32OperatingSystem {
    pub system_drive: Option<String>,
}
