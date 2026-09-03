use anyhow::Result;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use windows::core::PCWSTR;
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAGS_AND_ATTRIBUTES, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows::Win32::System::IO::DeviceIoControl;
use windows::Win32::System::Ioctl::{
    DISK_GEOMETRY, IOCTL_DISK_GET_DRIVE_GEOMETRY, IOCTL_STORAGE_QUERY_PROPERTY,
    STORAGE_DEVICE_DESCRIPTOR, STORAGE_PROPERTY_QUERY, StorageDeviceProperty,
    PropertyStandardQuery, BusTypeNvme, BusTypeSata, BusTypeAta, BusTypeAtapi,
    BusTypeUsb, BusTypeSas, BusTypeScsi,
};
use crate::model::device::StorageBusType;

/// Holds basic disk geometry information.
#[derive(Debug)]
pub struct DiskGeometry {
    pub bytes_per_sector: u32,
    pub total_sectors: u64,
}

/// Retrieves disk geometry for a given physical disk index using DeviceIoControl.
pub fn get_disk_geometry(disk_index: u32) -> Result<DiskGeometry> {
    let path = format!("\\\\.\\PhysicalDrive{}", disk_index);
    let path_u16: Vec<u16> = OsStr::new(&path)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let pcwstr = PCWSTR(path_u16.as_ptr());

    unsafe {
        // SAFETY: We are providing a valid null-terminated UTF-16 string.
        let handle_result = CreateFileW(
            pcwstr,
            0x80000000, // GENERIC_READ
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_FLAGS_AND_ATTRIBUTES(0),
            None,
        );

        let handle = match handle_result {
            Ok(h) => h,
            Err(e) => return Err(anyhow::anyhow!("CreateFileW failed: {}", e)),
        };

        let mut geometry = DISK_GEOMETRY::default();
        let mut bytes_returned: u32 = 0;

        // SAFETY: handle is valid. geometry and bytes_returned are valid stack variables.
        let result = DeviceIoControl(
            handle,
            IOCTL_DISK_GET_DRIVE_GEOMETRY,
            None,
            0,
            Some(&mut geometry as *mut _ as *mut std::ffi::c_void),
            std::mem::size_of::<DISK_GEOMETRY>() as u32,
            Some(&mut bytes_returned),
            None,
        );

        let _ = CloseHandle(handle);

        result.map_err(|e| anyhow::anyhow!("DeviceIoControl failed: {}", e))?;

        Ok(DiskGeometry {
            bytes_per_sector: geometry.BytesPerSector,
            total_sectors: (geometry.Cylinders as u64)
                * (geometry.TracksPerCylinder as u64)
                * (geometry.SectorsPerTrack as u64),
        })
    }
}

/// Queries the physical bus/transport a disk is attached through via
/// `IOCTL_STORAGE_QUERY_PROPERTY`. Used to gate hardware fast-erase
/// capability — see `sanitize::hardware_erase::probe`.
pub fn query_bus_type(disk_index: u32) -> Result<StorageBusType> {
    let path = format!("\\\\.\\PhysicalDrive{}", disk_index);
    let path_u16: Vec<u16> = OsStr::new(&path)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let pcwstr = PCWSTR(path_u16.as_ptr());

    unsafe {
        // SAFETY: We are providing a valid null-terminated UTF-16 string.
        let handle = CreateFileW(
            pcwstr,
            0x80000000, // GENERIC_READ
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_FLAGS_AND_ATTRIBUTES(0),
            None,
        )
        .map_err(|e| anyhow::anyhow!("CreateFileW failed: {}", e))?;

        let mut query = STORAGE_PROPERTY_QUERY::default();
        query.PropertyId = StorageDeviceProperty;
        query.QueryType = PropertyStandardQuery;

        // STORAGE_DEVICE_DESCRIPTOR has a trailing variable-length region for
        // vendor/product/serial strings. Over-allocate so DeviceIoControl has
        // room, even though we only read the fixed-offset BusType field.
        let mut out_buf = vec![0u8; 1024];
        let mut bytes_returned: u32 = 0;

        // SAFETY: handle is valid; query and out_buf are valid, sized buffers.
        let result = DeviceIoControl(
            handle,
            IOCTL_STORAGE_QUERY_PROPERTY,
            Some(&query as *const _ as *const std::ffi::c_void),
            std::mem::size_of::<STORAGE_PROPERTY_QUERY>() as u32,
            Some(out_buf.as_mut_ptr() as *mut std::ffi::c_void),
            out_buf.len() as u32,
            Some(&mut bytes_returned),
            None,
        );

        let _ = CloseHandle(handle);
        result.map_err(|e| anyhow::anyhow!("DeviceIoControl (bus type query) failed: {}", e))?;

        // SAFETY: out_buf is large enough to hold the fixed-offset header of
        // STORAGE_DEVICE_DESCRIPTOR (we don't touch the trailing string data).
        let descriptor = &*(out_buf.as_ptr() as *const STORAGE_DEVICE_DESCRIPTOR);
        let bus_type = descriptor.BusType;

        Ok(if bus_type == BusTypeNvme {
            StorageBusType::Nvme
        } else if bus_type == BusTypeSata {
            StorageBusType::Sata
        } else if bus_type == BusTypeAta || bus_type == BusTypeAtapi {
            StorageBusType::Ata
        } else if bus_type == BusTypeUsb {
            StorageBusType::Usb
        } else if bus_type == BusTypeSas {
            StorageBusType::Sas
        } else if bus_type == BusTypeScsi {
            StorageBusType::Scsi
        } else {
            StorageBusType::Other
        })
    }
}
