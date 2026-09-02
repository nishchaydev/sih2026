use anyhow::Result;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use windows::core::PCWSTR;
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAGS_AND_ATTRIBUTES, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows::Win32::System::IO::DeviceIoControl;
use windows::Win32::System::Ioctl::{DISK_GEOMETRY, IOCTL_DISK_GET_DRIVE_GEOMETRY};

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
