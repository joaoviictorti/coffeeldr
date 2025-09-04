use core::ffi::c_void;
use dinvk::data::NTSTATUS;

/// Type for `LoadLibraryExA`
pub type LoadLibraryExA = unsafe extern "system" fn(
    lp_lib_file_name: *const u8, 
    h_file: *mut c_void, 
    dw_flags: u32
) -> *mut c_void;

/// Type for `NtFreeVirtualMemory`
pub type NtFreeVirtualMemory = unsafe extern "system" fn(
    process_handle: *mut c_void, 
    base_address: *mut *mut c_void, 
    region_size: *mut usize, 
    free_type: u32
) -> NTSTATUS;