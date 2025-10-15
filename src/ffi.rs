use core::ffi::c_void;
use obfstr::obfstr as s;
use dinvk::data::NTSTATUS;
use dinvk::{GetModuleHandle, dinvoke, get_ntdll_address};

pub type LoadLibraryExAFn = unsafe extern "system" fn(
    lp_lib_file_name: *const u8, 
    h_file: *mut c_void, 
    dw_flags: u32
) -> *mut c_void;

pub type NtFreeVirtualMemoryFn = unsafe extern "system" fn(
    process_handle: *mut c_void, 
    base_address: *mut *mut c_void, 
    region_size: *mut usize, 
    free_type: u32
) -> NTSTATUS;

#[inline]
pub fn NtFreeVirtualMemory(
    process_handle: *mut c_void, 
    base_address: *mut *mut c_void, 
    region_size: *mut usize, 
    free_type: u32
) {
    dinvoke!(
        get_ntdll_address(),
        s!("NtFreeVirtualMemory"),
        NtFreeVirtualMemoryFn,
        process_handle,
        base_address,
        region_size,
        free_type
    );
}

#[inline]
pub fn LoadLibraryExA(
    lp_lib_file_name: *const u8, 
    h_file: *mut c_void, 
    dw_flags: u32
) -> Option<*mut c_void> {
    let kernel32 = GetModuleHandle(2808682670u32, Some(dinvk::hash::murmur3));
    dinvoke!(
        kernel32,
        s!("LoadLibraryExA"),
        LoadLibraryExAFn,
        lp_lib_file_name,
        h_file,
        dw_flags
    )
}