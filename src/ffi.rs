#![allow(non_snake_case)]

use core::ffi::c_void;
use core::ptr::null_mut;

use dinvk::{link, Module};
use windows_sys::Win32::Foundation::{HANDLE, NTSTATUS};

fn kernel32() -> *mut c_void {
    Module::find("kernel32.dll")
        .map(|m| m.base())
        .unwrap_or(null_mut())
}

fn ntdll() -> *mut c_void {
    Module::find("ntdll.dll")
        .map(|m| m.base())
        .unwrap_or(null_mut())
}

link!(
    kernel32(),
    "LoadLibraryExA",
    pub fn LoadLibraryExA(
        lp_lib_file_name: *const u8,
        h_file: *mut c_void,
        dw_flags: u32
    ) -> *mut c_void
);

link!(
    ntdll(),
    "NtFreeVirtualMemory",
    pub fn NtFreeVirtualMemory(
        process_handle: *mut c_void,
        base_address: *mut *mut c_void,
        region_size: *mut usize,
        free_type: u32
    ) -> NTSTATUS
);

link!(
    ntdll(),
    "NtProtectVirtualMemory",
    pub fn NtProtectVirtualMemory(
        process_handle: *mut c_void,
        base_address: *mut *mut c_void,
        region_size: *mut usize,
        new_protect: u32,
        old_protect: *mut u32,
    ) -> NTSTATUS
);

link!(
    ntdll(),
    "NtAllocateVirtualMemory",
    pub fn NtAllocateVirtualMemory(
        process_handle: HANDLE,
        base_address: *mut *mut c_void,
        zero_bits: usize,
        region_size: *mut usize,
        allocation_type: u32,
        protect: u32,
    ) -> NTSTATUS
);

link!(
    kernel32(),
    "LoadLibraryA",
    pub fn LoadLibraryA(
        lp_lib_file_name: *const u8
    ) -> *mut c_void
);

#[inline(always)]
pub fn NtCurrentProcess() -> HANDLE {
    -1isize as HANDLE
}

#[inline(always)]
pub const fn NT_SUCCESS(nt_status: NTSTATUS) -> bool {
    nt_status >= 0
}
