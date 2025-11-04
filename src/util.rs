use core::ptr::null_mut;
use alloc::{
    ffi::CString, 
    string::String, 
    vec, 
    vec::Vec
};

use obfstr::obfstring as s;
use windows_sys::Win32::{
    Foundation::{GENERIC_READ, INVALID_HANDLE_VALUE},
    Storage::FileSystem::{
        CreateFileA, FILE_ATTRIBUTE_NORMAL, 
        FILE_SHARE_READ, GetFileSize, INVALID_FILE_SIZE, 
        OPEN_EXISTING, ReadFile
    },
};

use super::error::{CoffeeLdrError, CoffResult};

/// Reads the entire contents of a file into memory using the Windows API.
///
/// # Arguments
///
/// * `name` - The path to the file as a UTF-8 string.
///
/// # Returns
///
/// Containing the file's contents if the operation succeeds.
pub fn read_file(name: &str) -> CoffResult<Vec<u8>> {
    let file_name = CString::new(name)
        .map_err(|_| CoffeeLdrError::Msg(s!("Invalid cstring")))?;
    let h_file = unsafe {
        CreateFileA(
            file_name.as_ptr().cast(),
            GENERIC_READ,
            FILE_SHARE_READ,
            null_mut(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            null_mut(),
        )
    };

    if h_file == INVALID_HANDLE_VALUE {
        return Err(CoffeeLdrError::Msg(s!("failed to open file")));
    }

    let size = unsafe { GetFileSize(h_file, null_mut()) };
    if size == INVALID_FILE_SIZE {
        return Err(CoffeeLdrError::Msg(s!("invalid file size")));
    }

    let mut out = vec![0u8; size as usize];
    let mut bytes = 0;
    unsafe {
        ReadFile(
            h_file,
            out.as_mut_ptr(),
            out.len() as u32,
            &mut bytes,
            null_mut(),
        );
    }

    Ok(out)
}

#[doc(hidden)]
#[macro_export]
macro_rules! debug {
    ($($arg:tt)*) => {{
        let _ = format_args!($($arg)*);
        #[cfg(debug_assertions)]
        {
            log::debug!($($arg)*);
        }
    }};
}

#[doc(hidden)]
#[macro_export]
macro_rules! info {
    ($($arg:tt)*) => {{
        let _ = format_args!($($arg)*);
        #[cfg(debug_assertions)]
        {
            log::info!($($arg)*);
        }
    }};
}

#[doc(hidden)]
#[macro_export]
macro_rules! warn {
    ($($arg:tt)*) => {{
        let _ = format_args!($($arg)*);
        #[cfg(debug_assertions)]
        {
            log::warn!($($arg)*);
        }
    }};
}
