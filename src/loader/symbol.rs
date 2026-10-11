use alloc::format;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use core::ffi::c_void;
use core::ptr::null_mut;

use dinvk::Module;
use obfstr::obfstr;
use windows_sys::Win32::Foundation::{GetLastError, STATUS_SUCCESS};
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE
};
use windows_sys::Win32::System::SystemServices::{
    IMAGE_SYM_CLASS_EXTERNAL, MEM_TOP_DOWN
};

use crate::error::{Error, Result};
use crate::beacon::get_function_internal_address;
use crate::parse::{CoffFile, Arch};
use crate::ffi::{
    NtAllocateVirtualMemory, NtCurrentProcess,
    LoadLibraryA,
}; 

/// Maximum number of external symbols supported.
const MAX_SYMBOLS: usize = 600;

/// Holds resolved external symbol addresses.
///
/// Maintains a table of function pointers for external imports referenced
/// by the COFF object.
#[derive(Debug, Clone, Copy)]
pub struct Symbol {
    pub address: *mut *mut c_void,
}

impl Symbol {
    /// Resolves all external symbols and allocates the function pointer table.
    ///
    /// Scans the COFF symbol table, resolves each external import to its
    /// runtime address (either a DLL export or Beacon internal function),
    /// and stores the addresses in a newly allocated table.
    pub fn new(
        coff: &CoffFile,
        module: &str,
        base_addr: Option<*mut c_void>,
    ) -> Result<(BTreeMap<String, usize>, Self)> {
        // Resolves the symbols of the coff file
        let symbols = Self::process_symbols(coff)?;
        
        // When stomping, we must reuse the memory at `base_addr`
        let address = if !module.is_empty() {
            let addr = base_addr.ok_or(Error::MissingStompingBaseAddress)?;
            addr as *mut *mut c_void
        } else {
            let mut size = MAX_SYMBOLS * size_of::<*mut c_void>();
            let mut addr = null_mut();
            let status = unsafe {
                NtAllocateVirtualMemory(
                    NtCurrentProcess(),
                    &mut addr,
                    0,
                    &mut size,
                    MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN,
                    PAGE_READWRITE,
                )?
            };

            if addr.is_null() || status != STATUS_SUCCESS {
                return Err(Error::MemoryAllocationError(unsafe { GetLastError() }));
            }

            addr as *mut *mut c_void
        };

        Ok((symbols, Self { address }))
    }

    /// Scans the COFF symbol table for external imports and resolves them.
    fn process_symbols(coff: &CoffFile) -> Result<BTreeMap<String, usize>> {
        let mut functions = BTreeMap::new();

        for symbol in &coff.symbols {
            if functions.len() >= MAX_SYMBOLS {
                return Err(Error::TooManySymbols(functions.len()));
            }

            if symbol.StorageClass == IMAGE_SYM_CLASS_EXTERNAL as u8 && symbol.SectionNumber == 0 {
                let name = coff.get_symbol_name(symbol);
                let address = Self::resolve_symbol_address(&name, coff)?;
                functions.insert(name, address);
            }
        }

        Ok(functions)
    }

    /// Resolves a symbol name to its runtime address.
    ///
    /// Handles both Beacon internal functions and standard DLL exports.
    /// Symbol names follow the format: `__imp_[DLL$Function]` for x64
    /// or `__imp__[DLL$Function@N]` for x86.
    fn resolve_symbol_address(name: &str, coff: &CoffFile) -> Result<usize> {
        log::debug!("Attempting to resolve address for symbol: {}", name);
        let prefix = match coff.arch {
            Arch::X64 => "__imp_",
            Arch::X86 => "__imp__",
        };

        let symbol_name = name
            .strip_prefix(prefix)
            .map_or_else(|| Err(Error::SymbolIgnored), Ok)?;

        if symbol_name.starts_with(obfstr!("Beacon")) || symbol_name.starts_with(obfstr!("toWideChar")) {
            let addr = get_function_internal_address(symbol_name)?;
            return Ok(addr);
        }

        let (module, mut function) = symbol_name
            .split_once('$')
            .ok_or_else(|| Error::ParseError(symbol_name.to_string()))?;

        if let Arch::X86 = coff.arch {
            function = function.split('@').next().unwrap_or(function);
        }

        log::debug!("Resolving Module {} and Function {}", module, function);
        let module = match Module::find(module) {
            Some(m) => m,
            None => {
                let module_cstr = format!("{module}\0");
                let handle = unsafe { LoadLibraryA(module_cstr.as_ptr())? };
                if handle.is_null() {
                    return Err(Error::ModuleNotFound(module.to_string()));
                }
                
                unsafe { Module::from_ptr(handle) }
                    .ok_or_else(|| Error::ModuleNotFound(module.to_string()))?
            }
        };

        module
            .proc(function)
            .map(|addr| addr as usize)
            .ok_or_else(|| Error::FunctionNotFound(symbol_name.to_string()))
    }
}

impl Default for Symbol {
    fn default() -> Self {
        Self { address: null_mut() }
    }
}
