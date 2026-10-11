use alloc::format;
use alloc::vec::Vec;
use alloc::string::String;
use core::ffi::c_void;
use core::ptr::null_mut;
use core::intrinsics::{
    volatile_copy_nonoverlapping_memory, 
    volatile_set_memory
};

use dinvk::Module;
use pelite::pe::{Pe, PeView};
use windows_sys::Win32::Foundation::{GetLastError, STATUS_SUCCESS};
use windows_sys::Win32::System::SystemServices::MEM_TOP_DOWN;
use windows_sys::Win32::System::LibraryLoader::DONT_RESOLVE_DLL_REFERENCES;
use windows_sys::Win32::System::Diagnostics::Debug::{
    IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_NOT_CACHED, 
    IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE
};
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE, 
    PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, 
    PAGE_EXECUTE_WRITECOPY, PAGE_NOACCESS,
    PAGE_NOCACHE, PAGE_READONLY, PAGE_READWRITE, 
    PAGE_WRITECOPY
};

use crate::error::{Error, Result};
use crate::parse::CoffFile;
use crate::ffi::{
    LoadLibraryExA, NtCurrentProcess,
    NT_SUCCESS, NtProtectVirtualMemory,
    NtAllocateVirtualMemory, 
}; 

/// Manages memory allocation for COFF sections.
pub struct Memory<'a> {
    coff: &'a CoffFile<'a>,
    module: &'a str,
}

impl<'a> Memory<'a> {
    /// Creates a new memory allocator for the given COFF object.
    #[inline]
    pub fn new(coff: &'a CoffFile<'a>, module: &'a str) -> Self {
        Self { coff, module }
    }

    /// Allocates memory by stomping a module or reserving a new region.
    pub fn alloc(&self) -> Result<(Vec<SectionMap>, Option<*mut c_void>)> {
        if !self.module.is_empty() {
            self.alloc_with_stomping()
        } else {
            self.alloc_bof_memory()
        }
    }

    /// Allocates fresh read-write memory for the COFF payload.
    fn alloc_bof_memory(&self) -> Result<(Vec<SectionMap>, Option<*mut c_void>)> {
        let mut size = self.coff.size();
        let mut addr = null_mut();
        let status = unsafe {
            NtAllocateVirtualMemory(
                NtCurrentProcess(), 
                &mut addr, 
                0, 
                &mut size, 
                MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN, 
                PAGE_READWRITE
            )?
        };
        
        if status != STATUS_SUCCESS {
            return Err(Error::MemoryAllocationError(unsafe { GetLastError() }));
        }

        let (sections, _) = SectionMap::copy_sections(addr, self.coff);
        Ok((sections, None))
    }

    /// Performs module stomping by overwriting a module's text section.
    ///
    /// Locates the target module's text section, changes its permissions to
    /// read-write, and copies the COFF sections into it. This keeps all code
    /// within relative jump range (REL32).
    fn alloc_with_stomping(&self) -> Result<(Vec<SectionMap>, Option<*mut c_void>)> {
        let (mut text_address, mut size) = self.get_text_module()
            .ok_or(Error::StompingTextSectionNotFound)?;

        // If the file is larger than the space inside the .text of the target module,
        // we do not stomp
        if self.coff.size() > size {
            return Err(Error::StompingSizeOverflow);
        }

        let mut old = 0;
        let status = unsafe {
            NtProtectVirtualMemory(
                NtCurrentProcess(), 
                &mut text_address,
                &mut size,
                PAGE_READWRITE,
                &mut old
            )?
        };

        if !NT_SUCCESS(status) {
            return Err(Error::MemoryProtectionError(unsafe { GetLastError() }));
        }

        // This is necessary because REL32 instructions must remain within range, and allocating the `Symbol`
        // elsewhere (e.g. with a distant `NtAllocateVirtualMemory`) could lead to crashes
        log::debug!(
            "Memory successfully allocated for BOF at address (Module Stomping): {:?}",
            text_address
        );
        let (sections, sec_base) = SectionMap::copy_sections(text_address, self.coff);
        Ok((sections, Some(sec_base)))
    }

    /// Finds the text section of the target module.
    ///
    /// Loads the module if not already loaded and locates its text section
    /// using PE header parsing.
    fn get_text_module(&self) -> Option<(*mut c_void, usize)> {
        let h_module = match Module::find(self.module) {
            Some(m) => m.base(),
            None => unsafe {
                let target = format!("{}\0", self.module);
                LoadLibraryExA(
                    target.as_ptr(),
                    null_mut(),
                    DONT_RESOLVE_DLL_REFERENCES
                )
                .ok()?
            }
        };

        if h_module.is_null() {
            return None;
        }

        // Retrieving `.text` from the target module
        let pe = unsafe { PeView::module(h_module.cast()) };
        let section = pe.section_headers().by_name(".text")?;
        let ptr = (h_module as usize + section.VirtualAddress as usize) as *mut c_void;
        let size = section.SizeOfRawData as usize;

        Some((ptr, size))
    }
}


/// Describes a mapped section: base address, size, characteristics and name.
#[derive(Debug, Clone)]
pub struct SectionMap {
    pub base: *mut c_void,
    pub size: usize,
    pub characteristics: u32,
    pub name: String,
}

impl SectionMap {
    /// Copies all COFF sections into the destination memory region.
    ///
    /// Iterates through each section, copies its raw data to the allocated
    /// memory, and returns both the section mappings and the next aligned
    /// address after all sections.
    fn copy_sections(virt_addr: *mut c_void, coff: &CoffFile) -> (Vec<SectionMap>, *mut c_void) {
        unsafe {
            let sections = &coff.sections;
            let mut base = virt_addr;
            let sections = sections
                .iter()
                .map(|section| {
                    let size = section.SizeOfRawData as usize;
                    let name = CoffFile::get_section_name(section);
                    let address = coff.buffer.as_ptr().add(section.PointerToRawData as usize);

                    if section.PointerToRawData != 0 {
                        volatile_copy_nonoverlapping_memory(base as *mut u8, address.cast_mut(), size);
                    } else {
                        volatile_set_memory(base as *mut u8, 0, size);
                    }

                    let section_map = SectionMap {
                        base,
                        size,
                        characteristics: section.Characteristics,
                        name,
                    };
                    base = CoffFile::page_align((base as usize) + size) as *mut c_void;

                    section_map
                })
                .collect();

            (sections, base)
        }
    }

    /// Applies the correct memory protections to this section.
    ///
    /// Determines the appropriate protection flags based on the section's
    /// characteristics (execute, read, write).
    pub fn adjust_permissions(&mut self) -> Result<()> {
        log::info!(
            "Adjusting memory permissions for section: Name = {}, Address = {:?}, Size = {}, Characteristics = 0x{:X}",
            self.name, self.base, self.size, self.characteristics
        );

        let bitmask = self.characteristics & (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE);
        let mut protection = if bitmask == 0 {
            PAGE_NOACCESS
        } else if bitmask == IMAGE_SCN_MEM_EXECUTE {
            PAGE_EXECUTE
        } else if bitmask == IMAGE_SCN_MEM_READ {
            PAGE_READONLY
        } else if bitmask == (IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE) {
            PAGE_EXECUTE_READ
        } else if bitmask == IMAGE_SCN_MEM_WRITE {
            PAGE_WRITECOPY
        } else if bitmask == (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_WRITE) {
            PAGE_EXECUTE_WRITECOPY
        } else if bitmask == (IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE) {
            PAGE_READWRITE
        } else if bitmask == (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE) {
            PAGE_EXECUTE_READWRITE
        } else {
            log::warn!("Unknown protection, using PAGE_EXECUTE_READWRITE");
            PAGE_EXECUTE_READWRITE
        };

        if (protection & IMAGE_SCN_MEM_NOT_CACHED) == IMAGE_SCN_MEM_NOT_CACHED {
            protection |= PAGE_NOCACHE;
        }

        let mut old = 0;
        let status = unsafe {
            NtProtectVirtualMemory(
                NtCurrentProcess(), 
                &mut self.base, 
                &mut self.size, 
                protection, 
                &mut old
            )?
        };

        if !NT_SUCCESS(status) {
            return Err(Error::MemoryProtectionError(unsafe { GetLastError() }));
        }

        Ok(())
    }
}
