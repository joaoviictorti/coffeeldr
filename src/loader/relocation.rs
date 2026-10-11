use alloc::collections::BTreeMap;
use alloc::string::String;
use core::ffi::c_void;
use core::ptr::write_unaligned;
use windows_sys::Win32::System::SystemServices::{
    IMAGE_SYM_CLASS_EXTERNAL, IMAGE_REL_AMD64_ADDR64, IMAGE_REL_AMD64_REL32_5,
    IMAGE_REL_AMD64_ADDR32NB, IMAGE_REL_AMD64_REL32, IMAGE_REL_I386_DIR32,
    IMAGE_REL_I386_REL32
};

use crate::error::{Error, Result};
use crate::parse::{
    CoffFile, Arch,
    IMAGE_RELOCATION, IMAGE_SYMBOL
};

use super::memory::SectionMap;
use super::symbol::Symbol;

/// Applies relocations to map symbols to their runtime addresses.
pub struct Relocation<'a> {
    coff: &'a CoffFile<'a>,
    sections: &'a [SectionMap],
}

impl<'a> Relocation<'a> {
    /// Creates a new relocation processor for the given COFF and mapped sections.
    #[inline]
    pub fn new(coff: &'a CoffFile, sections: &'a [SectionMap]) -> Self {
        Self { coff, sections }
    }

    /// Processes all relocations in the COFF image.
    ///
    /// For each relocation entry, resolves the target symbol address and
    /// applies the appropriate fixup. External symbols are resolved through
    /// the import table, while internal symbols use section-relative offsets.
    pub fn process_relocation(&self, imports: &BTreeMap<String, usize>, slots: &Symbol) -> Result<()> {
        let mut slot_idx = 0;

        for (sec_idx, section) in self.coff.sections.iter().enumerate() {
            let relocations = self.coff.get_relocations(section);
            log::debug!("Processing {} relocations for section {}", relocations.len(), sec_idx);

            for reloc in relocations.iter() {
                let symbol = &self.coff.symbols[reloc.SymbolTableIndex as usize];
                let reloc_addr = unsafe {
                    self.sections[sec_idx].base.add(reloc.Anonymous.VirtualAddress as usize)
                };

                // Check if this is an external import
                if symbol.StorageClass == IMAGE_SYM_CLASS_EXTERNAL as u8 
                    && symbol.SectionNumber == 0 
                {
                    // Resolve external import through the function table
                    let name = self.coff.get_symbol_name(symbol);
                    let func_addr = imports
                        .get(&name)
                        .ok_or_else(|| Error::FunctionNotFound(name.clone()))?;

                    // Write function pointer to import slot
                    let slot_ptr = unsafe { slots.address.add(slot_idx) };
                    unsafe { slot_ptr.write_volatile(*func_addr as *mut c_void) };
                    slot_idx += 1;

                    log::debug!(
                        "External: name={}, slot={:p}, func=0x{:X}",
                        name, slot_ptr, func_addr
                    );

                    self.apply_relocation(reloc_addr, slot_ptr as u64, reloc, symbol)?;
                } else if symbol.SectionNumber > 0 {
                    // Compute address from section base
                    let section_base = self.sections[(symbol.SectionNumber - 1) as usize].base;
                    let target = section_base as u64;
                    let sym_value = symbol.Value;

                    log::debug!(
                        "Internal: section={}, base=0x{:X}, value=0x{:X}",
                        symbol.SectionNumber, target, sym_value
                    );

                    self.apply_relocation(reloc_addr, target, reloc, symbol)?;
                }
            }
        }

        Ok(())
    }

    /// Dispatches to the architecture-specific relocation handler.
    fn apply_relocation(
        &self,
        addr: *mut c_void,
        target: u64,
        reloc: &IMAGE_RELOCATION,
        symbol: &IMAGE_SYMBOL,
    ) -> Result<()> {
        log::debug!(
            "Relocation: type=0x{:04X}, addr={:p}, target=0x{:X}",
            reloc.Type, addr, target
        );

        match self.coff.arch {
            Arch::X64 => self.apply_x64(addr, target, reloc, symbol),
            Arch::X86 => self.apply_x86(addr, target, reloc, symbol),
        }
    }

    /// Applies AMD64 (x64) relocations.
    fn apply_x64(
        &self,
        addr: *mut c_void,
        target: u64,
        reloc: &IMAGE_RELOCATION,
        symbol: &IMAGE_SYMBOL,
    ) -> Result<()> {
        match reloc.Type as u32 {
            IMAGE_REL_AMD64_ADDR64 => {
                let offset = symbol.get_offset::<u64>(addr as *const u64);
                let result = target.wrapping_add(offset);
                unsafe { write_unaligned(addr as *mut u64, result) };
            }
            IMAGE_REL_AMD64_ADDR32NB => {
                let offset = symbol.get_offset::<u32>(addr as *const u32);
                write_rel32(addr, target, offset, 0);
            }
            r @ IMAGE_REL_AMD64_REL32..=IMAGE_REL_AMD64_REL32_5 => {
                let adjustment = r - IMAGE_REL_AMD64_REL32;
                let offset = symbol.get_offset::<u32>(addr as *const u32);
                write_rel32(addr, target, offset, adjustment);
            }
            _ => return Err(Error::InvalidRelocationType(reloc.Type)),
        }

        Ok(())
    }

    /// Applies i386 (x86) relocations.
    fn apply_x86(
        &self,
        addr: *mut c_void,
        target: u64,
        reloc: &IMAGE_RELOCATION,
        symbol: &IMAGE_SYMBOL,
    ) -> Result<()> {
        match reloc.Type as u32 {
            IMAGE_REL_I386_DIR32 => {
                let offset = symbol.get_offset::<u32>(addr as *const u32);
                let result = (target as u32).wrapping_add(offset);
                unsafe { write_unaligned(addr as *mut u32, result) };
            }
            IMAGE_REL_I386_REL32 => {
                let offset = symbol.get_offset::<u32>(addr as *const u32);
                write_rel32(addr, target, offset, 0);
            }
            _ => return Err(Error::InvalidRelocationType(reloc.Type)),
        }
        
        Ok(())
    }

}

/// Writes a 32-bit PC-relative offset for x86/x64 relocations.
///
/// Subtracts 4 to account for the instruction reading the offset after
/// incrementing PC past the displacement field.
fn write_rel32(addr: *mut c_void, target: u64, offset: u32, adjustment: u32) {
    let result = (target as u32)
        .wrapping_add(offset)
        .wrapping_sub(addr as u32)
        .wrapping_sub(4)
        .wrapping_sub(adjustment);

    unsafe { write_unaligned(addr as *mut u32, result) };
}

