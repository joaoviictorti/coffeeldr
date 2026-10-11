#![allow(non_snake_case)]

use core::ffi::{CStr, c_void};
use alloc::borrow::Cow;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use binrw::{BinRead, binread};
use binrw::io::Cursor;

use crate::error::{Result, Error};

/// Arch type for AMD64 (x64).
const COFF_MACHINE_X64: u16 = 0x8664;

/// Arch type for i386 (x86).
const COFF_MACHINE_X86: u16 = 0x014C;

/// Maximum number of sections allowed by the Windows loader.
const MAX_SECTIONS: u16 = 96;

/// A parsed COFF object file.
pub struct CoffFile<'a> {
    /// File header describing the object layout.
    pub file_header: IMAGE_FILE_HEADER,
    /// Symbol table entries.
    pub symbols: Vec<IMAGE_SYMBOL>,
    /// Section headers describing each section.
    pub sections: Vec<IMAGE_SECTION_HEADER>,
    /// Raw file contents.
    pub buffer: Cow<'a, [u8]>,
    /// Target Arch architecture.
    pub arch: Arch,
}

impl<'a> CoffFile<'a> {
    /// Parses a COFF object from a byte slice or owned buffer.
    ///
    /// The buffer must contain a valid COFF file header, section table and
    /// symbol table. Minimal validation is performed to ensure the layout is
    /// consistent.
    pub fn parse(buffer: Cow<'a, [u8]>) -> Result<Self> {
        log::debug!("Parsing COFF file header, buffer size: {}", buffer.len());

        if buffer.len() < size_of::<IMAGE_FILE_HEADER>() {
            return Err(Error::InvalidCoffFile);
        }

        let mut cursor = Cursor::new(buffer.as_ref());
        let file_header = IMAGE_FILE_HEADER::read(&mut cursor)
            .map_err(|_| Error::InvalidCoffFile)?;

        // Detects the architecture of the COFF file
        let arch = Self::validate_architecture(file_header)?;

        // Checks that the number of sections and symbols is valid
        let num_sections = file_header.NumberOfSections;
        let num_symbols = file_header.NumberOfSymbols;
        if num_sections == 0 || num_symbols == 0 {
            return Err(Error::InvalidSectionsOrSymbols);
        }

        // Validation of the maximum number of sections (Windows limit)
        if num_sections > MAX_SECTIONS {
            log::warn!("Exceeded maximum number of sections: {} > {}", num_sections, MAX_SECTIONS);
            return Err(Error::SectionLimitExceeded);
        }

        // A vector of COFF symbols
        let symbol_offset = file_header.PointerToSymbolTable as usize;
        let mut cursor = Cursor::new(&buffer.as_ref()[symbol_offset..]);
        let symbols = (0..num_symbols)
            .map(|_| {
                IMAGE_SYMBOL::read(&mut cursor)
                    .map_err(|_| Error::InvalidCoffSymbolsFile)
            })
            .collect::<Result<Vec<IMAGE_SYMBOL>>>()?;

        // A vector of COFF sections
        let section_offset = size_of::<IMAGE_FILE_HEADER>() + file_header.SizeOfOptionalHeader as usize;
        let mut section_cursor = Cursor::new(&buffer.as_ref()[section_offset..]);
        let sections = (0..num_sections)
            .map(|_| {
                IMAGE_SECTION_HEADER::read(&mut section_cursor)
                    .map_err(|_| Error::InvalidCoffSectionFile)
            })
            .collect::<Result<Vec<IMAGE_SECTION_HEADER>>>()?;

        Ok(Self {
            file_header,
            symbols,
            sections,
            buffer,
            arch,
        })
    }

    /// Computes the total allocation size needed to load the COFF image.
    ///
    /// The result accounts for page-aligned sections and extra space for
    /// import pointers referenced by `__imp_` symbols.
    pub fn size(&self) -> usize {
        let length = self
            .sections
            .iter()
            .filter(|section| section.SizeOfRawData > 0)
            .map(|section| Self::page_align(section.SizeOfRawData as usize))
            .sum();

        let size = self
            .sections
            .iter()
            .fold(length, |mut size, section| {
                let relocations = self.get_relocations(section);
                relocations.iter().for_each(|relocation| {
                    let sym = &self.symbols[relocation.SymbolTableIndex as usize];
                    let name = self.get_symbol_name(sym);
                    if name.starts_with("__imp_") {
                        size += size_of::<*const c_void>();
                    }
                });

                size
            });

        log::debug!("Total image size after alignment: {} bytes", size);
        Self::page_align(size)
    }

    /// Returns relocation entries for the specified section.
    ///
    /// Invalid relocations are logged and skipped, allowing parsing to proceed.
    pub fn get_relocations(&self, section: &IMAGE_SECTION_HEADER) -> Vec<IMAGE_RELOCATION> {
        let reloc_offset = section.PointerToRelocations as usize;
        let num_relocs = section.NumberOfRelocations as usize;
        let mut relocations = Vec::with_capacity(num_relocs);
        let mut cursor = Cursor::new(&self.buffer[reloc_offset..]);

        for _ in 0..num_relocs {
            match IMAGE_RELOCATION::read(&mut cursor) {
                Ok(reloc) => relocations.push(reloc),
                Err(_e) => {
                    log::debug!("Failed to read relocation: {_e:?}");
                    continue;
                }
            }
        }

        relocations
    }

    /// Reads the symbol name, handling short names and long names from the string table.
    pub fn get_symbol_name(&self, symtbl: &IMAGE_SYMBOL) -> String {
        unsafe {
            let name = if symtbl.N.ShortName[0] != 0 {
                String::from_utf8_lossy(&symtbl.N.ShortName).into_owned()
            } else {
                let long_name_offset = symtbl.N.Name.Long as usize;
                let string_table_offset = self.file_header.PointerToSymbolTable as usize
                    + self.file_header.NumberOfSymbols as usize * size_of::<IMAGE_SYMBOL>();

                // Retrieve the name from the string table
                let offset = string_table_offset + long_name_offset;
                let name_ptr = &self.buffer[offset] as *const u8;
                CStr::from_ptr(name_ptr.cast())
                    .to_string_lossy()
                    .into_owned()
            };

            name.trim_end_matches('\0').to_string()
        }
    }

    /// Rounds a value up to the next 4 KiB page boundary.
    #[inline]
    pub fn page_align(value: usize) -> usize {
        const PAGE_SIZE: usize = 0x1000;
        (value + PAGE_SIZE - 1) & !(PAGE_SIZE - 1)
    }

    /// Extracts the section name, trimming trailing NUL bytes.
    pub fn get_section_name(section: &IMAGE_SECTION_HEADER) -> String {
        let s = String::from_utf8_lossy(&section.Name);
        s.trim_end_matches('\0').to_string()
    }

    /// Returns `true` if the symbol type indicates a function.
    ///
    /// The check extracts the derived type field (bits 4-5) and compares it
    /// against `IMAGE_DTYPE_FUNCTION` (0x2).
    #[inline]
    pub fn is_fcn(ty: u16) -> bool {
        const DTYPE_MASK: u16 = 0x30;
        const IMAGE_DTYPE_FUNCTION: u16 = 2 << 4;
        (ty & DTYPE_MASK) == IMAGE_DTYPE_FUNCTION
    }

    /// Determines the Arch architecture from the COFF header.
    ///
    /// Returns an error if the Arch field does not match any supported
    /// architecture (x86 or x64).
    fn validate_architecture(file_header: IMAGE_FILE_HEADER) -> Result<Arch> {
        match file_header.Arch {
            COFF_MACHINE_X64 => Ok(Arch::X64),
            COFF_MACHINE_X86 => Ok(Arch::X86),
            _ => {
                log::warn!("Unsupported COFF architecture: 0x{:04X}", file_header.Arch);
                Err(Error::UnsupportedArchitecture)
            }
        }
    }
}

impl<'a> Default for CoffFile<'a> {
    fn default() -> Self {
        Self {
            file_header: IMAGE_FILE_HEADER::default(),
            symbols: Vec::new(),
            sections: Vec::new(),
            buffer: Cow::Borrowed(&[]),
            arch: Arch::X64,
        }
    }
}

/// Target Arch architecture of a COFF file.
#[derive(Debug, PartialEq, Hash, Clone, Copy, Eq, PartialOrd, Ord)]
pub enum Arch {   
    X64,
    X86,
}

impl Arch {
    /// Validates that the COFF architecture matches the host process.
    pub fn check_architecture(&self) -> Result<()> {
        #[cfg(target_arch = "x86_64")]
        const ARCH: Arch = Arch::X64;
        #[cfg(target_arch = "x86")]
        const ARCH: Arch = Arch::X86;
        if *self != ARCH {
            return Err(Error::ArchitectureMismatch {
                expected: self.as_str(),
                actual: ARCH.as_str(),
            });
        }
        
        Ok(())
    }

    #[inline]
    const fn as_str(&self) -> &'static str {
        match self {
            Self::X64 => "x64",
            Self::X86 => "x86",
        }
    }
}

/// Source from which a COFF file can be loaded.
pub enum Source<'a> {
    File(&'a str),
    Buffer(&'a [u8]),
}

impl<'a> From<&'a str> for Source<'a> {
    fn from(file: &'a str) -> Self {
        Source::File(file)
    }
}

impl<'a, const N: usize> From<&'a [u8; N]> for Source<'a> {
    fn from(buffer: &'a [u8; N]) -> Self {
        Source::Buffer(buffer)
    }
}

impl<'a> From<&'a [u8]> for Source<'a> {
    fn from(buffer: &'a [u8]) -> Self {
        Source::Buffer(buffer)
    }
}

/// COFF file header structure.
#[repr(C)]
#[binread]
#[br(little)]
#[derive(Default, Debug, Clone, Copy)]
pub struct IMAGE_FILE_HEADER {
    pub Arch: u16,
    pub NumberOfSections: u16,
    pub TimeDateStamp: u32,
    pub PointerToSymbolTable: u32,
    pub NumberOfSymbols: u32,
    pub SizeOfOptionalHeader: u16,
    pub Characteristics: u16,
}

/// COFF symbol table entry.
#[binread]
#[derive(Clone, Copy)]
#[br(little)]
#[repr(C, packed(2))]
pub struct IMAGE_SYMBOL {
    #[br(temp)]
    name_raw: [u8; 8],
    pub Value: u32,
    pub SectionNumber: i16,
    pub Type: u16,
    pub StorageClass: u8,
    pub NumberOfAuxSymbols: u8,
    #[br(calc = unsafe {
        core::ptr::read_unaligned(name_raw.as_ptr() as *const IMAGE_SYMBOL_0)
    })]
    pub N: IMAGE_SYMBOL_0,
}

impl IMAGE_SYMBOL {
    /// Returns the symbol offset
    #[inline]
    pub fn get_offset<T>(&self, reloc_addr: *const T) -> T
    where
        T: Copy + From<u32> + core::ops::Add<Output = T>,
    {
        T::from(self.Value) + unsafe { core::ptr::read_unaligned(reloc_addr) }
    }
}

/// Union representing the symbol name storage.
#[repr(C, packed(2))]
#[derive(Clone, Copy)]
pub union IMAGE_SYMBOL_0 {
    pub ShortName: [u8; 8],
    pub Name: IMAGE_SYMBOL_0_0,
    pub LongName: [u32; 2],
}

/// String table reference for long symbol names.
#[repr(C, packed(2))]
#[derive(Clone, Copy)]
pub struct IMAGE_SYMBOL_0_0 {
    pub Short: u32,
    pub Long: u32,
}

/// COFF section header.
#[binread]
#[repr(C)]
#[br(little)]
#[derive(Clone, Copy)]
pub struct IMAGE_SECTION_HEADER {
    pub Name: [u8; 8],
    #[br(temp)]
    misc_raw: u32,
    pub VirtualAddress: u32, 
    pub SizeOfRawData: u32,
    pub PointerToRawData: u32,
    pub PointerToRelocations: u32,
    pub PointerToLinenumbers: u32,
    pub NumberOfRelocations: u16,
    pub NumberOfLinenumbers: u16,
    pub Characteristics: u32,
    #[br(calc = IMAGE_SECTION_HEADER_0 {
        PhysicalAddress: misc_raw
    })]
    pub Misc: IMAGE_SECTION_HEADER_0,
}

/// Union for physical address or virtual size in a section header.
#[repr(C)]
#[derive(Clone, Copy)]
pub union IMAGE_SECTION_HEADER_0 {
    pub PhysicalAddress: u32,
    pub VirtualSize: u32,
}

/// COFF relocation entry.
#[binread]
#[br(little)]
#[repr(C, packed(2))]
pub struct IMAGE_RELOCATION {
    #[br(temp)]
    va_raw: u32,
    pub SymbolTableIndex: u32,
    pub Type: u16,
    #[br(calc = IMAGE_RELOCATION_0 {
        VirtualAddress: va_raw
    })]
    pub Anonymous: IMAGE_RELOCATION_0,
}

/// Union for relocation virtual address or overflow count.
#[repr(C, packed(2))]
pub union IMAGE_RELOCATION_0 {
    pub VirtualAddress: u32,
    pub RelocCount: u32,
}
