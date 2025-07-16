#![allow(non_snake_case, non_camel_case_types)]

use alloc::{
    string::{String, ToString},
    vec::Vec,
};

use core::ffi::{CStr, c_void};
use binrw::{BinRead, binread};
use binrw::io::Cursor;

use super::{debug, warn};
use super::error::CoffError;

// Architecture definitions for x64
const COFF_MACHINE_X64: u16 = 0x8664;

// Architecture definitions for x32
const COFF_MACHINE_X32: u16 = 0x14c;

/// Limit of sections supported by the Windows loader
const MAX_SECTIONS: u16 = 96;

/// Represents a COFF (Common Object File Format) file.
/// This structure stores the file headers, symbols, sections and the file's byte buffer.
pub struct Coff<'a> {
    //// The COFF file header (`IMAGE_FILE_HEADER`).
    pub file_header: IMAGE_FILE_HEADER,

    // A vector of COFF symbols (`IMAGE_SYMBOL`).
    pub symbols: Vec<IMAGE_SYMBOL>,

    /// A vector of section headers (`IMAGE_SECTION_HEADER`).
    pub sections: Vec<IMAGE_SECTION_HEADER>,

    /// The raw contents of the file read into memory
    pub buffer: &'a [u8],

    /// Architecture of the COFF File (x64 or x32)
    pub arch: CoffMachine,
}

impl<'a> Default for Coff<'a> {
    /// Provides a default-initialized `Coff`.
    ///
    /// # Returns
    ///
    /// * A default-initialized `Coff`.
    fn default() -> Self {
        Self {
            file_header: IMAGE_FILE_HEADER::default(),
            symbols: Vec::new(),
            sections: Vec::new(),
            buffer: &[],
            arch: CoffMachine::X64,
        }
    }
}

impl<'a> Coff<'a> {
    /// Creates a new instance of the `Coff` structure from a given file.
    ///
    /// # Arguments
    ///
    /// * `buffer` - Buffer of the Coff file to be analyzed.
    ///
    /// # Returns
    ///
    /// * `Ok(Self)` - Returns a `Coff` instance if parsing succeeds.
    /// * `Err(CoffError)` - If parsing fails due to an invalid buffer or file structure.
    pub fn from_buffer(buffer: &'a [u8]) -> Result<Self, CoffError> {
        // Parse the file
        let coff = Self::parse(buffer)?;
        Ok(coff)
    }

    /// Internal function to parse the COFF file from a byte buffer.
    ///
    /// # Arguments
    ///
    /// * `buffer` - Buffer of the Coff file to be analyzed.
    ///
    /// # Returns
    ///
    /// * `Ok(Self)` - If the buffer is successfully parsed into a `Coff` structure.
    /// * `Err(CoffError)` - If parsing fails due to invalid file structure or errors in the buffer.
    fn parse(buffer: &'a [u8]) -> Result<Self, CoffError> {
        debug!("Parsing COFF file header, buffer size: {}", buffer.len());

        // Validates that the file has the minimum size to contain a COFF header
        if buffer.len() < size_of::<IMAGE_FILE_HEADER>() {
            return Err(CoffError::InvalidCoffFile);
        }

        // Creating a cursor
        let mut cursor = Cursor::new(buffer);

        // The COFF file header
        let file_header = IMAGE_FILE_HEADER::read(&mut cursor)
            .map_err(|_| CoffError::InvalidCoffFile)?;

        // Detects the architecture of the COFF file and returns an enum `CoffMachine`
        let arch = Self::validate_architecture(file_header)?;

        // Checks that the number of sections and symbols is valid
        let num_sections = file_header.NumberOfSections;
        let num_symbols = file_header.NumberOfSymbols;
        if num_sections == 0 || num_symbols == 0 {
            return Err(CoffError::InvalidSectionsOrSymbols);
        }

        // Validation of the maximum number of sections (Windows limit)
        if num_sections > MAX_SECTIONS {
            warn!("Exceeded maximum number of sections: {} > {}", num_sections, MAX_SECTIONS);
            return Err(CoffError::SectionLimitExceeded);
        }

        // A vector of COFF symbols
        let symbol_offset = file_header.PointerToSymbolTable as usize;
        let mut cursor = Cursor::new(&buffer[symbol_offset..]);
        let symbols = (0..num_symbols)
            .map(|_| {
                IMAGE_SYMBOL::read(&mut cursor)
                    .map_err(|_| CoffError::InvalidCoffSymbolsFile)
            })
            .collect::<Result<Vec<IMAGE_SYMBOL>, _>>()?;

        // A vector of COFF sections
        let section_offset = size_of::<IMAGE_FILE_HEADER>() + file_header.SizeOfOptionalHeader as usize;
        let mut section_cursor = Cursor::new(&buffer[section_offset..]);
        let sections = (0..num_sections)
            .map(|_| {
                IMAGE_SECTION_HEADER::read(&mut section_cursor)
                    .map_err(|_| CoffError::InvalidCoffSectionFile)
            })
            .collect::<Result<Vec<IMAGE_SECTION_HEADER>, _>>()?;

        Ok(Self {
            file_header,
            symbols,
            sections,
            buffer,
            arch,
        })
    }

    /// Validates the machine architecture of the COFF file.
    ///
    /// # Arguments
    ///
    /// * `file_header` - The COFF file header.
    ///
    /// # Returns
    ///
    /// * `Ok(CoffMachine)` - The COFF architecture (`X64` or `X32`).
    /// * `Err(CoffError)` - If the architecture is not supported.
    #[inline]
    fn validate_architecture(file_header: IMAGE_FILE_HEADER) -> Result<CoffMachine, CoffError> {
        match file_header.Machine {
            COFF_MACHINE_X64 => Ok(CoffMachine::X64),
            COFF_MACHINE_X32 => Ok(CoffMachine::X32),
            _ => {
                warn!("Unsupported COFF architecture: {:?}", file_header.Machine);
                Err(CoffError::UnsupportedArchitecture)
            }
        }
    }

    /// Calculates the total size of the image, including alignment and symbol relocation.
    ///
    /// # Returns
    ///
    /// * The total aligned size of the COFF image.
    pub fn size(&self) -> usize {
        let length = self
            .sections
            .iter()
            .filter(|section| section.SizeOfRawData > 0)
            .map(|section| Self::page_align(section.SizeOfRawData as usize))
            .sum();

        let total_length = self
            .sections
            .iter()
            .fold(length, |mut total_length, section| {
                let relocations = self.get_relocations(section);
                relocations.iter().for_each(|relocation| {
                    let sym = &self.symbols[relocation.SymbolTableIndex as usize];
                    let name = self.get_symbol_name(sym);
                    if name.starts_with("__imp_") {
                        total_length += size_of::<*const c_void>();
                    }
                });

                total_length
            });

        debug!("Total image size after alignment: {} bytes", total_length);
        Self::page_align(total_length)
    }

    /// Returns the relocation entries for a given section.
    ///
    /// # Arguments
    ///
    /// * `section` - A reference to an `IMAGE_SECTION_HEADER`.
    ///
    /// # Returns
    ///
    /// * A vector of relocation entries for the specified section.
    pub fn get_relocations(&self, section: &IMAGE_SECTION_HEADER) -> Vec<IMAGE_RELOCATION> {
        let reloc_offset = section.PointerToRelocations as usize;
        let num_relocs = section.NumberOfRelocations as usize;
        let mut relocations = Vec::with_capacity(num_relocs);
        let mut cursor = Cursor::new(&self.buffer[reloc_offset..]);

        for _ in 0..num_relocs {
            match IMAGE_RELOCATION::read(&mut cursor) {
                Ok(reloc) => relocations.push(reloc),
                Err(_e) => {
                    debug!("Failed to read relocation: {_e:?}");
                    continue;
                }
            }
        }

        relocations
    }

    /// Retrieves the name of a symbol from the symbol table.
    ///
    /// # Arguments
    ///
    /// * `symtbl` - A reference to an `IMAGE_SYMBOL` entry in the symbol table.
    ///
    /// # Returns
    ///
    /// * The symbol's name.
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

    /// Aligns an `page` value to the next multiple of 0x1000 (page alignment).
    ///
    /// # Arguments
    ///
    /// * `page` - The value to be aligned.
    ///
    /// # Returns
    ///
    /// * The page-aligned value.
    pub fn page_align(page: usize) -> usize {
        const SIZE_OF_PAGE: usize = 0x1000;
        (page + SIZE_OF_PAGE - 1) & !(SIZE_OF_PAGE - 1)
    }

    /// Retrieves the section name from an `IMAGE_SECTION_HEADER` struct.
    ///
    /// # Arguments
    ///
    /// * `section` - A reference to an `IMAGE_SECTION_HEADER` from which the name will be extracted.
    ///
    /// # Returns
    ///
    /// * The section name.
    pub fn get_section_name(section: &IMAGE_SECTION_HEADER) -> String {
        let name_bytes = &section.Name;
        let name = String::from_utf8_lossy(name_bytes);
        name.trim_end_matches('\0').to_string()
    }

    /// Checks if the given type is classified as a function type.
    ///
    /// # Arguments
    ///
    /// * `x` - A 16-bit unsigned integer representing the type to be checked.
    ///
    /// # Returns
    ///
    /// * `true` - If the type represents a function.
    /// * `false` - If the type does not represent a function.
    pub fn is_fcn(x: u16) -> bool {
        (x & 0x30) == (2 << 4)
    }
}

/// Represents the architecture of the COFF (Common Object File Format) file.
#[derive(Debug, PartialEq, Hash, Clone, Copy, Eq, PartialOrd, Ord)]
pub enum CoffMachine {
    /// 64-bit architecture.
    X64,

    /// 32-bit architecture.
    X32,
}

/// Represents the COFF data source, which can be a file or a memory buffer.
pub enum CoffSource<'a> {
    /// COFF file indicated by a string representing the file path.
    File(&'a str),

    /// Memory buffer containing COFF data.
    Buffer(&'a [u8]),
}

impl<'a> From<&'a str> for CoffSource<'a> {
    /// Converts a file path (`&'a str`) to a COFF source (`CoffSource::File`).
    ///
    /// # Arguments
    ///
    /// * `file` - Path of the COFF file.
    ///
    /// # Returns
    ///
    /// * The input string will be treated as the path of a COFF file.
    fn from(file: &'a str) -> Self {
        CoffSource::File(file)
    }
}

impl<'a, const N: usize> From<&'a [u8; N]> for CoffSource<'a> {
    /// Converts a fixed-size byte array (`&[u8; N]`) to a COFF source (`CoffSource::Buffer`).
    ///
    /// # Arguments
    ///
    /// * `buffer` - A fixed-size byte array representing the COFF file data.
    ///
    /// # Returns
    ///
    /// * The input byte array will be treated as a COFF buffer in memory.
    fn from(buffer: &'a [u8; N]) -> Self {
        CoffSource::Buffer(buffer)
    }
}

impl<'a> From<&'a [u8]> for CoffSource<'a> {
    /// Converts a byte slice (`&[u8]`) to a COFF source (`CoffSource::Buffer`).
    ///
    /// # Arguments
    ///
    /// * `buffer` - A byte slice representing the COFF file data.
    ///
    /// # Returns
    ///
    /// * The input byte slice will be treated as a COFF buffer in memory.
    fn from(buffer: &'a [u8]) -> Self {
        CoffSource::Buffer(buffer)
    }
}

/// Represents the file header of a COFF (Common Object File Format) file.
#[binread]
#[derive(Debug, Clone, Copy)]
#[br(little)]
#[repr(C)]
pub struct IMAGE_FILE_HEADER {
    /// The target machine architecture (e.g., x64, x32).
    pub Machine: u16,

    /// The number of sections in the COFF file.
    pub NumberOfSections: u16,

    /// The timestamp when the file was created.
    pub TimeDateStamp: u32,

    /// The pointer to the symbol table.
    pub PointerToSymbolTable: u32,

    /// The number of symbols in the COFF file.
    pub NumberOfSymbols: u32,

    /// The size of the optional header.
    pub SizeOfOptionalHeader: u16,

    /// The characteristics of the file.
    pub Characteristics: u16,
}

impl Default for IMAGE_FILE_HEADER {
    /// Provides a default-initialized `IMAGE_FILE_HEADER`.
    ///
    /// # Returns
    ///
    /// * A default-initialized `IMAGE_FILE_HEADER`.
    fn default() -> Self {
        Self {
            Machine: 0,
            NumberOfSections: 0,
            TimeDateStamp: 0,
            PointerToSymbolTable: 0,
            NumberOfSymbols: 0,
            SizeOfOptionalHeader: 0,
            Characteristics: 0,
        }
    }
}

/// Represents a symbol in the COFF symbol table.
#[binread]
#[derive(Clone, Copy)]
#[br(little)]
#[repr(C, packed(2))]
pub struct IMAGE_SYMBOL {
    #[br(temp)]
    name_raw: [u8; 8],

    /// The value associated with the symbol.
    pub Value: u32,

    /// The section number that contains the symbol.
    pub SectionNumber: i16,

    /// The type of the symbol.
    pub Type: u16,

    /// The storage class of the symbol (e.g., external, static).
    pub StorageClass: u8,

    /// The number of auxiliary symbol records.
    pub NumberOfAuxSymbols: u8,

    #[br(calc = unsafe {
        core::ptr::read_unaligned(name_raw.as_ptr() as *const IMAGE_SYMBOL_0)
    })]
    pub N: IMAGE_SYMBOL_0,
}

/// A union representing different ways a symbol name can be stored.
#[repr(C, packed(2))]
#[derive(Clone, Copy)]
pub union IMAGE_SYMBOL_0 {
    /// A short symbol name (8 bytes).
    pub ShortName: [u8; 8],

    /// A long symbol name stored in a different structure.
    pub Name: IMAGE_SYMBOL_0_0,

    /// Long symbol name stored as a pair of u32 values.
    pub LongName: [u32; 2],
}

/// Represents the long name of a symbol as a pair of values.
#[repr(C, packed(2))]
#[derive(Clone, Copy)]
pub struct IMAGE_SYMBOL_0_0 {
    /// The offset to the symbol name.
    pub Short: u32,

    /// The length of the symbol name.
    pub Long: u32,
}

/// Represents a section header in a COFF file.
#[binread]
#[repr(C)]
#[br(little)]
#[derive(Clone, Copy)]
pub struct IMAGE_SECTION_HEADER {
    /// The name of the section (8 bytes).
    pub Name: [u8; 8],

    #[br(temp)]
    misc_raw: u32,

    /// The virtual address of the section in memory.
    pub VirtualAddress: u32,

    /// The size of the section's raw data.
    pub SizeOfRawData: u32,

    /// The pointer to the raw data in the file.
    pub PointerToRawData: u32,

    /// The pointer to relocation entries.
    pub PointerToRelocations: u32,

    /// The pointer to line numbers (if any).
    pub PointerToLinenumbers: u32,

    /// The number of relocations in the section.
    pub NumberOfRelocations: u16,

    /// The number of line numbers in the section.
    pub NumberOfLinenumbers: u16,

    /// Characteristics that describe the section (e.g., executable, writable).
    pub Characteristics: u32,

    #[br(calc = IMAGE_SECTION_HEADER_0 {
        PhysicalAddress: misc_raw
    })]
    pub Misc: IMAGE_SECTION_HEADER_0,
}

/// A union representing either the physical or virtual size of the section.
#[repr(C)]
#[derive(Clone, Copy)]
pub union IMAGE_SECTION_HEADER_0 {
    /// The physical address of the section.
    pub PhysicalAddress: u32,

    /// The virtual size of the section.
    pub VirtualSize: u32,
}

/// Represents a relocation entry in a COFF file.
#[binread]
#[br(little)]
#[repr(C, packed(2))]
pub struct IMAGE_RELOCATION {
    #[br(temp)]
    va_raw: u32,

    /// The index of the symbol in the symbol table.
    pub SymbolTableIndex: u32,

    /// The type of relocation.
    pub Type: u16,

    #[br(calc = IMAGE_RELOCATION_0 {
        VirtualAddress: va_raw
    })]
    pub Anonymous: IMAGE_RELOCATION_0,
}

/// A union representing either the virtual address or relocation count.
#[repr(C, packed(2))]
pub union IMAGE_RELOCATION_0 {
    /// The virtual address of the relocation.
    pub VirtualAddress: u32,

    /// The relocation count.
    pub RelocCount: u32,
}
