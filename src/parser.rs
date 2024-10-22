#![allow(non_snake_case, non_camel_case_types)]

use {
    log::{warn, debug},
    super::error::CoffError,
    std::ffi::{c_void, CStr},
    scroll::{ctx::TryFromCtx, Endian, Pread, LE},
};

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
            arch: CoffMachine::X64
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

        // The COFF file header
        let mut offset = 0;
        let file_header: IMAGE_FILE_HEADER = buffer.gread_with(&mut offset, LE).map_err(|_| CoffError::InvalidCoffFile)?;

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
        let mut symbol_offset = file_header.PointerToSymbolTable as usize;
        let symbols: Vec<IMAGE_SYMBOL> = (0..num_symbols as usize).map(|_| {
            let symbol: IMAGE_SYMBOL = buffer.gread_with(&mut symbol_offset, LE).map_err(|_| CoffError::InvalidCoffSymbolsFile)?;
            Ok(symbol)
        }).collect::<Result<Vec<_>, CoffError>>()?;
        
        // A vector of COFF sections
        let sections: Vec<IMAGE_SECTION_HEADER> = (0..num_sections as usize).map(|_| {
            let section: IMAGE_SECTION_HEADER = buffer.gread_with(&mut offset, LE).map_err(|_| CoffError::InvalidCoffSectionFile)?;
            Ok(section)
        }).collect::<Result<Vec<_>, CoffError>>()?;

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
            },
        }
    }

    /// Calculates the total size of the image, including alignment and symbol relocation.
    /// 
    /// # Returns
    /// 
    /// * The total aligned size of the COFF image.
    pub fn size(&self) -> usize {
        let length: usize = self.sections
            .iter()
            .filter(|section| section.SizeOfRawData > 0)
            .map(|section| Self::page_align(section.SizeOfRawData as usize))
            .sum();

        let total_length = self.sections.iter().fold(length, |mut total_length, section| {
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
        let mut offset = reloc_offset;
        for _ in 0..num_relocs {
            let relocation: IMAGE_RELOCATION = self.buffer.gread_with(&mut offset, LE).unwrap();
            relocations.push(relocation);
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
                let full_offset = string_table_offset + long_name_offset;

                // Retrieve the name from the string table
                let name_ptr = &self.buffer[full_offset] as *const u8 as *const i8;
                CStr::from_ptr(name_ptr).to_string_lossy().into_owned()
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
        page + ((0x1000 - (page & (0x1000 - 1))) % 0x1000)
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
#[derive(Debug, PartialEq)]
pub enum CoffMachine {
    /// 64-bit architecture.
    X64,

    /// 32-bit architecture.
    X32
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
#[repr(C)]
#[derive(Clone, Copy)]
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

/// Implements context-based parsing for `IMAGE_FILE_HEADER`.
impl<'a> TryFromCtx<'a, Endian> for IMAGE_FILE_HEADER {
    type Error = scroll::Error;

    /// Attempts to read an `IMAGE_FILE_HEADER` from a byte slice.
    ///
    /// # Arguments
    ///
    /// * `bytes` - A byte slice containing the COFF file data.
    /// * `_ctx` - The endianness of the data (e.g., little-endian).
    ///
    /// # Returns
    ///
    /// * The parsed `IMAGE_FILE_HEADER` and the size read.
    fn try_from_ctx(bytes: &'a [u8], _ctx: Endian) -> Result<(Self, usize), Self::Error> {
        let file_header = IMAGE_FILE_HEADER {
            Machine: bytes.pread_with(0, LE)?,
            NumberOfSections: bytes.pread_with(2, LE)?,
            TimeDateStamp: bytes.pread_with(4, LE)?,
            PointerToSymbolTable: bytes.pread_with(8, LE)?,
            NumberOfSymbols: bytes.pread_with(12, LE)?,
            SizeOfOptionalHeader: bytes.pread_with(16, LE)?,
            Characteristics: bytes.pread_with(18, LE)?,
        };

        Ok((file_header, size_of::<IMAGE_FILE_HEADER>()))
    }
}

/// Represents a symbol in the COFF symbol table.
#[repr(C, packed(2))]
#[derive(Clone, Copy)]
pub struct IMAGE_SYMBOL {
    /// The union that contains the symbol's name.
    pub N: IMAGE_SYMBOL_0,

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

/// Implements context-based parsing for `IMAGE_SYMBOL`.
impl<'a> TryFromCtx<'a, Endian> for IMAGE_SYMBOL {
    type Error = scroll::Error;

    /// Attempts to read an `IMAGE_SYMBOL` from a byte slice.
    ///
    /// # Arguments
    ///
    /// * `bytes` - A byte slice containing the COFF symbol data.
    /// * `_ctx` - The endianness of the data (e.g., little-endian).
    ///
    /// # Returns
    ///
    /// * The parsed `IMAGE_SYMBOL` and the size read.
    fn try_from_ctx(bytes: &'a [u8], _ctx: Endian) -> Result<(Self, usize), Self::Error> {
        let symbol = IMAGE_SYMBOL {
            N: IMAGE_SYMBOL_0 {
                ShortName: bytes.pread_with(0, LE)?,
            },
            Value: bytes.pread_with(8, LE)?,
            SectionNumber: bytes.pread_with(12, LE)?,
            Type: bytes.pread_with(14, LE)?,
            StorageClass: bytes.pread_with(16, LE)?,
            NumberOfAuxSymbols: bytes.pread_with(17, LE)?,
        };

        Ok((symbol, size_of::<IMAGE_SYMBOL>()))
    }
}

/// Represents a section header in a COFF file.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct IMAGE_SECTION_HEADER {
    /// The name of the section (8 bytes).
    pub Name: [u8; 8],

    /// A union containing the physical or virtual size of the section.
    pub Misc: IMAGE_SECTION_HEADER_0,

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

/// Implements context-based parsing for `IMAGE_SECTION_HEADER`.
impl<'a> TryFromCtx<'a, Endian> for IMAGE_SECTION_HEADER {
    type Error = scroll::Error;
    
    /// Attempts to read an `IMAGE_SECTION_HEADER` from a byte slice.
    ///
    /// # Arguments
    ///
    /// * `bytes` - A byte slice containing the COFF section header data.
    /// * `_ctx` - The endianness of the data (e.g., little-endian).
    ///
    /// # Returns
    ///
    /// * The parsed `IMAGE_SECTION_HEADER` and the size read.
    fn try_from_ctx(bytes: &'a [u8], _ctx: Endian) -> Result<(Self, usize), Self::Error> {
        let section = IMAGE_SECTION_HEADER {
            Name: bytes.pread_with(0, LE)?,
            Misc: IMAGE_SECTION_HEADER_0 {
                PhysicalAddress: bytes.pread_with(8, LE)?,
            },
            VirtualAddress: bytes.pread_with(12, LE)?,
            SizeOfRawData: bytes.pread_with(16, LE)?,
            PointerToRawData: bytes.pread_with(20, LE)?,
            PointerToRelocations: bytes.pread_with(24, LE)?,
            PointerToLinenumbers: bytes.pread_with(28, LE)?,
            NumberOfRelocations: bytes.pread_with(32, LE)?,
            NumberOfLinenumbers: bytes.pread_with(34, LE)?,
            Characteristics: bytes.pread_with(36, LE)?,
        };
        
        Ok((section, size_of::<IMAGE_SECTION_HEADER>()))
    }
}

/// Represents a relocation entry in a COFF file.
#[repr(C, packed(2))]
pub struct IMAGE_RELOCATION {
    /// The union containing either the virtual address or the relocation count.
    pub Anonymous: IMAGE_RELOCATION_0,
    
    /// The index of the symbol in the symbol table.
    pub SymbolTableIndex: u32,

    /// The type of relocation.
    pub Type: u16,
}

/// A union representing either the virtual address or relocation count.
#[repr(C, packed(2))]
pub union IMAGE_RELOCATION_0 {
    /// The virtual address of the relocation.
    pub VirtualAddress: u32,
    
    /// The relocation count.
    pub RelocCount: u32,
}

/// Implements context-based parsing for `IMAGE_RELOCATION`.
impl<'a> TryFromCtx<'a, Endian> for IMAGE_RELOCATION {
    type Error = scroll::Error;

    /// Attempts to read an `IMAGE_RELOCATION` from a byte slice.
    ///
    /// # Arguments
    ///
    /// * `bytes` - A byte slice containing the COFF relocation data.
    /// * `_ctx` - The endianness of the data (e.g., little-endian).
    ///
    /// # Returns
    ///
    /// * The parsed `IMAGE_RELOCATION` and the size read.
    fn try_from_ctx(bytes: &'a [u8], _ctx: Endian) -> Result<(Self, usize), Self::Error> {
        let relocation = IMAGE_RELOCATION {
            Anonymous: IMAGE_RELOCATION_0 {
                VirtualAddress: bytes.pread_with(0, LE)?,
            },
            SymbolTableIndex: bytes.pread_with(4, LE)?,
            Type: bytes.pread_with(8, LE)?,
        };
        
        Ok((relocation, size_of::<IMAGE_RELOCATION>()))
    }
}