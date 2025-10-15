use alloc::string::String;
use thiserror::Error;

pub(crate) type CoffResult<T> = core::result::Result<T, crate::error::CoffeeLdrError>;

/// Represents errors that can occur during the loading and 
/// handling of COFF (Common Object File Format) files.
#[derive(Debug, Error)]
pub enum CoffeeLdrError {
    /// Occurs when memory allocation fails.
    #[error("Memory allocation error: code {0}")]
    MemoryAllocationError(u32),

    /// Occurs when there is a failure in setting memory protection for a region.
    #[error("Memory protection error: code {0}")]
    MemoryProtectionError(u32),

    /// Represents an error when a symbol in the COFF file has an invalid format.
    #[error("Invalid symbol format: '{0}'")]
    InvalidSymbolFormat(String),

    /// Raised when a relocation entry in the COFF file has an unsupported or invalid type.
    #[error("Invalid relocation type: {0}")]
    InvalidRelocationType(u16),

    /// Occurs when a required symbol (function) is not found during symbol resolution.
    #[error("Failed to resolve symbol: '{0}'")]
    FunctionNotFound(String),

    /// Raised when an internal symbol (used by the COFF loader itself) cannot be resolved.
    #[error("Failed to resolve internal symbol: '{0}'")]
    FunctionInternalNotFound(String),

    /// Raised when the specified module is not found during module resolution.
    #[error("Failed to resolve the module: '{0}'")]
    ModuleNotFound(String),

    /// Raised when the COFF file cannot be parsed correctly.
    #[error("Error loading COFF file.")]
    ParsingError,

    /// Propagates errors from the `CoffError` type, which represent issues specifically with COFF file handling.
    #[error("{0}")]
    CoffError(#[from] CoffError),

    /// Raised when there is a mismatch between the expected and actual system architecture.
    #[error("Unsupported architecture. File expects {expected}, but current system is {actual}.")]
    ArchitectureMismatch { expected: &'static str, actual: &'static str },

    /// Raised when the COFF file contains more symbols than allowed.
    #[error("Too many symbols in the COFF file. Maximum allowed is {0}.")]
    TooManySymbols(usize),

    /// Raised when an unspecified error occurs, useful for simple context-specific failures.
    #[error("{0}")]
    GenericError(String),

    /// Raised when a symbol cannot be parsed correctly.
    #[error("Failed to parse symbol: '{0}'")]
    ParseError(String),

    /// Raised when a symbol is ignored because it lacks a required prefix for processing.
    #[error("Symbol ignored because it lacks the required prefix.")]
    SymbolIgnored,

    /// Raised when an error occurs while reading the output buffer.
    #[error("Error reading output")]
    OutputError,

    /// Error returned when the `.text` section could not be located in the target module during module stomping.
    #[error("Could not extract .text section from module during stomping")]
    StompingTextSectionNotFound,

    /// Error returned when the COFF file is too large to fit in the target module's `.text` section.
    #[error("COFF is too large to stomp over target module section")]
    StompingSizeOverflow,

    /// Error returned when the base address for the target section is not set during module stomping.
    #[error("Missing base address for section during module stomping")]
    MissingStompingBaseAddress,
}

/// Represents errors specific to handling COFF files during parsing and processing.
#[derive(Debug, Error)]
pub enum CoffError {
    /// Raised when a COFF file cannot be read correctly.
    #[error("The file could not be read: {0}")]
    FileReadError(String),

    /// Raised when the COFF file's header cannot be read or is invalid.
    #[error("Invalid COFF file: Unable to read the COFF header.")]
    InvalidCoffFile,

    /// Raised when the COFF symbols in the file cannot be read or are invalid.
    #[error("Invalid COFF file: Unable to read the COFF symbols.")]
    InvalidCoffSymbolsFile,

    /// Raised when the section headers of the COFF file cannot be read or are invalid.
    #[error("Invalid COFF file: Unable to read the COFF section headers.")]
    InvalidCoffSectionFile,

    /// Raised when the COFF file is for an unsupported architecture (not x64 or x32).
    #[error("Unsupported architecture. Expected x64 or x32.")]
    UnsupportedArchitecture,

    /// Raised when the COFF file contains an invalid number of sections or symbols.
    #[error("Invalid number of sections or symbols.")]
    InvalidSectionsOrSymbols,

    /// Raised when the COFF file exceeds the allowed limit of sections (96 sections).
    #[error("Section limit exceeded: the number of sections exceeds the supported limit of 96.")]
    SectionLimitExceeded,
}

#[derive(Debug, Error)]
pub enum BeaconPackError {
    #[error("Hex error: {0}")]
    Hex(hex::FromHexError),

    #[error("IO error: {0}")]
    Io(binrw::io::Error),
}

impl From<hex::FromHexError> for BeaconPackError {
    fn from(e: hex::FromHexError) -> Self {
        Self::Hex(e)
    }
}

impl From<binrw::io::Error> for BeaconPackError {
    fn from(e: binrw::io::Error) -> Self {
        Self::Io(e)
    }
}
