//! Error types for the COFF loader.

use alloc::string::String;

/// Alias for results.
pub type Result<T> = core::result::Result<T, Error>;

/// Errors that can occur during COFF loading and execution.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Error returned by the `binrw`.
    #[error("binrw error: {0}")]
    Binrw(binrw::Error),
    /// Hexadecimal encoding or decoding failure.
    #[error("hex error: {0}")]
    Hex(hex::FromHexError),
    /// I/O read or write failure.
    #[error("io error: {0}")]
    Io(binrw::io::Error),
    #[error("dynamic error: {0}")]
    Dyn(#[from] dinvk::error::Error),
    /// Memory allocation failure.
    #[error("memory allocation error: code {0}")]
    MemoryAllocationError(u32),
    /// Memory protection or permission failure.
    #[error("memory protection error: code {0}")]
    MemoryProtectionError(u32),
    /// Invalid or malformed symbol format.
    #[error("invalid symbol format: '{0}'")]
    InvalidSymbolFormat(String),
    /// Unsupported relocation type.
    #[error("invalid relocation type: {0}")]
    InvalidRelocationType(u16),
    /// Symbol not found during resolution.
    #[error("symbol not found: '{0}'")]
    FunctionNotFound(String),
    /// Internal symbol could not be resolved.
    #[error("internal symbol not found: '{0}'")]
    FunctionInternalNotFound(String),
    /// Target module could not be resolved.
    #[error("module not found: '{0}'")]
    ModuleNotFound(String),
    /// Failed to parse or load COFF file.
    #[error("error loading COFF file")]
    ParsingError,
    /// Architecture mismatch between file and host.
    #[error("arch mismatch: expected {expected}, actual {actual}")]
    ArchitectureMismatch { expected: &'static str, actual: &'static str },
    /// File contains more symbols than supported.
    #[error("too many symbols (max {0})")]
    TooManySymbols(usize),
    /// Failed to parse symbol entry.
    #[error("symbol parse error: '{0}'")]
    ParseError(String),
    /// Symbol ignored due to missing required prefix.
    #[error("symbol ignored (missing required prefix)")]
    SymbolIgnored,
    /// Error reading or flushing output buffer.
    #[error("output read error")]
    OutputError,
    /// `.text` section could not be located.
    #[error("missing .text section in target module")]
    StompingTextSectionNotFound,
    /// COFF too large to overwrite target module.
    #[error("stomping size overflow")]
    StompingSizeOverflow,
    /// Missing base address during module stomping.
    #[error("missing base address for target section")]
    MissingStompingBaseAddress,
    /// File path contains a null byte.
    #[error("null byte in file path")]
    NullByteInPath,
    /// Failed to open file.
    #[error("failed to open file: code {0}")]
    FileOpenError(u32),
    /// Invalid file size returned by the system.
    #[error("invalid file size: code {0}")]
    InvalidFileSize(u32),
    /// File could not be opened or read.
    #[error("file read error: {0}")]
    FileReadError(String),
    /// COFF header is invalid or missing.
    #[error("invalid COFF header")]
    InvalidCoffFile,
    /// COFF symbol table could not be read.
    #[error("invalid COFF symbols")]
    InvalidCoffSymbolsFile,
    /// COFF section headers are invalid or missing.
    #[error("invalid COFF section headers")]
    InvalidCoffSectionFile,
    /// Architecture not supported (expected x64 or x86).
    #[error("unsupported architecture")]
    UnsupportedArchitecture,
    /// Invalid section or symbol count.
    #[error("invalid number of sections or symbols")]
    InvalidSectionsOrSymbols,
    /// Section count exceeds supported limit.
    #[error("section limit exceeded (max 96)")]
    SectionLimitExceeded,
    /// Relocation address not properly aligned.
    #[error("misaligned relocation")]
    MisalignedRelocation,
}

impl From<hex::FromHexError> for Error {
    fn from(err: hex::FromHexError) -> Self {
        Error::Hex(err)
    }
}

impl From<binrw::io::Error> for Error {
    fn from(err: binrw::io::Error) -> Self {
        Error::Binrw(binrw::Error::Io(err))
    }
}
