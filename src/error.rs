use thiserror::Error;

/// Represents errors that can occur during the loading and handling of COFF (Common Object File Format) files.
#[derive(Debug, Error)]
pub enum CoffeeLdrError {
    /// Occurs when memory allocation fails.
    ///
    /// # Arguments
    /// 
    /// * `{0}` - The error code returned during the memory allocation attempt.
    #[error("Memory allocation error: code {0}")]
    MemoryAllocationError(u32),

    /// Occurs when there is a failure in setting memory protection for a region.
    ///
    /// # Arguments
    /// 
    /// * `{0}` - The error code returned during the memory protection operation.
    #[error("Memory protection error: code {0}")]
    MemoryProtectionError(u32),
    
    /// Represents an error when a symbol in the COFF file has an invalid format.
    ///
    /// # Arguments
    /// 
    /// * `{0}` - The symbol string that is considered invalid.
    #[error("Invalid symbol format: '{0}'")]
    InvalidSymbolFormat(String),

    /// Raised when a relocation entry in the COFF file has an unsupported or invalid type.
    ///
    /// # Arguments
    /// 
    /// * `{0}` - The invalid relocation type encountered.
    #[error("Invalid relocation type: {0}")]
    InvalidRelocationType(u16),

    /// Occurs when a required symbol (function) is not found during symbol resolution.
    ///
    /// # Arguments
    /// 
    /// * `{0}` - The name of the symbol (function) that was not found.
    #[error("Failed to resolve symbol: '{0}'")]
    FunctionNotFound(String),

    /// Raised when an internal symbol (used by the COFF loader itself) cannot be resolved.
    ///
    /// # Arguments
    /// 
    /// * `{0}` - The name of the internal symbol that was not found.
    #[error("Failed to resolve internal symbol: '{0}'")]
    FunctionInternalNotFound(String),

    /// Raised when the specified module is not found during module resolution.
    ///
    /// # Arguments
    /// 
    /// * `{0}` - The name of the module that could not be found.
    #[error("Failed to resolve the module: '{0}'")]
    ModuleNotFound(String),

    /// Raised when the COFF file cannot be parsed correctly.
    #[error("Error loading COFF file.")]
    ParsingError,
    
    /// Propagates errors from the `CoffError` type, which represent issues specifically with COFF file handling.
    ///
    /// # Arguments
    /// 
    /// * `{0}` - The `CoffError` instance that caused the failure.
    #[error("{0}")]
    CoffError(#[from] CoffError),

    /// Raised when there is a mismatch between the expected and actual system architecture.
    ///
    /// # Arguments
    /// 
    /// * `expected` - The architecture the file expects (e.g., x64).
    /// * `actual` - The architecture of the current system (e.g., x32).
    #[error("Unsupported architecture. File expects {expected}, but current system is {actual}.")]
    ArchitectureMismatch {
        expected: &'static str,
        actual: &'static str,
    },

    /// Raised when the COFF file contains more symbols than allowed.
    ///
    /// # Arguments
    /// 
    /// * `{0}` - The number of symbols encountered, exceeding the limit.
    #[error("Too many symbols in the COFF file. Maximum allowed is {0}.")]
    TooManySymbols(usize),

    /// Raised when a symbol cannot be parsed correctly.
    ///
    /// # Arguments
    /// 
    /// * `{0}` - The name of the symbol that caused the parsing failure.
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
    ///
    /// # Arguments
    /// 
    /// * `{0}` - A message describing the file read error.
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
