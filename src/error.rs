use thiserror::Error;

#[derive(Debug, Error)]
pub enum CoffeeLdrError {
    #[error("Memory allocation error: code {0}")]
    MemoryAllocationError(u32),

    #[error("Memory protection error: code {0}")]
    MemoryProtectionError(u32),
    
    #[error("Invalid symbol format: '{0}'")]
    InvalidSymbolFormat(String),

    #[error("Invalid relocation type: {0}")]
    InvalidRelocationType(u16),

    #[error("Failed to resolve symbol: '{0}'")]
    FunctionNotFound(String),

    #[error("Failed to resolve internal symbol: '{0}'")]
    FunctionInternalNotFound(String),

    #[error("Failed to resolve the module: '{0}'")]
    ModuleNotFound(String),

    #[error("Error loading COFF file.")]
    ParsingError,
    
    #[error("{0}")]
    CoffError(#[from] CoffError),

    #[error("Unsupported architecture. File expects {expected}, but current system is {actual}.")]
    ArchitectureMismatch {
        expected: String,
        actual: String,
    },

    #[error("Too many symbols in the COFF file. Maximum allowed is {0}.")]
    TooManySymbols(usize),

    #[error("Failed to parse symbol: '{0}'")]
    ParseError(String),

    #[error("Symbol ignored because it lacks the required prefix.")]
    SymbolIgnored,

    #[error("Error reading output")]
    OutputError,
}

#[derive(Debug, Error)]
pub enum CoffError {
    #[error("The file could not be read: {0}")]
    FileReadError(String),

    #[error("Invalid COFF file: Unable to read the COFF header.")]
    InvalidCoffFile,
    
    #[error("Invalid COFF file: Unable to read the COFF symbols.")]
    InvalidCoffSymbolsFile,

    #[error("Invalid COFF file: Unable to read the COFF section headers.")]
    InvalidCoffSectionFile,

    #[error("Unsupported architecture. Expected x64 or x32.")]
    UnsupportedArchitecture,

    #[error("Invalid number of sections or symbols.")]
    InvalidSectionsOrSymbols,

    #[error("Section limit exceeded: the number of sections exceeds the supported limit of 96.")]
    SectionLimitExceeded,
}
