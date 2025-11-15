use alloc::{
    boxed::Box,
    collections::BTreeMap,
    format,
    string::{String, ToString},
    vec::Vec,
};
use core::intrinsics::{
    volatile_copy_nonoverlapping_memory, 
    volatile_set_memory
};
use core::{
    ffi::c_void,
    mem::transmute,
    ptr::{
        null_mut, 
        read_unaligned, 
        write_unaligned
    },
};

use log::{debug, info, warn};
use obfstr::obfstr as s;
use dinvk::{dinvoke, pe::PE, data::NTSTATUS};
use dinvk::{
    NT_SUCCESS, NtProtectVirtualMemory,
    NtAllocateVirtualMemory, NtCurrentProcess,
    GetProcAddress, LoadLibraryA,
    GetModuleHandle, get_ntdll_address
};
use windows_sys::Win32::{
    Foundation::{GetLastError, STATUS_SUCCESS},
    System::{
        Memory::*,
        SystemServices::*,
        Diagnostics::Debug::*,
        LibraryLoader::DONT_RESOLVE_DLL_REFERENCES,
    },
};

use super::util::read_file;
use super::error::{
    CoffError, 
    CoffeeLdrError, 
    Result
};
use super::coff::{
    Coff, 
    CoffMachine,
    CoffSource, 
    IMAGE_RELOCATION,
    IMAGE_SYMBOL
};
use super::beacon::{
    get_function_internal_address, 
    get_output_data
};

/// Type alias for the COFF main input function.
type CoffMain = extern "C" fn(*mut u8, usize);

/// Represents a Rust interface to the COFF (Common Object File Format) files.
/// 
/// # Examples
///
/// ## Using a file as a source:
///
/// ```
/// use coffeeldr::CoffeeLdr;
///
/// let mut loader = CoffeeLdr::new("whoami.o");
/// match loader {
///     Ok(ldr) => {
///         println!("COFF successfully uploaded!");
///         // Use `ldr` to execute or process the COFF file
///     },
///     Err(e) => eprintln!("Error loading COFF: {:?}", e),
/// }
/// ```
///
/// ## Using a byte buffer as a source:
///
/// ```
/// use coffeeldr::CoffeeLdr;
///
/// let coff_data = include_bytes!("path/to/coff_file.o");
/// let mut loader = CoffeeLdr::new(&coff_data);
/// match loader {
///     Ok(ldr) => {
///         println!("COFF successfully loaded from buffer!");
///         // Use `ldr` to execute or process the COFF file
///     },
///     Err(e) => eprintln!("Error loading COFF: {:?}", e),
/// }
/// ```
#[derive(Default)]
pub struct CoffeeLdr<'a> {
    /// COFF structure representing the loaded file or buffer.
    coff: Coff<'a>,

    /// Vector mapping the allocated memory sections.
    section_map: Vec<SectionMap>,

    /// Map of functions [`CoffSymbol`].
    symbols: CoffSymbol,

    /// Indicates whether module stomping is enabled.
    stomping: bool,

    /// Name of the module to be stomped
    module: &'a str,
}

impl<'a> CoffeeLdr<'a> {
    /// Creates a new [`CoffeeLdr`] instance with the specified assembly buffer.
    ///
    /// # Arguments
    ///
    /// * `source` - A value convertible into [`CoffSource`], representing either a file path or a byte buffer.
    pub fn new<T: Into<CoffSource<'a>>>(source: T) -> Result<Self> {
        // Processes COFF based on the source (file or buffer)
        let coff = match source.into() {
            CoffSource::File(path) => {
                info!("Try to read the file: {path}");
                // Try reading the file
                let buffer = read_file(path)
                    .map_err(|_| CoffError::FileReadError(path.to_string()))?;

                // Creates the COFF object from the buffer
                Coff::from_slice(Box::leak(buffer.into_boxed_slice()))?
            }

            // Creates the COFF directly from the buffer
            CoffSource::Buffer(buffer) => Coff::from_slice(buffer)?,
        };

        Ok(Self {
            coff,
            section_map: Vec::new(),
            symbols: CoffSymbol::default(),
            ..Default::default()
        })
    }

    /// Enables module stomping for a specified module.
    pub fn with_module_stomping(mut self, module: &'a str) -> Self {
        self.stomping = true;
        self.module = module;
        self
    }

    /// Executes a COFF (Common Object File Format) file in memory.
    ///
    /// # Arguments
    ///
    /// * `entry` - A string slice representing the entry point of the COFF file.
    /// * `args` - Optional pointer to an argument list passed to the entry point.
    /// * `argc` - An optional `usize` representing the count of arguments passed through `args`.
    ///
    /// # Returns
    ///
    /// The output of the COFF file execution as a `String` if the execution succeeds.
    ///
    /// # Examples
    ///
    /// ```
    /// use coffeeldr::CoffeeLdr;
    ///  
    /// let mut coffee = CoffeeLdr::new("whoami.o").expect("CoffeeLdr Failed With Error");
    /// match coffee.run("go", None, None) {
    ///     Ok(result) => println!("[+] Coff executed: \n{result}"),
    ///     Err(err_code) => eprintln!("[!] Error: {:?}", err_code)
    /// }
    /// ```
    pub fn run(&mut self, entry: &str, args: Option<*mut u8>, argc: Option<usize>) -> Result<String> {
        info!("Preparing environment for COFF execution.");

        // Prepares the environment to execute the COFF file
        self.prepare()?;

        for symbol in &self.coff.symbols {
            let name = self.coff.get_symbol_name(symbol);
            if name == entry && Coff::is_fcn(symbol.Type) {
                info!("Running COFF file: entry point = {}, args = {:?}, argc = {:?}", name, args, argc);

                let section_addr = self.section_map[(symbol.SectionNumber - 1) as usize].base;
                let entrypoint = unsafe { section_addr.offset(symbol.Value as isize) };
                let coff_main: CoffMain = unsafe { transmute(entrypoint) };
                coff_main(args.unwrap_or(null_mut()), argc.unwrap_or(0));
                break;
            }
        }

        // Returns the output if available, otherwise, returns an empty response
        Ok(get_output_data()
            .filter(|o| !o.buffer.is_empty())
            .map(|o| o.to_string())
            .unwrap_or_default())
    }

    /// Prepares the environment for the execution of the COFF file.
    fn prepare(&mut self) -> Result<()> {
        // Verify that the COFF file's architecture.
        self.coff.arch.check_architecture()?;

        // Allocate memory for loading COFF sections and store the allocated section mappings.
        // If module stomping is enabled, overwrite the specified module in memory.
        // Otherwise, allocate standalone memory for the BOF payload.
        let mem = CoffMemory::new(&self.coff, self.stomping, self.module);
        let (sections, sec_base) = mem.alloc()?;
        self.section_map = sections;

        // Resolve external symbols (such as function addresses) and build a function lookup map.
        // When using module stomping, base resolution on the stomped module's memory address.
        let (functions, symbols) = CoffSymbol::new(&self.coff, self.stomping, sec_base)?;
        self.symbols = symbols;

        // Process relocations to correctly adjust symbol addresses based on memory layout.
        let reloc = CoffRelocation::new(&self.coff, &self.section_map);
        reloc.apply_relocations(&functions, &self.symbols)?;

        // Adjust memory permissions for allocated sections.
        self.section_map
            .iter_mut()
            .filter(|section| section.size > 0)
            .try_for_each(|section| section.adjust_permissions())?;

        Ok(())
    }
}

impl Drop for CoffeeLdr<'_> {
    fn drop(&mut self) {
        // It doesn't free anything, because we've blocked memory from another module.
        if self.stomping {
            return;
        }
        
        // Iterate over each section in the section map
        let mut size = 0;
        for section in self.section_map.iter_mut() {
            // Release memory if the base pointer is not null
            if !section.base.is_null() {
                NtFreeVirtualMemory(
                    NtCurrentProcess(),
                    &mut section.base,
                    &mut size,
                    MEM_RELEASE
                );
            }
        }

        // Release memory for the function map if the address pointer is not null
        if !self.symbols.address.is_null() {
            NtFreeVirtualMemory(
                NtCurrentProcess(),
                unsafe { &mut *self.symbols.address },
                &mut size,
                MEM_RELEASE
            );
        }
    }
}

/// Manages allocation and optional module stomping for COFF sections.
struct CoffMemory<'a> {
    /// Parsed COFF file to be loaded.
    coff: &'a Coff<'a>,

    /// Whether module stomping is enabled.
    stomping: bool,

    /// Name of the target module to stomp.
    module: &'a str,
}

impl<'a> CoffMemory<'a> {
    /// Creates a new `CoffMemory`.
    pub fn new(coff: &'a Coff<'a>, stomping: bool, module: &'a str) -> Self {
        Self {
            coff,
            stomping,
            module,
        }
    }

    /// Allocates memory for COFF sections.
    pub fn alloc(&self) -> Result<(Vec<SectionMap>, Option<*mut c_void>)> {
        if self.stomping {
            self.alloc_with_stomping()
        } else {
            self.alloc_bof_memory()
        }
    }

    /// Allocates new virtual memory for loading the sections of the COFF file.
    ///
    /// # Returns
    ///
    /// A tuple containing a vector of section mappings and `None` as no base address is reused.
    fn alloc_bof_memory(&self) -> Result<(Vec<SectionMap>, Option<*mut c_void>)> {
        let mut size = self.coff.size();
        let mut addr = null_mut();
        let status = NtAllocateVirtualMemory(
            NtCurrentProcess(), 
            &mut addr, 
            0, 
            &mut size, 
            MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN, 
            PAGE_READWRITE
        );
        
        if status != STATUS_SUCCESS {
            return Err(CoffeeLdrError::MemoryAllocationError(unsafe { GetLastError() }));
        }

        debug!("Memory successfully allocated for BOF at address: {:?}", addr);
        let (sections, _) = SectionMap::copy_sections(addr, self.coff);
        Ok((sections, None))
    }

    /// Overwrites an existing module's memory with the COFF payload (Module Stomping).
    ///
    /// This method locates the `.text` section of the specified module (from `self.module`)
    /// and changes its memory protection to writable. It then copies the COFF sections into
    /// that memory, effectively "stomping" the original module code.
    ///
    /// # Returns
    ///
    /// A tuple containing the section mappings and the base address.
    fn alloc_with_stomping(&self) -> Result<(Vec<SectionMap>, Option<*mut c_void>)> {
        let (mut text_address, mut size) = self.get_text_module()
            .ok_or(CoffeeLdrError::StompingTextSectionNotFound)?;

        // If the file is larger than the space inside the .text of the target module,
        // we do not stomp
        if self.coff.size() > size {
            return Err(CoffeeLdrError::StompingSizeOverflow);
        }

        let mut old = 0;
        if !NT_SUCCESS(NtProtectVirtualMemory(
            NtCurrentProcess(), 
            &mut text_address, 
            &mut size, 
            PAGE_READWRITE, 
            &mut old
        )) {
            return Err(CoffeeLdrError::MemoryProtectionError(unsafe { GetLastError() }));
        }

        // This is necessary because REL32 instructions must remain within range, and allocating the `Symbol`
        // elsewhere (e.g. with a distant `NtAllocateVirtualMemory`) could lead to crashes.
        //
        // Returning `Some(sec_base)` signals that the loader must re-use that exact memory area.
        debug!("Memory successfully allocated for BOF at address (Module Stomping): {:?}", text_address);
        let (sections, sec_base) = SectionMap::copy_sections(text_address, self.coff);
        Ok((sections, Some(sec_base)))
    }

    /// Locates the `.text` section of the specified module for stomping.
    ///
    /// Loads the target module without resolving imports (`DONT_RESOLVE_DLL_REFERENCES`)
    /// and parses its PE headers to find the `.text` section.
    ///
    /// # Returns
    ///
    /// A pointer to the start of the `.text` section and its size.
    fn get_text_module(&self) -> Option<(*mut c_void, usize)> {
        // Invoking LoadLibraryExA dynamically
        let target = format!("{}\0", self.module);
        let h_module = {
            let handle = GetModuleHandle(self.module, None);
            if handle.is_null() {
                LoadLibraryExA(
                    target.as_ptr(),
                    null_mut(),
                    DONT_RESOLVE_DLL_REFERENCES
                )?
            } else {
                handle
            }
        };

        if h_module.is_null() {
            return None;
        }

        // Retrieving `.text` from the target module
        let pe = PE::parse(h_module);
        let section = pe.section_by_name(s!(".text"))?;
        let ptr = (h_module as usize + section.VirtualAddress as usize) as *mut c_void;
        let size = section.SizeOfRawData as usize;

        Some((ptr, size))
    }
}

/// Maximum number of symbols that the function map can handle.
const MAX_SYMBOLS: usize = 600;

/// Represents a mapping of external symbols (functions) to their memory addresses.
#[derive(Debug, Clone, Copy)]
struct CoffSymbol {
    /// A pointer to an array of pointers, each pointing to an external function.
    address: *mut *mut c_void,
}

impl CoffSymbol {
    /// Creates a new `CoffSymbol`.
    pub fn new(
        coff: &Coff,
        stomping: bool,
        base_addr: Option<*mut c_void>,
    ) -> Result<(BTreeMap<String, usize>, Self)> {
        // Resolves the symbols of the coff file
        let symbols = Self::process_symbols(coff)?;
        
        // When stomping, we must reuse the memory at `base_addr`.
        let address = if stomping {
            let addr = base_addr.ok_or(CoffeeLdrError::MissingStompingBaseAddress)?;
            addr as *mut *mut c_void
        } else {
            let mut size = MAX_SYMBOLS * size_of::<*mut c_void>();
            let mut addr = null_mut();
            let status = NtAllocateVirtualMemory(
                NtCurrentProcess(),
                &mut addr,
                0,
                &mut size,
                MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN,
                PAGE_READWRITE,
            );

            if addr.is_null() || status != STATUS_SUCCESS {
                return Err(CoffeeLdrError::MemoryAllocationError(unsafe { GetLastError() }));
            }

            addr as *mut *mut c_void
        };

        Ok((symbols, Self { address }))
    }

    /// Processes the external symbols in the COFF file and resolves their addresses.
    ///
    /// # Arguments
    ///
    /// * `coff` - A reference to the COFF file whose symbols are to be processed.
    ///
    /// # Returns
    ///
    /// A map of symbol names to their resolved addresses.
    fn process_symbols(coff: &Coff) -> Result<BTreeMap<String, usize>> {
        let mut functions = BTreeMap::new();

        for symbol in &coff.symbols {
            if functions.len() >= MAX_SYMBOLS {
                return Err(CoffeeLdrError::TooManySymbols(functions.len()));
            }

            if symbol.StorageClass == IMAGE_SYM_CLASS_EXTERNAL as u8 && symbol.SectionNumber == 0 {
                let name = coff.get_symbol_name(symbol);
                let address = Self::resolve_symbol_address(&name, coff)?;
                functions.insert(name, address);
            }
        }

        Ok(functions)
    }

    /// Resolves the address of a symbol by looking it up in the appropriate DLL.
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the symbol to resolve.
    /// * `coff` - A reference to the COFF file (used to determine the architecture).
    ///
    /// # Returns
    ///
    /// The resolved address of the symbol.
    fn resolve_symbol_address(name: &str, coff: &Coff) -> Result<usize> {
        debug!("Attempting to resolve address for symbol: {}", name);
        let prefix = match coff.arch {
            CoffMachine::X64 => "__imp_",
            CoffMachine::X32 => "__imp__",
        };

        let symbol_name = name
            .strip_prefix(prefix)
            .map_or_else(|| Err(CoffeeLdrError::SymbolIgnored), Ok)?;

        if symbol_name.starts_with(s!("Beacon")) || symbol_name.starts_with(s!("toWideChar")) {
            debug!("Resolving Beacon: {}", symbol_name);
            return get_function_internal_address(symbol_name);
        }

        let (dll, mut function) = symbol_name
            .split_once('$')
            .ok_or_else(|| CoffeeLdrError::ParseError(symbol_name.to_string()))?;

        if let CoffMachine::X32 = coff.arch {
            function = function.split('@').next().unwrap_or(function);
        }

        debug!("Resolving Module {} and Function {}", dll, function);
        let module = {
            let mut handle = GetModuleHandle(dll.to_string(), None);
            if handle.is_null() {
                handle = LoadLibraryA(dll);
                if handle.is_null() {
                    return Err(CoffeeLdrError::ModuleNotFound(dll.to_string()));
                }

                handle
            } else {
                handle
            }
        };

        let addr = GetProcAddress(module, function, None);
        if addr.is_null() {
            Err(CoffeeLdrError::FunctionNotFound(symbol_name.to_string()))
        } else {
            Ok(addr as usize)
        }
    }
}

impl Default for CoffSymbol {
    fn default() -> Self {
        Self { address: null_mut() }
    }
}

/// Structure that maps a section of memory, containing the base, size and characteristics.
#[derive(Debug, Clone)]
struct SectionMap {
    /// Base address of the section.
    pub base: *mut c_void,

    /// Section size in bytes.
    pub size: usize,

    /// Section characteristics (e.g. execute, read, write permissions).
    pub characteristics: u32,

    /// Section name.
    pub name: String,
}

impl SectionMap {
    /// Copies the sections of the COFF file to the allocated memory.
    ///
    /// # Arguments
    ///
    /// * `virt_addr` - Virtual memory address where the sections will be copied.
    /// * `coff` - Coff structure that will take the information from the sections.
    ///
    /// # Returns
    ///
    /// A vector containing the mapping of each section.
    fn copy_sections(virt_addr: *mut c_void, coff: &Coff) -> (Vec<SectionMap>, *mut c_void) {
        unsafe {
            let sections = &coff.sections;
            let mut base = virt_addr;
            let sections = sections
                .iter()
                .map(|section| {
                    let size = section.SizeOfRawData as usize;
                    let name = Coff::get_section_name(section);
                    let address = coff.buffer.as_ptr().add(section.PointerToRawData as usize);

                    if section.PointerToRawData != 0 {
                        debug!("Copying section: {}", name);
                        volatile_copy_nonoverlapping_memory(base as *mut u8, address.cast_mut(), size);
                    } else {
                        volatile_set_memory(address.cast_mut(), 0, size);
                    }

                    let section_map = SectionMap {
                        base,
                        size,
                        characteristics: section.Characteristics,
                        name,
                    };
                    base = Coff::page_align((base as usize) + size) as *mut c_void;

                    section_map
                })
                .collect();

            (sections, base)
        }
    }

    /// Set the memory permissions for each section loaded.
    fn adjust_permissions(&mut self) -> Result<()> {
        info!(
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
            warn!("Unknown protection, using PAGE_EXECUTE_READWRITE");
            PAGE_EXECUTE_READWRITE
        };

        if (protection & IMAGE_SCN_MEM_NOT_CACHED) == IMAGE_SCN_MEM_NOT_CACHED {
            protection |= PAGE_NOCACHE;
        }

        let mut old = 0;
        if !NT_SUCCESS(NtProtectVirtualMemory(
            NtCurrentProcess(), 
            &mut self.base, 
            &mut self.size, 
            protection, 
            &mut old
        )) {
            return Err(CoffeeLdrError::MemoryProtectionError(unsafe { GetLastError() }));
        }

        Ok(())
    }
}

/// Handles relocation of symbols for COFF sections.
struct CoffRelocation<'a> {   
    /// Reference to the parsed COFF object containing sections and symbols.
    coff: &'a Coff<'a>,

    /// List of mapped sections in memory, used to compute relocation targets.
    section_map: &'a [SectionMap],
}

impl<'a> CoffRelocation<'a> {
    /// Creates a new `CoffRelocation`.
    pub fn new(coff: &'a Coff, section_map: &'a [SectionMap]) -> Self {
        Self { coff, section_map }
    }

    /// Applies relocations for all sections.
    ///
    /// # Arguments
    /// 
    /// * `functions` - Map of resolved symbol names to their function addresses.
    /// * `symbols` - Pointer to the symbol table in memory.
    ///
    /// # Errors
    /// 
    /// Returns an error if any relocation type is invalid or unsupported.
    pub fn apply_relocations(
        &self,
        functions: &BTreeMap<String, usize>,
        symbols: &CoffSymbol
    ) -> Result<()> {
        let mut index = 0;
        for (i, section) in self.coff.sections.iter().enumerate() {
            // Retrieve relocation entries for the current section.
            let relocations = self.coff.get_relocations(section);
            for relocation in relocations.iter() {
                // Look up the symbol associated with the relocation.
                let symbol = &self.coff.symbols[relocation.SymbolTableIndex as usize];

                // Compute the address where the relocation should be applied.
                let symbol_reloc_addr = (self.section_map[i].base as usize 
                    + unsafe { relocation.Anonymous.VirtualAddress } as usize) as *mut c_void;

                // Retrieve the symbol's name (used for function lookups).
                let name = self.coff.get_symbol_name(symbol);
                if let Some(function_address) = functions.get(&name).map(|&addr| addr as *mut c_void) {
                    unsafe {
                        symbols
                            .address
                            .add(index)
                            .write_volatile(function_address);

                        // Apply the relocation using the resolved function address.
                        self.process_relocations(
                            symbol_reloc_addr, 
                            function_address, 
                            symbols.address.add(index), 
                            relocation, 
                            symbol
                        )?;
                    };

                    index += 1;
                } else {
                    // Apply the relocation but without a resolved function address (null pointer).
                    self.process_relocations(
                        symbol_reloc_addr, 
                        null_mut(), 
                        null_mut(), 
                        relocation, 
                        symbol
                    )?;
                }
            }
        }

        Ok(())
    }

    /// Applies a single relocation entry.
    ///
    /// # Arguments
    ///
    /// * `reloc_addr` - Memory address where relocation applies.  
    /// * `function_address` - Resolved function or symbol address (can be null).  
    /// * `symbols` - Function map pointer used for external symbols.  
    /// * `relocation` - COFF relocation entry (`IMAGE_RELOCATION`).  
    /// * `symbol` - Symbol associated with this relocation (`IMAGE_SYMBOL`).  
    ///
    /// # Errors
    /// 
    /// Returns `InvalidRelocationType` if relocation type is unsupported.
    fn process_relocations(
        &self, 
        reloc_addr: *mut c_void, 
        function_address: *mut c_void, 
        symbols: *mut *mut c_void, 
        relocation: &IMAGE_RELOCATION, 
        symbol: &IMAGE_SYMBOL
    ) -> Result<()> {
        debug!(
            "Processing relocation: Type = {}, Symbol Type = {}, StorageClass = {}, Section Number: {}", 
            relocation.Type, symbol.Type, symbol.StorageClass, symbol.SectionNumber
        );

        unsafe {
            if symbol.StorageClass == IMAGE_SYM_CLASS_EXTERNAL as u8 && symbol.SectionNumber == 0 {
                match self.coff.arch {
                    CoffMachine::X64 =>  {
                        if relocation.Type as u32 == IMAGE_REL_AMD64_REL32 && !function_address.is_null() {
                            let relative_address = (symbols as usize)
                                .wrapping_sub(reloc_addr as usize)
                                .wrapping_sub(size_of::<u32>());

                            write_unaligned(reloc_addr as *mut u32, relative_address as u32);
                            return Ok(())
                        }
                    },
                    CoffMachine::X32 => {
                        if relocation.Type as u32 == IMAGE_REL_I386_DIR32 && !function_address.is_null() {
                            write_unaligned(reloc_addr as *mut u32, symbols as u32);
                            return Ok(())
                        }
                    }
                }
            }

            let section_addr = self.section_map[(symbol.SectionNumber - 1) as usize].base;
            match self.coff.arch {
                CoffMachine::X64 => {
                    match relocation.Type as u32 {
                        IMAGE_REL_AMD64_ADDR32NB if function_address.is_null() => {
                            write_unaligned(
                                reloc_addr as *mut u32,
                                read_unaligned(reloc_addr as *mut u32)
                                    .wrapping_add((section_addr as usize)
                                        .wrapping_sub(reloc_addr as usize)
                                        .wrapping_sub(size_of::<u32>()) as u32
                                ),
                            );
                        },
                        IMAGE_REL_AMD64_ADDR64 if function_address.is_null() => {
                            write_unaligned(
                                reloc_addr as *mut u64,
                                read_unaligned(reloc_addr as *mut u64)
                                    .wrapping_add(section_addr as u64),
                            );
                        },
                        r @ IMAGE_REL_AMD64_REL32..=IMAGE_REL_AMD64_REL32_5 => {
                            write_unaligned(
                                reloc_addr as *mut u32,
                                read_unaligned(reloc_addr as *mut u32)
                                    .wrapping_add((section_addr as usize)
                                        .wrapping_sub(reloc_addr as usize)
                                        .wrapping_sub(size_of::<u32>())
                                        .wrapping_sub((r - 4) as usize) as u32
                                    ),
                            );
                        },
                        _ => return Err(CoffeeLdrError::InvalidRelocationType(relocation.Type))
                    }
                },
                CoffMachine::X32 => {
                    match relocation.Type as u32 {
                        IMAGE_REL_I386_REL32 if function_address.is_null() => {
                            write_unaligned(
                                reloc_addr as *mut u32,
                                read_unaligned(reloc_addr as *mut u32)
                                    .wrapping_add((section_addr as usize)
                                    .wrapping_sub(reloc_addr as usize)
                                    .wrapping_sub(size_of::<u32>()) as u32
                                )
                            );
                        },
                        IMAGE_REL_I386_DIR32 if function_address.is_null() => {
                            write_unaligned(
                                reloc_addr as *mut u32,
                                read_unaligned(reloc_addr as *mut u32)
                                    .wrapping_add(section_addr as u32)
                            );
                        },
                        _ => return Err(CoffeeLdrError::InvalidRelocationType(relocation.Type))
                    }
                }
            }
        }

        Ok(())
    }
}

#[inline]
fn NtFreeVirtualMemory(
    process_handle: *mut c_void, 
    base_address: *mut *mut c_void, 
    region_size: *mut usize, 
    free_type: u32
) {
    dinvoke!(
        get_ntdll_address(),
        s!("NtFreeVirtualMemory"),
        unsafe extern "system" fn(
            process_handle: *mut c_void,
            base_address: *mut *mut c_void,
            region_size: *mut usize,
            free_type: u32,
        ) -> NTSTATUS,
        process_handle,
        base_address,
        region_size,
        free_type
    );
}

#[inline]
fn LoadLibraryExA(
    lp_lib_file_name: *const u8, 
    h_file: *mut c_void, 
    dw_flags: u32
) -> Option<*mut c_void> {
    let kernel32 = GetModuleHandle(2808682670u32, Some(dinvk::hash::murmur3));
    dinvoke!(
        kernel32,
        s!("LoadLibraryExA"),
        unsafe extern "system" fn(
            lp_lib_file_name: *const u8,
            h_file: *mut c_void,
            dw_flags: u32,
        ) -> *mut c_void,
        lp_lib_file_name,
        h_file,
        dw_flags
    )
}