use {
    log::{debug, info, warn},
    crate::{
        error::{CoffError, CoffeeLdrError}, 
        parser::{
            Coff, CoffMachine, CoffSource,
            IMAGE_RELOCATION, IMAGE_SYMBOL
        },
        beacon::{
            get_output_data,
            get_function_internal_address, 
        },
    },
    std::{
        cell::RefCell,
        ffi::c_void, 
        mem::transmute,
        collections::HashMap,
        ptr::{
            null_mut, read_unaligned,
            write_unaligned, copy_nonoverlapping,
        },
    }, 
};

use windows_sys::Win32::{
    Foundation::GetLastError, 
    System::{
        LibraryLoader::{GetModuleHandleA, GetProcAddress, LoadLibraryA},
        Diagnostics::Debug::{
            IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_NOT_CACHED, 
            IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE
        }, 
        SystemServices::{
            IMAGE_REL_AMD64_ADDR32NB, IMAGE_REL_AMD64_ADDR64, 
            IMAGE_REL_AMD64_REL32, IMAGE_REL_AMD64_REL32_5, 
            IMAGE_REL_I386_DIR32, IMAGE_REL_I386_REL32, 
            IMAGE_SYM_CLASS_EXTERNAL, MEM_TOP_DOWN
        },
        Memory::{
            VirtualAlloc, VirtualFree, VirtualProtect,
            PAGE_EXECUTE_READWRITE, PAGE_EXECUTE, PAGE_EXECUTE_READ, 
            PAGE_EXECUTE_WRITECOPY, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, 
            PAGE_READWRITE, PAGE_NOACCESS, PAGE_READONLY, PAGE_WRITECOPY, 
            PAGE_NOCACHE
        },
    }
};

/// Type alias for the COFF main input function, which receives a pointer to data and the size of the data.
type CoffMain = fn(*mut u8, usize);

/// Main structure for loading and executing COFF (Common Object File Format) files.
pub struct CoffeeLdr<'a> {
    /// COFF structure representing the loaded file or buffer.
    coff: Coff<'a>,
    
    /// Vector mapping the allocated memory sections.
    section_map: RefCell<Vec<SectionMap>>,

    /// Map of functions `FunctionMap`.
    function_map: RefCell<FunctionMap>
}

impl<'a> Default for CoffeeLdr<'a> {
    /// Provides a default-initialized `CoffeeLdr`.
    ///
    /// # Returns
    ///
    /// - `Self`: A default-initialized `CoffeeLdr`.
    fn default() -> Self {
        Self {
            coff: Coff::default(),
            section_map: RefCell::new(Vec::new()),
            function_map: RefCell::new(FunctionMap::default())
        }
    }
}

impl<'a> CoffeeLdr<'a> {
    /// Creates a new `CoffeeLdr` instance from a given COFF source.
    ///
    /// # Arguments
    ///
    /// - `source`: A generic input that can be either a file or a memory buffer containing the COFF data. 
    ///   This is converted into a `CoffSource`.
    ///
    /// # Returns
    ///
    /// - `Result<Self, CoffeeLdrError>`: Returns a new instance of `CoffeeLdr` if the COFF source is successfully processed, 
    ///   or an error of type `CoffeeLdrError` if initialization fails.
    /// 
    /// # Examples
    ///
    /// ## Using a file as a source:
    /// ```ignore
    /// use coffeeldr::CoffeeLdr;
    ///
    /// let loader = CoffeeLdr::new("whoami.o");
    /// match loader {
    ///     Ok(ldr) => {
    ///         println!("COFF successfully uploaded!");
    ///         // Use `ldr` to execute or process the COFF file
    ///     },
    ///     Err(e) => println!("Error loading COFF: {:?}", e),
    /// }
    /// ```
    ///
    /// ## Using a byte buffer as a source:
    /// ```ignore
    /// use coffeeldr::CoffeeLdr;
    ///
    /// let coff_data = include_bytes!("path/to/coff_file.o");
    /// let loader = CoffeeLdr::new(&coff_data);
    /// match loader {
    ///     Ok(ldr) => {
    ///         println!("COFF successfully loaded from buffer!");
    ///         // Use `ldr` to execute or process the COFF file
    ///     },
    ///     Err(e) => println!("Error loading COFF: {:?}", e),
    /// }
    /// ```
    pub fn new<T: Into<CoffSource<'a>>>(source: T) -> Result<Self, CoffeeLdrError> {
        // Processes COFF based on the source (file or buffer)
        let coff = match source.into() {
            CoffSource::File(path) => {
                info!("Try to read the file: {path}");
                // Try reading the file
                let buffer = std::fs::read(path).map_err(|_| CoffError::FileReadError(path.to_string()))?;
                
                // Creates the COFF object from the buffer
                Coff::from_buffer(Box::leak(buffer.into_boxed_slice()))?
            }
            // Creates the COFF directly from the buffer
            CoffSource::Buffer(buffer) => Coff::from_buffer(buffer)?,
        };

        // Returns the new `CoffeeLdr` object
        Ok(Self {
            coff,
            section_map: RefCell::new(Vec::new()),
            function_map: RefCell::new(FunctionMap::default())
        })
    }

    /// Executes a COFF (Common Object File Format) file in memory.
    /// 
    /// # Arguments
    /// 
    /// - `entry`: A string slice representing the entry point of the COFF file. This is the symbol name where execution begins.
    /// - `args`: Optional pointer to an argument list (`*mut u8`) passed to the entry point. If `None`, no arguments are passed.
    /// - `argc`: An optional `usize` representing the count of arguments passed through `args`. If `None`, the argument count is considered zero.
    /// 
    /// # Returns
    /// 
    /// - `Result<(), CoffeeLdrError>`: On success, returns `Ok(())`. If an error occurs during the execution of the COFF file, 
    ///   it returns an appropriate `CoffeeLdrError`.
    ///
    /// # Examples
    /// 
    /// ```ignore
    /// use coffeeldr::CoffeeLdr;
    ///  
    /// let coffee = CoffeeLdr::new("whoami.o").expect("CoffeeLdr Failed With Error");
    /// match coffee.run("go", None, None) {
    ///     Ok(result) => println!("[+] Coff executed!: \n{result}"),
    ///     Err(err_code) => println!("[!] Error: {:?}", err_code)
    /// }
    /// ```
    pub fn run(&self, entry: &str, args: Option<*mut u8>, argc: Option<usize>) -> Result<String, CoffeeLdrError> {
        info!("Preparing environment for COFF execution.");

        // Prepares the environment to execute the COFF file
        self.prepare()?;

        for symbol in &self.coff.symbols {
            let name = self.coff.get_symbol_name(symbol);
            if name == entry && Coff::is_fcn(symbol.Type) {
                info!("Running COFF file: entry point = {}, args = {:?}, argc = {:?}", name, args, argc);

                let section_addr = self.section_map.borrow()[(symbol.SectionNumber - 1) as usize].base;
                let entrypoint = unsafe { section_addr.offset(symbol.Value as isize) };
                let coff_main: CoffMain = unsafe { transmute(entrypoint) };
                coff_main(args.unwrap_or(null_mut()), argc.unwrap_or(0));
                break;
            }
        }

        // Returns the output if available, otherwise, returns an empty response
        let beacon_output = get_output_data();
        if !beacon_output.buffer.is_empty() {
            Ok(beacon_output.to_string())
        } else {
            Ok(String::new())
        }
    }
    
    /// Prepares the environment for the execution of the COFF file, allocating memory and resolving relocations.
    ///
    /// # Returns
    ///
    /// - `Result<(), CoffeeLdrError>`: Returns `Ok(())` in case of success or a specific error in case of failure.
    fn prepare(&self) -> Result<(), CoffeeLdrError> {

        // Checks that the COFF architecture is compatible with the system
        self.check_architecture()?;

        // Allocates memory to load the COFF sections
        let allocated_sections = self.alloc_bof_memory()?;
        self.section_map.replace(allocated_sections);
        
        // Resolves external symbols (functions) and maps them to their memory addresses
        let (functions, function_map) = FunctionMap::new(&self.coff)?;
        self.function_map.replace(function_map);

        // Processes relocations to adjust addresses based on symbols
        let mut index = 0;
        for (i, section) in self.coff.sections.iter().enumerate() {
            let relocations = self.coff.get_relocations(section);

            for relocation in relocations.iter() {
                let symbol = &self.coff.symbols[relocation.SymbolTableIndex as usize];       
                let symbol_reloc_addr = (self.section_map.borrow()[i].base as usize +  unsafe { relocation.Anonymous.VirtualAddress } as usize) as *mut c_void;
                
                let name = self.coff.get_symbol_name(symbol); 
                if let Some(function_address) = functions.get(&name).copied() {
                    unsafe { 
                        let function_address = function_address as *mut c_void;
                        let address = self.function_map.borrow().address.add(index); 
                        address.write(function_address);

                        self.process_relocation(symbol_reloc_addr, function_address, address, relocation, symbol)?;
                    };
                    
                    index += 1;
                } else {
                    self.process_relocation(symbol_reloc_addr, null_mut(), null_mut(), relocation, symbol)?;
                }
            }
        }

        // Adjusts the memory permissions of the allocated sections
        self.adjust_permissions()?;

        Ok(())
    }

    /// Processes the relocation of symbols in a COFF (Common Object File Format) file.
    ///
    /// # Arguments
    ///
    /// - `reloc_addr`: A pointer to the location in memory where the relocation will be applied.
    /// - `function_address`: The address of the function or symbol being relocated, or `null` if not applicable.
    /// - `function_map`: A pointer to the function map, used when resolving external symbols.
    /// - `relocation`: A reference to the `IMAGE_RELOCATION` struct, which contains the relocation entry details.
    /// - `symbol`: A reference to the `IMAGE_SYMBOL` struct, representing the symbol being relocated.
    ///
    /// # Returns
    ///
    /// - `Result<(), CoffeeLdrError>`: Returns `Ok(())` if the relocation was successfully processed, 
    ///   or an error if an unsupported or invalid relocation type is encountered.
    fn process_relocation(
        &self, 
        reloc_addr: *mut c_void, 
        function_address: *mut c_void, 
        function_map: *mut *mut c_void, 
        relocation: &IMAGE_RELOCATION, 
        symbol: &IMAGE_SYMBOL
    ) -> Result<(), CoffeeLdrError> {
        debug!("Processing relocation: Type = {}, Symbol Type = {}, StorageClass = {}", relocation.Type, symbol.Type, symbol.StorageClass);

        unsafe {
            if symbol.StorageClass == IMAGE_SYM_CLASS_EXTERNAL as u8 && symbol.SectionNumber == 0 {
                match self.coff.arch {
                    CoffMachine::X64 =>  {
                        if relocation.Type as u32 == IMAGE_REL_AMD64_REL32 && !function_address.is_null() {
                            let relative_address = (function_map as usize)
                                .wrapping_sub(reloc_addr as usize)
                                .wrapping_sub(size_of::<u32>());
                            
                            write_unaligned(reloc_addr as *mut u32, relative_address as u32);
                            return Ok(())
                        }
                    },
                    CoffMachine::X32 => {
                        if relocation.Type as u32 == IMAGE_REL_I386_DIR32 && !function_address.is_null() {
                            write_unaligned(reloc_addr as *mut u32, function_map as u32);
                            return Ok(())
                        }
                    }
                }
            }

            let section_addr = self.section_map.borrow()[(symbol.SectionNumber - 1) as usize].base;
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

    /// Set the memory permissions for each section loaded.
    ///
    /// # Returns
    ///
    /// - `Result<(), CoffeeLdrError>`: Returns `Ok(())` if successful or an error if there was a problem adjusting the permissions.
    fn adjust_permissions(&self) -> Result<(), CoffeeLdrError> {
        self.section_map.borrow()
            .iter()
            .filter(|section| section.size > 0)
            .try_for_each(|section| section.adjust_permissions())
    }

    /// Allocates memory for loading the sections of the COFF file.
    ///
    /// # Returns
    ///
    /// - `Result<Vec<SectionMap>, CoffeeLdrError>`: A vector of loaded `SectionMap` structs, or an error if memory allocation fails.
    fn alloc_bof_memory(&self) -> Result<Vec<SectionMap>, CoffeeLdrError> {
        let size = self.coff.size();
        let address = unsafe {
            VirtualAlloc(
                null_mut(),
                size,
                MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN,
                PAGE_READWRITE,
            )
        };

        if address.is_null() {
            return Err(CoffeeLdrError::MemoryAllocationError(unsafe { GetLastError() }));
        }

        debug!("Memory successfully allocated for BOF at address: {:?}", address);
        Ok(SectionMap::copy_sections(address, &self.coff))
    }

    /// Checks if the COFF file's architecture matches the architecture of the system.
    /// 
    /// # Returns
    /// 
    /// - `Result<(), CoffeeLdrError>`: `Ok(())` if the architecture matches the system, or an error if it is not supported.
    #[inline] 
    fn check_architecture(&self) -> Result<(), CoffeeLdrError> {
        match self.coff.arch {
            CoffMachine::X32 => {
                if cfg!(target_pointer_width = "64") {
                    return Err(CoffeeLdrError::ArchitectureMismatch {
                        expected: "x32".to_string(),
                        actual: "x64".to_string(),
                    });
                }
            }
            CoffMachine::X64 => {
                if cfg!(target_pointer_width = "32") {
                    return Err(CoffeeLdrError::ArchitectureMismatch {
                        expected: "x64".to_string(),
                        actual: "x32".to_string(),
                    });
                }
            }
        }

        Ok(())
    }
}

/// Implements the `Drop` trait to release memory when `CoffeeLdr` goes out of scope.
impl<'a> Drop for CoffeeLdr<'a> {
    fn drop(&mut self) {
        for section in self.section_map.borrow().iter() {
            if !section.base.is_null() {
                unsafe {
                    VirtualFree(section.base, 0, MEM_RELEASE);
                }
            }
        }

        if !self.function_map.borrow().address.is_null() {
            unsafe {
                VirtualFree(*self.function_map.borrow().address, 0, MEM_RELEASE);
            }
        }
    }
}

/// Maximum number of symbols that the function map can handle.
const MAX_SYMBOLS: usize = 600;

/// Represents a mapping of external symbols (functions) to their memory addresses.
#[derive(Debug)]
struct FunctionMap {
    /// A pointer to an array of pointers, each pointing to an external function.
    address: *mut *mut c_void,
}

impl FunctionMap {
    /// Creates a new `FunctionMap` and resolves external symbols for the given COFF file.
    ///
    /// # Arguments
    /// 
    /// - `coff`: A reference to the COFF file that contains the symbols to be resolved.
    ///
    /// # Returns
    /// 
    /// - `Result<(HashMap<String, usize>, FunctionMap), CoffeeLdrError>`: A tuple with resolved symbols and function addresses, 
    ///   or an error if memory allocation fails.
    fn new(coff: &Coff) -> Result<(HashMap<String, usize>, FunctionMap), CoffeeLdrError> {
        let symbols = Self::process_symbols(coff)?;
        let address = unsafe {
            VirtualAlloc(
                null_mut(), 
                MAX_SYMBOLS * size_of::<*mut c_void>(),
                MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN, 
                PAGE_READWRITE
            ) as *mut *mut c_void
        };

        if address.is_null() {
            return Err(CoffeeLdrError::MemoryAllocationError(unsafe { GetLastError() }))
        }

        Ok((symbols, FunctionMap { address }))
    }

    /// Processes the external symbols in the COFF file and resolves their addresses.
    ///
    /// # Arguments
    /// 
    /// - `coff`: A reference to the COFF file whose symbols are to be processed.
    ///
    /// # Returns
    /// 
    /// - `Result<HashMap<String, usize>, CoffeeLdrError>`: A map of symbol names to their resolved addresses, 
    ///   or an error if an error occurs during symbol resolution, such as exceeding the maximum 
    ///   number of symbols or failing to resolve an address.
    fn process_symbols(coff: &Coff) -> Result<HashMap<String, usize>, CoffeeLdrError> {
        let mut functions = HashMap::with_capacity(MAX_SYMBOLS);

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
    /// - `name`: The name of the symbol to resolve.
    /// - `coff`: A reference to the COFF file (used to determine the architecture).
    ///
    /// # Returns
    /// 
    /// - `Result<usize, CoffeeLdrError>`: The resolved address of the symbol, or an error
    ///   if the symbol cannot be found or if any error occurs during resolution.
    fn resolve_symbol_address(name: &str, coff: &Coff) -> Result<usize, CoffeeLdrError> {
        debug!("Attempting to resolve address for symbol: {}", name);
        let prefix = match coff.arch { 
            CoffMachine::X64 => "__imp_",
            CoffMachine::X32 => "__imp__" 
        };

        let symbol_name = name.strip_prefix(prefix).map_or_else(|| Err(CoffeeLdrError::SymbolIgnored), Ok)?;
        if symbol_name.starts_with("Beacon") || symbol_name.starts_with("toWideChar") {
            debug!("Resolving Beacon: {}", symbol_name);
            return get_function_internal_address(symbol_name);
        }

        let (dll, mut function) = symbol_name.split_once('$').ok_or_else(|| CoffeeLdrError::ParseError(symbol_name.to_string()))?;
        if let CoffMachine::X32 = coff.arch {
            function = function.split('@').next().unwrap_or(function);
        }

        let dll = format!("{}\0", dll);
        let function = format!("{}\0", function);
        debug!("Resolving Module {} and Function {}", dll, function);

        let module = unsafe {
            let mut handle = GetModuleHandleA(dll.as_ptr());
            if handle.is_null() {
                handle = LoadLibraryA(dll.as_ptr());
                if handle.is_null() {
                    return Err(CoffeeLdrError::ModuleNotFound(dll));
                }

                handle
            } else {
                handle
            }
        };

        unsafe {
            GetProcAddress(module, function.as_ptr())
                .map(|addr| addr as usize)
                .ok_or(CoffeeLdrError::FunctionNotFound(symbol_name.to_string()))
        }
    }
}

impl Default for FunctionMap {
    /// Provides a default-initialized `FunctionMap`.
    ///
    /// # Returns
    ///
    /// - `Self`: A default-initialized `FunctionMap`.
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
    /// - `virt_addr`: Virtual memory address where the sections will be copied.
    /// - `coff`: Coff structure that will take the information from the sections.
    /// 
    /// # Returns
    /// 
    /// - `Vec<SectionMap>`: Returns a vector of the SectionMap structure.
    fn copy_sections(virt_addr: *mut c_void, coff: &Coff) -> Vec<SectionMap> {
        unsafe {
            let sections = &coff.sections;
            let mut sec_base = virt_addr;
            sections
                .iter()
                .map(|section| {
                    let size = section.SizeOfRawData as usize;
                    let address = coff.buffer.as_ptr().add(section.PointerToRawData as usize);
                    let name = Coff::get_section_name(section);
                    copy_nonoverlapping(address, sec_base as *mut u8, size);

                    debug!("Copying section: {}", name);
                    let section_map = SectionMap { base: sec_base, size, characteristics: section.Characteristics, name };
                    sec_base = Coff::page_align((sec_base as usize) + size) as *mut c_void;

                    section_map
                })
                .collect()
        }
    }
    
    /// Set the memory permissions for each section loaded.
    ///
    /// # Returnss
    ///
    /// - `Result<(), CoffeeLdrError>`: Returns `Ok(())` if successful or an error if there was a problem adjusting the permissions.
    fn adjust_permissions(&self) -> Result<(), CoffeeLdrError> {
        info!("Adjusting memory permissions for section: Name = {}, Address = {:?}, Size = {}, Characteristics = 0x{:X}", 
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

        let mut old_protect = 0;
        if unsafe { VirtualProtect(self.base, self.size, protection, &mut old_protect) } == 0 {
            return Err(CoffeeLdrError::MemoryProtectionError(unsafe { GetLastError() }));
        }

        Ok(())
    }
}