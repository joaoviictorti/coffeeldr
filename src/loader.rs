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
    ptr::{null_mut, read_unaligned, write_unaligned},
};

use obfstr::obfstr as s;
use dinvk::{
    parse::PE,
    data::{NT_SUCCESS, NTSTATUS},
    *,
};

use windows_sys::Win32::{
    Foundation::{GetLastError, STATUS_SUCCESS},
    System::{
        Memory::*,
        Diagnostics::Debug::*,
        SystemServices::*,
        LibraryLoader::DONT_RESOLVE_DLL_REFERENCES,
    },
};

use super::{debug, info, warn};
use super::{
    beacon::{
        get_function_internal_address, 
        get_output_data
    },
    error::{
        CoffError, 
        CoffeeLdrError, 
        Result
    },
    utils::read_file,
};
use super::parse::{
    Coff, 
    CoffMachine, 
    CoffSource, 
    IMAGE_RELOCATION, 
    IMAGE_SYMBOL
};

/// Type alias for the COFF main input function, which receives a pointer to data and the size of the data.
type CoffMain = extern "C" fn(*mut u8, usize);

/// Type for ntapi `LoadLibraryExA`
type LoadLibraryExA = unsafe extern "system" fn(
    lp_lib_file_name: *const u8, 
    h_file: *mut c_void, 
    dw_flags: u32
) -> *mut c_void;

/// Type for ntapi `NtFreeVirtualMemory`
type NtFreeVirtualMemory = unsafe extern "system" fn(
    process_handle: *mut c_void, 
    base_address: *mut *mut c_void, 
    region_size: *mut usize, 
    free_type: u32
) -> NTSTATUS;

/// Main structure for loading and executing COFF (Common Object File Format) files.
pub struct CoffeeLdr<'a> {
    /// COFF structure representing the loaded file or buffer.
    coff: Coff<'a>,

    /// Vector mapping the allocated memory sections.
    section_map: Vec<SectionMap>,

    /// Map of functions `FunctionMap`.
    function_map: FunctionMap,

    /// Indicates whether module stomping is enabled.
    ///
    /// When `true`, the loader will attempt to overwrite the `.text` section
    /// of the specified module instead of allocating fresh memory.
    stomping: bool,

    /// Name of the module to be stomped (e.g., `"amsi.dll"`).
    module: &'a str,
}

impl Default for CoffeeLdr<'_> {
    /// Provides a default-initialized `CoffeeLdr`.
    ///
    /// # Returns
    ///
    /// * A default-initialized `CoffeeLdr`.
    fn default() -> Self {
        Self { 
            coff: Coff::default(), 
            section_map: Vec::new(), 
            function_map: FunctionMap::default(), 
            stomping: false, 
            module: "" 
        }
    }
}

impl<'a> CoffeeLdr<'a> {
    /// Creates a new `CoffeeLdr` instance from a given COFF source.
    ///
    /// # Arguments
    ///
    /// * `source` - A generic input that can be either a file or a memory buffer containing the COFF data.
    ///   This is converted into a `CoffSource`.
    ///
    /// # Returns
    ///
    /// * `Ok(Self)` - If the COFF source is successfully processed, returning a new `CoffeeLdr` instance.
    /// * `Err(CoffeeLdrError)` - If an error occurs during processing.
    ///
    /// # Examples
    ///
    /// ## Using a file as a source:
    ///
    /// ```rust,ignore
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
    /// ```rust,ignore
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
    #[rustfmt::skip]
    pub fn new<T: Into<CoffSource<'a>>>(source: T) -> Result<Self> {
        // Processes COFF based on the source (file or buffer)
        let coff = match source.into() {
            CoffSource::File(path) => {
                info!("Try to read the file: {path}");
                // Try reading the file
                let buffer = read_file(path).map_err(|_| CoffError::FileReadError(path.to_string()))?;

                // Creates the COFF object from the buffer
                Coff::from_buffer(Box::leak(buffer.into_boxed_slice()))?
            }

            // Creates the COFF directly from the buffer
            CoffSource::Buffer(buffer) => Coff::from_buffer(buffer)?,
        };

        // Returns the new `CoffeeLdr` object
        Ok(Self {
            coff,
            section_map: Vec::new(),
            function_map: FunctionMap::default(),
            ..Default::default()
        })
    }

    /// Enables module stomping for a specified module.
    pub fn module_stomping(mut self, module: &'a str) -> Self {
        self.stomping = true;
        self.module = module;
        self
    }

    /// Executes a COFF (Common Object File Format) file in memory.
    ///
    /// # Arguments
    ///
    /// * `entry` - A string slice representing the entry point of the COFF file.
    ///   This is the symbol name where execution begins.
    /// * `args` - Optional pointer to an argument list (`*mut u8`) passed to the entry point.
    ///   If `None`, no arguments are passed.
    /// * `argc` - An optional `usize` representing the count of arguments passed through `args`.
    ///   If `None`, the argument count is considered zero.
    ///
    /// # Returns
    ///
    /// * `Ok(String)` - Returns the output of the COFF file execution as a `String` if the execution succeeds.
    /// * `Err(CoffeeLdrError)` - Returns an error if execution fails, wrapped in `CoffeeLdrError`.
    ///
    /// # Examples
    ///
    /// ```ignore
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

    /// Prepares the environment for the execution of the COFF file, allocating memory and resolving relocations.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If the environment is prepared successfully.
    /// * `Err(CoffeeLdrError)` - If any error occurs during preparation, returns a specific `CoffeeLdrError`.
    fn prepare(&mut self) -> Result<()> {
        // Verify that the COFF file's architecture.
        self.check_architecture()?;

        // Allocate memory for loading COFF sections and store the allocated section mappings.
        // If module stomping is enabled, overwrite the specified module in memory.
        // Otherwise, allocate standalone memory for the BOF payload.
        let (sections, sec_base) = if self.stomping {
            self.alloc_with_stomping()?
        } else {
            self.alloc_bof_memory()?
        };

        self.section_map = sections;

        // Resolve external symbols (such as function addresses) and build a function lookup map.
        // When using module stomping, base resolution on the stomped module's memory address.
        let (functions, function_map) = if self.stomping {
            let addr = sec_base.ok_or(CoffeeLdrError::MissingStompingBaseAddress)?;
            FunctionMap::with_address(&self.coff, addr)?
        } else {
            FunctionMap::new(&self.coff)?
        };

        self.function_map = function_map;

        // Process relocations to correctly adjust symbol addresses based on memory layout.
        let mut index = 0;
        for (i, section) in self.coff.sections.iter().enumerate() {
            // Retrieve relocation entries for the current section.
            let relocations = self.coff.get_relocations(section);
            for relocation in relocations.iter() {
                // Look up the symbol associated with the relocation.
                let symbol = &self.coff.symbols[relocation.SymbolTableIndex as usize];

                // Compute the address where the relocation should be applied.
                let symbol_reloc_addr = (self.section_map[i].base as usize + unsafe { relocation.Anonymous.VirtualAddress } as usize) as *mut c_void;

                // Retrieve the symbol's name (used for function lookups).
                let name = self.coff.get_symbol_name(symbol);
                if let Some(function_address) = functions.get(&name).map(|&addr| addr as *mut c_void) {
                    unsafe {
                        self.function_map
                            .address
                            .add(index)
                            .write_volatile(function_address);

                        // Apply the relocation using the resolved function address.
                        self.process_relocation(symbol_reloc_addr, function_address, self.function_map.address.add(index), relocation, symbol)?;
                    };

                    index += 1;
                } else {
                    // Apply the relocation but without a resolved function address (null pointer).
                    self.process_relocation(symbol_reloc_addr, null_mut(), null_mut(), relocation, symbol)?;
                }
            }
        }

        // Adjust memory permissions for allocated sections (e.g., marking executable sections).
        self.adjust_permissions()?;

        Ok(())
    }

    /// Processes the relocation of symbols in a COFF (Common Object File Format) file.
    ///
    /// # Arguments
    ///
    /// * `reloc_addr` - A pointer to the location in memory where the relocation will be applied.
    /// * `function_address` - The address of the function or symbol being relocated, or `null` if not applicable.
    /// * `function_map` - A pointer to the function map, used when resolving external symbols.
    /// * `relocation` - A reference to the `IMAGE_RELOCATION` struct, which contains the relocation entry details.
    /// * `symbol` - A reference to the `IMAGE_SYMBOL` struct, representing the symbol being relocated.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If the relocation was successfully processed.
    /// * `Err(CoffeeLdrError)` - If an unsupported or invalid relocation type is encountered,
    ///   an error is returned indicating the type of relocation that caused the failure.
    fn process_relocation(
        &self, 
        reloc_addr: *mut c_void, 
        function_address: *mut c_void, 
        function_map: *mut *mut c_void, 
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

    /// Set the memory permissions for each section loaded.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If all section permissions were adjusted successfully.
    /// * `Err(CoffeeLdrError)` - If an error occurs while adjusting permissions for any section.
    fn adjust_permissions(&mut self) -> Result<()> {
        self.section_map
            .iter_mut()
            .filter(|section| section.size > 0)
            .try_for_each(|section| section.adjust_permissions())
    }

    /// Allocates new virtual memory for loading the sections of the COFF file.
    ///
    /// This method reserves and commits a memory region for the BOF (Beacon Object File)
    /// using `NtAllocateVirtualMemory`. The memory is writable and top-down allocated.
    ///
    /// # Returns
    ///
    /// * `Ok((Vec<SectionMap>, Option<*mut c_void>))` - A tuple containing a vector of section mappings and `None` as no base address is reused.
    /// * `Err(CoffeeLdrError)` - If memory allocation fails, returns a corresponding loader error.
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
        let (sections, _) = SectionMap::copy_sections(addr, &self.coff);
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
    /// * `Ok((Vec<SectionMap>, Option<*mut c_void>))` - A tuple containing the section mappings and the base address 
    ///   used for function resolution.
    /// * `Err(CoffeeLdrError)` - If the module cannot be found or memory protection cannot be changed.
    fn alloc_with_stomping(&self) -> Result<(Vec<SectionMap>, Option<*mut c_void>)> {
        let (mut text_address, mut size) = self
            .get_text_module()
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

        // This is necessary because REL32 instructions must remain within range, and allocating the `FunctionMap`
        // elsewhere (e.g. with a distant `NtAllocateVirtualMemory`) could lead to crashes.
        //
        // Returning `Some(sec_base)` signals that the loader must re-use that exact memory area.
        debug!("Memory successfully allocated for BOF at address (Module Stomping): {:?}", text_address);
        let (sections, sec_base) = SectionMap::copy_sections(text_address, &self.coff);
        Ok((sections, Some(sec_base)))
    }

    /// Locates the `.text` section of the specified module for stomping.
    ///
    /// Loads the target module without resolving imports (`DONT_RESOLVE_DLL_REFERENCES`)
    /// and parses its PE headers to find the `.text` section.
    ///
    /// # Returns
    ///
    /// * `Some((*mut c_void, usize))` - A pointer to the start of the `.text` section and its size.
    /// * `None` - If the module or the section cannot be located.
    fn get_text_module(&self) -> Option<(*mut c_void, usize)> {
        // Invoking LoadLibraryExA dynamically
        let kernel32 = GetModuleHandle(2808682670u32, Some(dinvk::hash::murmur3));
        let target = format!("{}\0", self.module);
        let module = {
            let handle = GetModuleHandle(self.module, None);
            if handle.is_null() {
                dinvoke!(
                    kernel32,
                    s!("LoadLibraryExA"),
                    LoadLibraryExA,
                    target.as_ptr(),
                    null_mut(),
                    DONT_RESOLVE_DLL_REFERENCES
                )?
            } else {
                handle
            }
        };

        if module.is_null() {
            return None;
        }

        // Retrieving `.text` from the target module
        let pe = PE::parse(module);
        let section = pe.section_by_name(s!(".text"))?;
        let ptr = (module as usize + section.VirtualAddress as usize) as *mut c_void;
        let size = section.SizeOfRawData as usize;

        Some((ptr, size))
    }

    /// Checks if the COFF file's architecture matches the architecture of the system.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If the COFF architecture matches the system's architecture.
    /// * `Err(CoffeeLdrError)` - If there is a mismatch between the COFF and system architectures.
    #[inline]
    fn check_architecture(&self) -> Result<()> {
        match self.coff.arch {
            CoffMachine::X32 => {
                if cfg!(target_pointer_width = "64") {
                    return Err(CoffeeLdrError::ArchitectureMismatch {
                        expected: "x32",
                        actual: "x64",
                    });
                }
            }
            CoffMachine::X64 => {
                if cfg!(target_pointer_width = "32") {
                    return Err(CoffeeLdrError::ArchitectureMismatch {
                        expected: "x64",
                        actual: "x32",
                    });
                }
            }
        }

        Ok(())
    }
}

/// Implements the `Drop` trait to release memory when `CoffeeLdr` goes out of scope.
impl Drop for CoffeeLdr<'_> {
    fn drop(&mut self) {
        // It doesn't free anything, because we've blocked memory from another module.
        if self.stomping {
            return;
        }

        // Retrive Ntdll
        let ntdll = dinvk::get_ntdll_address();

        // Iterate over each section in the section map
        let mut size = 0;
        for section in self.section_map.iter_mut() {
            // Release memory if the base pointer is not null
            if !section.base.is_null() {
                dinvoke!(
                    ntdll,
                    s!("NtFreeVirtualMemory"),
                    NtFreeVirtualMemory,
                    NtCurrentProcess(),
                    &mut section.base,
                    &mut size,
                    MEM_RELEASE
                );
            }
        }

        // Release memory for the function map if the address pointer is not null
        if !self.function_map.address.is_null() {
            dinvoke!(
                ntdll,
                s!("NtFreeVirtualMemory"),
                NtFreeVirtualMemory,
                NtCurrentProcess(),
                &mut *self.function_map.address,
                &mut size,
                MEM_RELEASE
            );
        }
    }
}

/// Maximum number of symbols that the function map can handle.
const MAX_SYMBOLS: usize = 600;

/// Represents a mapping of external symbols (functions) to their memory addresses.
#[derive(Debug, Clone, Copy)]
struct FunctionMap {
    /// A pointer to an array of pointers, each pointing to an external function.
    address: *mut *mut c_void,
}

impl FunctionMap {
    /// Creates a new `FunctionMap` and resolves external symbols for the given COFF file.
    ///
    /// # Arguments
    ///
    /// * `coff` - A reference to the parsed COFF object.
    ///
    /// # Returns
    ///
    /// * `Ok((BTreeMap<String, usize>, FunctionMap))` - A tuple containing the resolved symbols and
    ///   function map, with each symbol's name mapped to its resolved address.
    /// * `Err(CoffeeLdrError)` - If memory allocation fails or symbol resolution exceeds the limit.
    fn new(coff: &Coff) -> Result<(BTreeMap<String, usize>, FunctionMap)> {
        let symbols = Self::process_symbols(coff)?;
        let mut size = MAX_SYMBOLS * size_of::<*mut c_void>();
        let mut addr = null_mut::<c_void>();
        let status = NtAllocateVirtualMemory(
            NtCurrentProcess(), 
            &mut addr, 
            0, 
            &mut size, 
            MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN, 
            PAGE_READWRITE
        );
        
        if addr.is_null() || status != STATUS_SUCCESS {
            return Err(CoffeeLdrError::MemoryAllocationError(unsafe { GetLastError() }));
        }

        let address = addr as *mut *mut c_void;
        Ok((symbols, FunctionMap { address }))
    }

    /// Creates a `FunctionMap` using a specified base address for symbol resolution.
    ///
    /// # Arguments
    ///
    /// * `coff` - A reference to the parsed COFF object.
    /// * `addr` - A pointer to the base address where the COFF sections were loaded in memory.
    ///
    /// # Returns
    ///
    /// * `Ok((BTreeMap<String, usize>, FunctionMap))` - A tuple containing the resolved symbol map
    ///   and the constructed `FunctionMap` with the associated base address.
    /// * `Err(CoffeeLdrError)` - If symbol processing fails.
    pub fn with_address(coff: &Coff, addr: *mut c_void) -> Result<(BTreeMap<String, usize>, FunctionMap)> {
        let symbols = Self::process_symbols(coff)?;
        Ok((
            symbols,
            FunctionMap {
                address: addr as *mut *mut c_void,
            },
        ))
    }

    /// Processes the external symbols in the COFF file and resolves their addresses.
    ///
    /// # Arguments
    ///
    /// * `coff` - A reference to the COFF file whose symbols are to be processed.
    ///
    /// # Returns
    ///
    /// * `Ok(BTreeMap<String, usize>)` - A map of symbol names to their resolved addresses.
    /// * `Err(CoffeeLdrError)` - If symbol resolution fails or the number of symbols exceeds the limit.
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
    /// * `Ok(usize)` - The resolved address of the symbol.
    /// * `Err(CoffeeLdrError)` - If the symbol cannot be found or resolution fails.
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

impl Default for FunctionMap {
    /// Provides a default-initialized `FunctionMap`.
    ///
    /// # Returns
    ///
    /// * A default-initialized `FunctionMap`.
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
    /// * A vector containing the mapping of each section.
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
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If the permissions were adjusted successfully.
    /// * `Err(CoffeeLdrError)` - If an error occurs while adjusting permissions.
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
