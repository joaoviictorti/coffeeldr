use alloc::ffi::CString;
use alloc::vec::Vec;
use alloc::vec;
use alloc::borrow::Cow;
use alloc::string::{String, ToString};
use core::mem::transmute;
use core::ptr::null_mut;

use windows_sys::Win32::System::Memory::MEM_RELEASE;
use windows_sys::Win32::Foundation::{
    CloseHandle, GENERIC_READ, GetLastError, INVALID_HANDLE_VALUE
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileA, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, 
    GetFileSize, INVALID_FILE_SIZE, OPEN_EXISTING, 
    ReadFile
};

use crate::error::{Error, Result};
use crate::beacon::get_output_data;
use crate::parse::{CoffFile, Source};
use crate::ffi::{NtFreeVirtualMemory, NtCurrentProcess}; 

use self::memory::{Memory, SectionMap};
use self::symbol::Symbol;
use self::relocation::Relocation;

mod relocation;
mod memory;
mod symbol;

/// Function signature for the COFF entry point.
type CoffMain = extern "C" fn(*mut u8, usize);

/// COFF loader and executor.
///
/// Parses a COFF object file, allocates memory, applies relocations, resolves
/// imports and executes the specified entry point. Supports loading from a
/// file path or an in-memory buffer, with optional module stomping.
///
/// # Examples
///
/// Loading from a file:
///
/// ```no_run
/// use coffeeldr::CoffLdr;
///
/// let mut loader = CoffLdr::new("whoami.o")?;
/// let output = loader.run("go", None, None)?;
/// println!("{output}");
/// # Ok::<(), coffeeldr::error::Error>(())
/// ```
///
/// Loading from a buffer:
///
/// ```no_run
/// # use coffeeldr::CoffLdr;
/// let data: &[u8] = &[/* COFF data */];
/// let mut loader = CoffLdr::new(data)?;
/// # Ok::<(), coffeeldr::error::Error>(())
/// ```
#[derive(Default)]
pub struct CoffLdr<'a> {
    coff: CoffFile<'a>,
    section_map: Vec<SectionMap>,
    symbols: Symbol,
    module: &'a str,
}

impl<'a> CoffLdr<'a> {
    /// Creates a new loader from a file path or in-memory buffer.
    pub fn new<T: Into<Source<'a>>>(source: T) -> Result<Self> {
        // Processes COFF based on the source (file or buffer)
        let coff = match source.into() {
            Source::File(path) => {
                log::info!("Try to read the file: {path}");
                let buffer = read_file(path)
                    .map_err(|_| Error::FileReadError(path.to_string()))?;

                CoffFile::parse(Cow::Owned(buffer))?
            }
            Source::Buffer(buffer) => CoffFile::parse(Cow::Borrowed(buffer))?,
        };

        Ok(Self {
            coff,
            section_map: Vec::new(),
            symbols: Symbol::default(),
            ..Default::default()
        })
    }

    /// Enables module stomping using the specified module's text section.
    ///
    /// Instead of allocating fresh memory, the loader overwrites the target
    /// module's text section with the COFF payload. This is useful for
    /// evading memory scanners that look for suspicious allocations.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use coffeeldr::CoffLdr;
    ///
    /// let loader = CoffLdr::new("payload.o")?
    ///     .with_module_stomping("amsi.dll");
    /// # Ok::<(), coffeeldr::error::Error>(())
    /// ```
    pub fn with_module_stomping(mut self, module: &'a str) -> Self {
        self.module = module;
        self
    }

    /// Executes the COFF payload at the specified entry point.
    ///
    /// Prepares the execution environment (memory, relocations, imports) and
    /// invokes the named symbol. Any Beacon output is returned as a string.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use coffeeldr::{CoffLdr, beacon::BeaconPack};
    ///
    /// let mut pack = BeaconPack::default();
    /// pack.addstr("C:\\Windows")?;
    /// let args = pack.getbuffer()?;
    ///
    /// let mut loader = CoffLdr::new("dir.o")?;
    /// let output = loader.run("go", Some(args.as_ptr() as _), Some(args.len()))?;
    /// # Ok::<(), coffeeldr::error::Error>(())
    /// ```
    pub fn run(
        &mut self,
        entry: &str,
        args: Option<*mut u8>,
        argc: Option<usize>,
    ) -> Result<String> {
        log::info!("Preparing environment for COFF execution.");

        // Prepares the environment to execute the COFF file
        self.prepare()?;

        for symbol in &self.coff.symbols {
            let name = self.coff.get_symbol_name(symbol);
            if name == entry && CoffFile::is_fcn(symbol.Type) {
                log::info!("Running COFF file: entry point = {}, args = {:?}, argc = {:?}", name, args, argc);

                let section_addr = self.section_map[(symbol.SectionNumber - 1) as usize].base;
                let entrypoint = unsafe { section_addr.offset(symbol.Value as isize) };
                let coff_main: CoffMain = unsafe { transmute(entrypoint) };
                coff_main(args.unwrap_or(null_mut()), argc.unwrap_or(0));
                break;
            }
        }

        Ok(get_output_data()
            .filter(|o| !o.buffer.is_empty())
            .map(|o| o.to_string())
            .unwrap_or_default())
    }

    /// Prepares the COFF for execution.
    fn prepare(&mut self) -> Result<()> {
        // Verify that the COFF file's architecture
        self.coff.arch.check_architecture()?;

        // Allocate memory for loading COFF sections and store the allocated section mappings
        let mem = Memory::new(&self.coff, self.module);
        let (sections, sec_base) = mem.alloc()?;
        self.section_map = sections;

        // Resolve external symbols and build a function lookup map
        let (functions, symbols) = Symbol::new(&self.coff, self.module, sec_base)?;
        self.symbols = symbols;

        // Process relocations to correctly adjust symbol addresses based on memory layout
        let reloc = Relocation::new(&self.coff, &self.section_map);
        reloc.process_relocation(&functions, &self.symbols)?;

        // Adjust memory permissions for allocated sections
        self.section_map
            .iter_mut()
            .filter(|section| section.size > 0)
            .try_for_each(|section| section.adjust_permissions())?;

        Ok(())
    }
}

impl Drop for CoffLdr<'_> {
    fn drop(&mut self) {
        if !self.module.is_empty() {
            return;
        }
        
        let mut size = 0;
        if let Some(section) = self.section_map.first_mut()
            && !section.base.is_null()
        {
            unsafe {
                let _ = NtFreeVirtualMemory(
                    NtCurrentProcess(),
                    &mut section.base,
                    &mut size,
                    MEM_RELEASE
                );
            }
        }

        if !self.symbols.address.is_null() {
            let mut address = self.symbols.address.cast();
            unsafe {
                let _ = NtFreeVirtualMemory(
                    NtCurrentProcess(),
                    &mut address,
                    &mut size,
                    MEM_RELEASE
                );
            }
        }
    }
}

fn read_file(name: &str) -> Result<Vec<u8>> {
    let file_name = CString::new(name)
        .map_err(|_| Error::NullByteInPath)?;

    let h_file = unsafe {
        CreateFileA(
            file_name.as_ptr().cast(),
            GENERIC_READ,
            FILE_SHARE_READ,
            null_mut(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            null_mut(),
        )
    };

    if h_file == INVALID_HANDLE_VALUE {
        return Err(Error::FileOpenError(unsafe { GetLastError() }));
    }

    let size = unsafe { GetFileSize(h_file, null_mut()) };
    if size == INVALID_FILE_SIZE {
        let error = unsafe { GetLastError() };
        unsafe { CloseHandle(h_file) };
        return Err(Error::InvalidFileSize(error));
    }

    let mut out = vec![0u8; size as usize];
    let mut bytes = 0;
    let read = unsafe {
        ReadFile(
            h_file,
            out.as_mut_ptr(),
            out.len() as u32,
            &mut bytes,
            null_mut(),
        )
    };
    unsafe { CloseHandle(h_file) };

    if read == 0 || bytes != size {
        return Err(Error::FileReadError(name.to_string()));
    }

    Ok(out)
}
