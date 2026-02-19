#![no_std]
extern crate alloc;
use alloc::borrow::Cow;
use alloc::vec::Vec;
use core::error::Error;
use core::ffi::c_void;
use core::fmt::Display;
use core::mem::size_of;
use core::result::Result;
#[cfg(target_pointer_width = "64")]
pub mod elf64;
#[cfg(target_pointer_width = "64")]
use elf64 as elf;
#[cfg(target_pointer_width = "32")]
pub mod elf32;
#[cfg(target_pointer_width = "32")]
use elf32 as elf;

/// Errors related to dynamic libraries
#[derive(Debug)]
pub enum DynamicError {
    TypeCast(elf::DynTypeError),
    DependentSection(DynamicSectionType, DynamicSectionType),
    RequiredSection(DynamicSectionType),
    ProgramHeader,
}

impl Display for DynamicError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TypeCast(e) => write!(f, "Unknown type witnessed: {e}"),
            Self::DependentSection(dependent, depended) => write!(
                f,
                "Given the prescence of `{dependent:#?}`, expected prescence of `{depended:#?}`"
            ),
            Self::RequiredSection(required) => write!(
                f,
                "Failed to parse, required section missing `{required:#?}`"
            ),
            Self::ProgramHeader => write!(f, "No dynamic program header available"),
        }
    }
}

impl From<elf::DynTypeError> for DynamicError {
    fn from(value: elf::DynTypeError) -> Self {
        Self::TypeCast(value)
    }
}

impl Error for DynamicError {}

/// Section type enumeration
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
#[allow(non_camel_case_types)]
pub enum DynamicSectionType {
    DT_NULL,
    DT_PLTRELSZ,
    DT_PLTGOT,
    DT_PLTREL,

    DT_STRTAB,
    DT_SYMTAB,
    DT_SYMENT,

    DT_RELA,
    DT_RELASZ,
    DT_RELAENT,

    DT_REL,
    DT_RELSZ,
    DT_RELENT,

    DT_STRSZ,
    DT_JMPREL,
}

/// Container of Dynamic Relocations
pub struct DynamicRelocations<'a> {
    inner: &'a [elf::DynRel],
}

impl DynamicRelocations<'_> {
    /// Extract string from table starting at carrot position
    pub fn read_at(&self, index: usize) -> Option<&elf::DynRel> {
        self.inner.get(index)
    }

    /// Dynamic relocations internal slice
    pub fn entries(&self) -> &[elf::DynRel] {
        self.inner
    }
}

/// Container of Dynamic Addend Relocations
pub struct DynamicAddendRelocations<'a> {
    inner: &'a [elf::DynRela],
}

impl DynamicAddendRelocations<'_> {
    /// Extract string from table starting at carrot position
    pub fn read_at(&self, index: usize) -> Option<&elf::DynRela> {
        self.inner.get(index)
    }

    /// Dynamic addend relocations internal slice
    pub fn entries(&self) -> &[elf::DynRela] {
        self.inner
    }
}

/// Container of Dynamic Symbols
pub struct DynamicSymbols<'a> {
    inner: &'a elf::DynSym,
}

impl DynamicSymbols<'_> {
    /// gets the dynamic symbol at this index
    fn get(&self, index: usize) -> Option<&elf::DynSym> {
        unsafe { (self.inner as *const elf::DynSym).add(index).as_ref() }
    }

    /// resolves the name of the dynamic symbol at `index`
    pub fn resolve_name<'b>(
        &'b self,
        index: usize,
        string_table: &'b StringTable<'b>,
    ) -> Option<Cow<'b, str>> {
        let entry = self.get(index)?;
        string_table.read_at(entry.st_name as usize)
    }
}

/// Container of Dynamic Entries
pub struct DynamicSection<'a> {
    inner: &'a elf::DynEntry,
}

#[derive(Debug)]
/// A view of the Library's String table
/// The inner `raw` reference refers to a continguous array of zero terminated strings.
/// The string table view is needed to arbitrarily access into the data and pull out the null terminated strings.
pub struct StringTable<'a> {
    raw: &'a [libc::c_char],
}

impl<'a> StringTable<'a> {
    /// Extract string from table starting at carrot position
    pub fn read_at(&'a self, carrot: usize) -> Option<Cow<'a, str>> {
        match carrot >= self.raw.len() {
            true => None,
            false => unsafe {
                Some(core::ffi::CStr::from_ptr(&self.raw[carrot]).to_string_lossy())
            },
        }
    }

    /// total size of the string table in memory.
    /// This does not reflect how many strings
    pub fn total_size(&self) -> usize {
        self.raw.len()
    }
}

impl DynamicSection<'_> {
    /// Iterate dynamic section's DynEntry link list attempting to find section with target section type
    fn find_section(&self, tag: DynamicSectionType) -> Option<&elf::DynEntry> {
        let mut current = Some(self.inner);
        while let Some(inner) = current {
            match DynamicSectionType::try_from(inner.d_tag) {
                Ok(DynamicSectionType::DT_NULL) => return None,
                Ok(this_tag) if this_tag == tag => return Some(inner),
                Ok(_) => {
                    // nothing to do.
                }
                Err(_err) => {
                    // continue for now...;
                }
            }

            current = unsafe { (inner as *const elf::DynEntry).offset(1).as_ref() };
        }

        None
    }
}

/// An Elf Program Header
/// Primary examples are PT_LOAD and PT_DYNAMIC
pub struct ProgramHeader<'a> {
    inner: &'a elf::ProgramHeader,
}

impl ProgramHeader<'_> {
    /// Access the program headers type
    pub fn header_type(&self) -> elf::Word {
        self.inner.p_type
    }

    /// Access the program headers virtual address
    pub fn virtual_addr(&self) -> usize {
        self.inner.p_vaddr as usize
    }

    /// Total size in memory
    pub fn memory_size(&self) -> usize {
        self.inner.p_memsz as usize
    }

    /// File size
    pub fn file_size(&self) -> usize {
        self.inner.p_filesz as usize
    }

    /// Program headers absolute address
    pub fn program_addr(&self) -> usize {
        self.inner.p_paddr as usize
    }

    /// Program headers offset
    pub fn offset(&self) -> usize {
        self.inner.p_offset as usize
    }
}

/// A dynamic libraries plt maybe be addend entries or non addend entries
pub enum RelocationTable<'a> {
    WithAddend(DynamicAddendRelocations<'a>),
    WithoutAddend(DynamicRelocations<'a>),
}

/// Dynamic Library Entry
/// An 'upgraded' LibraryEntry with the dynamic section resolved.
pub struct DynamicLibrary<'a> {
    library: LoadedLibrary<'a>,
    dyn_section: DynamicSection<'a>,
    dyn_string_table: StringTable<'a>,

    dyn_symbols: Option<DynamicSymbols<'a>>,
    dyn_relocs: Option<DynamicRelocations<'a>>,
    dyn_addend_relocs: Option<DynamicAddendRelocations<'a>>,
    dyn_plt: Option<RelocationTable<'a>>,
}

/// Access the libraries dynamic symbols through the library's dynamic section
fn extract_dyn_symbols<'a, 'b>(
    lib: &'a LoadedLibrary<'a>,
    dynamic_section: &'a DynamicSection<'a>,
) -> Result<Option<DynamicSymbols<'b>>, DynamicError> {
    // No actual requirement for dynamic symbols.
    let Some(dyn_symbol_table) = dynamic_section.find_section(DynamicSectionType::DT_SYMTAB) else {
        return Ok(None);
    };

    // We use explicit Elf Dynamic entry structs.
    // The SYMENT size doesn't seem relevant anymore, so we can assert it the same size as the dyn entry to combat any egregious misusages
    let table_size = dynamic_section
        .find_section(DynamicSectionType::DT_SYMENT)
        .ok_or(DynamicError::DependentSection(
            DynamicSectionType::DT_SYMTAB,
            DynamicSectionType::DT_SYMENT,
        ))?
        .d_val_ptr as usize;
    assert_eq!(table_size, size_of::<elf::DynSym>());

    // We don't have enough information to tell if this elf represents an Object Mapped or Shared Library / Executable mapped entry
    // For object mapped the ptr's are relative. So we have to rebase by the virtual address from dl_info
    let dyn_sym_ptr = match dyn_symbol_table.d_val_ptr as usize <= lib.addr() {
        false => dyn_symbol_table.d_val_ptr as usize,
        true => dyn_symbol_table.d_val_ptr as usize + lib.addr(),
    } as *const elf::DynSym;

    Ok(Some(DynamicSymbols {
        inner: unsafe { dyn_sym_ptr.as_ref().unwrap() },
    }))
}

/// Access the libraries dynamic section by dereferencing the PT_DYN program header's virtual address value
fn extract_dyn_section<'a, 'b>(
    lib: &'a LoadedLibrary<'a>,
) -> Result<DynamicSection<'b>, DynamicError> {
    let dynamic_header = lib
        .program_headers()
        .find(|p_h| p_h.header_type() == 0x02)
        .ok_or(DynamicError::ProgramHeader)?;

    let dynamic_sections = lib.addr() + dynamic_header.virtual_addr();
    let dynamic_sections = dynamic_sections as *const elf::DynEntry;
    Ok(DynamicSection {
        inner: unsafe { dynamic_sections.as_ref().unwrap() },
    })
}

/// Access the libraries string table through the library's dynamic section
fn extract_dyn_string_table<'a, 'b>(
    lib: &'a LoadedLibrary<'a>,
    dynamic_section: &'a DynamicSection<'a>,
) -> Result<StringTable<'b>, DynamicError> {
    let str_table_entry = dynamic_section
        .find_section(DynamicSectionType::DT_STRTAB)
        .ok_or(DynamicError::RequiredSection(DynamicSectionType::DT_STRTAB))?;
    let table_size = dynamic_section
        .find_section(DynamicSectionType::DT_STRSZ)
        .ok_or(DynamicError::DependentSection(
            DynamicSectionType::DT_STRTAB,
            DynamicSectionType::DT_STRSZ,
        ))?
        .d_val_ptr as usize;

    // We don't have enough information to tell if this elf represents an Object Mapped or Shared Library / Executable mapped entry
    // For object mapped the ptr's are relative. So we have to rebase by the virtual address from dl_info
    let str_table_ptr = match str_table_entry.d_val_ptr as usize <= lib.addr() {
        false => str_table_entry.d_val_ptr as usize,
        true => str_table_entry.d_val_ptr as usize + lib.addr(),
    } as *const libc::c_char;

    Ok(StringTable {
        raw: unsafe { core::slice::from_raw_parts(str_table_ptr, table_size) },
    })
}

/// Access the libaries dynamic relocations through the dynamic program header
fn extract_dyn_relocs<'a, 'b>(
    lib: &'a LoadedLibrary<'a>,
    dynamic_section: &'a DynamicSection<'a>,
) -> Result<Option<DynamicRelocations<'b>>, DynamicError> {
    let Some(dyn_rel_entry) = dynamic_section.find_section(DynamicSectionType::DT_REL) else {
        return Ok(None);
    };

    let total_size = dynamic_section
        .find_section(DynamicSectionType::DT_RELSZ)
        .ok_or(DynamicError::DependentSection(
            DynamicSectionType::DT_REL,
            DynamicSectionType::DT_RELSZ,
        ))?
        .d_val_ptr as usize;
    let entry_size = dynamic_section
        .find_section(DynamicSectionType::DT_RELENT)
        .ok_or(DynamicError::DependentSection(
            DynamicSectionType::DT_REL,
            DynamicSectionType::DT_RELENT,
        ))?
        .d_val_ptr as usize;

    assert_eq!(entry_size, size_of::<elf::DynRel>());

    let entry_count = total_size / entry_size;
    // We don't have enough information to tell if this elf represents an Object Mapped or Shared Library / Executable mapped entry
    // For object mapped the ptr's are relative. So we have to rebase by the virtual address from dl_info
    let dyn_rel_entry = match dyn_rel_entry.d_val_ptr as usize <= lib.addr() {
        false => dyn_rel_entry.d_val_ptr as usize,
        true => dyn_rel_entry.d_val_ptr as usize + lib.addr(),
    } as *const elf::DynRel;

    Ok(Some(DynamicRelocations {
        inner: unsafe { core::slice::from_raw_parts(dyn_rel_entry, entry_count) },
    }))
}

/// Access the libaries dynamic addend relocations through the dynamic program header
fn extract_dyn_addend_relocs<'a, 'b>(
    lib: &'a LoadedLibrary<'a>,
    dynamic_section: &'a DynamicSection<'a>,
) -> Result<Option<DynamicAddendRelocations<'b>>, DynamicError> {
    let Some(dyn_rel_entry) = dynamic_section.find_section(DynamicSectionType::DT_RELA) else {
        return Ok(None);
    };

    let total_size = dynamic_section
        .find_section(DynamicSectionType::DT_RELASZ)
        .ok_or(DynamicError::DependentSection(
            DynamicSectionType::DT_RELA,
            DynamicSectionType::DT_RELASZ,
        ))?
        .d_val_ptr as usize;
    let entry_size = dynamic_section
        .find_section(DynamicSectionType::DT_RELAENT)
        .ok_or(DynamicError::DependentSection(
            DynamicSectionType::DT_RELA,
            DynamicSectionType::DT_RELAENT,
        ))?
        .d_val_ptr as usize;

    assert_eq!(entry_size, size_of::<elf::DynRela>());

    let entry_count = total_size / entry_size;
    // We don't have enough information to tell if this elf represents an Object Mapped or Shared Library / Executable mapped entry
    // For object mapped the ptr's are relative. So we have to rebase by the virtual address from dl_info
    let dyn_rel_entry = match dyn_rel_entry.d_val_ptr as usize <= lib.addr() {
        false => dyn_rel_entry.d_val_ptr as usize,
        true => dyn_rel_entry.d_val_ptr as usize + lib.addr(),
    } as *const elf::DynRela;

    Ok(Some(DynamicAddendRelocations {
        inner: unsafe { core::slice::from_raw_parts(dyn_rel_entry, entry_count) },
    }))
}

/// Access the libraries plt relocations
fn extract_dyn_plt<'a, 'b>(
    lib: &'a LoadedLibrary<'a>,
    dynamic_section: &'a DynamicSection<'a>,
) -> Result<Option<RelocationTable<'b>>, DynamicError> {
    // decipher if its rel or rela relocation entries
    // if this isn't present we can't have a plt
    let Some(dyn_type) = dynamic_section.find_section(DynamicSectionType::DT_PLTREL) else {
        return Ok(None);
    };

    let relocation_type = DynamicSectionType::try_from(dyn_type.d_val_ptr)?;

    let dyn_plt_entry = dynamic_section
        .find_section(DynamicSectionType::DT_JMPREL)
        .ok_or(DynamicError::DependentSection(
            DynamicSectionType::DT_PLTREL,
            DynamicSectionType::DT_JMPREL,
        ))?;
    let total_size = dynamic_section
        .find_section(DynamicSectionType::DT_PLTRELSZ)
        .ok_or(DynamicError::DependentSection(
            DynamicSectionType::DT_PLTREL,
            DynamicSectionType::DT_PLTRELSZ,
        ))?
        .d_val_ptr as usize;

    let entry_addr = match dyn_plt_entry.d_val_ptr as usize <= lib.addr() {
        false => dyn_plt_entry.d_val_ptr as usize,
        true => dyn_plt_entry.d_val_ptr as usize + lib.addr(),
    };

    Ok(match relocation_type {
        DynamicSectionType::DT_REL => {
            let entry_count = total_size / size_of::<elf::DynRel>();
            Some(RelocationTable::WithoutAddend(DynamicRelocations {
                inner: unsafe {
                    core::slice::from_raw_parts(entry_addr as *const elf::DynRel, entry_count)
                },
            }))
        }
        DynamicSectionType::DT_RELA => {
            let entry_count = total_size / size_of::<elf::DynRela>();
            Some(RelocationTable::WithAddend(DynamicAddendRelocations {
                inner: unsafe {
                    core::slice::from_raw_parts(entry_addr as *const elf::DynRela, entry_count)
                },
            }))
        }
        _ => None,
    })
}

impl<'a> DynamicLibrary<'a> {
    /// Try to consume a LoadedLibrary and create a resolved Dynamic view
    /// The Dynamic Library will take ownership of the load library as well as store
    /// all relevant dynamic sections for easy access and symbol resolution
    pub fn initialize(lib: LoadedLibrary<'a>) -> Result<Self, DynamicError> {
        let dyn_section = extract_dyn_section(&lib)?;
        let dyn_string_table = extract_dyn_string_table(&lib, &dyn_section)?;
        let dyn_symbols = extract_dyn_symbols(&lib, &dyn_section)?;
        let dyn_relocs = extract_dyn_relocs(&lib, &dyn_section)?;
        let dyn_addend_relocs = extract_dyn_addend_relocs(&lib, &dyn_section)?;
        let dyn_plt = extract_dyn_plt(&lib, &dyn_section)?;

        Ok(Self {
            library: lib,
            dyn_section,
            dyn_string_table,
            dyn_symbols,
            dyn_relocs,
            dyn_addend_relocs,
            dyn_plt,
        })
    }

    /// Finding target function differs on 32 bit and 64 bit.
    /// On 32 bit we want to check the relocations table only, opposed to the addend relocations table.
    /// Additionally, we will fall back to the plt given it is an addendless relocation table.
    #[cfg(target_pointer_width = "32")]
    pub fn try_find_function(&self, symbol_name: &str) -> Option<&'_ elf32::DynRel> {
        let string_table = self.string_table();
        let dyn_symbols = self.symbols()?;
        if let Some(dyn_relas) = self.relocs() {
            let dyn_relas = dyn_relas.entries().iter();
            if let Some(symbol) = dyn_relas
                .flat_map(|e| {
                    dyn_symbols
                        .resolve_name(e.symbol_index() as usize, string_table)
                        .map(|s| (e, s))
                })
                .filter(|(_, s)| s.eq(symbol_name))
                .next()
                .map(|(target_function, _)| target_function)
            {
                return Some(symbol);
            }
        }

        if let Some(dyn_relas) = self.plt_rel() {
            let dyn_relas = dyn_relas.entries().iter();
            if let Some(symbol) = dyn_relas
                .flat_map(|e| {
                    dyn_symbols
                        .resolve_name(e.symbol_index() as usize, string_table)
                        .map(|s| (e, s))
                })
                .filter(|(_, s)| s.eq(symbol_name))
                .next()
                .map(|(target_function, _)| target_function)
            {
                return Some(symbol);
            }
        }
        None
    }

    /// Finding target function differs on 32 bit and 64 bit.
    /// On 64 bit we want to check the addended relocations table only, opposed to the addendless relocations table.
    /// Additionally, we will fall back to the plt given it is an addended relocation table.
    #[cfg(target_pointer_width = "64")]
    pub fn try_find_function(&self, symbol_name: &str) -> Option<&'_ elf64::DynRela> {
        let string_table = self.string_table();
        let symbols = self.symbols()?;
        if let Some(dyn_relas) = self.addend_relocs() {
            let dyn_relas = dyn_relas.entries().iter();
            if let Some(symbol) = dyn_relas
                .flat_map(|e| {
                    symbols
                        .resolve_name(e.symbol_index() as usize, string_table)
                        .map(|s| (e, s))
                })
                .find(|(_, s)| s.eq(symbol_name))
                .map(|(target_function, _)| target_function)
            {
                return Some(symbol);
            }
        }

        if let Some(dyn_relas) = self.plt_rela() {
            let dyn_relas = dyn_relas.entries().iter();
            if let Some(symbol) = dyn_relas
                .flat_map(|e| {
                    symbols
                        .resolve_name(e.symbol_index() as usize, string_table)
                        .map(|s| (e, s))
                })
                .find(|(_, s)| s.eq(symbol_name))
                .map(|(target_function, _)| target_function)
            {
                return Some(symbol);
            }
        }
        None
    }
    /// Access the plt as a dynamic relocation table if possible
    /// can fail if the plt is not available or the plt is with addend
    pub fn plt_rel(&self) -> Option<&DynamicRelocations<'_>> {
        match self.plt() {
            Some(RelocationTable::WithoutAddend(relocs)) => Some(relocs),
            _ => None,
        }
    }

    /// Access the plt as a dynamic addend relocation table if possible
    /// can fail if the plt is not available or the plt is without addend
    pub fn plt_rela(&self) -> Option<&DynamicAddendRelocations<'_>> {
        match self.plt() {
            Some(RelocationTable::WithAddend(relocs)) => Some(relocs),
            _ => None,
        }
    }
    /// Access the dynamic libraries plt if available
    /// Can be either a DynamicRelocations or DynamicAddendRelocations
    pub fn plt(&self) -> Option<&RelocationTable<'_>> {
        self.dyn_plt.as_ref()
    }

    /// Access the dynamic libraries relocations if available
    pub fn relocs(&self) -> Option<&DynamicRelocations<'_>> {
        self.dyn_relocs.as_ref()
    }

    /// Access the dynamic libraries addend relocations if available
    pub fn addend_relocs(&self) -> Option<&DynamicAddendRelocations<'_>> {
        self.dyn_addend_relocs.as_ref()
    }

    /// Access the dynamic libraries symbol table if available
    pub fn symbols(&self) -> Option<&DynamicSymbols<'_>> {
        self.dyn_symbols.as_ref()
    }

    /// Access the dynamic libraries dynamic section
    pub fn dyn_section(&self) -> &DynamicSection<'_> {
        &self.dyn_section
    }

    /// Access the dynamic libraries backing general loaded library structure
    /// capable of providing the name and base address of the in memory
    pub fn library(&self) -> &LoadedLibrary<'_> {
        &self.library
    }

    /// Accesses the Dynamic modules base address.
    /// Convenience function that reads base addr from backing LoadedLibrary
    pub fn base_addr(&self) -> usize {
        self.library.addr
    }

    /// Access the dynamic string table
    pub fn string_table(&self) -> &StringTable<'_> {
        &self.dyn_string_table
    }
}

/// A library loaded in the process
pub struct LoadedLibrary<'a> {
    addr: usize,
    name: Cow<'a, str>,
    program_headers: &'a [elf::ProgramHeader],
}

impl<'a> LoadedLibrary<'a> {
    /// Access the libraries string name
    /// This is more the libraries `path` than the name per say
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Access the libraries virtual address
    pub fn addr(&self) -> usize {
        self.addr
    }

    /// Iterate the libraries program headers
    pub fn program_headers(&self) -> impl Iterator<Item = ProgramHeader<'_>> {
        self.program_headers
            .iter()
            .map(|header| ProgramHeader { inner: header })
    }

    /// Access the libraries PT_INTERP program headers
    pub fn interpreter_header(&self) -> Option<ProgramHeader<'_>> {
        self.program_headers().find(|p_h| p_h.header_type() == 0x03)
    }

    /// Access the libraries PT_LOAD program headers
    pub fn load_headers(&self) -> impl Iterator<Item = ProgramHeader<'_>> {
        self.program_headers()
            .filter(|p_h| p_h.header_type() == 0x01)
    }
}

#[derive(Debug)]
pub struct PatchError {
    addr: usize,
    page_size: usize,
    prot: i32,
}

impl Display for PatchError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "Error while patching {:X}, page_size = {:X}, protection flags: {}",
            self.addr, self.page_size, self.prot,
        )
    }
}

impl Error for PatchError {}

/// Attempts to patch plt entry at entry_addr.
/// Sets page protections containing entry_addr to PROT_WRITE | PROT_EXEC before replacing the pointer.
/// After writing out reverts the page to solely PROT_READ.
/// Returns the previous value contained in the entry_addr prior to patching.
pub fn patch(entry_addr: usize, func: usize) -> Result<usize, PatchError> {
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGE_SIZE) as usize };
    let page_aligned_addr = ((entry_addr as usize / page_size) * page_size) as *mut c_void;

    unsafe {
        // Set the memory page to read, write
        let prot_res = libc::mprotect(
            page_aligned_addr,
            page_size,
            libc::PROT_WRITE | libc::PROT_READ,
        );
        if prot_res != 0 {
            return Err(PatchError {
                addr: page_aligned_addr as usize,
                page_size,
                prot: libc::PROT_WRITE | libc::PROT_EXEC,
            });
        }

        // Replace the function address
        let previous_address = core::ptr::replace(entry_addr as *mut _, func as *mut c_void);

        // Set the memory page protection back to read only
        let prot_res = libc::mprotect(page_aligned_addr, page_size, libc::PROT_READ);
        if prot_res != 0 {
            return Err(PatchError {
                addr: page_aligned_addr as usize,
                page_size,
                prot: libc::PROT_READ,
            });
        }

        Ok(previous_address as usize)
    }
}

/// Returns a `Vec` of objects loaded into the current address space.
pub fn collect_modules<'a>() -> Vec<LoadedLibrary<'a>> {
    let mut ret = Vec::new();

    // Pushes an `Object` into the result vector on the behalf of C.
    extern "C" fn push_object(objs: &mut Vec<LoadedLibrary>, dl_info: &libc::dl_phdr_info) {
        let name = unsafe { core::ffi::CStr::from_ptr(dl_info.dlpi_name) }.to_string_lossy();
        // We have to copy sthe `dl_phdr_info` struct out, as the same memory buffer is used for
        // each entry during the iteration process. Otherwise we could have used a vector of
        // pointers.

        if dl_info.dlpi_phnum == 0 {
            return;
        }

        let program_headers =
            unsafe { core::slice::from_raw_parts(dl_info.dlpi_phdr, dl_info.dlpi_phnum as usize) };
        objs.push(LoadedLibrary {
            addr: dl_info.dlpi_addr as usize,
            name,
            program_headers,
        });
    }

    // Callback for `dl_iterate_phdr(3)`.
    unsafe extern "C" fn collect_objs(
        info: *mut libc::dl_phdr_info,
        _sz: usize,
        data: *mut libc::c_void,
    ) -> libc::c_int {
        if let Some(info) = unsafe { info.as_ref() } {
            push_object(&mut *(data as *mut Vec<LoadedLibrary>), info); // Get Rust to push the object.
        };

        0
    }

    let ret_void_p = &mut ret as *mut Vec<LoadedLibrary> as *mut libc::c_void;
    unsafe { libc::dl_iterate_phdr(Some(collect_objs), ret_void_p) };

    ret
}
