use std::{borrow::Cow, ffi::c_int};

use libc::{c_void, mprotect, PROT_READ, PROT_WRITE, _SC_PAGE_SIZE};
use thiserror::Error;
use unixy::{ElfAddr, ElfDyn, ElfSym, LinkMap, SectionType, R_GLOB_DAT, R_JUMP_SLOT};

mod unixy;

#[cfg(target_os = "android")]
mod android_view;
#[cfg(target_os = "android")]
pub use android_view::LinkMapView;

#[cfg(target_os = "linux")]
mod unix_view;
#[cfg(target_os = "linux")]
pub use unix_view::LinkMapView;

#[derive(Debug, Error)]
pub enum PltError {
    #[error(
        "Unable to mprotect address, unaligned: {0:X?}, aligned: {1:X?}, desired flags: {2:?}, response: {3:?}"
    )]
    Protection(*const c_void, *const c_void, c_int, c_int),

    #[error("Expected the presence of section `{0:#?}`")]
    Section(SectionType),
}

pub type PltResult<T> = Result<T, PltError>;

#[derive(Debug)]
pub struct StringTableView<'a> {
    raw: &'a [libc::c_char],
}

impl<'a> StringTableView<'a> {
    pub fn get(&self, index: usize) -> Option<Cow<str>> {
        match index >= self.raw.len() {
            true => None,
            false => unsafe { Some(std::ffi::CStr::from_ptr(&self.raw[index]).to_string_lossy()) },
        }
    }
}

fn raw_query_name<'b>(
    index: isize,
    dyn_syms: *const ElfSym,
    string_table: &'b StringTableView,
) -> Option<Cow<'b, str>> {
    let idx = unsafe { dyn_syms.offset(index).as_ref()? };
    match idx.st_name == 0 {
        true => None,
        false => string_table.get(idx.st_name as usize),
    }
}

pub trait LinkMapBacked<'a>: Sized {
    fn inner(&'a self) -> &'a LinkMap;

    fn dynamic_load_address(&'a self) -> ElfAddr;

    fn from_address(address: usize) -> Option<Self>;

    fn from_executable() -> Option<Self> {
        let executable_name = std::env::current_exe().ok()?;
        let pid = std::process::id();

        let process_map = proc_maps::get_process_maps(pid as i32)
            .ok()?
            .into_iter()
            .find(|m| match m.filename() {
                Some(file_name) => executable_name == file_name,
                None => false,
            })?;

        Self::from_address(process_map.start() + process_map.size() / 2)
    }

    #[cfg(target_pointer_width = "64")]
    fn rel_dyn(&'a self) -> Option<&'a [unixy::ElfRela]> {
        let rela = self.try_find_section(SectionType::DT_RELA)?;
        let relasz = self.try_find_section(SectionType::DT_RELASZ)?.d_val as usize;
        let relaent = self.try_find_section(SectionType::DT_RELAENT)?.d_val as usize;
        let entries_count = relasz / relaent;
        let entries = (rela.d_val + self.dynamic_load_address()) as *const unixy::ElfRela;
        let entries = unsafe { std::slice::from_raw_parts(entries, entries_count) };
        Some(entries)
    }

    #[cfg(target_pointer_width = "64")]
    fn plt_dyn(&'a self) -> Option<&'a [unixy::ElfRela]> {
        let rela = self.try_find_section(SectionType::DT_JMPREL)?;
        let relasz = self.try_find_section(SectionType::DT_PLTRELSZ)?.d_val as usize;
        let relaent = std::mem::size_of::<unixy::ElfRela>();
        let entries_count = relasz / relaent;
        let entries = (rela.d_val + self.dynamic_load_address()) as *const unixy::ElfRela;
        let entries = unsafe { std::slice::from_raw_parts(entries, entries_count) };
        Some(entries)
    }

    #[cfg(target_pointer_width = "32")]
    fn rel_dyn(&'a self) -> Option<&'a [unixy::ElfRel]> {
        let rela = self.try_find_section(SectionType::DT_REL)?;
        let relasz = self.try_find_section(SectionType::DT_RELSZ)?.d_val as usize;
        let relaent = self.try_find_section(SectionType::DT_RELENT)?.d_val as usize;
        let entries_count = relasz / relaent;
        let entries = (rela.d_val + self.dynamic_load_address()) as *const unixy::ElfRel;
        let entries = unsafe { std::slice::from_raw_parts(entries, entries_count) };
        Some(entries)
    }

    #[cfg(target_pointer_width = "32")]
    fn plt_dyn(&'a self) -> Option<&'a [unixy::ElfRel]> {
        let rela = self.try_find_section(SectionType::DT_JMPREL)?;
        let relasz = self.try_find_section(SectionType::DT_PLTRELSZ)?.d_val as usize;
        let relaent = std::mem::size_of::<unixy::ElfRel>();
        let entries_count = relasz / relaent;
        let entries = (rela.d_val + self.dynamic_load_address()) as *const unixy::ElfRel;
        let entries = unsafe { std::slice::from_raw_parts(entries, entries_count) };
        Some(entries)
    }

    fn load_address(&'a self) -> ElfAddr {
        self.inner().l_addr
    }

    fn dynamic_section(&'a self) -> Option<&'a ElfDyn> {
        unsafe { self.inner().l_ld.as_ref() }
    }

    fn try_find_section(&'a self, tag: SectionType) -> Option<&'a ElfDyn> {
        let mut dyn_section = self.dynamic_section();
        while let Some(section) = dyn_section {
            if section.d_tag == 0 {
                break;
            }

            if section.d_tag == tag.into() {
                return Some(section);
            }

            dyn_section = unsafe { (section as *const ElfDyn).offset(1).as_ref() };
        }

        None
    }

    fn find_section(&'a self, tag: SectionType) -> PltResult<&'a ElfDyn> {
        self.try_find_section(tag).ok_or(PltError::Section(tag))
    }

    fn string_table(&'a self) -> PltResult<StringTableView<'a>> {
        let dyn_strs = self.find_section(SectionType::DT_STRTAB)?;
        let dyn_strs = (dyn_strs.d_val + self.dynamic_load_address()) as *const libc::c_char;
        let dyn_str_size = self.find_section(SectionType::DT_STRSZ)?.d_val as usize;
        Ok(StringTableView {
            raw: unsafe { std::slice::from_raw_parts(dyn_strs, dyn_str_size) },
        })
    }

    fn find_symbol(&'a self, symbol_name: &str) -> PltResult<Option<*mut *const c_void>> {
        let sym_tab = self.find_section(SectionType::DT_SYMTAB)?;
        let dyn_syms = (sym_tab.d_val + self.dynamic_load_address()) as *const ElfSym;
        let string_table = self.string_table()?;

        if let Some(entries) = self.rel_dyn() {
            for entry in entries.iter().filter(|e| e.symbol_type() == R_GLOB_DAT) {
                let queried_name =
                    raw_query_name(entry.symbol_index() as isize, dyn_syms, &string_table);

                if let Some(current_name) = queried_name {
                    if current_name == symbol_name {
                        let plt_pointer =
                            (entry.r_offset + self.load_address()) as *mut *const c_void;
                        return Ok(Some(plt_pointer));
                    }
                }
            }
        }

        if let Some(entries) = self.plt_dyn() {
            for entry in entries.iter().filter(|e| e.symbol_type() == R_JUMP_SLOT) {
                let queried_name =
                    raw_query_name(entry.symbol_index() as isize, dyn_syms, &string_table);

                if let Some(current_name) = queried_name {
                    if current_name == symbol_name {
                        let plt_pointer =
                            (entry.r_offset + self.load_address()) as *mut *const c_void;
                        return Ok(Some(plt_pointer));
                    }
                }
            }
        }
        Ok(None)
    }
}

pub struct MutableLinkMap<'a> {
    view: LinkMapView<'a>,
}

impl<'a> MutableLinkMap<'a> {
    pub fn from_view(view: LinkMapView<'a>) -> Self {
        Self { view }
    }

    fn replace_address(
        func_ptr: *mut *const c_void,
        destination: *const c_void,
    ) -> PltResult<*const c_void> {
        let page_size = unsafe { libc::sysconf(_SC_PAGE_SIZE) as usize };
        let aligned_address = ((func_ptr as usize / page_size) * page_size) as *mut c_void;

        unsafe {
            // Set the memory page to read, write
            let prot_res = mprotect(aligned_address, page_size, PROT_WRITE | PROT_READ);
            if prot_res != 0 {
                return Err(PltError::Protection(
                    func_ptr as *mut _,
                    aligned_address,
                    PROT_READ | PROT_WRITE,
                    std::io::Error::last_os_error().raw_os_error().unwrap(),
                ));
            }

            // Replace the previous function address
            let previous_address = std::ptr::replace(func_ptr, destination);

            // Set the memory page protection back to read only
            let prot_res = mprotect(aligned_address, page_size, PROT_READ);
            if prot_res != 0 {
                return Err(PltError::Protection(
                    func_ptr as *mut _,
                    aligned_address,
                    PROT_READ,
                    std::io::Error::last_os_error().raw_os_error().unwrap(),
                ));
            }

            Ok(previous_address as *const c_void)
        }
    }

    pub fn hook<FnT>(
        &'a mut self,
        symbol_name: &str,
        desired_function: *const FnT,
    ) -> PltResult<Option<FunctionHook<FnT>>>
    where
        FnT: Copy,
    {
        match self.view.find_symbol(symbol_name)? {
            Some(symbol) => {
                let previous_address =
                    Self::replace_address(symbol, desired_function as *const c_void)?;
                let previous_function =
                    unsafe { *((&previous_address as *const *const c_void) as *const FnT) };
                Ok(Some(FunctionHook::<FnT> {
                    symbol_name: symbol_name.to_owned(),
                    cached_function: previous_function,
                }))
            }
            None => Ok(None),
        }
    }

    pub fn restore<FnT>(&'a mut self, function_hook: FunctionHook<FnT>) -> PltResult<Option<FnT>>
    where
        FnT: Copy,
    {
        match self.view.find_symbol(&function_hook.symbol_name)? {
            Some(symbol) => {
                let hooked_fn_address = unsafe {
                    *((&function_hook.cached_function as *const FnT) as *const *const c_void)
                };
                let hooked_fn = Self::replace_address(symbol, hooked_fn_address)? as *const FnT;
                let hooked_fn = unsafe { *((&hooked_fn as *const *const FnT) as *const FnT) };

                Ok(Some(hooked_fn))
            }
            None => Ok(None),
        }
    }
}

#[derive(Debug)]
pub struct FunctionHook<T> {
    symbol_name: String,
    cached_function: T,
}

impl<T> FunctionHook<T> {
    pub fn cached_function(&self) -> &T {
        &self.cached_function
    }
}
