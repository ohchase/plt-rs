use libc::c_void;
use plt_rs::{collect_modules, DynamicLibrary, RelocationTable};

/// Make sure we can load all the modules we load ourselves
/// A simple sanity check, we are not checking the modules contents in any meaningful way.
/// But this works great to catch issues, because realistically we should never run into a issue parsing libraries.
#[test]
fn can_load_own_link_map() {
    let entries = collect_modules();

    for entry in entries.into_iter() {
        if let Ok(dynamic_lib) = DynamicLibrary::initialize(entry) {
            let dynamic_symbols = dynamic_lib.symbols().expect("symbols...");
            let string_table = dynamic_lib.string_table();
            if let Some(dyn_relas) = dynamic_lib.addend_relocs() {
                dyn_relas
                    .entries()
                    .iter()
                    .flat_map(|e| {
                        dynamic_symbols.resolve_name(e.symbol_index() as usize, string_table)
                    })
                    .filter(|s| !s.is_empty())
                    .for_each(|s| println!("\t{}", s));
            }

            if let Some(dyn_relocs) = dynamic_lib.relocs() {
                dyn_relocs
                    .entries()
                    .iter()
                    .flat_map(|e| {
                        dynamic_symbols.resolve_name(e.symbol_index() as usize, string_table)
                    })
                    .filter(|s| !s.is_empty())
                    .for_each(|s| println!("\t{}", s));
            }

            if let Some(plt) = dynamic_lib.plt() {
                match plt {
                    RelocationTable::WithAddend(rel) => {
                        rel.entries()
                            .iter()
                            .flat_map(|e| {
                                dynamic_symbols
                                    .resolve_name(e.symbol_index() as usize, string_table)
                            })
                            .filter(|s| !s.is_empty())
                            .for_each(|s| println!("\t{}", s));
                    }
                    RelocationTable::WithoutAddend(rel) => {
                        rel.entries()
                            .iter()
                            .flat_map(|e| {
                                dynamic_symbols
                                    .resolve_name(e.symbol_index() as usize, string_table)
                            })
                            .filter(|s| !s.is_empty())
                            .for_each(|s| println!("\t{}", s));
                    }
                }
            }
        }
    }
}

unsafe fn getpid() -> u32 {
    999
}

/// Finding executable target differs on unix and android
#[cfg(target_os = "linux")]
fn find_executable<'a>() -> Option<plt_rs::LoadedLibrary<'a>> {
    let loaded_modules = collect_modules();
    loaded_modules.into_iter().next()
}

/// Finding executable target differs on unix and android
#[cfg(target_os = "android")]
fn find_executable<'a>() -> Option<plt_rs::LoadedLibrary<'a>> {
    let executable = std::env::current_exe().expect("current exe");
    let file_stem = executable.file_stem()?;
    let file_stem = file_stem.to_str()?;
    let loaded_modules = collect_modules();
    loaded_modules
        .into_iter()
        .filter(|lib| lib.name().contains(file_stem))
        .next()
}
#[test]
fn can_hook_getpid() {
    let my_pid = unsafe { libc::getpid() };
    println!("application pid is {my_pid}");

    let executable_entry = find_executable().expect("can find executable");
    println!("successfully identified executable");

    let dyn_lib = DynamicLibrary::initialize(executable_entry).expect("can load");
    println!("successfully initialied dynamic library for instrumentation");

    let target_function = dyn_lib
        .try_find_function("getpid")
        .expect("executable should link getpid");
    println!(
        "successfully identified libc getpid offset: {:#X?}",
        target_function.r_offset
    );

    let base_addr = dyn_lib.library().addr();
    let plt_fn_ptr = (base_addr + target_function.r_offset as usize) as *mut *mut libc::c_void;
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGE_SIZE) as usize };
    let plt_page = ((plt_fn_ptr as usize / page_size) * page_size) as *mut libc::c_void;
    println!("page start for function is {plt_page:#X?}");

    let _stored_address = unsafe {
        // Set the memory page to read, write
        let prot_res = libc::mprotect(plt_page, page_size, libc::PROT_WRITE | libc::PROT_READ);
        if prot_res != 0 {
            panic!("failed to set prot res");
        }

        // Replace the function address
        let previous_address = std::ptr::replace(plt_fn_ptr, getpid as *mut _);

        // Set the memory page protection back to read only
        let prot_res = libc::mprotect(plt_page, page_size, libc::PROT_READ);
        if prot_res != 0 {
            panic!("failed to set prot res");
        }

        previous_address as *const c_void
    };

    let get_pid = unsafe { libc::getpid() };
    assert_eq!(get_pid, 999)
}
