use anyhow::anyhow;
use anyhow::Result;
use libc::c_void;
use plt_rs::{collect_modules, DynamicLibrary};

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

fn main() -> Result<()> {
    let my_pid = unsafe { libc::getpid() };
    println!("application pid is {my_pid}");

    let executable_entry = find_executable().ok_or(anyhow!("unable to find target executable"))?;
    println!("successfully identified executable");

    let dyn_lib = DynamicLibrary::initialize(executable_entry)?;
    println!("successfully initialied dynamic library for instrumentation");

    let target_function = dyn_lib
        .try_find_function("getpid")
        .ok_or(anyhow!("unable to find getpid symbol"))?;
    println!(
        "successfully identified libc getpid offset: {:#X?}",
        target_function.r_offset
    );

    let base_addr = dyn_lib.library().addr();
    let plt_fn_ptr = (base_addr + target_function.r_offset as usize) as *mut *mut c_void;
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGE_SIZE) as usize };
    let plt_page = ((plt_fn_ptr as usize / page_size) * page_size) as *mut c_void;
    println!("page start for function is {plt_page:#X?}");

    let _stored_address = unsafe {
        // Set the memory page to read, write
        let prot_res = libc::mprotect(plt_page, page_size, libc::PROT_WRITE | libc::PROT_READ);
        if prot_res != 0 {
            println!("protection res: {prot_res}");
            return Err(anyhow!("mprotect to rw"));
        }

        // Replace the function address
        let previous_address = std::ptr::replace(plt_fn_ptr, getpid as *mut _);

        // Set the memory page protection back to read only
        let prot_res = libc::mprotect(plt_page, page_size, libc::PROT_READ);
        if prot_res != 0 {
            return Err(anyhow!("mprotect to r"));
        }

        previous_address as *const c_void
    };

    let get_pid = unsafe { libc::getpid() };
    println!("new pid is: {get_pid}");

    Ok(())
}
