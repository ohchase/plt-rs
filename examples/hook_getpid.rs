use anyhow::anyhow;
use anyhow::Result;
use plt_rs::DynamicLibrary;

unsafe fn hook_getpid() -> u32 {
    999
}

/// Finding executable target differs on unix and android
#[cfg(target_os = "linux")]
fn find_executable<'a>() -> Option<plt_rs::LoadedLibrary<'a>> {
    let loaded_modules = plt_rs::collect_modules();
    loaded_modules.into_iter().next()
}

/// Finding executable target differs on unix and android
#[cfg(target_os = "android")]
fn find_executable<'a>() -> Option<plt_rs::LoadedLibrary<'a>> {
    let executable = std::env::current_exe().expect("current exe");
    let file_stem = executable.file_stem()?;
    let file_stem = file_stem.to_str()?;
    let loaded_modules = plt_rs::collect_modules();
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
    println!("successfully initialized dynamic library for instrumentation");

    let target_function = dyn_lib
        .try_find_function("getpid")
        .ok_or(anyhow!("unable to find getpid symbol"))?;
    println!(
        "successfully identified libc getpid offset: {:X?}",
        target_function.r_offset
    );

    let base_addr = dyn_lib.base_addr();
    let plt_func_ptr = base_addr + target_function.r_offset as usize;
    let previous_func = plt_rs::patch(plt_func_ptr, hook_getpid as usize)?;
    println!("cached previous function as value: {:X}", previous_func);

    let get_pid = unsafe { libc::getpid() };
    println!("application new pid is: {get_pid}");

    let _ = plt_rs::patch(plt_func_ptr, previous_func)?;
    println!("restored plt entry");

    let get_pid = unsafe { libc::getpid() };
    println!("application restored pid is: {get_pid}");

    Ok(())
}
