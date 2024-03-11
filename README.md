# PLT-RS

## Change Notes
### 0.1.0 initial release
### 0.2.0 total revamp
- removed hooking functionality
- reduced linux/android bloat
- documented and generally made more ergonomic

## Inspirations / Sources utilized
Projects I referenced while working on this.
- [Plthook by Kubo] https://github.com/kubo/plthook
- [Bhook by bytedance] https://github.com/bytedance/bhook

## Overview
By crawling the dynamically loaded objects of an executable we can hook exported functions.
Generally, PLT hooking is an ideal solution for hooking given you can guarantee a Unix Like environment.
This library does not do any inline hooking, so there is no architecture (i686, arm, etc.) specific assembly magic going on, 
making cross compatibility very easy. There IS architecture specific constants, but its very minimal. 

## ... Unix Like?
Ye this library supports two target operating systems: Linux and Android;
So, android is unix like but has a separate linker implemention called Bionic.
At the ground floor, both are still linking shared objects in elf format; but 
the library has to change how it crawls the dynamially loaded objects.

## Why
Video game modding, reverse engineering, etc
- Can hook networking calls: recv / send
- Rendering calls: eglSwapBuffers / video game overlays

## Supports and tests against many targets
- ![i686-unknown-linux-gnu](https://github.com/ohchase/plt-rs/actions/workflows/i686-unknown-linux-gnu.yml/badge.svg)
- ![x86_64-unknown-linux-gnu](https://github.com/ohchase/plt-rs/actions/workflows/x86_64-unknown-linux-gnu.yml/badge.svg)
- ![aarch64-unknown-linux-gnu](https://github.com/ohchase/plt-rs/actions/workflows/aarch64-unknown-linux-gnu.yml/badge.svg)
- ![arm-unknown-linux-gnueabi](https://github.com/ohchase/plt-rs/actions/workflows/arm-unknown-linux-gnueabi.yml/badge.svg)
- ![i686-linux-android](https://github.com/ohchase/plt-rs/actions/workflows/i686-linux-android.yml/badge.svg)
- ![x86_64-linux-android](https://github.com/ohchase/plt-rs/actions/workflows/x86_64-linux-android.yml/badge.svg)
- ![aarch64-linux-android](https://github.com/ohchase/plt-rs/actions/workflows/aarch64-linux-android.yml/badge.svg)
- ![arm-linux-androideabi](https://github.com/ohchase/plt-rs/actions/workflows/arm-linux-androideabi.yml/badge.svg)
- ![armv7-linux-androideabi](https://github.com/ohchase/plt-rs/actions/workflows/armv7-linux-androideabi.yml/badge.svg)

## Show me da code
Here we are hooking our own executables usages of libc getpid.
Refer to `examples/hook_getpid.rs` for the full example, supporting android and 32 bit.
A good chunk of the code is for the actual pointer replacement to hook the function!

```rust

/// our own get pid function
unsafe fn getpid() -> u32 {
    999
}

/// Finding target function differs on 32 bit and 64 bit.
/// On 64 bit we want to check the addended relocations table only, opposed to the addendless relocations table.
/// Additionally, we will fall back to the plt given it is an addended relocation table.
#[cfg(target_pointer_width = "64")]
fn try_find_function<'a>(
    dyn_lib: &'a DynamicLibrary,
    dyn_symbols: &'a DynamicSymbols,
) -> Option<&'a plt_rs::elf64::DynRela> {
    let string_table = dyn_lib.string_table();
    if let Some(dyn_relas) = dyn_lib.addend_relocs() {
        let dyn_relas = dyn_relas.entries().iter();
        if let Some(symbol) = dyn_relas
            .flat_map(|e| {
                dyn_symbols
                    .resolve_name(e.symbol_index() as usize, string_table)
                    .map(|s| (e, s))
            })
            .filter(|(_, s)| s.eq("getpid"))
            .next()
            .map(|(target_function, _)| target_function)
        {
            return Some(symbol);
        }
    }

    if let Some(dyn_relas) = dyn_lib.plt_rela() {
        let dyn_relas = dyn_relas.entries().iter();
        if let Some(symbol) = dyn_relas
            .flat_map(|e| {
                dyn_symbols
                    .resolve_name(e.symbol_index() as usize, string_table)
                    .map(|s| (e, s))
            })
            .filter(|(_, s)| s.eq("getpid"))
            .next()
            .map(|(target_function, _)| target_function)
        {
            return Some(symbol);
        }
    }
    return None;
}

fn main() -> Result<()> {
    let my_pid = unsafe { libc::getpid() };
    println!("application pid is {my_pid}");

    let executable_entry = find_executable().ok_or(anyhow!("unable to find target executable"))?;
    println!("successfully identified executable");

    let dyn_lib = DynamicLibrary::initialize(executable_entry)?;
    println!("successfully initialied dynamic library for instrumentation");

    let dyn_symbols = dyn_lib
        .symbols()
        .ok_or(anyhow!("dynamic lib should have symbols"))?;
    let target_function =
        try_find_function(&dyn_lib, &dyn_symbols).ok_or(anyhow!("unable to find getpid symbol"))?;
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
```

```terminal
application pid is 127765
successfully identified executable
successfully initialied dynamic library for instrumentation
successfully identified libc getpid offset: 0x7E460
page start for function is 0x000061019c41b000
new pid is: 999
```
