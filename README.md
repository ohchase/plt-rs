# Plt-rs

## Overview
By crawling the dynamically loaded objects of an executable we can hook exported functions.
Generally, PLT hooking is an ideal solution for hooking given you can guarantee a Unix Like environment.
This library does not do any inline hooking, so there is no architecture (i686, arm, etc.) specific assembly magic going on, 
making cross compatibility very easy. There IS architecture specific constants, but its very minimal. 

## Why
Video game modding, reverse engineering, etc
- Can hook networking calls: recv / send
- Rendering calls: eglSwapBuffers / video game mods and overlays
- Application hardening and monitoring
- Defensive and Offensive usages

## Supports and tests against many targets
highlighted builds
- ![i686-unknown-linux-gnu](https://github.com/ohchase/plt-rs/actions/workflows/i686-unknown-linux-gnu.yml/badge.svg)
- ![x86_64-unknown-linux-gnu](https://github.com/ohchase/plt-rs/actions/workflows/x86_64-unknown-linux-gnu.yml/badge.svg)
- ![aarch64-unknown-linux-gnu](https://github.com/ohchase/plt-rs/actions/workflows/aarch64-unknown-linux-gnu.yml/badge.svg)
- ![aarch64-linux-android](https://github.com/ohchase/plt-rs/actions/workflows/aarch64-linux-android.yml/badge.svg)
- ![armv7-linux-androideabi](https://github.com/ohchase/plt-rs/actions/workflows/armv7-linux-androideabi.yml/badge.svg)

## Worked Example hooking `getpid`
Here we are hooking our own executables usages of libc getpid.
Refer to `examples/hook_getpid.rs` for the full example, supporting android and 32 bit.
A good chunk of the code is for the actual pointer replacement to hook the function!

```rust

/// our own get pid function
unsafe fn getpid() -> u32 {
    999
}

fn main() -> Result<()> {
    let my_pid = unsafe { libc::getpid() };
    println!("application pid is {my_pid}");

    let executable_entry = find_executable().ok_or(anyhow!("unable to find target executable"))?;
    println!("successfully identified executable");

    let dyn_lib = DynamicLibrary::initialize(executable_entry)?;
    println!("successfully initialied dynamic library for instrumentation");

    let target_function =
        dyn_lib.try_find_function("getpid").ok_or(anyhow!("unable to find getpid symbol"))?;
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

## References / Inspirations
Projects I referenced and was heavily inspired by while working on this.
- [Plthook by Kubo] https://github.com/kubo/plthook
- [Bhook by bytedance] https://github.com/bytedance/bhook
