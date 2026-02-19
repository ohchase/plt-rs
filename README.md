# Plt-rs
[![Crates.io](https://img.shields.io/crates/v/plt-rs)](https://crates.io/crates/plt-rs)
[![Crates.io License](https://img.shields.io/crates/l/plt-rs)](https://github.com/ohchase/plt-rs/blob/master/LICENSE)

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
Here we are hooking our own executables usages of libc getpid,
and then restoring the function back to the original libc implementation.

```rust
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
```

```terminal
application pid is 159911
successfully identified executable
successfully initialized dynamic library for instrumentation
successfully identified libc getpid offset: 7FD38
cached previous function as value: FFFF9B7AD6C0
application new pid is: 999
restored plt entry
application restored pid is: 159911
```

## References / Inspirations
Projects I referenced and was heavily inspired by while working on this.
- [Plthook by Kubo] https://github.com/kubo/plthook
- [Bhook by bytedance] https://github.com/bytedance/bhook
