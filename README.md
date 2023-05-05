# PLT-RS
Get in losers we are hooking the procedural linkage tables

## Derivatives
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

## Look at all these ~~chickens~~ targets
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
Here we are hooking our own executables usages of libc puts

```rust
#[inline(never)]
unsafe fn puts_hooked(_input: *const libc::c_char) -> libc::c_int {
    let c_str: &std::ffi::CStr = unsafe { std::ffi::CStr::from_ptr(_input) };
    let str_slice: &str = c_str.to_str().unwrap();
    println!("Puts C was hooked. Intercepted: {:#?}", str_slice);
    0
}

fn get_mut_map<'a>() -> plt::MutableLinkMap<'a> {
    use plt::LinkMapBacked;
    let link_map =
        plt::LinkMapView::from_address(main as *mut libc::c_void as usize).expect("open link map");
    plt::MutableLinkMap::from_view(link_map)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut mutable_link_map = get_mut_map();
    let _previous_function = mutable_link_map
        .hook::<unsafe fn(*const libc::c_char) -> libc::c_int>("puts", puts_hooked as *const _)?
        .unwrap();
    unsafe { libc::puts(String::from("Hello\0").as_ptr() as *const _) };
    Ok(())
}
```

Below you can see it works on both debug and release build.


```shell
    Finished dev [unoptimized + debuginfo] target(s) in 0.32s
     Running `target/debug/examples/libc_puts`
Puts C was hooked. Intercepted: "Hello"
```

```shell
    Finished release [optimized] target(s) in 8.09s
     Running `target/release/examples/libc_puts`
Puts C was hooked. Intercepted: "Hello"
```
