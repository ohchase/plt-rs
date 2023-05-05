use std::ffi::c_int;

use plt_rs::{LinkMapView, MutableLinkMap};

#[inline(never)]
unsafe fn hk_getpid() -> c_int {
    420
}

fn main() {
    let lib = unsafe { libloading::Library::new("libpayload.so").expect("load payload") };
    let func = unsafe {
        let func: libloading::Symbol<unsafe extern "C" fn() -> c_int> =
            lib.get(b"get_process_pid").expect("get pid function");
        func
    };

    use proc_maps::get_process_maps;

    let maps = unsafe { get_process_maps(func()).expect("maps") };

    let map_name = maps
        .iter()
        .flat_map(|m| m.filename())
        .find(|name| name.ends_with("libpayload.so"))
        .expect("find payload");

    let map_name = format!("{}\0", map_name.to_str().expect("to str"));
    println!("Target lib {map_name}");

    let link_map = LinkMapView::from_shared_library(&map_name).expect("open link map");

    let mut mutable_link_map: MutableLinkMap = MutableLinkMap::from_view(link_map);
    let _previous_function = mutable_link_map
        .hook::<unsafe fn() -> c_int>("getpid", hk_getpid as *const _)
        .expect("search for func")
        .unwrap();

    let new_pid = unsafe { func() };
    println!("New pid {new_pid}");
}
