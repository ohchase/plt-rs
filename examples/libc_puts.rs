#[inline(never)]
unsafe fn puts_hooked(_input: *const libc::c_char) -> libc::c_int {
    let c_str: &std::ffi::CStr = unsafe { std::ffi::CStr::from_ptr(_input) };
    let str_slice: &str = c_str.to_str().unwrap();

    println!("Puts C was hooked. Intercepted: {:#?}", str_slice);
    0
}

fn get_mut_map<'a>() -> plt_rs::MutableLinkMap<'a> {
    use plt_rs::LinkMapBacked;

    let link_map = plt_rs::LinkMapView::from_address(main as *mut libc::c_void as usize)
        .expect("open link map");
    plt_rs::MutableLinkMap::from_view(link_map)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut mutable_link_map = get_mut_map();

    let _previous_function = mutable_link_map
        .hook::<unsafe fn(*const libc::c_char) -> libc::c_int>("puts", puts_hooked as *const _)?
        .unwrap();

    unsafe { libc::puts(String::from("Hello\0").as_ptr() as *const _) };
    Ok(())
}
