use plt_rs::LinkMapBacked;

#[test]
fn can_load_own_link_map() {
    use plt_rs::LinkMapView;

    let link_map = LinkMapView::from_address(can_load_own_link_map as *const usize as usize);
    assert!(link_map.is_some())
}

#[test]
fn can_hook_getpid() {
    use plt_rs::LinkMapView;
    use plt_rs::MutableLinkMap;

    #[inline(never)]
    unsafe fn getpid_hk() -> libc::c_int {
        808
    }

    let link_map = LinkMapView::from_address(can_hook_getpid as *mut libc::c_void as usize)
        .expect("open link map");
    let mut mutable_link_map: MutableLinkMap = MutableLinkMap::from_view(link_map);

    let _previous_function = mutable_link_map
        .hook::<unsafe fn() -> libc::c_int>("getpid", getpid_hk as *const _)
        .expect("iterate")
        .unwrap();

    let pid = unsafe { libc::getpid() };
    assert_eq!(pid, 808)
}
