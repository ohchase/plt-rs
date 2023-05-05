use libc::c_int;

#[no_mangle]
pub extern "C" fn get_process_pid() -> c_int {
    let pid = unsafe { libc::getpid() };
    pid
}
