use std::{borrow::Cow, ffi::CStr};

use crate::{unixy::ElfAddr, LinkMap, LinkMapBacked};

#[derive(Debug)]
pub struct LinkMapView<'a> {
    raw: &'a LinkMap,
}

impl<'a> LinkMapView<'a> {
    pub fn next(&self) -> Option<LinkMapView<'a>> {
        let candidate_next = self.inner().l_next;
        unsafe { candidate_next.as_ref() }.map(|r| LinkMapView { raw: r })
    }

    pub fn previous(&self) -> Option<LinkMapView<'a>> {
        let candidate_next = self.inner().l_prev;
        unsafe { candidate_next.as_ref() }.map(|r| LinkMapView { raw: r })
    }

    pub fn name(&self) -> Option<Cow<'a, str>> {
        match self.inner().l_name.is_null() {
            true => None,
            false => unsafe { Some(CStr::from_ptr(self.inner().l_name).to_string_lossy()) },
        }
    }

    pub fn from_shared_library(library_name: &str) -> Option<LinkMapView<'a>> {
        let mut output: *mut LinkMap = std::ptr::null_mut();

        unsafe {
            let handle = libc::dlopen(
                library_name.as_ptr() as *const libc::c_char,
                libc::RTLD_LAZY | libc::RTLD_NOLOAD,
            );

            if handle.is_null() {
                return None;
            }

            let res = libc::dlinfo(
                handle,
                libc::RTLD_DI_LINKMAP,
                &mut output as *mut *mut LinkMap as *mut libc::c_void,
            );

            if libc::dlclose(handle) != 0 {
                // todo
            }

            if res == -1 {
                return None;
            }

            Some(LinkMapView {
                raw: output.as_ref()?,
            })
        }
    }
}

impl<'a> LinkMapBacked<'a> for LinkMapView<'a> {
    fn inner(&'a self) -> &'a LinkMap {
        self.raw
    }

    fn dynamic_load_address(&'a self) -> ElfAddr {
        0
    }

    fn from_address(address: usize) -> Option<LinkMapView<'a>> {
        let mut info = libc::Dl_info {
            dli_fname: std::ptr::null(),
            dli_fbase: std::ptr::null_mut(),
            dli_sname: std::ptr::null(),
            dli_saddr: std::ptr::null_mut(),
        };

        let mut output = std::ptr::null_mut();
        unsafe {
            let addr_result = libc::dladdr1(
                address as *const libc::c_void,
                &mut info,
                &mut output,
                libc::RTLD_DI_LINKMAP,
            );
            if addr_result == 0 {
                return None;
            }

            let output: *mut LinkMap = output as *mut _ as *mut LinkMap;
            Some(LinkMapView {
                raw: output.as_ref()?,
            })
        }
    }
}
