use crate::{
    unixy::{ElfAddr, ElfDyn, ElfPhdr},
    LinkMap, LinkMapBacked,
};
use std::marker::PhantomData;

#[derive(Debug)]
pub struct LinkMapView<'a> {
    raw: LinkMap,

    // This is a copy of a link map actually in memory
    // It should be bound to some lifetime
    _life: PhantomData<&'a LinkMap>,
}

impl<'a> LinkMapBacked<'a> for LinkMapView<'a> {
    fn inner(&'a self) -> &'a LinkMap {
        &self.raw
    }

    fn dynamic_load_address(&'a self) -> ElfAddr {
        self.inner().l_addr
    }

    fn from_address(address: usize) -> Option<LinkMapView<'a>> {
        #[derive(Debug)]
        struct IterateData {
            address: usize,
            result: Option<(ElfAddr, *const ElfDyn)>,
        }

        let mut current_data = IterateData {
            address,
            result: None,
        };

        unsafe extern "C" fn iterate(
            info: *mut libc::dl_phdr_info,
            _size: libc::size_t,
            data: *mut libc::c_void,
        ) -> libc::c_int {
            let data: &mut IterateData = &mut *(data as *mut IterateData);

            let Some(dl_info) = info.as_ref() else {
                return 0;
            };
            if !does_contain_address(dl_info, data.address) {
                return 0;
            };

            let containing = find_dynamic_section(dl_info);
            match containing {
                Some(elf_dyn) => {
                    data.result = Some((dl_info.dlpi_addr, elf_dyn));
                    1
                }
                None => 0,
            }
        }

        if unsafe {
            libc::dl_iterate_phdr(
                Some(iterate),
                &mut current_data as *mut _ as *mut libc::c_void,
            ) != 0
        } {
            if let Some(result) = current_data.result {
                return Some(LinkMapView::new(result.0, result.1));
            }
        }
        None
    }
}

fn does_contain_address(dl_info: &libc::dl_phdr_info, target_address: usize) -> bool {
    for idx in 0..dl_info.dlpi_phnum as isize {
        let phdr: *const ElfPhdr = unsafe { dl_info.dlpi_phdr.offset(idx) };

        let phdr = unsafe {
            match phdr.as_ref() {
                Some(phdr) => phdr,
                None => continue,
            }
        };

        let base: usize = dl_info.dlpi_addr as usize + phdr.p_vaddr as usize;
        if base <= target_address && target_address < base + phdr.p_memsz as usize {
            return true;
        }
    }

    false
}

fn find_dynamic_section(dl_info: &libc::dl_phdr_info) -> Option<*const ElfDyn> {
    for idx in 0..dl_info.dlpi_phnum as isize {
        let phdr: *const ElfPhdr = unsafe { dl_info.dlpi_phdr.offset(idx) };

        let phdr = unsafe {
            match phdr.as_ref() {
                Some(phdr) => phdr,
                None => return None,
            }
        };

        if phdr.p_type == 0x02 {
            unsafe {
                return Some(std::mem::transmute::<*const _, *const ElfDyn>(
                    (dl_info.dlpi_addr as usize + phdr.p_vaddr as usize) as *const usize
                        as *const _,
                ));
            };
        }
    }

    None
}

impl<'a> LinkMapView<'a> {
    fn new(l_addr: ElfAddr, l_ld: *const ElfDyn) -> Self {
        Self {
            raw: LinkMap {
                l_addr,
                l_name: std::ptr::null(),
                l_ld,
                l_next: std::ptr::null(),
                l_prev: std::ptr::null(),
            },

            _life: PhantomData,
        }
    }
}
