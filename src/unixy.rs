// 32 bit

#[cfg(all(target_os = "android", target_pointer_width = "32"))]
pub type ElfPhdr = libc::Elf32_Phdr;

#[cfg(target_pointer_width = "32")]
pub type ElfAddr = libc::Elf32_Addr;

#[cfg(target_pointer_width = "32")]
pub type ElfWord = libc::Elf32_Word;

#[cfg(target_pointer_width = "32")]
pub type ElfSword = libc::c_int;

#[cfg(target_pointer_width = "32")]
pub type ElfHalf = libc::Elf32_Half;

// 64 bit
#[cfg(all(target_os = "android", target_pointer_width = "64"))]
pub type ElfPhdr = libc::Elf64_Phdr;

#[cfg(target_pointer_width = "64")]
pub type ElfAddr = libc::Elf64_Addr;

#[cfg(target_pointer_width = "64")]
pub type ElfWord = libc::Elf64_Word;

#[cfg(target_pointer_width = "64")]
pub type ElfXword = libc::Elf64_Xword;

#[cfg(target_pointer_width = "64")]
pub type ElfSxword = i64;

#[cfg(target_pointer_width = "64")]
pub type ElfHalf = libc::Elf64_Half;

#[cfg(target_pointer_width = "64")]
#[repr(C)]
#[derive(Debug)]
pub struct ElfDyn {
    pub d_tag: ElfSxword,
    pub d_val: ElfXword,
}

#[cfg(target_pointer_width = "32")]
#[repr(C)]
#[derive(Debug)]
pub struct ElfDyn {
    pub d_tag: ElfSword,
    pub d_val: ElfWord,
}

#[cfg(target_pointer_width = "64")]
#[repr(C)]
#[derive(Debug)]
pub struct ElfRela {
    pub r_offset: ElfAddr,
    pub r_info: ElfXword,
    pub r_addend: ElfSxword,
}

#[cfg(target_pointer_width = "32")]
#[repr(C)]
#[derive(Debug)]
pub struct ElfRela {
    pub r_offset: ElfAddr,
    pub r_info: ElfWord,
    pub r_addend: ElfSword,
}

#[allow(dead_code)]
impl ElfRela {
    #[cfg(target_pointer_width = "64")]
    pub fn symbol_index(&self) -> ElfWord {
        (self.r_info >> 32) as ElfWord
    }

    #[cfg(target_pointer_width = "32")]
    pub fn symbol_index(&self) -> ElfWord {
        (self.r_info >> 8) as ElfWord
    }

    #[cfg(target_pointer_width = "64")]
    pub fn symbol_type(&self) -> ElfWord {
        (self.r_info & 0xffffffff) as ElfWord
    }

    #[cfg(target_pointer_width = "32")]
    pub fn symbol_type(&self) -> ElfWord {
        (self.r_info & 0x0ff) as ElfWord
    }
}

#[cfg(target_pointer_width = "64")]
#[repr(C)]
#[derive(Debug)]
pub struct ElfRel {
    pub r_offset: ElfAddr,
    pub r_info: ElfXword,
}

#[cfg(target_pointer_width = "32")]
#[repr(C)]
#[derive(Debug)]
pub struct ElfRel {
    pub r_offset: ElfAddr,
    pub r_info: ElfWord,
}

#[allow(dead_code)]
impl ElfRel {
    #[cfg(target_pointer_width = "64")]
    pub fn symbol_index(&self) -> ElfWord {
        (self.r_info >> 32) as ElfWord
    }

    #[cfg(target_pointer_width = "32")]
    pub fn symbol_index(&self) -> ElfWord {
        (self.r_info >> 8) as ElfWord
    }

    #[cfg(target_pointer_width = "64")]
    pub fn symbol_type(&self) -> ElfWord {
        (self.r_info & 0xffffffff) as ElfWord
    }

    #[cfg(target_pointer_width = "32")]
    pub fn symbol_type(&self) -> ElfWord {
        (self.r_info & 0x0ff) as ElfWord
    }
}

#[cfg(target_pointer_width = "64")]
#[repr(C)]
#[derive(Debug)]
pub struct ElfSym {
    pub st_name: ElfWord,
    pub st_info: u8,
    pub st_other: u8,
    pub st_shndx: ElfHalf,
    pub st_value: ElfAddr,
    pub st_size: ElfXword,
}

#[cfg(target_pointer_width = "32")]
#[repr(C)]
#[derive(Debug)]
pub struct ElfSym {
    pub st_name: ElfWord,
    pub st_value: ElfAddr,
    pub st_size: ElfWord,
    pub st_info: u8,
    pub st_other: u8,
    pub st_shndx: ElfHalf,
}

// Switch based on arch..
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub const R_GLOB_DAT: u32 = 6;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub const R_JUMP_SLOT: u32 = 7;

#[cfg(target_arch = "arm")]
pub const R_GLOB_DAT: u32 = 21;
#[cfg(target_arch = "arm")]
pub const R_JUMP_SLOT: u32 = 22;

#[cfg(target_arch = "aarch64")]
pub const R_GLOB_DAT: u32 = 1025;
#[cfg(target_arch = "aarch64")]
pub const R_JUMP_SLOT: u32 = 1026;

#[derive(Debug, Clone, Copy)]
#[allow(non_camel_case_types)]
pub enum SectionType {
    DT_PLTRELSZ,
    DT_PLTGOT,

    DT_STRTAB,
    DT_SYMTAB,

    DT_RELA,
    DT_RELASZ,
    DT_RELAENT,

    DT_REL,
    DT_RELSZ,
    DT_RELENT,

    DT_STRSZ,
    DT_JMPREL,
}

#[cfg(target_pointer_width = "64")]
impl From<SectionType> for i64 {
    fn from(val: SectionType) -> Self {
        match val {
            SectionType::DT_PLTRELSZ => 2,
            SectionType::DT_PLTGOT => 3,
            SectionType::DT_STRTAB => 5,
            SectionType::DT_SYMTAB => 6,

            SectionType::DT_REL => 17,
            SectionType::DT_RELSZ => 18,
            SectionType::DT_RELENT => 19,

            SectionType::DT_RELA => 7,
            SectionType::DT_RELASZ => 8,
            SectionType::DT_RELAENT => 9,

            SectionType::DT_STRSZ => 10,
            SectionType::DT_JMPREL => 23,
        }
    }
}

#[cfg(target_pointer_width = "32")]
impl From<SectionType> for i32 {
    fn from(val: SectionType) -> Self {
        match val {
            SectionType::DT_PLTRELSZ => 2,
            SectionType::DT_PLTGOT => 3,

            SectionType::DT_STRTAB => 5,
            SectionType::DT_SYMTAB => 6,

            SectionType::DT_RELA => 7,
            SectionType::DT_RELASZ => 8,
            SectionType::DT_RELAENT => 9,

            SectionType::DT_STRSZ => 10,
            SectionType::DT_JMPREL => 23,

            SectionType::DT_REL => 17,
            SectionType::DT_RELSZ => 18,
            SectionType::DT_RELENT => 19,
        }
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct LinkMap {
    pub l_addr: ElfAddr,
    pub l_name: *const libc::c_char,
    pub l_ld: *const ElfDyn,
    pub l_next: *const LinkMap,
    pub l_prev: *const LinkMap,
}
