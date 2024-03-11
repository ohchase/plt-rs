use super::DynamicSectionType;

pub type Word = libc::Elf64_Word;
pub type Half = libc::Elf64_Half;
pub type Addr = libc::Elf64_Addr;
pub type ExtendedWord = libc::Elf64_Xword;

// manual impl doesn't exist everywhere
pub type ExtendedSignedWord = i64;

pub type ProgramHeader = libc::Elf64_Phdr;

#[repr(C)]
#[derive(Debug)]
pub struct DynEntry {
    pub d_tag: libc::Elf64_Xword,
    /// Either a value (Elf64_Xword) or an address (Elf64_Addr)
    pub d_val_ptr: libc::Elf64_Xword,
}

#[repr(C)]
#[derive(Debug)]
pub struct DynSym {
    pub st_name: self::Word,
    pub st_info: u8,
    pub st_other: u8,
    pub st_shndx: self::Half,
    pub st_value: self::Addr,
    pub st_size: self::ExtendedWord,
}

#[repr(C)]
#[derive(Debug)]
pub struct DynRel {
    pub r_offset: self::Addr,
    pub r_info: self::ExtendedWord,
}

impl DynRel {
    pub fn symbol_index(&self) -> self::Word {
        (self.r_info >> 32) as self::Word
    }
    pub fn symbol_type(&self) -> self::Word {
        (self.r_info & 0xffffffff) as self::Word
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct DynRela {
    pub r_offset: self::Addr,
    pub r_info: self::ExtendedWord,
    pub r_addend: self::ExtendedSignedWord,
}

impl DynRela {
    pub fn symbol_index(&self) -> self::Word {
        (self.r_info >> 32) as self::Word
    }
    pub fn symbol_type(&self) -> self::Word {
        (self.r_info & 0xffffffff) as self::Word
    }
}

/// An unknown Dynamic Section Type was observed
#[derive(Debug, thiserror::Error)]
#[error("Unknown Dynamic section type witnessed: `{0}`")]
pub struct DynTypeError(self::ExtendedWord);

impl TryFrom<self::ExtendedWord> for DynamicSectionType {
    type Error = DynTypeError;
    fn try_from(value: self::ExtendedWord) -> Result<Self, Self::Error> {
        use DynamicSectionType::*;
        Ok(match value {
            0 => DT_NULL,

            2 => DT_PLTRELSZ,
            3 => DT_PLTGOT,
            20 => DT_PLTREL,

            5 => DT_STRTAB,
            6 => DT_SYMTAB,
            11 => DT_SYMENT,

            17 => DT_REL,
            18 => DT_RELSZ,
            19 => DT_RELENT,

            7 => DT_RELA,
            8 => DT_RELASZ,
            9 => DT_RELAENT,

            10 => DT_STRSZ,
            23 => DT_JMPREL,

            tag => return Err(DynTypeError(tag)),
        })
    }
}
