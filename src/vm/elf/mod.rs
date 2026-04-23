pub mod loader;

pub use loader::ElfLoader;

use x86_64::PhysAddr;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Elf64Ehdr {
    pub e_ident: [u8; 16],
    pub e_type: u16,
    pub e_machine: u16,
    pub e_version: u32,
    pub e_entry: u64,
    pub e_phoff: u64,
    pub e_shoff: u64,
    pub e_flags: u32,
    pub e_ehsize: u16,
    pub e_phentsize: u16,
    pub e_phnum: u16,
    pub e_shentsize: u16,
    pub e_shnum: u16,
    pub e_shstrndx: u16,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Elf64Phdr {
    pub p_type: u32,
    pub p_flags: u32,
    pub p_offset: u64,
    pub p_vaddr: u64,
    pub p_paddr: u64,
    pub p_filesz: u64,
    pub p_memsz: u64,
    pub p_align: u64,
}

pub const PT_NULL: u32 = 0;
pub const PT_LOAD: u32 = 1;
pub const PT_DYNAMIC: u32 = 2;
pub const PT_INTERP: u32 = 3;
pub const PT_NOTE: u32 = 4;
pub const PT_SHLIB: u32 = 5;
pub const PT_PHDR: u32 = 6;
pub const PT_TLS: u32 = 7;

pub const PF_X: u32 = 1;
pub const PF_W: u32 = 2;
pub const PF_R: u32 = 4;

pub const ELFMAG0: u8 = 0x7F;
pub const ELFMAG1: u8 = b'E';
pub const ELFMAG2: u8 = b'L';
pub const ELFMAG3: u8 = b'F';

pub const EI_CLASS: usize = 4;
pub const EI_DATA: usize = 5;
pub const EI_VERSION: usize = 6;
pub const EI_OSABI: usize = 7;
pub const EI_PAD: usize = 8;

pub const ELFCLASS64: u8 = 2;
pub const ELFDATA2LSB: u8 = 1;

pub const ET_EXEC: u16 = 2;
pub const ET_DYN: u16 = 3;

pub const EM_X86_64: u16 = 62;

impl Elf64Ehdr {
    pub fn is_valid(&self) -> bool {
        self.e_ident[0] == ELFMAG0 &&
        self.e_ident[1] == ELFMAG1 &&
        self.e_ident[2] == ELFMAG2 &&
        self.e_ident[3] == ELFMAG3 &&
        self.e_ident[EI_CLASS] == ELFCLASS64 &&
        self.e_ident[EI_DATA] == ELFDATA2LSB &&
        self.e_machine == EM_X86_64 &&
        (self.e_type == ET_EXEC || self.e_type == ET_DYN)
    }

    pub fn entry_point(&self) -> u64 {
        self.e_entry
    }

    pub fn phdr_count(&self) -> usize {
        self.e_phnum as usize
    }

    pub fn phdr_offset(&self) -> u64 {
        self.e_phoff
    }
}

pub struct LoadedElfInfo {
    pub entry_point: u64,
    pub lowest_vaddr: u64,
    pub highest_vaddr: u64,
    pub is_dynamic: bool,
}
