use super::{Elf64Ehdr, Elf64Phdr, LoadedElfInfo, PT_LOAD, PF_R, PF_W, PF_X};
use crate::memory::ept::{EptManager, EptFlags};
use x86_64::PhysAddr;

pub struct ElfLoader;

impl ElfLoader {
    pub fn new() -> Self {
        Self
    }

    pub fn validate_elf(elf_data: &[u8]) -> Result<&Elf64Ehdr, &'static str> {
        if elf_data.len() < core::mem::size_of::<Elf64Ehdr>() {
            return Err("ELF 数据太小");
        }

        let ehdr = unsafe {
            &*(elf_data.as_ptr() as *const Elf64Ehdr)
        };

        if !ehdr.is_valid() {
            return Err("无效的 ELF 头");
        }

        Ok(ehdr)
    }

    pub fn load_elf(
        &self,
        elf_data: &[u8],
        ept_manager: &mut EptManager,
        load_offset: u64,
    ) -> Result<LoadedElfInfo, &'static str> {
        let ehdr = Self::validate_elf(elf_data)?;

        let phdr_count = ehdr.phdr_count();
        let phdr_offset = ehdr.phdr_offset();
        let phdr_size = core::mem::size_of::<Elf64Phdr>();

        if elf_data.len() < (phdr_offset + (phdr_count * phdr_size) as u64) as usize {
            return Err("程序头表超出 ELF 数据范围");
        }

        let mut lowest_vaddr = u64::MAX;
        let mut highest_vaddr = u64::MIN;
        let mut is_dynamic = false;

        for i in 0..phdr_count {
            let phdr_offset = phdr_offset + (i * phdr_size) as u64;
            let phdr = unsafe {
                &*(elf_data.as_ptr().add(phdr_offset as usize) as *const Elf64Phdr)
            };

            if phdr.p_type == PT_LOAD {
                let vaddr = phdr.p_vaddr + load_offset;
                let memsz = phdr.p_memsz;
                let filesz = phdr.p_filesz;
                let offset = phdr.p_offset;

                if vaddr < lowest_vaddr {
                    lowest_vaddr = vaddr;
                }
                if vaddr + memsz > highest_vaddr {
                    highest_vaddr = vaddr + memsz;
                }

                let flags = EptFlags::MEMORY_TYPE_WB
                    | if (phdr.p_flags & PF_R) != 0 { EptFlags::READ } else { EptFlags::empty() }
                    | if (phdr.p_flags & PF_W) != 0 { EptFlags::WRITE } else { EptFlags::empty() }
                    | if (phdr.p_flags & PF_X) != 0 { EptFlags::EXECUTE } else { EptFlags::empty() };

                self.load_segment(elf_data, offset, filesz, memsz, vaddr, flags, ept_manager)?;
            }
        }

        Ok(LoadedElfInfo {
            entry_point: ehdr.entry_point() + load_offset,
            lowest_vaddr,
            highest_vaddr,
            is_dynamic,
        })
    }

    fn load_segment(
        &self,
        elf_data: &[u8],
        file_offset: u64,
        filesz: u64,
        memsz: u64,
        vaddr: u64,
        flags: EptFlags,
        ept_manager: &mut EptManager,
    ) -> Result<(), &'static str> {
        let start_page = vaddr & !0xFFF;
        let end_page = (vaddr + memsz + 0xFFF) & !0xFFF;
        
        let mut current_gpa = start_page;
        while current_gpa < end_page {
            let frame = crate::memory::allocate_frame()
                .ok_or("分配物理帧失败")?;
            let hpa = frame.start_address();
            
            let virt = crate::memory::phys_to_virt(hpa);
            unsafe {
                core::ptr::write_bytes(virt.as_mut_ptr::<u8>(), 0, 4096);
            }
            
            let offset_in_page = (current_gpa - start_page) as usize;
            let segment_offset = current_gpa.saturating_sub(vaddr);
            
            if segment_offset < filesz {
                let copy_start = (file_offset + segment_offset) as usize;
                let copy_end = core::cmp::min(
                    (file_offset + filesz) as usize,
                    copy_start + 4096 - (vaddr & 0xFFF) as usize,
                );
                
                if copy_start < elf_data.len() && copy_end <= elf_data.len() {
                    let dst_offset = if current_gpa == start_page {
                        (vaddr & 0xFFF) as usize
                    } else {
                        0
                    };
                    
                    unsafe {
                        let src = elf_data.as_ptr().add(copy_start);
                        let dst = virt.as_mut_ptr::<u8>().add(dst_offset);
                        let count = copy_end - copy_start;
                        core::ptr::copy_nonoverlapping(src, dst, count);
                    }
                }
            }
            
            ept_manager.map(
                PhysAddr::new(current_gpa),
                hpa,
                flags,
            );
            
            current_gpa += 4096;
        }
        
        Ok(())
    }
}
