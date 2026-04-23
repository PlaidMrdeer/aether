use crate::arch::x86_64::vmx::{instructions::vmwrite, vmcs::VmcsField, GuestRegisters};

pub const X86_TRAP_DE: u8 = 0;
pub const X86_TRAP_DB: u8 = 1;
pub const X86_TRAP_NMI: u8 = 2;
pub const X86_TRAP_BP: u8 = 3;
pub const X86_TRAP_OF: u8 = 4;
pub const X86_TRAP_BR: u8 = 5;
pub const X86_TRAP_UD: u8 = 6;
pub const X86_TRAP_NM: u8 = 7;
pub const X86_TRAP_DF: u8 = 8;
pub const X86_TRAP_OLD_MF: u8 = 9;
pub const X86_TRAP_TS: u8 = 10;
pub const X86_TRAP_NP: u8 = 11;
pub const X86_TRAP_SS: u8 = 12;
pub const X86_TRAP_GP: u8 = 13;
pub const X86_TRAP_PF: u8 = 14;
pub const X86_TRAP_SPURIOUS: u8 = 15;
pub const X86_TRAP_MF: u8 = 16;
pub const X86_TRAP_AC: u8 = 17;
pub const X86_TRAP_MC: u8 = 18;
pub const X86_TRAP_XF: u8 = 19;
pub const X86_TRAP_VE: u8 = 20;
pub const X86_TRAP_CP: u8 = 21;

pub const VM_ENTRY_INTR_TYPE_HW_EXC: u32 = 3 << 8;
pub const VM_ENTRY_INTR_TYPE_SW_EXC: u32 = 6 << 8;
pub const VM_ENTRY_INTR_TYPE_EXT: u32 = 0 << 8;

pub struct ExceptionInfo {
    pub vector: u8,
    pub error_code: u64,
    pub cr2: u64,
    pub rip: u64,
}

pub struct GuestInterruptController {
    pending_interrupts: [bool; 256],
    pending_exceptions: [Option<u64>; 32],
}

impl GuestInterruptController {
    pub fn new() -> Self {
        Self {
            pending_interrupts: [false; 256],
            pending_exceptions: [None; 32],
        }
    }

    pub fn inject_interrupt(&mut self, vector: u8) {
        self.pending_interrupts[vector as usize] = true;
    }

    pub fn inject_exception(&mut self, vector: u8, error_code: u64) {
        if vector < 32 {
            self.pending_exceptions[vector as usize] = Some(error_code);
        }
    }

    pub fn clear_interrupt(&mut self, vector: u8) {
        self.pending_interrupts[vector as usize] = false;
    }

    pub fn clear_exception(&mut self, vector: u8) {
        if vector < 32 {
            self.pending_exceptions[vector as usize] = None;
        }
    }

    pub fn has_pending_interrupt(&self) -> Option<u8> {
        for (i, &pending) in self.pending_interrupts.iter().enumerate() {
            if pending {
                return Some(i as u8);
            }
        }
        None
    }

    pub fn has_pending_exception(&self) -> Option<(u8, u64)> {
        for (i, &error_code) in self.pending_exceptions.iter().enumerate() {
            if let Some(ec) = error_code {
                return Some((i as u8, ec));
            }
        }
        None
    }
}

pub fn inject_hardware_exception(vector: u8, error_code: u64) {
    let interruption_info: u32 = (1 << 31) | VM_ENTRY_INTR_TYPE_HW_EXC | (vector as u32);
    
    unsafe {
        vmwrite(VmcsField::VmEntryInterruptionInfo as u64, interruption_info as u64);
        vmwrite(VmcsField::VmEntryInterruptionErrorCode as u64, error_code);
    }
}

pub fn inject_software_exception(vector: u8, error_code: u64) {
    let interruption_info: u32 = (1 << 31) | VM_ENTRY_INTR_TYPE_SW_EXC | (vector as u32);
    
    unsafe {
        vmwrite(VmcsField::VmEntryInterruptionInfo as u64, interruption_info as u64);
        vmwrite(VmcsField::VmEntryInterruptionErrorCode as u64, error_code);
    }
}

pub fn inject_external_interrupt(vector: u8) {
    let interruption_info: u32 = (1 << 31) | VM_ENTRY_INTR_TYPE_EXT | (vector as u32);
    
    unsafe {
        vmwrite(VmcsField::VmEntryInterruptionInfo as u64, interruption_info as u64);
        vmwrite(VmcsField::VmEntryInterruptionErrorCode as u64, 0);
    }
}

pub fn clear_pending_interrupt() {
    unsafe {
        vmwrite(VmcsField::VmEntryInterruptionInfo as u64, 0);
        vmwrite(VmcsField::VmEntryInterruptionErrorCode as u64, 0);
    }
}

pub fn handle_page_fault(regs: &mut GuestRegisters, exit_qual: u64, guest_rip: u64) -> bool {
    let gpa = unsafe { crate::arch::x86_64::vmx::instructions::vmread(VmcsField::GuestPhysicalAddress as u64) };
    let is_write = (exit_qual & 0b10) != 0;
    let is_instruction_fetch = (exit_qual & 0b100) != 0;

    crate::log_debug!(
        "页面错误: RIP={:#x}, GPA={:#x}, write={}, fetch={}, exit_qual={:#x}",
        guest_rip, gpa, is_write, is_instruction_fetch, exit_qual
    );

    if is_write {
        let mut handled = false;
        let mut mgr_guard = crate::enclave::get_manager();
        if let Some(m) = mgr_guard.as_mut() {
            if let Some(id) = m.current_id() {
                if let Some(enclave) = m.get_enclave_mut(id) {
                    let mut ledger = crate::mmdl::ledger();
                    handled = ledger.handle_cow_fault(x86_64::PhysAddr::new(gpa), &mut enclave.ept, id as u16);
                    
                    if !handled {
                        handled = try_handle_demand_page(enclave, gpa, is_instruction_fetch);
                    }
                }
            }
        }
        if handled {
            return true;
        }
    }

    if !is_write {
        let mut mgr_guard = crate::enclave::get_manager();
        if let Some(m) = mgr_guard.as_mut() {
            if let Some(id) = m.current_id() {
                if let Some(enclave) = m.get_enclave_mut(id) {
                    if try_handle_demand_page(enclave, gpa, is_instruction_fetch) {
                        return true;
                    }
                }
            }
        }
    }

    let error_code = exit_qual & 0b111;
    inject_hardware_exception(X86_TRAP_PF, error_code);
    true
}

fn try_handle_demand_page(enclave: &mut crate::enclave::Enclave, gpa: u64, is_instruction_fetch: bool) -> bool {
    if gpa < 0x1000_0000 || gpa >= 0x8000_0000 {
        return false;
    }

    let page_gpa = gpa & !0xFFF;
    
    if enclave.ept.translate_gpa(x86_64::PhysAddr::new(page_gpa)).is_some() {
        return false;
    }

    if let Some(frame) = crate::memory::allocate_frame() {
        let hpa = frame.start_address();
        let virt = crate::memory::phys_to_virt(hpa);
        unsafe {
            core::ptr::write_bytes(virt.as_mut_ptr::<u8>(), 0, 4096);
        }

        let mut flags = crate::memory::ept::EptFlags::READ | crate::memory::ept::EptFlags::MEMORY_TYPE_WB;
        if !is_instruction_fetch {
            flags |= crate::memory::ept::EptFlags::WRITE;
        }
        flags |= crate::memory::ept::EptFlags::EXECUTE;

        enclave.ept.map(x86_64::PhysAddr::new(page_gpa), hpa, flags);
        crate::log_debug!("按需分配页面: GPA={:#x}, HPA={:#x}", page_gpa, hpa);
        true
    } else {
        false
    }
}

pub fn handle_general_protection(regs: &mut GuestRegisters, exit_qual: u64, guest_rip: u64) -> bool {
    crate::log_warn!("通用保护错误: RIP={:#x}, exit_qual={:#x}", guest_rip, exit_qual);
    
    let error_code = exit_qual & 0xFFFF;
    inject_hardware_exception(X86_TRAP_GP, error_code);
    true
}

pub fn handle_invalid_opcode(regs: &mut GuestRegisters, exit_qual: u64, guest_rip: u64) -> bool {
    crate::log_warn!("无效操作码: RIP={:#x}, exit_qual={:#x}", guest_rip, exit_qual);
    
    inject_hardware_exception(X86_TRAP_UD, 0);
    true
}

pub fn handle_device_not_available(regs: &mut GuestRegisters, exit_qual: u64, guest_rip: u64) -> bool {
    crate::log_debug!("设备不可用 (FPU/MMX/SSE): RIP={:#x}", guest_rip);
    
    inject_hardware_exception(X86_TRAP_NM, 0);
    true
}

pub fn handle_divide_error(regs: &mut GuestRegisters, exit_qual: u64, guest_rip: u64) -> bool {
    crate::log_debug!("除法错误: RIP={:#x}", guest_rip);
    
    inject_hardware_exception(X86_TRAP_DE, 0);
    true
}

pub fn handle_overflow(regs: &mut GuestRegisters, exit_qual: u64, guest_rip: u64) -> bool {
    crate::log_debug!("溢出错误: RIP={:#x}", guest_rip);
    
    inject_hardware_exception(X86_TRAP_OF, 0);
    true
}

pub fn handle_bound_range_exceeded(regs: &mut GuestRegisters, exit_qual: u64, guest_rip: u64) -> bool {
    crate::log_debug!("边界范围超出: RIP={:#x}", guest_rip);
    
    inject_hardware_exception(X86_TRAP_BR, 0);
    true
}

pub fn handle_double_fault(regs: &mut GuestRegisters, exit_qual: u64, guest_rip: u64) -> bool {
    crate::log_error!("双重故障: RIP={:#x}, 隔离域将被终止", guest_rip);
    false
}

pub fn handle_invalid_tss(regs: &mut GuestRegisters, exit_qual: u64, guest_rip: u64) -> bool {
    crate::log_warn!("无效 TSS: RIP={:#x}, exit_qual={:#x}", guest_rip, exit_qual);
    
    let error_code = exit_qual & 0xFFFF;
    inject_hardware_exception(X86_TRAP_TS, error_code);
    true
}

pub fn handle_segment_not_present(regs: &mut GuestRegisters, exit_qual: u64, guest_rip: u64) -> bool {
    crate::log_warn!("段不存在: RIP={:#x}, exit_qual={:#x}", guest_rip, exit_qual);
    
    let error_code = exit_qual & 0xFFFF;
    inject_hardware_exception(X86_TRAP_NP, error_code);
    true
}

pub fn handle_stack_segment_fault(regs: &mut GuestRegisters, exit_qual: u64, guest_rip: u64) -> bool {
    crate::log_warn!("栈段错误: RIP={:#x}, exit_qual={:#x}", guest_rip, exit_qual);
    
    let error_code = exit_qual & 0xFFFF;
    inject_hardware_exception(X86_TRAP_SS, error_code);
    true
}

pub fn handle_machine_check(regs: &mut GuestRegisters, exit_qual: u64, guest_rip: u64) -> bool {
    crate::log_error!("机器检查异常: RIP={:#x}", guest_rip);
    false
}

pub fn handle_floating_point_error(regs: &mut GuestRegisters, exit_qual: u64, guest_rip: u64) -> bool {
    crate::log_debug!("浮点错误: RIP={:#x}", guest_rip);
    
    inject_hardware_exception(X86_TRAP_MF, 0);
    true
}

pub fn handle_alignment_check(regs: &mut GuestRegisters, exit_qual: u64, guest_rip: u64) -> bool {
    crate::log_debug!("对齐检查: RIP={:#x}", guest_rip);
    
    let error_code = 0;
    inject_hardware_exception(X86_TRAP_AC, error_code);
    true
}

pub fn handle_sse_numeric_error(regs: &mut GuestRegisters, exit_qual: u64, guest_rip: u64) -> bool {
    crate::log_debug!("SSE 数值错误: RIP={:#x}", guest_rip);
    
    inject_hardware_exception(X86_TRAP_XF, 0);
    true
}
