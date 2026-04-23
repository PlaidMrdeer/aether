/* src/vm/exit.rs */
use crate::arch::x86_64::vmx::{GuestRegisters, instructions::{vmread, vmwrite}, vmcs::VmcsField};
use crate::vm::syscall::SyscallHandler;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitReason {
    ExceptionOrNmi,
    ExternalInterrupt,
    TripleFault,
    Init,
    Sipi,
    IoSmi,
    OtherSmi,
    InterruptWindow,
    NmiWindow,
    TaskSwitch,
    Cpuid,
    Hlt,
    Invd,
    Invlpg,
    Rdpmc,
    Rdtsc,
    Rsm,
    Vmcall,
    Vmclear,
    Vmlaunch,
    Vmptrld,
    Vmptrst,
    Vmread,
    Vmresume,
    Vmwrite,
    Vmxoff,
    Vmxon,
    CrAccess,
    DrAccess,
    Io,
    Msr,
    FailedVmEntry,
    FailedVmExit,
    EptViolation,
    EptMisconfig,
    Invept,
    Invvpid,
    VmxPreemptionTimer,
    Wbinvd,
    Xsetbv,
    ApicWrite,
    Rdrand,
    Invpcid,
    Vmfunc,
    Encls,
    Unhandled(u32),
}

impl ExitReason {
    pub fn from_u32(val: u32) -> Self {
        match val {
            0 => ExitReason::ExceptionOrNmi,
            1 => ExitReason::ExternalInterrupt,
            2 => ExitReason::TripleFault,
            3 => ExitReason::Init,
            4 => ExitReason::Sipi,
            5 => ExitReason::IoSmi,
            6 => ExitReason::OtherSmi,
            7 => ExitReason::InterruptWindow,
            8 => ExitReason::NmiWindow,
            9 => ExitReason::TaskSwitch,
            10 => ExitReason::Cpuid,
            12 => ExitReason::Hlt,
            13 => ExitReason::Invd,
            14 => ExitReason::Invlpg,
            15 => ExitReason::Rdpmc,
            16 => ExitReason::Rdtsc,
            17 => ExitReason::Rsm,
            18 => ExitReason::Vmcall,
            19 => ExitReason::Vmclear,
            20 => ExitReason::Vmlaunch,
            21 => ExitReason::Vmptrld,
            22 => ExitReason::Vmptrst,
            23 => ExitReason::Vmread,
            24 => ExitReason::Vmresume,
            25 => ExitReason::Vmwrite,
            26 => ExitReason::Vmxoff,
            27 => ExitReason::Vmxon,
            28 => ExitReason::CrAccess,
            29 => ExitReason::DrAccess,
            30 => ExitReason::Io,
            31 => ExitReason::Msr,
            32 => ExitReason::FailedVmEntry,
            33 => ExitReason::FailedVmExit,
            48 => ExitReason::EptViolation,
            49 => ExitReason::EptMisconfig,
            50 => ExitReason::Invept,
            51 => ExitReason::Invvpid,
            52 => ExitReason::VmxPreemptionTimer,
            53 => ExitReason::Wbinvd,
            54 => ExitReason::Xsetbv,
            55 => ExitReason::ApicWrite,
            56 => ExitReason::Rdrand,
            57 => ExitReason::Invpcid,
            58 => ExitReason::Vmfunc,
            59 => ExitReason::Encls,
            x => ExitReason::Unhandled(x),
        }
    }
}

fn handle_vmcall(regs: &mut GuestRegisters) -> bool {
    let hypercall_nr = regs.rcx as u8;
    let args = crate::vm::hypercall::HypercallArgs {
        arg1: regs.rdx,
        arg2: regs.rsi,
        arg3: regs.rdi,
        arg4: regs.r8,
        arg5: regs.r9,
    };

    regs.rax = crate::vm::hypercall::dispatch(args, regs, hypercall_nr);
    true
}

fn handle_preemption_timer(_regs: &mut GuestRegisters) -> bool {
    crate::log_debug!("VMX preemption timer fired");
    true
}

fn check_syscall_instruction(guest_rip: u64, regs: &mut GuestRegisters) -> Option<usize> {
    let mut mgr = crate::enclave::get_manager();
    let manager = mgr.as_mut()?;
    let cur = manager.current_id()?;
    let enclave = manager.get_enclave_mut(cur)?;

    let mut instr_bytes = [0u8; 16];
    let n = crate::vm::hypercall::utils::copy_guest_gpa_bytes(&enclave.ept, guest_rip, &mut instr_bytes);
    
    if n < 2 {
        return None;
    }

    if instr_bytes[0] == 0x0F && instr_bytes[1] == 0x05 {
        let next_rip = guest_rip + 2;
        regs.rcx = next_rip;
        regs.r11 = 0x02;
        
        regs.rax = regs.rax;
        return Some(2);
    }

    if instr_bytes[0] == 0x0F && instr_bytes[1] == 0x07 {
        crate::log_debug!("检测到 sysret 指令");
        return Some(2);
    }

    None
}

const MSR_IA32_APIC_BASE: u32 = 0x1B;
const MSR_IA32_EFER: u32 = 0xC0000080;
const MSR_IA32_STAR: u32 = 0xC0000081;
const MSR_IA32_LSTAR: u32 = 0xC0000082;
const MSR_IA32_CSTAR: u32 = 0xC0000083;
const MSR_IA32_FMASK: u32 = 0xC0000084;
const MSR_IA32_FS_BASE: u32 = 0xC0000100;
const MSR_IA32_GS_BASE: u32 = 0xC0000101;
const MSR_IA32_KERNEL_GS_BASE: u32 = 0xC0000102;
const MSR_IA32_TSC_AUX: u32 = 0xC0000103;
const MSR_IA32_SYSENTER_CS: u32 = 0x174;
const MSR_IA32_SYSENTER_ESP: u32 = 0x175;
const MSR_IA32_SYSENTER_EIP: u32 = 0x176;

pub struct MacroRealmMsrState {
    pub star: u64,
    pub lstar: u64,
    pub cstar: u64,
    pub fmask: u64,
    pub fs_base: u64,
    pub gs_base: u64,
    pub kernel_gs_base: u64,
    pub sysenter_cs: u64,
    pub sysenter_esp: u64,
    pub sysenter_eip: u64,
    pub efer: u64,
}

pub static mut GUEST_MSR_STATE: MacroRealmMsrState = MacroRealmMsrState {
    star: 0,
    lstar: 0,
    cstar: 0,
    fmask: 0,
    fs_base: 0,
    gs_base: 0,
    kernel_gs_base: 0,
    sysenter_cs: 0,
    sysenter_esp: 0,
    sysenter_eip: 0,
    efer: 0x500,
};

fn handle_msr_access(regs: &mut GuestRegisters, exit_qual: u64) -> bool {
    let msr_id = regs.rcx as u32;
    let is_write = exit_qual != 0;

    if is_write {
        let value = (regs.rdx << 32) | (regs.rax & 0xFFFFFFFF);
        match msr_id {
            MSR_IA32_STAR => {
                unsafe { GUEST_MSR_STATE.star = value };
            }
            MSR_IA32_LSTAR => {
                unsafe { GUEST_MSR_STATE.lstar = value };
            }
            MSR_IA32_CSTAR => {
                unsafe { GUEST_MSR_STATE.cstar = value };
            }
            MSR_IA32_FMASK => {
                unsafe { GUEST_MSR_STATE.fmask = value };
            }
            MSR_IA32_FS_BASE => {
                unsafe { GUEST_MSR_STATE.fs_base = value };
            }
            MSR_IA32_GS_BASE => {
                unsafe { GUEST_MSR_STATE.gs_base = value };
            }
            MSR_IA32_KERNEL_GS_BASE => {
                unsafe { GUEST_MSR_STATE.kernel_gs_base = value };
            }
            MSR_IA32_SYSENTER_CS => {
                unsafe { GUEST_MSR_STATE.sysenter_cs = value };
            }
            MSR_IA32_SYSENTER_ESP => {
                unsafe { GUEST_MSR_STATE.sysenter_esp = value };
            }
            MSR_IA32_SYSENTER_EIP => {
                unsafe { GUEST_MSR_STATE.sysenter_eip = value };
            }
            MSR_IA32_EFER => {
                unsafe { GUEST_MSR_STATE.efer = value | 0x500 };
            }
            MSR_IA32_APIC_BASE => {
            }
            _ => {
                crate::log_debug!("拦截到隔离域 MSR 写入: {:#x} 内容: {:#x}", msr_id, value);
            }
        }
    } else {
        match msr_id {
            MSR_IA32_APIC_BASE => {
                regs.rax = 0xfee00000 | (1 << 11);
                regs.rdx = 0;
            }
            MSR_IA32_EFER => {
                let val = unsafe { GUEST_MSR_STATE.efer };
                regs.rax = val & 0xFFFFFFFF;
                regs.rdx = val >> 32;
            }
            MSR_IA32_STAR => {
                let val = unsafe { GUEST_MSR_STATE.star };
                regs.rax = val & 0xFFFFFFFF;
                regs.rdx = val >> 32;
            }
            MSR_IA32_LSTAR => {
                let val = unsafe { GUEST_MSR_STATE.lstar };
                regs.rax = val & 0xFFFFFFFF;
                regs.rdx = val >> 32;
            }
            MSR_IA32_CSTAR => {
                let val = unsafe { GUEST_MSR_STATE.cstar };
                regs.rax = val & 0xFFFFFFFF;
                regs.rdx = val >> 32;
            }
            MSR_IA32_FMASK => {
                let val = unsafe { GUEST_MSR_STATE.fmask };
                regs.rax = val & 0xFFFFFFFF;
                regs.rdx = val >> 32;
            }
            MSR_IA32_FS_BASE => {
                let val = unsafe { GUEST_MSR_STATE.fs_base };
                regs.rax = val & 0xFFFFFFFF;
                regs.rdx = val >> 32;
            }
            MSR_IA32_GS_BASE => {
                let val = unsafe { GUEST_MSR_STATE.gs_base };
                regs.rax = val & 0xFFFFFFFF;
                regs.rdx = val >> 32;
            }
            MSR_IA32_KERNEL_GS_BASE => {
                let val = unsafe { GUEST_MSR_STATE.kernel_gs_base };
                regs.rax = val & 0xFFFFFFFF;
                regs.rdx = val >> 32;
            }
            MSR_IA32_SYSENTER_CS => {
                let val = unsafe { GUEST_MSR_STATE.sysenter_cs };
                regs.rax = val & 0xFFFFFFFF;
                regs.rdx = val >> 32;
            }
            MSR_IA32_SYSENTER_ESP => {
                let val = unsafe { GUEST_MSR_STATE.sysenter_esp };
                regs.rax = val & 0xFFFFFFFF;
                regs.rdx = val >> 32;
            }
            MSR_IA32_SYSENTER_EIP => {
                let val = unsafe { GUEST_MSR_STATE.sysenter_eip };
                regs.rax = val & 0xFFFFFFFF;
                regs.rdx = val >> 32;
            }
            MSR_IA32_TSC_AUX => {
                regs.rax = 0;
                regs.rdx = 0;
            }
            _ => {
                crate::log_debug!("拦截到未处理的 MSR 读取: {:#x}", msr_id);
                regs.rax = 0;
                regs.rdx = 0;
            }
        }
    }
    true
}

fn handle_cr_access(regs: &mut GuestRegisters, exit_qual: u64) -> bool {
    let cr_num = ((exit_qual >> 8) & 0xF) as u8;
    let access_type = ((exit_qual >> 4) & 0x3) as u8;

    match access_type {
        0 => {
            let value = match cr_num {
                0 => {
                    let guest_cr0 = unsafe { vmread(VmcsField::GuestCr0 as u64) };
                    guest_cr0
                }
                3 => {
                    let guest_cr3 = unsafe { vmread(VmcsField::GuestCr3 as u64) };
                    guest_cr3
                }
                4 => {
                    let guest_cr4 = unsafe { vmread(VmcsField::GuestCr4 as u64) };
                    guest_cr4
                }
                2 => 0,
                _ => {
                    crate::log_warn!("未处理的控制寄存器读取: CR{}", cr_num);
                    0
                }
            };
            match cr_num {
                0 => regs.rax = value,
                3 => regs.rax = value,
                4 => regs.rax = value,
                _ => {}
            }
        }
        1 => {
            let value = match cr_num {
                0 => regs.rax,
                3 => regs.rax,
                4 => regs.rax,
                _ => regs.rax,
            };
            match cr_num {
                0 => {
                    unsafe { vmwrite(VmcsField::GuestCr0 as u64, value) };
                }
                3 => {
                    unsafe { vmwrite(VmcsField::GuestCr3 as u64, value) };
                }
                4 => {
                    unsafe { vmwrite(VmcsField::GuestCr4 as u64, value) };
                }
                _ => {
                    crate::log_warn!("未处理的控制寄存器写入: CR{} = {:#x}", cr_num, value);
                }
            }
        }
        2 => {
            crate::log_debug!("CLTS 指令执行");
            let guest_cr0 = unsafe { vmread(VmcsField::GuestCr0 as u64) };
            unsafe { vmwrite(VmcsField::GuestCr0 as u64, guest_cr0 & !(1 << 3)) };
        }
        3 => {
            crate::log_debug!("LMSW 指令执行");
        }
        _ => {}
    }
    true
}

fn handle_io_access(regs: &mut GuestRegisters, exit_qual: u64) -> bool {
    let is_in = (exit_qual & 0x1) == 0;
    let is_string = (exit_qual & 0x4) != 0;
    let is_rep = (exit_qual & 0x8) != 0;
    let operand_size = ((exit_qual >> 5) & 0x3) as u8;
    let port = ((exit_qual >> 16) & 0xFFFF) as u16;

    if is_string || is_rep {
        crate::log_warn!("字符串 I/O 操作尚未完全支持");
        return true;
    }

    match port {
        0x3F8 => {
            if is_in {
                match operand_size {
                    1 => regs.rax = (regs.rax & !0xFF) | 0x20,
                    2 => regs.rax = (regs.rax & !0xFFFF) | 0x20,
                    _ => {}
                }
            } else {
                let byte = (regs.rax & 0xFF) as u8;
                if byte >= 0x20 && byte < 0x7F || byte == b'\n' || byte == b'\r' || byte == b'\t' {
                    crate::serial_print!("{}", byte as char);
                }
            }
        }
        0x3F9..=0x3FF => {
            if is_in {
                match operand_size {
                    1 => regs.rax = (regs.rax & !0xFF) | 0x00,
                    2 => regs.rax = (regs.rax & !0xFFFF) | 0x00,
                    _ => {}
                }
            }
        }
        _ => {
            if is_in {
                crate::log_debug!("未处理的 I/O 端口读取: port={:#x}, size={}", port, operand_size);
                match operand_size {
                    1 => regs.rax = (regs.rax & !0xFF) | 0xFF,
                    2 => regs.rax = (regs.rax & !0xFFFF) | 0xFFFF,
                    4 => regs.rax = 0xFFFFFFFF,
                    _ => {}
                }
            } else {
                crate::log_debug!("未处理的 I/O 端口写入: port={:#x}, value={:#x}", port, regs.rax);
            }
        }
    }
    true
}

fn handle_cpuid(regs: &mut GuestRegisters) {
    let leaf = regs.rax as u32;
    let subleaf = regs.rcx as u32;

    match leaf {
        0x00000000 => {
            regs.rax = 0x0000000D;
            regs.rbx = 0x756E6547;
            regs.rcx = 0x6C65746E;
            regs.rdx = 0x49656E69;
        }
        0x00000001 => {
            regs.rax = 0x000306A9;
            regs.rbx = 0x00020800;
            regs.rcx = 1 << 31 | 1 << 26 | 1 << 24 | 1 << 23 | 1 << 22 | 1 << 21 | 1 << 20 | 1 << 19 | 1 << 17 | 1 << 16 | 1 << 13 | 1 << 9 | 1 << 8 | 1 << 5 | 1 << 4 | 1 << 3 | 1 << 2 | 1 << 1 | 1 << 0;
            regs.rdx = 1 << 29 | 1 << 28 | 1 << 27 | 1 << 26 | 1 << 25 | 1 << 24 | 1 << 23 | 1 << 22 | 1 << 21 | 1 << 19 | 1 << 18 | 1 << 17 | 1 << 16 | 1 << 15 | 1 << 14 | 1 << 13 | 1 << 12 | 1 << 11 | 1 << 9 | 1 << 8 | 1 << 6 | 1 << 5 | 1 << 4 | 1 << 3 | 1 << 0;
        }
        0x00000002 => {
            regs.rax = 0x76036301;
            regs.rbx = 0x00F0B2FF;
            regs.rcx = 0x00000000;
            regs.rdx = 0x00CA0000;
        }
        0x00000003 => {
            regs.rax = 0x00000000;
            regs.rbx = 0x00000000;
            regs.rcx = 0x00000000;
            regs.rdx = 0x00000000;
        }
        0x00000004 => {
            regs.rax = 0x00000121;
            regs.rbx = 0x01C0003F;
            regs.rcx = 0x0000003F;
            regs.rdx = 0x00000000;
        }
        0x00000005 => {
            regs.rax = 0x00000040;
            regs.rbx = 0x00000040;
            regs.rcx = 0x00000003;
            regs.rdx = 0x00000020;
        }
        0x00000006 => {
            regs.rax = 0x00000001;
            regs.rbx = 0x00000002;
            regs.rcx = 0x00000001;
            regs.rdx = 0x00000000;
        }
        0x00000007 => {
            match subleaf {
                0 => {
                    regs.rax = 0x00000000;
                    regs.rbx = 1 << 12 | 1 << 9 | 1 << 7 | 1 << 5 | 1 << 4 | 1 << 3 | 1 << 2 | 1 << 1 | 1 << 0;
                    regs.rcx = 1 << 14 | 1 << 10 | 1 << 8 | 1 << 6 | 1 << 4 | 1 << 3 | 1 << 2 | 1 << 0;
                    regs.rdx = 1 << 18 | 1 << 17 | 1 << 16 | 1 << 15 | 1 << 14 | 1 << 12 | 1 << 11 | 1 << 10 | 1 << 9 | 1 << 8 | 1 << 7 | 1 << 4 | 1 << 3 | 1 << 2 | 1 << 1 | 1 << 0;
                }
                _ => {
                    regs.rax = 0;
                    regs.rbx = 0;
                    regs.rcx = 0;
                    regs.rdx = 0;
                }
            }
        }
        0x00000009 => {
            regs.rax = 0x00000000;
            regs.rbx = 0x00000000;
            regs.rcx = 0x00000000;
            regs.rdx = 0x00000000;
        }
        0x0000000A => {
            regs.rax = 0x07300403;
            regs.rbx = 0x00000004;
            regs.rcx = 0x00000000;
            regs.rdx = 0x00000603;
        }
        0x0000000B => {
            match subleaf {
                0 => {
                    regs.rax = 0x00000001;
                    regs.rbx = 0x00000002;
                    regs.rcx = 0x00000100;
                    regs.rdx = 0x00000000;
                }
                1 => {
                    regs.rax = 0x00000004;
                    regs.rbx = 0x00000008;
                    regs.rcx = 0x00000201;
                    regs.rdx = 0x00000000;
                }
                _ => {
                    regs.rax = 0;
                    regs.rbx = 0;
                    regs.rcx = 0;
                    regs.rdx = 0;
                }
            }
        }
        0x0000000D => {
            match subleaf {
                0 => {
                    regs.rax = 0x00000007;
                    regs.rbx = 0x00000340;
                    regs.rcx = 0x00000340;
                    regs.rdx = 0x00000000;
                }
                1 => {
                    regs.rax = 0x00000002;
                    regs.rbx = 0x00000000;
                    regs.rcx = 0x00000000;
                    regs.rdx = 0x00000000;
                }
                2 => {
                    regs.rax = 0x00000100;
                    regs.rbx = 0x00000240;
                    regs.rcx = 0x00000000;
                    regs.rdx = 0x00000000;
                }
                _ => {
                    regs.rax = 0;
                    regs.rbx = 0;
                    regs.rcx = 0;
                    regs.rdx = 0;
                }
            }
        }
        0x80000000 => {
            regs.rax = 0x8000000A;
            regs.rbx = 0x00000000;
            regs.rcx = 0x00000000;
            regs.rdx = 0x00000000;
        }
        0x80000001 => {
            regs.rax = 0x000306A9;
            regs.rbx = 0x00000000;
            regs.rcx = 1 << 31 | 1 << 29 | 1 << 28 | 1 << 27 | 1 << 26 | 1 << 25 | 1 << 24 | 1 << 23 | 1 << 22 | 1 << 21 | 1 << 20 | 1 << 17 | 1 << 16 | 1 << 10 | 1 << 8 | 1 << 5;
            regs.rdx = 1 << 31 | 1 << 29 | 1 << 28 | 1 << 27 | 1 << 26 | 1 << 25 | 1 << 24 | 1 << 23 | 1 << 22 | 1 << 21 | 1 << 20 | 1 << 19 | 1 << 18 | 1 << 17 | 1 << 16 | 1 << 15 | 1 << 14 | 1 << 13 | 1 << 12 | 1 << 11 | 1 << 10 | 1 << 9 | 1 << 8 | 1 << 7 | 1 << 6 | 1 << 5;
        }
        0x80000002 => {
            regs.rax = 0x65746E49;
            regs.rbx = 0x2952286C;
            regs.rcx = 0x6F725020;
            regs.rdx = 0x73736563;
        }
        0x80000003 => {
            regs.rax = 0x206F7369;
            regs.rbx = 0x20352E32;
            regs.rcx = 0x47206874;
            regs.rdx = 0x00000000;
        }
        0x80000004 => {
            regs.rax = 0x00000000;
            regs.rbx = 0x00000000;
            regs.rcx = 0x00000000;
            regs.rdx = 0x00000000;
        }
        0x80000005 => {
            regs.rax = 0xFF08FF08;
            regs.rbx = 0xFF20FF20;
            regs.rcx = 0x40020140;
            regs.rdx = 0x40020140;
        }
        0x80000006 => {
            regs.rax = 0x00000000;
            regs.rbx = 0x42004200;
            regs.rcx = 0x02008140;
            regs.rdx = 0x00000000;
        }
        0x80000007 => {
            regs.rax = 0x00000000;
            regs.rbx = 0x00000000;
            regs.rcx = 0x00000000;
            regs.rdx = 0x00000100;
        }
        0x80000008 => {
            regs.rax = 0x00003028;
            regs.rbx = 0x00000000;
            regs.rcx = 0x00000000;
            regs.rdx = 0x00000000;
        }
        0x8000000A => {
            regs.rax = 0x00000001;
            regs.rbx = 0x000000C8;
            regs.rcx = 0x00000000;
            regs.rdx = 0x00000000;
        }
        _ => {
            regs.rax = 0;
            regs.rbx = 0;
            regs.rcx = 0;
            regs.rdx = 0;
        }
    }
}

pub fn dispatch_exit(reason: ExitReason, regs: &mut GuestRegisters, exit_qual: u64, guest_rip: u64) -> bool {
    match reason {
        ExitReason::Hlt => false,
        ExitReason::Vmcall => handle_vmcall(regs),
        ExitReason::Msr => handle_msr_access(regs, exit_qual),
        ExitReason::VmxPreemptionTimer => handle_preemption_timer(regs),
        ExitReason::CrAccess => handle_cr_access(regs, exit_qual),
        ExitReason::Io => handle_io_access(regs, exit_qual),
        ExitReason::Cpuid => {
            handle_cpuid(regs);
            true
        }
        ExitReason::Rdtsc => {
            let mut lo: u32;
            let mut hi: u32;
            unsafe {
                core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack));
            }
            regs.rax = lo as u64;
            regs.rdx = hi as u64;
            true
        }
        ExitReason::Rdpmc => {
            regs.rax = 0;
            regs.rdx = 0;
            true
        }
        ExitReason::Invd | ExitReason::Wbinvd => true,
        ExitReason::Xsetbv => true,
        ExitReason::DrAccess => {
            crate::log_debug!("调试寄存器访问: exit_qual={:#x}", exit_qual);
            true
        }
        ExitReason::Invlpg => {
            crate::log_debug!("INVLPG 指令执行");
            true
        }
        ExitReason::ExceptionOrNmi => {
            let inter_info = unsafe { vmread(VmcsField::ExitInterruptionInfo as u64) };
            let vector = inter_info & 0xFF;
            let is_valid = (inter_info >> 31) & 1 != 0;
            
            if !is_valid {
                return true;
            }
            
            if vector == 6 {
                if let Some(inst_len) = check_syscall_instruction(guest_rip, regs) {
                    crate::log_debug!("捕获 syscall 指令，向量={}, rip={:#x}", vector, guest_rip);
                    let syscall_handler = crate::vm::syscall::linux::LinuxSyscallHandler;
                    return syscall_handler.handle_syscall(regs);
                }
                crate::log_debug!("捕获 #UD 异常: rip={:#x}", guest_rip);
                return crate::vm::interrupt::handle_invalid_opcode(regs, exit_qual, guest_rip);
            }
            
            match vector as u8 {
                crate::vm::interrupt::X86_TRAP_DE => {
                    crate::vm::interrupt::handle_divide_error(regs, exit_qual, guest_rip)
                }
                crate::vm::interrupt::X86_TRAP_DB => {
                    crate::log_debug!("调试异常: rip={:#x}", guest_rip);
                    true
                }
                crate::vm::interrupt::X86_TRAP_NMI => {
                    crate::log_debug!("NMI: rip={:#x}", guest_rip);
                    true
                }
                crate::vm::interrupt::X86_TRAP_BP => {
                    crate::vm::interrupt::inject_software_exception(vector as u8, 0);
                    true
                }
                crate::vm::interrupt::X86_TRAP_OF => {
                    crate::vm::interrupt::handle_overflow(regs, exit_qual, guest_rip)
                }
                crate::vm::interrupt::X86_TRAP_BR => {
                    crate::vm::interrupt::handle_bound_range_exceeded(regs, exit_qual, guest_rip)
                }
                crate::vm::interrupt::X86_TRAP_NM => {
                    crate::vm::interrupt::handle_device_not_available(regs, exit_qual, guest_rip)
                }
                crate::vm::interrupt::X86_TRAP_DF => {
                    crate::vm::interrupt::handle_double_fault(regs, exit_qual, guest_rip)
                }
                crate::vm::interrupt::X86_TRAP_TS => {
                    crate::vm::interrupt::handle_invalid_tss(regs, exit_qual, guest_rip)
                }
                crate::vm::interrupt::X86_TRAP_NP => {
                    crate::vm::interrupt::handle_segment_not_present(regs, exit_qual, guest_rip)
                }
                crate::vm::interrupt::X86_TRAP_SS => {
                    crate::vm::interrupt::handle_stack_segment_fault(regs, exit_qual, guest_rip)
                }
                crate::vm::interrupt::X86_TRAP_GP => {
                    crate::vm::interrupt::handle_general_protection(regs, exit_qual, guest_rip)
                }
                crate::vm::interrupt::X86_TRAP_PF => {
                    crate::vm::interrupt::handle_page_fault(regs, exit_qual, guest_rip)
                }
                crate::vm::interrupt::X86_TRAP_MF => {
                    crate::vm::interrupt::handle_floating_point_error(regs, exit_qual, guest_rip)
                }
                crate::vm::interrupt::X86_TRAP_AC => {
                    crate::vm::interrupt::handle_alignment_check(regs, exit_qual, guest_rip)
                }
                crate::vm::interrupt::X86_TRAP_MC => {
                    crate::vm::interrupt::handle_machine_check(regs, exit_qual, guest_rip)
                }
                crate::vm::interrupt::X86_TRAP_XF => {
                    crate::vm::interrupt::handle_sse_numeric_error(regs, exit_qual, guest_rip)
                }
                _ => {
                    crate::log_warn!("未处理的异常向量: {}, 现场限定: {:#x}", vector, exit_qual);
                    true
                }
            }
        }
        ExitReason::ExternalInterrupt => {
            let exit_intr = unsafe { vmread(VmcsField::ExitInterruptionInfo as u64) };
            let guard = crate::arch::x86_64::apic::get_manager();
            if let Some(apic) = guard.as_ref() {
                apic.route_external_interrupt_vmexit(exit_intr);
            }
            true
        }
        ExitReason::EptViolation => {
            crate::vm::interrupt::handle_page_fault(regs, exit_qual, guest_rip)
        }
        ExitReason::EptMisconfig => {
            crate::log_error!("物理环境降级：EPT 页表构造受损 RIP={:#x} 限定位={:#x}", guest_rip, exit_qual);
            false
        }
        _ => {
            crate::log_error!("无可恢复路径错误 {:?} 现场RIP={:#x} 限定位={:#x} (目标隔离域已进入销毁队列)", reason, guest_rip, exit_qual);
            false
        }
    }
}