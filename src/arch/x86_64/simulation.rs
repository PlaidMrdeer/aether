/* src/arch/x86_64/simulation.rs */
use crate::arch::x86_64::virtualization::VirtualizationProvider;
use crate::arch::x86_64::vmx::GuestRegisters;
use crate::vm::syscall::SyscallHandler;
use x86_64::PhysAddr;
use x86_64::registers::model_specific::Msr;
use spin::Mutex;
use lazy_static::lazy_static;

const MSR_IA32_EFER: u32 = 0xC0000080;
const EFER_SCE: u64 = 1 << 0;

#[repr(C, packed)]
#[derive(Copy, Clone)]
struct IdtEntry {
    offset_low: u16,
    selector: u16,
    ist: u8,
    type_attr: u8,
    offset_mid: u16,
    offset_high: u32,
    zero: u32,
}

impl IdtEntry {
    const fn new() -> Self {
        Self {
            offset_low: 0,
            selector: 0,
            ist: 0,
            type_attr: 0,
            offset_mid: 0,
            offset_high: 0,
            zero: 0,
        }
    }

    fn set_handler(&mut self, handler: u64, code_selector: u16) {
        self.offset_low = handler as u16;
        self.offset_mid = (handler >> 16) as u16;
        self.offset_high = (handler >> 32) as u32;
        self.selector = code_selector;
        self.type_attr = 0x8E;
        self.ist = 0;
        self.zero = 0;
    }
}

#[repr(C, packed)]
struct IdtPointer {
    limit: u16,
    base: u64,
}

const IDT_ENTRIES: usize = 256;

static mut IDT: [IdtEntry; IDT_ENTRIES] = [const { IdtEntry::new() }; IDT_ENTRIES];

lazy_static! {
    pub static ref SIMULATION_STATE: Mutex<SimulationState> = Mutex::new(SimulationState::new());
}

pub struct SimulationState {
    pub current_guest_rip: u64,
    pub current_guest_rsp: u64,
    pub regs: GuestRegisters,
}

impl SimulationState {
    pub const fn new() -> Self {
        Self {
            current_guest_rip: 0,
            current_guest_rsp: 0,
            regs: GuestRegisters {
                rax: 0, rcx: 0, rdx: 0, rbx: 0,
                rbp: 0, rsi: 0, rdi: 0,
                r8: 0, r9: 0, r10: 0, r11: 0,
                r12: 0, r13: 0, r14: 0, r15: 0,
            },
        }
    }
}

pub struct SimulationProvider;

impl SimulationProvider {
    pub fn new() -> Self {
        Self
    }

    fn disable_syscall(&self) {
        unsafe {
            let mut efer = Msr::new(MSR_IA32_EFER);
            let val = efer.read();
            efer.write(val & !EFER_SCE);
        }
    }

    fn setup_idt(&self) {
        unsafe {
            let code_selector: u16;
            core::arch::asm!(
                "mov {0:x}, cs",
                out(reg) code_selector,
                options(nomem, nostack, preserves_flags)
            );

            extern "C" {
                fn exception_ud();
            }

            IDT[6].set_handler(exception_ud as u64, code_selector);

            let idt_ptr = IdtPointer {
                limit: (core::mem::size_of::<IdtEntry>() * IDT_ENTRIES - 1) as u16,
                base: IDT.as_ptr() as u64,
            };

            core::arch::asm!(
                "lidt [{0}]",
                in(reg) &idt_ptr,
                options(nomem, nostack, preserves_flags)
            );
        }
    }
}

impl VirtualizationProvider for SimulationProvider {
    fn check_support(&self) {
        crate::log_info!("软件模拟模式：无需硬件虚拟化支持");
    }

    fn enable(&mut self) {
        crate::log_info!("软件模拟模式：禁用 syscall 指令 (EFER.SCE)");
        self.disable_syscall();
        
        crate::log_info!("软件模拟模式：设置 IDT 用于捕获 #UD 异常");
        self.setup_idt();
    }

    fn enter_root_mode(&mut self) {
        crate::log_info!("软件模拟模式：已进入模拟执行环境");
    }

    fn launch_guest(&self) {
        crate::log_info!("软件模拟模式：启动 guest 执行");
        
        let state = SIMULATION_STATE.lock();
        let guest_rip = state.current_guest_rip;
        let guest_rsp = state.current_guest_rsp;
        
        crate::log_info!("软件模拟模式：跳转到 guest 入口 RIP={:#x}, RSP={:#x}", guest_rip, guest_rsp);
        
        unsafe {
            core::arch::asm!(
                "mov rsp, {0}",
                "jmp {1}",
                in(reg) guest_rsp,
                in(reg) guest_rip,
                options(noreturn)
            );
        }
    }

    fn get_revision_id(&self) -> u32 {
        0
    }

    fn prepare_guest(
        &self,
        _vmcs_region: PhysAddr,
        guest_rip: u64,
        guest_rsp: u64,
        _ept_pointer: u64,
        _vpid: u16,
        _pml_pointer: PhysAddr,
    ) {
        crate::log_info!("软件模拟模式：准备 guest 状态 RIP={:#x}, RSP={:#x}", guest_rip, guest_rsp);
        
        let mut state = SIMULATION_STATE.lock();
        state.current_guest_rip = guest_rip;
        state.current_guest_rsp = guest_rsp;
        state.regs.rax = 0;
        state.regs.rbx = 0;
        state.regs.rcx = 0;
        state.regs.rdx = 0;
        state.regs.rsi = 0;
        state.regs.rdi = 0;
        state.regs.rbp = 0;
        state.regs.r8 = 0;
        state.regs.r9 = 0;
        state.regs.r10 = 0;
        state.regs.r11 = 0;
        state.regs.r12 = 0;
        state.regs.r13 = 0;
        state.regs.r14 = 0;
        state.regs.r15 = 0;
    }
}

#[unsafe(naked)]
extern "C" fn exception_ud() {
    core::arch::naked_asm!(
        "push rax",
        "push rbx",
        "push rcx",
        "push rdx",
        "push rsi",
        "push rdi",
        "push rbp",
        "push r8",
        "push r9",
        "push r10",
        "push r11",
        "push r12",
        "push r13",
        "push r14",
        "push r15",
        "mov rdi, rsp",
        "call handle_ud_exception",
        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop r11",
        "pop r10",
        "pop r9",
        "pop r8",
        "pop rbp",
        "pop rdi",
        "pop rsi",
        "pop rdx",
        "pop rcx",
        "pop rbx",
        "pop rax",
        "add rsp, 8",
        "iretq",
    );
}

#[repr(C)]
struct ExceptionStackFrame {
    r15: u64,
    r14: u64,
    r13: u64,
    r12: u64,
    r11: u64,
    r10: u64,
    r9: u64,
    r8: u64,
    rbp: u64,
    rdi: u64,
    rsi: u64,
    rdx: u64,
    rcx: u64,
    rbx: u64,
    rax: u64,
    error_code: u64,
    rip: u64,
    cs: u64,
    rflags: u64,
    rsp: u64,
    ss: u64,
}

#[no_mangle]
extern "C" fn handle_ud_exception(stack_ptr: *mut ExceptionStackFrame) {
    unsafe {
        let frame = &*stack_ptr;
        let rip = frame.rip;
        
        let mut instr_bytes = [0u8; 16];
        core::ptr::copy_nonoverlapping(rip as *const u8, instr_bytes.as_mut_ptr(), 16);
        
        if instr_bytes[0] == 0x0F && instr_bytes[1] == 0x05 {
            crate::log_debug!("软件模拟模式：捕获 syscall 指令 at RIP={:#x}", rip);
            
            let next_rip = rip + 2;
            
            let mut state = SIMULATION_STATE.lock();
            state.regs.rax = frame.rax;
            state.regs.rbx = frame.rbx;
            state.regs.rcx = next_rip;
            state.regs.rdx = frame.rdx;
            state.regs.rsi = frame.rsi;
            state.regs.rdi = frame.rdi;
            state.regs.rbp = frame.rbp;
            state.regs.r8 = frame.r8;
            state.regs.r9 = frame.r9;
            state.regs.r10 = frame.r10;
            state.regs.r11 = 0x02;
            state.regs.r12 = frame.r12;
            state.regs.r13 = frame.r13;
            state.regs.r14 = frame.r14;
            state.regs.r15 = frame.r15;
            
            let syscall_handler = crate::vm::syscall::linux::LinuxSyscallHandler;
            syscall_handler.handle_syscall(&mut state.regs);
            
            let frame = &mut *stack_ptr;
            frame.rax = state.regs.rax;
            frame.rbx = state.regs.rbx;
            frame.rcx = state.regs.rcx;
            frame.rdx = state.regs.rdx;
            frame.rsi = state.regs.rsi;
            frame.rdi = state.regs.rdi;
            frame.rbp = state.regs.rbp;
            frame.r8 = state.regs.r8;
            frame.r9 = state.regs.r9;
            frame.r10 = state.regs.r10;
            frame.r11 = state.regs.r11;
            frame.r12 = state.regs.r12;
            frame.r13 = state.regs.r13;
            frame.r14 = state.regs.r14;
            frame.r15 = state.regs.r15;
            frame.rip = next_rip;
            
            return;
        }
        
        crate::log_warn!("软件模拟模式：未处理的 #UD 异常 at RIP={:#x}", rip);
        crate::log_warn!("软件模拟模式：指令字节: {:02X} {:02X} {:02X} {:02X}", 
            instr_bytes[0], instr_bytes[1], instr_bytes[2], instr_bytes[3]);
    }
}
