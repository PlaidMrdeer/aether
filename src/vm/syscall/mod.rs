    pub mod linux;

pub use linux::LinuxSyscallHandler;

use crate::arch::x86_64::vmx::GuestRegisters;

pub trait SyscallHandler {
    fn handle_syscall(&self, regs: &mut GuestRegisters) -> bool;
}
