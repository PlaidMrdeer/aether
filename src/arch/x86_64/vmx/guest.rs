// src/arch/x86_64/vmx/guest.rs

use crate::arch::x86_64::vmx::{
    instructions::vmwrite,
    vmcs::VmcsField,
    IA32_VMX_CR0_FIXED0, IA32_VMX_CR0_FIXED1, IA32_VMX_CR4_FIXED0, IA32_VMX_CR4_FIXED1,
};
use x86_64::registers::model_specific::Msr;

pub(super) fn setup_guest_state(guest_rip: u64, guest_rsp: u64) {
    unsafe {
        let guest_gdt_gpa: u64 = 0x1000;
        let guest_gdt_virt = crate::memory::phys_to_virt(x86_64::PhysAddr::new(guest_gdt_gpa));
        let gdt_ptr = guest_gdt_virt.as_u64() as *mut u64;
        
        gdt_ptr.add(0).write_volatile(0u64);
        gdt_ptr.add(1).write_volatile(0x00AF_9B00_0000_FFFFu64);
        gdt_ptr.add(2).write_volatile(0x00CF_9300_0000_FFFFu64);
        gdt_ptr.add(3).write_volatile(0x00AF_FB00_0000_FFFFu64);
        gdt_ptr.add(4).write_volatile(0x00CF_F300_0000_FFFFu64);

        vmwrite(VmcsField::GuestCsSelector as u64, 0x08);
        vmwrite(VmcsField::GuestCsLimit as u64, 0xFFFF);
        vmwrite(VmcsField::GuestCsArBytes as u64, 0xA09B);
        vmwrite(VmcsField::GuestCsBase as u64, 0);

        vmwrite(VmcsField::GuestSsSelector as u64, 0x10);
        vmwrite(VmcsField::GuestSsLimit as u64, 0xFFFF);
        vmwrite(VmcsField::GuestSsArBytes as u64, 0xC093);
        vmwrite(VmcsField::GuestSsBase as u64, 0);

        vmwrite(VmcsField::GuestDsSelector as u64, 0x10);
        vmwrite(VmcsField::GuestDsLimit as u64, 0xFFFF);
        vmwrite(VmcsField::GuestDsArBytes as u64, 0xC093);
        vmwrite(VmcsField::GuestDsBase as u64, 0);
        vmwrite(VmcsField::GuestEsSelector as u64, 0x10);
        vmwrite(VmcsField::GuestEsLimit as u64, 0xFFFF);
        vmwrite(VmcsField::GuestEsArBytes as u64, 0xC093);
        vmwrite(VmcsField::GuestEsBase as u64, 0);
        vmwrite(VmcsField::GuestFsSelector as u64, 0x10);
        vmwrite(VmcsField::GuestFsLimit as u64, 0xFFFF);
        vmwrite(VmcsField::GuestFsArBytes as u64, 0xC093);
        vmwrite(VmcsField::GuestFsBase as u64, 0);
        vmwrite(VmcsField::GuestGsSelector as u64, 0x10);
        vmwrite(VmcsField::GuestGsLimit as u64, 0xFFFF);
        vmwrite(VmcsField::GuestGsArBytes as u64, 0xC093);
        vmwrite(VmcsField::GuestGsBase as u64, 0);

        vmwrite(VmcsField::GuestLdtrSelector as u64, 0);
        vmwrite(VmcsField::GuestLdtrLimit as u64, 0);
        vmwrite(VmcsField::GuestLdtrArBytes as u64, 0x10000);
        vmwrite(VmcsField::GuestLdtrBase as u64, 0);

        vmwrite(VmcsField::GuestGdtrBase as u64, guest_gdt_gpa);
        vmwrite(VmcsField::GuestGdtrLimit as u64, 0x0027);

        vmwrite(VmcsField::GuestIdtrBase as u64, 0);
        vmwrite(VmcsField::GuestIdtrLimit as u64, 0x3FF);

        vmwrite(VmcsField::GuestTrSelector as u64, 0x18);
        vmwrite(VmcsField::GuestTrLimit as u64, 0x67);
        vmwrite(VmcsField::GuestTrArBytes as u64, 0x008B);
        vmwrite(VmcsField::GuestTrBase as u64, 0);

        let cr0_fixed0_raw = Msr::new(IA32_VMX_CR0_FIXED0).read();
        let cr0_fixed1_raw = Msr::new(IA32_VMX_CR0_FIXED1).read();

        let mut guest_cr0 = cr0_fixed0_raw;
        guest_cr0 |= 1u64 << 31;
        guest_cr0 |= 1u64 << 0;
        guest_cr0 |= 1u64 << 4;
        guest_cr0 |= 1u64 << 5;
        guest_cr0 &= cr0_fixed1_raw;

        vmwrite(VmcsField::GuestCr0 as u64, guest_cr0);

        let cr4_fixed0_raw = Msr::new(IA32_VMX_CR4_FIXED0).read();
        let cr4_fixed1_raw = Msr::new(IA32_VMX_CR4_FIXED1).read();
        let mut guest_cr4 = cr4_fixed0_raw & cr4_fixed1_raw;
        guest_cr4 |= 1u64 << 5;
        vmwrite(VmcsField::GuestCr4 as u64, guest_cr4);

        vmwrite(VmcsField::GuestCr3 as u64, 0);
        
        let guest_efer: u64 = (1 << 8) | (1 << 10);
        vmwrite(VmcsField::GuestIa32Efer as u64, guest_efer);

        vmwrite(VmcsField::GuestRip as u64, guest_rip);
        vmwrite(VmcsField::GuestRsp as u64, guest_rsp);
        vmwrite(VmcsField::GuestRflags as u64, 0x2);
    }
}