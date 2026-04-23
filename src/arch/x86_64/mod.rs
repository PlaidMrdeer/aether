// src/arch/x86_64/mod.rs
pub mod apic;
pub mod iommu;
pub mod vmx;
pub mod svm;
pub mod virtualization;
pub mod simulation;

use self::virtualization::VirtualizationProvider;
use alloc::boxed::Box;
use raw_cpuid::CpuId;

fn has_vmx_support(cpuid: &CpuId) -> bool {
    if let Some(feature_info) = cpuid.get_feature_info() {
        feature_info.has_vmx()
    } else {
        false
    }
}

fn has_svm_support(_cpuid: &CpuId) -> bool {
    false
}

pub fn init() -> Box<dyn VirtualizationProvider> {
    let cpuid = CpuId::new();
    
    let vendor_info_result = cpuid.get_vendor_info()
                                  .expect("CPUID Vendor Info not available");
    let vendor_str = vendor_info_result.as_str();
    
    match vendor_str {
        "GenuineIntel" => {
            if has_vmx_support(&cpuid) {
                crate::log_info!("检测到 Intel 架构，启用 VMX 硬件抽象层");
                Box::new(vmx::VmxManager::new())
            } else {
                crate::log_info!("检测到 Intel 架构，但无 VMX 支持，启用软件模拟模式");
                Box::new(simulation::SimulationProvider::new())
            }
        }
        "AuthenticAMD" => {
            if has_svm_support(&cpuid) {
                crate::log_info!("检测到 AMD 架构，启用 SVM 硬件抽象层");
                Box::new(svm::SvmManager::new())
            } else {
                crate::log_info!("检测到 AMD 架构，但无 SVM 支持，启用软件模拟模式");
                Box::new(simulation::SimulationProvider::new())
            }
        }
        _ => {
            crate::log_info!("未知 CPU 厂商，启用软件模拟模式");
            Box::new(simulation::SimulationProvider::new())
        }
    }
}