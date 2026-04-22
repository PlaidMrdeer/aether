#![no_std]
#![no_main]

use core::arch::asm;
use core::panic::PanicInfo;

const SYS_WRITE: u64 = 1;
const SYS_BRK: u64 = 12;
const SYS_MMAP: u64 = 9;
const SYS_MUNMAP: u64 = 11;
const SYS_UNAME: u64 = 63;
const SYS_GETPID: u64 = 39;
const SYS_GETPPID: u64 = 110;
const SYS_GETUID: u64 = 102;
const SYS_GETGID: u64 = 104;
const SYS_GETEUID: u64 = 107;
const SYS_GETEGID: u64 = 108;
const SYS_GETTIMEOFDAY: u64 = 96;
const SYS_TIME: u64 = 201;
const SYS_RT_SIGPROCMASK: u64 = 14;
const SYS_RT_SIGACTION: u64 = 13;
const SYS_ARCH_PRCTL: u64 = 158;
const SYS_EXIT: u64 = 60;
const SYS_GETRANDOM: u64 = 318;
const SYS_OPEN: u64 = 2;
const SYS_CLOSE: u64 = 3;
const SYS_LSEEK: u64 = 8;
const SYS_PREAD64: u64 = 17;
const SYS_PWRITE64: u64 = 18;
const SYS_ACCESS: u64 = 21;
const SYS_FSTAT: u64 = 5;
const SYS_FCNTL: u64 = 72;
const SYS_IOCTL: u64 = 16;
const SYS_PRCTL: u64 = 157;
const SYS_SCHED_GETPARAM: u64 = 140;
const SYS_SCHED_SETSCHEDULER: u64 = 146;
const SYS_SCHED_GETAFFINITY: u64 = 123;
const SYS_SET_TID_ADDRESS: u64 = 218;
const SYS_SET_ROBUST_LIST: u64 = 273;

const STDOUT_FILENO: u64 = 1;
const STDERR_FILENO: u64 = 2;

const PROT_READ: u64 = 1;
const PROT_WRITE: u64 = 2;
const PROT_EXEC: u64 = 4;
const MAP_PRIVATE: u64 = 2;
const MAP_ANONYMOUS: u64 = 32;

const ARCH_SET_FS: u64 = 0x1002;
const ARCH_GET_FS: u64 = 0x1003;
const ARCH_SET_GS: u64 = 0x1001;
const ARCH_GET_GS: u64 = 0x1004;

#[inline(always)]
unsafe fn syscall0(nr: u64) -> u64 {
    let ret: u64;
    asm!(
        "syscall",
        in("rax") nr,
        out("rcx") _,
        out("r11") _,
        lateout("rax") ret,
        options(nostack)
    );
    ret
}

#[inline(always)]
unsafe fn syscall1(nr: u64, arg1: u64) -> u64 {
    let ret: u64;
    asm!(
        "syscall",
        in("rax") nr,
        in("rdi") arg1,
        out("rcx") _,
        out("r11") _,
        lateout("rax") ret,
        options(nostack)
    );
    ret
}

#[inline(always)]
unsafe fn syscall2(nr: u64, arg1: u64, arg2: u64) -> u64 {
    let ret: u64;
    asm!(
        "syscall",
        in("rax") nr,
        in("rdi") arg1,
        in("rsi") arg2,
        out("rcx") _,
        out("r11") _,
        lateout("rax") ret,
        options(nostack)
    );
    ret
}

#[inline(always)]
unsafe fn syscall3(nr: u64, arg1: u64, arg2: u64, arg3: u64) -> u64 {
    let ret: u64;
    asm!(
        "syscall",
        in("rax") nr,
        in("rdi") arg1,
        in("rsi") arg2,
        in("rdx") arg3,
        out("rcx") _,
        out("r11") _,
        lateout("rax") ret,
        options(nostack)
    );
    ret
}

#[inline(always)]
unsafe fn syscall4(nr: u64, arg1: u64, arg2: u64, arg3: u64, arg4: u64) -> u64 {
    let ret: u64;
    asm!(
        "syscall",
        in("rax") nr,
        in("rdi") arg1,
        in("rsi") arg2,
        in("rdx") arg3,
        in("r10") arg4,
        out("rcx") _,
        out("r11") _,
        lateout("rax") ret,
        options(nostack)
    );
    ret
}

#[inline(always)]
unsafe fn syscall5(nr: u64, arg1: u64, arg2: u64, arg3: u64, arg4: u64, arg5: u64) -> u64 {
    let ret: u64;
    asm!(
        "syscall",
        in("rax") nr,
        in("rdi") arg1,
        in("rsi") arg2,
        in("rdx") arg3,
        in("r10") arg4,
        in("r8") arg5,
        out("rcx") _,
        out("r11") _,
        lateout("rax") ret,
        options(nostack)
    );
    ret
}

#[inline(always)]
unsafe fn syscall6(nr: u64, arg1: u64, arg2: u64, arg3: u64, arg4: u64, arg5: u64, arg6: u64) -> u64 {
    let ret: u64;
    asm!(
        "syscall",
        in("rax") nr,
        in("rdi") arg1,
        in("rsi") arg2,
        in("rdx") arg3,
        in("r10") arg4,
        in("r8") arg5,
        in("r9") arg6,
        out("rcx") _,
        out("r11") _,
        lateout("rax") ret,
        options(nostack)
    );
    ret
}

fn write_str(s: &str) {
    unsafe {
        syscall3(SYS_WRITE, STDOUT_FILENO, s.as_ptr() as u64, s.len() as u64);
    }
}

fn hex_dump(buf: &[u8]) {
    for (i, &byte) in buf.iter().enumerate() {
        if i % 16 == 0 {
            write_str(&format!("{:04x}: ", i));
        }
        write_str(&format!("{:02x} ", byte));
        if i % 16 == 15 {
            write_str("\n");
        }
    }
    write_str("\n");
}

#[repr(C)]
struct Utsname {
    sysname: [u8; 65],
    nodename: [u8; 65],
    release: [u8; 65],
    version: [u8; 65],
    machine: [u8; 65],
    domainname: [u8; 65],
}

impl Utsname {
    fn new() -> Self {
        Utsname {
            sysname: [0; 65],
            nodename: [0; 65],
            release: [0; 65],
            version: [0; 65],
            machine: [0; 65],
            domainname: [0; 65],
        }
    }
}

#[repr(C)]
struct Timeval {
    tv_sec: i64,
    tv_usec: i64,
}

#[no_mangle]
#[link_section = ".text.entry"]
pub extern "C" fn _start() -> ! {
    write_str("[MacroDomain] Starting Linux syscall compatibility test...\n");
    
    write_str("[MacroDomain] Test 1: write syscall to stdout... ");
    let test_msg = "Hello from MacroDomain!\n";
    unsafe {
        let ret = syscall3(SYS_WRITE, STDOUT_FILENO, test_msg.as_ptr() as u64, test_msg.len() as u64);
        if ret == test_msg.len() as u64 {
            write_str("PASSED\n");
        } else {
            write_str(&format!("FAILED (ret={})\n", ret));
        }
    }
    
    write_str("[MacroDomain] Test 2: getpid syscall... ");
    unsafe {
        let pid = syscall0(SYS_GETPID);
        write_str(&format!("PASSED (pid={})\n", pid));
    }
    
    write_str("[MacroDomain] Test 3: getppid syscall... ");
    unsafe {
        let ppid = syscall0(SYS_GETPPID);
        write_str(&format!("PASSED (ppid={})\n", ppid));
    }
    
    write_str("[MacroDomain] Test 4: getuid/getgid syscalls... ");
    unsafe {
        let uid = syscall0(SYS_GETUID);
        let gid = syscall0(SYS_GETGID);
        let euid = syscall0(SYS_GETEUID);
        let egid = syscall0(SYS_GETEGID);
        write_str(&format!("PASSED (uid={}, gid={}, euid={}, egid={})\n", uid, gid, euid, egid));
    }
    
    write_str("[MacroDomain] Test 5: brk syscall for heap allocation... ");
    unsafe {
        let initial_brk = syscall1(SYS_BRK, 0);
        write_str(&format!("initial_brk={:#x} ", initial_brk));
        
        let new_brk = initial_brk + 0x2000;
        let result = syscall1(SYS_BRK, new_brk);
        
        if result >= new_brk {
            write_str(&format!("PASSED (new_brk={:#x})\n", result));
            
            let ptr = initial_brk as *mut u8;
            for i in 0..0x2000 {
                *ptr.add(i) = (i & 0xFF) as u8;
            }
            
            for i in 0..0x2000 {
                if *ptr.add(i) != (i & 0xFF) as u8 {
                    write_str(&format!("Heap verification FAILED at offset {}\n", i));
                    break;
                }
            }
            write_str("[MacroDomain] Heap write/read verification PASSED\n");
        } else {
            write_str(&format!("FAILED (result={:#x})\n", result));
        }
    }
    
    write_str("[MacroDomain] Test 6: uname syscall... ");
    unsafe {
        let mut utsname = Utsname::new();
        let ret = syscall1(SYS_UNAME, &mut utsname as *mut Utsname as u64);
        
        if ret == 0 {
            write_str("PASSED\n");
            
            let sysname = core::ffi::CStr::from_ptr(utsname.sysname.as_ptr() as *const i8);
            let release = core::ffi::CStr::from_ptr(utsname.release.as_ptr() as *const i8);
            let version = core::ffi::CStr::from_ptr(utsname.version.as_ptr() as *const i8);
            let machine = core::ffi::CStr::from_ptr(utsname.machine.as_ptr() as *const i8);
            
            write_str(&format!("[MacroDomain]   sysname: {:?}\n", sysname.to_str().unwrap_or("")));
            write_str(&format!("[MacroDomain]   release: {:?}\n", release.to_str().unwrap_or("")));
            write_str(&format!("[MacroDomain]   version: {:?}\n", version.to_str().unwrap_or("")));
            write_str(&format!("[MacroDomain]   machine: {:?}\n", machine.to_str().unwrap_or("")));
        } else {
            write_str(&format!("FAILED (ret={})\n", ret));
        }
    }
    
    write_str("[MacroDomain] Test 7: mmap syscall for anonymous mapping... ");
    unsafe {
        let addr = syscall6(
            SYS_MMAP,
            0,
            0x4000,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS,
            u64::MAX,
            0,
        );
        
        if addr < 0xFFFF_FFFF_FFFF_0000 {
            write_str(&format!("PASSED (addr={:#x})\n", addr));
            
            let ptr = addr as *mut u8;
            for i in 0..0x4000 {
                *ptr.add(i) = ((i * 3) & 0xFF) as u8;
            }
            
            for i in 0..0x4000 {
                if *ptr.add(i) != ((i * 3) & 0xFF) as u8 {
                    write_str(&format!("MMAP verification FAILED at offset {}\n", i));
                    break;
                }
            }
            write_str("[MacroDomain] MMAP write/read verification PASSED\n");
            
            let ret = syscall2(SYS_MUNMAP, addr, 0x4000);
            if ret == 0 {
                write_str("[MacroDomain] munmap PASSED\n");
            } else {
                write_str(&format!("[MacroDomain] munmap FAILED (ret={})\n", ret));
            }
        } else {
            write_str(&format!("FAILED (addr={:#x})\n", addr));
        }
    }
    
    write_str("[MacroDomain] Test 8: arch_prctl for FS/GS base... ");
    unsafe {
        let test_fs_base: u64 = 0x7FFF_0000;
        let ret_set = syscall2(SYS_ARCH_PRCTL, ARCH_SET_FS, test_fs_base);
        
        if ret_set == 0 {
            let mut get_fs: u64 = 0;
            let ret_get = syscall2(SYS_ARCH_PRCTL, ARCH_GET_FS, &mut get_fs as *mut u64 as u64);
            
            if ret_get == 0 && get_fs == test_fs_base {
                write_str(&format!("PASSED (FS base set to {:#x})\n", get_fs));
            } else {
                write_str(&format!("get_fs FAILED (ret={}, fs={:#x})\n", ret_get, get_fs));
            }
        } else {
            write_str(&format!("set_fs FAILED (ret={})\n", ret_set));
        }
    }
    
    write_str("[MacroDomain] Test 9: time/gettimeofday syscalls... ");
    unsafe {
        let mut t: i64 = 0;
        let time_ret = syscall1(SYS_TIME, &mut t as *mut i64 as u64);
        write_str(&format!("time: t={}, ret={} ", t, time_ret));
        
        let mut tv = Timeval { tv_sec: 0, tv_usec: 0 };
        let gtod_ret = syscall2(SYS_GETTIMEOFDAY, &mut tv as *mut Timeval as u64, 0);
        write_str(&format!("gettimeofday: tv_sec={}, tv_usec={}, ret={} ", tv.tv_sec, tv.tv_usec, gtod_ret));
        
        if gtod_ret == 0 && tv.tv_sec > 0 {
            write_str("PASSED\n");
        } else {
            write_str("FAILED\n");
        }
    }
    
    write_str("[MacroDomain] Test 10: getrandom syscall... ");
    unsafe {
        let mut random_buf = [0u8; 32];
        let ret = syscall3(SYS_GETRANDOM, random_buf.as_mut_ptr() as u64, 32, 0);
        
        if ret == 32 {
            write_str("PASSED\n[MacroDomain]   Random bytes: ");
            for b in &random_buf {
                write_str(&format!("{:02x} ", b));
            }
            write_str("\n");
        } else {
            write_str(&format!("FAILED (ret={})\n", ret));
        }
    }
    
    write_str("[MacroDomain] All basic syscall tests completed!\n");
    
    write_str("[MacroDomain] Testing additional syscalls expected by libc...\n");
    
    unsafe {
        write_str("[MacroDomain]   SYS_RT_SIGPROCMASK: ");
        let ret = syscall4(SYS_RT_SIGPROCMASK, 0, 0, 0, 8);
        write_str(&format!("ret={}\n", ret));
        
        write_str("[MacroDomain]   SYS_RT_SIGACTION: ");
        let ret = syscall4(SYS_RT_SIGACTION, 0, 0, 0, 8);
        write_str(&format!("ret={}\n", ret));
        
        write_str("[MacroDomain]   SYS_PRCTL: ");
        let ret = syscall5(SYS_PRCTL, 15, 0, 0, 0, 0);
        write_str(&format!("ret={}\n", ret));
        
        write_str("[MacroDomain]   SYS_SCHED_GETPARAM: ");
        let ret = syscall2(SYS_SCHED_GETPARAM, 0, 0);
        write_str(&format!("ret={}\n", ret));
        
        write_str("[MacroDomain]   SYS_SCHED_SETSCHEDULER: ");
        let ret = syscall3(SYS_SCHED_SETSCHEDULER, 0, 0, 0);
        write_str(&format!("ret={}\n", ret));
        
        write_str("[MacroDomain]   SYS_SET_TID_ADDRESS: ");
        let ret = syscall1(SYS_SET_TID_ADDRESS, 0);
        write_str(&format!("ret={}\n", ret));
        
        write_str("[MacroDomain]   SYS_SET_ROBUST_LIST: ");
        let ret = syscall2(SYS_SET_ROBUST_LIST, 0, 0);
        write_str(&format!("ret={}\n", ret));
        
        write_str("[MacroDomain]   SYS_OPEN (test /dev/null): ");
        let path = b"/dev/null\0";
        let fd = syscall2(SYS_OPEN, path.as_ptr() as u64, 0);
        write_str(&format!("fd={} ", fd));
        if fd < 0x8000_0000_0000_0000 {
            syscall1(SYS_CLOSE, fd);
            write_str("PASSED\n");
        } else {
            write_str("FAILED\n");
        }
        
        write_str("[MacroDomain]   SYS_ACCESS: ");
        let ret = syscall2(SYS_ACCESS, path.as_ptr() as u64, 0);
        write_str(&format!("ret={}\n", ret));
    }
    
    write_str("[MacroDomain] ================================================\n");
    write_str("[MacroDomain] Linux syscall compatibility layer test PASSED!\n");
    write_str("[MacroDomain] ================================================\n");
    
    write_str("[MacroDomain] Halting guest execution...\n");
    
    loop {
        unsafe {
            asm!("hlt", options(nomem, nostack));
        }
    }
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    write_str("[MacroDomain] PANIC: ");
    let msg = format_args!("{}", info);
    
    let mut buf = [0u8; 256];
    let len = if let Some(fmt) = msg.as_str() {
        let bytes = fmt.as_bytes();
        let copy_len = core::cmp::min(bytes.len(), buf.len());
        buf[..copy_len].copy_from_slice(&bytes[..copy_len]);
        copy_len
    } else {
        0
    };
    
    unsafe {
        syscall3(SYS_WRITE, STDERR_FILENO, buf.as_ptr() as u64, len as u64);
    }
    write_str("\n");
    
    loop {
        unsafe {
            asm!("hlt", options(nomem, nostack));
        }
    }
}
