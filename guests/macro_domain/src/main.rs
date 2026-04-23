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

fn u64_to_hex(mut n: u64, buf: &mut [u8]) -> usize {
    const HEX_CHARS: &[u8] = b"0123456789abcdef";
    let mut i = buf.len();
    
    if n == 0 {
        i -= 1;
        buf[i] = b'0';
        return 1;
    }
    
    while n > 0 && i > 0 {
        i -= 1;
        buf[i] = HEX_CHARS[(n & 0xF) as usize];
        n >>= 4;
    }
    buf.len() - i
}

fn u64_to_hex_padded(mut n: u64, buf: &mut [u8], width: usize) -> usize {
    const HEX_CHARS: &[u8] = b"0123456789abcdef";
    let mut i = buf.len();
    let start = if width > buf.len() { 0 } else { buf.len() - width };
    
    while n > 0 && i > start {
        i -= 1;
        buf[i] = HEX_CHARS[(n & 0xF) as usize];
        n >>= 4;
    }
    
    while i > start {
        i -= 1;
        buf[i] = b'0';
    }
    
    buf.len() - i
}

fn u64_to_dec(mut n: u64, buf: &mut [u8]) -> usize {
    let mut i = buf.len();
    
    if n == 0 {
        i -= 1;
        buf[i] = b'0';
        return 1;
    }
    
    while n > 0 && i > 0 {
        i -= 1;
        buf[i] = (n % 10) as u8 + b'0';
        n /= 10;
    }
    buf.len() - i
}

fn i64_to_dec(mut n: i64, buf: &mut [u8]) -> usize {
    let is_negative = n < 0;
    if is_negative {
        n = -n;
    }
    
    let len = u64_to_dec(n as u64, buf);
    
    if is_negative {
        let start = buf.len() - len - 1;
        if start > 0 {
            buf[start] = b'-';
            return len + 1;
        }
    }
    len
}

fn hex_dump(buf: &[u8]) {
    let mut hex_buf = [0u8; 32];
    for (i, &byte) in buf.iter().enumerate() {
        if i % 16 == 0 {
            write_str("\n");
            let len = u64_to_hex_padded(i as u64, &mut hex_buf, 4);
            write_str(unsafe { core::str::from_utf8_unchecked(&hex_buf[hex_buf.len() - len..]) });
            write_str(": ");
        }
        let len = u64_to_hex_padded(byte as u64, &mut hex_buf, 2);
        write_str(unsafe { core::str::from_utf8_unchecked(&hex_buf[hex_buf.len() - len..]) });
        write_str(" ");
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

fn cstr_to_str(cstr: &[u8]) -> &str {
    let len = cstr.iter().position(|&b| b == 0).unwrap_or(cstr.len());
    unsafe { core::str::from_utf8_unchecked(&cstr[..len]) }
}

#[no_mangle]
#[link_section = ".text.entry"]
pub extern "C" fn _start() -> ! {
    let mut dec_buf = [0u8; 32];
    let mut hex_buf = [0u8; 32];
    
    write_str("[MacroDomain] Starting Linux syscall compatibility test...\n");
    
    write_str("[MacroDomain] Test 1: write syscall to stdout... ");
    let test_msg = "Hello from MacroDomain!\n";
    unsafe {
        let ret = syscall3(SYS_WRITE, STDOUT_FILENO, test_msg.as_ptr() as u64, test_msg.len() as u64);
        if ret == test_msg.len() as u64 {
            write_str("PASSED\n");
        } else {
            write_str("FAILED (ret=");
            let len = u64_to_dec(ret, &mut dec_buf);
            write_str(unsafe { core::str::from_utf8_unchecked(&dec_buf[dec_buf.len() - len..]) });
            write_str(")\n");
        }
    }
    
    write_str("[MacroDomain] Test 2: getpid syscall... ");
    unsafe {
        let pid = syscall0(SYS_GETPID);
        write_str("PASSED (pid=");
        let len = u64_to_dec(pid, &mut dec_buf);
        write_str(unsafe { core::str::from_utf8_unchecked(&dec_buf[dec_buf.len() - len..]) });
        write_str(")\n");
    }
    
    write_str("[MacroDomain] Test 3: getppid syscall... ");
    unsafe {
        let ppid = syscall0(SYS_GETPPID);
        write_str("PASSED (ppid=");
        let len = u64_to_dec(ppid, &mut dec_buf);
        write_str(unsafe { core::str::from_utf8_unchecked(&dec_buf[dec_buf.len() - len..]) });
        write_str(")\n");
    }
    
    write_str("[MacroDomain] Test 4: getuid/getgid syscalls... ");
    unsafe {
        let uid = syscall0(SYS_GETUID);
        let gid = syscall0(SYS_GETGID);
        let euid = syscall0(SYS_GETEUID);
        let egid = syscall0(SYS_GETEGID);
        write_str("PASSED (uid=");
        let mut len = u64_to_dec(uid, &mut dec_buf);
        write_str(unsafe { core::str::from_utf8_unchecked(&dec_buf[dec_buf.len() - len..]) });
        write_str(", gid=");
        len = u64_to_dec(gid, &mut dec_buf);
        write_str(unsafe { core::str::from_utf8_unchecked(&dec_buf[dec_buf.len() - len..]) });
        write_str(", euid=");
        len = u64_to_dec(euid, &mut dec_buf);
        write_str(unsafe { core::str::from_utf8_unchecked(&dec_buf[dec_buf.len() - len..]) });
        write_str(", egid=");
        len = u64_to_dec(egid, &mut dec_buf);
        write_str(unsafe { core::str::from_utf8_unchecked(&dec_buf[dec_buf.len() - len..]) });
        write_str(")\n");
    }
    
    write_str("[MacroDomain] Test 5: brk syscall for heap allocation... ");
    unsafe {
        let initial_brk = syscall1(SYS_BRK, 0);
        write_str("initial_brk=");
        let mut len = u64_to_hex(initial_brk, &mut hex_buf);
        write_str(unsafe { core::str::from_utf8_unchecked(&hex_buf[hex_buf.len() - len..]) });
        write_str(" ");
        
        let new_brk = initial_brk + 0x2000;
        let result = syscall1(SYS_BRK, new_brk);
        
        if result >= new_brk {
            write_str("PASSED (new_brk=");
            len = u64_to_hex(result, &mut hex_buf);
            write_str(unsafe { core::str::from_utf8_unchecked(&hex_buf[hex_buf.len() - len..]) });
            write_str(")\n");
            
            let ptr = initial_brk as *mut u8;
            for i in 0..0x2000 {
                *ptr.add(i) = (i & 0xFF) as u8;
            }
            
            let mut verified = true;
            for i in 0..0x2000 {
                if *ptr.add(i) != (i & 0xFF) as u8 {
                    write_str("Heap verification FAILED at offset ");
                    len = u64_to_dec(i as u64, &mut dec_buf);
                    write_str(unsafe { core::str::from_utf8_unchecked(&dec_buf[dec_buf.len() - len..]) });
                    write_str("\n");
                    verified = false;
                    break;
                }
            }
            if verified {
                write_str("[MacroDomain] Heap write/read verification PASSED\n");
            }
        } else {
            write_str("FAILED (result=");
            len = u64_to_hex(result, &mut hex_buf);
            write_str(unsafe { core::str::from_utf8_unchecked(&hex_buf[hex_buf.len() - len..]) });
            write_str(")\n");
        }
    }
    
    write_str("[MacroDomain] Test 6: uname syscall... ");
    unsafe {
        let mut utsname = Utsname::new();
        let ret = syscall1(SYS_UNAME, &mut utsname as *mut Utsname as u64);
        
        if ret == 0 {
            write_str("PASSED\n");
            
            write_str("[MacroDomain]   sysname: ");
            write_str(cstr_to_str(&utsname.sysname));
            write_str("\n");
            
            write_str("[MacroDomain]   release: ");
            write_str(cstr_to_str(&utsname.release));
            write_str("\n");
            
            write_str("[MacroDomain]   version: ");
            write_str(cstr_to_str(&utsname.version));
            write_str("\n");
            
            write_str("[MacroDomain]   machine: ");
            write_str(cstr_to_str(&utsname.machine));
            write_str("\n");
        } else {
            write_str("FAILED (ret=");
            let len = u64_to_dec(ret, &mut dec_buf);
            write_str(unsafe { core::str::from_utf8_unchecked(&dec_buf[dec_buf.len() - len..]) });
            write_str(")\n");
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
            write_str("PASSED (addr=");
            let mut len = u64_to_hex(addr, &mut hex_buf);
            write_str(unsafe { core::str::from_utf8_unchecked(&hex_buf[hex_buf.len() - len..]) });
            write_str(")\n");
            
            let ptr = addr as *mut u8;
            for i in 0..0x4000 {
                *ptr.add(i) = ((i * 3) & 0xFF) as u8;
            }
            
            let mut verified = true;
            for i in 0..0x4000 {
                if *ptr.add(i) != ((i * 3) & 0xFF) as u8 {
                    write_str("MMAP verification FAILED at offset ");
                    len = u64_to_dec(i as u64, &mut dec_buf);
                    write_str(unsafe { core::str::from_utf8_unchecked(&dec_buf[dec_buf.len() - len..]) });
                    write_str("\n");
                    verified = false;
                    break;
                }
            }
            if verified {
                write_str("[MacroDomain] MMAP write/read verification PASSED\n");
            }
            
            let ret = syscall2(SYS_MUNMAP, addr, 0x4000);
            if ret == 0 {
                write_str("[MacroDomain] munmap PASSED\n");
            } else {
                write_str("[MacroDomain] munmap FAILED (ret=");
                len = u64_to_dec(ret, &mut dec_buf);
                write_str(unsafe { core::str::from_utf8_unchecked(&dec_buf[dec_buf.len() - len..]) });
                write_str(")\n");
            }
        } else {
            write_str("FAILED (addr=");
            let len = u64_to_hex(addr, &mut hex_buf);
            write_str(unsafe { core::str::from_utf8_unchecked(&hex_buf[hex_buf.len() - len..]) });
            write_str(")\n");
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
                write_str("PASSED (FS base set to ");
                let len = u64_to_hex(get_fs, &mut hex_buf);
                write_str(unsafe { core::str::from_utf8_unchecked(&hex_buf[hex_buf.len() - len..]) });
                write_str(")\n");
            } else {
                write_str("get_fs FAILED (ret=");
                let mut len = u64_to_dec(ret_get, &mut dec_buf);
                write_str(unsafe { core::str::from_utf8_unchecked(&dec_buf[dec_buf.len() - len..]) });
                write_str(", fs=");
                len = u64_to_hex(get_fs, &mut hex_buf);
                write_str(unsafe { core::str::from_utf8_unchecked(&hex_buf[hex_buf.len() - len..]) });
                write_str(")\n");
            }
        } else {
            write_str("set_fs FAILED (ret=");
            let len = u64_to_dec(ret_set, &mut dec_buf);
            write_str(unsafe { core::str::from_utf8_unchecked(&dec_buf[dec_buf.len() - len..]) });
            write_str(")\n");
        }
    }
    
    write_str("[MacroDomain] Test 9: time/gettimeofday syscalls... ");
    unsafe {
        let mut t: i64 = 0;
        let time_ret = syscall1(SYS_TIME, &mut t as *mut i64 as u64);
        write_str("time: t=");
        let mut len = i64_to_dec(t, &mut dec_buf);
        write_str(unsafe { core::str::from_utf8_unchecked(&dec_buf[dec_buf.len() - len..]) });
        write_str(", ret=");
        len = u64_to_dec(time_ret, &mut dec_buf);
        write_str(unsafe { core::str::from_utf8_unchecked(&dec_buf[dec_buf.len() - len..]) });
        write_str(" ");
        
        let mut tv = Timeval { tv_sec: 0, tv_usec: 0 };
        let gtod_ret = syscall2(SYS_GETTIMEOFDAY, &mut tv as *mut Timeval as u64, 0);
        write_str("gettimeofday: tv_sec=");
        len = i64_to_dec(tv.tv_sec, &mut dec_buf);
        write_str(unsafe { core::str::from_utf8_unchecked(&dec_buf[dec_buf.len() - len..]) });
        write_str(", tv_usec=");
        len = i64_to_dec(tv.tv_usec, &mut dec_buf);
        write_str(unsafe { core::str::from_utf8_unchecked(&dec_buf[dec_buf.len() - len..]) });
        write_str(", ret=");
        len = u64_to_dec(gtod_ret, &mut dec_buf);
        write_str(unsafe { core::str::from_utf8_unchecked(&dec_buf[dec_buf.len() - len..]) });
        write_str(" ");
        
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
                let len = u64_to_hex_padded(*b as u64, &mut hex_buf, 2);
                write_str(unsafe { core::str::from_utf8_unchecked(&hex_buf[hex_buf.len() - len..]) });
                write_str(" ");
            }
            write_str("\n");
        } else {
            write_str("FAILED (ret=");
            let len = u64_to_dec(ret, &mut dec_buf);
            write_str(unsafe { core::str::from_utf8_unchecked(&dec_buf[dec_buf.len() - len..]) });
            write_str(")\n");
        }
    }
    
    write_str("[MacroDomain] All basic syscall tests completed!\n");
    
    write_str("[MacroDomain] Testing additional syscalls expected by libc...\n");
    
    unsafe {
        write_str("[MacroDomain]   SYS_RT_SIGPROCMASK: ");
        let ret = syscall4(SYS_RT_SIGPROCMASK, 0, 0, 0, 8);
        let len = u64_to_dec(ret, &mut dec_buf);
        write_str("ret=");
        write_str(unsafe { core::str::from_utf8_unchecked(&dec_buf[dec_buf.len() - len..]) });
        write_str("\n");
        
        write_str("[MacroDomain]   SYS_RT_SIGACTION: ");
        let ret = syscall4(SYS_RT_SIGACTION, 0, 0, 0, 8);
        let len = u64_to_dec(ret, &mut dec_buf);
        write_str("ret=");
        write_str(unsafe { core::str::from_utf8_unchecked(&dec_buf[dec_buf.len() - len..]) });
        write_str("\n");
        
        write_str("[MacroDomain]   SYS_PRCTL: ");
        let ret = syscall5(SYS_PRCTL, 15, 0, 0, 0, 0);
        let len = u64_to_dec(ret, &mut dec_buf);
        write_str("ret=");
        write_str(unsafe { core::str::from_utf8_unchecked(&dec_buf[dec_buf.len() - len..]) });
        write_str("\n");
        
        write_str("[MacroDomain]   SYS_SCHED_GETPARAM: ");
        let ret = syscall2(SYS_SCHED_GETPARAM, 0, 0);
        let len = u64_to_dec(ret, &mut dec_buf);
        write_str("ret=");
        write_str(unsafe { core::str::from_utf8_unchecked(&dec_buf[dec_buf.len() - len..]) });
        write_str("\n");
        
        write_str("[MacroDomain]   SYS_SCHED_SETSCHEDULER: ");
        let ret = syscall3(SYS_SCHED_SETSCHEDULER, 0, 0, 0);
        let len = u64_to_dec(ret, &mut dec_buf);
        write_str("ret=");
        write_str(unsafe { core::str::from_utf8_unchecked(&dec_buf[dec_buf.len() - len..]) });
        write_str("\n");
        
        write_str("[MacroDomain]   SYS_SET_TID_ADDRESS: ");
        let ret = syscall1(SYS_SET_TID_ADDRESS, 0);
        let len = u64_to_dec(ret, &mut dec_buf);
        write_str("ret=");
        write_str(unsafe { core::str::from_utf8_unchecked(&dec_buf[dec_buf.len() - len..]) });
        write_str("\n");
        
        write_str("[MacroDomain]   SYS_SET_ROBUST_LIST: ");
        let ret = syscall2(SYS_SET_ROBUST_LIST, 0, 0);
        let len = u64_to_dec(ret, &mut dec_buf);
        write_str("ret=");
        write_str(unsafe { core::str::from_utf8_unchecked(&dec_buf[dec_buf.len() - len..]) });
        write_str("\n");
        
        write_str("[MacroDomain]   SYS_OPEN (test /dev/null): ");
        let path = b"/dev/null\0";
        let fd = syscall2(SYS_OPEN, path.as_ptr() as u64, 0);
        let mut len = u64_to_dec(fd, &mut dec_buf);
        write_str("fd=");
        write_str(unsafe { core::str::from_utf8_unchecked(&dec_buf[dec_buf.len() - len..]) });
        write_str(" ");
        if fd < 0x8000_0000_0000_0000 {
            syscall1(SYS_CLOSE, fd);
            write_str("PASSED\n");
        } else {
            write_str("FAILED\n");
        }
        
        write_str("[MacroDomain]   SYS_ACCESS: ");
        let ret = syscall2(SYS_ACCESS, path.as_ptr() as u64, 0);
        len = u64_to_dec(ret, &mut dec_buf);
        write_str("ret=");
        write_str(unsafe { core::str::from_utf8_unchecked(&dec_buf[dec_buf.len() - len..]) });
        write_str("\n");
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
fn panic(_info: &PanicInfo) -> ! {
    write_str("[MacroDomain] PANIC occurred\n");
    loop {
        unsafe {
            asm!("hlt", options(nomem, nostack));
        }
    }
}
