use crate::arch::x86_64::vmx::GuestRegisters;
use crate::vm::hypercall::utils::{copy_guest_gpa_bytes, copy_bytes_to_guest_gpa};
use super::SyscallHandler;

const SYS_READ: u64 = 0;
const SYS_WRITE: u64 = 1;
const SYS_OPEN: u64 = 2;
const SYS_CLOSE: u64 = 3;
const SYS_FSTAT: u64 = 5;
const SYS_MMAP: u64 = 9;
const SYS_MPROTECT: u64 = 10;
const SYS_MUNMAP: u64 = 11;
const SYS_BRK: u64 = 12;
const SYS_RT_SIGACTION: u64 = 13;
const SYS_RT_SIGPROCMASK: u64 = 14;
const SYS_IOCTL: u64 = 16;
const SYS_ACCESS: u64 = 21;
const SYS_SCHED_YIELD: u64 = 24;
const SYS_GETPID: u64 = 39;
const SYS_CLONE: u64 = 56;
const SYS_FORK: u64 = 57;
const SYS_EXECVE: u64 = 59;
const SYS_EXIT: u64 = 60;
const SYS_WAIT4: u64 = 61;
const SYS_KILL: u64 = 62;
const SYS_UNAME: u64 = 63;
const SYS_FCNTL: u64 = 72;
const SYS_TRUNCATE: u64 = 76;
const SYS_FTRUNCATE: u64 = 77;
const SYS_GETCWD: u64 = 79;
const SYS_CHDIR: u64 = 80;
const SYS_FCHDIR: u64 = 81;
const SYS_RENAME: u64 = 82;
const SYS_MKDIR: u64 = 83;
const SYS_RMDIR: u64 = 84;
const SYS_CREAT: u64 = 85;
const SYS_LINK: u64 = 86;
const SYS_UNLINK: u64 = 87;
const SYS_SYMLINK: u64 = 88;
const SYS_READLINK: u64 = 89;
const SYS_CHMOD: u64 = 90;
const SYS_FCHMOD: u64 = 91;
const SYS_CHOWN: u64 = 92;
const SYS_FCHOWN: u64 = 93;
const SYS_LCHOWN: u64 = 94;
const SYS_UMASK: u64 = 95;
const SYS_GETTIMEOFDAY: u64 = 96;
const SYS_GETRLIMIT: u64 = 97;
const SYS_GETRUSAGE: u64 = 98;
const SYS_SYSINFO: u64 = 99;
const SYS_TIMES: u64 = 100;
const SYS_GETUID: u64 = 102;
const SYS_GETGID: u64 = 104;
const SYS_SETUID: u64 = 105;
const SYS_SETGID: u64 = 106;
const SYS_GETEUID: u64 = 107;
const SYS_GETEGID: u64 = 108;
const SYS_SETPGID: u64 = 109;
const SYS_GETPPID: u64 = 110;
const SYS_GETPGRP: u64 = 111;
const SYS_SETSID: u64 = 112;
const SYS_ARCH_PRCTL: u64 = 158;
const SYS_EXIT_GROUP: u64 = 231;
const SYS_SET_TID_ADDRESS: u64 = 218;
const SYS_FUTEX: u64 = 202;
const SYS_SET_ROBUST_LIST: u64 = 273;
const SYS_GET_ROBUST_LIST: u64 = 274;
const SYS_PRCTL: u64 = 157;
const SYS_GETRANDOM: u64 = 318;
const SYS_CLOCK_GETTIME: u64 = 228;
const SYS_NANOSLEEP: u64 = 230;
const SYS_POLL: u64 = 7;
const SYS_SELECT: u64 = 23;
const SYS_EPOLL_CREATE: u64 = 212;
const SYS_EPOLL_CTL: u64 = 233;
const SYS_EPOLL_WAIT: u64 = 232;
const SYS_EVENTFD: u64 = 284;
const SYS_EVENTFD2: u64 = 290;
const SYS_TIMERFD_CREATE: u64 = 283;
const SYS_SIGNALFD: u64 = 282;
const SYS_INOTIFY_INIT: u64 = 253;
const SYS_INOTIFY_ADD_WATCH: u64 = 254;
const SYS_INOTIFY_RM_WATCH: u64 = 255;
const SYS_DUP: u64 = 32;
const SYS_DUP2: u64 = 33;
const SYS_PIPE: u64 = 22;
const SYS_PIPE2: u64 = 293;
const SYS_SOCKET: u64 = 41;
const SYS_CONNECT: u64 = 42;
const SYS_ACCEPT: u64 = 43;
const SYS_SENDTO: u64 = 44;
const SYS_RECVFROM: u64 = 45;
const SYS_SHUTDOWN: u64 = 48;
const SYS_BIND: u64 = 49;
const SYS_LISTEN: u64 = 50;
const SYS_GETSOCKOPT: u64 = 55;
const SYS_SETSOCKOPT: u64 = 54;
const SYS_GETSOCKNAME: u64 = 51;
const SYS_GETPEERNAME: u64 = 52;
const SYS_STATX: u64 = 332;
const SYS_MEMFD_CREATE: u64 = 319;
const SYS_READLINKAT: u64 = 267;
const SYS_NEWFSTATAT: u64 = 262;
const SYS_UNLINKAT: u64 = 263;
const SYS_RENAMEAT: u64 = 264;
const SYS_LINKAT: u64 = 265;
const SYS_SYMLINKAT: u64 = 266;
const SYS_FCHMODAT: u64 = 268;
const SYS_FACCESSAT: u64 = 269;
const SYS_OPENAT: u64 = 257;
const SYS_MKDIRAT: u64 = 258;
const SYS_MKNODAT: u64 = 259;
const SYS_FCHOWNAT: u64 = 260;
const SYS_FUTIMESAT: u64 = 261;
const SYS_GETDENTS64: u64 = 217;
const SYS_LSEEK: u64 = 8;
const SYS_READV: u64 = 19;
const SYS_WRITEV: u64 = 20;
const SYS_PREAD64: u64 = 17;
const SYS_PWRITE64: u64 = 18;
const SYS_SENDFILE: u64 = 40;
const SYS_PSELECT6: u64 = 270;
const SYS_PPOLL: u64 = 271;
const SYS_UNSHARE: u64 = 272;
const SYS_SPLICE: u64 = 275;
const SYS_TEE: u64 = 276;
const SYS_VMSPLICE: u64 = 278;
const SYS_SYNC_FILE_RANGE: u64 = 277;
const SYS_FALLOCATE: u64 = 285;
const SYS_ACCEPT4: u64 = 288;
const SYS_RECVMMSG: u64 = 299;
const SYS_SENDMMSG: u64 = 307;
const SYS_MLOCK: u64 = 149;
const SYS_MUNLOCK: u64 = 150;
const SYS_MLOCKALL: u64 = 151;
const SYS_MUNLOCKALL: u64 = 152;
const SYS_MINCORE: u64 = 147;
const SYS_MADVISE: u64 = 148;
const SYS_MREMAP: u64 = 163;
const SYS_FSYNC: u64 = 74;
const SYS_FDATASYNC: u64 = 75;
const SYS_MSYNC: u64 = 144;
const SYS_FLOCK: u64 = 73;
const SYS_FADVISE64: u64 = 221;
const SYS_STAT: u64 = 4;
const SYS_LSTAT: u64 = 6;
const SYS_STATFS: u64 = 137;
const SYS_FSTATFS: u64 = 138;
const SYS_GETDENTS: u64 = 78;
const SYS_SETSID: u64 = 112;
const SYS_GETSID: u64 = 124;
const SYS_SETREUID: u64 = 113;
const SYS_SETREGID: u64 = 114;
const SYS_SETRESUID: u64 = 117;
const SYS_GETRESUID: u64 = 118;
const SYS_SETRESGID: u64 = 119;
const SYS_GETRESGID: u64 = 120;
const SYS_SETFSUID: u64 = 122;
const SYS_SETFSGID: u64 = 123;
const SYS_GETGROUPS: u64 = 115;
const SYS_SETGROUPS: u64 = 116;
const SYS_SETPRIORITY: u64 = 141;
const SYS_GETPRIORITY: u64 = 140;
const SYS_SCHED_SETSCHEDULER: u64 = 144;
const SYS_SCHED_GETSCHEDULER: u64 = 145;
const SYS_SCHED_SETPARAM: u64 = 142;
const SYS_SCHED_GETPARAM: u64 = 143;
const SYS_SCHED_GET_PRIORITY_MAX: u64 = 146;
const SYS_SCHED_GET_PRIORITY_MIN: u64 = 147;
const SYS_SCHED_RR_GET_INTERVAL: u64 = 148;
const SYS_RT_SIGPENDING: u64 = 127;
const SYS_RT_SIGTIMEDWAIT: u64 = 128;
const SYS_RT_SIGQUEUEINFO: u64 = 129;
const SYS_RT_SIGSUSPEND: u64 = 130;
const SYS_SIGALTSTACK: u64 = 131;
const SYS_TIMER_CREATE: u64 = 222;
const SYS_TIMER_SETTIME: u64 = 223;
const SYS_TIMER_GETTIME: u64 = 224;
const SYS_TIMER_GETOVERRUN: u64 = 225;
const SYS_TIMER_DELETE: u64 = 226;
const SYS_CLOCK_SETTIME: u64 = 227;
const SYS_CLOCK_GETRES: u64 = 229;
const SYS_CLOCK_NANOSLEEP: u64 = 230;
const SYS_SYSLOG: u64 = 103;
const SYS_UTIME: u64 = 132;
const SYS_UTIMES: u64 = 235;
const SYS_UTIMENSAT: u64 = 280;
const SYS_ADJTIMEX: u64 = 159;
const SYS_SETRLIMIT: u64 = 160;
const SYS_CHROOT: u64 = 161;
const SYS_SYNC: u64 = 162;
const SYS_ACCT: u64 = 163;
const SYS_SETTIMEOFDAY: u64 = 164;
const SYS_MOUNT: u64 = 165;
const SYS_UMOUNT2: u64 = 166;
const SYS_SWAPON: u64 = 167;
const SYS_SWAPOFF: u64 = 168;
const SYS_REBOOT: u64 = 169;
const SYS_SETHOSTNAME: u64 = 170;
const SYS_SETDOMAINNAME: u64 = 171;
const SYS_IOPL: u64 = 172;
const SYS_IOPERM: u64 = 173;
const SYS_CREATE_MODULE: u64 = 174;
const SYS_INIT_MODULE: u64 = 175;
const SYS_DELETE_MODULE: u64 = 176;
const SYS_GET_KERNEL_SYMS: u64 = 177;
const SYS_QUERY_MODULE: u64 = 178;
const SYS_QUOTACTL: u64 = 179;
const SYS_NFSSERVCTL: u64 = 180;
const SYS_AFS_SYSCALL: u64 = 183;
const SYS_SECURITY: u64 = 185;
const SYS_GETTID: u64 = 186;
const SYS_READAHEAD: u64 = 187;
const SYS_SETXATTR: u64 = 188;
const SYS_LSETXATTR: u64 = 189;
const SYS_FSETXATTR: u64 = 190;
const SYS_GETXATTR: u64 = 191;
const SYS_LGETXATTR: u64 = 192;
const SYS_FGETXATTR: u64 = 193;
const SYS_LISTXATTR: u64 = 194;
const SYS_LLISTXATTR: u64 = 195;
const SYS_FLISTXATTR: u64 = 196;
const SYS_REMOVEXATTR: u64 = 197;
const SYS_LREMOVEXATTR: u64 = 198;
const SYS_FREMOVEXATTR: u64 = 199;
const SYS_SCHED_SET_AFFINITY: u64 = 203;
const SYS_SCHED_GET_AFFINITY: u64 = 204;
const SYS_IO_SETUP: u64 = 206;
const SYS_IO_DESTROY: u64 = 207;
const SYS_IO_GETEVENTS: u64 = 208;
const SYS_IO_SUBMIT: u64 = 209;
const SYS_IO_CANCEL: u64 = 210;
const SYS_GET_THREAD_AREA: u64 = 211;
const SYS_RESTART_SYSCALL: u64 = 219;
const SYS_SEMTIMEDOP: u64 = 220;
const SYS_TGKILL: u64 = 234;
const SYS_VSERVER: u64 = 236;
const SYS_MBIND: u64 = 237;
const SYS_SET_MEMPOLICY: u64 = 238;
const SYS_GET_MEMPOLICY: u64 = 239;
const SYS_MQ_OPEN: u64 = 240;
const SYS_MQ_UNLINK: u64 = 241;
const SYS_MQ_TIMEDSEND: u64 = 242;
const SYS_MQ_TIMEDRECEIVE: u64 = 243;
const SYS_MQ_NOTIFY: u64 = 244;
const SYS_MQ_GETSETATTR: u64 = 245;
const SYS_KEXEC_LOAD: u64 = 246;
const SYS_WAITID: u64 = 247;
const SYS_ADD_KEY: u64 = 248;
const SYS_REQUEST_KEY: u64 = 249;
const SYS_KEYCTL: u64 = 250;
const SYS_IOPRIO_SET: u64 = 251;
const SYS_IOPRIO_GET: u64 = 252;
const SYS_MIGRATE_PAGES: u64 = 256;
const SYS_EPOLL_PWAIT: u64 = 281;
const SYS_SIGNALFD4: u64 = 289;
const SYS_TIMERFD_SETTIME: u64 = 286;
const SYS_TIMERFD_GETTIME: u64 = 287;
const SYS_EPOLL_CREATE1: u64 = 291;
const SYS_DUP3: u64 = 292;
const SYS_PREADV: u64 = 295;
const SYS_PWRITEV: u64 = 296;
const SYS_RT_TGSIGQUEUEINFO: u64 = 297;
const SYS_PERF_EVENT_OPEN: u64 = 298;
const SYS_FANOTIFY_INIT: u64 = 300;
const SYS_FANOTIFY_MARK: u64 = 301;
const SYS_PRLIMIT64: u64 = 302;
const SYS_NAME_TO_HANDLE_AT: u64 = 303;
const SYS_OPEN_BY_HANDLE_AT: u64 = 304;
const SYS_CLOCK_ADJTIME: u64 = 305;
const SYS_SYNCFS: u64 = 306;
const SYS_SETNS: u64 = 308;
const SYS_GETCPU: u64 = 309;
const SYS_PROCESS_VM_READV: u64 = 310;
const SYS_PROCESS_VM_WRITEV: u64 = 311;
const SYS_KCMP: u64 = 312;
const SYS_FINIT_MODULE: u64 = 313;
const SYS_SCHED_SETATTR: u64 = 314;
const SYS_SCHED_GETATTR: u64 = 315;
const SYS_RENAMEAT2: u64 = 316;
const SYS_SECCOMP: u64 = 317;
const SYS_PKEY_MPROTECT: u64 = 329;
const SYS_PKEY_ALLOC: u64 = 330;
const SYS_PKEY_FREE: u64 = 331;
const SYS_USERFAULTFD: u64 = 323;
const SYS_MEMBARRIER: u64 = 324;
const SYS_MLOCK2: u64 = 325;
const SYS_COPY_FILE_RANGE: u64 = 326;
const SYS_PREADV2: u64 = 327;
const SYS_PWRITEV2: u64 = 328;
const SYS_KEXEC_FILE_LOAD: u64 = 320;
const SYS_BPF: u64 = 321;
const SYS_EXECVEAT: u64 = 322;
const SYS_PERSONALITY: u64 = 135;
const SYS_VHANGUP: u64 = 153;
const SYS_MODIFY_LDT: u64 = 154;
const SYS_PIVOT_ROOT: u64 = 155;
const SYS__SYSCTL: u64 = 156;
const SYS_PTRACE: u64 = 101;
const SYS_SEMGET: u64 = 64;
const SYS_SEMOP: u64 = 65;
const SYS_SEMCTL: u64 = 66;
const SYS_SHMDT: u64 = 67;
const SYS_SHMGET: u64 = 29;
const SYS_SHMAT: u64 = 30;
const SYS_SHMCTL: u64 = 31;
const SYS_MSGGET: u64 = 68;
const SYS_MSGSND: u64 = 69;
const SYS_MSGRCV: u64 = 70;
const SYS_MSGCTL: u64 = 71;
const SYS_MKNOD: u64 = 133;
const SYS_USELIB: u64 = 134;
const SYS_USTAT: u64 = 136;
const SYS_LOOP_CTL: u64 = 333;
const SYS_LOOP_CONFIGURE: u64 = 334;

const ENOSYS: i64 = -38;
const EINVAL: i64 = -22;
const ENOMEM: i64 = -12;
const EBADF: i64 = -9;
const EFAULT: i64 = -14;
const ERANGE: i64 = -34;

pub struct LinuxSyscallHandler;

static mut BRK_CURRENT: u64 = 0x4000_0000;
static mut MMAP_NEXT: u64 = 0x7000_0000;

impl SyscallHandler for LinuxSyscallHandler {
    fn handle_syscall(&self, regs: &mut GuestRegisters) -> bool {
        let syscall_nr = regs.rax;
        let result = match syscall_nr {
            SYS_READ => sys_read(regs),
            SYS_WRITE => sys_write(regs),
            SYS_OPEN => sys_open(regs),
            SYS_CLOSE => sys_close(regs),
            SYS_BRK => sys_brk(regs),
            SYS_MMAP => sys_mmap(regs),
            SYS_MUNMAP => sys_munmap(regs),
            SYS_MPROTECT => sys_mprotect(regs),
            SYS_GETPID => sys_getpid(regs),
            SYS_GETPPID => sys_getppid(regs),
            SYS_GETUID => sys_getuid(regs),
            SYS_GETEUID => sys_geteuid(regs),
            SYS_GETGID => sys_getgid(regs),
            SYS_GETEGID => sys_getegid(regs),
            SYS_UNAME => sys_uname(regs),
            SYS_ARCH_PRCTL => sys_arch_prctl(regs),
            SYS_EXIT | SYS_EXIT_GROUP => sys_exit(regs),
            SYS_SCHED_YIELD => sys_sched_yield(regs),
            SYS_FSTAT => sys_fstat(regs),
            SYS_LSEEK => EINVAL as u64,
            SYS_IOCTL => sys_ioctl(regs),
            SYS_ACCESS => sys_access(regs),
            SYS_GETCWD => sys_getcwd(regs),
            SYS_CHDIR | SYS_FCHDIR => sys_chdir(regs),
            SYS_FCNTL => sys_fcntl(regs),
            SYS_GETDENTS64 | SYS_GETDENTS => sys_getdents64(regs),
            SYS_DUP => sys_dup(regs),
            SYS_DUP2 => sys_dup2(regs),
            SYS_PIPE | SYS_PIPE2 => sys_pipe(regs),
            SYS_SOCKET | SYS_CONNECT | SYS_ACCEPT | SYS_SENDTO | SYS_RECVFROM |
            SYS_SHUTDOWN | SYS_BIND | SYS_LISTEN => ENOSYS as u64,
            SYS_GETSOCKOPT | SYS_SETSOCKOPT | SYS_GETSOCKNAME | SYS_GETPEERNAME => 0,
            SYS_POLL | SYS_SELECT | SYS_PSELECT6 | SYS_PPOLL => 0,
            SYS_EPOLL_CREATE | SYS_EPOLL_CREATE1 => 4,
            SYS_EPOLL_CTL | SYS_EPOLL_WAIT | SYS_EPOLL_PWAIT => 0,
            SYS_EVENTFD | SYS_EVENTFD2 => 5,
            SYS_TIMERFD_CREATE => 6,
            SYS_SIGNALFD | SYS_SIGNALFD4 => 7,
            SYS_INOTIFY_INIT | SYS_INOTIFY_INIT1 => 8,
            SYS_INOTIFY_ADD_WATCH => 1,
            SYS_INOTIFY_RM_WATCH => 0,
            SYS_CLONE | SYS_FORK | SYS_VFORK => ENOSYS as u64,
            SYS_EXECVE => ENOSYS as u64,
            SYS_WAIT4 => ENOSYS as u64,
            SYS_KILL | SYS_TGKILL => 0,
            SYS_RT_SIGACTION | SYS_RT_SIGPROCMASK => 0,
            SYS_PRCTL => sys_prctl(regs),
            SYS_FUTEX => 0,
            SYS_SET_TID_ADDRESS => 1,
            SYS_SET_ROBUST_LIST | SYS_GET_ROBUST_LIST => 0,
            SYS_GETRANDOM => sys_getrandom(regs),
            SYS_MEMFD_CREATE => 10,
            SYS_STATX | SYS_NEWFSTATAT | SYS_STAT | SYS_LSTAT | SYS_FSTAT => 0,
            SYS_CLOCK_GETTIME | SYS_CLOCK_GETRES => 0,
            SYS_NANOSLEEP | SYS_CLOCK_NANOSLEEP => 0,
            SYS_GETTIMEOFDAY | SYS_TIME | SYS_TIMES | SYS_SYSINFO => 0,
            SYS_GETRLIMIT | SYS_SETRLIMIT | SYS_GETRUSAGE => 0,
            SYS_UMASK => 0o022,
            SYS_CHMOD | SYS_FCHMOD | SYS_FCHMODAT => 0,
            SYS_CHOWN | SYS_FCHOWN | SYS_LCHOWN | SYS_FCHOWNAT => 0,
            SYS_MKDIR | SYS_MKDIRAT => 0,
            SYS_RMDIR => 0,
            SYS_CREAT | SYS_MKNOD | SYS_MKNODAT => ENOSYS as u64,
            SYS_LINK | SYS_LINKAT => 0,
            SYS_UNLINK | SYS_UNLINKAT => 0,
            SYS_SYMLINK | SYS_SYMLINKAT => 0,
            SYS_READLINK | SYS_READLINKAT => 0,
            SYS_RENAME | SYS_RENAMEAT | SYS_RENAMEAT2 => 0,
            SYS_TRUNCATE | SYS_FTRUNCATE => 0,
            SYS_FSYNC | SYS_FDATASYNC | SYS_MSYNC => 0,
            SYS_FLOCK | SYS_MADVISE => 0,
            SYS_MREMAP => ENOSYS as u64,
            SYS_MLOCK | SYS_MUNLOCK | SYS_MLOCKALL | SYS_MUNLOCKALL | SYS_MINCORE => 0,
            SYS_READV | SYS_WRITEV | SYS_PREADV | SYS_PWRITEV | SYS_PREADV2 | SYS_PWRITEV2 => 0,
            SYS_PREAD64 | SYS_PWRITE64 => 0,
            SYS_SENDFILE | SYS_COPY_FILE_RANGE => 0,
            SYS_SYNC | SYS_SYNCFS => 0,
            SYS_FALLOCATE | SYS_FADVISE64 => 0,
            SYS_STATFS | SYS_FSTATFS | SYS_USTAT => 0,
            SYS_MOUNT | SYS_UMOUNT2 => 0,
            SYS_PIVOT_ROOT | SYS_CHROOT => 0,
            SYS_SETHOSTNAME | SYS_SETDOMAINNAME => 0,
            SYS_SYSLOG => 0,
            SYS_UTIME | SYS_UTIMES | SYS_UTIMENSAT | SYS_FUTIMESAT => 0,
            SYS_ADJTIMEX | SYS_SETTIMEOFDAY => 0,
            SYS_REBOOT => 0,
            SYS_IOPL | SYS_IOPERM | SYS_MODIFY_LDT => 0,
            SYS_CREATE_MODULE | SYS_INIT_MODULE | SYS_DELETE_MODULE | SYS_FINIT_MODULE => 0,
            SYS_GET_KERNEL_SYMS | SYS_QUERY_MODULE => 0,
            SYS_QUOTACTL | SYS_NFSSERVCTL | SYS_AFS_SYSCALL | SYS_SECURITY => 0,
            SYS_GETTID => 1,
            SYS_READAHEAD => 0,
            SYS_SETXATTR | SYS_LSETXATTR | SYS_FSETXATTR => 0,
            SYS_GETXATTR | SYS_LGETXATTR | SYS_FGETXATTR => 0,
            SYS_LISTXATTR | SYS_LLISTXATTR | SYS_FLISTXATTR => 0,
            SYS_REMOVEXATTR | SYS_LREMOVEXATTR | SYS_FREMOVEXATTR => 0,
            SYS_SCHED_SET_AFFINITY | SYS_SCHED_GET_AFFINITY => 0,
            SYS_IO_SETUP | SYS_IO_DESTROY | SYS_IO_GETEVENTS | SYS_IO_SUBMIT | SYS_IO_CANCEL => 0,
            SYS_GET_THREAD_AREA => 0,
            SYS_RESTART_SYSCALL => 0,
            SYS_SEMTIMEDOP | SYS_SEMOP | SYS_SEMCTL | SYS_SEMGET => 0,
            SYS_SHMGET | SYS_SHMAT | SYS_SHMDT | SYS_SHMCTL => 0,
            SYS_MSGGET | SYS_MSGSND | SYS_MSGRCV | SYS_MSGCTL => 0,
            SYS_TIMER_CREATE | SYS_TIMER_SETTIME | SYS_TIMER_GETTIME | SYS_TIMER_GETOVERRUN | SYS_TIMER_DELETE => 0,
            SYS_TIMERFD_SETTIME | SYS_TIMERFD_GETTIME => 0,
            SYS_CLOCK_SETTIME => 0,
            SYS_MBIND | SYS_SET_MEMPOLICY | SYS_GET_MEMPOLICY => 0,
            SYS_MQ_OPEN | SYS_MQ_UNLINK | SYS_MQ_TIMEDSEND | SYS_MQ_TIMEDRECEIVE |
            SYS_MQ_NOTIFY | SYS_MQ_GETSETATTR => 0,
            SYS_KEXEC_LOAD | SYS_KEXEC_FILE_LOAD => 0,
            SYS_WAITID => 0,
            SYS_ADD_KEY | SYS_REQUEST_KEY | SYS_KEYCTL => 0,
            SYS_IOPRIO_SET | SYS_IOPRIO_GET => 0,
            SYS_MIGRATE_PAGES => 0,
            SYS_RT_SIGPENDING | SYS_RT_SIGTIMEDWAIT | SYS_RT_SIGQUEUEINFO | SYS_RT_SIGSUSPEND => 0,
            SYS_SIGALTSTACK => 0,
            SYS_ACCEPT4 | SYS_RECVMMSG | SYS_SENDMMSG => 0,
            SYS_FANOTIFY_INIT | SYS_FANOTIFY_MARK => 0,
            SYS_PRLIMIT64 => 0,
            SYS_NAME_TO_HANDLE_AT | SYS_OPEN_BY_HANDLE_AT => 0,
            SYS_CLOCK_ADJTIME => 0,
            SYS_SETNS => 0,
            SYS_GETCPU => 0,
            SYS_PROCESS_VM_READV | SYS_PROCESS_VM_WRITEV => 0,
            SYS_KCMP => 0,
            SYS_SCHED_SETATTR | SYS_SCHED_GETATTR => 0,
            SYS_SECCOMP => 0,
            SYS_PKEY_MPROTECT | SYS_PKEY_ALLOC | SYS_PKEY_FREE => 0,
            SYS_USERFAULTFD => 0,
            SYS_MEMBARRIER => 0,
            SYS_MLOCK2 => 0,
            SYS_UNSHARE | SYS_SPLICE | SYS_TEE | SYS_VMSPLICE | SYS_SYNC_FILE_RANGE => 0,
            SYS_PERSONALITY | SYS_VHANGUP | SYS_USELIB | SYS_PIVOT_ROOT | SYS__SYSCTL => 0,
            SYS_PTRACE => 0,
            SYS_SETPGID | SYS_GETPGRP | SYS_SETSID | SYS_GETSID | SYS_GETPGID => 0,
            SYS_SETREUID | SYS_SETREGID | SYS_SETRESUID | SYS_GETRESUID |
            SYS_SETRESGID | SYS_GETRESGID | SYS_SETUID | SYS_SETGID |
            SYS_SETFSUID | SYS_SETFSGID | SYS_GETGROUPS | SYS_SETGROUPS => 0,
            SYS_SETPRIORITY | SYS_GETPRIORITY => 0,
            SYS_SCHED_SETSCHEDULER | SYS_SCHED_GETSCHEDULER | SYS_SCHED_SETPARAM |
            SYS_SCHED_GETPARAM | SYS_SCHED_GET_PRIORITY_MAX | SYS_SCHED_GET_PRIORITY_MIN |
            SYS_SCHED_RR_GET_INTERVAL => 0,
            SYS_ACCT | SYS_SWAPON | SYS_SWAPOFF => 0,
            SYS_FACCESSAT => 0,
            SYS_OPENAT => ENOSYS as u64,
            SYS_BPF => 0,
            SYS_EXECVEAT => ENOSYS as u64,
            SYS_LOOP_CTL | SYS_LOOP_CONFIGURE => -ENOSYS as u64,
            _ => {
                crate::log_debug!("未实现的系统调用: nr={}, rdi={:#x}, rsi={:#x}, rdx={:#x}",
                    syscall_nr, regs.rdi, regs.rsi, regs.rdx);
                ENOSYS as u64
            }
        };

        regs.rax = result;
        true
    }
}

fn sys_read(regs: &mut GuestRegisters) -> u64 {
    let fd = regs.rdi as i32;
    if fd < 0 {
        return EBADF as u64;
    }
    0
}

fn sys_write(regs: &mut GuestRegisters) -> u64 {
    let fd = regs.rdi as i32;
    let buf_gpa = regs.rsi;
    let count = regs.rdx as usize;

    if fd < 0 {
        return EBADF as u64;
    }
    if count == 0 {
        return 0;
    }

    let mut mgr = crate::enclave::get_manager();
    let manager = match mgr.as_mut() {
        Some(m) => m,
        None => return EFAULT as u64,
    };
    let cur = match manager.current_id() {
        Some(id) => id,
        None => return EFAULT as u64,
    };
    let enclave = match manager.get_enclave_mut(cur) {
        Some(e) => e,
        None => return EFAULT as u64,
    };

    let mut buf = [0u8; 512];
    let mut offset = 0usize;
    let mut remaining = count;

    while remaining > 0 {
        let chunk = core::cmp::min(remaining, 512);
        let n = copy_guest_gpa_bytes(&enclave.ept, buf_gpa + offset as u64, &mut buf[..chunk]);
        if n == 0 {
            break;
        }
        
        if fd == 1 || fd == 2 {
            for i in 0..n {
                let c = buf[i];
                if c == b'\n' || c == b'\r' || c == b'\t' || (c >= 0x20 && c < 0x7f) {
                    crate::serial_print!("{}", c as char);
                }
            }
        }
        
        offset += n;
        remaining -= n;
        if n < chunk {
            break;
        }
    }

    offset as u64
}

fn sys_open(regs: &mut GuestRegisters) -> u64 {
    ENOSYS as u64
}

fn sys_close(regs: &mut GuestRegisters) -> u64 {
    0
}

fn sys_brk(regs: &mut GuestRegisters) -> u64 {
    let addr = regs.rdi;
    unsafe {
        if addr == 0 {
            return BRK_CURRENT;
        }
        if addr >= 0x4000_0000 && addr < 0x8000_0000 {
            BRK_CURRENT = addr;
            return addr;
        }
    }
    ENOMEM as u64
}

fn sys_mmap(regs: &mut GuestRegisters) -> u64 {
    let len = regs.rsi;
    if len == 0 {
        return EINVAL as u64;
    }

    let aligned_len = (len + 0xFFF) & !0xFFF;

    unsafe {
        let result = MMAP_NEXT;
        MMAP_NEXT += aligned_len;
        
        let mut mgr = crate::enclave::get_manager();
        if let Some(manager) = mgr.as_mut() {
            if let Some(cur) = manager.current_id() {
                if let Some(enclave) = manager.get_enclave_mut(cur) {
                    let mut gpa = result;
                    let end = result + aligned_len;
                    while gpa < end {
                        if let Some(frame) = crate::memory::allocate_frame() {
                            let hpa = frame.start_address();
                            let flags = crate::memory::ept::EptFlags::READ 
                                | crate::memory::ept::EptFlags::WRITE
                                | crate::memory::ept::EptFlags::EXECUTE
                                | crate::memory::ept::EptFlags::MEMORY_TYPE_WB;
                            enclave.ept.map(x86_64::PhysAddr::new(gpa), hpa, flags);
                        }
                        gpa += 4096;
                    }
                }
            }
        }
        result
    }
}

fn sys_munmap(regs: &mut GuestRegisters) -> u64 {
    0
}

fn sys_mprotect(regs: &mut GuestRegisters) -> u64 {
    0
}

fn sys_getpid(regs: &mut GuestRegisters) -> u64 {
    1
}

fn sys_getppid(regs: &mut GuestRegisters) -> u64 {
    0
}

fn sys_getuid(regs: &mut GuestRegisters) -> u64 {
    0
}

fn sys_geteuid(regs: &mut GuestRegisters) -> u64 {
    0
}

fn sys_getgid(regs: &mut GuestRegisters) -> u64 {
    0
}

fn sys_getegid(regs: &mut GuestRegisters) -> u64 {
    0
}

fn sys_uname(regs: &mut GuestRegisters) -> u64 {
    let buf_gpa = regs.rdi;
    
    let mut mgr = crate::enclave::get_manager();
    let manager = match mgr.as_mut() {
        Some(m) => m,
        None => return EFAULT as u64,
    };
    let cur = match manager.current_id() {
        Some(id) => id,
        None => return EFAULT as u64,
    };
    let enclave = match manager.get_enclave_mut(cur) {
        Some(e) => e,
        None => return EFAULT as u64,
    };

    let mut utsname = [0u8; 390];
    let sysname = b"Linux\0";
    let nodename = b"aether\0";
    let release = b"6.1.0-aether\0";
    let version = b"#1 SMP\0";
    let machine = b"x86_64\0";
    let domainname = b"(none)\0";

    fn copy_to_buf(buf: &mut [u8], offset: usize, src: &[u8]) {
        let len = core::cmp::min(src.len(), buf.len() - offset);
        buf[offset..offset + len].copy_from_slice(&src[..len]);
    }

    copy_to_buf(&mut utsname, 0, sysname);
    copy_to_buf(&mut utsname, 65, nodename);
    copy_to_buf(&mut utsname, 130, release);
    copy_to_buf(&mut utsname, 195, version);
    copy_to_buf(&mut utsname, 260, machine);
    copy_to_buf(&mut utsname, 325, domainname);

    copy_bytes_to_guest_gpa(&enclave.ept, buf_gpa, &utsname);
    0
}

const ARCH_SET_GS: i32 = 0x1001;
const ARCH_SET_FS: i32 = 0x1002;
const ARCH_GET_FS: i32 = 0x1003;
const ARCH_GET_GS: i32 = 0x1004;

fn sys_arch_prctl(regs: &mut GuestRegisters) -> u64 {
    let option = regs.rdi as i32;
    let addr = regs.rsi;

    match option {
        ARCH_SET_FS => {
            unsafe { crate::vm::exit::GUEST_MSR_STATE.fs_base = addr };
            0
        }
        ARCH_SET_GS => {
            unsafe { crate::vm::exit::GUEST_MSR_STATE.gs_base = addr };
            0
        }
        ARCH_GET_FS => {
            let mut mgr = crate::enclave::get_manager();
            if let Some(manager) = mgr.as_mut() {
                if let Some(cur) = manager.current_id() {
                    if let Some(enclave) = manager.get_enclave_mut(cur) {
                        let val = unsafe { crate::vm::exit::GUEST_MSR_STATE.fs_base };
                        let val_bytes = val.to_ne_bytes();
                        copy_bytes_to_guest_gpa(&enclave.ept, addr, &val_bytes);
                        return 0;
                    }
                }
            }
            EFAULT as u64
        }
        ARCH_GET_GS => {
            let mut mgr = crate::enclave::get_manager();
            if let Some(manager) = mgr.as_mut() {
                if let Some(cur) = manager.current_id() {
                    if let Some(enclave) = manager.get_enclave_mut(cur) {
                        let val = unsafe { crate::vm::exit::GUEST_MSR_STATE.gs_base };
                        let val_bytes = val.to_ne_bytes();
                        copy_bytes_to_guest_gpa(&enclave.ept, addr, &val_bytes);
                        return 0;
                    }
                }
            }
            EFAULT as u64
        }
        _ => EINVAL as u64,
    }
}

fn sys_exit(regs: &mut GuestRegisters) -> u64 {
    let exit_code = regs.rdi as i32;
    crate::log_info!("隔离域退出，退出码: {}", exit_code);
    0
}

fn sys_sched_yield(regs: &mut GuestRegisters) -> u64 {
    0
}

fn sys_fstat(regs: &mut GuestRegisters) -> u64 {
    0
}

fn sys_ioctl(regs: &mut GuestRegisters) -> u64 {
    ENOSYS as u64
}

fn sys_access(regs: &mut GuestRegisters) -> u64 {
    0
}

fn sys_getcwd(regs: &mut GuestRegisters) -> u64 {
    let buf_gpa = regs.rdi;
    let size = regs.rsi as usize;

    if size < 2 {
        return ERANGE as u64;
    }

    let cwd = b"/\0";
    if cwd.len() > size {
        return ERANGE as u64;
    }

    let mut mgr = crate::enclave::get_manager();
    if let Some(manager) = mgr.as_mut() {
        if let Some(cur) = manager.current_id() {
            if let Some(enclave) = manager.get_enclave_mut(cur) {
                copy_bytes_to_guest_gpa(&enclave.ept, buf_gpa, cwd);
                return buf_gpa;
            }
        }
    }
    EFAULT as u64
}

fn sys_chdir(regs: &mut GuestRegisters) -> u64 {
    0
}

fn sys_fcntl(regs: &mut GuestRegisters) -> u64 {
    ENOSYS as u64
}

fn sys_getdents64(regs: &mut GuestRegisters) -> u64 {
    0
}

fn sys_dup(regs: &mut GuestRegisters) -> u64 {
    let fd = regs.rdi as i32;
    if fd < 0 || fd > 2 {
        return EBADF as u64;
    }
    3
}

fn sys_dup2(regs: &mut GuestRegisters) -> u64 {
    let old_fd = regs.rdi as i32;
    let new_fd = regs.rsi as i32;
    if old_fd < 0 || old_fd > 2 {
        return EBADF as u64;
    }
    new_fd as u64
}

fn sys_pipe(regs: &mut GuestRegisters) -> u64 {
    ENOSYS as u64
}

fn sys_prctl(regs: &mut GuestRegisters) -> u64 {
    let option = regs.rdi as i32;
    match option {
        15 => 0,
        _ => EINVAL as u64,
    }
}

fn sys_getrandom(regs: &mut GuestRegisters) -> u64 {
    let buf_gpa = regs.rdi;
    let count = regs.rsi as usize;

    if count == 0 {
        return 0;
    }

    let mut mgr = crate::enclave::get_manager();
    let manager = match mgr.as_mut() {
        Some(m) => m,
        None => return EFAULT as u64,
    };
    let cur = match manager.current_id() {
        Some(id) => id,
        None => return EFAULT as u64,
    };
    let enclave = match manager.get_enclave_mut(cur) {
        Some(e) => e,
        None => return EFAULT as u64,
    };

    let mut seed = 0x12345678u64;
    let mut written = 0usize;
    let mut buf = [0u8; 256];
    let mut remaining = count;

    while remaining > 0 {
        let chunk = core::cmp::min(remaining, 256);
        for i in 0..chunk {
            seed = seed.wrapping_mul(1103515245).wrapping_add(12345);
            buf[i] = (seed >> 16) as u8;
        }
        let n = copy_bytes_to_guest_gpa(&enclave.ept, buf_gpa + written as u64, &buf[..chunk]);
        if n == 0 {
            break;
        }
        written += n;
        remaining -= n;
    }

    written as u64
}
