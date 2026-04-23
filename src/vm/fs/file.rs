use crate::memory::ept::EptManager;
use alloc::boxed::Box;
use bitflags::bitflags;

pub enum SeekFrom {
    Start(u64),
    Current(i64),
    End(i64),
}

bitflags! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct OpenFlags: i32 {
        const RDONLY = 0o0;
        const WRONLY = 0o1;
        const RDWR = 0o2;
        const CREAT = 0o100;
        const EXCL = 0o200;
        const NOCTTY = 0o400;
        const TRUNC = 0o1000;
        const APPEND = 0o2000;
        const NONBLOCK = 0o4000;
        const DSYNC = 0o10000;
        const ASYNC = 0o20000;
        const LARGEFILE = 0o100000;
        const DIRECTORY = 0o200000;
        const NOFOLLOW = 0o400000;
        const NOATIME = 0o1000000;
        const CLOEXEC = 0o2000000;
        const SYNC = 0o4000000;
        const PATH = 0o10000000;
        const TMPFILE = 0o20000000;
        const NDELAY = 0o4000;
    }
}

bitflags! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct FileMode: u32 {
        const SUID = 0o4000;
        const SGID = 0o2000;
        const SVTX = 0o1000;
        const RWXU = 0o0700;
        const RUSR = 0o0400;
        const WUSR = 0o0200;
        const XUSR = 0o0100;
        const RWXG = 0o0070;
        const RGRP = 0o0040;
        const WGRP = 0o0020;
        const XGRP = 0o0010;
        const RWXO = 0o0007;
        const ROTH = 0o0004;
        const WOTH = 0o0002;
        const XOTH = 0o0001;
    }
}

pub trait FileOps: Send + Sync {
    fn read(&mut self, buf: &mut [u8], ept: &EptManager) -> Result<usize, i64>;
    fn write(&mut self, buf: &[u8], ept: &EptManager) -> Result<usize, i64>;
    fn lseek(&mut self, offset: i64, whence: SeekFrom) -> Result<u64, i64>;
    fn fstat(&mut self, stat_buf: &mut super::Stat, ept: &EptManager) -> Result<(), i64>;
    fn clone(&self) -> Box<dyn FileOps>;
}

pub struct FileHandle {
    pub name: &'static str,
    pub flags: OpenFlags,
    pub mode: FileMode,
    pub offset: u64,
    ops: Box<dyn FileOps>,
}

impl FileHandle {
    pub fn new(name: &'static str, flags: OpenFlags, mode: FileMode, ops: Box<dyn FileOps>) -> Self {
        Self {
            name,
            flags,
            mode,
            offset: 0,
            ops,
        }
    }

    pub fn read(&mut self, buf: &mut [u8], ept: &EptManager) -> Result<usize, i64> {
        self.ops.read(buf, ept)
    }

    pub fn write(&mut self, buf: &[u8], ept: &EptManager) -> Result<usize, i64> {
        self.ops.write(buf, ept)
    }

    pub fn lseek(&mut self, offset: i64, whence: SeekFrom) -> Result<u64, i64> {
        self.ops.lseek(offset, whence)
    }

    pub fn fstat(&mut self, stat_buf: &mut super::Stat, ept: &EptManager) -> Result<(), i64> {
        self.ops.fstat(stat_buf, ept)
    }
}

impl Clone for FileHandle {
    fn clone(&self) -> Self {
        Self {
            name: self.name,
            flags: self.flags,
            mode: self.mode,
            offset: self.offset,
            ops: self.ops.clone(),
        }
    }
}

pub struct FileDescriptor {
    handle: Option<FileHandle>,
    close_on_exec: bool,
}

impl FileDescriptor {
    pub fn new(handle: FileHandle) -> Self {
        Self {
            handle: Some(handle),
            close_on_exec: false,
        }
    }

    pub fn is_used(&self) -> bool {
        self.handle.is_some()
    }

    pub fn handle(&self) -> Option<&FileHandle> {
        self.handle.as_ref()
    }

    pub fn handle_mut(&mut self) -> Option<&mut FileHandle> {
        self.handle.as_mut()
    }

    pub fn take(&mut self) -> Option<FileHandle> {
        self.handle.take()
    }
}

pub struct FileDescriptorTable {
    descriptors: [Option<FileDescriptor>; 64],
    next_fd: usize,
}

impl FileDescriptorTable {
    pub fn new() -> Self {
        const INIT: Option<FileDescriptor> = None;
        Self {
            descriptors: [INIT; 64],
            next_fd: 3,
        }
    }

    pub fn allocate(&mut self, handle: FileHandle) -> Option<i32> {
        for (fd, slot) in self.descriptors.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(FileDescriptor::new(handle));
                self.next_fd = fd + 1;
                return Some(fd as i32);
            }
        }
        None
    }

    pub fn allocate_with_fd(&mut self, fd: usize, handle: FileHandle) -> bool {
        if fd >= 64 {
            return false;
        }
        self.descriptors[fd] = Some(FileDescriptor::new(handle));
        true
    }

    pub fn get(&self, fd: usize) -> Option<&FileHandle> {
        if fd >= 64 {
            return None;
        }
        self.descriptors[fd]
            .as_ref()
            .and_then(|d| d.handle())
    }

    pub fn get_mut(&mut self, fd: usize) -> Option<&mut FileHandle> {
        if fd >= 64 {
            return None;
        }
        self.descriptors[fd]
            .as_mut()
            .and_then(|d| d.handle_mut())
    }

    pub fn deallocate(&mut self, fd: i32) -> Option<FileHandle> {
        if fd < 0 || fd as usize >= 64 {
            return None;
        }
        let fd_usize = fd as usize;
        self.descriptors[fd_usize]
            .as_mut()
            .and_then(|d| d.take())
    }

    pub fn clone_table(&self) -> Self {
        let mut new_table = Self::new();
        for (fd, slot) in self.descriptors.iter().enumerate() {
            if let Some(desc) = slot {
                if let Some(handle) = desc.handle() {
                    let cloned = handle.clone();
                    new_table.allocate_with_fd(fd, cloned);
                }
            }
        }
        new_table
    }
}

impl Default for FileDescriptorTable {
    fn default() -> Self {
        Self::new()
    }
}
