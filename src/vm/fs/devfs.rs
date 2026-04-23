use super::file::{FileHandle, FileOps, OpenFlags, FileMode, SeekFrom};
use crate::memory::ept::EptManager;
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::ToString;

pub struct DevNull;

impl FileOps for DevNull {
    fn read(&mut self, _buf: &mut [u8], _ept: &EptManager) -> Result<usize, i64> {
        Ok(0)
    }

    fn write(&mut self, buf: &[u8], _ept: &EptManager) -> Result<usize, i64> {
        Ok(buf.len())
    }

    fn lseek(&mut self, _offset: i64, _whence: SeekFrom) -> Result<u64, i64> {
        Ok(0)
    }

    fn fstat(&mut self, stat_buf: &mut super::Stat, _ept: &EptManager) -> Result<(), i64> {
        stat_buf.st_dev = 0x6;
        stat_buf.st_ino = 0x3;
        stat_buf.st_mode = 0o666 | 0o010000;
        stat_buf.st_nlink = 1;
        stat_buf.st_uid = 0;
        stat_buf.st_gid = 0;
        stat_buf.st_rdev = 0x103;
        stat_buf.st_size = 0;
        stat_buf.st_blksize = 4096;
        stat_buf.st_blocks = 0;
        stat_buf.st_atime = 0;
        stat_buf.st_atime_nsec = 0;
        stat_buf.st_mtime = 0;
        stat_buf.st_mtime_nsec = 0;
        stat_buf.st_ctime = 0;
        stat_buf.st_ctime_nsec = 0;
        Ok(())
    }

    fn clone(&self) -> Box<dyn FileOps> {
        Box::new(DevNull)
    }
}

pub struct DevZero;

impl FileOps for DevZero {
    fn read(&mut self, buf: &mut [u8], _ept: &EptManager) -> Result<usize, i64> {
        for b in buf.iter_mut() {
            *b = 0;
        }
        Ok(buf.len())
    }

    fn write(&mut self, buf: &[u8], _ept: &EptManager) -> Result<usize, i64> {
        Ok(buf.len())
    }

    fn lseek(&mut self, _offset: i64, _whence: SeekFrom) -> Result<u64, i64> {
        Ok(0)
    }

    fn fstat(&mut self, stat_buf: &mut super::Stat, _ept: &EptManager) -> Result<(), i64> {
        stat_buf.st_dev = 0x6;
        stat_buf.st_ino = 0x5;
        stat_buf.st_mode = 0o666 | 0o010000;
        stat_buf.st_nlink = 1;
        stat_buf.st_uid = 0;
        stat_buf.st_gid = 0;
        stat_buf.st_rdev = 0x105;
        stat_buf.st_size = 0;
        stat_buf.st_blksize = 4096;
        stat_buf.st_blocks = 0;
        stat_buf.st_atime = 0;
        stat_buf.st_atime_nsec = 0;
        stat_buf.st_mtime = 0;
        stat_buf.st_mtime_nsec = 0;
        stat_buf.st_ctime = 0;
        stat_buf.st_ctime_nsec = 0;
        Ok(())
    }

    fn clone(&self) -> Box<dyn FileOps> {
        Box::new(DevZero)
    }
}

pub struct DevRandom {
    seed: u64,
}

impl DevRandom {
    pub fn new() -> Self {
        let mut lo: u32 = 0;
        let mut hi: u32 = 0;
        unsafe {
            core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack));
        }
        Self {
            seed: (hi as u64) << 32 | (lo as u64),
        }
    }

    fn next_byte(&mut self) -> u8 {
        self.seed = self.seed.wrapping_mul(1103515245).wrapping_add(12345);
        (self.seed >> 16) as u8
    }
}

impl Default for DevRandom {
    fn default() -> Self {
        Self::new()
    }
}

impl FileOps for DevRandom {
    fn read(&mut self, buf: &mut [u8], _ept: &EptManager) -> Result<usize, i64> {
        for b in buf.iter_mut() {
            *b = self.next_byte();
        }
        Ok(buf.len())
    }

    fn write(&mut self, buf: &[u8], _ept: &EptManager) -> Result<usize, i64> {
        for &b in buf {
            self.seed = self.seed.wrapping_mul(1103515245).wrapping_add(b as u64);
        }
        Ok(buf.len())
    }

    fn lseek(&mut self, _offset: i64, _whence: SeekFrom) -> Result<u64, i64> {
        Ok(0)
    }

    fn fstat(&mut self, stat_buf: &mut super::Stat, _ept: &EptManager) -> Result<(), i64> {
        stat_buf.st_dev = 0x6;
        stat_buf.st_ino = 0x8;
        stat_buf.st_mode = 0o444 | 0o010000;
        stat_buf.st_nlink = 1;
        stat_buf.st_uid = 0;
        stat_buf.st_gid = 0;
        stat_buf.st_rdev = 0x108;
        stat_buf.st_size = 0;
        stat_buf.st_blksize = 4096;
        stat_buf.st_blocks = 0;
        stat_buf.st_atime = 0;
        stat_buf.st_atime_nsec = 0;
        stat_buf.st_mtime = 0;
        stat_buf.st_mtime_nsec = 0;
        stat_buf.st_ctime = 0;
        stat_buf.st_ctime_nsec = 0;
        Ok(())
    }

    fn clone(&self) -> Box<dyn FileOps> {
        Box::new(Self::new())
    }
}

pub struct DevUrandom {
    inner: DevRandom,
}

impl DevUrandom {
    pub fn new() -> Self {
        Self {
            inner: DevRandom::new(),
        }
    }
}

impl Default for DevUrandom {
    fn default() -> Self {
        Self::new()
    }
}

impl FileOps for DevUrandom {
    fn read(&mut self, buf: &mut [u8], ept: &EptManager) -> Result<usize, i64> {
        self.inner.read(buf, ept)
    }

    fn write(&mut self, buf: &[u8], ept: &EptManager) -> Result<usize, i64> {
        self.inner.write(buf, ept)
    }

    fn lseek(&mut self, offset: i64, whence: SeekFrom) -> Result<u64, i64> {
        self.inner.lseek(offset, whence)
    }

    fn fstat(&mut self, stat_buf: &mut super::Stat, ept: &EptManager) -> Result<(), i64> {
        self.inner.fstat(stat_buf, ept)?;
        stat_buf.st_ino = 0x9;
        stat_buf.st_rdev = 0x109;
        stat_buf.st_mode = 0o666 | 0o010000;
        Ok(())
    }

    fn clone(&self) -> Box<dyn FileOps> {
        Box::new(Self::new())
    }
}

pub struct DevFs {
    devices: BTreeMap<&'static str, fn() -> Box<dyn FileOps>>,
}

impl DevFs {
    pub fn new() -> Self {
        fn create_null() -> Box<dyn FileOps> { Box::new(DevNull) }
        fn create_zero() -> Box<dyn FileOps> { Box::new(DevZero) }
        fn create_random() -> Box<dyn FileOps> { Box::new(DevRandom::new()) }
        fn create_urandom() -> Box<dyn FileOps> { Box::new(DevUrandom::new()) }
        
        let mut devices: BTreeMap<&'static str, fn() -> Box<dyn FileOps>> = BTreeMap::new();
        
        devices.insert("null", create_null as fn() -> Box<dyn FileOps>);
        devices.insert("zero", create_zero as fn() -> Box<dyn FileOps>);
        devices.insert("random", create_random as fn() -> Box<dyn FileOps>);
        devices.insert("urandom", create_urandom as fn() -> Box<dyn FileOps>);
        
        Self { devices }
    }

    pub fn exists(&self, path: &str) -> bool {
        if path.starts_with("dev/") {
            let dev_name = &path[4..];
            self.devices.contains_key(dev_name)
        } else {
            self.devices.contains_key(path)
        }
    }

    pub fn open(&self, path: &str, flags: OpenFlags, mode: FileMode) -> Option<FileHandle> {
        let dev_name = if path.starts_with("dev/") {
            &path[4..]
        } else {
            path
        };

        let constructor = self.devices.get(dev_name)?;
        let ops = constructor();
        
        let name = match dev_name {
            "null" => "/dev/null",
            "zero" => "/dev/zero",
            "random" => "/dev/random",
            "urandom" => "/dev/urandom",
            _ => "",
        };

        Some(FileHandle::new(
            Box::leak(name.to_string().into_boxed_str()),
            flags,
            mode,
            ops,
        ))
    }
}

impl Default for DevFs {
    fn default() -> Self {
        Self::new()
    }
}
