use super::file::{FileHandle, FileOps, OpenFlags, FileMode, SeekFrom};
use crate::memory::ept::EptManager;
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use alloc::string::ToString;

pub struct RamFile {
    data: Vec<u8>,
    position: usize,
}

impl RamFile {
    pub fn new() -> Self {
        Self {
            data: Vec::new(),
            position: 0,
        }
    }

    pub fn with_data(data: Vec<u8>) -> Self {
        Self {
            data,
            position: 0,
        }
    }
}

impl Default for RamFile {
    fn default() -> Self {
        Self::new()
    }
}

impl FileOps for RamFile {
    fn read(&mut self, buf: &mut [u8], _ept: &EptManager) -> Result<usize, i64> {
        if self.position >= self.data.len() {
            return Ok(0);
        }

        let available = self.data.len() - self.position;
        let to_read = core::cmp::min(buf.len(), available);

        buf[..to_read].copy_from_slice(&self.data[self.position..self.position + to_read]);
        self.position += to_read;

        Ok(to_read)
    }

    fn write(&mut self, buf: &[u8], _ept: &EptManager) -> Result<usize, i64> {
        let end = self.position + buf.len();

        if end > self.data.len() {
            self.data.resize(end, 0);
        }

        self.data[self.position..end].copy_from_slice(buf);
        self.position = end;

        Ok(buf.len())
    }

    fn lseek(&mut self, offset: i64, whence: SeekFrom) -> Result<u64, i64> {
        let new_pos = match whence {
            SeekFrom::Start(pos) => pos as i64,
            SeekFrom::Current(off) => self.position as i64 + off,
            SeekFrom::End(off) => self.data.len() as i64 + off,
        };

        if new_pos < 0 {
            return Err(-crate::vm::syscall::linux::EINVAL);
        }

        self.position = new_pos as usize;
        Ok(self.position as u64)
    }

    fn fstat(&mut self, stat_buf: &mut super::Stat, _ept: &EptManager) -> Result<(), i64> {
        stat_buf.st_dev = 0x1;
        stat_buf.st_ino = 1;
        stat_buf.st_mode = 0o644 | 0o010000;
        stat_buf.st_nlink = 1;
        stat_buf.st_uid = 0;
        stat_buf.st_gid = 0;
        stat_buf.st_rdev = 0;
        stat_buf.st_size = self.data.len() as i64;
        stat_buf.st_blksize = 4096;
        stat_buf.st_blocks = ((self.data.len() + 4095) / 4096) as i64 * 8;
        stat_buf.st_atime = 0;
        stat_buf.st_atime_nsec = 0;
        stat_buf.st_mtime = 0;
        stat_buf.st_mtime_nsec = 0;
        stat_buf.st_ctime = 0;
        stat_buf.st_ctime_nsec = 0;
        Ok(())
    }

    fn clone(&self) -> Box<dyn FileOps> {
        Box::new(Self {
            data: self.data.clone(),
            position: self.position,
        })
    }
}

pub struct RamDirectory {
    entries: BTreeMap<&'static str, DirectoryEntry>,
}

enum DirectoryEntry {
    File(RamFile),
    Directory(RamDirectory),
}

impl RamDirectory {
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    pub fn add_file(&mut self, name: &'static str, file: RamFile) {
        self.entries.insert(name, DirectoryEntry::File(file));
    }

    pub fn add_directory(&mut self, name: &'static str, dir: RamDirectory) {
        self.entries.insert(name, DirectoryEntry::Directory(dir));
    }

    pub fn get_file_mut(&mut self, path: &str) -> Option<&mut RamFile> {
        let mut parts = path.split('/').filter(|s| !s.is_empty());
        let mut current = self;

        while let Some(part) = parts.next() {
            match current.entries.get_mut(part) {
                Some(DirectoryEntry::Directory(dir)) => {
                    current = dir;
                }
                Some(DirectoryEntry::File(file)) => {
                    if parts.next().is_none() {
                        return Some(file);
                    }
                    return None;
                }
                None => return None,
            }
        }

        None
    }

    pub fn exists(&self, path: &str) -> bool {
        let mut parts = path.split('/').filter(|s| !s.is_empty());
        let mut current = self;

        while let Some(part) = parts.next() {
            match current.entries.get(part) {
                Some(DirectoryEntry::Directory(dir)) => {
                    current = dir;
                }
                Some(DirectoryEntry::File(_)) => {
                    return parts.next().is_none();
                }
                None => return false,
            }
        }

        true
    }
}

impl Default for RamDirectory {
    fn default() -> Self {
        Self::new()
    }
}

pub struct RamFileSystem {
    root: RamDirectory,
    inode_counter: u64,
}

impl RamFileSystem {
    pub fn new() -> Self {
        let mut fs = Self {
            root: RamDirectory::new(),
            inode_counter: 2,
        };
        fs.init_default_files();
        fs
    }

    fn init_default_files(&mut self) {
        let mut etc_dir = RamDirectory::new();
        
        let mut passwd_content = Vec::new();
        passwd_content.extend_from_slice(b"root:x:0:0:root:/root:/bin/sh\n");
        passwd_content.extend_from_slice(b"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n");
        passwd_content.extend_from_slice(b"bin:x:2:2:bin:/bin:/usr/sbin/nologin\n");
        etc_dir.add_file("passwd", RamFile::with_data(passwd_content));

        let mut group_content = Vec::new();
        group_content.extend_from_slice(b"root:x:0:\n");
        group_content.extend_from_slice(b"daemon:x:1:\n");
        group_content.extend_from_slice(b"bin:x:2:\n");
        etc_dir.add_file("group", RamFile::with_data(group_content));

        let mut hosts_content = Vec::new();
        hosts_content.extend_from_slice(b"127.0.0.1\tlocalhost\n");
        hosts_content.extend_from_slice(b"::1\t\tlocalhost ip6-localhost ip6-loopback\n");
        etc_dir.add_file("hosts", RamFile::with_data(hosts_content));

        let mut resolv_content = Vec::new();
        resolv_content.extend_from_slice(b"nameserver 8.8.8.8\n");
        resolv_content.extend_from_slice(b"nameserver 8.8.4.4\n");
        etc_dir.add_file("resolv.conf", RamFile::with_data(resolv_content));

        self.root.add_directory("etc", etc_dir);

        let mut tmp_dir = RamDirectory::new();
        self.root.add_directory("tmp", tmp_dir);

        let mut var_dir = RamDirectory::new();
        self.root.add_directory("var", var_dir);

        let mut usr_dir = RamDirectory::new();
        let mut usr_bin = RamDirectory::new();
        usr_dir.add_directory("bin", usr_bin);
        let mut usr_lib = RamDirectory::new();
        usr_dir.add_directory("lib", usr_lib);
        self.root.add_directory("usr", usr_dir);

        let mut root_dir = RamDirectory::new();
        self.root.add_directory("root", root_dir);
    }

    pub fn exists(&self, path: &str) -> bool {
        if path == "/" || path.is_empty() {
            return true;
        }
        self.root.exists(path)
    }

    pub fn open(&mut self, path: &str, flags: OpenFlags, mode: FileMode) -> Option<FileHandle> {
        let create = flags.contains(OpenFlags::CREAT);
        let truncate = flags.contains(OpenFlags::TRUNC);

        if let Some(file) = self.root.get_file_mut(path) {
            if truncate {
                file.data.clear();
                file.position = 0;
            }
            
            let name = Box::leak(path.to_string().into_boxed_str());
            return Some(FileHandle::new(
                name,
                flags,
                mode,
                file.clone(),
            ));
        }

        if create {
            let mut parts = path.split('/').filter(|s| !s.is_empty());
            let file_name = match parts.next_back() {
                Some(name) => name,
                None => return None,
            };

            let parent_path = parts.collect::<Vec<_>>().join("/");
            
            let parent_dir = if parent_path.is_empty() {
                &mut self.root
            } else {
                return None;
            };

            let new_file = RamFile::new();
            let name = Box::leak(path.to_string().into_boxed_str());
            
            parent_dir.add_file(
                Box::leak(file_name.to_string().into_boxed_str()),
                new_file,
            );

            self.root.get_file_mut(path).map(|file| {
                FileHandle::new(
                    name,
                    flags,
                    mode,
                    file.clone(),
                )
            })
        } else {
            None
        }
    }
}

impl Default for RamFileSystem {
    fn default() -> Self {
        Self::new()
    }
}
