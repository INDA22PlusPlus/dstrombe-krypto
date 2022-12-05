use std::collections::HashMap;
use std::env;
use std::ffi::OsStr;
use std::time::{Duration, UNIX_EPOCH};
use libc::{c_int, ENOENT};
use fuse::{FileType, FileAttr, Filesystem, Request, ReplyData, ReplyEntry, ReplyAttr, ReplyDirectory};
use crate::api;
use crypto::digest::Digest;
use crypto::sha2::Sha384;
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};

// cache time to live, could be set to 0 to disable caching probably
const TTL: Duration = Duration::from_secs(1);           // 1 second

const HELLO_TXT_ATTR: FileAttr = FileAttr {
    ino: 2,
    size: 13,
    blocks: 1,
    atime: UNIX_EPOCH,                                  // 1970-01-01 00:00:00
    mtime: UNIX_EPOCH,
    ctime: UNIX_EPOCH,
    crtime: UNIX_EPOCH,
    kind: FileType::RegularFile,
    perm: 0o644,
    nlink: 1,
    uid: 501,
    gid: 20,
    rdev: 0,
    flags: 0,
};

const HELLO_DIR_ATTR: FileAttr = FileAttr {
    ino: 1,
    size: 0,
    blocks: 0,
    atime: UNIX_EPOCH,                                  // 1970-01-01 00:00:00
    mtime: UNIX_EPOCH,
    ctime: UNIX_EPOCH,
    crtime: UNIX_EPOCH,
    kind: FileType::Directory,
    perm: 0o755,
    nlink: 2,
    uid: 501,
    gid: 20,
    rdev: 0,
    flags: 0,
};

#[derive(Serialize, Deserialize, Debug)]
pub struct XFileAttr {
    pub attr: FileAttr,
    pub file_name: String,
}

pub struct File {
    xattr: XFileAttr,
    data: Vec<u8>,
}

pub struct Q1FS {
    // inode -> hash -> file hashmaps
    hashes : HashMap<u64, String>,
    files : HashMap<String, File>,
    http_client: Client,
    crypto_key: Vec<u8>,
    server_url: String,
}
impl Q1FS {
    pub fn new() -> Q1FS {
        Q1FS {
            hashes: HashMap::new(),
            files: HashMap::new(),
            http_client: Client::new(),
            crypto_key: Vec::new(), //FIXME
            server_url: "movitzlol.com".to_string(),
        }
    }
}

impl Filesystem for Q1FS {
    
    fn readdir(&mut self, _req: &Request, ino: u64, _fh: u64, offset: i64, mut reply: ReplyDirectory) {
        
        let dir_hash = self.hashes.get(&ino);
        match dir_hash {
            Some(hash) => {
                let hashes_of_children = api::get_child_hashes(&hash, &self.http_client, &self.server_url);
                for child_hash in hashes_of_children {
                    match self.files.get(&child_hash) {
                        Some(file) => {
                            reply.add(file.xattr.attr.ino, offset, file.xattr.attr.kind, &file.xattr.file_name);
                        },
                        None => {
                            let xattr = api::get_xattr(&child_hash, &self.http_client, &self.server_url);
                            reply.add(xattr.attr.ino, offset, xattr.attr.kind, &xattr.file_name);
                        }
                    }
                } 
            }
            None => {
                // FIXME recursively check the parent directory for the directory
                reply.error(ENOENT);
            }
        }

        if ino != 1 {
            reply.error(ENOENT);
            return;
        }

        let entries = vec![
            (1, FileType::Directory, "."),
            (1, FileType::Directory, ".."),
            (2, FileType::RegularFile, "hello.txt"),
        ];

        for (i, entry) in entries.into_iter().enumerate().skip(offset as usize) {
            // i + 1 means the index of the next entry
            reply.add(entry.0, (i + 1) as i64, entry.1, entry.2);
        }
        reply.ok();
    }

    fn getattr(&mut self, _req: &Request, ino: u64, reply: ReplyAttr) {
        let hash = self.hashes.get(&ino);
        match hash {
            Some(hash) => {
                // TODO make this function return an option/result and handle it here
                let xattr = api::get_xattr(&hash.to_string(), &mut self.http_client, &self.crypto_key, &self.server_url);
                reply.attr(&TTL, &xattr.attr);
            }
            None => {
                // FIXME recursively check the parent directory for the file
                reply.error(ENOENT);
            }
        }
    }
    
    fn init(&mut self, _req: &Request) -> Result<(), c_int> { 
        Ok(())
    }
    /*
    fn destroy(&mut self, _req: &Request) { ... }
    fn lookup(
        &mut self, 
        _req: &Request, 
        _parent: u64, 
        _name: &OsStr, 
        reply: ReplyEntry
    ) { ... }
    fn forget (&mut self, _req: &Request, _ino: u64, _nlookup: u64) { ... }
    fn getattr (&mut self, _req: &Request, _ino: u64, reply: ReplyAttr) { ... }
    fn setattr (
        &mut self, 
        _req: &Request, 
        _ino: u64, 
        _mode: Option<u32>, 
        _uid: Option<u32>, 
        _gid: Option<u32>, 
        _size: Option<u64>, 
        _atime: Option<Timespec>, 
        _mtime: Option<Timespec>, 
        _fh: Option<u64>, 
        _crtime: Option<Timespec>, 
        _chgtime: Option<Timespec>, 
        _bkuptime: Option<Timespec>, 
        _flags: Option<u32>, 
        reply: ReplyAttr
    ) { ... }
    fn readlink(&mut self, _req: &Request, _ino: u64, reply: ReplyData) { ... }
    fn mknod(
        &mut self, 
        _req: &Request, 
        _parent: u64, 
        _name: &OsStr, 
        _mode: u32, 
        _rdev: u32, 
        reply: ReplyEntry
    ) { ... }
    fn mkdir(
        &mut self, 
        _req: &Request, 
        _parent: u64, 
        _name: &OsStr, 
        _mode: u32, 
        reply: ReplyEntry
    ) { ... }
    fn unlink(
        &mut self, 
        _req: &Request, 
        _parent: u64, 
        _name: &OsStr, 
        reply: ReplyEmpty
    ) { ... }
    fn rmdir(
        &mut self, 
        _req: &Request, 
        _parent: u64, 
        _name: &OsStr, 
        reply: ReplyEmpty
    ) { ... }
    fn symlink(
        &mut self, 
        _req: &Request, 
        _parent: u64, 
        _name: &OsStr, 
        _link: &Path, 
        reply: ReplyEntry
    ) { ... }
    fn rename(
        &mut self, 
        _req: &Request, 
        _parent: u64, 
        _name: &OsStr, 
        _newparent: u64, 
        _newname: &OsStr, 
        reply: ReplyEmpty
    ) { ... }
    fn link(
        &mut self, 
        _req: &Request, 
        _ino: u64, 
        _newparent: u64, 
        _newname: &OsStr, 
        reply: ReplyEntry
    ) { ... }
    fn open(&mut self, _req: &Request, _ino: u64, _flags: u32, reply: ReplyOpen) { ... }
    fn read(
        &mut self, 
        _req: &Request, 
        _ino: u64, 
        _fh: u64, 
        _offset: i64, 
        _size: u32, 
        reply: ReplyData
    ) { ... }
    fn write(
        &mut self, 
        _req: &Request, 
        _ino: u64, 
        _fh: u64, 
        _offset: i64, 
        _data: &[u8], 
        _flags: u32, 
        reply: ReplyWrite
    ) { ... }
    fn flush(
        &mut self, 
        _req: &Request, 
        _ino: u64, 
        _fh: u64, 
        _lock_owner: u64, 
        reply: ReplyEmpty
    ) { ... }
    fn release(
        &mut self, 
        _req: &Request, 
        _ino: u64, 
        _fh: u64, 
        _flags: u32, 
        _lock_owner: u64, 
        _flush: bool, 
        reply: ReplyEmpty
    ) { ... }
    fn fsync(
        &mut self, 
        _req: &Request, 
        _ino: u64, 
        _fh: u64, 
        _datasync: bool, 
        reply: ReplyEmpty
    ) { ... }
    fn opendir(
        &mut self, 
        _req: &Request, 
        _ino: u64, 
        _flags: u32, 
        reply: ReplyOpen
    ) { ... }
    fn readdir(
        &mut self, 
        _req: &Request, 
        _ino: u64, 
        _fh: u64, 
        _offset: i64, 
        reply: ReplyDirectory
    ) { ... }
    fn releasedir(
        &mut self, 
        _req: &Request, 
        _ino: u64, 
        _fh: u64, 
        _flags: u32, 
        reply: ReplyEmpty
    ) { ... }
    fn fsyncdir(
        &mut self, 
        _req: &Request, 
        _ino: u64, 
        _fh: u64, 
        _datasync: bool, 
        reply: ReplyEmpty
    ) { ... }
    fn statfs(&mut self, _req: &Request, _ino: u64, reply: ReplyStatfs) { ... }
    fn setxattr(
        &mut self, 
        _req: &Request, 
        _ino: u64, 
        _name: &OsStr, 
        _value: &[u8], 
        _flags: u32, 
        _position: u32, 
        reply: ReplyEmpty
    ) { ... }
    fn getxattr(
        &mut self, 
        _req: &Request, 
        _ino: u64, 
        _name: &OsStr, 
        _size: u32, 
        reply: ReplyXattr
    ) { ... }
    fn listxattr(
        &mut self, 
        _req: &Request, 
        _ino: u64, 
        _size: u32, 
        reply: ReplyXattr
    ) { ... }
    fn removexattr(
        &mut self, 
        _req: &Request, 
        _ino: u64, 
        _name: &OsStr, 
        reply: ReplyEmpty
    ) { ... }
    fn access(
        &mut self, 
        _req: &Request, 
        _ino: u64, 
        _mask: u32, 
        reply: ReplyEmpty
    ) { ... }
    fn create(
        &mut self, 
        _req: &Request, 
        _parent: u64, 
        _name: &OsStr, 
        _mode: u32, 
        _flags: u32, 
        reply: ReplyCreate
    ) { ... }
    fn getlk(
        &mut self, 
        _req: &Request, 
        _ino: u64, 
        _fh: u64, 
        _lock_owner: u64, 
        _start: u64, 
        _end: u64, 
        _typ: u32, 
        _pid: u32, 
        reply: ReplyLock
    ) { ... }
    fn setlk(
        &mut self, 
        _req: &Request, 
        _ino: u64, 
        _fh: u64, 
        _lock_owner: u64, 
        _start: u64, 
        _end: u64, 
        _typ: u32, 
        _pid: u32, 
        _sleep: bool, 
        reply: ReplyEmpty
    ) { ... }
    fn bmap(
        &mut self, 
        _req: &Request, 
        _ino: u64, 
        _blocksize: u32, 
        _idx: u64, 
        reply: ReplyBmap
    ) { ... }
*/
}
