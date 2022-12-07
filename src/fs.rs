use std::collections::HashMap;
use std::env;
use std::ffi::OsStr;
use std::time::{Duration, UNIX_EPOCH, SystemTime};
use libc::{c_int, ENOENT, ENOSYS};
use fuse::{FileType, FileAttr, Filesystem, Request, ReplyOpen, ReplyWrite, ReplyData, ReplyEntry, ReplyAttr, ReplyDirectory};
use crate::api;
use crypto::digest::Digest;
use crypto::sha2::Sha384;
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use crate::crypto::encrypt_and_hash_file;

// cache time to live, could be set to 0 to disable caching probably
const TTL: Duration = Duration::from_secs(1);           // 1 second


#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct XFileAttr {
    pub attr: FileAttr,
    pub file_name: String,
}

#[derive(Clone)]
pub struct File {
    pub xattr: XFileAttr,
    pub data: Vec<u8>,
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
            server_url: "localhost:8000".to_string(),
        }
    }
}

impl Filesystem for Q1FS {
    
    fn readdir(&mut self, _req: &Request, ino: u64, _fh: u64, offset: i64, mut reply: ReplyDirectory) {
        // Directories always contain . and ..
        reply.add(ino, offset + 1, FileType::Directory, ".");
        reply.add(ino, offset + 2, FileType::Directory, "..");
        let dir_hash = self.hashes.get(&ino);
        match dir_hash {
            Some(hash) => {
                let file = self.files.get(hash).unwrap();
                if file.xattr.attr.kind != FileType::Directory {
                    reply.error(-1); // todo: replace with "not a directory" error
                    return;
                }

                let hashes_of_children = api::get_child_hashes(&hash, &mut self.http_client, &self.server_url);
                for (i, child_hash) in hashes_of_children.iter().enumerate() {
                    match self.files.get(child_hash) {
                        Some(file) => {
                            let mut f_clone : File = file.clone();
                            // check if the file is different; if yes we should verify the tree
                            let fresh_hash = encrypt_and_hash_file(&mut f_clone, &self.crypto_key);
                            if fresh_hash != child_hash.clone() { 
                                // FIXME verify tree
                                // this state should be impossible if the server has not tampered with our data
                            }
                            else {
                                reply.add(file.xattr.attr.ino, offset + 2 + i as i64, file.xattr.attr.kind, &file.xattr.file_name);

                            }
                            
                        },
                        None => {
                            // TODO: Should this state really be possible? Consider removing this branch
                            let xattr = api::get_xattr(&child_hash, &mut self.http_client, &self.crypto_key, &self.server_url);
                            let data = api::get_data(&child_hash, &mut self.http_client, &self.crypto_key, &self.server_url);
                            let ino = xattr.attr.ino;
                            reply.add(xattr.attr.ino, offset + 2 + i as i64, xattr.attr.kind, &xattr.file_name);
                            
                            let file = File {
                                xattr: xattr,
                                data: data,
                            };

                            self.hashes.insert(ino, child_hash.clone());
                            self.files.insert(child_hash.clone(), file);

                            
                        }
                    }
                }
                reply.ok();
            }
            None => {
                // FIXME recursively check the parent directory for the directory
                reply.error(ENOENT);
            }
        }

        
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
    
    fn open(&mut self, _req: &Request<'_>, _ino: u64, _flags: u32, reply: ReplyOpen) {
        // check if the file exists either on the server or locally,
        // if it exists we should check its permissions

        let hash = self.hashes.get(&_ino);
        match hash {
            Some(hash) => {
                reply.opened(0, 0); // all opened instances of this file will share fh 0
            }
            None => {
                // FIXME recursively check the parent directory for the file
                reply.error(ENOENT);
            }
        }

    }

    fn read(&mut self, _req: &Request<'_>, _ino: u64, _fh: u64, _offset: i64, _size: u32, reply: ReplyData) {
        reply.error(ENOSYS);
    }

    fn write(&mut self, _req: &Request<'_>, _ino: u64, _fh: u64, _offset: i64, _data: &[u8], _flags: u32, reply: ReplyWrite) {
        reply.error(ENOSYS);
    }

    fn setattr(&mut self, _req: &Request<'_>, _ino: u64, _mode: Option<u32>, _uid: Option<u32>, _gid: Option<u32>, _size: Option<u64>, _atime: Option<SystemTime>, _mtime: Option<SystemTime>, _fh: Option<u64>, _crtime: Option<SystemTime>, _chgtime: Option<SystemTime>, _bkuptime: Option<SystemTime>, _flags: Option<u32>, reply: ReplyAttr) {
        let hash = self.hashes.get(&_ino);
        match hash {
            Some(hash) => {
                // file exists
                let mut new_hash = "".to_string();
                let mut file_clone : Option<File> = None;
                {
                    let file = self.files.get_mut(hash).unwrap();
                    let mut attr = file.xattr.attr.clone();

                    // set all the attributes that are Some
                    if let Some(mode) = _mode {
                        // attr.mode = mode; doesn't exist?
                    }
                    if let Some(uid) = _uid {
                        attr.uid = uid;
                    }
                    if let Some(gid) = _gid {
                        attr.gid = gid;
                    }
                    if let Some(size) = _size {
                        attr.size = size;
                    }
                    if let Some(atime) = _atime {
                        attr.atime = atime;
                    }
                    if let Some(mtime) = _mtime {
                        attr.mtime = mtime;
                    }
                    if let Some(fh) = _fh {
                        // attr.fh = fh; doesn't exist ?
                    }
                    if let Some(crtime) = _crtime {
                        attr.crtime = crtime;
                    }
                    if let Some(chgtime) = _chgtime {
                        // attr.chgtime = chgtime; doesn't exist?
                    }
                    if let Some(bkuptime) = _bkuptime {
                        // attr.bkuptime = bkuptime; doesn't exist?
                    }
                    if let Some(flags) = _flags {
                        attr.flags = flags;
                    }

                    let xattr = XFileAttr {
                        attr: attr,
                        file_name: file.xattr.file_name.clone(),
                    };
                    // TODO hack wasn't actually needed, refactor
                    (*file).xattr = xattr;
                    new_hash = api::set_xattr(&hash.to_string(), file, &mut self.http_client, &self.crypto_key, &self.server_url);
                    file_clone = Some(file.clone());
                    
                    
                    reply.attr(&TTL, &attr);
                }
                self.files.insert(new_hash.clone(), file_clone.unwrap());
                
                self.files.remove(hash);               
                self.hashes.insert(_ino, new_hash.clone());
                
                
                
            }
            None => {
                reply.error(ENOENT);
            }
        }
    }
    fn mknod(&mut self, _req: &Request<'_>, _parent: u64, _name: &OsStr, _mode: u32, _rdev: u32, reply: ReplyEntry) {
        reply.error(ENOSYS);
    }

    fn mkdir(&mut self, _req: &Request<'_>, _parent: u64, _name: &OsStr, _mode: u32, reply: ReplyEntry) {
        reply.error(ENOSYS);
    }

    fn init(&mut self, _req: &Request) -> Result<(), c_int> { 
        Ok(())
    }
}
