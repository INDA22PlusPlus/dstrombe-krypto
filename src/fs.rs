use std::collections::HashMap;
use std::env;
use std::ffi::OsStr;
use std::time::{Duration, UNIX_EPOCH, SystemTime};
use libc::{c_int, ENOENT, ENOSYS};
use fuse::{FileType, FileAttr, Filesystem, Request, ReplyOpen, ReplyWrite, ReplyData, ReplyCreate, ReplyEntry, ReplyAttr, ReplyDirectory};
use crate::api;
use crypto::digest::Digest;
use crypto::sha2::Sha384;
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use crate::crypto::{hash, encrypt_and_hash_file};
use std::path::PathBuf;

// cache time to live, could be set to 0 to disable caching probably
const TTL: Duration = Duration::from_secs(1);           // 1 second

#[derive(Debug, Serialize, Deserialize)]
pub struct Dir {
    pub files : HashMap<u64, String>, // inode -> filename
}

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
    // fs metadata
    top_ino : u64, // tracks the highest inode number

    // name -> inode -> hash -> file hashmaps
    // effectively allowing us to retreive a file by name, inode, or hash
    hashes : HashMap<u64, String>,
    files : HashMap<String, File>,
    inodes : HashMap<String, u64>,

    http_client: Client,
    crypto_key: Vec<u8>,
    server_url: String,
}

impl Q1FS {
    pub fn new() -> Q1FS {
        Q1FS {
            top_ino : 1, // 1 is reserved for root
            hashes: HashMap::new(),
            files: HashMap::new(),
            inodes: HashMap::new(),
            http_client: Client::new(),
            crypto_key: hash(&"hunter2".as_bytes())[..32].to_vec(), //FIXME
            server_url: "http://127.0.0.1:8000/api".to_string(),
        }
    }
}

impl Filesystem for Q1FS {
    
    fn readdir(&mut self, _req: &Request, ino: u64, _fh: u64, offset: i64, mut reply: ReplyDirectory) {
        println!("readdir: ino: {}, offset: {}", ino, offset);
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

                            self.inodes.insert(file.xattr.file_name.clone(), ino);
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
                //let xattr = api::get_xattr(&hash.to_string(), &mut self.http_client, &self.crypto_key, &self.server_url);
                println!("getattr: {} {:?}", ino, hash);
                let xattr = &self.files.get(hash).unwrap().xattr;
                reply.attr(&TTL, &xattr.attr.clone());
            }
            None => {
                // impossible state
                
                reply.error(ENOENT);
            }
        }
    }
    
    fn open(&mut self, _req: &Request<'_>, _ino: u64, _flags: u32, reply: ReplyOpen) {
        println!("open: {}", _ino);
        // should check flags + perms

        let hash = self.hashes.get(&_ino);
        match hash {
            Some(hash) => {
                reply.opened(0, 0); // all opened instances of this file will share fh 0
            }
            None => {
                reply.error(ENOENT);
            }
        }

    }

    fn create(&mut self, _req: &Request<'_>, _parent: u64, _name: &OsStr, _mode: u32, _flags: u32, reply: ReplyCreate) {
        println!("create: {} {:?}", _parent, _name);

        // should check flags + perms
        // FIXME update parent hashes recursively.
        let mut parent_hash = self.hashes.get(&_parent).clone();

        match parent_hash {
            Some(parent_hash) => {

                let file = File {
                    xattr: XFileAttr {
                        attr: FileAttr {
                            ino: self.top_ino + 1, // FIXME
                            size: 0,
                            blocks: 0,
                            atime: SystemTime::now(),
                            mtime: SystemTime::now(),
                            ctime: SystemTime::now(),
                            crtime: SystemTime::now(),
                            kind: FileType::RegularFile,
                            perm: 0o777,
                            nlink: 0,
                            uid: 0,
                            gid: 0,
                            rdev: 0,
                            flags: 0,
                        },
                        file_name: _name.to_str().unwrap().to_string(),
                    },
                    data: Vec::new(),
                };

                let hash = encrypt_and_hash_file(&mut file.clone(), &self.crypto_key);

                api::create(&file.xattr, &parent_hash.clone(), &mut self.http_client, &self.crypto_key, &self.server_url);
                
                self.inodes.insert(file.xattr.file_name.clone(), self.top_ino + 1);
                self.hashes.insert(self.top_ino + 1, hash.clone());
                self.files.insert(hash.clone(), file.clone());
                self.top_ino += 1;
                
                reply.created(&TTL, &file.xattr.attr, 0, 0, 0);
            }
            None => {
                reply.error(ENOENT);
            }
        }
    }

    fn lookup(&mut self, _req: &Request<'_>, _parent: u64, _name: &OsStr, reply: ReplyEntry) {
        println!("lookup: {} {}", _parent, _name.to_str().unwrap());
        let ino = self.inodes.get(_name.to_str().unwrap());
        match ino {
            Some(ino) => {
                let hash = self.hashes.get(ino).unwrap();
                let xattr = self.files.get(hash).unwrap().xattr.clone();
                reply.entry(&TTL, &xattr.attr, 0);
            }
            None => {
                println!("lookup: downloading xattr for {}", _name.to_str().unwrap());
                let parent_hash = self.hashes.get(&_parent);
                println!("parent: {:?}", _parent);
                let child_hashes = api::get_child_hashes(parent_hash.unwrap(), &mut self.http_client, &self.server_url);
                for hash in child_hashes {
                    let xattr = api::get_xattr(&hash, &mut self.http_client, &self.crypto_key, &self.server_url);
                    if xattr.file_name == _name.to_str().unwrap() {
                        reply.entry(&TTL, &xattr.attr, 0);
                        return;
                    }
                }
                println!("lookup: not found");
                // create file
                let parent_hash = self.hashes.get(&_parent);
                match parent_hash {
                    Some(parent_hash) => {
                        let file = File {
                            xattr: XFileAttr {
                                attr: FileAttr {
                                    ino: self.top_ino + 1, // FIXME
                                    size: 0,
                                    blocks: 0,
                                    atime: SystemTime::now(),
                                    mtime: SystemTime::now(),
                                    ctime: SystemTime::now(),
                                    crtime: SystemTime::now(),
                                    kind: FileType::RegularFile,
                                    perm: 0o777,
                                    nlink: 0,
                                    uid: 0,
                                    gid: 0,
                                    rdev: 0,
                                    flags: 0,
                                },
                                file_name: _name.to_str().unwrap().to_string(),
                            },
                            data: Vec::new(),
                        };

                        let hash = encrypt_and_hash_file(&mut file.clone(), &self.crypto_key);
                        api::create(&file.xattr, &parent_hash.clone(), &mut self.http_client, &self.crypto_key, &self.server_url);
                        self.inodes.insert(file.xattr.file_name.clone(), self.top_ino + 1);
                        self.hashes.insert(self.top_ino + 1, hash.clone());
                        self.files.insert(hash.clone(), file.clone());
                        reply.entry(&TTL, &file.xattr.attr, 0);
                    }
                    None => {
                        reply.error(ENOENT);
                    }
                }

                /*
                // recursively check the parent directory for the file
                
                // truncate the last item in the path
                let mut pathbuf = PathBuf::from(_name);
                while pathbuf.pop() {
                    let parent_ino = self.inodes.get(pathbuf.to_str().unwrap());
                    match parent_ino {
                        Some(ino) => {
                            
                        }
                        None => {

                        }
                    }
                }
                */
            }
        }
    }

    fn read(&mut self, _req: &Request<'_>, _ino: u64, _fh: u64, _offset: i64, _size: u32, reply: ReplyData) {
        println!("read: {} {} {} {}", _ino, _fh, _offset, _size);
        // check file permissions (TODO)

        let hash = self.hashes.get(&_ino);
        match hash {
            Some(hash) => {
                let file = self.files.get(hash).unwrap();
                if _offset > file.data.len() as i64 {
                    reply.error(0);
                    return;
                }
                if _offset + _size as i64 > file.data.len() as i64 {
                    reply.data(&file.data[_offset as usize..]);
                }
                else {
                    reply.data(&file.data[_offset as usize.._offset as usize + _size as usize]);
                }
            }
            None => {
                reply.error(ENOENT);
            }
        }
    }

    fn write(&mut self, _req: &Request<'_>, _ino: u64, _fh: u64, _offset: i64, _data: &[u8], _flags: u32, reply: ReplyWrite) {
        println!("write: {} {} {} {:?}", _ino, _fh, _offset, _data);
        // check file permissions (TODO)
        let hash = self.hashes.get(&_ino);
        match hash {
            Some(hash) => {
                let hash = hash.clone();
                let mut file = self.files.get_mut(&hash.clone()).unwrap().clone();
                if _offset > file.data.len() as i64 {
                    reply.error(0);
                    return;
                }
                if _offset + _data.len() as i64 > file.data.len() as i64 {
                    // extend the file
                    file.data.resize(_offset as usize + _data.len(), 0);
                    let flen = file.data.len();
                    file.data[_offset as usize..].copy_from_slice(&_data);

                    // update the file's xattr
                    file.xattr.attr.size = flen as u64;
                    file.xattr.attr.blocks = flen as u64 / 4096; // bogus, idk how blocks work

                    let new_hash = api::set_xattr(&hash, &mut file, &mut self.http_client, &self.crypto_key, &self.server_url);
                    self.hashes.remove(&_ino);
                    self.hashes.insert(_ino, new_hash.clone());
                    self.files.insert(new_hash, file);
                    self.files.remove(&hash);
                    
                }
                else {
                    file.data[_offset as usize.._offset as usize + _data.len()].copy_from_slice(_data);
                }
                reply.written(_data.len() as u32);
                
            }
            None => {
                reply.error(ENOENT);
            }
        }
    }

    fn setattr(&mut self, _req: &Request<'_>, _ino: u64, _mode: Option<u32>, _uid: Option<u32>, _gid: Option<u32>, _size: Option<u64>, _atime: Option<SystemTime>, _mtime: Option<SystemTime>, _fh: Option<u64>, _crtime: Option<SystemTime>, _chgtime: Option<SystemTime>, _bkuptime: Option<SystemTime>, _flags: Option<u32>, reply: ReplyAttr) {
        println!("setattr: {} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?}", _ino, _mode, _uid, _gid, _size, _atime, _mtime, _fh, _crtime, _chgtime, _bkuptime, _flags);
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
                //println!("old hash: {} new hash: {} ino: {}", hash, new_hash, _ino);
                self.files.remove(hash);
                self.files.insert(new_hash.clone(), file_clone.unwrap());
                
                               
                self.hashes.insert(_ino, new_hash.clone());
                
                
                
            }
            None => {
                reply.error(ENOENT);
            }
        }
    }

    fn mkdir(&mut self, _req: &Request<'_>, _parent: u64, _name: &OsStr, _mode: u32, reply: ReplyEntry) {
        println!("mkdir: {} {:?} {}", _parent, _name, _mode);
        let parent = self.hashes.get(&_parent);
        match parent {
            Some(hash) => {
                
            }
            None => {
                reply.error(ENOENT);
            }
        }
    }

    fn init(&mut self, _req: &Request) -> Result<(), c_int> { 
        println!("init");
        // check if root dir exists
        // FIXME establish implementation
        
        let has_root_dir = false;
        if !has_root_dir {
            // create root dir
            let root_dir = File {
                xattr: XFileAttr {
                    attr: FileAttr {
                        ino: 1,
                        size: 0,
                        blocks: 0,
                        atime: SystemTime::now(),
                        mtime: SystemTime::now(),
                        ctime: SystemTime::now(),
                        crtime: SystemTime::now(),
                        kind: FileType::Directory,
                        perm: 0o777,
                        nlink: 0,
                        uid: 0,
                        gid: 0,
                        rdev: 0,
                        flags: 0,
                    },
                    file_name: "root".to_string(),
                },
                data: Vec::new(),
            };
            let top_hash = api::new_root(&root_dir.xattr, &mut self.http_client, &self.crypto_key, &self.server_url);
            self.inodes.insert("".to_string(), 1);
            self.hashes.insert(1, top_hash.clone()); // FIXME
            self.files.insert(top_hash, root_dir);
        }

        Ok(())
    }
}
