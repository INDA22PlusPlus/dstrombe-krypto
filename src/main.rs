mod api;
mod fs;
mod crypto;
use fuse::mount;
use std::ffi::OsStr;
use std::env;

fn main() {
    println!("Attempting mount");
    let mountpoint = env::args_os().nth(1).unwrap();
    let options = ["-o", "rw", "-o", "fsname=hello"]
        .iter()
        .map(|o| o.as_ref())
        .collect::<Vec<&OsStr>>();
    fuse::mount(fs::Q1FS::new(), &mountpoint, &options).unwrap();
}
