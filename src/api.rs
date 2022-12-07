use reqwest::blocking::Client;
use reqwest;
use serde_json;
use fuse::{FileType, FileAttr, Filesystem, Request, ReplyData, ReplyEntry, ReplyAttr, ReplyDirectory};
use crate::crypto::{encrypt, decrypt, encrypt_and_hash_file};
use crate::fs::{ XFileAttr, File };
use std::io::Read;

pub fn get_xattr(hash: &String, client : &mut Client, key : &Vec<u8>, server : &String) -> XFileAttr {
    // Get file attributes of the provided file id by hash from the server
    let url = format!("{}/api/attr/{}", server, hash);
    let mut response = client.get(&url).send().unwrap();
    let mut encrypted = Vec::new();
    response.read_to_end(&mut encrypted).unwrap();
    let nonce = get_nonce(hash, client, server);
    let decrypted = decrypt(&encrypted, &key, &nonce);
    let xattr: XFileAttr = serde_json::from_slice(&decrypted).unwrap();
    xattr
}

pub fn set_xattr(hash: &String, file : &mut File, client : &mut Client, key : &Vec<u8>, server : &String) -> String {
    // Set file attributes of the provided file id by hash from the server
    let url = format!("{}/api/attr/{}", server, hash);
    let encrypted = encrypt(&serde_json::to_vec(&file.xattr).unwrap(), &key, &get_nonce(hash, client, server));
    // wasteful but ok, we need to compute the new hash to return to the caller
    let hash = encrypt_and_hash_file(file, &key);
    client.post(&url).body(encrypted).send().unwrap();
    hash
}

// Get the file data of the provided file id'd by hash from the server
pub fn get_data(hash: &String, client : &Client, key : &Vec<u8>, server : &String) -> Vec<u8> {
    
    let url = format!("{}/api/data/{}", server, hash);
    let mut response = client.get(&url).send().unwrap();
    let mut encrypted = Vec::new();
    response.read_to_end(&mut encrypted).unwrap();
    let nonce = get_nonce(hash, client, server);
    let decrypted = decrypt(&mut encrypted, &key, &nonce);
    decrypted
}

pub fn get_nonce(hash: &String, client : &Client, server : &String) -> Vec<u8> {
    // Get the nonce of the provided file id'd by hash from the server
    let url = format!("{}/api/nonce/{}", server, hash);
    let mut response = client.get(&url).send().unwrap();
    let mut body = Vec::new();
    response.read_to_end(&mut body).unwrap();
    body
}

pub fn mkdir(xfileattr : &XFileAttr, parent_hash : Option<String>, client : &mut Client, key : &Vec<u8>, server : &String) {
    
    let query = match parent_hash {
        Some(hash) => format!("?parent={}", hash),
        None => String::new()
    };
    let url = format!("{}/api/mkdir{}", server, query);
    let encrypted = encrypt(&serde_json::to_vec(&xfileattr).unwrap(), &key, &vec![0; 24]); // FIXME nonce
    let mut response = client.post(&url).body(encrypted).send().unwrap();
    let mut body = Vec::new();
    response.read_to_end(&mut body).unwrap();
}

pub fn create(xfileattr : &XFileAttr, parent_hash : &String, client : &mut Client, key : &Vec<u8>, server : &String) {
    // Create a file
    let url = format!("{}/api/mkdir?parent={}", server, parent_hash);
    let encrypted = encrypt(&serde_json::to_vec(&xfileattr).unwrap(), &key, &vec![0; 24]); // FIXME nonce
    let mut response = client.post(&url).body(encrypted).send().unwrap();
    let mut body = Vec::new();
    response.read_to_end(&mut body).unwrap();
}

pub fn write_data(hash: &String, data : &Vec<u8>, client : &mut Client, key : &Vec<u8>, server : &String) {
    // Write data to the provided file id'd by hash on the server
    let url = format!("{}/api/data/{}", server, hash);
    let encrypted = encrypt(&data, &key, &vec![0; 24]); // FIXME nonce
    let mut response = client.post(&url).body(encrypted).send().unwrap();
    let mut body = Vec::new();
    response.read_to_end(&mut body).unwrap();
}

pub fn get_child_hashes(hash: &String, client : &Client, server : &String) -> Vec<String> { 
    //FIXME implement
    Vec::new()
}


