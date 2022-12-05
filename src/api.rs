use reqwest::blocking::Client;
use reqwest;
use serde_json;
use fuse::{FileType, FileAttr, Filesystem, Request, ReplyData, ReplyEntry, ReplyAttr, ReplyDirectory};
use crate::crypto::{encrypt, decrypt};
use crate::fs::XFileAttr;
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


// Get the file data of the provided file id'd by hash from the server
pub fn get_data(hash: &String, client : &Client, server : &String) -> Vec<u8> {
    
    let url = format!("{}/api/data/{}", server, hash);
    let mut response = client.get(&url).send().unwrap();
    let mut body = Vec::new();
    response.read_to_end(&mut body).unwrap();
    body
}

pub fn get_nonce(hash: &String, client : &Client, server : &String) -> Vec<u8> {
    // Get the nonce of the provided file id'd by hash from the server
    let url = format!("{}/api/nonce/{}", server, hash);
    let mut response = client.get(&url).send().unwrap();
    let mut body = Vec::new();
    response.read_to_end(&mut body).unwrap();
    body
}


