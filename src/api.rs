use reqwest::blocking::Client;
use reqwest;
use serde_json;
use fuse::{FileType, FileAttr, Filesystem, Request, ReplyData, ReplyEntry, ReplyAttr, ReplyDirectory};
use crate::crypto::{encrypt, hash, hash_s, decrypt, encrypt_and_hash_file};
use crate::fs::{ XFileAttr, File };
use std::io::Read;
use base64::{encode, decode};
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Node {
    hash: String,
    metadata: String,
    metadata_hash: String,
    data_hash: String,
    //data : Option<String>,
    parent_hash: String,
    is_dir: bool,
}


#[derive(Serialize, Deserialize)]
struct InsertPayload<'r> {
    is_dir: bool,
    metadata: &'r str,
    parent_hash: &'r str,
}

pub fn get_xattr(hash: &String, client : &mut Client, key : &Vec<u8>, server : &String) -> XFileAttr {
    // Get file attributes of the provided file id by hash from the server
    let url = format!("{}/node/{}", server, hash);
    let mut response = client.get(&url).send().unwrap();
    let mut node_json = Vec::new();
    response.read_to_end(&mut node_json).unwrap();
    let node: Node = serde_json::from_slice(&node_json).unwrap();

    let nonce = vec![0; 24];
    let decrypted = decrypt(&base64::decode(node.metadata).unwrap(), &key, &nonce);
    let xattr: XFileAttr = serde_json::from_slice(&decrypted).unwrap();
    xattr
}

pub fn set_xattr(hash: &String, file : &mut File, client : &mut Client, key : &Vec<u8>, server : &String) -> String {
    // Set file attributes of the provided file id by hash from the server
    let url = format!("{}/node", server);
    
    let encrypted = encrypt(&serde_json::to_vec(&file.xattr).unwrap(), &key, &vec![0; 24]);
    // wasteful but ok, we need to compute the new hash to return to the caller
    let insertpayload : InsertPayload = InsertPayload {
        is_dir: file.xattr.attr.kind == FileType::Directory,
        metadata: base64::encode(&encrypted).as_str(),
        parent_hash: "",
    };
    let hash = encrypt_and_hash_file(file, &key);
    client.post(&url).body(encrypted).send().unwrap();
    hash
}

// Get the file data of the provided file id'd by hash from the server
pub fn get_data(hash: &String, client : &Client, key : &Vec<u8>, server : &String) -> Vec<u8> {
    
    let url = format!("{}/node/{}", server, hash);
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

#[derive(Serialize, Deserialize)]
struct InsertProcedure {
    metadata : String, 
    r#type : String,
    parent_hash : String,
    content_hash : String,
    content_length : u32,
}

#[derive(Serialize, Deserialize)]
struct InitPayload {
    metadata : String, 
    username : String,
}

pub fn new_root(xfileattr : &XFileAttr, client : &mut Client, key : &Vec<u8>, server : &String) -> String {
    let url = format!("{}/root", server);
    let insert_procedure = InitPayload {
        metadata: base64::encode(&encrypt(&serde_json::to_vec(&xfileattr).unwrap(), &key, &vec![0;24])),
        username: "lol".to_string(),
    };
    let payload = serde_json::to_string(&insert_procedure).unwrap(); // FIXME nonce
    let mut response = client.post(&url).body(payload).send().unwrap();
    let mut body = Vec::new();

    // FIXME verify hash
    response.read_to_end(&mut body).unwrap();
    assert!(response.status().is_success());
    encrypt_and_hash_file(&mut File { xattr: xfileattr.clone() , data: Vec::new() }, &key)
    
}

pub fn mkdir(xfileattr : &XFileAttr, parent_hash : Option<String>, client : &mut Client, key : &Vec<u8>, server : &String) {
    let url = format!("{}/insert", server);
    let insert_procedure = InsertProcedure {
        metadata: base64::encode(&encrypt(&serde_json::to_vec(&xfileattr).unwrap(), &key, &vec![0;24])),
        r#type: "directory".to_string(),
        parent_hash: parent_hash.unwrap_or("".to_string()),
    };
    let payload = serde_json::to_string(&insert_procedure).unwrap(); // FIXME nonce
    let mut response = client.post(&url).body(payload).send().unwrap();
    let mut body = Vec::new();
    response.read_to_end(&mut body).unwrap();
}

pub fn create(xfileattr : &XFileAttr, parent_hash : &String, client : &mut Client, key : &Vec<u8>, server : &String) {
    //FIXME nonce
    let url = format!("{}/node", server);
    let metadata = &base64::encode(&encrypt(&serde_json::to_vec(&xfileattr).unwrap(), &key, &vec![0;24]));
    println!("metadata: {}", metadata);
    let insert_procedure = InsertPayload {
        metadata: metadata,
        is_dir: false,
        parent_hash: &parent_hash.to_string(),
    };
    let payload = serde_json::to_string(&insert_procedure).unwrap(); // FIXME nonce
    let mut response = client.post(&url).body(payload).send().unwrap();
    let mut body = Vec::new();
    assert!(response.status().is_success());
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
    let url = format!("{}/node/{}/children", server, hash);
    let mut response = client.get(&url).send().unwrap();
    let mut body = Vec::new();
    response.read_to_end(&mut body).unwrap();
    let hashes : Vec<String> = serde_json::from_slice(&body).unwrap();
    hashes
}


