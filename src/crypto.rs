use crypto::{symmetriccipher::{Encryptor, Decryptor}, chacha20::ChaCha20, buffer::{RefReadBuffer, RefWriteBuffer, ReadBuffer, WriteBuffer}};
use std::io::Read;
use crate::fs::File;
use crypto::sha2::Sha384;
use crypto::digest::Digest;
use crypto::buffer::BufferResult;
pub fn encrypt_and_hash_file(file : &mut File, key : &Vec<u8>) -> String {
    let mut hasher_xattr = Sha384::new();
    let mut hasher_file = Sha384::new();

    let mut plaintext_attr = serde_json::to_string(&file.xattr).unwrap();
    let mut plaintext = file.data.clone();


    let mut buf = plaintext_attr.as_bytes().to_vec().clone();
    let mut ciphertext_attr = encrypt(&mut buf, &key, &generate_nonce());
    let mut ciphertext = encrypt(&mut plaintext, &key, &generate_nonce());
    
    
    hasher_xattr.input(&ciphertext_attr);
    hasher_file.input(&ciphertext);
    
    let mut hash_xattr = vec![0; hasher_xattr.output_bytes()];
    let mut hash_file = vec![0; hasher_file.output_bytes()];

    hasher_xattr.result(&mut hash_xattr);
    hasher_file.result(&mut hash_file);

    let mut node_hasher = Sha384::new();
    node_hasher.input(&hash_xattr);
    if file.data.len() > 0 {
        node_hasher.input(&hash_file);
    }

    let mut node_hash = vec![0; node_hasher.output_bytes()];
    node_hasher.result_str()
}

// FIXME implement
pub fn verify_merkle_hashes() {
    panic!("FIXME");
}

pub fn encrypt(data: &Vec<u8>, key: &Vec<u8>, nonce : &Vec<u8>) -> Vec<u8> {
    println!("key length : {}, key : {:?}", key.len(), key);
    let mut encryptor = Box::new(ChaCha20::new_xchacha20(&key, &nonce)) as Box<dyn Encryptor>;
    let mut plaintext = RefReadBuffer::new(&data);
    let mut ciphertext_out : Vec<u8> = Vec::new();
    loop {
        let mut buf = [0; 512];
        let mut encrypted = RefWriteBuffer::new(&mut buf);
        let result = encryptor.encrypt(&mut plaintext, &mut encrypted, true);
        ciphertext_out.extend_from_slice(&encrypted.take_read_buffer().take_remaining());
        match result.unwrap() {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => continue,
        } 
    }
    ciphertext_out
}

pub fn decrypt(encrypted: &Vec<u8>, key: &Vec<u8>, nonce: &Vec<u8>) -> Vec<u8> {
    println!("key length : {}, key : {:?}", key.len(), key);
    let mut decryptor = Box::new(ChaCha20::new_xchacha20(&key, &nonce)) as Box<dyn Decryptor>;
    let mut ciphertext = RefReadBuffer::new(&encrypted);
    let mut plaintext_out : Vec<u8> = Vec::new();
    loop {
        let mut buf = [0; 512];
        let mut decrypted = RefWriteBuffer::new(&mut buf);
        let result = decryptor.decrypt(&mut ciphertext, &mut decrypted, true);
        plaintext_out.extend_from_slice(&decrypted.take_read_buffer().take_remaining());
        match result.unwrap() {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => continue,
        } 
    }
    plaintext_out
}

pub fn hash(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha384::new();
    hasher.input(&data);
    let mut hash = vec![0; hasher.output_bytes()];
    hasher.result(&mut hash);
    hash
}

pub fn hash_s(data: &[u8]) -> String {
    let mut hasher = Sha384::new();
    hasher.input(&data);
    hasher.result_str()
}
// we use xchacha20 so as to use a 192 bit nonce
// otherwise our nonces may collide after sufficient file uploads
pub fn generate_nonce() -> Vec<u8> {
    let mut nonce = vec![0u8; 24]; // FIXME lol
    nonce
}
