use crypto::{symmetriccipher::{Encryptor, Decryptor}, chacha20::ChaCha20, buffer::{RefReadBuffer, RefWriteBuffer, ReadBuffer, WriteBuffer}};
use std::io::Read;
use crate::fs::File;
use crypto::sha2::Sha384;
use crypto::digest::Digest;

pub fn encrypt_and_hash_file(file : &mut File, key : &Vec<u8>) -> String {
    let mut hasher = Sha384::new();
    let mut plaintext_attr = serde_json::to_string(&file.xattr).unwrap();
    let mut plaintext = file.data.clone();

    let mut buf = plaintext_attr.as_bytes().to_vec().clone();
    let mut ciphertext_attr = encrypt(&mut buf, &key, &generate_nonce());
    let mut ciphertext = encrypt(&mut plaintext, &key, &generate_nonce());
    
    hasher.input(&ciphertext_attr);
    hasher.input(&ciphertext);
    let hash = hasher.result_str();
    hash
}

// FIXME implement
pub fn verify_merkle_hashes() {
    panic!("FIXME");
}

pub fn encrypt(data: &Vec<u8>, key: &Vec<u8>, nonce : &Vec<u8>) -> Vec<u8> {
    
    let mut encryptor = Box::new(ChaCha20::new_xchacha20(&key, &nonce)) as Box<dyn Encryptor>;
    let mut plaintext = RefReadBuffer::new(&data);
    let mut buf = Vec::new();
    let mut encrypted = RefWriteBuffer::new(&mut buf);
    encryptor.encrypt(&mut plaintext, &mut encrypted, false);
    encrypted.take_remaining().to_vec()
}

pub fn decrypt(encrypted: &Vec<u8>, key: &Vec<u8>, nonce: &Vec<u8>) -> Vec<u8> {
    
    let mut decryptor = Box::new(ChaCha20::new_xchacha20(&key, &nonce)) as Box<dyn Decryptor>;
    let mut ciphertext = RefReadBuffer::new(&encrypted);
    let mut buf = Vec::new();
    let mut decrypted = RefWriteBuffer::new(&mut buf);
    decryptor.decrypt(&mut ciphertext, &mut decrypted, true);
    decrypted.take_remaining().to_vec()
}

// we use xchacha20 so as to use a 192 bit nonce
// otherwise our nonces may collide after sufficient file uploads
pub fn generate_nonce() -> Vec<u8> {
    let mut nonce = vec![0u8; 24]; // FIXME lol
    nonce
}
