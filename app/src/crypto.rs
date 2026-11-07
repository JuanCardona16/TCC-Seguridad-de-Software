//! Cifrado de documentos en reposo (AES-256-GCM) para el modo endurecido.
//!
//! Formato del archivo cifrado: `[nonce 12 bytes][ciphertext + tag GCM]`.
//! El nonce se genera al azar por documento, que es la condición para que
//! reutilizar la misma clave maestra sea seguro en GCM.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use rand::RngCore;

const NONCE_LEN: usize = 12;

pub fn seal(key: &[u8; 32], plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);

    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), plaintext)
        .map_err(|_| anyhow::anyhow!("fallo al cifrar el documento"))?;

    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

pub fn open(key: &[u8; 32], data: &[u8]) -> anyhow::Result<Vec<u8>> {
    anyhow::ensure!(data.len() > NONCE_LEN, "documento cifrado truncado");
    let (nonce_bytes, ciphertext) = data.split_at(NONCE_LEN);

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher
        .decrypt(Nonce::from_slice(nonce_bytes), ciphertext)
        .map_err(|_| anyhow::anyhow!("fallo al descifrar: dato alterado o clave incorrecta"))
}
