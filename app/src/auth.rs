//! Contraseñas, sesiones y TOTP (RFC 6238).
//!
//! Aquí vive la diferencia criptográfica central del trabajo:
//!   v1 -> MD5 sin sal (rompible en segundos, rainbow tables).
//!   v2 -> Argon2id con Parámetros OWASP (19 MiB, t=2, p=1).
//!
//! `verify_password` acepta ambos formatos: eso permite demostrar la migración
//! de hashes sin invalidar las cuentas existentes.

use hmac::{Hmac, Mac};
use rand::RngCore;
use sha1::Sha1;
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::state::{hex_encode, Mode};

pub const COOKIE_NAME: &str = "sid";
const TOTP_STEP_SECONDS: u64 = 30;
const TOTP_DIGITS: u32 = 6;
const B32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

pub fn random_hex(nbytes: usize) -> String {
    let mut buf = vec![0u8; nbytes];
    rand::thread_rng().fill_bytes(&mut buf);
    hex_encode(&buf)
}

fn random_bytes(nbytes: usize) -> Vec<u8> {
    let mut buf = vec![0u8; nbytes];
    rand::thread_rng().fill_bytes(&mut buf);
    buf
}

pub fn md5_hex(value: &str) -> String {
    format!("{:x}", md5::compute(value.as_bytes()))
}

pub fn hash_password(mode: Mode, password: &str) -> anyhow::Result<String> {
    match mode {
        // DEFECTO A02 (criptografia): MD5 sin sal. Ver attacks/06-weak-hash.sh
        Mode::Vulnerable => Ok(md5_hex(password)),
        Mode::Hardened => {
            use argon2::password_hash::{rand_core::OsRng, PasswordHasher, SaltString};
            use argon2::{Algorithm, Argon2, Params, Version};

            let salt = SaltString::generate(&mut OsRng);
            let params = Params::new(19_456, 2, 1, None)
                .map_err(|e| anyhow::anyhow!("parametros argon2 invalidos: {e}"))?;
            let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
            let hash = argon
                .hash_password(password.as_bytes(), &salt)
                .map_err(|e| anyhow::anyhow!("fallo al calcular argon2id: {e}"))?;
            Ok(hash.to_string())
        }
    }
}

pub fn verify_password(stored: &str, password: &str) -> bool {
    if stored.starts_with("$argon2") {
        use argon2::password_hash::{PasswordHash, PasswordVerifier};
        let Ok(parsed) = PasswordHash::new(stored) else {
            return false;
        };
        return argon2::Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok();
    }

    // Hash legado MD5: comparación directa, sin sal ni trabajo computacional.
    md5_hex(password) == stored
}

// ---------------------------------------------------------------- sesiones

pub fn sign_session(secret: &[u8], sid: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("HMAC admite cualquier clave");
    mac.update(sid.as_bytes());
    format!("{}.{}", sid, hex_encode(&mac.finalize().into_bytes()))
}

pub fn verify_session(secret: &[u8], value: &str) -> Option<String> {
    let (sid, signature_hex) = value.split_once('.')?;
    if sid.is_empty() {
        return None;
    }

    let mut mac = Hmac::<Sha256>::new_from_slice(secret).ok()?;
    mac.update(sid.as_bytes());
    let expected = mac.finalize().into_bytes();
    let provided = crate::state::hex_decode(signature_hex).ok()?;

    if provided.len() != expected.len() {
        return None;
    }
    // Comparación en tiempo constante: evita filtrar la firma por temporización.
    if bool::from(expected.as_slice().ct_eq(provided.as_slice())) {
        Some(sid.to_string())
    } else {
        None
    }
}

// -------------------------------------------------------------------- TOTP

pub fn generate_totp_secret() -> String {
    base32_encode(&random_bytes(20))
}

pub fn totp_now(secret_b32: &str) -> Option<u32> {
    let secret = base32_decode(secret_b32).ok()?;
    Some(totp_code(&secret, unix_now() / TOTP_STEP_SECONDS))
}

pub fn verify_totp(secret_b32: &str, code: &str) -> bool {
    let Ok(secret) = base32_decode(secret_b32) else {
        return false;
    };
    let Ok(code) = code.trim().parse::<u32>() else {
        return false;
    };
    let counter = (unix_now() / TOTP_STEP_SECONDS) as i64;

    // Ventana de ±1 paso (30 s) para tolerar desfase de reloj.
    (-1..=1i64).any(|skew| {
        let c = counter + skew;
        c >= 0 && totp_code(&secret, c as u64) == code
    })
}

fn totp_code(secret: &[u8], counter: u64) -> u32 {
    let mut mac = Hmac::<Sha1>::new_from_slice(secret).expect("HMAC admite cualquier clave");
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();

    // Truncamiento dinámico (RFC 4226 sección 5.3).
    let offset = (digest[19] & 0x0f) as usize;
    let binary = ((digest[offset] as u32 & 0x7f) << 24)
        | ((digest[offset + 1] as u32) << 16)
        | ((digest[offset + 2] as u32) << 8)
        | (digest[offset + 3] as u32);

    binary % 10u32.pow(TOTP_DIGITS)
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn base32_encode(data: &[u8]) -> String {
    let mut out = String::new();
    let mut buffer: u64 = 0;
    let mut bits = 0u32;

    for &byte in data {
        buffer = (buffer << 8) | byte as u64;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(B32_ALPHABET[((buffer >> bits) & 0x1f) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(B32_ALPHABET[((buffer << (5 - bits)) & 0x1f) as usize] as char);
    }
    out
}

fn base32_decode(text: &str) -> anyhow::Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut buffer: u64 = 0;
    let mut bits = 0u32;

    for ch in text.chars() {
        if ch == '=' || ch.is_whitespace() {
            continue;
        }
        let upper = ch.to_ascii_uppercase() as u8;
        let value = B32_ALPHABET
            .iter()
            .position(|&a| a == upper)
            .ok_or_else(|| anyhow::anyhow!("caracter base32 invalido"))?
            as u64;

        buffer = (buffer << 5) | value;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xff) as u8);
        }
    }
    Ok(out)
}
