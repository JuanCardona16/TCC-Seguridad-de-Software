use std::sync::Arc;

use sqlx::PgPool;

use crate::security::LoginLimiter;

/// Modo de operación del mismo binario. Un solo código, dos políticas de
/// seguridad: así el "antes/después" del TCC compara decisiones de diseño y no
/// dos proyectos distintos.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    /// v1: defectos deliberados, material de auditoría.
    Vulnerable,
    /// v2: controles aplicados.
    Hardened,
}

impl Mode {
    pub fn is_hardened(self) -> bool {
        matches!(self, Mode::Hardened)
    }

    pub fn label(self) -> &'static str {
        match self {
            Mode::Vulnerable => "vulnerable",
            Mode::Hardened => "endurecido",
        }
    }
}

#[derive(Clone)]
pub struct Config {
    pub mode: Mode,
    pub bind: String,
    pub database_url: String,
    pub docs_dir: String,
    pub docs_key: [u8; 32],
    pub session_secret: Vec<u8>,
    pub public_base_url: String,
}

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub cfg: Config,
    pub limiter: Arc<LoginLimiter>,
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key)
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| default.to_string())
}

pub fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{:02x}", byte));
    }
    out
}

pub fn hex_decode(text: &str) -> anyhow::Result<Vec<u8>> {
    let trimmed = text.trim();
    anyhow::ensure!(trimmed.len() % 2 == 0, "cadena hex con longitud impar");
    let raw = trimmed.as_bytes();
    let mut out = Vec::with_capacity(raw.len() / 2);
    let mut i = 0;
    while i < raw.len() {
        let hi = hex_val(raw[i])?;
        let lo = hex_val(raw[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

fn hex_val(byte: u8) -> anyhow::Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => anyhow::bail!("caracter hex invalido"),
    }
}

const LAB_MASTER_KEY: &str =
    "8f2b6d1c4a9e7f305b8c2d6a1e9f4b7c3d5a8e2f6b1c9d4a7e3f5b8c2d6a1e9f";

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        let mode = match env_or("MODE", "vulnerable").to_ascii_lowercase().as_str() {
            "hardened" | "endurecido" | "hard" | "v2" => Mode::Hardened,
            _ => Mode::Vulnerable,
        };

        let key_hex = env_or("DOCS_MASTER_KEY", LAB_MASTER_KEY);
        let key_bytes = hex_decode(&key_hex)?;
        anyhow::ensure!(
            key_bytes.len() == 32,
            "DOCS_MASTER_KEY debe ser de 32 bytes (64 caracteres hex)"
        );
        let mut docs_key = [0u8; 32];
        docs_key.copy_from_slice(&key_bytes);

        Ok(Self {
            mode,
            bind: env_or("BIND", "0.0.0.0:8080"),
            database_url: env_or(
                "DATABASE_URL",
                "postgres://lab:lab@localhost:5432/minigestor_vuln",
            ),
            docs_dir: env_or("DOCS_DIR", "/data/docs"),
            docs_key,
            session_secret: env_or("SESSION_SECRET", "dev-secret-laboratorio").into_bytes(),
            public_base_url: env_or("PUBLIC_BASE_URL", "http://127.0.0.1:8080"),
        })
    }
}
