use std::time::Duration;

use sqlx::PgPool;

use crate::auth;
use crate::crypto;
use crate::state::{Config, Mode};

pub async fn connect(url: &str) -> anyhow::Result<PgPool> {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(5)
        .acquire_timeout(Duration::from_secs(20))
        .connect(url)
        .await?;
    Ok(pool)
}

pub async fn migrate(pool: &PgPool) -> anyhow::Result<()> {
    sqlx::raw_sql(include_str!("../migrations/001_init.sql"))
        .execute(pool)
        .await?;
    Ok(())
}

/// Registro de auditoría: obligatorio en el modo endurecido (A09).
pub async fn audit(
    pool: &PgPool,
    actor: Option<&str>,
    action: &str,
    target: Option<&str>,
    outcome: &str,
    detail: Option<&str>,
) {
    let result = sqlx::query(
        "INSERT INTO audit_log (actor, action, target, outcome, detail) VALUES ($1,$2,$3,$4,$5)",
    )
    .bind(actor)
    .bind(action)
    .bind(target)
    .bind(outcome)
    .bind(detail)
    .execute(pool)
    .await;

    if let Err(err) = result {
        tracing::warn!("no se pudo escribir en audit_log: {err}");
    }
}

struct SeedUser {
    username: &'static str,
    password: &'static str,
    role: &'static str,
}

struct SeedDoc {
    owner: &'static str,
    title: &'static str,
    filename: &'static str,
    mime: &'static str,
    classification: &'static str,
    content: &'static str,
}

const SEED_USERS: [SeedUser; 3] = [
    SeedUser { username: "admin", password: "admin123", role: "admin" },
    SeedUser { username: "alice", password: "alice123", role: "user" },
    SeedUser { username: "bob", password: "bob123", role: "user" },
];

const SEED_DOCS: [SeedDoc; 3] = [
    SeedDoc {
        owner: "alice",
        title: "Contrato confidencial - Cliente Andes",
        filename: "contrato-andes.txt",
        mime: "text/plain",
        classification: "confidencial",
        content: "CONTRATO CONFIDENCIAL\nCliente: Andes S.A.S.\nValor: 480.000.000 COP\n\
                  Clave de retiro de garantia: ANDES-9981\n\
                  Este documento solo debe verlo el area juridica.\n",
    },
    SeedDoc {
        owner: "bob",
        title: "Historia clinica - Paciente 001",
        filename: "historia-001.txt",
        mime: "text/plain",
        classification: "sensible",
        content: "HISTORIA CLINICA 001\nPaciente: dato personal simulado\n\
                  Diagnostico: informacion sensible de demostracion\n\
                  Documento de laboratorio: no contiene datos reales.\n",
    },
    SeedDoc {
        owner: "admin",
        title: "Politica de seguridad de la informacion v3",
        filename: "politica-seguridad.txt",
        mime: "text/plain",
        classification: "publico",
        content: "POLITICA DE SEGURIDAD DE LA INFORMACION v3\n\
                  Documento de referencia del sistema de gestion.\n",
    },
];

pub async fn seed(pool: &PgPool, cfg: &Config) -> anyhow::Result<()> {
    let existing: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(pool)
        .await?;
    if existing > 0 {
        return Ok(());
    }

    tracing::info!(
        "sembrando datos demo en modo {} (hash de contrasenas: {})",
        cfg.mode.label(),
        if cfg.mode.is_hardened() { "Argon2id" } else { "MD5" }
    );

    for user in SEED_USERS.iter() {
        let hash = auth::hash_password(cfg.mode, user.password)?;
        sqlx::query("INSERT INTO users (username, password_hash, role) VALUES ($1,$2,$3)")
            .bind(user.username)
            .bind(hash)
            .bind(user.role)
            .execute(pool)
            .await?;
        tracing::info!("usuario demo: {} / {}", user.username, user.password);
    }

    std::fs::create_dir_all(&cfg.docs_dir)?;

    for doc in SEED_DOCS.iter() {
        let owner_id: i64 = sqlx::query_scalar("SELECT id FROM users WHERE username = $1")
            .bind(doc.owner)
            .fetch_one(pool)
            .await?;

        let storage_ref = match cfg.mode {
            Mode::Vulnerable => {
                // DEFECTO A02: documento en claro y con nombre predecible.
                let path = std::path::Path::new(&cfg.docs_dir).join(doc.filename);
                std::fs::write(path, doc.content.as_bytes())?;
                doc.filename.to_string()
            }
            Mode::Hardened => {
                // Identificador opaco + contenido cifrado con AES-256-GCM.
                let reference = format!("{}.enc", uuid::Uuid::new_v4());
                let sealed = crypto::seal(&cfg.docs_key, doc.content.as_bytes())?;
                std::fs::write(std::path::Path::new(&cfg.docs_dir).join(&reference), sealed)?;
                reference
            }
        };

        sqlx::query(
            "INSERT INTO documents (owner_id, title, filename, mime, size_bytes, storage_ref, classification)
             VALUES ($1,$2,$3,$4,$5,$6,$7)",
        )
        .bind(owner_id)
        .bind(doc.title)
        .bind(doc.filename)
        .bind(doc.mime)
        .bind(doc.content.len() as i64)
        .bind(storage_ref)
        .bind(doc.classification)
        .execute(pool)
        .await?;
    }

    Ok(())
}
