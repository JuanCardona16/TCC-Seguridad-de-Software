use std::path::{Path, PathBuf};

use axum::extract::{Multipart, Path as UrlPath, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use serde::Deserialize;
use sqlx::postgres::PgRow;
use sqlx::Row;

use crate::crypto;
use crate::db;
use crate::error::AppError;
use crate::session::{self, SessionUser};
use crate::state::{AppState, Mode};
use crate::views;

const MAX_UPLOAD_BYTES: usize = 5 * 1024 * 1024;
const ALLOWED_EXTENSIONS: [&str; 4] = ["txt", "pdf", "png", "jpg"];

#[derive(Deserialize)]
pub struct SearchQuery {
    #[serde(default)]
    q: String,
}

fn row_to_doc(row: &PgRow) -> Result<views::DocRow, sqlx::Error> {
    Ok(views::DocRow {
        id: row.try_get("id")?,
        title: row.try_get("title")?,
        filename: row.try_get("filename")?,
        owner: row.try_get("owner")?,
        classification: row.try_get("classification")?,
        size_bytes: row.try_get("size_bytes")?,
    })
}

async fn require_user(state: &AppState, headers: &HeaderMap) -> Option<SessionUser> {
    session::current_user(state, headers).await
}

pub async fn dashboard(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(user) = require_user(&state, &headers).await else {
        return Ok(Redirect::to("/login").into_response());
    };
    let mode = state.cfg.mode;
    let show_owner = mode.is_hardened() && user.is_admin();

    let rows: Vec<PgRow> = if show_owner {
        sqlx::query(
            "SELECT d.id, d.title, d.filename, d.classification, d.size_bytes, u.username AS owner
               FROM documents d JOIN users u ON u.id = d.owner_id
              ORDER BY d.id",
        )
        .fetch_all(&state.pool)
        .await?
    } else {
        sqlx::query(
            "SELECT d.id, d.title, d.filename, d.classification, d.size_bytes, u.username AS owner
               FROM documents d JOIN users u ON u.id = d.owner_id
              WHERE d.owner_id = $1
              ORDER BY d.id",
        )
        .bind(user.id)
        .fetch_all(&state.pool)
        .await?
    };

    let docs = rows
        .iter()
        .map(row_to_doc)
        .collect::<Result<Vec<_>, _>>()?;

    Ok(views::dashboard_page(mode, &user, &docs, show_owner).into_response())
}

pub async fn search(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<SearchQuery>,
) -> Result<Response, AppError> {
    let Some(user) = require_user(&state, &headers).await else {
        return Ok(Redirect::to("/login").into_response());
    };
    let mode = state.cfg.mode;
    let term = query.q;

    let rows: Vec<PgRow> = match mode {
        // DEFECTO A03: el término se concatena dentro del SQL. Con
        // `' OR '1'='1` se listan documentos de todos los usuarios.
        // Ver attacks/01-sqli-search.sh
        Mode::Vulnerable => {
            // Sentencia en una sola línea a propósito: el `--` del payload
            // comenta el resto de la consulta y la inyección resulta explotable.
            let sql = format!(
                "SELECT d.id, d.title, d.filename, d.classification, d.size_bytes, u.username AS owner FROM documents d JOIN users u ON u.id = d.owner_id WHERE d.title LIKE '%{}%' ORDER BY d.id",
                term
            );
            sqlx::query(&sql).fetch_all(&state.pool).await?
        }
        // Consulta parametrizada + escape de salida: la inyección y el XSS
        // reflejado quedan cerrados en el mismo punto.
        Mode::Hardened => {
            let like = format!("%{}%", term);
            sqlx::query(
                "SELECT d.id, d.title, d.filename, d.classification, d.size_bytes, u.username AS owner
                   FROM documents d JOIN users u ON u.id = d.owner_id
                  WHERE d.title ILIKE $1 AND (d.owner_id = $2 OR $3)
                  ORDER BY d.id",
            )
            .bind(like)
            .bind(user.id)
            .bind(user.is_admin())
            .fetch_all(&state.pool)
            .await?
        }
    };

    if mode.is_hardened() {
        db::audit(
            &state.pool,
            Some(&user.username),
            "buscar",
            None,
            "ok",
            Some(&format!("resultados={}", rows.len())),
        )
        .await;
    }

    let docs = rows
        .iter()
        .map(row_to_doc)
        .collect::<Result<Vec<_>, _>>()?;

    Ok(views::search_page(mode, &user, &term, &docs).into_response())
}

pub async fn upload_form(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let Some(user) = require_user(&state, &headers).await else {
        return Redirect::to("/login").into_response();
    };
    views::upload_page(state.cfg.mode, &user, None).into_response()
}

pub async fn upload_submit(
    State(state): State<AppState>,
    headers: HeaderMap,
    mut multipart: Multipart,
) -> Result<Response, AppError> {
    let Some(user) = require_user(&state, &headers).await else {
        return Ok(Redirect::to("/login").into_response());
    };
    let mode = state.cfg.mode;

    let mut title = String::new();
    let mut client_filename = String::new();
    let mut mime = String::from("application/octet-stream");
    let mut data = Vec::new();

    while let Some(field) = multipart.next_field().await? {
        let name = field.name().map(str::to_string);
        match name.as_deref() {
            Some("title") => title = field.text().await?.trim().to_string(),
            Some("file") => {
                client_filename = field.file_name().unwrap_or("documento.bin").to_string();
                if let Some(content_type) = field.content_type().map(str::to_string) {
                    mime = content_type;
                }
                data = field.bytes().await?.to_vec();
            }
            _ => {}
        }
    }

    if title.is_empty() || data.is_empty() {
        return Ok(views::upload_page(
            mode,
            &user,
            Some("El título y el archivo son obligatorios."),
        )
        .into_response());
    }

    // Validación de entrada (solo v2). En v1 no hay ninguna: se acepta
    // cualquier extensión, cualquier tamaño y cualquier nombre.
    if mode.is_hardened() {
        let extension = Path::new(&client_filename)
            .extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| ext.to_ascii_lowercase())
            .unwrap_or_default();

        if !ALLOWED_EXTENSIONS.contains(&extension.as_str()) {
            db::audit(
                &state.pool,
                Some(&user.username),
                "subir",
                Some(&client_filename),
                "rechazado",
                Some("extension no permitida"),
            )
            .await;
            return Ok(views::upload_page(
                mode,
                &user,
                Some("Extensión no permitida. Solo se aceptan: txt, pdf, png, jpg."),
            )
            .into_response());
        }

        if data.len() > MAX_UPLOAD_BYTES {
            db::audit(
                &state.pool,
                Some(&user.username),
                "subir",
                Some(&client_filename),
                "rechazado",
                Some("archivo demasiado grande"),
            )
            .await;
            return Ok(views::upload_page(mode, &user, Some("El archivo supera el límite de 5 MiB."))
                .into_response());
        }
    }

    let storage_ref = match mode {
        // DEFECTO A04/A05: el nombre lo controla el cliente y se usa tal cual
        // como ruta de escritura (path traversal). Ver attacks/07-upload-traversal.sh
        Mode::Vulnerable => {
            let target = Path::new(&state.cfg.docs_dir).join(&client_filename);
            if let Some(parent) = target.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            std::fs::write(&target, &data)?;
            client_filename.clone()
        }
        // Nombre opaco generado por el servidor + contenido cifrado en reposo.
        Mode::Hardened => {
            let reference = format!("{}.enc", uuid::Uuid::new_v4());
            let sealed = crypto::seal(&state.cfg.docs_key, &data)?;
            std::fs::write(Path::new(&state.cfg.docs_dir).join(&reference), sealed)?;
            reference
        }
    };

    // El nombre original se guarda solo como etiqueta de presentación, y solo
    // con caracteres seguros.
    let display_name = if mode.is_hardened() {
        sanitize_filename(&client_filename)
    } else {
        client_filename.clone()
    };

    sqlx::query(
        "INSERT INTO documents (owner_id, title, filename, mime, size_bytes, storage_ref, classification)
         VALUES ($1,$2,$3,$4,$5,$6,$7)",
    )
    .bind(user.id)
    .bind(title.clone())
    .bind(display_name)
    .bind(mime)
    .bind(data.len() as i64)
    .bind(storage_ref)
    .bind("interno")
    .execute(&state.pool)
    .await?;

    if mode.is_hardened() {
        db::audit(
            &state.pool,
            Some(&user.username),
            "subir",
            Some(&title),
            "ok",
            Some(&format!("bytes={}", data.len())),
        )
        .await;
    }

    Ok(Redirect::to("/dashboard").into_response())
}

fn sanitize_filename(name: &str) -> String {
    let base = name
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or("documento")
        .to_string();
    let cleaned: String = base
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' { c } else { '_' })
        .collect();
    if cleaned.is_empty() {
        "documento".to_string()
    } else {
        cleaned
    }
}

fn read_document(state: &AppState, storage_ref: &str) -> anyhow::Result<Vec<u8>> {
    let path: PathBuf = Path::new(&state.cfg.docs_dir).join(storage_ref);
    let raw = std::fs::read(path)?;
    if state.cfg.mode.is_hardened() {
        crypto::open(&state.cfg.docs_key, &raw)
    } else {
        Ok(raw)
    }
}

struct DocRecord {
    id: i64,
    owner_id: i64,
    storage_ref: String,
    mime: String,
    filename: String,
}

async fn load_document(state: &AppState, id: i64) -> Result<Option<DocRecord>, AppError> {
    let row = sqlx::query(
        "SELECT id, owner_id, storage_ref, mime, filename FROM documents WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&state.pool)
    .await?;

    Ok(row.map(|row| DocRecord {
        id: row.get::<i64, _>("id"),
        owner_id: row.get::<i64, _>("owner_id"),
        storage_ref: row.get::<String, _>("storage_ref"),
        mime: row.get::<String, _>("mime"),
        filename: row.get::<String, _>("filename"),
    }))
}

pub async fn doc_view(
    State(state): State<AppState>,
    headers: HeaderMap,
    UrlPath(id): UrlPath<i64>,
) -> Result<Response, AppError> {
    let Some(user) = require_user(&state, &headers).await else {
        return Ok(Redirect::to("/login").into_response());
    };
    let mode = state.cfg.mode;

    let Some(doc) = load_document(&state, id).await? else {
        return Ok((
            StatusCode::NOT_FOUND,
            views::notice_page(mode, Some(&user), "No encontrado", "El documento no existe."),
        )
            .into_response());
    };

    // DEFECTO A01: en v1 no se verifica la propiedad del documento.
    // Cualquier usuario autenticado lee cualquier id. Ver attacks/03-idor.sh
    if mode.is_hardened() && doc.owner_id != user.id && !user.is_admin() {
        db::audit(
            &state.pool,
            Some(&user.username),
            "leer",
            Some(&format!("doc:{}", doc.id)),
            "denegado",
            Some("propietario distinto"),
        )
        .await;
        return Ok((
            StatusCode::FORBIDDEN,
            views::notice_page(
                mode,
                Some(&user),
                "Acceso denegado",
                "No tenés permiso para ver este documento.",
            ),
        )
            .into_response());
    }

    let content = match read_document(&state, &doc.storage_ref) {
        Ok(bytes) => String::from_utf8_lossy(&bytes).chars().take(2000).collect::<String>(),
        Err(err) => format!("[no se pudo leer el contenido: {err}]"),
    };

    let row = sqlx::query(
        "SELECT d.id, d.title, d.filename, d.classification, d.size_bytes, u.username AS owner
           FROM documents d JOIN users u ON u.id = d.owner_id WHERE d.id = $1",
    )
    .bind(id)
    .fetch_one(&state.pool)
    .await?;
    let doc_row = row_to_doc(&row)?;

    if mode.is_hardened() {
        db::audit(
            &state.pool,
            Some(&user.username),
            "leer",
            Some(&format!("doc:{}", doc.id)),
            "ok",
            None,
        )
        .await;
    }

    Ok(views::doc_page(mode, &user, &doc_row, &content).into_response())
}

pub async fn doc_download(
    State(state): State<AppState>,
    headers: HeaderMap,
    UrlPath(id): UrlPath<i64>,
) -> Result<Response, AppError> {
    let Some(user) = require_user(&state, &headers).await else {
        return Ok(Redirect::to("/login").into_response());
    };
    let mode = state.cfg.mode;

    let Some(doc) = load_document(&state, id).await? else {
        return Ok((StatusCode::NOT_FOUND, "no encontrado").into_response());
    };

    if mode.is_hardened() && doc.owner_id != user.id && !user.is_admin() {
        db::audit(
            &state.pool,
            Some(&user.username),
            "descargar",
            Some(&format!("doc:{}", doc.id)),
            "denegado",
            Some("propietario distinto"),
        )
        .await;
        return Ok((StatusCode::FORBIDDEN, "acceso denegado").into_response());
    }

    let bytes = read_document(&state, &doc.storage_ref)?;

    if mode.is_hardened() {
        db::audit(
            &state.pool,
            Some(&user.username),
            "descargar",
            Some(&format!("doc:{}", doc.id)),
            "ok",
            Some(&format!("bytes={}", bytes.len())),
        )
        .await;
    }

    let safe_name: String = doc
        .filename
        .chars()
        .filter(|c| !c.is_control() && *c != '"')
        .collect();

    let mut response = (StatusCode::OK, bytes).into_response();
    let headers_mut = response.headers_mut();
    headers_mut.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(&doc.mime).unwrap_or(HeaderValue::from_static("application/octet-stream")),
    );
    headers_mut.insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&format!("attachment; filename=\"{}\"", safe_name))
            .unwrap_or(HeaderValue::from_static("attachment")),
    );
    headers_mut.insert(
        header::HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    Ok(response)
}
