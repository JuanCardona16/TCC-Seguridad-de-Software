use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use sqlx::Row;

use crate::error::AppError;
use crate::session;
use crate::state::{AppState, Mode};
use crate::views;

/// Rol efectivo del solicitante.
///
/// v1: se toma el rol de la cookie (texto plano que el cliente controla).
/// v2: se vuelve a consultar la base de datos, de modo que una cookie manipulada
/// no otorga privilegios.
async fn effective_role(state: &AppState, user: &session::SessionUser) -> Result<String, AppError> {
    match state.cfg.mode {
        Mode::Vulnerable => Ok(user.role.clone()),
        Mode::Hardened => {
            let role: String = sqlx::query_scalar("SELECT role FROM users WHERE id = $1")
                .bind(user.id)
                .fetch_one(&state.pool)
                .await?;
            Ok(role)
        }
    }
}

pub async fn users_page(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(user) = session::current_user(&state, &headers).await else {
        return Ok(Redirect::to("/login").into_response());
    };
    let mode = state.cfg.mode;

    if effective_role(&state, &user).await? != "admin" {
        if mode.is_hardened() {
            crate::db::audit(
                &state.pool,
                Some(&user.username),
                "admin_usuarios",
                None,
                "denegado",
                Some("rol insuficiente"),
            )
            .await;
        }
        return Ok((
            StatusCode::FORBIDDEN,
            views::notice_page(mode, Some(&user), "Acceso denegado", "Esta sección es solo para administradores."),
        )
            .into_response());
    }

    let rows = sqlx::query(
        "SELECT u.username,
                u.role,
                (SELECT COUNT(*) FROM documents d WHERE d.owner_id = u.id) AS docs,
                u.failed_logins
           FROM users u ORDER BY u.id",
    )
    .fetch_all(&state.pool)
    .await?;

    let data: Vec<(String, String, i64, i64)> = rows
        .iter()
        .map(|row| {
            (
                row.get::<String, _>("username"),
                row.get::<String, _>("role"),
                row.get::<i64, _>("docs"),
                row.get::<i32, _>("failed_logins") as i64,
            )
        })
        .collect();

    Ok(views::users_page(mode, &user, &data).into_response())
}

pub async fn audit_page(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(user) = session::current_user(&state, &headers).await else {
        return Ok(Redirect::to("/login").into_response());
    };
    let mode = state.cfg.mode;

    // En v1 no hay auditoría: el propio panel avisa de la carencia (hallazgo A09).
    if !mode.is_hardened() {
        return Ok(views::notice_page(
            mode,
            Some(&user),
            "Auditoría no disponible",
            "El modo vulnerable no registra eventos de seguridad.",
        )
        .into_response());
    }

    if effective_role(&state, &user).await? != "admin" {
        return Ok((
            StatusCode::FORBIDDEN,
            views::notice_page(mode, Some(&user), "Acceso denegado", "Esta sección es solo para administradores."),
        )
            .into_response());
    }

    let rows = sqlx::query(
        "SELECT to_char(ts, 'YYYY-MM-DD HH24:MI:SS') AS ts,
                COALESCE(actor, '-') AS actor,
                action,
                COALESCE(target, '-') AS target,
                outcome
           FROM audit_log ORDER BY ts DESC LIMIT 50",
    )
    .fetch_all(&state.pool)
    .await?;

    let data: Vec<(String, String, String, String, String)> = rows
        .iter()
        .map(|row| {
            (
                row.get::<String, _>("ts"),
                row.get::<String, _>("actor"),
                row.get::<String, _>("action"),
                row.get::<String, _>("target"),
                row.get::<String, _>("outcome"),
            )
        })
        .collect();

    Ok(views::audit_page(mode, &user, &data).into_response())
}
