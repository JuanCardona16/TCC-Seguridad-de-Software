use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::Form;
use chrono::Utc;
use serde::Deserialize;
use sqlx::Row;

use crate::auth;
use crate::db;
use crate::error::AppError;
use crate::session;
use crate::state::{AppState, Mode};
use crate::views;

#[derive(Deserialize)]
pub struct LoginForm {
    #[serde(default)]
    username: String,
    #[serde(default)]
    password: String,
    #[serde(default)]
    code: String,
}

pub async fn login_form(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if session::current_user(&state, &headers).await.is_some() {
        return Redirect::to("/dashboard").into_response();
    }
    views::login_page(state.cfg.mode, None, "").into_response()
}

pub async fn login_submit(
    State(state): State<AppState>,
    Form(form): Form<LoginForm>,
) -> Result<Response, AppError> {
    let mode = state.cfg.mode;
    let username = form.username.trim().to_string();
    let password = form.password;

    if username.is_empty() || password.is_empty() {
        return Ok(views::login_page(mode, Some("Usuario y contraseña son obligatorios"), &username)
            .into_response());
    }

    // Control 1 (solo v2): ventana deslizante de intentos por cuenta en memoria.
    if mode.is_hardened() && !state.limiter.allow(&username.to_ascii_lowercase()) {
        db::audit(
            &state.pool,
            Some(&username),
            "login",
            None,
            "bloqueado",
            Some("limite de intentos por ventana"),
        )
        .await;
        return Ok(too_many_attempts(mode));
    }

    let row = sqlx::query(
        "SELECT id, username, role, password_hash, totp_secret, totp_enabled, failed_logins, locked_until
           FROM users WHERE username = $1",
    )
    .bind(&username)
    .fetch_optional(&state.pool)
    .await?;

    let Some(row) = row else {
        return Ok(login_failure(&state, None, &username, false).await);
    };

    let user_id: i64 = row.try_get("id")?;
    let stored_hash: String = row.try_get("password_hash")?;
    let role: String = row.try_get("role")?;
    let totp_secret: Option<String> = row.try_get("totp_secret")?;
    let totp_enabled: bool = row.try_get("totp_enabled")?;
    let failed_logins: i32 = row.try_get("failed_logins")?;
    let locked_until: Option<chrono::DateTime<Utc>> = row.try_get("locked_until")?;

    // Control 2 (solo v2): bloqueo temporal de la cuenta tras 5 fallos.
    if mode.is_hardened() {
        if let Some(until) = locked_until {
            if until > Utc::now() {
                db::audit(
                    &state.pool,
                    Some(&username),
                    "login",
                    None,
                    "bloqueado",
                    Some("cuenta bloqueada temporalmente"),
                )
                .await;
                return Ok(too_many_attempts(mode));
            }
        }
    }

    if !auth::verify_password(&stored_hash, &password) {
        return Ok(login_failure(&state, Some(user_id), &username, failed_logins >= 4).await);
    }

    // Control 3 (solo v2): segundo factor TOTP cuando la cuenta lo tiene activo.
    if mode.is_hardened() && totp_enabled {
        let secret = totp_secret.as_deref().unwrap_or_default();
        if !auth::verify_totp(secret, &form.code) {
            return Ok(login_failure(&state, Some(user_id), &username, false).await);
        }
    }

    let user = session::SessionUser {
        id: user_id,
        username: row.try_get("username")?,
        role,
    };

    if mode.is_hardened() {
        sqlx::query("UPDATE users SET failed_logins = 0, locked_until = NULL WHERE id = $1")
            .bind(user_id)
            .execute(&state.pool)
            .await?;
        state.limiter.reset(&username.to_ascii_lowercase());
        db::audit(&state.pool, Some(&user.username), "login", None, "ok", None).await;
    }

    let cookie_value = session::create_session(&state, &user).await?;
    let cookie = session::session_cookie(&state, &cookie_value);
    Ok(super::with_cookie(
        Redirect::to("/dashboard").into_response(),
        cookie,
    ))
}

fn too_many_attempts(mode: Mode) -> Response {
    (
        StatusCode::TOO_MANY_REQUESTS,
        views::notice_page(
            mode,
            None,
            "Demasiados intentos",
            "Se superó el límite de intentos de autenticación. Esperá un minuto y volvé a probar.",
        ),
    )
        .into_response()
}

async fn login_failure(
    state: &AppState,
    user_id: Option<i64>,
    username: &str,
    will_lock: bool,
) -> Response {
    let mode = state.cfg.mode;

    if mode.is_hardened() {
        let message = if will_lock {
            "Credenciales inválidas. Por seguridad, la cuenta quedará bloqueada temporalmente."
        } else {
            "Credenciales inválidas."
        };

        if let Some(id) = user_id {
            let lock_sql = if will_lock {
                "UPDATE users SET failed_logins = 0, locked_until = now() + interval '5 minutes' WHERE id = $1"
            } else {
                "UPDATE users SET failed_logins = failed_logins + 1 WHERE id = $1"
            };
            let _ = sqlx::query(lock_sql).bind(id).execute(&state.pool).await;
        }

        let detail = format!("2fa_o_password_invalido={}", !will_lock);
        db::audit(
            &state.pool,
            Some(username),
            "login",
            None,
            "fallido",
            Some(&detail),
        )
        .await;

        // v2 no distingue "usuario inexistente" de "contraseña incorrecta":
        // evita enumeración de cuentas.
        return views::login_page(mode, Some(message), username).into_response();
    }

    // DEFECTO A07: mensajes distintos según exista o no la cuenta
    // (enumeración de usuarios) y sin ningún contador de intentos.
    let message = if user_id.is_some() {
        "La contraseña no coincide con el usuario."
    } else {
        "El usuario no existe en el sistema."
    };
    views::login_page(mode, Some(message), username).into_response()
}

pub async fn logout(State(state): State<AppState>, headers: HeaderMap) -> Response {
    session::destroy_session(&state, &headers).await;
    let cookie = session::clear_cookie(&state);
    super::with_cookie(Redirect::to("/login").into_response(), cookie)
}

pub async fn twofa_page(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let Some(user) = session::current_user(&state, &headers).await else {
        return Redirect::to("/login").into_response();
    };
    let mode = state.cfg.mode;

    if !mode.is_hardened() {
        return views::twofa_page(mode, &user, false, None, None).into_response();
    }

    let row = sqlx::query("SELECT totp_secret, totp_enabled FROM users WHERE id = $1")
        .bind(user.id)
        .fetch_one(&state.pool)
        .await;

    let Ok(row) = row else {
        return views::notice_page(mode, Some(&user), "Error", "No se pudo leer la cuenta.").into_response();
    };

    let secret: Option<String> = row.try_get("totp_secret").ok();
    let enabled: bool = row.try_get("totp_enabled").unwrap_or(false);
    let current_code = secret.as_deref().and_then(auth::totp_now);

    views::twofa_page(mode, &user, enabled, secret.as_deref(), current_code).into_response()
}

pub async fn twofa_toggle(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let Some(user) = session::current_user(&state, &headers).await else {
        return Redirect::to("/login").into_response();
    };
    if !state.cfg.mode.is_hardened() {
        return Redirect::to("/account/2fa").into_response();
    }

    let row = sqlx::query("SELECT totp_secret, totp_enabled FROM users WHERE id = $1")
        .bind(user.id)
        .fetch_one(&state.pool)
        .await;

    let Ok(row) = row else {
        return Redirect::to("/account/2fa").into_response();
    };
    let secret: Option<String> = row.try_get("totp_secret").ok();
    let enabled: bool = row.try_get("totp_enabled").unwrap_or(false);

    let next_secret = secret.unwrap_or_else(auth::generate_totp_secret);
    let next_enabled = !enabled;

    let _ = sqlx::query("UPDATE users SET totp_secret = $1, totp_enabled = $2 WHERE id = $3")
        .bind(&next_secret)
        .bind(next_enabled)
        .bind(user.id)
        .execute(&state.pool)
        .await;

    db::audit(
        &state.pool,
        Some(&user.username),
        "2fa_config",
        Some(&user.username),
        if next_enabled { "activado" } else { "desactivado" },
        None,
    )
    .await;

    Redirect::to("/account/2fa").into_response()
}
