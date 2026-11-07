//! Resolución y emisión de sesiones. Es el punto donde se materializa la
//! diferencia A01/A07 entre los dos modos.

use axum::http::{header, HeaderMap};
use chrono::{Duration, Utc};
use sqlx::Row;

use crate::auth;
use crate::state::{AppState, Mode};

#[derive(Clone, Debug)]
pub struct SessionUser {
    pub id: i64,
    pub username: String,
    pub role: String,
}

impl SessionUser {
    pub fn is_admin(&self) -> bool {
        self.role == "admin"
    }
}

pub fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    raw.split(';').filter_map(|part| {
        let (key, value) = part.trim().split_once('=')?;
        if key == name {
            Some(value.trim().to_string())
        } else {
            None
        }
    })
    .next()
}

pub async fn current_user(state: &AppState, headers: &HeaderMap) -> Option<SessionUser> {
    let raw = cookie_value(headers, auth::COOKIE_NAME)?;

    match state.cfg.mode {
        // DEFECTO A01/A07: la cookie es texto plano sin firmar, así que el
        // cliente decide su propio usuario y su propio rol.
        // Ver attacks/05-session-forgery.sh
        Mode::Vulnerable => {
            let (username, role) = raw.split_once(':')?;
            let id: Option<i64> = sqlx::query_scalar("SELECT id FROM users WHERE username = $1")
                .bind(username)
                .fetch_optional(&state.pool)
                .await
                .ok()?;
            Some(SessionUser {
                id: id?,
                username: username.to_string(),
                role: role.to_string(),
            })
        }
        // Sesión con estado en el servidor, identificador opaco y firma HMAC:
        // el cliente no puede inventar ni editar su rol.
        Mode::Hardened => {
            let sid = auth::verify_session(&state.cfg.session_secret, &raw)?;
            let row = sqlx::query(
                "SELECT u.id, u.username, u.role
                   FROM sessions s
                   JOIN users u ON u.username = s.username
                  WHERE s.sid = $1 AND s.expires_at > now()",
            )
            .bind(&sid)
            .fetch_optional(&state.pool)
            .await
            .ok()??;

            Some(SessionUser {
                id: row.try_get("id").ok()?,
                username: row.try_get("username").ok()?,
                role: row.try_get("role").ok()?,
            })
        }
    }
}

pub async fn create_session(state: &AppState, user: &SessionUser) -> anyhow::Result<String> {
    match state.cfg.mode {
        Mode::Vulnerable => Ok(format!("{}:{}", user.username, user.role)),
        Mode::Hardened => {
            let sid = auth::random_hex(32);
            let expires_at = Utc::now() + Duration::hours(8);
            sqlx::query("INSERT INTO sessions (sid, username, expires_at) VALUES ($1, $2, $3)")
                .bind(&sid)
                .bind(&user.username)
                .bind(expires_at)
                .execute(&state.pool)
                .await?;
            Ok(auth::sign_session(&state.cfg.session_secret, &sid))
        }
    }
}

pub async fn destroy_session(state: &AppState, headers: &HeaderMap) {
    if !state.cfg.mode.is_hardened() {
        return;
    }
    if let Some(raw) = cookie_value(headers, auth::COOKIE_NAME) {
        if let Some(sid) = auth::verify_session(&state.cfg.session_secret, &raw) {
            let _ = sqlx::query("DELETE FROM sessions WHERE sid = $1")
                .bind(sid)
                .execute(&state.pool)
                .await;
        }
    }
}

pub fn session_cookie(state: &AppState, value: &str) -> String {
    if state.cfg.mode.is_hardened() {
        // HttpOnly impide leer la cookie desde JavaScript (mitiga el robo de
        // sesión por XSS); Secure evita que viaje por HTTP; SameSite acota CSRF.
        format!(
            "{}={}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=28800",
            auth::COOKIE_NAME,
            value
        )
    } else {
        // DEFECTO A07: sin HttpOnly, sin Secure, sin SameSite y sin expiración.
        format!("{}={}; Path=/", auth::COOKIE_NAME, value)
    }
}

pub fn clear_cookie(state: &AppState) -> String {
    if state.cfg.mode.is_hardened() {
        format!(
            "{}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0",
            auth::COOKIE_NAME
        )
    } else {
        format!("{}=; Path=/; Max-Age=0", auth::COOKIE_NAME)
    }
}
