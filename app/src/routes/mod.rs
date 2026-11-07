pub mod admin_routes;
pub mod auth_routes;
pub mod docs_routes;

use axum::extract::State;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::middleware;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::json;

use crate::security;
use crate::session;
use crate::state::{hex_encode, AppState, Mode};

pub fn router(state: AppState) -> Router {
    let mut app = Router::new()
        .route("/healthz", get(healthz))
        .route("/", get(index))
        .route(
            "/login",
            get(auth_routes::login_form).post(auth_routes::login_submit),
        )
        .route("/logout", post(auth_routes::logout))
        .route(
            "/account/2fa",
            get(auth_routes::twofa_page).post(auth_routes::twofa_toggle),
        )
        .route("/dashboard", get(docs_routes::dashboard))
        .route("/search", get(docs_routes::search))
        .route(
            "/docs",
            get(docs_routes::upload_form).post(docs_routes::upload_submit),
        )
        .route("/docs/{id}", get(docs_routes::doc_view))
        .route("/docs/{id}/download", get(docs_routes::doc_download))
        .route("/admin/users", get(admin_routes::users_page))
        .route("/admin/audit", get(admin_routes::audit_page));

    // El endpoint de depuración solo existe en v1: expone secretos sin pedir
    // autenticación (hallazgo A05 del informe).
    if state.cfg.mode == Mode::Vulnerable {
        app = app.route("/debug/config", get(debug_config));
    }

    if state.cfg.mode.is_hardened() {
        app = app.layer(middleware::from_fn_with_state(
            state.clone(),
            security::hardening_headers,
        ));
    }

    app.with_state(state)
}

pub fn with_cookie(response: Response, cookie: String) -> Response {
    let mut response = response;
    if let Ok(value) = HeaderValue::from_str(&cookie) {
        response.headers_mut().insert(header::SET_COOKIE, value);
    }
    response
}

async fn healthz(State(state): State<AppState>) -> Response {
    match sqlx::query("SELECT 1").execute(&state.pool).await {
        Ok(_) => (StatusCode::OK, "ok").into_response(),
        Err(err) => {
            tracing::error!("healthz: base de datos no disponible: {err}");
            (StatusCode::SERVICE_UNAVAILABLE, "db").into_response()
        }
    }
}

async fn index(State(state): State<AppState>, headers: HeaderMap) -> Response {
    match session::current_user(&state, &headers).await {
        Some(_) => Redirect::to("/dashboard").into_response(),
        None => Redirect::to("/login").into_response(),
    }
}

/// DEFECTO A05 (solo v1): configuración y secretos expuestos sin autenticación.
async fn debug_config(State(state): State<AppState>) -> Response {
    Json(json!({
        "mode": state.cfg.mode.label(),
        "database_url": state.cfg.database_url,
        "docs_dir": state.cfg.docs_dir,
        "docs_master_key": hex_encode(&state.cfg.docs_key),
        "session_secret": String::from_utf8_lossy(&state.cfg.session_secret),
        "advertencia": "endpoint de depuracion expuesto: hallazgo de laboratorio"
    }))
    .into_response()
}
