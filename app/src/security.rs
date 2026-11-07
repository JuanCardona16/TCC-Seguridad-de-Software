//! Controles transversales del modo endurecido: cabeceras de seguridad y
//! limitador de intentos de autenticación.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use axum::extract::{Request, State};
use axum::http::{header::HeaderName, HeaderValue};
use axum::middleware::Next;
use axum::response::Response;

use crate::state::AppState;

const MAX_LOGIN_ATTEMPTS: usize = 5;
const LOGIN_WINDOW: Duration = Duration::from_secs(60);

pub struct LoginLimiter {
    attempts: Mutex<HashMap<String, VecDeque<Instant>>>,
}

impl LoginLimiter {
    pub fn new() -> Self {
        Self {
            attempts: Mutex::new(HashMap::new()),
        }
    }

    /// Ventana deslizante por clave (usuario o IP). Devuelve `false` cuando se
    /// superó el presupuesto de intentos dentro de la ventana.
    pub fn allow(&self, key: &str) -> bool {
        let now = Instant::now();
        let mut guard = match self.attempts.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let entry = guard.entry(key.to_string()).or_default();

        while entry
            .front()
            .is_some_and(|t| now.duration_since(*t) > LOGIN_WINDOW)
        {
            entry.pop_front();
        }

        if entry.len() >= MAX_LOGIN_ATTEMPTS {
            return false;
        }
        entry.push_back(now);
        true
    }

    pub fn reset(&self, key: &str) {
        if let Ok(mut guard) = self.attempts.lock() {
            guard.remove(key);
        }
    }

    pub fn max_attempts(&self) -> usize {
        MAX_LOGIN_ATTEMPTS
    }
}

impl Default for LoginLimiter {
    fn default() -> Self {
        Self::new()
    }
}

/// Cabeceras de endurecimiento. En v1 simplemente no existe este middleware:
/// esa ausencia es el hallazgo A05 del informe.
pub async fn hardening_headers(
    State(_state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();

    let pairs: [(HeaderName, &str); 6] = [
        (
            HeaderName::from_static("content-security-policy"),
            "default-src 'none'; style-src 'unsafe-inline'; img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
        ),
        (HeaderName::from_static("x-content-type-options"), "nosniff"),
        (HeaderName::from_static("x-frame-options"), "DENY"),
        (HeaderName::from_static("referrer-policy"), "no-referrer"),
        (
            HeaderName::from_static("permissions-policy"),
            "geolocation=(), camera=(), microphone=()",
        ),
        (HeaderName::from_static("cache-control"), "no-store"),
    ];

    for (name, value) in pairs {
        headers.insert(name, HeaderValue::from_static(value));
    }
    response
}
