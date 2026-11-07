use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

/// Envoltorio de errores internos: nunca se filtra el detalle al cliente en el
/// modo endurecido (A09: fallas de registro y monitoreo).
#[derive(Debug)]
pub struct AppError(pub anyhow::Error);

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl<E> From<E> for AppError
where
    E: Into<anyhow::Error>,
{
    fn from(err: E) -> Self {
        Self(err.into())
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        tracing::error!("error interno: {:#}", self.0);
        (StatusCode::INTERNAL_SERVER_ERROR, "error interno del servidor").into_response()
    }
}
