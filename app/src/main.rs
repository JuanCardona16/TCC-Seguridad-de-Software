mod auth;
mod crypto;
mod db;
mod error;
mod routes;
mod security;
mod session;
mod state;
mod views;

use state::{AppState, Mode};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cfg = state::Config::from_env()?;

    if cfg.mode == Mode::Vulnerable {
        tracing::warn!("=========================================================");
        tracing::warn!(" MiniGestor en MODO VULNERABLE: defectos intencionales.");
        tracing::warn!(" Solo laboratorio local en 127.0.0.1. Uso academico.");
        tracing::warn!("=========================================================");
    }

    let pool = db::connect(&cfg.database_url).await?;
    db::migrate(&pool).await?;
    db::seed(&pool, &cfg).await?;

    let state = AppState {
        pool,
        cfg: cfg.clone(),
        limiter: std::sync::Arc::new(security::LoginLimiter::new()),
    };
    let app = routes::router(state);

    let addr: std::net::SocketAddr = cfg.bind.parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(modo = cfg.mode.label(), %addr, "minigestor escuchando");
    axum::serve(listener, app).await?;
    Ok(())
}
