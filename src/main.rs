use axum::routing::get;
use axum::Router;
use nix_relay::auth::AuthValidator;
use nix_relay::config::Config;
use nix_relay::relay::{relay_handler, RelayState};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::signal;
use tokio::sync::Semaphore;
use tracing::{error, info};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "nix_relay=info".parse().unwrap()),
        )
        .init();

    let config_path = std::env::args()
        .nth(1)
        .or_else(|| std::env::var("NIX_RELAY_CONFIG").ok())
        .map(PathBuf::from);

    let config = match Config::load(config_path) {
        Ok(c) => c,
        Err(e) => {
            error!(error = %e, "failed to load config");
            std::process::exit(1);
        }
    };

    if config.auth.allowed_org.is_empty() {
        error!("auth.allowed_org must be set (via config or NIX_RELAY_ALLOWED_ORG)");
        std::process::exit(1);
    }

    info!(listen = %config.server.listen, org = %config.auth.allowed_org, "starting nix-relay");

    let auth = match AuthValidator::new(config.auth.clone()).await {
        Ok(a) => a,
        Err(e) => {
            error!(error = %e, "failed to initialize auth validator");
            std::process::exit(1);
        }
    };

    let state = Arc::new(RelayState {
        auth,
        daemon_config: config.daemon.clone(),
        connection_semaphore: Arc::new(Semaphore::new(config.daemon.max_connections as usize)),
    });

    let app = Router::new()
        .route("/relay", get(relay_handler))
        .with_state(state);

    let listener = match TcpListener::bind(&config.server.listen).await {
        Ok(l) => l,
        Err(e) => {
            error!(addr = %config.server.listen, error = %e, "failed to bind");
            std::process::exit(1);
        }
    };

    info!(addr = %config.server.listen, "listening");

    let grace = std::time::Duration::from_secs(config.server.shutdown_grace_secs);
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .unwrap();

    info!(grace_secs = grace.as_secs(), "shutting down gracefully");
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => info!("received Ctrl+C"),
        _ = terminate => info!("received SIGTERM"),
    }
}
