use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("missing Authorization header")]
    MissingAuth,

    #[error("invalid Authorization header format")]
    InvalidAuthFormat,

    #[error("OIDC discovery failed: {0}")]
    OidcDiscovery(#[from] reqwest::Error),

    #[error("JWKS error: {0}")]
    Jwks(String),

    #[error("JWT validation failed: {0}")]
    JwtValidation(#[from] jsonwebtoken::errors::Error),

    #[error("unauthorized: {0}")]
    Unauthorized(String),

    #[error("too many connections")]
    TooManyConnections,

    #[error("daemon spawn failed: {0}")]
    DaemonSpawn(#[source] std::io::Error),

    #[error("config error: {0}")]
    Config(String),
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let status = match &self {
            Error::MissingAuth | Error::InvalidAuthFormat => StatusCode::UNAUTHORIZED,
            Error::JwtValidation(_) | Error::Unauthorized(_) => StatusCode::FORBIDDEN,
            Error::TooManyConnections => StatusCode::SERVICE_UNAVAILABLE,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        (status, self.to_string()).into_response()
    }
}
