use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ApiError {
    #[error("Missing bearer token")]
    MissingBearer,
    #[error("Invalid bearer token")]
    InvalidBearer,
    #[error("Invalid base64 encoding")]
    InvalidBase64,
    #[error("{0}")]
    BadRequest(&'static str),
    #[error("App Attest verification failed: {0}")]
    AppAttest(String),
    #[error("Database operation failed")]
    Database(#[from] sqlx::Error),
    #[error("Verification worker failed")]
    Worker(#[from] tokio::task::JoinError),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = match &self {
            Self::MissingBearer | Self::InvalidBearer => StatusCode::UNAUTHORIZED,
            Self::InvalidBase64 | Self::BadRequest(_) | Self::AppAttest(_) => {
                StatusCode::BAD_REQUEST
            }
            Self::Database(error) => {
                tracing::error!(%error, "Database operation failed");
                StatusCode::INTERNAL_SERVER_ERROR
            }
            Self::Worker(error) => {
                tracing::error!(%error, "Verification worker failed");
                StatusCode::INTERNAL_SERVER_ERROR
            }
        };
        (status, self.to_string()).into_response()
    }
}
