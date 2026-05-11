use crate::challenge::ChallengeError;
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
    Challenge(#[from] ChallengeError),
    #[error("App Attest verification failed: {0}")]
    AppAttest(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = match self {
            ApiError::MissingBearer | ApiError::InvalidBearer => StatusCode::UNAUTHORIZED,
            ApiError::InvalidBase64 => StatusCode::BAD_REQUEST,
            ApiError::Challenge(ChallengeError::Expired | ChallengeError::InvalidPayload) => {
                StatusCode::BAD_REQUEST
            }
            ApiError::Challenge(ChallengeError::InvalidClock) | ApiError::AppAttest(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        };

        (status, self.to_string()).into_response()
    }
}
