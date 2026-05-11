mod challenge;
mod config;
mod error;
mod models;

use appattest_rs::{assertion::Assertion, attestation::Attestation};
use axum::{
    Router,
    extract::{Json, State},
    http::{HeaderMap, StatusCode, header::AUTHORIZATION},
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use challenge::ChallengeService;
use config::Config;
use error::ApiError;
use models::{AssertRequest, AttestRequest, ChallengeRequest, ChallengeResponse};
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Clone)]
struct AppState {
    config: Config,
    challenge_service: ChallengeService,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let config = Config::from_env()?;
    let address = config.address;
    let state = Arc::new(AppState {
        challenge_service: ChallengeService::new(&config.challenge_secret),
        config,
    });

    let app = Router::new()
        .route("/ping", get(ping))
        .route("/challenge", post(challenge))
        .route("/attest", post(attest))
        .route("/assert", post(assertion))
        .with_state(state);

    let listener = TcpListener::bind(address).await?;
    tracing::info!("listening on {}", listener.local_addr()?);
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

async fn ping() -> &'static str {
    "pong"
}

async fn challenge(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<ChallengeRequest>,
) -> Result<Json<ChallengeResponse>, ApiError> {
    authorize(&headers, &state.config.bearer_key)?;

    let challenge = state
        .challenge_service
        .generate_challenge(body.user_id.as_deref())?;

    Ok(Json(ChallengeResponse {
        challenge: STANDARD.encode(challenge),
    }))
}

async fn attest(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<AttestRequest>,
) -> Result<StatusCode, ApiError> {
    authorize(&headers, &state.config.bearer_key)?;

    let challenge = decode_base64(&body.challenge)?;
    decode_base64(&body.attestation)?;
    decode_base64(&body.key_id)?;

    state.challenge_service.verify_challenge(&challenge)?;

    let attestation = Attestation::from_base64(&body.attestation)
        .map_err(|error| ApiError::AppAttest(error.to_string()))?;
    attestation
        .verify_bytes(&challenge, &state.config.app_id(), &body.key_id)
        .map_err(|error| ApiError::AppAttest(error.to_string()))?;

    Ok(StatusCode::NO_CONTENT)
}

async fn assertion(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<AssertRequest>,
) -> Result<StatusCode, ApiError> {
    authorize(&headers, &state.config.bearer_key)?;

    let challenge = decode_base64(&body.challenge)?;
    let client_data = decode_base64(&body.client_data)?;
    let public_key = decode_base64(&body.public_key)?;

    state.challenge_service.verify_challenge(&challenge)?;

    let assertion = Assertion::from_base64(&body.assertion)
        .map_err(|error| ApiError::AppAttest(error.to_string()))?;
    assertion
        .verify_bytes(
            client_data,
            &state.config.app_id(),
            public_key,
            None,
            &challenge,
            &challenge,
        )
        .map_err(|error| ApiError::AppAttest(error.to_string()))?;

    Ok(StatusCode::NO_CONTENT)
}

fn authorize(headers: &HeaderMap, bearer_key: &str) -> Result<(), ApiError> {
    let Some(value) = headers.get(AUTHORIZATION) else {
        return Err(ApiError::MissingBearer);
    };

    let value = value.to_str().map_err(|_| ApiError::InvalidBearer)?;
    let Some(token) = value.strip_prefix("Bearer ") else {
        return Err(ApiError::MissingBearer);
    };

    if token != bearer_key {
        return Err(ApiError::InvalidBearer);
    }

    Ok(())
}

fn decode_base64(value: &str) -> Result<Vec<u8>, ApiError> {
    STANDARD.decode(value).map_err(|_| ApiError::InvalidBase64)
}
