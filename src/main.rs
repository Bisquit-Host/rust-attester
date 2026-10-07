mod challenge;
mod client_data;
mod config;
mod error;
mod models;
mod store;

use appattest_rs::{assertion::Assertion, attestation::Attestation};
use axum::{
    Router,
    extract::{Json, State},
    http::{HeaderMap, header::AUTHORIZATION},
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use client_data::AssertionClientData;
use config::Config;
use error::ApiError;
use models::{
    AssertRequest, AssertResponse, AttestRequest, AttestResponse, ChallengePurpose,
    ChallengeRequest, ChallengeResponse,
};
use std::sync::Arc;
use store::AppAttestStore;
use tokio::net::TcpListener;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Clone)]
struct AppState {
    config: Config,
    store: AppAttestStore,
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
        store: AppAttestStore::connect(
            config.database_options.clone(),
            config.challenge_ttl_seconds,
        )
        .await?,
        config,
    });

    let app = Router::new()
        .route("/ping", get(ping))
        .route("/health", get(ping))
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
        .store
        .create_challenge(body.user_id.as_deref(), body.purpose)
        .await?;

    Ok(Json(ChallengeResponse {
        challenge: STANDARD.encode(challenge),
    }))
}

async fn attest(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<AttestRequest>,
) -> Result<Json<AttestResponse>, ApiError> {
    authorize(&headers, &state.config.bearer_key)?;
    let challenge = decode_base64(&body.challenge)?;
    decode_base64(&body.attestation)?;
    let key_id = canonical_key_id(&body.key_id)?;
    let consumed = state
        .store
        .consume_challenge(&challenge, ChallengePurpose::Attestation)
        .await?;
    let app_id = state.config.app_id();
    let verification_app_id = app_id.clone();
    let verification_key_id = key_id.clone();
    // The vendored verifier fetches Apple's root certificate synchronously
    let (public_key, receipt) = tokio::task::spawn_blocking(move || {
        let attestation = Attestation::from_base64(&body.attestation)
            .map_err(|error| ApiError::AppAttest(error.to_string()))?;
        attestation
            .verify_bytes(&challenge, &verification_app_id, &verification_key_id)
            .map_err(|error| ApiError::AppAttest(error.to_string()))
    })
    .await??;
    state
        .store
        .save_attestation(
            &key_id,
            consumed.user_id.as_deref(),
            &public_key,
            &receipt,
            &app_id,
            state.config.environment.as_deref(),
        )
        .await?;
    Ok(Json(AttestResponse {
        success: true,
        user_id: consumed.user_id,
        key_id,
        public_key: STANDARD.encode(public_key),
    }))
}

async fn assertion(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<AssertRequest>,
) -> Result<Json<AssertResponse>, ApiError> {
    authorize(&headers, &state.config.bearer_key)?;
    let challenge = decode_base64(&body.challenge)?;
    let client_data = decode_base64(&body.client_data)?;
    let key_id = canonical_key_id(&body.key_id)?;
    let signed_data = AssertionClientData::validate(&client_data, &challenge)?;
    let consumed = state
        .store
        .consume_challenge(&challenge, ChallengePurpose::Assertion)
        .await?;
    let app_id = state.config.app_id();
    let key = state.store.active_key(&key_id, &app_id).await?;
    if let (Some(challenge_user), Some(key_user)) = (&consumed.user_id, &key.user_id)
        && challenge_user != key_user
    {
        return Err(ApiError::BadRequest(
            "Challenge user does not match the attested key owner",
        ));
    }
    let previous_counter = u32::try_from(key.last_counter)
        .map_err(|_| ApiError::BadRequest("Stored assertion counter is invalid"))?;
    let verification_app_id = app_id.clone();
    let counter = tokio::task::spawn_blocking(move || {
        let assertion = Assertion::from_base64(&body.assertion)
            .map_err(|error| ApiError::AppAttest(error.to_string()))?;
        assertion
            .verify_bytes(
                client_data,
                &verification_app_id,
                key.public_key,
                Some(previous_counter),
                &challenge,
                &challenge,
            )
            .map_err(|error| ApiError::AppAttest(error.to_string()))
    })
    .await??;
    state
        .store
        .advance_counter(&key_id, &app_id, counter)
        .await?;
    Ok(Json(AssertResponse {
        success: true,
        user_id: consumed.user_id.or(key.user_id),
        counter,
        action: signed_data.action,
        payload_hash: signed_data.payload_hash,
    }))
}

fn canonical_key_id(value: &str) -> Result<String, ApiError> {
    let bytes = decode_base64(value)?;
    if bytes.len() != 32 {
        return Err(ApiError::BadRequest(
            "Key ID must be a SHA-256 base64 digest",
        ));
    }
    Ok(STANDARD.encode(bytes))
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

#[cfg(test)]
mod tests;
