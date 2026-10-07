use sqlx::{
    PgPool,
    postgres::{PgConnectOptions, PgPoolOptions},
};

use crate::{
    challenge::{challenge_hash, random_challenge},
    error::ApiError,
    models::ChallengePurpose,
};

#[derive(Clone)]
pub struct AppAttestStore {
    pool: PgPool,
    challenge_ttl_seconds: u32,
}

#[derive(Debug, sqlx::FromRow)]
pub struct ConsumedChallenge {
    pub user_id: Option<String>,
}

#[derive(Debug, sqlx::FromRow)]
pub struct StoredKey {
    pub user_id: Option<String>,
    pub public_key: Vec<u8>,
    pub last_counter: i64,
}

impl AppAttestStore {
    pub async fn connect(
        options: PgConnectOptions,
        challenge_ttl_seconds: u32,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let pool = PgPoolOptions::new()
            .max_connections(10)
            .connect_with(options)
            .await?;
        sqlx::migrate!().run(&pool).await?;
        Ok(Self {
            pool,
            challenge_ttl_seconds,
        })
    }

    pub async fn create_challenge(
        &self,
        user_id: Option<&str>,
        purpose: ChallengePurpose,
    ) -> Result<[u8; 32], ApiError> {
        let challenge = random_challenge();
        sqlx::query(
            r#"
            INSERT INTO rust_app_attest_challenges (challenge_hash, user_id, purpose, expires_at)
            VALUES ($1, $2, $3, clock_timestamp() + $4::bigint * INTERVAL '1 second')
        "#,
        )
        .bind(challenge_hash(&challenge))
        .bind(user_id.filter(|value| !value.is_empty()))
        .bind(purpose.as_str())
        .bind(i64::from(self.challenge_ttl_seconds))
        .execute(&self.pool)
        .await?;
        Ok(challenge)
    }

    pub async fn consume_challenge(
        &self,
        challenge: &[u8],
        purpose: ChallengePurpose,
    ) -> Result<ConsumedChallenge, ApiError> {
        sqlx::query_as::<_, ConsumedChallenge>(
            r#"
            UPDATE rust_app_attest_challenges SET consumed_at = clock_timestamp()
            WHERE challenge_hash = $1 AND purpose = $2
                AND consumed_at IS NULL AND expires_at > clock_timestamp()
            RETURNING user_id
        "#,
        )
        .bind(challenge_hash(challenge))
        .bind(purpose.as_str())
        .fetch_optional(&self.pool)
        .await?
        .ok_or(ApiError::BadRequest(
            "Challenge is missing, expired, already consumed, or not valid for this request",
        ))
    }

    pub async fn save_attestation(
        &self,
        key_id: &str,
        user_id: Option<&str>,
        public_key: &[u8],
        receipt: &[u8],
        app_id: &str,
        environment: Option<&str>,
    ) -> Result<(), ApiError> {
        // Re-enrollment preserves counters and never reactivates a revoked key
        let result = sqlx::query(r#"
            INSERT INTO rust_app_attest_keys (key_id, user_id, public_key, receipt, app_id, environment)
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (key_id) DO UPDATE SET
                user_id = COALESCE(rust_app_attest_keys.user_id, EXCLUDED.user_id),
                receipt = EXCLUDED.receipt, environment = EXCLUDED.environment,
                updated_at = clock_timestamp()
            WHERE rust_app_attest_keys.status = 'active'
                AND rust_app_attest_keys.app_id = EXCLUDED.app_id
                AND rust_app_attest_keys.public_key = EXCLUDED.public_key
                AND (rust_app_attest_keys.user_id IS NULL OR EXCLUDED.user_id IS NULL
                    OR rust_app_attest_keys.user_id = EXCLUDED.user_id)
        "#)
            .bind(key_id).bind(user_id.filter(|value| !value.is_empty())).bind(public_key).bind(receipt).bind(app_id).bind(environment)
            .execute(&self.pool).await?;
        if result.rows_affected() != 1 {
            return Err(ApiError::BadRequest(
                "Key enrollment conflicts with an existing or revoked key",
            ));
        }
        Ok(())
    }

    pub async fn active_key(&self, key_id: &str, app_id: &str) -> Result<StoredKey, ApiError> {
        sqlx::query_as::<_, StoredKey>(
            r#"
            SELECT user_id, public_key, last_counter FROM rust_app_attest_keys
            WHERE key_id = $1 AND app_id = $2 AND status = 'active'
        "#,
        )
        .bind(key_id)
        .bind(app_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(ApiError::BadRequest(
            "Attested key is not registered or active",
        ))
    }

    pub async fn advance_counter(
        &self,
        key_id: &str,
        app_id: &str,
        counter: u32,
    ) -> Result<(), ApiError> {
        let result = sqlx::query(
            r#"
            UPDATE rust_app_attest_keys SET last_counter = $3,
                last_seen_at = clock_timestamp(), updated_at = clock_timestamp()
            WHERE key_id = $1 AND app_id = $2 AND status = 'active' AND last_counter < $3
        "#,
        )
        .bind(key_id)
        .bind(app_id)
        .bind(i64::from(counter))
        .execute(&self.pool)
        .await?;
        if result.rows_affected() != 1 {
            return Err(ApiError::BadRequest(
                "Assertion counter did not increase or key is no longer active",
            ));
        }
        Ok(())
    }

    #[cfg(test)]
    pub async fn test_store(url: &str, schema: &str) -> Self {
        use std::str::FromStr;
        let options = sqlx::postgres::PgConnectOptions::from_str(url)
            .unwrap()
            .options([("search_path", schema)]);
        let pool = PgPoolOptions::new()
            .max_connections(10)
            .connect_with(options)
            .await
            .unwrap();
        sqlx::migrate!().run(&pool).await.unwrap();
        Self {
            pool,
            challenge_ttl_seconds: 300,
        }
    }

    #[cfg(test)]
    pub fn test_pool(&self) -> &PgPool {
        &self.pool
    }
}
