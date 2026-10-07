use sqlx::postgres::PgConnectOptions;
use std::{env, net::SocketAddr};
use thiserror::Error;

#[derive(Clone)]
pub struct Config {
    pub team_id: String,
    pub bundle_id: String,
    pub database_options: PgConnectOptions,
    pub bearer_key: String,
    pub challenge_ttl_seconds: u32,
    pub environment: Option<String>,
    pub address: SocketAddr,
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("{0} must be set")]
    Missing(&'static str),
    #[error("DATABASE_PORT must be an integer between 1 and 65535")]
    InvalidDatabasePort,
    #[error("Invalid HOST or PORT")]
    InvalidAddress,
    #[error("CHALLENGE_TTL_SECONDS must be a positive integer")]
    InvalidChallengeLifetime,
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        let team_id = required_env("TEAM_ID")?;
        let bundle_id = required_env("BUNDLE_ID")?;
        let database_host = required_env("DATABASE_HOST")?;
        let database_port = env::var("DATABASE_PORT")
            .unwrap_or_else(|_| "5432".to_string())
            .parse::<u16>()
            .ok()
            .filter(|port| *port > 0)
            .ok_or(ConfigError::InvalidDatabasePort)?;
        let database_username = required_env("DATABASE_USERNAME")?;
        let database_password = required_env("DATABASE_PASSWORD")?;
        let database_name = required_env("DATABASE_NAME")?;
        let database_options = PgConnectOptions::new()
            .host(&database_host)
            .port(database_port)
            .username(&database_username)
            .password(&database_password)
            .database(&database_name);
        let bearer_key = required_env("BEARER_KEY")?;
        let challenge_ttl_seconds = parse_challenge_ttl(
            &env::var("CHALLENGE_TTL_SECONDS").unwrap_or_else(|_| "300".to_string()),
        )?;
        let environment = env::var("APP_ATTEST_ENVIRONMENT")
            .ok()
            .filter(|value| !value.is_empty());
        let host = env::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
        let port = env::var("PORT").unwrap_or_else(|_| "1993".to_string());
        let address = format!("{host}:{port}")
            .parse()
            .map_err(|_| ConfigError::InvalidAddress)?;
        Ok(Self {
            team_id,
            bundle_id,
            database_options,
            bearer_key,
            challenge_ttl_seconds,
            environment,
            address,
        })
    }

    pub fn app_id(&self) -> String {
        format!("{}.{}", self.team_id, self.bundle_id)
    }
}

fn parse_challenge_ttl(value: &str) -> Result<u32, ConfigError> {
    value
        .parse::<u32>()
        .ok()
        .filter(|ttl| *ttl > 0)
        .ok_or(ConfigError::InvalidChallengeLifetime)
}

fn required_env(key: &'static str) -> Result<String, ConfigError> {
    match env::var(key) {
        Ok(value) if !value.is_empty() => Ok(value),
        _ => Err(ConfigError::Missing(key)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_challenge_lifetime() {
        assert_eq!(parse_challenge_ttl("300").unwrap(), 300);
        for value in ["0", "-1", "NaN", "1.5", "4294967296"] {
            assert!(parse_challenge_ttl(value).is_err());
        }
    }
}
