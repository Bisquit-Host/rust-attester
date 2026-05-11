use std::{env, net::SocketAddr};
use thiserror::Error;

#[derive(Clone)]
pub struct Config {
    pub team_id: String,
    pub bundle_id: String,
    pub challenge_secret: String,
    pub bearer_key: String,
    pub address: SocketAddr,
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("{0} must be set")]
    Missing(&'static str),
    #[error("Invalid HOST or PORT")]
    InvalidAddress,
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        let team_id = required_env("TEAM_ID")?;
        let bundle_id = required_env("BUNDLE_ID")?;
        let challenge_secret = required_env("CHALLENGE_SECRET")?;
        let bearer_key = required_env("BEARER_KEY")?;

        let host = env::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
        let port = env::var("PORT").unwrap_or_else(|_| "1992".to_string());
        let address = format!("{host}:{port}")
            .parse()
            .map_err(|_| ConfigError::InvalidAddress)?;

        Ok(Self {
            team_id,
            bundle_id,
            challenge_secret,
            bearer_key,
            address,
        })
    }

    pub fn app_id(&self) -> String {
        format!("{}.{}", self.team_id, self.bundle_id)
    }
}

fn required_env(key: &'static str) -> Result<String, ConfigError> {
    match env::var(key) {
        Ok(value) if !value.is_empty() => Ok(value),
        _ => Err(ConfigError::Missing(key)),
    }
}
