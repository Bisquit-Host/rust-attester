#![allow(deprecated)]

use aes_gcm::{
    Aes256Gcm,
    aead::{Aead, AeadCore, KeyInit, OsRng},
};
use sha2::{Digest, Sha256};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;

const NONCE_LENGTH: usize = 12;
const TIMESTAMP_LENGTH: usize = 8;
const USER_ID_LENGTH_LENGTH: usize = 2;
const MIN_PAYLOAD_LENGTH: usize = NONCE_LENGTH + TIMESTAMP_LENGTH + USER_ID_LENGTH_LENGTH;

#[derive(Clone)]
pub struct ChallengeService {
    key: [u8; 32],
    max_age: Duration,
}

#[derive(Debug, Error)]
pub enum ChallengeError {
    #[error("Challenge expired")]
    Expired,
    #[error("Invalid challenge payload")]
    InvalidPayload,
    #[error("System clock is before UNIX epoch")]
    InvalidClock,
}

#[derive(Debug, Eq, PartialEq)]
pub struct VerifiedChallenge {
    pub nonce: Vec<u8>,
    pub user_id: Option<String>,
}

impl ChallengeService {
    pub fn new(secret_key: &str) -> Self {
        Self::with_max_age(secret_key, Duration::from_secs(300))
    }

    pub fn with_max_age(secret_key: &str, max_age: Duration) -> Self {
        let key = Sha256::digest(secret_key.as_bytes()).into();
        Self { key, max_age }
    }

    pub fn generate_challenge(&self, user_id: Option<&str>) -> Result<Vec<u8>, ChallengeError> {
        let payload = self.payload(user_id, now_timestamp()?)?;
        let cipher = Aes256Gcm::new(&self.key.into());
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = cipher
            .encrypt(&nonce, payload.as_slice())
            .map_err(|_| ChallengeError::InvalidPayload)?;

        let mut combined = Vec::with_capacity(nonce.len() + ciphertext.len());
        combined.extend_from_slice(&nonce);
        combined.extend_from_slice(&ciphertext);
        Ok(combined)
    }

    pub fn verify_challenge(&self, challenge: &[u8]) -> Result<VerifiedChallenge, ChallengeError> {
        if challenge.len() < NONCE_LENGTH {
            return Err(ChallengeError::InvalidPayload);
        }

        let cipher = Aes256Gcm::new(&self.key.into());
        let nonce = aes_gcm::Nonce::from_slice(&challenge[..NONCE_LENGTH]);
        let payload = cipher
            .decrypt(nonce, &challenge[NONCE_LENGTH..])
            .map_err(|_| ChallengeError::InvalidPayload)?;

        self.verify_payload(&payload, now_timestamp()?)
    }

    fn payload(&self, user_id: Option<&str>, timestamp: u64) -> Result<Vec<u8>, ChallengeError> {
        let user_id = user_id.unwrap_or_default().as_bytes();
        let user_id_length =
            u16::try_from(user_id.len()).map_err(|_| ChallengeError::InvalidPayload)?;
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

        let mut payload = Vec::with_capacity(MIN_PAYLOAD_LENGTH + user_id.len());
        payload.extend_from_slice(&nonce);
        payload.extend_from_slice(&timestamp.to_ne_bytes());
        payload.extend_from_slice(&user_id_length.to_ne_bytes());
        payload.extend_from_slice(user_id);
        Ok(payload)
    }

    fn verify_payload(
        &self,
        payload: &[u8],
        now: u64,
    ) -> Result<VerifiedChallenge, ChallengeError> {
        if payload.len() < MIN_PAYLOAD_LENGTH {
            return Err(ChallengeError::InvalidPayload);
        }

        let nonce = payload[..NONCE_LENGTH].to_vec();
        let timestamp = u64::from_ne_bytes(
            payload[NONCE_LENGTH..NONCE_LENGTH + TIMESTAMP_LENGTH]
                .try_into()
                .map_err(|_| ChallengeError::InvalidPayload)?,
        );
        let user_id_length = u16::from_ne_bytes(
            payload[NONCE_LENGTH + TIMESTAMP_LENGTH..MIN_PAYLOAD_LENGTH]
                .try_into()
                .map_err(|_| ChallengeError::InvalidPayload)?,
        ) as usize;

        let age = now.saturating_sub(timestamp);
        if age >= self.max_age.as_secs() {
            return Err(ChallengeError::Expired);
        }

        if payload.len() < MIN_PAYLOAD_LENGTH + user_id_length {
            return Err(ChallengeError::InvalidPayload);
        }

        let user_id = if user_id_length > 0 {
            let data = &payload[MIN_PAYLOAD_LENGTH..MIN_PAYLOAD_LENGTH + user_id_length];
            Some(String::from_utf8(data.to_vec()).map_err(|_| ChallengeError::InvalidPayload)?)
        } else {
            None
        };

        Ok(VerifiedChallenge { nonce, user_id })
    }
}

fn now_timestamp() -> Result<u64, ChallengeError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| ChallengeError::InvalidClock)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_without_user_id() {
        let service = ChallengeService::new("secret");

        let challenge = service.generate_challenge(None).unwrap();
        let verified = service.verify_challenge(&challenge).unwrap();

        assert_eq!(verified.nonce.len(), NONCE_LENGTH);
        assert_eq!(verified.user_id, None);
    }

    #[test]
    fn round_trips_with_user_id() {
        let service = ChallengeService::new("secret");

        let challenge = service.generate_challenge(Some("user-1")).unwrap();
        let verified = service.verify_challenge(&challenge).unwrap();

        assert_eq!(verified.nonce.len(), NONCE_LENGTH);
        assert_eq!(verified.user_id, Some("user-1".to_string()));
    }

    #[test]
    fn rejects_wrong_secret() {
        let service = ChallengeService::new("secret");
        let other = ChallengeService::new("different");

        let challenge = service.generate_challenge(None).unwrap();

        assert!(matches!(
            other.verify_challenge(&challenge),
            Err(ChallengeError::InvalidPayload)
        ));
    }
}
