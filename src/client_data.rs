use base64::{Engine, engine::general_purpose::STANDARD};
use serde::Deserialize;

use crate::error::ApiError;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AssertionClientData {
    pub challenge: String,
    pub action: String,
    pub payload_hash: String,
}

impl AssertionClientData {
    pub fn validate(bytes: &[u8], challenge: &[u8]) -> Result<Self, ApiError> {
        let data: Self = serde_json::from_slice(bytes).map_err(|_| {
            ApiError::BadRequest(
                "Client data must be JSON containing challenge, action and payloadHash",
            )
        })?;
        let signed_challenge = STANDARD
            .decode(&data.challenge)
            .map_err(|_| ApiError::BadRequest("Client data challenge must be base64"))?;
        if signed_challenge != challenge {
            return Err(ApiError::BadRequest(
                "Client data must contain the assertion challenge",
            ));
        }
        if data.action.trim().is_empty() {
            return Err(ApiError::BadRequest("Client data action is required"));
        }
        if STANDARD
            .decode(&data.payload_hash)
            .map(|hash| hash.len())
            .ok()
            != Some(32)
        {
            return Err(ApiError::BadRequest(
                "Client data payload hash must be a SHA-256 base64 digest",
            ));
        }
        Ok(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn valid_data() -> serde_json::Value {
        json!({ "challenge": STANDARD.encode(b"issued"), "action": "login", "payloadHash": STANDARD.encode([0; 32]) })
    }

    #[test]
    fn accepts_valid_client_data() {
        let data =
            AssertionClientData::validate(&serde_json::to_vec(&valid_data()).unwrap(), b"issued")
                .unwrap();
        assert_eq!(data.action, "login");
    }

    #[test]
    fn rejects_different_challenge() {
        assert!(
            AssertionClientData::validate(
                &serde_json::to_vec(&valid_data()).unwrap(),
                b"different"
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_missing_fields_blank_action_and_invalid_hashes() {
        assert!(AssertionClientData::validate(b"not-json", b"issued").is_err());
        for field in ["challenge", "action", "payloadHash"] {
            let mut data = valid_data();
            data.as_object_mut().unwrap().remove(field);
            assert!(
                AssertionClientData::validate(&serde_json::to_vec(&data).unwrap(), b"issued")
                    .is_err()
            );
        }
        for (field, value) in [
            ("action", ""),
            ("action", "  "),
            ("payloadHash", "invalid-base64"),
            ("payloadHash", "YQ=="),
            ("challenge", "invalid-base64"),
        ] {
            let mut data = valid_data();
            data[field] = value.into();
            assert!(
                AssertionClientData::validate(&serde_json::to_vec(&data).unwrap(), b"issued")
                    .is_err()
            );
        }
    }
}
