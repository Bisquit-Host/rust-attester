use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct ChallengeRequest {
    #[serde(rename = "userID")]
    pub user_id: Option<String>,
}

#[derive(Serialize)]
pub struct ChallengeResponse {
    pub challenge: String,
}

#[derive(Deserialize)]
pub struct AttestRequest {
    pub challenge: String,
    pub attestation: String,
    #[serde(rename = "keyID")]
    pub key_id: String,
}

#[derive(Deserialize)]
pub struct AssertRequest {
    pub challenge: String,
    pub assertion: String,
    #[serde(rename = "publicKey")]
    pub public_key: String,
    #[serde(rename = "clientData")]
    pub client_data: String,
}
