use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ChallengePurpose {
    #[default]
    Attestation,
    Assertion,
}

impl ChallengePurpose {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Attestation => "attestation",
            Self::Assertion => "assertion",
        }
    }
}

#[derive(Deserialize)]
pub struct ChallengeRequest {
    #[serde(rename = "userID")]
    pub user_id: Option<String>,
    #[serde(default)]
    pub purpose: ChallengePurpose,
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

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttestResponse {
    pub success: bool,
    pub user_id: Option<String>,
    pub key_id: String,
    pub public_key: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssertRequest {
    pub challenge: String,
    pub assertion: String,
    #[serde(rename = "keyID")]
    pub key_id: String,
    #[serde(rename = "clientData")]
    pub client_data: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AssertResponse {
    pub success: bool,
    pub user_id: Option<String>,
    pub counter: u32,
    pub action: String,
    pub payload_hash: String,
}
