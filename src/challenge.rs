use base64::{Engine, engine::general_purpose::STANDARD};
use rand::{RngCore, rngs::OsRng};
use sha2::{Digest, Sha256};

pub fn random_challenge() -> [u8; 32] {
    let mut challenge = [0; 32];
    OsRng.fill_bytes(&mut challenge);
    challenge
}

pub fn challenge_hash(challenge: &[u8]) -> String {
    STANDARD.encode(Sha256::digest(challenge))
}
