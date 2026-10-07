use super::*;
use axum::{http::StatusCode, response::IntoResponse};
use p256::ecdsa::{Signature, SigningKey, signature::Signer};
use serde_json::json;
use sha2::{Digest, Sha256};

fn bearer_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(AUTHORIZATION, "Bearer test-key".parse().unwrap());
    headers
}

fn assertion_body(key: &SigningKey, challenge: &[u8], counter: u32) -> AssertRequest {
    let client_data = serde_json::to_vec(&json!({
        "challenge": STANDARD.encode(challenge), "action": "login", "payloadHash": STANDARD.encode(Sha256::digest(b"request-body"))
    })).unwrap();
    let mut auth_data = Sha256::digest(b"team.app").to_vec();
    auth_data.push(0);
    auth_data.extend(counter.to_be_bytes());
    let mut nonce = auth_data.clone();
    nonce.extend(Sha256::digest(&client_data));
    let signature: Signature = key.sign(&Sha256::digest(nonce));
    let object = ciborium::value::Value::Map(vec![
        (
            "authenticatorData".into(),
            ciborium::value::Value::Bytes(auth_data),
        ),
        (
            "signature".into(),
            ciborium::value::Value::Bytes(signature.to_der().as_bytes().to_vec()),
        ),
    ]);
    let mut cbor = Vec::new();
    ciborium::ser::into_writer(&object, &mut cbor).unwrap();
    AssertRequest {
        challenge: STANDARD.encode(challenge),
        assertion: STANDARD.encode(cbor),
        key_id: STANDARD.encode(Sha256::digest(
            key.verifying_key().to_encoded_point(false).as_bytes(),
        )),
        client_data: STANDARD.encode(client_data),
    }
}

#[test]
fn rejects_legacy_public_key_requests_and_invalid_key_ids() {
    assert!(
        serde_json::from_value::<AssertRequest>(json!({
            "challenge": "", "assertion": "", "publicKey": "", "clientData": ""
        }))
        .is_err()
    );
    assert!(canonical_key_id("YQ==").is_err());
    assert!(canonical_key_id("not-base64").is_err());
    assert_eq!(
        canonical_key_id(&STANDARD.encode([1; 32])).unwrap(),
        STANDARD.encode([1; 32])
    );
}

#[test]
fn authorization_and_error_responses() {
    assert!(authorize(&bearer_headers(), "test-key").is_ok());
    assert!(authorize(&HeaderMap::new(), "test-key").is_err());
    assert!(authorize(&bearer_headers(), "other-key").is_err());
    assert_eq!(
        ApiError::AppAttest("Invalid signature".into())
            .into_response()
            .status(),
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL pointing to a disposable PostgreSQL database"]
async fn postgres_security_and_assertion_flow() {
    let url = std::env::var("TEST_DATABASE_URL").expect("Set TEST_DATABASE_URL");
    let admin = sqlx::PgPool::connect(&url).await.unwrap();
    let schema = format!("attester_test_{}", rand::random::<u64>());
    sqlx::query(&format!("CREATE SCHEMA {schema}"))
        .execute(&admin)
        .await
        .unwrap();
    let store = AppAttestStore::test_store(&url, &schema).await;

    // Wrong purpose does not consume the challenge; consumption survives reconnects
    let c = store
        .create_challenge(Some("user-1"), ChallengePurpose::Attestation)
        .await
        .unwrap();
    assert!(
        store
            .consume_challenge(&c, ChallengePurpose::Assertion)
            .await
            .is_err()
    );
    assert_eq!(
        store
            .consume_challenge(&c, ChallengePurpose::Attestation)
            .await
            .unwrap()
            .user_id
            .as_deref(),
        Some("user-1")
    );
    let restarted = AppAttestStore::test_store(&url, &schema).await;
    assert!(
        restarted
            .consume_challenge(&c, ChallengePurpose::Attestation)
            .await
            .is_err()
    );
    assert!(
        store
            .consume_challenge(b"unknown", ChallengePurpose::Assertion)
            .await
            .is_err()
    );

    let expired = store
        .create_challenge(None, ChallengePurpose::Assertion)
        .await
        .unwrap();
    sqlx::query("UPDATE rust_app_attest_challenges SET expires_at = clock_timestamp() - INTERVAL '1 second' WHERE challenge_hash = $1")
        .bind(challenge::challenge_hash(&expired)).execute(store.test_pool()).await.unwrap();
    assert!(
        store
            .consume_challenge(&expired, ChallengePurpose::Assertion)
            .await
            .is_err()
    );

    let c = store
        .create_challenge(None, ChallengePurpose::Assertion)
        .await
        .unwrap();
    let (first, second) = tokio::join!(
        store.consume_challenge(&c, ChallengePurpose::Assertion),
        restarted.consume_challenge(&c, ChallengePurpose::Assertion)
    );
    assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);

    let key = SigningKey::from_bytes((&[1u8; 32]).into()).unwrap();
    let public_key = key.verifying_key().to_encoded_point(false);
    let key_id = STANDARD.encode(Sha256::digest(public_key.as_bytes()));
    store
        .save_attestation(
            &key_id,
            Some("user-1"),
            public_key.as_bytes(),
            b"receipt",
            "team.app",
            None,
        )
        .await
        .unwrap();
    assert!(store.active_key(&key_id, "wrong.app").await.is_err());
    assert!(store.active_key("unknown", "team.app").await.is_err());

    let state = Arc::new(AppState {
        config: Config {
            team_id: "team".into(),
            bundle_id: "app".into(),
            database_options: url.parse().unwrap(),
            bearer_key: "test-key".into(),
            challenge_ttl_seconds: 300,
            environment: None,
            address: "127.0.0.1:0".parse().unwrap(),
        },
        store: store.clone(),
    });
    let enrollment = challenge(
        State(state.clone()),
        bearer_headers(),
        Json(ChallengeRequest {
            user_id: None,
            purpose: ChallengePurpose::Attestation,
        }),
    )
    .await
    .unwrap()
    .0;
    let enrollment_bytes = decode_base64(&enrollment.challenge).unwrap();
    assert!(
        attest(
            State(state.clone()),
            bearer_headers(),
            Json(AttestRequest {
                challenge: enrollment.challenge,
                attestation: STANDARD.encode(b"invalid-cbor"),
                key_id: key_id.clone()
            })
        )
        .await
        .is_err()
    );
    assert!(
        store
            .consume_challenge(&enrollment_bytes, ChallengePurpose::Attestation)
            .await
            .is_err()
    );

    let auth_challenge = store
        .create_challenge(None, ChallengePurpose::Assertion)
        .await
        .unwrap();
    assert!(
        assertion(
            State(state.clone()),
            HeaderMap::new(),
            Json(assertion_body(&key, &auth_challenge, 1))
        )
        .await
        .is_err()
    );
    assert!(
        store
            .consume_challenge(&auth_challenge, ChallengePurpose::Assertion)
            .await
            .is_ok()
    );

    let c = store
        .create_challenge(Some("user-1"), ChallengePurpose::Assertion)
        .await
        .unwrap();
    let response = assertion(
        State(state.clone()),
        bearer_headers(),
        Json(assertion_body(&key, &c, 1)),
    )
    .await
    .unwrap()
    .0;
    assert!(response.success);
    assert_eq!(response.user_id.as_deref(), Some("user-1"));
    assert_eq!(response.counter, 1);
    assert_eq!(response.action, "login");
    assert_eq!(
        response.payload_hash,
        STANDARD.encode(Sha256::digest(b"request-body"))
    );
    assert!(
        assertion(
            State(state.clone()),
            bearer_headers(),
            Json(assertion_body(&key, &c, 1))
        )
        .await
        .is_err()
    );

    // A fresh challenge cannot make an old counter or old signed challenge acceptable
    let fresh = store
        .create_challenge(None, ChallengePurpose::Assertion)
        .await
        .unwrap();
    assert!(
        assertion(
            State(state.clone()),
            bearer_headers(),
            Json(assertion_body(&key, &fresh, 1))
        )
        .await
        .is_err()
    );
    let fresh = store
        .create_challenge(None, ChallengePurpose::Assertion)
        .await
        .unwrap();
    let mut replay = assertion_body(&key, &c, 2);
    replay.challenge = STANDARD.encode(fresh);
    assert!(
        assertion(State(state.clone()), bearer_headers(), Json(replay))
            .await
            .is_err()
    );
    let other_user = store
        .create_challenge(Some("user-2"), ChallengePurpose::Assertion)
        .await
        .unwrap();
    assert!(
        assertion(
            State(state.clone()),
            bearer_headers(),
            Json(assertion_body(&key, &other_user, 2))
        )
        .await
        .is_err()
    );
    let impostor = SigningKey::from_bytes((&[2u8; 32]).into()).unwrap();
    let fresh = store
        .create_challenge(None, ChallengePurpose::Assertion)
        .await
        .unwrap();
    let mut forged = assertion_body(&impostor, &fresh, 2);
    forged.key_id = key_id.clone();
    assert!(
        assertion(State(state.clone()), bearer_headers(), Json(forged))
            .await
            .is_err()
    );

    let first = store
        .create_challenge(None, ChallengePurpose::Assertion)
        .await
        .unwrap();
    let second = store
        .create_challenge(None, ChallengePurpose::Assertion)
        .await
        .unwrap();
    let (a, b) = tokio::join!(
        assertion(
            State(state.clone()),
            bearer_headers(),
            Json(assertion_body(&key, &first, 2))
        ),
        assertion(
            State(state.clone()),
            bearer_headers(),
            Json(assertion_body(&key, &second, 2))
        )
    );
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    assert_eq!(
        restarted
            .active_key(&key_id, "team.app")
            .await
            .unwrap()
            .last_counter,
        2
    );

    store
        .save_attestation(
            &key_id,
            Some("user-1"),
            public_key.as_bytes(),
            b"new-receipt",
            "team.app",
            None,
        )
        .await
        .unwrap();
    assert_eq!(
        store
            .active_key(&key_id, "team.app")
            .await
            .unwrap()
            .last_counter,
        2
    );
    assert!(
        store
            .save_attestation(
                &key_id,
                Some("user-2"),
                public_key.as_bytes(),
                b"receipt",
                "team.app",
                None
            )
            .await
            .is_err()
    );
    sqlx::query("UPDATE rust_app_attest_keys SET status = 'revoked' WHERE key_id = $1")
        .bind(&key_id)
        .execute(store.test_pool())
        .await
        .unwrap();
    assert!(store.active_key(&key_id, "team.app").await.is_err());
    assert!(store.advance_counter(&key_id, "team.app", 3).await.is_err());
    assert!(
        store
            .save_attestation(
                &key_id,
                Some("user-1"),
                public_key.as_bytes(),
                b"receipt",
                "team.app",
                None
            )
            .await
            .is_err()
    );

    store.test_pool().close().await;
    restarted.test_pool().close().await;
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&admin)
        .await
        .unwrap();
    admin.close().await;
}
