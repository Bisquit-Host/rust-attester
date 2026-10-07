CREATE TABLE rust_app_attest_challenges (
    challenge_hash TEXT PRIMARY KEY,
    user_id TEXT,
    purpose TEXT NOT NULL CHECK (purpose IN ('attestation', 'assertion')),
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX rust_app_attest_challenges_expiry ON rust_app_attest_challenges (expires_at);

CREATE TABLE rust_app_attest_keys (
    key_id TEXT PRIMARY KEY,
    user_id TEXT,
    public_key BYTEA NOT NULL,
    receipt BYTEA NOT NULL,
    app_id TEXT NOT NULL,
    environment TEXT,
    last_counter BIGINT NOT NULL DEFAULT 0 CHECK (last_counter BETWEEN 0 AND 4294967295),
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
    last_seen_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
