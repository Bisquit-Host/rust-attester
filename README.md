# Rust Attester

App Attest service built with Rust, Axum and PostgreSQL

## Required Environment Props

- `TEAM_ID`
- `BUNDLE_ID`
- `DATABASE_HOST` PostgreSQL hostname
- `DATABASE_USERNAME` PostgreSQL username
- `DATABASE_PASSWORD` PostgreSQL password
- `DATABASE_NAME` PostgreSQL database name
- `BEARER_KEY` requires `Authorization: Bearer <key>` on protected routes

## Optional Environment Props

- `DATABASE_PORT` defaults to `5432`, must be an integer between `1` and `65535`
- `HOST` defaults to `0.0.0.0`
- `PORT` defaults to `1993`
- `CHALLENGE_TTL_SECONDS` defaults to `300`, must be a positive integer
- `APP_ATTEST_ENVIRONMENT` optional environment metadata stored with enrolled keys

Database credentials are passed directly to the PostgreSQL driver and do not need URL encoding
`DATABASE_URL` is no longer used by the service

Migrations run automatically before the HTTP listener starts and require permission to create tables
The service uses `rust_app_attest_challenges` and `rust_app_attest_keys`, separate from the Swift service's tables
Environment metadata is recorded for auditing and does not change the verifier's accepted environments

## Security behavior

- Challenges are random 32-byte values stored as SHA-256 digests with expiry, user identifier and purpose
- PostgreSQL atomically consumes each challenge once, including across restarts and multiple service instances
- Attestation enrolls the verified public key and receipt under a canonical Base64 key ID
- Assertions use the enrolled active key and a persisted, atomically increasing counter
- The signed client data must contain the issued challenge, a nonblank action and a Base64 SHA-256 payload digest
- When both the challenge and key have a user identifier, those identifiers must match
- Re-enrollment preserves counters and rejects revoked keys or conflicting owners and public keys
- Invalid proofs return `400 Bad Request`, authentication failures return `401 Unauthorized`, database and worker failures return `500 Internal Server Error`

Challenges consumed during verification remain consumed if later verification fails
Request a new challenge before retrying
The backend must keep `BEARER_KEY` private and supply trustworthy user identifiers

## Routes

`GET /ping` and `GET /health` return `pong`

`POST /challenge` creates a single-use challenge

```json
{
  "userID": "optional-user-id",
  "purpose": "attestation"
}
```

`purpose` can be `attestation` or `assertion` and defaults to `attestation` when omitted
The response is `{ "challenge": "base64" }`

`POST /attest` consumes an attestation challenge, verifies the attestation, stores the key and receipt, and returns `200 OK`

```json
{
  "challenge": "base64",
  "attestation": "base64",
  "keyID": "base64"
}
```

```json
{
  "success": true,
  "userID": "optional-user-id",
  "keyID": "base64",
  "publicKey": "base64-x963"
}
```

`POST /assert` consumes an assertion challenge, verifies the proof using the stored key, advances its counter and returns `200 OK`

```json
{
  "challenge": "base64",
  "assertion": "base64",
  "keyID": "base64",
  "clientData": "base64-json"
}
```

The exact decoded `clientData` bytes must have been signed by App Attest and contain this JSON

```json
{
  "challenge": "base64",
  "action": "login",
  "payloadHash": "base64-sha256"
}
```

```json
{
  "success": true,
  "userID": "optional-user-id",
  "counter": 1,
  "action": "login",
  "payloadHash": "base64-sha256"
}
```

The calling backend must compare the returned `action` and `payloadHash` against the intended operation and SHA-256 digest of the request payload before accepting the request
The attester validates the signed claims and digest format; it does not receive the operation's actual payload

## Migration from the stateless service

- Set `DATABASE_HOST`, `DATABASE_PORT`, `DATABASE_USERNAME`, `DATABASE_PASSWORD` and `DATABASE_NAME`, and keep the database durable across deployments
- `CHALLENGE_SECRET` is no longer used
- Existing stateless challenges are invalid and must be replaced
- Existing devices must enroll their keys through `/attest` before using `/assert`
- Request challenges with `purpose: "assertion"` for assertions
- Replace caller-supplied `publicKey` with `keyID` in assertion requests
- Include `challenge`, `action` and `payloadHash` in signed client data
- Handle JSON verification responses instead of `204 No Content`

Multiple active keys per user are allowed for multiple devices, reinstalls and restored devices
Key revocation is managed through the database; there is no public revocation route
Expired and consumed challenge records can be pruned with a scheduled database maintenance job

## Build and run

```bash
cargo build --locked
```

```bash
TEAM_ID=... \
BUNDLE_ID=... \
DATABASE_HOST=localhost \
DATABASE_PORT=5432 \
DATABASE_USERNAME=attester \
DATABASE_PASSWORD=... \
DATABASE_NAME=attester \
BEARER_KEY=... \
cargo run --locked
```

The Docker build includes the migrations and embeds them in the service binary

## Test

```bash
cargo test --locked
CARGO_TARGET_DIR=target/vendor-tests cargo test --manifest-path vendor/appattest-rs/Cargo.toml --locked --lib
```

The PostgreSQL integration test creates and removes an isolated schema in the supplied disposable database
It covers expiry, challenge purposes, concurrent consumption, persistence after reconnecting, stored key lookup, valid signed assertions, replay rejection, concurrent counter updates, user ownership and revoked keys

```bash
TEST_DATABASE_URL=postgres://localhost/attester_test cargo test --locked postgres_security_and_assertion_flow -- --ignored
```
