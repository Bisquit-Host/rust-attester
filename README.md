# Rust Attester

App Attest service built with Rust and Axum

## Required Environment Props

- `TEAM_ID`
- `BUNDLE_ID`
- `CHALLENGE_SECRET`
- `BEARER_KEY` requires `Authorization: Bearer <key>` on protected routes

## Optional Environment Props

- `HOST` defaults to `0.0.0.0`
- `PORT` defaults to `1993`

## Routes

- `GET /ping` returns `pong`
- `GET /health` returns `pong`
- `POST /challenge` returns a Base64 challenge
- `POST /attest` verifies App Attest attestation and returns `204 No Content`
- `POST /assert` verifies App Attest assertion and returns `204 No Content`

## Build

```bash
cargo build
```

## Run

```bash
TEAM_ID=... \
BUNDLE_ID=... \
CHALLENGE_SECRET=... \
BEARER_KEY=... \
cargo run
```

## Test

```bash
cargo test
```
