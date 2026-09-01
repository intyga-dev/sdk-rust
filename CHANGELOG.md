# Changelog

All notable changes to `intyga-sdk` (Rust) are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [SemVer](https://semver.org/).

## [Unreleased]

- Re-export `ApproverTrustAnchor` alongside `Expected` — `Expected.approvers` is a required field
  of that type, so verification was previously unconstructable from this crate's re-exports alone.
- Token refresh: `Client::token` now honours the `expires_in` the gateway returns and re-exchanges
  the client credentials shortly before expiry (`min(60s, expires_in / 10)` ahead of it), and a
  `401` on a token this client exchanged itself is retried exactly once with a fresh exchange.
  Previously the exchanged token was cached for the life of the process, so a client older than
  the token's lifetime — including a `require_approval` wait longer than it — failed permanently
  until restart. An explicit `ClientOptions::token` is unchanged: it is never re-exchanged, and a
  `401` on it is still returned to the caller. A response without `expires_in` keeps the old
  cache-until-401 behaviour.

## [1.0.0]

Initial public release.

- Blocking client with a pluggable `Transport` (built-in `ureq` transport behind the default
  `ureq-transport` feature); `target` is required (DIV Target Isolation).
- Re-exports the `intyga-verify` offline receipt verifier.
