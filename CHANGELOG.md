# Changelog

All notable changes to `intyga-sdk` (Rust) are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [SemVer](https://semver.org/).

## [Unreleased]

## [1.0.0]

- Packaging: the standalone SDK source includes the embedded verifier's license, README and changelog.

- **Breaking (I11):** `Client::new` and `Client::with_transport` now return `Result<Client, String>`
  and refuse a `gateway_url` that is not `https://`, except `http://` to a loopback host
  (`localhost`, `127.0.0.0/8`, `::1`) for local development.

- Refresh the SDK lockfile to include the verifier's existing Unicode normalization dependency.

- Refuse approvals received after the caller's monotonic wait deadline; include challenge creation
  in the wait window and cap polling sleeps to its remaining duration.

- Preserve challenge-issued agent context through approval polling for DIV continuity checks.
- Public witness lookups require no credentials and refuse non-success HTTP responses.
- Default HTTP transports use finite request timeouts and refuse redirects; caller-supplied
  transports remain the caller's responsibility.

- Rebuilt against the DIV Intent Payload's new REQUIRED `evidence` field (DIV §4.3.4), which is
  `null` in this version. No API change; receipts carry the field inside `canonicalPayload` only.

- `Client::authorize` now omits `actionType` when unset, matching the gateway's optional field
  schema instead of serializing JSON `null`.
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


Initial public release.

- Blocking client with a pluggable `Transport` (built-in `ureq` transport behind the default
  `ureq-transport` feature); `target` is required (DIV Target Isolation).
- Re-exports the `intyga-verify` offline receipt verifier.
