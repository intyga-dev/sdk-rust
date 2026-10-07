# Changelog

All notable changes to `intyga-sdk` (Rust) are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [SemVer](https://semver.org/).

## [Unreleased]

## [1.2.0]

- **Offline approval (DIV §5a).** The SDK half of offline approval, matching the TypeScript
  reference and passing every section of the shared `offline-approval-vectors.json`
  (docs/OFFLINE-APPROVAL-SDK.md):
  - Trust bundles: `verify_trust_bundle` (RS256 compact JWS against a pinned JWK, `alg` checked,
    never chosen), `check_trust_bundle_freshness` (`expiresAt` plus the 30-day age cap),
    `save_trust_bundle` / `load_trust_bundle` (`trust-bundle.jws` + `gateway-key.jwk.json`, private
    files), `approver_anchor(bundle, limit_to_dids, purpose)` with offline signing keys admitted only
    for `BundleAnchorPurpose::OfflineIntent`, and `requirement_for` with the exact-ID (v3) policy
    selection of `approval_policy` (`validate_exact_approval_policy`, `lost_approval_constraints`,
    `select_approval_rule`).
  - Trust-anchor files: `parse_trust_anchor_file(text, purpose)` and `trust_anchor_approvers`; an
    online anchor is refused where offline approvals are verified, and the reverse.
  - Ceremony: `create_offline_challenge`, `decode_challenge_envelope` (`DIV1:`),
    `encode_signature_envelope` / `decode_signature_envelope` (`SIG1:`), `sign_challenge_envelope`
    (PKCS#8 PEM or DER, SEC1 PEM — including `openssl ecparam -genkey` output with its leading
    `EC PARAMETERS` block — or a `p256` signing key), `assemble_offline_receipt`.
  - Running it: `use_offline_approval` with `FileRedemptionStore` (exclusive-create single use),
    `pending_approvals` / `clear_pending_approval` over `<bundle_dir>/.pending`.
  - Client: `Client::require_approval_with_offline` falls back only when the gateway could not be
    asked (transport failure, 5xx, five such polling failures in a row) — never on a 4xx, `DENIED`,
    `EXPIRED`, a local error, an unreadable 2xx body or an agent-continuity request — and reports
    the new `ApprovalStatus::OfflineApproved`, never `Approved`. `Client::reconcile_offline_approvals`
    posts each buffered record to `/offline-approval/reconcile` and clears it only on a 2xx; an
    unreadable record is counted as failed, kept and named.
  - Envelopes decode strict base64url only and must hold a JSON object; a `DIV1:` payload's fields
    must have the contract's shapes (string fields, a non-blank `target`, object `params` and
    `requirement`, a `requester` with a string `did`); a supplied empty nonce or a blank target is
    refused, never replaced; delegation files are tried in file-name order; a failed
    `collect_signatures` buffers and redeems nothing.
  - Pasted envelopes, the bundle file and the target are trimmed exactly as JavaScript's
    `String.prototype.trim()` does — a leading BOM is removed, U+0085 is not — so a paste that decodes
    in one SDK decodes in all of them. `Client::authorize` trims the target it sends the same way.
- `require_approval` (with or without offline options): when five consecutive polling failures
  include a refusal (a 4xx, or an unreadable 2xx body), the first such refusal is returned rather
  than "polling failed after 5 consecutive errors", whatever the later errors were.
- **Breaking:** `Transport::request` now returns `Result<HttpResponse, TransportError>` instead of
  `Result<HttpResponse, String>`. `TransportError::NoResponse` (no HTTP response received) is the only
  failure the offline fallback treats as "could not ask"; `UnreadableBody` and `Other` never fall back,
  and `From<String>` produces `Other`, so a transport that turns a 4xx into an `Err` cannot route a
  refusal offline. Every HTTP status, 3xx/4xx/5xx included, must be returned as `Ok(HttpResponse)`.
  To migrate, change the return type and map connection-level failures to `NoResponse`
  (`.map_err(|e| e.to_string().into())` compiles, but never falls back).
- The built-in `UreqTransport` returns a non-2xx as a status (as before), classifies DNS, connection,
  proxy-connect and I/O failures as `NoResponse` and everything else as `Other`, and reports a body it
  cannot read (an I/O error mid-body, over ureq's 10 MB cap, invalid UTF-8) as `UnreadableBody`
  instead of a transport failure.
- `ApprovalStatus` gains the `OfflineApproved` variant. An exhaustive `match` on it needs a new arm;
  only `require_approval_with_offline` ever returns it.
- New direct dependencies `p256`, `sha2`, `base64`, `rsa` and `getrandom`, each already in the
  dependency graph through `intyga-verify` at the same version — no new crate is pulled in.
- Re-exports `verify_delegation`, `ApprovalRequirement`, `ApprovalWitness`, `RequesterIdentity`,
  `RequirementFloor` and `VerifiedDelegation` from the verifier, which the offline API takes and
  returns.

## [1.1.0]

- No code change. The matched set moves together (`pnpm test:versions`); this release carries the
  new `@intyga/sdk` CLI options and the `require-approval` Action update.

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
