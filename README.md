# intyga-sdk — INTYGA client for Rust

[![Release gated by INTYGA](https://www.intyga.com/badges/release-gated-by-intyga.svg)](https://www.intyga.com/use-cases/package-publishing)

Gate any high-risk backend action behind a real human approval. The primitive is uniform: **request a challenge → a human approves with a passkey or security key → poll until resolved** — the same client works for scripts, pipelines, and AI agents.

The example below uses a human or `SERVICE` key. `AI_AGENT` keys must include
`AuthorizeOptions.agent_context`; the executing service must independently check live configuration,
the signed session sequence and aggregate, and a budget across sessions (DIV §4.3.6).

This crate **bundles the offline verifier**, re-exporting it, so you can request an approval *and* independently verify the receipt without adding a second dependency.

> The standalone verifier also ships on its own as [`intyga-verify`](https://github.com/intyga-dev/verify-rust).

## Add it

```sh
cargo add intyga-sdk
```

## Require a human approval before a high-risk action

```rust
use intyga_sdk::{
    verify_approval_receipt_with_options, ApprovalStatus, AuthorizeOptions, Client, ClientOptions,
    Expected, RequireApprovalOptions, VerifyOptions,
};
use serde_json::json;

let mut client = Client::new(ClientOptions {
    gateway_url: "https://api.intyga.com".into(),
    client_id: std::env::var("INTYGA_CLIENT_ID").ok(),
    client_secret: std::env::var("INTYGA_CLIENT_SECRET").ok(),
    ..Default::default()
})?;

let params = json!({ "cluster": "prod-db-1" });

// Blocks until the human approves with their passkey / security key (or times out).
// `target` names THIS relying party. It is required: it is what stops an approval minted here from
// being replayed at a different service (DIV §3 Invariant 5, Target Isolation).
let r = client.require_approval("Delete production database", &RequireApprovalOptions {
    authorize: AuthorizeOptions {
        target: Some("prod-db-cluster-01".into()),
        action_type: Some("wipe_production".into()),
        params: Some(params.clone()),
        ..Default::default()
    },
    ..Default::default()
})?;
if r.status != ApprovalStatus::Approved {
    return Err("not authorized".into());
}

// Re-verify locally before executing. This is not optional under DIV §5: the relying party checks
// the signature itself, against a key IT resolved. `approvers` is required for exactly that reason —
// a receipt checked against its own embedded key proves only that the receipt is self-consistent.
let receipt = r.receipt.as_ref().ok_or("approved with no receipt")?;
let expected = Expected {
    target: "prod-db-cluster-01".into(),
    nonce: r.nonce.clone().ok_or("approved with no nonce")?,
    action_type: "wipe_production".into(),
    params: params.clone(),
    approvers: trusted_approver_anchor(),
};
// REQUIRED for passkey receipts (the normal flow): the approval console's exact origin and RP ID,
// from the trust-anchor file exported in the console (its `webauthn` block).
let opts = VerifyOptions {
    expected_origin: std::env::var("INTYGA_WEBAUTHN_ORIGIN").ok(),
    expected_rp_id: std::env::var("INTYGA_WEBAUTHN_RP_ID").ok(),
    ..Default::default()
};
verify_approval_receipt_with_options(receipt, &expected, &opts)?;

// Redeem it exactly once, immediately before the action runs. Same target, same params: this is
// what makes the approval single-use and re-binds it to what is about to execute.
let c = client.consume(
    r.nonce.as_deref().unwrap(),
    "prod-db-cluster-01",
    "wipe_production",
    Some(params),
)?;
if !c.ok {
    return Err("could not consume the approval".into());
}
```

`Client::new` and `Client::with_transport` return an error unless `gateway_url` is `https://`; plain `http://` is accepted only for a loopback host (`localhost`, `127.0.0.0/8`, `::1`) for local development, and the built-in transport never follows redirects.

With `client_id`/`client_secret`, the client exchanges them for a bearer token and re-exchanges automatically shortly before the `expires_in` the gateway reports (and once more on a `401`), so a long-lived client or a long `require_approval` wait never outlives its token. A `token` you pass yourself is used as-is and never refreshed.

## Offline approval (DIV §5a)

When the gateway cannot be reached, a relying party can still collect a real quorum approval out of
band: it builds the challenge itself from a gateway-signed **trust bundle** exported earlier, the
approvers review and sign it on a disconnected device, and the result is verified locally by the
ordinary verifier. Nothing written to disk can authorize a later action.

```rust
use intyga_sdk::{ApprovalStatus, AuthorizeOptions, OfflineApprovalOptions, RequireApprovalOptions};

let opts = RequireApprovalOptions {
    authorize: AuthorizeOptions {
        target: Some("prod-db-cluster-01".into()),
        // The exact action ID the trust bundle's policy is keyed on.
        action_type: Some("db.restart".into()),
        ..Default::default()
    },
    ..Default::default()
};
// Opt in at THIS call site only. Falls back only when the gateway could not be asked
// (connection failure, timeout, 5xx, five such polling failures in a row) — never on a 4xx, DENIED
// or EXPIRED, and never when a polling streak contained a 4xx.
let offline = OfflineApprovalOptions::new("/etc/myservice/intyga", "did:intyga:service:oncall", |challenge| {
    // Show challenge.envelope (DIV1:…) and challenge.verification_code to the approvers, and return
    // the SIG1:… strings they send back.
    collect_from_approvers(challenge)
});
let r = client.require_approval_with_offline("Restart the primary database", &opts, &offline)?;
match r.status {
    ApprovalStatus::Approved => { /* online approval */ }
    ApprovalStatus::OfflineApproved => { /* out-of-band approval: verified, redeemed, buffered */ }
    _ => return Err("not authorized".into()),
}

// When connectivity returns, report what happened offline.
client.reconcile_offline_approvals("/etc/myservice/intyga", None)?;
```

- **Trust bundle:** `save_trust_bundle`, `load_trust_bundle`, `verify_trust_bundle`,
  `check_trust_bundle_freshness`, `approver_anchor`, `requirement_for`.
- **Ceremony:** `create_offline_challenge`, `decode_challenge_envelope`, `sign_challenge_envelope`
  (the approver's side), `encode_signature_envelope` / `decode_signature_envelope`,
  `assemble_offline_receipt`.
- **Running it yourself:** `use_offline_approval`, `FileRedemptionStore` (single use),
  `pending_approvals`, `clear_pending_approval`.
- **Trust-anchor files:** `parse_trust_anchor_file(text, TrustAnchorPurpose::Online | Offline)`,
  `trust_anchor_approvers`.

The on-disk layout (`trust-bundle.jws`, `gateway-key.jwk.json`, `.redeemed/`, `.pending/`) is shared
with the other INTYGA SDKs, so tools in different languages can use one directory.

## Bring your own HTTP client

The client is generic over a pluggable `Transport`. `Client::new(..)` uses a built-in blocking `ureq` transport (default feature `ureq-transport`); disable it and implement `Transport` to route requests through your own async/instrumented HTTP stack:

```rust
let client = Client::with_transport(opts, MyTransport)?;
```

`Transport::request` returns `Result<HttpResponse, TransportError>`, and the error variant matters:

- **Every HTTP status — 3xx, 4xx and 5xx included — must come back as `Ok(HttpResponse)`.** Many HTTP
  libraries (ureq among them) return an error for a non-2xx by default; unwrap it into an
  `HttpResponse`. The client decides what a status means, and a 4xx must reach it as the gateway
  refusing, never as an outage.
- Return `TransportError::NoResponse` only when no HTTP response was received at all (DNS, connection
  refused, TLS failure, timeout). It is the only error that lets `require_approval_with_offline` fall
  back to an offline approval.
- Return `TransportError::UnreadableBody` when a response arrived but its body could not be read, and
  `TransportError::Other` for anything else. A plain `String` converts to `Other`, which never falls
  back — so a transport that does not classify its errors fails closed.

## Also available in
- TypeScript — [`@intyga/sdk`](https://github.com/intyga-dev/sdk)
- Python — [`sdk-python`](https://github.com/intyga-dev/sdk-python)
- Go — [`sdk-go`](https://github.com/intyga-dev/sdk-go)
- Java — [`sdk-java`](https://github.com/intyga-dev/sdk-java)

## License

Apache-2.0.
