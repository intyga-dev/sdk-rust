# intyga-sdk — Intyga client for Rust

Gate any high-risk backend action behind a real human approval. The primitive is uniform: **request a challenge → a human approves with a passkey or security key → poll until resolved** — the same client works for scripts, pipelines, and AI agents.

This crate **bundles the offline verifier**, re-exporting it, so you can request an approval *and* independently verify the receipt without adding a second dependency.

> Status: **not yet published** to crates.io. The standalone verifier also ships on its own as [`intyga-verify`](https://github.com/intyga-dev/verify-rust).

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
});

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
verify_approval_receipt_with_options(receipt, &expected, &VerifyOptions::default())?;

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

With `client_id`/`client_secret`, the client exchanges them for a bearer token and re-exchanges automatically shortly before the `expires_in` the gateway reports (and once more on a `401`), so a long-lived client or a long `require_approval` wait never outlives its token. A `token` you pass yourself is used as-is and never refreshed.

## Bring your own HTTP client

The client is generic over a pluggable `Transport`. `Client::new(..)` uses a built-in blocking `ureq` transport (default feature `ureq-transport`); disable it and implement `Transport` to route requests through your own async/instrumented HTTP stack:

```rust
let client = Client::with_transport(opts, MyTransport);
```

## Also available in
- TypeScript — [`@intyga/sdk`](https://github.com/intyga-dev/sdk)
- Python — [`sdk-python`](https://github.com/intyga-dev/sdk-python)
- Go — [`sdk-go`](https://github.com/intyga-dev/sdk-go)
- Java — [`sdk-java`](https://github.com/intyga-dev/sdk-java)

## License

Apache-2.0.
