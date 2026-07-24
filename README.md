# sakra-sdk — SÄKRA client for Rust

Gate any high-risk backend action behind a real human approval. The primitive is uniform: **request a challenge → a human approves with a passkey or security key → poll until resolved** — the same client works for scripts, pipelines, and AI agents.

This crate **bundles the offline verifier**, re-exporting it, so you can request an approval *and* independently verify the receipt without adding a second dependency.

> Status: **not yet published** to crates.io. The standalone verifier also ships on its own as [`sakra-verify`](https://github.com/SAKRA-trust/verify-rust).

## Add it

```sh
cargo add sakra-sdk
```

## Require a human approval before a high-risk action

```rust
use sakra_sdk::{
    verify_approval_receipt_with_options, ApprovalStatus, AuthorizeOptions, Client, ClientOptions,
    Expected, RequireApprovalOptions, VerifyOptions,
};
use serde_json::json;

let mut client = Client::new(ClientOptions {
    gateway_url: "https://api.sakra.com".into(),
    client_id: std::env::var("SAKRA_CLIENT_ID").ok(),
    client_secret: std::env::var("SAKRA_CLIENT_SECRET").ok(),
    ..Default::default()
});

// Blocks until the human approves with their passkey / security key (or times out):
let r = client.require_approval("Delete production database", &RequireApprovalOptions {
    authorize: AuthorizeOptions {
        action_type: Some("wipe_production".into()),
        params: Some(json!({ "target": "prod-db-1" })),
        ..Default::default()
    },
    ..Default::default()
})?;
if r.status != ApprovalStatus::Approved {
    return Err("not authorized".into());
}

// Optional hard binding before executing — no SÄKRA secret involved:
let expected = Expected {
    nonce: r.nonce.clone().unwrap(),
    action_type: "wipe_production".into(),
    params: json!({ "target": "prod-db-1" }),
};
verify_approval_receipt_with_options(&r.receipt.unwrap(), &expected, &VerifyOptions::default())?;
```

## Bring your own HTTP client

The client is generic over a pluggable `Transport`. `Client::new(..)` uses a built-in blocking `ureq` transport (default feature `ureq-transport`); disable it and implement `Transport` to route requests through your own async/instrumented HTTP stack:

```rust
let client = Client::with_transport(opts, MyTransport);
```

## Also available in
- TypeScript — [`@sakra-trust/sdk`](https://github.com/SAKRA-trust/sdk)
- Python — [`sdk-python`](https://github.com/SAKRA-trust/sdk-python)
- Go — [`sdk-go`](https://github.com/SAKRA-trust/sdk-go)

## License

Apache-2.0.
