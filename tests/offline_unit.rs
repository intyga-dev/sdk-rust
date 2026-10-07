//! What the conformance vectors do not cover: single use, the pending buffer, unsafe nonces, key
//! formats, bundle files, and the client's fallback gating and reconciliation.

mod common;

use std::cell::{Cell, RefCell};
use std::path::Path;
use std::rc::Rc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use common::*;
use intyga_sdk::{
    clear_pending_approval, create_offline_challenge, decode_signature_envelope, load_trust_bundle,
    pending_approvals, save_trust_bundle, sign_challenge_envelope, use_offline_approval,
    ApprovalStatus, AuthorizeOptions, ChallengeOptions, Client, ClientOptions, FileRedemptionStore,
    HttpResponse, OfflineAction, OfflineApprovalOptions, OfflineSigningKey, RedemptionStore,
    RequesterIdentity, RequireApprovalOptions, SignOptions, Transport, TransportError,
    TrustBundleFiles,
};
use serde_json::{json, Value};

const AS_OF: &str = "2026-10-06T12:00:00.123Z";

fn restart() -> OfflineAction {
    OfflineAction {
        target: "prod-db-cluster-01".into(),
        action_type: "db.restart".into(),
        display: "Restart the primary database".into(),
        params: json!({ "cluster": "primary" }),
    }
}

/// Offline options whose collector has alice and bob sign with their offline keys (db.restart's
/// 2-of-2), counting how often it is asked.
fn alice_and_bob<'a>(dir: &Path, asked: &'a Cell<u32>) -> OfflineApprovalOptions<'a> {
    let mut opts =
        OfflineApprovalOptions::new(dir, str_of(&v()["requesterDid"]), move |challenge| {
            asked.set(asked.get() + 1);
            Ok(vec![
                sig1("alice", "offline", "alice", &challenge.canonical_payload),
                sig1("bob", "offline", "bob", &challenge.canonical_payload),
            ])
        });
    opts.as_of = Some(at(AS_OF));
    opts.warn = Some(Box::new(|_: &str| {}));
    opts
}

#[cfg(unix)]
fn mode_of(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

// ---------------------------------------------------------------------------------------------
// Single use, the buffer, unsafe nonces
// ---------------------------------------------------------------------------------------------

#[test]
fn a_nonce_redeems_exactly_once() {
    let dir = TempDir::new("redeem");
    let store = FileRedemptionStore::new(dir.path().join(".redeemed")).unwrap();
    assert!(store.redeem("off_one"));
    assert!(!store.redeem("off_one"), "a second claim must fail");
    // A fresh store over the same directory sees the same claim: the state is on disk.
    let again = FileRedemptionStore::new(dir.path().join(".redeemed")).unwrap();
    assert!(!again.redeem("off_one"));
    let marker = dir.path().join(".redeemed/off_one.used");
    let text = std::fs::read_to_string(&marker).unwrap();
    assert!(intyga_sdk::parse_timestamp(&text).is_some(), "{text}");
    #[cfg(unix)]
    {
        assert_eq!(mode_of(&marker), 0o600);
        assert_eq!(mode_of(&dir.path().join(".redeemed")), 0o700);
    }
}

#[test]
fn racing_redemptions_have_one_winner() {
    let dir = TempDir::new("race");
    let store = Arc::new(FileRedemptionStore::new(dir.path().join(".redeemed")).unwrap());
    let wins = Arc::new(AtomicUsize::new(0));
    let threads: Vec<_> = (0..8)
        .map(|_| {
            let (store, wins) = (store.clone(), wins.clone());
            std::thread::spawn(move || {
                if store.redeem("off_race") {
                    wins.fetch_add(1, Ordering::SeqCst);
                }
            })
        })
        .collect();
    threads.into_iter().for_each(|t| t.join().unwrap());
    assert_eq!(wins.load(Ordering::SeqCst), 1);
}

#[test]
fn unsafe_nonces_never_become_paths() {
    let dir = TempDir::new("unsafe");
    let store = FileRedemptionStore::new(dir.path().join(".redeemed")).unwrap();
    for bad in ["../escape", "a/b", "", "nul\0", &"a".repeat(201)] {
        assert!(!store.redeem(bad), "{bad:?}");
    }
    assert!(!dir.path().join("escape.used").exists());

    // clear_pending_approval must not reach outside the buffer either.
    let victim = dir.path().join("victim.json");
    std::fs::write(&victim, "{}").unwrap();
    clear_pending_approval("../victim", dir.path(), None);
    assert!(victim.exists());

    let bundle = serde_json::from_value(v()["bundle"].clone()).unwrap();
    let requester = RequesterIdentity {
        did: "did:intyga:service:oncall".into(),
        attestation: None,
    };
    let refused = create_offline_challenge(
        &bundle,
        &restart(),
        &requester,
        &ChallengeOptions {
            nonce: Some("../escape".into()),
            as_of: Some(at(AS_OF)),
            ..Default::default()
        },
    );
    assert!(refused.unwrap_err().contains("safe path segment"));
    let generated = create_offline_challenge(
        &bundle,
        &restart(),
        &requester,
        &ChallengeOptions {
            as_of: Some(at(AS_OF)),
            ..Default::default()
        },
    )
    .unwrap();
    assert!(
        generated.nonce.starts_with("off_") && generated.nonce.len() == 40,
        "{}",
        generated.nonce
    );
}

#[test]
fn an_approval_is_buffered_then_cleared() {
    let dir = bundle_dir("pending");
    let asked = Cell::new(0);
    let approval = use_offline_approval(&restart(), &alice_and_bob(dir.path(), &asked)).unwrap();
    assert_eq!(asked.get(), 1);
    assert_eq!(approval.signers, vec!["did:intyga:alice", "did:intyga:bob"]);
    assert_eq!(approval.via_delegation, None);

    let pending = pending_approvals(dir.path(), None);
    assert_eq!(pending.len(), 1);
    let record = &pending[0];
    assert_eq!(record.nonce, approval.nonce);
    assert_eq!(record.target, "prod-db-cluster-01");
    assert_eq!(record.action_type, "db.restart");
    assert_eq!(record.display, "Restart the primary database");
    assert!(intyga_sdk::parse_timestamp(&record.used_at).is_some());
    assert_eq!(
        record.receipt.canonical_payload,
        approval.receipt.canonical_payload
    );
    assert_eq!(record.delegation_nonce, None);

    // The on-disk shape matches the reference's: no delegationNonce key when none was used, and no
    // `null` placeholders for absent receipt fields.
    let file = dir
        .path()
        .join(".pending")
        .join(format!("{}.json", approval.nonce));
    let raw: Value = serde_json::from_str(&std::fs::read_to_string(&file).unwrap()).unwrap();
    assert!(raw.get("delegationNonce").is_none());
    assert_no_nulls(&raw["receipt"]);
    #[cfg(unix)]
    {
        assert_eq!(mode_of(&file), 0o600);
        assert_eq!(mode_of(&dir.path().join(".pending")), 0o700);
    }
    // And the nonce is redeemed.
    assert!(dir
        .path()
        .join(".redeemed")
        .join(format!("{}.used", approval.nonce))
        .exists());

    clear_pending_approval(&approval.nonce, dir.path(), None);
    assert!(pending_approvals(dir.path(), None).is_empty());
}

fn assert_no_nulls(receipt: &Value) {
    for (k, val) in receipt.as_object().unwrap() {
        assert!(!val.is_null(), "receipt.{k} is null");
    }
    for w in receipt["signatures"].as_array().unwrap() {
        for (k, val) in w.as_object().unwrap() {
            assert!(!val.is_null(), "witness.{k} is null");
        }
    }
}

#[test]
fn a_store_that_refuses_the_nonce_refuses_the_approval_and_drops_its_record() {
    struct AlreadyUsed;
    impl RedemptionStore for AlreadyUsed {
        fn redeem(&self, _: &str) -> bool {
            false
        }
    }
    let dir = bundle_dir("replay");
    let asked = Cell::new(0);
    let mut opts = alice_and_bob(dir.path(), &asked);
    opts.store = Some(Box::new(AlreadyUsed));
    let err = use_offline_approval(&restart(), &opts).unwrap_err();
    assert!(err.contains("already been redeemed"), "{err}");
    assert!(pending_approvals(dir.path(), None).is_empty());
}

#[test]
fn an_offline_approval_is_never_quiet() {
    let dir = bundle_dir("warn");
    let asked = Cell::new(0);
    let warnings = RefCell::new(Vec::<String>::new());
    let mut opts = alice_and_bob(dir.path(), &asked);
    opts.warn = Some(Box::new(|m: &str| {
        warnings.borrow_mut().push(m.to_string())
    }));
    use_offline_approval(&restart(), &opts).unwrap();
    let warnings = warnings.borrow();
    assert_eq!(warnings.len(), 1);
    assert!(
        warnings[0].contains("OFFLINE APPROVAL USED"),
        "{}",
        warnings[0]
    );
}

// ---------------------------------------------------------------------------------------------
// Bundle files and key formats
// ---------------------------------------------------------------------------------------------

#[test]
fn a_saved_bundle_loads_and_is_private() {
    let dir = TempDir::new("save");
    let target = dir.path().join("bundle");
    save_trust_bundle(
        &target,
        &TrustBundleFiles {
            jws: str_of(&v()["bundleJws"]).into(),
            gateway_jwk: v()["gatewayJwk"].clone(),
        },
    )
    .unwrap();
    let loaded = load_trust_bundle(&target, Some(at(AS_OF))).unwrap();
    assert_eq!(serde_json::to_value(&loaded).unwrap(), v()["bundle"]);
    #[cfg(unix)]
    {
        assert_eq!(mode_of(&target), 0o700);
        assert_eq!(mode_of(&target.join("trust-bundle.jws")), 0o600);
        assert_eq!(mode_of(&target.join("gateway-key.jwk.json")), 0o600);
    }
    // Overwriting in place works (atomic replace).
    save_trust_bundle(
        &target,
        &TrustBundleFiles {
            jws: str_of(&v()["bundleJws"]).into(),
            gateway_jwk: v()["gatewayJwk"].clone(),
        },
    )
    .unwrap();
    let missing = load_trust_bundle(dir.path().join("nowhere"), Some(at(AS_OF))).unwrap_err();
    assert!(missing.contains("no trust bundle"), "{missing}");
}

#[test]
fn approvers_sign_with_pem_or_der_keys() {
    use p256::pkcs8::EncodePrivateKey;
    let key = key_from_seed(seed_of("alice", "offline"));
    let pem = key.to_pkcs8_pem(Default::default()).unwrap().to_string();
    let der = key.to_pkcs8_der().unwrap().as_bytes().to_vec();
    // SEC1 (`EC PRIVATE KEY`), alone and as `openssl ecparam -name prime256v1 -genkey` writes it:
    // with an `EC PARAMETERS` block (the prime256v1 OID) in front of the key.
    let sec1 = p256::SecretKey::from(key.clone())
        .to_sec1_pem(Default::default())
        .unwrap()
        .to_string();
    let openssl_ecparam = format!(
        "-----BEGIN EC PARAMETERS-----\nBggqhkjOPQMBBw==\n-----END EC PARAMETERS-----\n{sec1}"
    );
    let bundle = serde_json::from_value(v()["bundle"].clone()).unwrap();
    let challenge = create_offline_challenge(
        &bundle,
        &restart(),
        &RequesterIdentity {
            did: "did:intyga:service:oncall".into(),
            attestation: None,
        },
        &ChallengeOptions {
            as_of: Some(at(AS_OF)),
            ..Default::default()
        },
    )
    .unwrap();
    let sign = |private_key, signer_did: &str| {
        sign_challenge_envelope(
            &challenge.envelope,
            &SignOptions {
                private_key,
                signer_did: signer_did.into(),
                as_of: Some(at(AS_OF)),
            },
        )
    };
    for private_key in [
        OfflineSigningKey::Pem(pem.clone()),
        OfflineSigningKey::Der(der.clone()),
        OfflineSigningKey::Der(pem.clone().into_bytes()),
        OfflineSigningKey::Pem(sec1.clone()),
        OfflineSigningKey::Pem(openssl_ecparam.clone()),
        OfflineSigningKey::Der(openssl_ecparam.into_bytes()),
        OfflineSigningKey::Pem(format!("\u{feff}\n{pem}\n")),
        OfflineSigningKey::P256(key.clone()),
    ] {
        let signed = sign(private_key, "did:intyga:alice").unwrap();
        let w = decode_signature_envelope(&signed.envelope).unwrap();
        assert_eq!(w.signer_public_key, spki_published("alice", "offline"));
        assert_eq!(signed.challenge.nonce, challenge.nonce);
    }
    assert!(sign(OfflineSigningKey::Pem(pem), "alice")
        .unwrap_err()
        .contains("DID"));
    assert!(
        sign(OfflineSigningKey::Der(vec![1, 2, 3]), "did:intyga:alice")
            .unwrap_err()
            .contains("private key")
    );
    // A truncated SEC1 block is refused, not guessed at.
    let truncated = sec1.replace("-----END EC PRIVATE KEY-----", "");
    assert!(sign(OfflineSigningKey::Pem(truncated), "did:intyga:alice").is_err());
}

// ---------------------------------------------------------------------------------------------
// The client: fallback gating and reconciliation
// ---------------------------------------------------------------------------------------------

/// A scripted answer: `Ok((status, body))`, or `Err` for a transport failure.
type Reply = Result<(u16, String), String>;

/// A scripted transport: each (method, path suffix) route answers from its own queue, repeating the
/// last answer once the queue is down to one.
struct Scripted {
    routes: RefCell<Vec<(String, String, Vec<Reply>)>>,
}

impl Scripted {
    fn new() -> Self {
        Scripted {
            routes: RefCell::new(Vec::new()),
        }
    }
    fn on(self, method: &str, suffix: &str, replies: Vec<Reply>) -> Self {
        self.routes
            .borrow_mut()
            .push((method.into(), suffix.into(), replies));
        self
    }
}

fn reply(status: u16, body: &str) -> Reply {
    Ok((status, body.into()))
}

fn down() -> Reply {
    Err("connection refused".into())
}

/// A scripted `Err` is "no response received" — the one transport failure that may go offline.
fn respond(r: Reply) -> Result<HttpResponse, TransportError> {
    r.map(|(status, body)| HttpResponse { status, body })
        .map_err(TransportError::NoResponse)
}

impl Transport for Scripted {
    fn request(
        &self,
        method: &str,
        url: &str,
        _: &[(&str, &str)],
        _: Option<&str>,
    ) -> Result<HttpResponse, TransportError> {
        for (m, suffix, replies) in self.routes.borrow_mut().iter_mut() {
            if m == method && url.ends_with(suffix.as_str()) {
                let next = if replies.len() > 1 {
                    replies.remove(0)
                } else {
                    replies[0].clone()
                };
                return respond(next);
            }
        }
        Err(format!("no route for {method} {url}").into())
    }
}

fn client(transport: Scripted) -> Client<Scripted> {
    Client::with_transport(
        ClientOptions {
            gateway_url: "https://gw.example".into(),
            token: Some("t".into()),
            ..Default::default()
        },
        transport,
    )
    .unwrap()
}

fn fast(authorize: AuthorizeOptions) -> RequireApprovalOptions {
    RequireApprovalOptions {
        authorize,
        timeout: std::time::Duration::from_secs(5),
        interval: std::time::Duration::from_millis(1),
    }
}

fn restart_request() -> AuthorizeOptions {
    AuthorizeOptions {
        target: Some("prod-db-cluster-01".into()),
        action_type: Some("db.restart".into()),
        params: Some(json!({ "cluster": "primary" })),
        ..Default::default()
    }
}

const PENDING: &str = r#"{"nonce":"n_1","status":"PENDING"}"#;

#[test]
fn an_unreachable_gateway_falls_back_to_offline_approval() {
    for (label, authorize_reply) in [
        ("transport failure", down()),
        ("502", reply(502, "bad gateway")),
        ("503", reply(503, "unavailable")),
    ] {
        let dir = bundle_dir("fallback");
        let asked = Cell::new(0);
        let mut c = client(Scripted::new().on("POST", "/authorize", vec![authorize_reply]));
        let r = c
            .require_approval_with_offline(
                "Restart the primary database",
                &fast(restart_request()),
                &alice_and_bob(dir.path(), &asked),
            )
            .unwrap_or_else(|e| panic!("{label}: {e}"));
        assert_eq!(r.status, ApprovalStatus::OfflineApproved, "{label}");
        assert_ne!(r.status, ApprovalStatus::Approved);
        assert_eq!(asked.get(), 1, "{label}");
        let nonce = r.nonce.unwrap();
        assert!(nonce.starts_with("off_"), "{label}: {nonce}");
        assert!(r
            .receipt
            .unwrap()
            .canonical_payload
            .contains("div-offline-intent"));
        assert_eq!(pending_approvals(dir.path(), None).len(), 1, "{label}");
    }
}

#[test]
fn repeated_polling_failures_fall_back() {
    let dir = bundle_dir("poll-down");
    let asked = Cell::new(0);
    let mut c = client(
        Scripted::new()
            .on("POST", "/authorize", vec![reply(200, PENDING)])
            .on("GET", "/authorize/n_1", vec![down()]),
    );
    let r = c
        .require_approval_with_offline(
            "Restart the primary database",
            &fast(restart_request()),
            &alice_and_bob(dir.path(), &asked),
        )
        .unwrap();
    assert_eq!(r.status, ApprovalStatus::OfflineApproved);
    assert_eq!(asked.get(), 1);
}

#[test]
fn a_gateway_verdict_is_never_routed_offline() {
    // A 4xx is the gateway answering — 403 is its own fail-closed refusal. Never a fallback.
    for status in [400u16, 401, 402, 403, 404, 429] {
        let dir = bundle_dir("verdict");
        let asked = Cell::new(0);
        let mut c = client(Scripted::new().on("POST", "/authorize", vec![reply(status, "no")]));
        let err = c
            .require_approval_with_offline(
                "Restart the primary database",
                &fast(restart_request()),
                &alice_and_bob(dir.path(), &asked),
            )
            .unwrap_err();
        assert!(err.contains(&status.to_string()), "{status}: {err}");
        assert_eq!(asked.get(), 0, "{status} reached the offline path");
        assert!(pending_approvals(dir.path(), None).is_empty());
    }
}

/// Run `require_approval_with_offline` against a gateway that accepts the challenge and then
/// answers the polls with `polls`, returning the result and how often signatures were collected.
fn poll_streak(polls: Vec<Reply>) -> (Result<intyga_sdk::ApprovalResult, String>, u32) {
    let dir = bundle_dir("streak");
    let asked = Cell::new(0);
    let mut c = client(
        Scripted::new()
            .on("POST", "/authorize", vec![reply(200, PENDING)])
            .on("GET", "/authorize/n_1", polls),
    );
    let r = c.require_approval_with_offline(
        "Restart the primary database",
        &fast(restart_request()),
        &alice_and_bob(dir.path(), &asked),
    );
    (r, asked.get())
}

#[test]
fn a_refusal_anywhere_in_the_polling_streak_is_never_routed_offline() {
    // The first refusal in the streak is returned, even when every later error is a 5xx: a gateway
    // that answered 404 once and then went quiet was reached, and its answer was not an outage.
    let (r, asked) = poll_streak(vec![
        reply(404, "unknown challenge"),
        reply(503, "x"),
        reply(503, "x"),
        reply(503, "x"),
        reply(503, "x"),
    ]);
    let err = r.unwrap_err();
    assert!(
        err.contains("404") && err.contains("unknown challenge"),
        "{err}"
    );
    assert_eq!(asked, 0);

    // In the middle, or at the end, it is the same verdict — and it is the FIRST refusal that is
    // returned when there are several.
    let (r, asked) = poll_streak(vec![
        down(),
        reply(429, "slow"),
        down(),
        reply(403, "no"),
        down(),
    ]);
    let err = r.unwrap_err();
    assert!(err.contains("429") && !err.contains("403"), "{err}");
    assert_eq!(asked, 0);
    let (r, asked) = poll_streak(vec![down(), down(), down(), down(), reply(403, "no")]);
    assert!(r.unwrap_err().contains("403"));
    assert_eq!(asked, 0);

    // An unreadable 2xx body came from something that answered: also not an outage.
    let (r, asked) = poll_streak(vec![
        reply(200, "<html>proxy</html>"),
        down(),
        down(),
        down(),
        down(),
    ]);
    assert!(r.unwrap_err().contains("bad status response"));
    assert_eq!(asked, 0);
}

/// A custom transport written the natural ureq way: every non-2xx becomes an `Err` via
/// `.map_err(|e| e.to_string().into())`, so a 403 arrives as an unclassified transport error rather
/// than as a status. Requests whose URL ends in `/authorize` get `on_authorize`; polls get `on_poll`.
struct ErrOnNon2xx {
    on_authorize: u16,
    on_poll: u16,
}

impl Transport for ErrOnNon2xx {
    fn request(
        &self,
        method: &str,
        url: &str,
        _: &[(&str, &str)],
        _: Option<&str>,
    ) -> Result<HttpResponse, TransportError> {
        let status = if method == "POST" && url.ends_with("/authorize") {
            self.on_authorize
        } else {
            self.on_poll
        };
        if !(200..300).contains(&status) {
            // What `ureq::Error::Status(..).to_string()` looks like.
            return Err(format!("{url}: status code {status}").into());
        }
        Ok(HttpResponse {
            status,
            body: PENDING.into(),
        })
    }
}

#[test]
fn a_transport_that_errors_on_a_refusal_never_goes_offline() {
    for (on_authorize, on_poll) in [(403, 200), (401, 200), (429, 200), (200, 403), (200, 404)] {
        let dir = bundle_dir("err-on-4xx");
        let asked = Cell::new(0);
        let mut c = Client::with_transport(
            ClientOptions {
                gateway_url: "https://gw.example".into(),
                token: Some("t".into()),
                ..Default::default()
            },
            ErrOnNon2xx {
                on_authorize,
                on_poll,
            },
        )
        .unwrap();
        let err = c
            .require_approval_with_offline(
                "Restart the primary database",
                &fast(restart_request()),
                &alice_and_bob(dir.path(), &asked),
            )
            .unwrap_err();
        let status = on_authorize.max(on_poll).to_string();
        assert!(err.contains(&status), "{on_authorize}/{on_poll}: {err}");
        assert_eq!(
            asked.get(),
            0,
            "{on_authorize}/{on_poll} reached the offline path"
        );
        assert!(pending_approvals(dir.path(), None).is_empty());
        assert!(!dir.path().join(".redeemed").exists());
    }
}

#[test]
fn an_unreadable_body_from_the_transport_never_goes_offline() {
    struct Garbled;
    impl Transport for Garbled {
        fn request(
            &self,
            _: &str,
            _: &str,
            _: &[(&str, &str)],
            _: Option<&str>,
        ) -> Result<HttpResponse, TransportError> {
            Err(TransportError::UnreadableBody(
                "HTTP 503: invalid UTF-8".into(),
            ))
        }
    }
    let dir = bundle_dir("unreadable-body");
    let asked = Cell::new(0);
    let mut c = Client::with_transport(
        ClientOptions {
            gateway_url: "https://gw.example".into(),
            token: Some("t".into()),
            ..Default::default()
        },
        Garbled,
    )
    .unwrap();
    let err = c
        .require_approval_with_offline(
            "Restart the primary database",
            &fast(restart_request()),
            &alice_and_bob(dir.path(), &asked),
        )
        .unwrap_err();
    assert!(err.contains("invalid UTF-8"), "{err}");
    assert_eq!(asked.get(), 0);
}

#[test]
fn a_successful_poll_clears_an_earlier_refusal() {
    // [404, PENDING] ends that streak; the next five are all "could not ask", so this falls back.
    let (r, asked) = poll_streak(vec![
        reply(404, "blip"),
        reply(200, PENDING),
        reply(503, "x"),
        down(),
        reply(502, "x"),
        down(),
        reply(503, "x"),
    ]);
    assert_eq!(r.unwrap().status, ApprovalStatus::OfflineApproved);
    assert_eq!(asked, 1);
}

#[test]
fn the_streak_rule_holds_without_offline_options_too() {
    let mut c = client(
        Scripted::new()
            .on("POST", "/authorize", vec![reply(200, PENDING)])
            .on(
                "GET",
                "/authorize/n_1",
                vec![reply(404, "gone"), reply(503, "x")],
            ),
    );
    let err = c
        .require_approval("Restart the primary database", &fast(restart_request()))
        .unwrap_err();
    assert!(err.contains("404") && err.contains("gone"), "{err}");
    let mut c = client(
        Scripted::new()
            .on("POST", "/authorize", vec![reply(200, PENDING)])
            .on("GET", "/authorize/n_1", vec![reply(503, "x")]),
    );
    let err = c
        .require_approval("Restart the primary database", &fast(restart_request()))
        .unwrap_err();
    assert!(
        err.starts_with("polling failed after 5 consecutive errors"),
        "{err}"
    );
}

#[test]
fn an_unreadable_answer_to_the_challenge_is_never_routed_offline() {
    let dir = bundle_dir("bad-body");
    let asked = Cell::new(0);
    let mut c =
        client(Scripted::new().on("POST", "/authorize", vec![reply(200, "<html>proxy</html>")]));
    let err = c
        .require_approval_with_offline(
            "Restart the primary database",
            &fast(restart_request()),
            &alice_and_bob(dir.path(), &asked),
        )
        .unwrap_err();
    assert!(err.contains("bad authorize response"), "{err}");
    assert_eq!(asked.get(), 0);
}

#[test]
fn a_failed_collection_buffers_and_redeems_nothing() {
    let dir = bundle_dir("collect-fails");
    let mut opts = OfflineApprovalOptions::new(dir.path(), "did:intyga:service:oncall", |_| {
        Err("the bridge line dropped".to_string())
    });
    opts.as_of = Some(at(AS_OF));
    opts.warn = Some(Box::new(|_: &str| {}));
    let err = use_offline_approval(&restart(), &opts).unwrap_err();
    assert!(err.contains("the bridge line dropped"), "{err}");
    assert!(pending_approvals(dir.path(), None).is_empty());
    let redeemed = dir.path().join(".redeemed");
    assert!(
        !redeemed.exists() || std::fs::read_dir(&redeemed).unwrap().next().is_none(),
        "a nonce was redeemed"
    );
}

#[test]
fn a_null_or_garbled_envelope_is_discarded_not_fatal() {
    let dir = bundle_dir("null-envelope");
    let mut opts =
        OfflineApprovalOptions::new(dir.path(), "did:intyga:service:oncall", |challenge| {
            Ok(vec![
                "SIG1:bnVsbA".to_string(), // `null`
                "SIG1:W10".to_string(),    // `[]`
                // A stray character: strict base64url refuses it rather than skipping it.
                sig1("alice", "offline", "alice", &challenge.canonical_payload)
                    .replacen(':', ":!", 1),
                sig1("alice", "offline", "alice", &challenge.canonical_payload),
                sig1("bob", "offline", "bob", &challenge.canonical_payload),
            ])
        });
    opts.as_of = Some(at(AS_OF));
    opts.warn = Some(Box::new(|_: &str| {}));
    let approval = use_offline_approval(&restart(), &opts).unwrap();
    assert_eq!(approval.signers, vec!["did:intyga:alice", "did:intyga:bob"]);
    assert_eq!(approval.receipt.signatures.as_ref().unwrap().len(), 2);
}

/// A delegation of db.restart to carol and dave (2 of 2), sealed by alice and bob's ORDINARY keys.
fn delegation_receipt(nonce: &str) -> Value {
    use intyga_sdk::{ApprovalRequirement, RequesterIdentity};
    let action = restart();
    let requester = RequesterIdentity {
        did: str_of(&v()["requesterDid"]).into(),
        attestation: None,
    };
    let requirement = ApprovalRequirement {
        required_approvals: 2,
        require_hardware_key: false,
        allowed_aaguids: Vec::new(),
        requester_cannot_approve: false,
        signer_class: "human".into(),
    };
    let payload = intyga_verify::canonical_delegation_payload(
        &action.target,
        &action.action_type,
        &action.display,
        &action.params,
        &requester,
        &requirement,
        &[did_of("carol"), did_of("dave")],
        2,
        nonce,
        "2026-10-06T11:00:00.123Z",
        "2026-10-06T13:00:00.123Z",
    )
    .unwrap();
    let witness = |id: &str| {
        json!({
            "signerDid": did_of(id),
            "signerPublicKey": spki_published(id, "ordinary"),
            "signature": sign(id, "ordinary", &payload),
            "sigAlg": "ES256",
        })
    };
    json!({
        "canonicalPayload": payload,
        "actionDescription": action.display,
        "params": action.params,
        "requester": requester,
        "signatures": [witness("alice"), witness("bob")],
        "verificationCode": intyga_sdk::verification_code(&payload),
    })
}

#[test]
fn delegations_are_tried_in_file_name_order() {
    let dir = bundle_dir("delegation-order");
    let delegations = dir.path().join("delegations");
    std::fs::create_dir(&delegations).unwrap();
    // Both apply. Written in reverse order, so directory order cannot pass this by accident.
    std::fs::write(
        delegations.join("b.json"),
        delegation_receipt("dlg-from-b").to_string(),
    )
    .unwrap();
    std::fs::write(
        delegations.join("a.json"),
        delegation_receipt("dlg-from-a").to_string(),
    )
    .unwrap();
    std::fs::write(delegations.join("0-not-a-receipt.json"), "{}").unwrap();
    let warnings = RefCell::new(Vec::<String>::new());
    let mut opts =
        OfflineApprovalOptions::new(dir.path(), str_of(&v()["requesterDid"]), |challenge| {
            Ok(vec![
                sig1("carol", "ordinary", "carol", &challenge.canonical_payload),
                sig1("dave", "ordinary", "dave", &challenge.canonical_payload),
            ])
        });
    opts.delegation_dir = Some(delegations);
    opts.as_of = Some(at(AS_OF));
    opts.warn = Some(Box::new(|m: &str| {
        warnings.borrow_mut().push(m.to_string())
    }));
    let approval = use_offline_approval(&restart(), &opts).unwrap();
    assert_eq!(approval.via_delegation.as_deref(), Some("dlg-from-a"));
    assert_eq!(
        approval.signers,
        vec!["did:intyga:carol", "did:intyga:dave"]
    );
    assert_eq!(
        pending_approvals(dir.path(), None)[0]
            .delegation_nonce
            .as_deref(),
        Some("dlg-from-a")
    );
    // A usable delegation ends the search quietly, even after a file that did not apply.
    assert!(warnings
        .borrow()
        .iter()
        .all(|w| !w.contains("no delegation applies")));
}

#[test]
fn a_human_answer_is_never_routed_offline() {
    for (status, expected) in [
        ("DENIED", ApprovalStatus::Denied),
        ("EXPIRED", ApprovalStatus::Expired),
    ] {
        let dir = bundle_dir("answered");
        let asked = Cell::new(0);
        let mut c = client(
            Scripted::new()
                .on("POST", "/authorize", vec![reply(200, PENDING)])
                .on(
                    "GET",
                    "/authorize/n_1",
                    vec![reply(200, &format!(r#"{{"status":"{status}"}}"#))],
                ),
        );
        let r = c
            .require_approval_with_offline(
                "Restart the primary database",
                &fast(restart_request()),
                &alice_and_bob(dir.path(), &asked),
            )
            .unwrap();
        assert_eq!(r.status, expected);
        assert_eq!(asked.get(), 0, "{status} reached the offline path");
    }
}

#[test]
fn agent_continuity_and_local_mistakes_never_fall_back() {
    let dir = bundle_dir("agent");
    let asked = Cell::new(0);
    let mut c = client(Scripted::new().on("POST", "/authorize", vec![down()]));
    let agent = AuthorizeOptions {
        agent_context: Some(json!({ "configDigest": "x" })),
        ..restart_request()
    };
    let err = c
        .require_approval_with_offline(
            "Restart the primary database",
            &fast(agent),
            &alice_and_bob(dir.path(), &asked),
        )
        .unwrap_err();
    assert!(err.contains("agent continuity"), "{err}");

    // A missing target is refused before anything is sent — not an outage.
    let no_target = AuthorizeOptions {
        target: None,
        ..restart_request()
    };
    let err = c
        .require_approval_with_offline(
            "Restart the primary database",
            &fast(no_target),
            &alice_and_bob(dir.path(), &asked),
        )
        .unwrap_err();
    assert!(err.contains("target is required"), "{err}");
    assert_eq!(asked.get(), 0);
}

#[test]
fn without_offline_options_nothing_changes() {
    let mut c = client(Scripted::new().on("POST", "/authorize", vec![down()]));
    let err = c
        .require_approval("Restart the primary database", &fast(restart_request()))
        .unwrap_err();
    assert_eq!(err, "connection refused");
}

#[test]
fn a_failed_offline_approval_names_both_failures() {
    let dir = bundle_dir("both");
    let mut opts =
        OfflineApprovalOptions::new(dir.path(), "did:intyga:service:oncall", |_| Ok(Vec::new()));
    opts.as_of = Some(at(AS_OF));
    let mut c = client(Scripted::new().on("POST", "/authorize", vec![down()]));
    let err = c
        .require_approval_with_offline(
            "Restart the primary database",
            &fast(restart_request()),
            &opts,
        )
        .unwrap_err();
    assert!(
        err.starts_with("could not reach Intyga to request approval: connection refused"),
        "{err}"
    );
    assert!(err.contains("no signatures were collected"), "{err}");
}

#[test]
fn reconciliation_clears_only_what_the_gateway_acknowledged() {
    let dir = bundle_dir("reconcile");
    let asked = Cell::new(0);
    let first = use_offline_approval(&restart(), &alice_and_bob(dir.path(), &asked)).unwrap();
    let second = use_offline_approval(&restart(), &alice_and_bob(dir.path(), &asked)).unwrap();
    let third = use_offline_approval(&restart(), &alice_and_bob(dir.path(), &asked)).unwrap();
    std::fs::write(dir.path().join(".pending/garbage.json"), "{not json").unwrap();

    // The gateway acknowledges `first`, refuses `second` with a 422, and is unreachable for `third`.
    struct ByNonce {
        ok: String,
        refused: String,
        bodies: Rc<RefCell<Vec<Value>>>,
    }
    impl Transport for ByNonce {
        fn request(
            &self,
            method: &str,
            url: &str,
            headers: &[(&str, &str)],
            body: Option<&str>,
        ) -> Result<HttpResponse, TransportError> {
            assert_eq!(method, "POST");
            assert!(url.ends_with("/offline-approval/reconcile"), "{url}");
            assert!(headers.contains(&("authorization", "Bearer t")));
            assert!(headers.contains(&("content-type", "application/json")));
            let body: Value = serde_json::from_str(body.unwrap()).unwrap();
            self.bodies.borrow_mut().push(body.clone());
            let nonce = body["nonce"].as_str().unwrap();
            respond(if nonce == self.ok {
                reply(200, r#"{"ok":true}"#)
            } else if nonce == self.refused {
                reply(422, r#"{"error":"POLICY_MISMATCH"}"#)
            } else {
                down()
            })
        }
    }
    let bodies = Rc::new(RefCell::new(Vec::new()));
    let transport = ByNonce {
        ok: first.nonce.clone(),
        refused: second.nonce.clone(),
        bodies: bodies.clone(),
    };
    let mut c = Client::with_transport(
        ClientOptions {
            gateway_url: "https://gw.example".into(),
            token: Some("t".into()),
            ..Default::default()
        },
        transport,
    )
    .unwrap();
    let report = c.reconcile_offline_approvals(dir.path(), None).unwrap();
    assert_eq!(report.reported, 1);
    assert_eq!(report.failed, 3, "{:?}", report.reasons);
    assert!(
        report
            .reasons
            .iter()
            .any(|r| r == &format!("{}: 422 {{\"error\":\"POLICY_MISMATCH\"}}", second.nonce)),
        "{:?}",
        report.reasons
    );
    assert!(report
        .reasons
        .iter()
        .any(|r| r.starts_with(&format!("{}: ", third.nonce))));
    assert!(report
        .reasons
        .iter()
        .any(|r| r.starts_with("garbage.json:")));

    let left: Vec<String> = pending_approvals(dir.path(), None)
        .into_iter()
        .map(|p| p.nonce)
        .collect();
    assert!(!left.contains(&first.nonce));
    assert!(left.contains(&second.nonce) && left.contains(&third.nonce));

    // The body is the reference's: these keys exactly, no delegationNonce, no nulls in the receipt,
    // and the receipt is the one that verified.
    let bodies = bodies.borrow();
    assert_eq!(bodies.len(), 3);
    for body in bodies.iter() {
        let mut keys: Vec<&String> = body.as_object().unwrap().keys().collect();
        keys.sort();
        assert_eq!(
            keys,
            [
                "actionType",
                "display",
                "nonce",
                "receipt",
                "target",
                "usedAt"
            ]
        );
        assert_no_nulls(&body["receipt"]);
        assert!(intyga_sdk::parse_timestamp(body["usedAt"].as_str().unwrap()).is_some());
    }
    let reported = bodies
        .iter()
        .find(|b| b["nonce"] == json!(first.nonce))
        .unwrap();
    assert_eq!(
        reported["receipt"]["canonicalPayload"],
        json!(first.receipt.canonical_payload)
    );

    // A second pass retries only what is still buffered, and an empty 2xx body still counts.
    let mut c =
        client(Scripted::new().on("POST", "/offline-approval/reconcile", vec![reply(204, "")]));
    let report = c.reconcile_offline_approvals(dir.path(), None).unwrap();
    assert_eq!(
        (report.reported, report.failed),
        (2, 1),
        "{:?}",
        report.reasons
    );
    assert!(pending_approvals(dir.path(), None).is_empty());
}

#[test]
fn reconciliation_needs_credentials_first() {
    let dir = bundle_dir("reconcile-creds");
    let mut c = Client::with_transport(
        ClientOptions {
            gateway_url: "https://gw.example".into(),
            ..Default::default()
        },
        Scripted::new(),
    )
    .unwrap();
    assert!(c.reconcile_offline_approvals(dir.path(), None).is_err());
}

#[test]
fn offline_approved_is_its_own_wire_status() {
    let s: ApprovalStatus = serde_json::from_value(json!("OFFLINE_APPROVED")).unwrap();
    assert_eq!(s, ApprovalStatus::OfflineApproved);
    assert_eq!(
        serde_json::to_value(ApprovalStatus::OfflineApproved).unwrap(),
        json!("OFFLINE_APPROVED")
    );
}
