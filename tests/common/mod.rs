//! Shared helpers for the offline-approval tests: the conformance vectors, approver keys derived
//! from their published seeds, and throwaway directories.
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::OnceLock;
use std::time::SystemTime;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use intyga_sdk::{encode_signature_envelope, parse_timestamp, ApprovalWitness};
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use p256::elliptic_curve::bigint::{Encoding, U256};
use p256::elliptic_curve::Curve;
use p256::pkcs8::EncodePublicKey;
use serde_json::Value;
use sha2::{Digest, Sha256};

/// The committed conformance file — never the generator, so an unreviewed behaviour change fails.
/// The `/vectors/` spelling is what scripts/build-public-tree.sh rewrites to the copy
/// vendored into the public sdk-rust repository.
const VECTORS: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/vectors/offline-approval-vectors.json"
);

pub fn v() -> &'static Value {
    static CELL: OnceLock<Value> = OnceLock::new();
    CELL.get_or_init(|| {
        let text = std::fs::read_to_string(VECTORS).expect("read offline-approval-vectors.json");
        serde_json::from_str(&text).expect("parse offline-approval-vectors.json")
    })
}

/// `keyDerivation`: d = (uint256_be(SHA-256(utf8(seed))) mod (n - 1)) + 1.
pub fn key_from_seed(seed: &str) -> SigningKey {
    let h = U256::from_be_slice(&Sha256::digest(seed.as_bytes()));
    let n_minus_1 = p256::NistP256::ORDER.wrapping_sub(&U256::ONE);
    // h < 2^256 < 2(n - 1), so one subtraction is the whole reduction.
    let reduced = if h >= n_minus_1 {
        h.wrapping_sub(&n_minus_1)
    } else {
        h
    };
    let d = reduced.wrapping_add(&U256::ONE);
    SigningKey::from_slice(&d.to_be_bytes()).expect("a valid P-256 scalar")
}

pub fn spki_of(key: &SigningKey) -> String {
    let der = p256::PublicKey::from(key.verifying_key())
        .to_public_key_der()
        .expect("encode SPKI");
    STANDARD.encode(der.as_bytes())
}

pub fn person(id: &str) -> &'static Value {
    &v()["people"][id]
}

pub fn did_of(id: &str) -> String {
    person(id)["did"].as_str().expect("did").to_string()
}

pub fn seed_of(id: &str, kind: &str) -> &'static str {
    person(id)["keys"][kind]["seed"]
        .as_str()
        .unwrap_or_else(|| panic!("{id} has no {kind} key"))
}

pub fn spki_published(id: &str, kind: &str) -> &'static str {
    person(id)["keys"][kind]["spki"]
        .as_str()
        .unwrap_or_else(|| panic!("{id} has no {kind} key"))
}

/// ES256 over the UTF-8 payload, IEEE P1363, base64.
pub fn sign(id: &str, kind: &str, payload: &str) -> String {
    let signature: Signature = key_from_seed(seed_of(id, kind)).sign(payload.as_bytes());
    STANDARD.encode(signature.to_bytes())
}

/// A `SIG1:` envelope from `id`'s `kind` key, claiming `claim_did`'s identity.
pub fn sig1(id: &str, kind: &str, claim: &str, payload: &str) -> String {
    encode_signature_envelope(&ApprovalWitness {
        signer_did: did_of(claim),
        signer_public_key: spki_published(id, kind).to_string(),
        signature: sign(id, kind, payload),
        sig_alg: Some("ES256".into()),
        authenticator_data: None,
        client_data_json: None,
    })
}

pub fn at(s: &str) -> SystemTime {
    parse_timestamp(s).unwrap_or_else(|| panic!("not a timestamp: {s}"))
}

pub fn str_of(v: &Value) -> &str {
    v.as_str().expect("string")
}

/// A directory removed when dropped. Under `std::env::temp_dir()`, uniquely named per process.
pub struct TempDir(pub PathBuf);

impl TempDir {
    pub fn new(prefix: &str) -> Self {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let nanos = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default();
        let dir = std::env::temp_dir().join(format!(
            "intyga-sdk-rust-{prefix}-{}-{}-{nanos}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        TempDir(dir)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A bundle directory holding the vectors' signed bundle and pinned gateway key, as the reference
/// harness writes it.
pub fn bundle_dir(prefix: &str) -> TempDir {
    let dir = TempDir::new(prefix);
    std::fs::write(
        dir.path().join("trust-bundle.jws"),
        str_of(&v()["bundleJws"]),
    )
    .unwrap();
    std::fs::write(
        dir.path().join("gateway-key.jwk.json"),
        serde_json::to_string(&v()["gatewayJwk"]).unwrap(),
    )
    .unwrap();
    dir
}
