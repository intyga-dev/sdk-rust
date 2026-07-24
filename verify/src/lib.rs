use base64::{engine::general_purpose::STANDARD, Engine as _};
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use p256::pkcs8::DecodePublicKey;
use p256::PublicKey;
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub mod ledger;
mod webauthn;

/// DIV protocol version (docs/DIV.md v1).
pub const DIV_VERSION: i64 = 1;
/// DIV Intent Payload `type` discriminator.
pub const DIV_INTENT_TYPE: &str = "div-intent-verification";
/// RECOMMENDED expiry tolerance in seconds (DIV §6.2).
pub const DEFAULT_CLOCK_SKEW_SECONDS: i64 = 30;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RequesterAttestation {
    pub method: String,
    pub issuer: String,
    pub subject: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RequesterIdentity {
    pub did: String,
    pub attestation: Option<RequesterAttestation>,
}

/// A DIV Proof Envelope: the signed canonical payload plus the signature metadata needed to verify
/// it (extended with the WebAuthn assertion components).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalReceipt {
    #[serde(rename = "canonicalPayload")]
    pub canonical_payload: String,
    /// The intended execution target (display/telemetry only; the RP asserts its own via Expected).
    #[serde(default)]
    pub target: Option<String>,
    #[serde(rename = "actionType")]
    pub action_type: Option<String>,
    /// The DIV `display` field.
    #[serde(rename = "actionDescription")]
    pub action_description: String,
    pub params: Value,
    #[serde(rename = "signerDid")]
    pub signer_did: Option<String>,
    #[serde(rename = "signerPublicKey")]
    pub signer_public_key: Option<String>,
    pub signature: Option<String>,
    #[serde(rename = "sigAlg")]
    pub sig_alg: Option<String>,
    #[serde(rename = "authenticatorData")]
    pub authenticator_data: Option<String>,
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: Option<String>,
    pub requester: Option<RequesterIdentity>,
    #[serde(rename = "verificationCode")]
    pub verification_code: String,
}

/// What the relying party asserts. `target` and `nonce` come from the RP's own state — never read
/// from the receipt (DIV Target Isolation + replay binding).
pub struct Expected {
    pub target: String,
    pub nonce: String,
    pub action_type: String,
    pub params: Value,
}

/// Relying-party context required to verify certain receipts. The WebAuthn expectations are
/// mandatory for a WEBAUTHN receipt: without a pinned origin and RP ID, an assertion harvested
/// at any relying party would verify.
#[derive(Debug, Clone, Default)]
pub struct VerifyOptions {
    /// Opt in to attesting policy AUTO_APPROVED receipts, which carry no human signature.
    /// Off by default: such receipts fail closed.
    pub allow_auto_approved: bool,
    /// Exact origin the assertion must carry, e.g. "https://app.example.com".
    pub expected_origin: Option<String>,
    /// RP ID the authenticatorData must hash to, e.g. "app.example.com".
    pub expected_rp_id: Option<String>,
    /// Demand the User-Verified flag (biometric/PIN). Defaults to true when None.
    pub require_user_verification: Option<bool>,
    /// Opt out of the fail-closed expiry check (DIV §5.8) for post-hoc audit re-verification.
    pub allow_expired: bool,
    /// Wall-clock instant (unix seconds) to evaluate expiry against. None = system time now.
    pub as_of_unix_secs: Option<i64>,
    /// Clock-skew tolerance in seconds. None = DEFAULT_CLOCK_SKEW_SECONDS.
    pub clock_skew_seconds: Option<i64>,
}

/// Recursively stringify JSON values with UTF-16 sorted keys to match JS/Python byte-for-byte.
pub fn stable_stringify(value: &Value) -> String {
    match value {
        Value::Null => "null".to_string(),
        Value::Bool(b) => {
            if *b {
                "true".to_string()
            } else {
                "false".to_string()
            }
        }
        Value::Number(n) => n.to_string(),
        Value::String(s) => serde_json::to_string(s).unwrap_or_else(|_| "null".to_string()),
        Value::Array(arr) => {
            let elems: Vec<String> = arr.iter().map(stable_stringify).collect();
            format!("[{}]", elems.join(","))
        }
        Value::Object(obj) => {
            let mut keys: Vec<&String> = obj.keys().collect();
            keys.sort_by(|a, b| {
                let u1: Vec<u16> = a.encode_utf16().collect();
                let u2: Vec<u16> = b.encode_utf16().collect();
                u1.cmp(&u2)
            });
            let parts: Vec<String> = keys
                .into_iter()
                .map(|k| {
                    let k_str = serde_json::to_string(k).unwrap();
                    let v_str = stable_stringify(&obj[k]);
                    format!("{}:{}", k_str, v_str)
                })
                .collect();
            format!("{{{}}}", parts.join(","))
        }
    }
}

/// Build a byte-identical DIV Intent Payload (docs/DIV.md v1) matching TypeScript, Go and Python.
/// Builds the full object and serializes it via [`stable_stringify`] (strict RFC 8785 JCS — every
/// key sorted). Do NOT hand-template key order; the sort is the contract.
pub fn canonical_intent_payload(
    target: &str,
    action_type: &str,
    display: &str,
    params: &Value,
    requester: &RequesterIdentity,
    nonce: &str,
    expires_at: &str,
) -> String {
    let attestation = match &requester.attestation {
        None => Value::Null,
        Some(a) => serde_json::json!({
            "method": a.method,
            "issuer": a.issuer,
            "subject": a.subject,
        }),
    };
    let obj = serde_json::json!({
        "v": DIV_VERSION,
        "type": DIV_INTENT_TYPE,
        "target": target,
        "actionType": action_type,
        "display": display,
        "params": params,
        "requester": { "did": requester.did, "attestation": attestation },
        "nonce": nonce,
        "expiresAt": expires_at,
    });
    stable_stringify(&obj)
}

/// Read a string field out of the canonical payload JSON, or None.
fn canonical_str_field(canonical: &str, key: &str) -> Option<String> {
    serde_json::from_str::<Value>(canonical)
        .ok()
        .and_then(|v| v.get(key).and_then(|x| x.as_str().map(String::from)))
}

/// Parse an RFC3339 UTC timestamp (`YYYY-MM-DDTHH:MM:SS[.fff]Z`) to unix seconds. UTC only (DIV
/// mandates UTC `expiresAt`); returns None on any other shape. Zero external dependencies.
fn parse_rfc3339_utc_secs(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    // Minimum: "YYYY-MM-DDTHH:MM:SSZ" = 20 chars, must end in Z.
    if b.len() < 20 || *b.last()? != b'Z' {
        return None;
    }
    if b[4] != b'-' || b[7] != b'-' || (b[10] != b'T' && b[10] != b't') || b[13] != b':' || b[16] != b':' {
        return None;
    }
    let year: i64 = s.get(0..4)?.parse().ok()?;
    let month: i64 = s.get(5..7)?.parse().ok()?;
    let day: i64 = s.get(8..10)?.parse().ok()?;
    let hour: i64 = s.get(11..13)?.parse().ok()?;
    let min: i64 = s.get(14..16)?.parse().ok()?;
    let sec: i64 = s.get(17..19)?.parse().ok()?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || min > 59 || sec > 60 {
        return None;
    }
    // days_from_civil (Howard Hinnant), then seconds. Fractional seconds are floored (ignored).
    let y = year - if month <= 2 { 1 } else { 0 };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400;
    let mp = if month > 2 { month - 3 } else { month + 9 };
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    Some(days * 86400 + hour * 3600 + min * 60 + sec)
}

fn now_unix_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Verify an ApprovalReceipt offline (ES256 receipts; WebAuthn receipts fail closed here).
///
/// This is the convenience entry point; use [`verify_approval_receipt_with_options`] to attest
/// WEBAUTHN receipts (which require a pinned origin and RP ID) or policy AUTO_APPROVED receipts.
pub fn verify_approval_receipt(
    receipt: &ApprovalReceipt,
    expected: &Expected,
) -> Result<(), String> {
    verify_approval_receipt_with_options(receipt, expected, &VerifyOptions::default())
}

/// Verify an ApprovalReceipt offline, with relying-party context.
///
/// Recomputes the canonical payload from the caller's own params, confirms it byte-matches what
/// was signed, and verifies the human's ES256 or WebAuthn signature. A WEBAUTHN receipt requires
/// `opts.expected_origin` and `opts.expected_rp_id`.
pub fn verify_approval_receipt_with_options(
    receipt: &ApprovalReceipt,
    expected: &Expected,
    opts: &VerifyOptions,
) -> Result<(), String> {
    if receipt.canonical_payload.is_empty() {
        return Err("missing canonicalPayload".to_string());
    }

    // Version / type / nonce gate.
    let probe: Value = serde_json::from_str(&receipt.canonical_payload)
        .map_err(|_| "canonicalPayload is not valid JSON".to_string())?;
    if probe.get("v").and_then(Value::as_i64) != Some(DIV_VERSION) {
        return Err("unsupported DIV payload version".to_string());
    }
    if probe.get("type").and_then(Value::as_str) != Some(DIV_INTENT_TYPE) {
        return Err("payload is not a div-intent-verification".to_string());
    }
    let payload_nonce = canonical_str_field(&receipt.canonical_payload, "nonce").unwrap_or_default();
    if payload_nonce != expected.nonce {
        return Err("receipt is for a different challenge".to_string());
    }

    if let Some(alg) = &receipt.sig_alg {
        if alg == "AUTO_APPROVED" {
            if !opts.allow_auto_approved {
                return Err("AUTO_APPROVED receipts are refused by default".to_string());
            }
            return Ok(());
        }
    }

    let requester = receipt
        .requester
        .as_ref()
        .ok_or("receipt missing requester")?;

    let expires_at = canonical_str_field(&receipt.canonical_payload, "expiresAt")
        .filter(|s| !s.is_empty())
        .ok_or("receipt missing expiresAt")?;

    let recomputed = canonical_intent_payload(
        &expected.target,
        &expected.action_type,
        &receipt.action_description,
        &expected.params,
        requester,
        &payload_nonce,
        &expires_at,
    );

    if recomputed != receipt.canonical_payload {
        return Err("target/params/actionType do not match what was approved".to_string());
    }

    // Expiration (DIV §5.8/§6.2). Fail-closed by default; opt out only for audit re-verification.
    if !opts.allow_expired {
        let expiry = parse_rfc3339_utc_secs(&expires_at)
            .ok_or("expiresAt is not a valid RFC3339 UTC timestamp")?;
        let now = opts.as_of_unix_secs.unwrap_or_else(now_unix_secs);
        let skew = opts.clock_skew_seconds.unwrap_or(DEFAULT_CLOCK_SKEW_SECONDS);
        if now > expiry + skew {
            return Err("proof has expired (set allow_expired for audit re-verification)".to_string());
        }
    }

    let signature_b64 = receipt
        .signature
        .as_ref()
        .ok_or("missing signature or public key")?;
    let public_key_b64 = receipt
        .signer_public_key
        .as_ref()
        .ok_or("missing signature or public key")?;

    if receipt.sig_alg.as_deref() == Some("WEBAUTHN") {
        return webauthn::verify_webauthn(receipt, opts);
    }

    // ES256: the human's key signed the canonical payload bytes directly.
    let pub_bytes = STANDARD
        .decode(public_key_b64)
        .map_err(|_| "invalid signerPublicKey base64".to_string())?;
    let sig_bytes = STANDARD
        .decode(signature_b64)
        .map_err(|_| "invalid signature base64".to_string())?;
    let verifying_key = parse_p256_public_key(&pub_bytes)
        .ok_or_else(|| "failed to parse signerPublicKey".to_string())?;
    if verify_p256_signature(
        &verifying_key,
        receipt.canonical_payload.as_bytes(),
        &sig_bytes,
    ) {
        Ok(())
    } else {
        Err("signature does not verify against signer key".to_string())
    }
}

/// Parse a P-256 public key from base64-decoded bytes: SPKI (PKIX) DER first, then a raw SEC1
/// point (0x04‖x‖y). Returns None if the bytes are neither.
pub(crate) fn parse_p256_public_key(pub_bytes: &[u8]) -> Option<VerifyingKey> {
    PublicKey::from_public_key_der(pub_bytes)
        .map(|pk| VerifyingKey::from(&pk))
        .or_else(|_| VerifyingKey::from_sec1_bytes(pub_bytes))
        .ok()
}

/// Verify an ES256 (P-256 + SHA-256) signature over `message`, accepting either an ASN.1/DER or a
/// raw IEEE-P1363 (64-byte r‖s) encoding. The high-level Verifier hashes `message` with SHA-256.
pub(crate) fn verify_p256_signature(
    verifying_key: &VerifyingKey,
    message: &[u8],
    sig_bytes: &[u8],
) -> bool {
    let signature =
        match Signature::from_der(sig_bytes).or_else(|_| Signature::from_slice(sig_bytes)) {
            Ok(sig) => sig,
            Err(_) => return false,
        };
    verifying_key.verify(message, &signature).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ecdsa::signature::Signer;
    use p256::ecdsa::SigningKey;
    use p256::pkcs8::EncodePublicKey;
    use serde_json::json;

    // Deterministic signing key (fixed scalar) so the round-trip is reproducible
    // without an RNG. RFC 6979 makes the signature itself deterministic too.
    fn test_signing_key() -> SigningKey {
        SigningKey::from_slice(&[0x11u8; 32]).expect("valid P-256 scalar")
    }

    fn signed_receipt() -> (ApprovalReceipt, Expected) {
        let requester = RequesterIdentity {
            did: "did:sakra:service:deploy-pipeline".to_string(),
            attestation: None,
        };
        let params = json!({ "environment": "staging" });
        // Far-future expiry so the fail-closed expiry check (DIV §5.8) passes without being
        // time-dependent; expiry itself is exercised by test_expiry_* below.
        let canonical = canonical_intent_payload(
            "prod-db-cluster-01",
            "deleteDatabase",
            "Delete staging database",
            &params,
            &requester,
            "c_8f91a2",
            "2999-01-01T00:00:00.000Z",
        );

        let sk = test_signing_key();
        let sig: Signature = sk.sign(canonical.as_bytes());
        let spki = sk.verifying_key().to_public_key_der().expect("encode SPKI");

        let receipt = ApprovalReceipt {
            canonical_payload: canonical,
            target: Some("prod-db-cluster-01".to_string()),
            action_type: Some("deleteDatabase".to_string()),
            action_description: "Delete staging database".to_string(),
            params: params.clone(),
            signer_did: Some("did:sakra:user:alice".to_string()),
            signer_public_key: Some(STANDARD.encode(spki.as_bytes())),
            signature: Some(STANDARD.encode(sig.to_der().as_bytes())),
            sig_alg: Some("ES256".to_string()),
            authenticator_data: None,
            client_data_json: None,
            requester: Some(requester),
            verification_code: "1234".to_string(),
        };
        let expected = Expected {
            target: "prod-db-cluster-01".to_string(),
            nonce: "c_8f91a2".to_string(),
            action_type: "deleteDatabase".to_string(),
            params,
        };
        (receipt, expected)
    }

    #[test]
    fn test_valid_signature_verifies() {
        let (receipt, expected) = signed_receipt();
        assert_eq!(verify_approval_receipt(&receipt, &expected), Ok(()));
    }

    #[test]
    fn test_valid_signature_verifies_with_raw_p1363() {
        // Same key/message, but present the signature as raw 64-byte r‖s.
        let (mut receipt, expected) = signed_receipt();
        let sk = test_signing_key();
        let sig: Signature = sk.sign(receipt.canonical_payload.as_bytes());
        receipt.signature = Some(STANDARD.encode(sig.to_bytes()));
        assert_eq!(verify_approval_receipt(&receipt, &expected), Ok(()));
    }

    #[test]
    fn test_forged_signature_is_rejected() {
        let (mut receipt, expected) = signed_receipt();
        receipt.signature = Some(STANDARD.encode(b"forged-signature-total-garbage"));
        assert!(verify_approval_receipt(&receipt, &expected).is_err());
    }

    #[test]
    fn test_valid_signature_wrong_key_is_rejected() {
        // A well-formed signature that simply was not made over this payload:
        // flip the signed message but keep the (now stale) signature.
        let (mut receipt, expected) = signed_receipt();
        let sk = test_signing_key();
        let other: Signature = sk.sign(b"a completely different message");
        receipt.signature = Some(STANDARD.encode(other.to_der().as_bytes()));
        assert_eq!(
            verify_approval_receipt(&receipt, &expected),
            Err("signature does not verify against signer key".to_string())
        );
    }

    #[test]
    fn test_tampered_params_are_rejected() {
        // Approver signed environment=staging; relying party checks production.
        let (receipt, _) = signed_receipt();
        let expected = Expected {
            target: "prod-db-cluster-01".to_string(),
            nonce: "c_8f91a2".to_string(),
            action_type: "deleteDatabase".to_string(),
            params: json!({ "environment": "production" }),
        };
        assert_eq!(
            verify_approval_receipt(&receipt, &expected),
            Err("target/params/actionType do not match what was approved".to_string())
        );
    }

    #[test]
    fn test_auto_approved_is_refused() {
        let (mut receipt, expected) = signed_receipt();
        receipt.sig_alg = Some("AUTO_APPROVED".to_string());
        assert_eq!(
            verify_approval_receipt(&receipt, &expected),
            Err("AUTO_APPROVED receipts are refused by default".to_string())
        );
    }

    // Drive the current-version receipts from the shared cross-language golden vectors
    // (packages/mcp-schemas/vectors/canonical-vectors.json), the same file the Python and TS
    // suites consume. The verifier targets the single current canonical version; legacy v2 and
    // WebAuthn vectors are skipped here (WebAuthn is exercised separately).
    #[test]
    fn test_shared_golden_receipt_vectors() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/vectors/canonical-vectors.json"
        );
        let raw = std::fs::read_to_string(path).expect("read golden vectors");
        let doc: Value = serde_json::from_str(&raw).expect("parse golden vectors");
        let receipts = doc["receipts"].as_array().expect("receipts array");

        let mut checked = 0;
        for entry in receipts {
            let name = entry["name"].as_str().unwrap_or("<unnamed>");
            let sig_alg = entry["receipt"]["sigAlg"].as_str().unwrap_or("");
            let canonical = entry["receipt"]["canonicalPayload"].as_str().unwrap_or("");
            // Skip WebAuthn (tested separately) and any non-current canonical version.
            if sig_alg == "WEBAUTHN"
                || (sig_alg != "AUTO_APPROVED" && canonical_version(canonical) != DIV_VERSION)
            {
                continue;
            }
            let receipt: ApprovalReceipt =
                serde_json::from_value(entry["receipt"].clone()).expect("deserialize receipt");
            let expect_ok = entry["expectOk"].as_bool().unwrap_or(false);

            let expected = Expected {
                target: receipt.target.clone().unwrap_or_default(),
                nonce: parse_nonce(&receipt.canonical_payload),
                action_type: receipt.action_type.clone().unwrap_or_default(),
                params: receipt.params.clone(),
            };

            let result = verify_approval_receipt(&receipt, &expected);
            assert_eq!(
                result.is_ok(),
                expect_ok,
                "vector '{}' expected ok={} but got {:?}",
                name,
                expect_ok,
                result
            );
            checked += 1;
        }
        assert!(
            checked >= 3,
            "expected to exercise the current-version vectors, ran {}",
            checked
        );
    }

    fn canonical_version(canonical: &str) -> i64 {
        serde_json::from_str::<Value>(canonical)
            .ok()
            .and_then(|v| v.get("v").and_then(Value::as_i64))
            .unwrap_or(0)
    }

    fn parse_nonce(canonical: &str) -> String {
        serde_json::from_str::<Value>(canonical)
            .ok()
            .and_then(|v| v.get("nonce").and_then(|n| n.as_str().map(String::from)))
            .unwrap_or_default()
    }

    // ── WebAuthn: shared cross-language golden fixture ──────────────────────────────
    // packages/mcp-schemas/vectors/webauthn-vector.json is generated by an authenticator
    // simulation and validated by the Python reference verifier; Go and Rust must agree.
    struct WaVector {
        rp_id: String,
        origin: String,
        expected: Expected,
        receipt: ApprovalReceipt,
    }

    fn load_webauthn_vector() -> WaVector {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/vectors/webauthn-vector.json"
        );
        let raw = std::fs::read_to_string(path).expect("read webauthn vector");
        let doc: Value = serde_json::from_str(&raw).expect("parse webauthn vector");
        let receipt: ApprovalReceipt =
            serde_json::from_value(doc["receipt"].clone()).expect("deserialize receipt");
        let expected = Expected {
            target: doc["expected"]["target"].as_str().unwrap().to_string(),
            nonce: doc["expected"]["nonce"].as_str().unwrap().to_string(),
            action_type: doc["expected"]["actionType"].as_str().unwrap().to_string(),
            params: doc["expected"]["params"].clone(),
        };
        WaVector {
            rp_id: doc["rpId"].as_str().unwrap().to_string(),
            origin: doc["origin"].as_str().unwrap().to_string(),
            expected,
            receipt,
        }
    }

    fn wa_opts(origin: Option<&str>, rp_id: Option<&str>) -> VerifyOptions {
        VerifyOptions {
            expected_origin: origin.map(String::from),
            expected_rp_id: rp_id.map(String::from),
            ..Default::default()
        }
    }

    #[test]
    fn test_webauthn_valid_vector() {
        let v = load_webauthn_vector();
        let res = verify_approval_receipt_with_options(
            &v.receipt,
            &v.expected,
            &wa_opts(Some(&v.origin), Some(&v.rp_id)),
        );
        assert_eq!(res, Ok(()), "valid WebAuthn receipt should verify");
    }

    #[test]
    fn test_webauthn_rejects_wrong_origin() {
        let v = load_webauthn_vector();
        let res = verify_approval_receipt_with_options(
            &v.receipt,
            &v.expected,
            &wa_opts(Some("https://evil.example.com"), Some(&v.rp_id)),
        );
        assert!(res.is_err(), "wrong origin must not verify");
    }

    #[test]
    fn test_webauthn_rejects_wrong_rp_id() {
        let v = load_webauthn_vector();
        let res = verify_approval_receipt_with_options(
            &v.receipt,
            &v.expected,
            &wa_opts(Some(&v.origin), Some("evil.example.com")),
        );
        assert!(res.is_err(), "wrong RP ID must not verify");
    }

    #[test]
    fn test_webauthn_fails_closed_without_pinning() {
        let v = load_webauthn_vector();
        let res = verify_approval_receipt_with_options(
            &v.receipt,
            &v.expected,
            &VerifyOptions::default(),
        );
        assert!(
            res.is_err(),
            "WebAuthn must fail closed without origin/rp_id"
        );
    }

    #[test]
    fn test_webauthn_rejects_forged_signature() {
        let mut v = load_webauthn_vector();
        v.receipt.signature = Some(STANDARD.encode(b"forged-signature-total-garbage"));
        let res = verify_approval_receipt_with_options(
            &v.receipt,
            &v.expected,
            &wa_opts(Some(&v.origin), Some(&v.rp_id)),
        );
        assert!(res.is_err(), "forged WebAuthn signature must not verify");
    }

    #[test]
    fn test_webauthn_rejects_tampered_params() {
        let v = load_webauthn_vector();
        let tampered = Expected {
            target: v.expected.target.clone(),
            nonce: v.expected.nonce.clone(),
            action_type: v.expected.action_type.clone(),
            params: json!({ "amount": 999999 }),
        };
        let res = verify_approval_receipt_with_options(
            &v.receipt,
            &tampered,
            &wa_opts(Some(&v.origin), Some(&v.rp_id)),
        );
        assert!(res.is_err(), "tampered params must not verify");
    }

    #[test]
    fn test_canonical_intent_parity() {
        let params = json!({
            "zeta": 1,
            "alpha": 2,
            "mid": { "z": 1, "a": 2 }
        });
        let requester = RequesterIdentity {
            did: "did:sakra:service:deploy-pipeline".to_string(),
            attestation: None,
        };
        let got = canonical_intent_payload(
            "prod-db-cluster-01",
            "deleteDatabase",
            "Delete staging database",
            &params,
            &requester,
            "c_8f91a2",
            "2026-07-23T19:30:00Z",
        );
        // Strict RFC 8785 JCS: every key sorted; type/version last.
        let expected = r#"{"actionType":"deleteDatabase","display":"Delete staging database","expiresAt":"2026-07-23T19:30:00Z","nonce":"c_8f91a2","params":{"alpha":2,"mid":{"a":2,"z":1},"zeta":1},"requester":{"attestation":null,"did":"did:sakra:service:deploy-pipeline"},"target":"prod-db-cluster-01","type":"div-intent-verification","v":1}"#;
        assert_eq!(got, expected);
    }

    #[test]
    fn test_expiry_fail_closed_and_allow_expired() {
        // Build a receipt that expired in 2020.
        let requester = RequesterIdentity {
            did: "did:sakra:service:deploy-pipeline".to_string(),
            attestation: None,
        };
        let params = json!({ "environment": "staging" });
        let canonical = canonical_intent_payload(
            "prod-db-cluster-01",
            "deleteDatabase",
            "Delete staging database",
            &params,
            &requester,
            "c_exp",
            "2020-01-01T00:00:00.000Z",
        );
        let sk = test_signing_key();
        let sig: Signature = sk.sign(canonical.as_bytes());
        let spki = sk.verifying_key().to_public_key_der().expect("encode SPKI");
        let receipt = ApprovalReceipt {
            canonical_payload: canonical,
            target: Some("prod-db-cluster-01".to_string()),
            action_type: Some("deleteDatabase".to_string()),
            action_description: "Delete staging database".to_string(),
            params: params.clone(),
            signer_did: None,
            signer_public_key: Some(STANDARD.encode(spki.as_bytes())),
            signature: Some(STANDARD.encode(sig.to_der().as_bytes())),
            sig_alg: Some("ES256".to_string()),
            authenticator_data: None,
            client_data_json: None,
            requester: Some(requester),
            verification_code: "1234".to_string(),
        };
        let expected = Expected {
            target: "prod-db-cluster-01".to_string(),
            nonce: "c_exp".to_string(),
            action_type: "deleteDatabase".to_string(),
            params,
        };
        // Fail-closed by default.
        assert!(verify_approval_receipt(&receipt, &expected).is_err());
        // allow_expired accepts the otherwise-valid proof (audit re-verification).
        let opts = VerifyOptions { allow_expired: true, ..Default::default() };
        assert_eq!(
            verify_approval_receipt_with_options(&receipt, &expected, &opts),
            Ok(())
        );
    }

    #[test]
    fn test_rfc3339_parser() {
        assert_eq!(parse_rfc3339_utc_secs("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_rfc3339_utc_secs("2020-01-01T00:00:00.000Z"), Some(1_577_836_800));
        assert_eq!(parse_rfc3339_utc_secs("not-a-date"), None);
        assert_eq!(parse_rfc3339_utc_secs("2020-01-01T00:00:00+02:00"), None); // UTC only
    }
}
