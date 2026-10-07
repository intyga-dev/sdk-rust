//! The customer-authored trust-anchor file — a port of `packages/sdk/src/trust-anchor.ts`.
//!
//! This file IS the relying party's pinning (DIV §4.4.6, identity-associating anchor): it names the
//! approver identities that may sign and, for each, the public keys that speak for it. Unlike the
//! offline trust bundle, which travels through the gateway and is therefore gateway-SIGNED, it carries
//! no signature: adopting the file into your configuration is itself the act of trust, like pinning
//! a CA bundle.
//!
//! An anchor has a PURPOSE. `online` pins passkeys and node keys and verifies ordinary approval
//! receipts; `offline` pins offline signing keys only and verifies DIV §5a offline approvals. Two
//! files, never one: a bare offline key — no origin binding, no user verification — must not satisfy
//! a relying party that verifies online approvals.

use std::collections::HashMap;

use intyga_verify::{ApproverTrustAnchor, SELF_CERTIFYING_DID_PREFIX};
use serde_json::Value;

use crate::trust_bundle::BundleApprover;

/// The file's `type` discriminator.
pub const TRUST_ANCHOR_FILE_TYPE: &str = "intyga-trust-anchor";

/// What an anchor is FOR, and so which keys it may pin. A file with no `purpose` predates the field
/// and reads as `Online`, which is also what a caller that does not think about it gets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TrustAnchorPurpose {
    #[default]
    Online,
    Offline,
}

impl TrustAnchorPurpose {
    /// The spelling in the file.
    pub fn as_str(self) -> &'static str {
        match self {
            TrustAnchorPurpose::Online => "online",
            TrustAnchorPurpose::Offline => "offline",
        }
    }
}

/// The WebAuthn expectations of the approval console the approvers sign in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebAuthnExpectation {
    pub origin: String,
    pub rp_id: String,
}

/// A parsed, validated trust-anchor file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustAnchorFile {
    /// Always set after parsing; absent in the file means `Online`.
    pub purpose: TrustAnchorPurpose,
    /// Monotonic export counter. Lets a human diffing two copies see which is older; it carries no
    /// cryptographic weight.
    pub epoch: u64,
    /// What the export was scoped to. Display only.
    pub label: Option<String>,
    /// The approver identities this relying party trusts. Only `did` and `public_keys` are read.
    pub approvers: Vec<BundleApprover>,
    /// Passkey receipts cannot verify without these, so exports SHOULD carry them.
    pub webauthn: Option<WebAuthnExpectation>,
    pub exported_at: Option<String>,
}

fn fail<T>(detail: impl std::fmt::Display) -> Result<T, String> {
    Err(format!("invalid trust-anchor file: {detail}"))
}

fn js(value: Option<&Value>) -> String {
    match value {
        None => "undefined".into(),
        Some(v) => v.to_string(),
    }
}

/// Base64 or base64url that decodes to at least one byte (Node's reading of it).
fn is_base64(s: &str) -> bool {
    let body = s.trim_end_matches('=');
    if s.len() - body.len() > 2 || body.is_empty() {
        return false;
    }
    if !body
        .bytes()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'+' | b'/' | b'_' | b'-'))
    {
        return false;
    }
    // Node drops a trailing partial sextet; anything from two characters up yields a byte.
    body.len() >= 2
}

/// Parse and validate a trust-anchor file, refusing with a precise, single-problem reason — a trust
/// anchor is security configuration, so a malformed one must fail at load time rather than surface
/// later as an unverifiable receipt.
///
/// `purpose` is what the CALLER is about to verify, and the file must say the same: an offline anchor
/// handed to an online verifier (or the reverse) is refused rather than trusted.
pub fn parse_trust_anchor_file(
    json_text: &str,
    purpose: TrustAnchorPurpose,
) -> Result<TrustAnchorFile, String> {
    let raw: Value = match serde_json::from_str(json_text) {
        Ok(v) => v,
        Err(e) => return fail(format!("not valid JSON ({e})")),
    };
    let Some(obj) = raw.as_object() else {
        return fail("root must be an object");
    };

    if obj.get("type").and_then(Value::as_str) != Some(TRUST_ANCHOR_FILE_TYPE) {
        return fail(format!(
            "type must be \"{TRUST_ANCHOR_FILE_TYPE}\" — a div-trust-bundle JWS (offline approval) is a different, gateway-signed artifact and cannot be used here"
        ));
    }
    if obj.get("v").and_then(Value::as_f64) != Some(1.0) {
        return fail(format!(
            "unsupported version {} (expected 1)",
            js(obj.get("v"))
        ));
    }
    let file_purpose = match obj.get("purpose") {
        None => TrustAnchorPurpose::Online,
        Some(Value::String(s)) if s == "online" => TrustAnchorPurpose::Online,
        Some(Value::String(s)) if s == "offline" => TrustAnchorPurpose::Offline,
        Some(other) => {
            return fail(format!(
                "purpose must be \"online\" or \"offline\", got {other}"
            ))
        }
    };
    if file_purpose != purpose {
        return fail(format!(
            "this is an {} anchor, but it is being loaded to verify {} approvals — export the {} anchor instead",
            file_purpose.as_str(),
            purpose.as_str(),
            purpose.as_str()
        ));
    }
    let epoch = match obj.get("epoch") {
        Some(Value::Number(n)) => n.as_u64().or_else(|| {
            n.as_f64()
                .filter(|f| f.fract() == 0.0 && *f >= 0.0 && *f <= u64::MAX as f64)
                .map(|f| f as u64)
        }),
        _ => None,
    };
    let Some(epoch) = epoch else {
        return fail("epoch must be a non-negative integer");
    };
    let label = match obj.get("label") {
        None => None,
        Some(Value::String(s)) => Some(s.clone()),
        Some(_) => return fail("label must be a string"),
    };
    let exported_at = match obj.get("exportedAt") {
        None => None,
        Some(Value::String(s)) => Some(s.clone()),
        Some(_) => return fail("exportedAt must be a string"),
    };

    let entries = match obj.get("approvers").and_then(Value::as_array) {
        Some(a) if !a.is_empty() => a,
        _ => {
            return fail("approvers must be a non-empty array — an empty anchor would trust nobody")
        }
    };
    let mut approvers: Vec<BundleApprover> = Vec::with_capacity(entries.len());
    for entry in entries {
        let Some(entry) = entry.as_object() else {
            return fail("every approvers[] entry must be an object");
        };
        let did = match entry.get("did") {
            Some(Value::String(d)) if d.starts_with("did:") => d.clone(),
            other => {
                return fail(format!(
                    "approver did {} must be a string starting with \"did:\"",
                    js(other)
                ))
            }
        };
        if approvers.iter().any(|a| a.did == did) {
            return fail(format!("duplicate approver did {did}"));
        }
        let Some(keys) = entry.get("publicKeys").and_then(Value::as_array) else {
            return fail(format!("approver {did}: publicKeys must be an array"));
        };
        let mut public_keys = Vec::with_capacity(keys.len());
        for key in keys {
            match key.as_str() {
                Some(k) if is_base64(k) => public_keys.push(k.to_string()),
                _ => {
                    return fail(format!(
                        "approver {did}: every publicKeys[] entry must be a base64 SPKI or COSE key"
                    ))
                }
            }
        }
        // A stable DID with no keys can never satisfy verification — refuse at load, where the
        // problem is diagnosable. Self-certifying DIDs are the deliberate exception online (their key
        // travels in the receipt and is checked by hash); an offline anchor has none, because a DID
        // commits to its ONLINE key, not to an offline signing key its owner chose to register.
        if public_keys.is_empty() && file_purpose == TrustAnchorPurpose::Offline {
            return fail(format!(
                "approver {did} has no publicKeys — an offline anchor must pin every offline key"
            ));
        }
        if public_keys.is_empty() && !did.starts_with(SELF_CERTIFYING_DID_PREFIX) {
            return fail(format!(
                "approver {did} has no publicKeys and is not self-certifying ({SELF_CERTIFYING_DID_PREFIX}…) — a receipt from them could never verify"
            ));
        }
        approvers.push(BundleApprover {
            did,
            public_keys,
            offline_public_keys: None,
        });
    }

    let webauthn = match obj.get("webauthn") {
        None => None,
        Some(Value::Object(w)) => {
            let origin = match w.get("origin").and_then(Value::as_str) {
                Some(o) if o.starts_with("http://") || o.starts_with("https://") => o.to_string(),
                _ => return fail("webauthn.origin must be an http(s) origin string"),
            };
            let rp_id = match w.get("rpId").and_then(Value::as_str) {
                Some(r) if !r.is_empty() => r.to_string(),
                _ => return fail("webauthn.rpId must be a non-empty string"),
            };
            Some(WebAuthnExpectation { origin, rp_id })
        }
        Some(_) => return fail("webauthn must be an object"),
    };

    Ok(TrustAnchorFile {
        purpose: file_purpose,
        epoch,
        label,
        approvers,
        webauthn,
        exported_at,
    })
}

/// Build the verifier's trust anchor from a parsed file: DID mode, one identity per approver however
/// many keys they hold. `limit_to_dids` narrows the eligible set without widening anything. A
/// self-certifying DID with no listed keys resolves to none, which lets the verifier check the
/// receipt-carried key against the DID's own commitment.
pub fn trust_anchor_approvers(
    file: &TrustAnchorFile,
    limit_to_dids: Option<&[String]>,
) -> ApproverTrustAnchor {
    let mut dids = Vec::new();
    let mut by_did: HashMap<String, Vec<String>> = HashMap::new();
    for approver in file
        .approvers
        .iter()
        .filter(|a| limit_to_dids.is_none_or(|limit| limit.contains(&a.did)))
    {
        if !by_did.contains_key(&approver.did) {
            dids.push(approver.did.clone());
        }
        by_did.insert(approver.did.clone(), approver.public_keys.clone());
    }
    ApproverTrustAnchor::DidsMultiKey {
        dids,
        resolve: Box::new(move |did| by_did.get(did).cloned().unwrap_or_default()),
    }
}
