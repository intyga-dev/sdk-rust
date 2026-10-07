//! Offline trust bundle (docs/DIV.md §5a.4) — the relying party's local answer to "whose signature
//! counts, and what does policy require?" A port of `packages/sdk/src/trust-bundle.ts`.
//!
//! Offline verification needs two things the network normally supplies: the approver public keys
//! (DIV Invariant 3 forbids taking them from the proof under verification) and the approval
//! REQUIREMENT. The relying party builds its own offline challenge, so if it also invented the quorum
//! it would be setting its own policy. The bundle is the offline projection of the tenant's real
//! policy, exported while the gateway was reachable, signed with the gateway's existing OIDC key and
//! verified against that key as PINNED at export time — fetching it at incident time is both
//! impossible (offline) and pointless (a fetched key is only as good as the fetch).

use std::collections::HashMap;
use std::path::Path;
use std::time::SystemTime;

use intyga_verify::{ApprovalRequirement, ApproverTrustAnchor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Number, Value};

use crate::approval_policy::{
    select_approval_rule, validate_exact_approval_policy, MAX_SAFE_INTEGER,
};
use crate::support::{
    b64_decode_lenient, ensure_private_dir, js_trim, now_ms, parse_rfc3339_ms, write_private_file,
};

/// Bundle `type` discriminator, inside the signed JWS payload.
pub const DIV_TRUST_BUNDLE_TYPE: &str = "div-trust-bundle-v1";

/// Hard ceiling on bundle age, enforced regardless of the `expiresAt` the gateway wrote. A stale
/// bundle is a stale approver set: a revoked approver stays trusted, and a tightened quorum stays
/// loose. Exactly 30 days is accepted.
pub const MAX_TRUST_BUNDLE_AGE_DAYS: i64 = 30;

const DAY_MS: i64 = 86_400_000;
const BUNDLE_FILE: &str = "trust-bundle.jws";
const KEY_FILE: &str = "gateway-key.jwk.json";

/// One approver and every public key bound to them at export time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BundleApprover {
    pub did: String,
    /// base64 SPKI (raw P-256) and/or base64 COSE (WebAuthn credential) keys — all this ONE approver.
    pub public_keys: Vec<String>,
    /// base64 SPKI offline signing keys (DIV §5a.4). They count ONLY toward a `div-offline-intent` —
    /// never a delegation or an ordinary intent — so they are kept apart from `public_keys`. See
    /// [`approver_anchor`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offline_public_keys: Option<Vec<String>>,
}

/// The tenant's decision for an action no exact rule names, covered by the bundle signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UnmatchedActionPolicy {
    /// Refuse it.
    #[serde(rename = "DENY")]
    Deny,
    /// Apply the `*` baseline rule.
    #[serde(rename = "BASELINE")]
    Baseline,
}

/// The approval requirement for one action ID (or `*`), as the gateway resolved and exported it.
/// Mirrors the gateway's `TrustBundlePolicyEntry` (apps/gateway/src/approvalMatch.ts).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BundlePolicy {
    /// Always `"human"` in a valid bundle (DIV §4.3.2).
    pub signer_class: String,
    /// Informational only; constraints are evaluated from the complete policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selection_rank: Option<Number>,
    /// Informational only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selection_key: Option<String>,
    /// Exact action ID, or `*` for the tenant baseline. Display text never selects a rule.
    pub action_pattern: String,
    #[serde(deserialize_with = "de_int")]
    pub required_approvals: i64,
    pub require_hardware_key: bool,
    pub allowed_aaguids: Vec<String>,
    pub requester_cannot_approve: bool,
    pub require_attested_requester: bool,
    pub allowed_issuers: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approver_group_ids: Option<Vec<String>>,
    pub escalation_approver_dids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub escalation_group_ids: Option<Vec<String>>,
    #[serde(default, deserialize_with = "de_opt_int")]
    pub escalate_after_seconds: Option<i64>,
    #[serde(default)]
    pub auto_approve_requester_did: Option<String>,
    #[serde(default, deserialize_with = "de_opt_int")]
    pub auto_approve_day_of_week: Option<i64>,
    #[serde(default)]
    pub auto_approve_window_start: Option<String>,
    #[serde(default)]
    pub auto_approve_window_end: Option<String>,
    /// Which approvers are eligible for THIS pattern. A subset of the bundle's `approvers`.
    pub approver_dids: Vec<String>,
}

/// A verified trust bundle (the JWS payload).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrustBundle {
    #[serde(deserialize_with = "de_int")]
    pub v: i64,
    #[serde(rename = "type")]
    pub bundle_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    pub approvers: Vec<BundleApprover>,
    pub policy: Vec<BundlePolicy>,
    pub unmatched_action_policy: UnmatchedActionPolicy,
    pub issued_at: String,
    pub expires_at: String,
}

/// What [`save_trust_bundle`] writes and [`load_trust_bundle`] reads: the bundle JWS plus the key it
/// must be verified against.
#[derive(Debug, Clone, PartialEq)]
pub struct TrustBundleFiles {
    /// Compact JWS produced by the gateway.
    pub jws: String,
    /// The gateway public key, as a JWK, PINNED when the bundle was exported.
    pub gateway_jwk: Value,
}

/// What a bundle anchor will verify.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BundleAnchorPurpose {
    /// `publicKeys` only — what a delegation or an ordinary intent is checked against.
    #[default]
    Ordinary,
    /// Also `offlinePublicKeys` — only for verifying a `div-offline-intent` proof.
    OfflineIntent,
}

/// The requirement the bundle imposes on one action, plus who may approve it.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResolvedRequirement {
    pub requirement: ApprovalRequirement,
    pub approver_dids: Vec<String>,
}

// ---------------------------------------------------------------------------------------------
// Integers: the reference's are JavaScript numbers, so 2 and 2.0 are the same value.
// ---------------------------------------------------------------------------------------------

fn number_to_i64(n: &Number) -> Option<i64> {
    n.as_i64().or_else(|| {
        n.as_f64()
            .filter(|f| f.fract() == 0.0 && f.abs() <= MAX_SAFE_INTEGER as f64)
            .map(|f| f as i64)
    })
}

/// `Number.isSafeInteger` over a JSON value.
fn safe_integer(v: &Value) -> Option<i64> {
    match v {
        Value::Number(n) => {
            number_to_i64(n).filter(|n| n.unsigned_abs() <= MAX_SAFE_INTEGER.unsigned_abs())
        }
        _ => None,
    }
}

fn de_int<'de, D: Deserializer<'de>>(d: D) -> Result<i64, D::Error> {
    let n = Number::deserialize(d)?;
    number_to_i64(&n).ok_or_else(|| serde::de::Error::custom("expected an integer"))
}

fn de_opt_int<'de, D: Deserializer<'de>>(d: D) -> Result<Option<i64>, D::Error> {
    Option::<Number>::deserialize(d)?
        .map(|n| number_to_i64(&n).ok_or_else(|| serde::de::Error::custom("expected an integer")))
        .transpose()
}

/// Blank under JavaScript's `String.prototype.trim` (see `support::js_trim`).
fn js_blank(s: &str) -> bool {
    js_trim(s).is_empty()
}

// ---------------------------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------------------------

fn pinned_rsa_key(jwk: &Value) -> Result<rsa::RsaPublicKey, String> {
    let obj = jwk.as_object().ok_or("the JWK is not a JSON object")?;
    if obj.get("kty").and_then(Value::as_str) != Some("RSA") {
        return Err("the JWK is not an RSA key (kty must be \"RSA\")".into());
    }
    let part = |name: &str| -> Result<rsa::BigUint, String> {
        let text = obj
            .get(name)
            .and_then(Value::as_str)
            .ok_or_else(|| format!("the JWK has no \"{name}\""))?;
        let bytes = b64_decode_lenient(text)
            .ok_or_else(|| format!("the JWK \"{name}\" is not base64url"))?;
        Ok(rsa::BigUint::from_bytes_be(&bytes))
    };
    // Up to 16384 bits: the crate's default 4096-bit ceiling would refuse a larger gateway key.
    rsa::RsaPublicKey::new_with_max_size(part("n")?, part("e")?, 16_384).map_err(|e| e.to_string())
}

fn rs256_verifies(key: rsa::RsaPublicKey, signing_input: &[u8], signature: &[u8]) -> bool {
    use rsa::signature::Verifier;
    let Ok(signature) = rsa::pkcs1v15::Signature::try_from(signature) else {
        return false;
    };
    rsa::pkcs1v15::VerifyingKey::<sha2::Sha256>::new(key)
        .verify(signing_input, &signature)
        .is_ok()
}

fn non_empty_strings(v: Option<&Value>) -> bool {
    v.and_then(Value::as_array)
        .is_some_and(|a| a.iter().all(|s| s.as_str().is_some_and(|s| !s.is_empty())))
}

fn valid_bundle_approver(a: &Value) -> bool {
    let Some(a) = a.as_object() else { return false };
    a.get("did")
        .and_then(Value::as_str)
        .is_some_and(|d| !d.is_empty())
        && a.get("publicKeys")
            .and_then(Value::as_array)
            .is_some_and(|k| !k.is_empty())
        && non_empty_strings(a.get("publicKeys"))
        // Optional, but when present (even as null) it must be a list of non-empty strings.
        && (a.get("offlinePublicKeys").is_none() || non_empty_strings(a.get("offlinePublicKeys")))
}

/// `validBundlePolicy` over the raw payload: a complete v1 policy entry. Raw rather than typed
/// because absent and `null` differ here — every nullable field must be PRESENT.
fn valid_bundle_policy_value(value: &Value) -> bool {
    let Some(p) = value.as_object() else {
        return false;
    };
    if p.get("signerClass").and_then(Value::as_str) != Some("human") {
        return false;
    }
    if !p
        .get("actionPattern")
        .and_then(Value::as_str)
        .is_some_and(|s| !js_blank(s))
        || !p
            .get("requiredApprovals")
            .and_then(safe_integer)
            .is_some_and(|n| n >= 1)
    {
        return false;
    }
    for field in [
        "requireHardwareKey",
        "requesterCannotApprove",
        "requireAttestedRequester",
    ] {
        if !p.get(field).is_some_and(Value::is_boolean) {
            return false;
        }
    }
    for field in [
        "approverDids",
        "allowedAaguids",
        "allowedIssuers",
        "escalationApproverDids",
    ] {
        if !non_empty_strings(p.get(field)) {
            return false;
        }
    }
    match p.get("escalateAfterSeconds") {
        Some(Value::Null) => {}
        Some(v) if safe_integer(v).is_some_and(|n| n >= 1) => {}
        _ => return false,
    }
    for field in [
        "autoApproveRequesterDid",
        "autoApproveWindowStart",
        "autoApproveWindowEnd",
    ] {
        if !matches!(p.get(field), Some(Value::Null) | Some(Value::String(_))) {
            return false;
        }
    }
    match p.get("autoApproveDayOfWeek") {
        Some(Value::Null) => true,
        Some(v) => safe_integer(v).is_some_and(|d| (0..=6).contains(&d)),
        None => false,
    }
}

/// The typed counterpart of [`valid_bundle_policy_value`], for a bundle built in code.
fn valid_bundle_policy(p: &BundlePolicy) -> bool {
    let strings_ok = |v: &[String]| v.iter().all(|s| !s.is_empty());
    p.signer_class == "human"
        && !js_blank(&p.action_pattern)
        && (1..=MAX_SAFE_INTEGER).contains(&p.required_approvals)
        && strings_ok(&p.approver_dids)
        && strings_ok(&p.allowed_aaguids)
        && strings_ok(&p.allowed_issuers)
        && strings_ok(&p.escalation_approver_dids)
        && p.escalate_after_seconds
            .is_none_or(|n| (1..=MAX_SAFE_INTEGER).contains(&n))
        && p.auto_approve_day_of_week
            .is_none_or(|d| (0..=6).contains(&d))
}

/// Verify a compact JWS bundle against a PINNED gateway key, and its freshness at `as_of` (default:
/// now). Returns the bundle, or the reason it is refused.
///
/// Only RS256 is accepted, and the `alg` header is checked against that fixed expectation rather than
/// used to select an algorithm: trusting the token's own `alg` is the classic JWS confusion bug —
/// `none` would skip verification, and an HMAC alg would verify a MAC keyed with the public key.
pub fn verify_trust_bundle(
    jws: &str,
    gateway_jwk: &Value,
    as_of: Option<SystemTime>,
) -> Result<TrustBundle, String> {
    let parts: Vec<&str> = jws.split('.').collect();
    let [header_b64, payload_b64, sig_b64] = parts[..] else {
        return Err("trust bundle is not a compact JWS".into());
    };

    let header: Value = b64_decode_lenient(header_b64)
        .and_then(|b| serde_json::from_slice(&b).ok())
        .ok_or("trust bundle header is not JSON")?;
    let Some(header) = header.as_object() else {
        return Err("invalid trust bundle header".into());
    };
    match header.get("alg").and_then(Value::as_str) {
        Some("RS256") => {}
        other => {
            return Err(format!(
                "trust bundle alg must be RS256, got {}",
                other.unwrap_or("(none)")
            ))
        }
    }

    let key = pinned_rsa_key(gateway_jwk)
        .map_err(|why| format!("pinned gateway key is unusable: {why}"))?;
    let signature = b64_decode_lenient(sig_b64).unwrap_or_default();
    let signing_input = format!("{header_b64}.{payload_b64}");
    if !rs256_verifies(key, signing_input.as_bytes(), &signature) {
        return Err("trust bundle signature does not verify against the pinned gateway key".into());
    }

    let payload: Value = b64_decode_lenient(payload_b64)
        .and_then(|b| serde_json::from_str(&String::from_utf8_lossy(&b)).ok())
        .ok_or("trust bundle payload is not JSON")?;
    let Some(raw) = payload.as_object() else {
        return Err("invalid trust bundle payload".into());
    };
    if raw.get("type").and_then(Value::as_str) != Some(DIV_TRUST_BUNDLE_TYPE)
        || raw.get("v").and_then(Value::as_f64) != Some(1.0)
    {
        return Err("unsupported trust bundle type or version".into());
    }
    if !matches!(
        raw.get("unmatchedActionPolicy").and_then(Value::as_str),
        Some("DENY" | "BASELINE")
    ) {
        return Err("trust bundle has no valid unmatched-action decision".into());
    }
    let approvers = raw
        .get("approvers")
        .and_then(Value::as_array)
        .filter(|a| !a.is_empty())
        .ok_or("trust bundle names no approvers")?;
    if !approvers.iter().all(valid_bundle_approver) {
        return Err("invalid bundle approver keys".into());
    }
    if !raw
        .get("policy")
        .and_then(Value::as_array)
        .is_some_and(|p| p.iter().all(valid_bundle_policy_value))
    {
        return Err("trust bundle carries invalid or incomplete policy".into());
    }
    let bundle: TrustBundle = serde_json::from_value(payload.clone())
        .map_err(|e| format!("trust bundle payload does not have the expected shape: {e}"))?;

    // A key listed as both ordinary and offline-only would undo the split the second list exists for.
    let ordinary: Vec<&String> = bundle
        .approvers
        .iter()
        .flat_map(|a| &a.public_keys)
        .collect();
    if bundle.approvers.iter().any(|a| {
        a.offline_public_keys
            .iter()
            .flatten()
            .any(|k| ordinary.contains(&k))
    }) {
        return Err("trust bundle lists an offline signing key as an ordinary key".into());
    }
    if let Err(conflict) = validate_exact_approval_policy(&bundle.policy) {
        return Err(format!(
            "trust bundle has invalid exact-action policy: {}",
            conflict.fields.join(", ")
        ));
    }
    if bundle.unmatched_action_policy == UnmatchedActionPolicy::Baseline
        && !bundle.policy.iter().any(|r| r.action_pattern == "*")
    {
        return Err("trust bundle has no baseline for unknown actions".into());
    }

    check_trust_bundle_freshness(&bundle, as_of)?;
    Ok(bundle)
}

/// Recheck a verified bundle's freshness — after an out-of-band signing ceremony, for instance —
/// without touching its trust keys.
///
/// Two independent checks. The gateway's own `expiresAt` can be generous, so the local 30-day age cap
/// is what actually bounds drift: a relying party must not run for a year on a bundle just because
/// whoever exported it chose a long expiry.
pub fn check_trust_bundle_freshness(
    bundle: &TrustBundle,
    as_of: Option<SystemTime>,
) -> Result<(), String> {
    let now = now_ms(as_of);
    let expiry = parse_rfc3339_ms(&bundle.expires_at)
        .ok_or("trust bundle expiresAt is not a valid RFC3339 timestamp")?;
    if now > expiry {
        return Err(format!(
            "trust bundle expired at {} — export a fresh one",
            bundle.expires_at
        ));
    }
    let issued = parse_rfc3339_ms(&bundle.issued_at)
        .ok_or("trust bundle issuedAt is not a valid RFC3339 timestamp")?;
    let age_ms = now.saturating_sub(issued);
    if age_ms > MAX_TRUST_BUNDLE_AGE_DAYS * DAY_MS {
        return Err(format!(
            "trust bundle is {:.1} days old, over the {MAX_TRUST_BUNDLE_AGE_DAYS}-day maximum — export a fresh one",
            age_ms as f64 / DAY_MS as f64
        ));
    }
    Ok(())
}

/// Write a bundle and its pinned verification key into `dir` (`trust-bundle.jws`,
/// `gateway-key.jwk.json`; directory `0700`, files `0600`), for use during a later outage.
pub fn save_trust_bundle(dir: impl AsRef<Path>, files: &TrustBundleFiles) -> Result<(), String> {
    let dir = dir.as_ref();
    ensure_private_dir(dir)?;
    write_private_file(&dir.join(BUNDLE_FILE), files.jws.as_bytes())?;
    let jwk = serde_json::to_string_pretty(&files.gateway_jwk).map_err(|e| e.to_string())?;
    write_private_file(&dir.join(KEY_FILE), format!("{jwk}\n").as_bytes())
}

/// Load and verify the bundle in `dir`.
///
/// Fails closed and LOUDLY: there is deliberately no "continue without a bundle" path, because the
/// fallback would be an unverified approver set — the one thing DIV Invariant 3 forbids.
pub fn load_trust_bundle(
    dir: impl AsRef<Path>,
    as_of: Option<SystemTime>,
) -> Result<TrustBundle, String> {
    let dir = dir.as_ref();
    let bundle_path = dir.join(BUNDLE_FILE);
    let key_path = dir.join(KEY_FILE);
    let jws = std::fs::read_to_string(&bundle_path).map_err(|_| {
        format!(
            "no trust bundle at {} — export one with `intyga trust-bundle export` while the gateway is reachable",
            bundle_path.display()
        )
    })?;
    let jwk: Value = std::fs::read_to_string(&key_path)
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
        .ok_or_else(|| format!("no pinned gateway key at {}", key_path.display()))?;
    verify_trust_bundle(js_trim(&jws), &jwk, as_of)
}

/// Build a DID-mode trust anchor from the bundle.
///
/// DID mode, and that is load-bearing: quorum must count distinct APPROVERS, and a delegation names
/// identities. Flattening every key into one allowlist would let one approver holding a software key
/// and two passkeys satisfy a 3-of-N quorum alone.
///
/// `limit_to_dids` narrows the eligible set (never widens it). [`BundleAnchorPurpose::Ordinary`]
/// never admits an offline signing key; pass `OfflineIntent` only when the receipt being verified is
/// a `div-offline-intent` — a bare offline key that could seal a delegation would hand its holder the
/// approval authority the delegation transfers.
pub fn approver_anchor(
    bundle: &TrustBundle,
    limit_to_dids: Option<&[String]>,
    purpose: BundleAnchorPurpose,
) -> ApproverTrustAnchor {
    let mut dids: Vec<String> = Vec::new();
    let mut by_did: HashMap<String, Vec<String>> = HashMap::new();
    for approver in bundle
        .approvers
        .iter()
        .filter(|a| limit_to_dids.is_none_or(|limit| limit.contains(&a.did)))
    {
        let mut keys = approver.public_keys.clone();
        if purpose == BundleAnchorPurpose::OfflineIntent {
            keys.extend(approver.offline_public_keys.iter().flatten().cloned());
        }
        // A Map keyed by DID, as in the reference: first position, last value.
        if !by_did.contains_key(&approver.did) {
            dids.push(approver.did.clone());
        }
        by_did.insert(approver.did.clone(), keys);
    }
    ApproverTrustAnchor::DidsMultiKey {
        dids,
        resolve: Box::new(move |did| by_did.get(did).cloned().unwrap_or_default()),
    }
}

/// Resolve the requirement for an action from the bundle's policy projection.
///
/// Exact-ID selection (see [`crate::approval_policy`]): the exact rule, else the `*` rule only under
/// `BASELINE`. `None` — a refusal — when the bundle or any rule is malformed, the policy conflicts,
/// the action is unmatched, the rule has fewer distinct approvers than its quorum, or it uses a
/// control an offline ceremony cannot reproduce (`requireAttestedRequester`, `allowedIssuers`,
/// escalation, an auto-approve requester).
pub fn requirement_for(
    bundle: &TrustBundle,
    action_type: &str,
    display: &str,
) -> Option<ResolvedRequirement> {
    if bundle.v != 1
        || bundle.bundle_type != DIV_TRUST_BUNDLE_TYPE
        || !bundle.policy.iter().all(valid_bundle_policy)
    {
        return None;
    }
    let winner = select_approval_rule(
        &bundle.policy,
        action_type,
        display,
        bundle.unmatched_action_policy,
    )
    .ok()??;
    let mut distinct: Vec<&String> = Vec::new();
    for did in &winner.approver_dids {
        if !distinct.contains(&did) {
            distinct.push(did);
        }
    }
    // These online-only conditions cannot be reconstructed by an offline ceremony.
    if (distinct.len() as i64) < winner.required_approvals
        || winner.require_attested_requester
        || !winner.allowed_issuers.is_empty()
        || winner.escalate_after_seconds.is_some_and(|n| n != 0)
        || winner
            .auto_approve_requester_did
            .as_deref()
            .is_some_and(|d| !d.is_empty())
    {
        return None;
    }
    Some(ResolvedRequirement {
        requirement: ApprovalRequirement {
            required_approvals: u32::try_from(winner.required_approvals.max(1)).ok()?,
            require_hardware_key: winner.require_hardware_key,
            allowed_aaguids: winner.allowed_aaguids.clone(),
            requester_cannot_approve: winner.requester_cannot_approve,
            signer_class: "human".into(),
        },
        approver_dids: winner.approver_dids.clone(),
    })
}
