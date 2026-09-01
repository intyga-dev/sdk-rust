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
/// Offline approval (DIV §5a.2): a normal quorum approval collected OUT OF BAND at incident time
/// because the gateway is unreachable. The relying party builds the challenge itself, humans sign it
/// on a disconnected device, and this verifier checks the result.
///
/// The distinct type lives INSIDE the signed bytes, so an offline proof can never verify as a normal
/// approval, or the reverse — even for a byte-identical action, because the reconstructed payload
/// differs and the signature comparison fails.
pub const DIV_OFFLINE_INTENT_TYPE: &str = "div-offline-intent";
/// Delegation (DIV §5a.5): a pre-signed statement transferring the AUTHORITY TO APPROVE one
/// pre-declared action to named local operators. It authorizes NOTHING on its own —
/// [`verify_approval_receipt`] refuses this type outright, with no opt-in. Use [`verify_delegation`].
pub const DIV_DELEGATION_TYPE: &str = "div-delegation";
/// RECOMMENDED expiry tolerance in seconds (DIV §6.2).
pub const DEFAULT_CLOCK_SKEW_SECONDS: i64 = 30;
/// Hard cap on an offline proof's validity window, enforced at verification and not only at mint. An
/// offline relying party has no revocation channel, so the short window is the only bound (DIV §5a.3).
pub const MAX_OFFLINE_WINDOW_MINUTES: i64 = 60;
/// Hard cap on a delegation's window (DIV §5a.6). Hours, not weeks: a delegation cannot be recalled
/// from a relying party that is offline.
pub const MAX_DELEGATION_WINDOW_HOURS: i64 = 72;
/// Ceiling on the witness list this verifier will process. A DIV quorum is single digits — this is
/// a denial-of-service bound, not a policy limit: the witness list is attacker-supplied, every entry
/// costs an ECDSA verification per candidate key, and verification runs in the relying party's own
/// process immediately before an irreversible action. The TS reference measured a 20,000-witness
/// receipt at 3.6s of blocked verification and a 1.16 MB error string. Matches @intyga/verify.
pub const MAX_WITNESSES: usize = 64;
/// How many per-witness failure reasons are folded into the returned reason string; the rest are
/// elided as "+N more". Folding every reason is what produced the megabyte error above.
const MAX_REPORTED_FAILURES: usize = 8;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RequesterAttestation {
    pub method: String,
    pub issuer: String,
    pub subject: String,
}

/// The approval policy in force, frozen at challenge creation and SIGNED into the intent payload.
///
/// Without it in the signed bytes, a 3-of-3 hardware-pinned receipt is byte-for-byte identical to a
/// 1-of-1 one, so a relying party still has to trust the gateway for the whole policy. Offline
/// checkability differs per field: `required_approvals` and `requester_cannot_approve` are fully
/// verifiable; `require_hardware_key` only partially (an assertion proves WebAuthn, not the
/// authenticator model); `allowed_aaguids` not at all (the AAGUID is registration data).
/// `signer_class` is partially checkable: a WEBAUTHN witness's UV flag corroborates a human
/// ceremony, an ES256 witness carries no class evidence — but the verifier's own rule is absolute:
/// refuse any value it does not recognize (`"human"` is the only class defined today, DIV §4.3.2).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApprovalRequirement {
    pub required_approvals: u32,
    pub require_hardware_key: bool,
    #[serde(default)]
    pub allowed_aaguids: Vec<String>,
    pub requester_cannot_approve: bool,
    #[serde(default)]
    pub signer_class: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RequesterIdentity {
    pub did: String,
    pub attestation: Option<RequesterAttestation>,
}

/// One approver's signature over the canonical payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalWitness {
    #[serde(rename = "signerDid", default)]
    pub signer_did: String,
    #[serde(rename = "signerPublicKey")]
    pub signer_public_key: String,
    pub signature: String,
    #[serde(rename = "sigAlg", default)]
    pub sig_alg: Option<String>,
    #[serde(rename = "authenticatorData", default)]
    pub authenticator_data: Option<String>,
    #[serde(rename = "clientDataJSON", default)]
    pub client_data_json: Option<String>,
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
    /// EVERY witness signature over `canonical_payload` — one entry per approver. Emitting only the
    /// first approval made an M-of-N receipt indistinguishable from a 1-of-1 one, so the quorum
    /// could not be checked offline at all. Empty/absent for AUTO_APPROVED.
    #[serde(default)]
    pub signatures: Option<Vec<ApprovalWitness>>,
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

/// The approver keys the relying party trusts, resolved from its OWN key-management policy.
///
/// This is the single most important verification input. Without it, verification would use the
/// public key carried INSIDE the receipt, which proves only that the receipt is internally
/// consistent — per the DIV threat model anyone able to hand you a receipt (including the untrusted
/// agent) could have minted that keypair. DIV §3 Invariant 3 / §5 step 3 require the Approver key to
/// come from deployment policy; this type is that step.
pub enum ApproverTrustAnchor {
    /// A direct allowlist of base64 SPKI (ES256) or COSE (WebAuthn) keys.
    PublicKeys(Vec<String>),
    /// A DID allowlist plus the caller's own resolver. Return None for an unknown DID.
    Dids {
        dids: Vec<String>,
        resolve: Box<dyn Fn(&str) -> Option<String>>,
    },
    /// A DID allowlist whose resolver returns EVERY key bound to one DID.
    ///
    /// An approver commonly holds a software key plus one or more registered authenticators, and any
    /// of them is legitimately theirs. Returning them all keeps the identity intact instead of forcing
    /// callers into `PublicKeys` mode and losing the DID binding — which would make quorum count
    /// credentials instead of people, so one approver with three keys could satisfy a 3-of-N. Every key
    /// returned here counts as that ONE approver, and a delegation (DIV §5a.6) needs this mode because
    /// it names identities.
    DidsMultiKey {
        dids: Vec<String>,
        resolve: Box<dyn Fn(&str) -> Vec<String>>,
    },
}

/// What the relying party asserts. `target`, `nonce` and `approvers` come from the RP's own state —
/// never read from the receipt (DIV Target Isolation + replay binding + Invariant 3).
pub struct Expected {
    pub target: String,
    pub nonce: String,
    pub action_type: String,
    pub params: Value,
    /// REQUIRED. There is deliberately no default: a receipt must not vouch for its own signer.
    pub approvers: ApproverTrustAnchor,
}

impl ApproverTrustAnchor {
    /// Keys we will accept this witness under, each tagged with the identity it represents so a
    /// quorum counts distinct APPROVERS. In `PublicKeys` mode the identity is the key itself: the
    /// receipt's `signerDid` is unverified there, and counting it would let one approver claim to be
    /// three. We deliberately do NOT compare the presented key to the trusted one — a mismatched key
    /// simply fails to verify, and byte-equality is wrong for COSE, which has many valid encodings
    /// of one P-256 key.
    fn candidates(&self, signer_did: &str) -> Result<Vec<(String, String)>, String> {
        self.candidates_restricted(signer_did, None)
    }

    /// `candidates` plus an optional narrowing to the identities a delegation names (DIV §5a.6 step
    /// 3). Applied ON TOP of the trust anchor, never instead of it: a delegation says WHO may approve,
    /// and the anchor still says which key is actually theirs.
    fn candidates_restricted(
        &self,
        signer_did: &str,
        restrict_to: Option<&[String]>,
    ) -> Result<Vec<(String, String)>, String> {
        // A delegation names identities, and in `PublicKeys` mode `signerDid` is an unverified string —
        // enforcing `delegatedTo` against it would be security theatre. Refuse rather than pretend.
        if restrict_to.is_some() {
            if let ApproverTrustAnchor::PublicKeys(_) = self {
                return Err("a delegation names approver identities, so it requires a DID-mode trust anchor; in PublicKeys mode signerDid is unverified and delegatedTo cannot be enforced".to_string());
            }
        }
        if let Some(named) = restrict_to {
            if !named.iter().any(|d| d == signer_did) {
                return Err(format!(
                    "signer {signer_did} is not named in the delegation"
                ));
            }
        }
        match self {
            ApproverTrustAnchor::PublicKeys(keys) => {
                if keys.is_empty() {
                    return Err("trusted approver allowlist is empty".to_string());
                }
                Ok(keys.iter().map(|k| (k.clone(), k.clone())).collect())
            }
            ApproverTrustAnchor::Dids { dids, resolve } => {
                if signer_did.is_empty() || !dids.iter().any(|d| d == signer_did) {
                    return Err(format!("signer {signer_did} is not an authorized approver"));
                }
                match resolve(signer_did) {
                    Some(key) => Ok(vec![(key, signer_did.to_string())]),
                    None => Err(format!("no trusted key could be resolved for {signer_did}")),
                }
            }
            ApproverTrustAnchor::DidsMultiKey { dids, resolve } => {
                if signer_did.is_empty() || !dids.iter().any(|d| d == signer_did) {
                    return Err(format!("signer {signer_did} is not an authorized approver"));
                }
                // All keys for one DID share that DID as their identity, so quorum still counts one.
                let keys: Vec<(String, String)> = resolve(signer_did)
                    .into_iter()
                    .filter(|k| !k.is_empty())
                    .map(|k| (k, signer_did.to_string()))
                    .collect();
                if keys.is_empty() {
                    return Err(format!("no trusted key could be resolved for {signer_did}"));
                }
                Ok(keys)
            }
        }
    }
}

/// Relying-party context required to verify certain receipts. The WebAuthn expectations are
/// mandatory for a WEBAUTHN receipt: without a pinned origin and RP ID, an assertion harvested
/// at any relying party would verify.
#[derive(Debug, Clone, Default)]
pub struct VerifyOptions {
    /// Opt in to attesting policy AUTO_APPROVED receipts, which carry no human signature.
    /// Off by default: such receipts fail closed.
    pub allow_auto_approved: bool,
    /// Accept an assertion produced inside a cross-origin frame. Defaults to false (refuse).
    pub allow_cross_origin: Option<bool>,
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
    /// Opt in to accepting an OFFLINE APPROVAL (DIV §5a.3). Off by default, exactly like
    /// `allow_auto_approved`: set it at the SPECIFIC call permitted to run under one, never globally.
    /// A process-wide default would make every gated action accept an out-of-band approval.
    ///
    /// It weakens nothing else: the quorum, four-eyes and target binding signed into the payload are
    /// still enforced, the window is capped at [`MAX_OFFLINE_WINDOW_MINUTES`], and a proof whose signed
    /// policy demands a hardware key is REFUSED because that cannot be satisfied offline.
    pub allow_offline: bool,
    /// A delegation ALREADY verified by [`verify_delegation`], substituting the eligible approver set
    /// and the quorum for this one verification (DIV §5a.6). Only meaningful with `allow_offline`.
    pub delegation: Option<VerifiedDelegation>,
}

/// A delegation whose own signature, quorum and window have been checked by [`verify_delegation`].
/// It is an INPUT to a later approval check, never a substitute for one.
#[derive(Debug, Clone, Default)]
pub struct VerifiedDelegation {
    /// Identities permitted to approve at incident time, deduplicated.
    pub delegated_to: Vec<String>,
    /// How many distinct members of `delegated_to` must sign. Same width as
    /// `ApprovalRequirement::required_approvals`, which it is compared against.
    pub delegated_quorum: u32,
    /// The single action this delegation covers. All three must equal what is being executed.
    pub target: String,
    pub action_type: String,
    pub params: Value,
    /// The delegation's OWN nonce — for the audit trail, never for authorization.
    pub nonce: String,
    pub signers: Vec<String>,
    pub expires_at: String,
}

/// The portability bound the golden vectors pin: integers are exact below 1e16, and outside it
/// every implementation switches to exponent notation at a different threshold.
const PORTABLE_LIMIT: u64 = 10_000_000_000_000_000; // 1e16

/// Recursively stringify JSON values with UTF-16 sorted keys to match JS/Python byte-for-byte.
///
/// Returns `Err` for any number that cannot be canonicalized IDENTICALLY in every language this
/// contract spans (`isPortableNumber` in @intyga/mcp-schemas, `NonCanonicalValue` in @intyga/verify):
/// negative zero (serde_json prints "-0.0" where JS prints "0"), any nonzero |x| >= 1e16, and any
/// nonzero non-integer |x| < 1e-4 (Python and V8 switch to exponent notation at different
/// thresholds). Refusing here rather than emitting keeps this port from signing bytes the other
/// verifiers can never re-derive — a failure that would read as tampering, not as drift.
///
/// NaN/Infinity need no guard: serde_json's `Number` cannot hold them (`Number::from_f64` refuses
/// non-finite values, and `json!` maps them to `null`).
pub fn stable_stringify(value: &Value) -> Result<String, String> {
    match value {
        Value::Null => Ok("null".to_string()),
        Value::Bool(b) => Ok(if *b { "true" } else { "false" }.to_string()),
        Value::Number(n) => {
            // serde_json's Display is NOT the ES6 Number::toString RFC 8785 §3.2.2.3 mandates: it
            // prints a decimal point for whole-valued floats, where JS emits none.
            //
            // Normalising only zero was not enough, and the reasoning that it was ("producers refuse
            // to sign numbers outside the portable range") does not apply: isPortableNumber ACCEPTS
            // any integer under 1e16, and JS cannot tell 3 from 3.0, so the signed bytes always say
            // "3". A relying party building expected params from its own runtime — json!({"amount":
            // 100.0}), or any struct with an f64 field — emitted "100.0" here and got a false
            // "params do not match" on a perfectly valid receipt. Tests missed it because values
            // parsed from JSON *text* stay integer-typed in serde_json.
            //
            // The integer branches enforce PORTABLE_LIMIT too: serde_json would print an i64 1e16
            // exactly, but the TS reference REFUSES to sign it, so emitting it here would produce
            // bytes no TS relying party can ever re-derive.
            if let Some(i) = n.as_i64() {
                if i.unsigned_abs() >= PORTABLE_LIMIT {
                    return Err(format!("{i} is outside the portable range (|x| < 1e16)"));
                }
                return Ok(i.to_string());
            }
            if let Some(u) = n.as_u64() {
                if u >= PORTABLE_LIMIT {
                    return Err(format!("{u} is outside the portable range (|x| < 1e16)"));
                }
                return Ok(u.to_string());
            }
            if let Some(f) = n.as_f64() {
                if f == 0.0 {
                    // Previously folded silently to "0". Refused now: the TS producer refuses to
                    // sign -0, so a Rust RP accepting it would diverge on the very value whose
                    // serialization ("-0.0" here, "0" in JS) motivated the portability rule.
                    if f.is_sign_negative() {
                        return Err("-0 does not serialize portably across verifiers".to_string());
                    }
                    return Ok("0".to_string());
                }
                if f.abs() >= 1e16 {
                    return Err(format!("{f} is outside the portable range (|x| < 1e16)"));
                }
                // Integers are exact below 1e16 (bound enforced just above); whole-valued floats
                // print without the decimal point JS omits.
                if f.fract() == 0.0 {
                    return Ok(format!("{}", f as i64));
                }
                if f.abs() < 1e-4 {
                    return Err(format!(
                        "{f} is outside the portable float range (1e-4 ≤ |x| < 1e16)"
                    ));
                }
            }
            Ok(n.to_string())
        }
        Value::String(s) => Ok(serde_json::to_string(s).unwrap_or_else(|_| "null".to_string())),
        Value::Array(arr) => {
            let mut elems: Vec<String> = Vec::with_capacity(arr.len());
            for v in arr {
                elems.push(stable_stringify(v)?);
            }
            Ok(format!("[{}]", elems.join(",")))
        }
        Value::Object(obj) => {
            let mut keys: Vec<&String> = obj.keys().collect();
            keys.sort_by(|a, b| {
                let u1: Vec<u16> = a.encode_utf16().collect();
                let u2: Vec<u16> = b.encode_utf16().collect();
                u1.cmp(&u2)
            });
            let mut parts: Vec<String> = Vec::with_capacity(keys.len());
            for k in keys {
                let k_str = serde_json::to_string(k).unwrap();
                let v_str = stable_stringify(&obj[k])?;
                parts.push(format!("{}:{}", k_str, v_str));
            }
            Ok(format!("{{{}}}", parts.join(",")))
        }
    }
}

/// Build a byte-identical DIV Intent Payload (docs/DIV.md v1) matching TypeScript, Go and Python.
/// Builds the full object and serializes it via [`stable_stringify`] (strict RFC 8785 JCS — every
/// key sorted). Do NOT hand-template key order; the sort is the contract.
///
/// `Err` means the params contain a non-portable number (see [`stable_stringify`]) — the payload
/// could never verify in the other language ports, so it is refused rather than built.
#[allow(clippy::too_many_arguments)]
pub fn canonical_intent_payload(
    target: &str,
    action_type: &str,
    display: &str,
    params: &Value,
    requester: &RequesterIdentity,
    requirement: &ApprovalRequirement,
    nonce: &str,
    expires_at: &str,
) -> Result<String, String> {
    let (req, rq) = canonical_common(requester, requirement);
    let obj = serde_json::json!({
        "v": DIV_VERSION,
        "type": DIV_INTENT_TYPE,
        "target": target,
        "actionType": action_type,
        "display": display,
        "params": params,
        "requester": req,
        "requirement": rq,
        "nonce": nonce,
        "expiresAt": expires_at,
    });
    stable_stringify(&obj)
}

/// The requester + requirement projection shared by all three canonical builders.
///
/// One definition rather than three copies: these bytes are the contract, and a field added to one
/// builder but not the others is exactly the drift the golden vectors exist to catch.
///
/// Infallible on purpose: it only BUILDS `Value`s (strings, bools, a u32 — none can be
/// non-portable); the fallible serialization happens in the callers' [`stable_stringify`] pass.
fn canonical_common(
    requester: &RequesterIdentity,
    requirement: &ApprovalRequirement,
) -> (Value, Value) {
    let attestation = match &requester.attestation {
        None => Value::Null,
        Some(a) => serde_json::json!({
            "method": a.method,
            "issuer": a.issuer,
            "subject": a.subject,
        }),
    };
    // The SET is the policy: sort so two identical allowlists written in different orders sign
    // identically. Clone first — mutating the caller's vector would be a surprising side effect.
    let mut aaguids = requirement.allowed_aaguids.clone();
    // UTF-16 code units, not Rust's native UTF-8 byte order — the same comparator the object
    // keys use. The two differ only for non-BMP characters, which no AAGUID (hex UUID) or DID
    // carries today, but a set sorted one way here and another in the TS reference produces
    // different SIGNED BYTES, caught by nothing until a receipt fails elsewhere. DIV §4.3.3.
    aaguids.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
    (
        serde_json::json!({ "did": requester.did, "attestation": attestation }),
        serde_json::json!({
            "requiredApprovals": requirement.required_approvals,
            "requireHardwareKey": requirement.require_hardware_key,
            "allowedAaguids": aaguids,
            "requesterCannotApprove": requirement.requester_cannot_approve,
            "signerClass": requirement.signer_class,
        }),
    )
}

/// Build a byte-identical OFFLINE APPROVAL payload (DIV §5a.2), pinned by the
/// `offlineIntentPayloads` golden vectors and matching TypeScript, Go and Python.
///
/// Deliberately a separate function rather than a `type` argument on [`canonical_intent_payload`], so
/// the ordinary approval path cannot accidentally emit an offline payload.
///
/// `challenged_at` exists so a verifier can bound the validity WINDOW, not merely the expiry: a
/// payload minted with an over-long `expires_at` is otherwise indistinguishable from a correct one.
#[allow(clippy::too_many_arguments)]
pub fn canonical_offline_intent_payload(
    target: &str,
    action_type: &str,
    display: &str,
    params: &Value,
    requester: &RequesterIdentity,
    requirement: &ApprovalRequirement,
    nonce: &str,
    challenged_at: &str,
    expires_at: &str,
) -> Result<String, String> {
    let (req, rq) = canonical_common(requester, requirement);
    stable_stringify(&serde_json::json!({
        "v": DIV_VERSION,
        "type": DIV_OFFLINE_INTENT_TYPE,
        "target": target,
        "actionType": action_type,
        "display": display,
        "params": params,
        "requester": req,
        "requirement": rq,
        "nonce": nonce,
        "challengedAt": challenged_at,
        "expiresAt": expires_at,
    }))
}

/// Build a byte-identical DELEGATION payload (DIV §5a.5) — a signed statement about WHO MAY APPROVE,
/// not about what may run.
///
/// `delegated_to` is sorted because it is a SET, exactly as `allowed_aaguids` is. `requirement`
/// describes the quorum that signed this delegation; `delegated_quorum` is how many of `delegated_to`
/// must sign at incident time. Two different quorums, so both are in the signed bytes.
#[allow(clippy::too_many_arguments)]
pub fn canonical_delegation_payload(
    target: &str,
    action_type: &str,
    display: &str,
    params: &Value,
    requester: &RequesterIdentity,
    requirement: &ApprovalRequirement,
    delegated_to: &[String],
    delegated_quorum: i64,
    nonce: &str,
    sealed_at: &str,
    expires_at: &str,
) -> Result<String, String> {
    let (req, rq) = canonical_common(requester, requirement);
    let mut delegates = delegated_to.to_vec();
    // UTF-16 code units, not Rust's native UTF-8 byte order — the same comparator the object
    // keys use. The two differ only for non-BMP characters, which no AAGUID (hex UUID) or DID
    // carries today, but a set sorted one way here and another in the TS reference produces
    // different SIGNED BYTES, caught by nothing until a receipt fails elsewhere. DIV §4.3.3.
    delegates.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
    stable_stringify(&serde_json::json!({
        "v": DIV_VERSION,
        "type": DIV_DELEGATION_TYPE,
        "target": target,
        "actionType": action_type,
        "display": display,
        "params": params,
        "requester": req,
        "requirement": rq,
        "delegatedTo": delegates,
        "delegatedQuorum": delegated_quorum,
        "nonce": nonce,
        "sealedAt": sealed_at,
        "expiresAt": expires_at,
    }))
}

/// Read a string field out of the canonical payload JSON, or None.
fn canonical_str_field(canonical: &str, key: &str) -> Option<String> {
    serde_json::from_str::<Value>(canonical)
        .ok()
        .and_then(|v| v.get(key).and_then(|x| x.as_str().map(String::from)))
}

/// Parse an RFC3339 UTC timestamp (`YYYY-MM-DDTHH:MM:SS[.fff]Z`) to unix seconds. UTC only (DIV
/// mandates UTC `expiresAt`); returns None on any other shape. Zero external dependencies.
/// Parse an RFC 3339 timestamp to a Unix second count.
///
/// Accepts a `Z`/`z` suffix OR a numeric `±HH:MM` offset, and normalizes the latter to UTC. This
/// used to require the string to END in `Z`, which made `2036-01-01T00:00:00+00:00` — perfectly
/// valid RFC 3339 denoting UTC, and accepted by both `Date.parse` in the TS reference and
/// `time.RFC3339` in the Go port — return None here alone.
///
/// That divergence was not cosmetic: the caller treated None as "skip the check", so a proof every
/// other port would refuse for its window sailed through Rust. Both halves are fixed — this parser
/// now agrees with its siblings, and the caller now fails closed on None rather than skipping.
fn parse_rfc3339_utc_secs(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    // Minimum: "YYYY-MM-DDTHH:MM:SSZ" = 20 chars.
    if b.len() < 20 {
        return None;
    }
    if b[4] != b'-'
        || b[7] != b'-'
        || (b[10] != b'T' && b[10] != b't')
        || b[13] != b':'
        || b[16] != b':'
    {
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

    // Everything after the seconds: an optional fractional part (floored, per the note below), then
    // the zone designator — `Z`/`z`, or a numeric offset which is subtracted to reach UTC.
    let mut rest = s.get(19..)?;
    if rest.starts_with('.') || rest.starts_with(',') {
        // `.` and `,` are both legal decimal signs in ISO 8601; RFC 3339 uses `.`. The separator is
        // one ASCII byte, so slicing at 1 is always a char boundary.
        let digits = rest[1..].chars().take_while(|c| c.is_ascii_digit()).count();
        if digits == 0 {
            return None;
        }
        rest = rest.get(1 + digits..)?;
    }
    let offset_secs: i64 = if rest == "Z" || rest == "z" {
        0
    } else {
        let rb = rest.as_bytes();
        if rb.len() != 6 || (rb[0] != b'+' && rb[0] != b'-') || rb[3] != b':' {
            return None;
        }
        let off_hour: i64 = rest.get(1..3)?.parse().ok()?;
        let off_min: i64 = rest.get(4..6)?.parse().ok()?;
        if off_hour > 23 || off_min > 59 {
            return None;
        }
        let magnitude = off_hour * 3600 + off_min * 60;
        if rb[0] == b'-' {
            -magnitude
        } else {
            magnitude
        }
    };

    // days_from_civil (Howard Hinnant), then seconds. Fractional seconds are floored (ignored).
    let y = year - if month <= 2 { 1 } else { 0 };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400;
    let mp = if month > 2 { month - 3 } else { month + 9 };
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    Some(days * 86400 + hour * 3600 + min * 60 + sec - offset_secs)
}

fn now_unix_secs() -> i64 {
    // FAIL CLOSED on a broken clock: a pre-epoch SystemTime used to yield 0, which made
    // `now > expiresAt + skew` false and silently PASSED the expiry check. i64::MAX makes every
    // receipt read as expired instead — a refusal the caller can see (and `allow_expired` still
    // works for audit re-verification).
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(i64::MAX)
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

/// Validate `requirement.signerClass` out of the signed bytes (DIV §4.3.2). `"human"` is the only
/// class defined today. FAIL CLOSED both ways: an absent class predates (or dropped) the field, and
/// an unrecognized class must never verify as if it were human-approved — that is the entire point
/// of putting the class in the signed bytes.
fn check_signer_class(requirement: &ApprovalRequirement) -> Result<(), String> {
    if requirement.signer_class.is_empty() {
        return Err("the signed requirement is missing signerClass (DIV §4.3.2)".to_string());
    }
    if requirement.signer_class != "human" {
        return Err(format!(
            "the signed requirement declares signerClass \"{}\", which this verifier does not recognize — refusing rather than treating it as human-approved (DIV §4.3.2)",
            requirement.signer_class
        ));
    }
    Ok(())
}

/// Enforce DIV §4.3.2: `requiredApprovals` is an integer ≥ 1.
///
/// Stated as its own refusal rather than clamped, because §5 step 7 rejects unless the counted
/// identities are AT LEAST this number — 0 is satisfied by counting nothing, so an unenforced
/// minimum would attest an envelope carrying no valid witness signature. (Non-integral and negative
/// values never reach here: the field deserializes as `u32`, so they fail the payload parse.)
fn check_quorum_minimum(requirement: &ApprovalRequirement) -> Result<(), String> {
    if requirement.required_approvals < 1 {
        return Err(
            "signed requirement.requiredApprovals must be an integer of at least 1 (DIV §4.3.2)"
                .to_string(),
        );
    }
    Ok(())
}

/// The instant and skew tolerance every time-based check shares: expiry (DIV §6.2) and the
/// forward-dating rule of §5a.3 rule 3.
fn evaluation_time(opts: &VerifyOptions) -> (i64, i64) {
    (
        opts.as_of_unix_secs.unwrap_or_else(now_unix_secs),
        opts.clock_skew_seconds
            .unwrap_or(DEFAULT_CLOCK_SKEW_SECONDS),
    )
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
    let payload_type = probe
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or_default();
    // A DELEGATION authorizes nothing (DIV §5a.5). Refused here unconditionally — there is deliberately
    // NO option that would let one through, because a delegation that could authorize its own action
    // would be exactly the pre-signed bearer capability the design exists to avoid.
    if payload_type == DIV_DELEGATION_TYPE {
        return Err("this is a delegation, which authorizes no action on its own — verify it with verify_delegation and pass the result as opts.delegation, together with an offline approval signed by the delegated operators".to_string());
    }
    let offline = payload_type == DIV_OFFLINE_INTENT_TYPE;
    if !offline && payload_type != DIV_INTENT_TYPE {
        return Err("payload is not a div-intent-verification".to_string());
    }
    if offline && !opts.allow_offline {
        return Err("this is an offline approval; set allow_offline at the specific call site permitted to run under one".to_string());
    }
    // A delegation only ever substitutes the approver set for an OFFLINE proof. Accepting it against an
    // ordinary gateway-mediated receipt would silently replace the quorum the gateway enforced.
    if opts.delegation.is_some() && !offline {
        return Err(
            "a delegation can only substitute the approver set for an offline approval".to_string(),
        );
    }
    let payload_nonce =
        canonical_str_field(&receipt.canonical_payload, "nonce").unwrap_or_default();
    if payload_nonce != expected.nonce {
        return Err("receipt is for a different challenge".to_string());
    }

    // NOTE: the AUTO_APPROVED decision deliberately does NOT live here. Accepting it before the
    // canonical payload has been recomputed would attest a receipt on the strength of a matching
    // nonce alone — see the block after the expiry check below.

    let requester = receipt
        .requester
        .as_ref()
        .ok_or("receipt missing requester")?;

    let expires_at = canonical_str_field(&receipt.canonical_payload, "expiresAt")
        .filter(|s| !s.is_empty())
        .ok_or("receipt missing expiresAt")?;

    // The requirement is part of the SIGNED bytes, so reading it back from the payload is not
    // circular: a forged value changes the string and fails the byte comparison below.
    let requirement: ApprovalRequirement =
        serde_json::from_str::<Value>(&receipt.canonical_payload)
            .ok()
            .and_then(|v| v.get("requirement").cloned())
            .and_then(|v| serde_json::from_value(v).ok())
            .ok_or("receipt payload is missing the signed approval requirement")?;
    check_quorum_minimum(&requirement)?;
    check_signer_class(&requirement)?;

    // Offline proofs carry `challengedAt` so the validity WINDOW can be bounded here, not merely at mint.
    let mut challenged_at = String::new();
    if offline {
        challenged_at = canonical_str_field(&receipt.canonical_payload, "challengedAt")
            .filter(|s| !s.is_empty())
            .ok_or("offline proof is missing challengedAt")?;
        let challenged = parse_rfc3339_utc_secs(&challenged_at)
            .ok_or("challengedAt is not a valid RFC3339 UTC timestamp")?;
        // An unparseable `expiresAt` must be refused HERE rather than skipping the window cap and
        // relying on the expiry check further down — that check is disabled by `allow_expired`, so
        // the `allow_offline + allow_expired` combination (the documented forensic re-verification
        // mode, and the only mode under which an offline proof is examined at all) left the cap
        // unenforced on a proof whose window could not be computed at all.
        //
        // `expiresAt` is inside the signed bytes, but an offline proof is minted by whoever
        // constructs it and the verifier reconstructs the payload from the receipt's OWN expiresAt,
        // so any string round-trips. DIV §5a.3 makes the window the entire revocation story for an
        // offline proof — an offline relying party has no channel to recall one — so an unbounded
        // window turns a 60-minute incident credential into a permanent bearer capability.
        //
        // This port was the worst of the three that had the bug: its parser also rejected a valid
        // `+00:00` offset that the TS and Go ports accept, so a proof they would refuse for its
        // window passed here. See `parse_rfc3339_utc_secs`, now fixed to agree with them.
        let expiry = parse_rfc3339_utc_secs(&expires_at)
            .ok_or("expiresAt is not a valid RFC3339 timestamp")?;
        let window_secs = expiry - challenged;
        if window_secs < 0 {
            return Err("offline proof expires before it was challenged".to_string());
        }
        if window_secs > MAX_OFFLINE_WINDOW_MINUTES * 60 {
            return Err(format!(
                "offline window is {:.1} minutes, over the {MAX_OFFLINE_WINDOW_MINUTES}-minute maximum",
                window_secs as f64 / 60.0
            ));
        }
        // The cap above bounds the window's WIDTH; this bounds its POSITION (DIV §5a.3 rule 3).
        // Without it a proof challenged for a date years out, with a compliant 60-minute window,
        // verifies today and keeps verifying until that date — the pre-signed bearer capability
        // §5a.1 rejects. NOT gated on `allow_expired`: that override re-examines a proof that WAS
        // valid and has lapsed, and says nothing about one dated in the future.
        let (now, skew) = evaluation_time(opts);
        if challenged > now + skew {
            return Err("offline proof is challenged in the future (DIV §5a.3)".to_string());
        }
        // A hardware-key policy CANNOT be satisfied offline (DIV §5a.3 step 4). WebAuthn needs a secure
        // context and an RP ID an offline signing surface will not match, so an offline witness is
        // always a bare key. Accepting the proof anyway would silently downgrade the policy the approver
        // attested to, so it is refused instead — fail closed, and say why.
        if requirement.require_hardware_key {
            return Err("the signed policy requires a hardware-backed WebAuthn credential, which cannot be produced offline — this action cannot be approved out of band (DIV §5a.3)".to_string());
        }
    }

    // A delegation substitutes WHO may approve and HOW MANY, and nothing else (DIV §5a.6). Every
    // agreement check is on the SIGNED bytes of both proofs, so neither can widen the other.
    let mut delegated_to: Option<Vec<String>> = None;
    let mut delegated_quorum: Option<u32> = None;
    if let Some(d) = &opts.delegation {
        if d.target != expected.target {
            return Err("the delegation was issued for a different target".to_string());
        }
        if d.action_type != expected.action_type {
            return Err("the delegation was issued for a different actionType".to_string());
        }
        // A canonicalization failure here is fail-closed but deliberately NOT the tampering-shaped
        // "issued for different params": the params were never compared at all.
        let delegation_params = stable_stringify(&d.params).map_err(|why| {
            format!("params contain a non-portable number and cannot be canonicalized: {why}")
        })?;
        let expected_params = stable_stringify(&expected.params).map_err(|why| {
            format!("params contain a non-portable number and cannot be canonicalized: {why}")
        })?;
        if delegation_params != expected_params {
            return Err("the delegation was issued for different params".to_string());
        }
        // The offline payload's signed quorum must equal the delegated one, so the operators signed the
        // policy their signatures are being counted toward rather than a different one.
        if requirement.required_approvals != d.delegated_quorum {
            return Err(format!(
                "offline proof declares {} required approval(s) but the delegation delegates a quorum of {}",
                requirement.required_approvals, d.delegated_quorum
            ));
        }
        delegated_to = Some(d.delegated_to.clone());
        delegated_quorum = Some(d.delegated_quorum);
    }

    let recomputed = if offline {
        canonical_offline_intent_payload(
            &expected.target,
            &expected.action_type,
            &receipt.action_description,
            &expected.params,
            requester,
            &requirement,
            &payload_nonce,
            &challenged_at,
            &expires_at,
        )
    } else {
        canonical_intent_payload(
            &expected.target,
            &expected.action_type,
            &receipt.action_description,
            &expected.params,
            requester,
            &requirement,
            &payload_nonce,
            &expires_at,
        )
    }
    // Fail closed, but with a reason DISTINCT from the "do not match" one below: that one is
    // tampering-shaped, while this one means the relying party's own expected params hold a number
    // no port can canonicalize identically — nothing was compared, and there is no attacker to hunt.
    .map_err(|why| {
        format!("params contain a non-portable number and cannot be canonicalized: {why}")
    })?;

    if recomputed != receipt.canonical_payload {
        return Err("target/params/actionType do not match what was approved".to_string());
    }

    // Expiration (DIV §5.8/§6.2). Fail-closed by default; opt out only for audit re-verification.
    if !opts.allow_expired {
        let expiry = parse_rfc3339_utc_secs(&expires_at)
            .ok_or("expiresAt is not a valid RFC3339 UTC timestamp")?;
        let (now, skew) = evaluation_time(opts);
        if now > expiry + skew {
            return Err(
                "proof has expired (set allow_expired for audit re-verification)".to_string(),
            );
        }
    }

    // A policy AUTO_APPROVED receipt carries NO human signature, so there is nothing to verify
    // cryptographically and a relying party must opt in. Opting in waives the SIGNATURE requirement —
    // it does not waive DIV §5 steps 8 and 9. This check therefore sits AFTER the canonical payload
    // comparison and the expiry check, matching the TypeScript reference.
    //
    // It used to sit immediately after the nonce comparison. An agent holding a nonce could then get
    // any trivial action auto-approved under it and present that receipt for a destructive call: the
    // target, actionType and params were never examined, and a years-expired approval passed too.
    if let Some(alg) = &receipt.sig_alg {
        if alg == "AUTO_APPROVED" {
            // An offline approval with no human signature is a contradiction: the entire premise is that
            // humans signed out of band, so `allow_auto_approved` must not rescue it.
            if offline {
                return Err("an offline approval cannot be auto-approved — there is no human signature to verify".to_string());
            }
            if !opts.allow_auto_approved {
                return Err("AUTO_APPROVED receipts are refused by default".to_string());
            }
            return Ok(());
        }
    }

    let witnesses = witnesses_of(receipt);
    if witnesses.is_empty() {
        return Err("missing signature or public key".to_string());
    }
    // DoS bound, not a policy limit — see MAX_WITNESSES.
    if witnesses.len() > MAX_WITNESSES {
        return Err(format!(
            "receipt carries {} witnesses, above the {MAX_WITNESSES} this verifier will process",
            witnesses.len()
        ));
    }

    // Count DISTINCT approvers whose signature verifies under a key we independently trust. Distinct
    // is load-bearing: without it, N copies of one approver's signature satisfy an N-of-M quorum.
    let mut verified: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut failures: Vec<String> = Vec::new();
    for witness in &witnesses {
        let candidates = match expected
            .approvers
            .candidates_restricted(&witness.signer_did, delegated_to.as_deref())
        {
            Ok(c) => c,
            Err(reason) => {
                failures.push(reason);
                continue;
            }
        };
        let mut matched: Option<String> = None;
        let mut last = "signature does not verify against any trusted approver key".to_string();
        for (key, identity) in candidates {
            match verify_witness(witness, &key, receipt, opts) {
                Ok(()) => {
                    matched = Some(identity);
                    break;
                }
                Err(why) => last = why,
            }
        }
        let Some(identity) = matched else {
            failures.push(last);
            continue;
        };
        // A hardware-key policy is only partially checkable offline: a bare P-256 key carries no
        // attestation at all, so it can never satisfy the requirement, while a WebAuthn assertion is
        // accepted without proving the authenticator's model.
        if requirement.require_hardware_key && witness.sig_alg.as_deref() != Some("WEBAUTHN") {
            failures.push(format!(
                "signer {} used a bare key, but the signed policy requires a hardware-backed WebAuthn credential",
                witness.signer_did
            ));
            continue;
        }
        // Four-eyes, verified offline against the requester in the same signed payload.
        if requirement.requester_cannot_approve && witness.signer_did == requester.did {
            failures.push(format!(
                "four-eyes: requester {} cannot approve their own action",
                witness.signer_did
            ));
            continue;
        }
        verified.insert(identity);
    }

    // Under a delegation the quorum is the DELEGATED one. Already checked to equal the offline
    // payload's signed `required_approvals`, so this is the same number by a different route — stated
    // explicitly so the substitution is visible where it takes effect. Both numbers were refused
    // above unless they are at least 1, so no floor is applied here.
    let required = delegated_quorum.unwrap_or(requirement.required_approvals) as usize;
    if verified.len() < required {
        return Err(format!(
            "quorum not met: {} of {} required approver signatures verified{}",
            verified.len(),
            required,
            fold_failures(&failures)
        ));
    }
    Ok(())
}

/// Fold per-witness failure reasons into a bounded parenthetical detail string.
///
/// Capped at [`MAX_REPORTED_FAILURES`] with a "; +N more" suffix: joining every reason is what
/// turned a 20,000-witness receipt into 1.16 MB of error text in the TS reference, and the leading
/// reasons are the diagnostic ones anyway.
fn fold_failures(failures: &[String]) -> String {
    if failures.is_empty() {
        return String::new();
    }
    let shown: Vec<&str> = failures
        .iter()
        .take(MAX_REPORTED_FAILURES)
        .map(String::as_str)
        .collect();
    let elided = failures.len().saturating_sub(MAX_REPORTED_FAILURES);
    if elided > 0 {
        format!(" ({}; +{elided} more)", shown.join("; "))
    } else {
        format!(" ({})", shown.join("; "))
    }
}

/// Verify a DELEGATION (DIV §5a.6 step 1) — a statement, signed in advance by the ordinary quorum,
/// naming local operators who may approve one pre-declared action while the gateway is unreachable.
///
/// Deliberately a SEPARATE function from [`verify_approval_receipt_with_options`], which refuses this
/// payload type outright. A delegation authorizes nothing, and the only way to keep that true
/// structurally is to make it impossible to hand one to the approval verifier and get an `Ok` back.
/// What you get here is a [`VerifiedDelegation`] — an input to a later approval check, never a
/// substitute for one.
///
/// `expected.approvers` MUST be the ORDINARY approver set, not the delegated operators: the point of
/// the check is that the people entitled to approve this action are the ones who signed away that
/// entitlement.
pub fn verify_delegation(
    receipt: &ApprovalReceipt,
    expected: &Expected,
    opts: &VerifyOptions,
) -> Result<VerifiedDelegation, String> {
    if receipt.canonical_payload.is_empty() {
        return Err("missing canonicalPayload".to_string());
    }
    let probe: Value = serde_json::from_str(&receipt.canonical_payload)
        .map_err(|_| "canonicalPayload is not valid JSON".to_string())?;
    if probe.get("v").and_then(Value::as_i64) != Some(DIV_VERSION) {
        return Err("unsupported DIV payload version".to_string());
    }
    if probe.get("type").and_then(Value::as_str) != Some(DIV_DELEGATION_TYPE) {
        return Err("payload is not a div-delegation".to_string());
    }

    // DIV §4.4.6: a Delegation REQUIRES an identity-associating anchor and MUST be refused under a
    // key-set anchor — at seal verification too, not only when delegatedTo is enforced at use time.
    // The sealing quorum names PEOPLE; in PublicKeys mode it would count credentials instead.
    if matches!(expected.approvers, ApproverTrustAnchor::PublicKeys(_)) {
        return Err(
            "a delegation requires a DID-mode trust anchor; a key-set anchor cannot associate identities (DIV §4.4.6)"
                .to_string(),
        );
    }

    let delegated_to: Vec<String> = probe
        .get("delegatedTo")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    if delegated_to.is_empty() {
        return Err("delegation is missing a valid delegatedTo set".to_string());
    }
    let delegated_quorum = probe
        .get("delegatedQuorum")
        .and_then(Value::as_i64)
        .filter(|q| *q >= 1)
        .ok_or("delegation is missing a valid delegatedQuorum")? as u32;

    // Deduplicate before the size check: a delegatedTo listing one operator three times would otherwise
    // appear to support a 3-of-3 quorum that one person could satisfy alone.
    let mut distinct: Vec<String> = Vec::new();
    for d in &delegated_to {
        if !distinct.contains(d) {
            distinct.push(d.clone());
        }
    }
    if (distinct.len() as u32) < delegated_quorum {
        return Err(format!(
            "delegation names {} distinct operator(s) but delegates a quorum of {delegated_quorum} — it can never be satisfied",
            distinct.len()
        ));
    }

    let sealed_at = canonical_str_field(&receipt.canonical_payload, "sealedAt")
        .filter(|s| !s.is_empty())
        .ok_or("delegation is missing sealedAt")?;
    let expires_at = canonical_str_field(&receipt.canonical_payload, "expiresAt")
        .filter(|s| !s.is_empty())
        .ok_or("delegation is missing expiresAt")?;
    let sealed = parse_rfc3339_utc_secs(&sealed_at)
        .ok_or("sealedAt is not a valid RFC3339 UTC timestamp")?;
    let expiry = parse_rfc3339_utc_secs(&expires_at)
        .ok_or("expiresAt is not a valid RFC3339 UTC timestamp")?;
    let window_secs = expiry - sealed;
    if window_secs < 0 {
        return Err("delegation expires before it was sealed".to_string());
    }
    if window_secs > MAX_DELEGATION_WINDOW_HOURS * 3600 {
        return Err(format!(
            "delegation window is {:.1} hours, over the {MAX_DELEGATION_WINDOW_HOURS}-hour maximum",
            window_secs as f64 / 3600.0
        ));
    }
    // Position, not just width (DIV §5a.6 step 1, mirroring §5a.3 rule 3). A forward-dated
    // `sealedAt` slides the 72-hour window arbitrarily far out, and §5a.8 names that cap as
    // Delegation's ONLY mitigation. Unconditional, like the offline mirror.
    let (now, skew) = evaluation_time(opts);
    if sealed > now + skew {
        return Err("delegation is sealed in the future (DIV §5a.6)".to_string());
    }

    let requester = receipt
        .requester
        .as_ref()
        .ok_or("delegation missing requester")?;
    let requirement: ApprovalRequirement = probe
        .get("requirement")
        .cloned()
        .and_then(|v| serde_json::from_value(v).ok())
        .ok_or("delegation payload is missing the signed approval requirement")?;
    check_quorum_minimum(&requirement)?;
    check_signer_class(&requirement)?;
    if expected.target.is_empty() {
        return Err("expected.target is required — it must be YOUR target identifier, asserted independently of the delegation (DIV Target Isolation)".to_string());
    }
    let payload_nonce =
        canonical_str_field(&receipt.canonical_payload, "nonce").unwrap_or_default();

    let recomputed = canonical_delegation_payload(
        &expected.target,
        &expected.action_type,
        &receipt.action_description,
        &expected.params,
        requester,
        &requirement,
        &delegated_to,
        delegated_quorum as i64,
        &payload_nonce,
        &sealed_at,
        &expires_at,
    )
    // Same split as the approval path: this is a canonicalization refusal on the caller's own
    // params, deliberately distinct from the tampering-shaped "do not match" reason below.
    .map_err(|why| {
        format!("params contain a non-portable number and cannot be canonicalized: {why}")
    })?;
    if recomputed != receipt.canonical_payload {
        return Err("target/params/actionType do not match what was delegated".to_string());
    }

    if !opts.allow_expired && now > expiry + skew {
        return Err(
            "delegation has expired (set allow_expired for audit re-verification)".to_string(),
        );
    }
    if receipt.sig_alg.as_deref() == Some("AUTO_APPROVED") {
        return Err("a delegation cannot be auto-approved — delegating approval authority requires human signatures".to_string());
    }

    let witnesses = witnesses_of(receipt);
    if witnesses.is_empty() {
        return Err("delegation missing signature material".to_string());
    }
    // Same DoS bound as the approval path: the witness list is attacker-supplied and a delegation
    // is signed by a single-digit quorum.
    if witnesses.len() > MAX_WITNESSES {
        return Err(format!(
            "delegation carries {} witnesses, above the {MAX_WITNESSES} this verifier will process",
            witnesses.len()
        ));
    }
    let mut verified: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut failures: Vec<String> = Vec::new();
    for witness in &witnesses {
        let candidates = match expected.approvers.candidates(&witness.signer_did) {
            Ok(c) => c,
            Err(reason) => {
                failures.push(reason);
                continue;
            }
        };
        let mut matched: Option<String> = None;
        let mut last = "signature does not verify against any trusted approver key".to_string();
        for (key, identity) in candidates {
            match verify_witness(witness, &key, receipt, opts) {
                Ok(()) => {
                    matched = Some(identity);
                    break;
                }
                Err(why) => last = why,
            }
        }
        let Some(identity) = matched else {
            failures.push(last);
            continue;
        };
        if requirement.require_hardware_key && witness.sig_alg.as_deref() != Some("WEBAUTHN") {
            failures.push(format!(
                "signer {} used a bare key, but the signed policy requires a hardware-backed WebAuthn credential",
                witness.signer_did
            ));
            continue;
        }
        if requirement.requester_cannot_approve && witness.signer_did == requester.did {
            failures.push(format!(
                "four-eyes: requester {} cannot delegate to themselves",
                witness.signer_did
            ));
            continue;
        }
        verified.insert(identity);
    }

    let required = requirement.required_approvals as usize;
    if verified.len() < required {
        let detail = fold_failures(&failures);
        return Err(format!(
            "delegation quorum not met: {} of {required} required approver signatures verified{detail}",
            verified.len()
        ));
    }

    Ok(VerifiedDelegation {
        // The DEDUPLICATED set: this is what gets enforced against witness DIDs later, and a duplicate
        // entry must not create the illusion of a larger eligible pool.
        delegated_to: distinct,
        delegated_quorum,
        target: expected.target.clone(),
        action_type: expected.action_type.clone(),
        params: expected.params.clone(),
        nonce: payload_nonce,
        signers: verified.into_iter().collect(),
        expires_at,
    })
}

/// Normalize a receipt to a witness list: `signatures` if present, else the single-signature fields.
fn witnesses_of(receipt: &ApprovalReceipt) -> Vec<ApprovalWitness> {
    if let Some(sigs) = &receipt.signatures {
        if !sigs.is_empty() {
            return sigs.clone();
        }
    }
    match (&receipt.signer_public_key, &receipt.signature) {
        (Some(key), Some(sig)) => vec![ApprovalWitness {
            signer_did: receipt.signer_did.clone().unwrap_or_default(),
            signer_public_key: key.clone(),
            signature: sig.clone(),
            sig_alg: receipt.sig_alg.clone(),
            authenticator_data: receipt.authenticator_data.clone(),
            client_data_json: receipt.client_data_json.clone(),
        }],
        _ => Vec::new(),
    }
}

/// Verify one witness signature using an already-TRUSTED key.
fn verify_witness(
    witness: &ApprovalWitness,
    trusted_key: &str,
    receipt: &ApprovalReceipt,
    opts: &VerifyOptions,
) -> Result<(), String> {
    if witness.sig_alg.as_deref() == Some("WEBAUTHN") {
        return webauthn::verify_webauthn_witness(witness, trusted_key, receipt, opts);
    }
    // ES256: the human's key signed the canonical payload bytes directly.
    let pub_bytes = STANDARD
        .decode(trusted_key)
        .map_err(|_| "invalid trusted key base64".to_string())?;
    let sig_bytes = STANDARD
        .decode(&witness.signature)
        .map_err(|_| "invalid signature base64".to_string())?;
    let verifying_key = parse_p256_public_key(&pub_bytes)
        .ok_or_else(|| "failed to parse trusted approver key".to_string())?;
    if verify_p256_signature(
        &verifying_key,
        receipt.canonical_payload.as_bytes(),
        &sig_bytes,
    ) {
        Ok(())
    } else {
        Err("signature does not verify against the trusted signer key".to_string())
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

    // Local fixture for unit-behavior tests (signature handling, tampering, expiry, quorum). The
    // authoritative CANONICALIZATION parity pin is the shared vectors file
    // (packages/mcp-schemas/vectors/canonical-vectors.json) via test_shared_intent_payload_vectors.
    fn signed_receipt() -> (ApprovalReceipt, Expected) {
        let requester = RequesterIdentity {
            did: "did:intyga:service:deploy-pipeline".to_string(),
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
            &default_requirement(),
            "c_8f91a2",
            "2999-01-01T00:00:00.000Z",
        )
        .expect("canonicalize fixture payload");

        let sk = test_signing_key();
        let sig: Signature = sk.sign(canonical.as_bytes());
        let spki = sk.verifying_key().to_public_key_der().expect("encode SPKI");

        let receipt = ApprovalReceipt {
            canonical_payload: canonical,
            target: Some("prod-db-cluster-01".to_string()),
            action_type: Some("deleteDatabase".to_string()),
            action_description: "Delete staging database".to_string(),
            params: params.clone(),
            signer_did: Some("did:intyga:user:alice".to_string()),
            signer_public_key: Some(STANDARD.encode(spki.as_bytes())),
            signature: Some(STANDARD.encode(sig.to_der().as_bytes())),
            sig_alg: Some("ES256".to_string()),
            authenticator_data: None,
            client_data_json: None,
            requester: Some(requester),
            signatures: None,
            verification_code: "1234".to_string(),
        };
        let expected = Expected {
            target: "prod-db-cluster-01".to_string(),
            nonce: "c_8f91a2".to_string(),
            action_type: "deleteDatabase".to_string(),
            params,
            approvers: ApproverTrustAnchor::PublicKeys(vec![STANDARD.encode(spki.as_bytes())]),
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

    /// DIV §4.3.2 / §5-step-3a: the signerClass registry fails closed. An unrecognized class must
    /// never verify as if it were human-approved, and a payload with no class predates the field
    /// and cannot be verified by this version. Both receipts are GENUINELY signed, which pins that
    /// the refusal is the registry rule rather than a broken signature.
    #[test]
    fn test_signer_class_registry_fails_closed() {
        for (class, want) in [
            ("delegated-agent", "does not recognize"),
            ("", "missing signerClass"),
        ] {
            let requester = RequesterIdentity {
                did: "did:intyga:service:deploy-pipeline".to_string(),
                attestation: None,
            };
            let params = json!({ "environment": "staging" });
            let requirement = ApprovalRequirement {
                signer_class: class.to_string(),
                ..default_requirement()
            };
            let canonical = canonical_intent_payload(
                "prod-db-cluster-01",
                "deleteDatabase",
                "Delete staging database",
                &params,
                &requester,
                &requirement,
                "c_8f91a2",
                "2999-01-01T00:00:00.000Z",
            )
            .expect("canonicalize fixture payload");
            let sk = test_signing_key();
            let sig: Signature = sk.sign(canonical.as_bytes());
            let spki = sk.verifying_key().to_public_key_der().expect("encode SPKI");
            let (mut receipt, mut expected) = signed_receipt();
            receipt.canonical_payload = canonical;
            receipt.signature = Some(STANDARD.encode(sig.to_der().as_bytes()));
            expected.approvers =
                ApproverTrustAnchor::PublicKeys(vec![STANDARD.encode(spki.as_bytes())]);
            let err = verify_approval_receipt(&receipt, &expected)
                .expect_err(&format!("signerClass {class:?} must be refused"));
            assert!(
                err.contains(want),
                "signerClass {class:?}: refused for the wrong reason: {err}"
            );
        }
    }

    #[test]
    fn test_valid_signature_wrong_key_is_rejected() {
        // A well-formed signature that simply was not made over this payload:
        // flip the signed message but keep the (now stale) signature.
        let (mut receipt, expected) = signed_receipt();
        let sk = test_signing_key();
        let other: Signature = sk.sign(b"a completely different message");
        receipt.signature = Some(STANDARD.encode(other.to_der().as_bytes()));
        // The failure is now reported through the quorum, which names the underlying reason.
        let err = verify_approval_receipt(&receipt, &expected).expect_err("must not verify");
        assert!(
            err.contains("does not verify against the trusted signer key"),
            "unexpected reason: {err}"
        );
    }

    #[test]
    fn test_tampered_params_are_rejected() {
        // Approver signed environment=staging; relying party checks production.
        let (receipt, base) = signed_receipt();
        let expected = Expected {
            target: "prod-db-cluster-01".to_string(),
            nonce: "c_8f91a2".to_string(),
            action_type: "deleteDatabase".to_string(),
            params: json!({ "environment": "production" }),
            approvers: base.approvers,
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
                // For a golden vector the committed file is the enrollment record, so pinning its
                // key is the legitimate resolution step — it still comes from outside the verifier.
                approvers: ApproverTrustAnchor::PublicKeys(vec![receipt
                    .signer_public_key
                    .clone()
                    .unwrap_or_default()]),
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
            // Pinning the REASON, not just the refusal: `0 >= 0` makes DIV §5 step 7 true with
            // nothing counted, so this receipt can be refused for the right rule or for none.
            if name == "zero-required-approvals-refused" {
                let err = result.clone().expect_err("must be refused");
                assert!(
                    err.contains("requiredApprovals must be an integer of at least 1"),
                    "{name}: refused for the wrong rule ({err})"
                );
            }
            checked += 1;
        }
        assert!(
            checked >= 3,
            "expected to exercise the current-version vectors, ran {}",
            checked
        );
    }

    /// Byte-parity for the SEALED BREAK-GLASS builder against the shared golden vectors.
    ///
    /// The receipts test above exercises verification; this one pins the CANONICALIZATION, which is
    /// where a port silently diverges. A Rust build that emits different bytes would produce tokens
    /// no TypeScript relying party can verify — and the failure would look like tampering.
    /// Shared helper: read one requirement out of a golden vector case.
    fn vector_requirement(i: &Value) -> ApprovalRequirement {
        ApprovalRequirement {
            required_approvals: i["requirement"]["requiredApprovals"].as_u64().unwrap_or(1) as u32,
            require_hardware_key: i["requirement"]["requireHardwareKey"]
                .as_bool()
                .unwrap_or(false),
            allowed_aaguids: i["requirement"]["allowedAaguids"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default(),
            requester_cannot_approve: i["requirement"]["requesterCannotApprove"]
                .as_bool()
                .unwrap_or(false),
            signer_class: i["requirement"]["signerClass"]
                .as_str()
                .unwrap_or("")
                .to_string(),
        }
    }

    fn golden_vectors() -> Value {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/vectors/canonical-vectors.json"
        );
        let raw = std::fs::read_to_string(path).expect("read golden vectors");
        serde_json::from_str(&raw).expect("parse golden vectors")
    }

    /// A case's committed evaluation time (DIV §5a.3 rule 3). Panics rather than defaulting to the
    /// wall clock: a missing `asOf` would silently restore the position-blind behaviour these
    /// vectors pin against.
    fn vector_as_of(name: &str, case: &Value) -> i64 {
        case["asOf"]
            .as_str()
            .and_then(parse_rfc3339_utc_secs)
            .unwrap_or_else(|| panic!("{name}: vector carries no usable asOf"))
    }

    /// Runs the canonicalizer against the same `stableStringify` cases the TypeScript and Python
    /// suites use. This port implements its own `stable_stringify` but never checked it against the
    /// shared file — the receipts happen to exercise none of the awkward inputs, which is how a
    /// whole-valued-float divergence survived.
    ///
    /// NOTE what this CANNOT catch: JSON has no int/float distinction, so `100.0` in the vector file
    /// round-trips to an integer-typed `Value` here. The f64 path is pinned by
    /// `test_stable_stringify_whole_floats_match_javascript`, which builds the value in Rust.
    #[test]
    fn test_shared_stable_stringify_vectors() {
        let doc = golden_vectors();
        let cases = doc["stableStringify"]
            .as_array()
            .expect("canonical-vectors.json carries no stableStringify cases");
        assert!(!cases.is_empty());
        for c in cases {
            let got = stable_stringify(&c["value"]).expect("vector value must canonicalize");
            assert_eq!(
                got,
                c["expected"].as_str().unwrap(),
                "stableStringify[{}]",
                c["name"]
            );
        }
    }

    /// Pins the OFFLINE APPROVAL canonicalization against the shared vectors. This is where a port
    /// silently diverges: a Rust build emitting different bytes could not verify an approval any
    /// TypeScript relying party produced, and the failure would look like tampering rather than drift.
    #[test]
    fn offline_intent_canonical_parity() {
        let doc = golden_vectors();
        let cases = doc["offlineIntentPayloads"]
            .as_array()
            .expect("offlineIntentPayloads array");
        assert!(!cases.is_empty(), "no offline-approval vectors present");

        for case in cases {
            let i = &case["input"];
            let requester: RequesterIdentity =
                serde_json::from_value(i["requester"].clone()).expect("requester");
            let got = canonical_offline_intent_payload(
                i["target"].as_str().unwrap_or_default(),
                i["actionType"].as_str().unwrap_or_default(),
                i["actionDescription"].as_str().unwrap_or_default(),
                &i["params"],
                &requester,
                &vector_requirement(i),
                i["nonce"].as_str().unwrap_or_default(),
                i["challengedAt"].as_str().unwrap_or_default(),
                i["expiresAt"].as_str().unwrap_or_default(),
            )
            .expect("canonicalize offline vector");
            assert_eq!(got, case["expected"].as_str().unwrap_or_default());
            assert!(got.contains("\"type\":\"div-offline-intent\""));
        }
    }

    /// Pins the DELEGATION canonicalization, including that `delegatedTo` is canonicalized as a SET.
    /// The vector input is deliberately unsorted, so this is what proves the sort.
    #[test]
    fn delegation_canonical_parity() {
        let doc = golden_vectors();
        let cases = doc["delegationPayloads"]
            .as_array()
            .expect("delegationPayloads array");
        assert!(!cases.is_empty(), "no delegation vectors present");

        for case in cases {
            let i = &case["input"];
            let requester: RequesterIdentity =
                serde_json::from_value(i["requester"].clone()).expect("requester");
            let delegated_to: Vec<String> = i["delegatedTo"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();
            let got = canonical_delegation_payload(
                i["target"].as_str().unwrap_or_default(),
                i["actionType"].as_str().unwrap_or_default(),
                i["actionDescription"].as_str().unwrap_or_default(),
                &i["params"],
                &requester,
                &vector_requirement(i),
                &delegated_to,
                i["delegatedQuorum"].as_i64().unwrap_or(0),
                i["nonce"].as_str().unwrap_or_default(),
                i["sealedAt"].as_str().unwrap_or_default(),
                i["expiresAt"].as_str().unwrap_or_default(),
            )
            .expect("canonicalize delegation vector");
            assert_eq!(got, case["expected"].as_str().unwrap_or_default());
            assert!(got.contains("\"type\":\"div-delegation\""));
            assert!(got.contains(
                // UTF-16 code-unit order: U+1F600 before U+FFFD, where a UTF-8 byte sort puts it after.
                "\"delegatedTo\":[\"did:intyga:sre-a\",\"did:intyga:sre-c\",\"did:intyga:sre-\u{1F600}\",\"did:intyga:sre-\u{FFFD}\"]"
            ));
        }
    }

    /// The property that matters more than parity: the payload kinds must never produce the same bytes
    /// for the same action. If they could, an out-of-band approval would be indistinguishable from a
    /// gateway-mediated one, and an ordinary approval could be replayed as an offline one.
    #[test]
    fn payload_kinds_never_collide() {
        let doc = golden_vectors();
        for case in doc["offlineIntentPayloads"].as_array().unwrap() {
            let i = &case["input"];
            let requester: RequesterIdentity =
                serde_json::from_value(i["requester"].clone()).expect("requester");
            let req = vector_requirement(i);
            let offline = canonical_offline_intent_payload(
                i["target"].as_str().unwrap_or_default(),
                i["actionType"].as_str().unwrap_or_default(),
                i["actionDescription"].as_str().unwrap_or_default(),
                &i["params"],
                &requester,
                &req,
                i["nonce"].as_str().unwrap_or_default(),
                i["challengedAt"].as_str().unwrap_or_default(),
                i["expiresAt"].as_str().unwrap_or_default(),
            )
            .expect("canonicalize offline vector");
            let intent = canonical_intent_payload(
                i["target"].as_str().unwrap_or_default(),
                i["actionType"].as_str().unwrap_or_default(),
                i["actionDescription"].as_str().unwrap_or_default(),
                &i["params"],
                &requester,
                &req,
                i["nonce"].as_str().unwrap_or_default(),
                i["expiresAt"].as_str().unwrap_or_default(),
            )
            .expect("canonicalize intent vector");
            assert_ne!(offline, intent, "offline and intent payloads must differ");
        }
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
            approvers: ApproverTrustAnchor::PublicKeys(vec![receipt
                .signer_public_key
                .clone()
                .unwrap_or_default()]),
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
            approvers: ApproverTrustAnchor::PublicKeys(vec![v
                .receipt
                .signer_public_key
                .clone()
                .unwrap_or_default()]),
        };
        let res = verify_approval_receipt_with_options(
            &v.receipt,
            &tampered,
            &wa_opts(Some(&v.origin), Some(&v.rp_id)),
        );
        assert!(res.is_err(), "tampered params must not verify");
    }

    /// The no-rule-matched policy: single-sig, no hardware requirement, no four-eyes.
    fn default_requirement() -> ApprovalRequirement {
        ApprovalRequirement {
            required_approvals: 1,
            require_hardware_key: false,
            allowed_aaguids: vec![],
            requester_cannot_approve: false,
            signer_class: "human".to_string(),
        }
    }

    #[test]
    fn test_canonical_intent_parity() {
        let params = json!({
            "zeta": 1,
            "alpha": 2,
            "mid": { "z": 1, "a": 2 }
        });
        let requester = RequesterIdentity {
            did: "did:intyga:service:deploy-pipeline".to_string(),
            attestation: None,
        };
        // Deliberately UNSORTED allowedAaguids: the builder sorts, and this pins that it does.
        let requirement = ApprovalRequirement {
            required_approvals: 2,
            require_hardware_key: true,
            allowed_aaguids: vec!["b-aaguid".to_string(), "a-aaguid".to_string()],
            requester_cannot_approve: true,
            signer_class: "human".to_string(),
        };
        let got = canonical_intent_payload(
            "prod-db-cluster-01",
            "deleteDatabase",
            "Delete staging database",
            &params,
            &requester,
            &requirement,
            "c_8f91a2",
            "2026-07-23T19:30:00Z",
        )
        .expect("canonicalize");
        // Strict RFC 8785 JCS: every key sorted; type/version last. Byte-for-byte the string the TS
        // reference implementation (@intyga/mcp-schemas) emits for the same input.
        let expected = r#"{"actionType":"deleteDatabase","display":"Delete staging database","expiresAt":"2026-07-23T19:30:00Z","nonce":"c_8f91a2","params":{"alpha":2,"mid":{"a":2,"z":1},"zeta":1},"requester":{"attestation":null,"did":"did:intyga:service:deploy-pipeline"},"requirement":{"allowedAaguids":["a-aaguid","b-aaguid"],"requesterCannotApprove":true,"requireHardwareKey":true,"requiredApprovals":2,"signerClass":"human"},"target":"prod-db-cluster-01","type":"div-intent-verification","v":1}"#;
        assert_eq!(got, expected);
    }

    #[test]
    fn test_expiry_fail_closed_and_allow_expired() {
        // Build a receipt that expired in 2020.
        let requester = RequesterIdentity {
            did: "did:intyga:service:deploy-pipeline".to_string(),
            attestation: None,
        };
        let params = json!({ "environment": "staging" });
        let canonical = canonical_intent_payload(
            "prod-db-cluster-01",
            "deleteDatabase",
            "Delete staging database",
            &params,
            &requester,
            &default_requirement(),
            "c_exp",
            "2020-01-01T00:00:00.000Z",
        )
        .expect("canonicalize");
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
            signatures: None,
            verification_code: "1234".to_string(),
        };
        let expected = Expected {
            target: "prod-db-cluster-01".to_string(),
            nonce: "c_exp".to_string(),
            action_type: "deleteDatabase".to_string(),
            params,
            approvers: ApproverTrustAnchor::PublicKeys(vec![STANDARD.encode(spki.as_bytes())]),
        };
        // Fail-closed by default.
        assert!(verify_approval_receipt(&receipt, &expected).is_err());
        // allow_expired accepts the otherwise-valid proof (audit re-verification).
        let opts = VerifyOptions {
            allow_expired: true,
            ..Default::default()
        };
        assert_eq!(
            verify_approval_receipt_with_options(&receipt, &expected, &opts),
            Ok(())
        );
    }

    #[test]
    fn test_rfc3339_parser() {
        assert_eq!(parse_rfc3339_utc_secs("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(
            parse_rfc3339_utc_secs("2020-01-01T00:00:00.000Z"),
            Some(1_577_836_800)
        );
        assert_eq!(parse_rfc3339_utc_secs("not-a-date"), None);

        // A numeric offset is ACCEPTED and normalized to UTC. This assertion used to read
        // `..."+02:00"), None); // UTC only`, and that strictness was a real interoperability
        // defect rather than rigour: `Date.parse` in the TS reference and `time.RFC3339` in the Go
        // port both accept an offset, so a receipt they verify was refused here alone. An offset is
        // only a representation of an instant — normalizing loses nothing and gains parity.
        //
        // It mattered because the caller treated None as "skip the window check": a proof carrying
        // `+00:00` — which denotes UTC, so nothing is even irregular about it — jumped the
        // offline-window cap in this port while every other port enforced it.
        assert_eq!(
            parse_rfc3339_utc_secs("2020-01-01T00:00:00+02:00"),
            Some(1_577_829_600)
        );
        assert_eq!(
            parse_rfc3339_utc_secs("2020-01-01T00:00:00-02:00"),
            Some(1_577_844_000)
        );
        assert_eq!(
            parse_rfc3339_utc_secs("2020-01-01T00:00:00+00:00"),
            parse_rfc3339_utc_secs("2020-01-01T00:00:00Z"),
            "+00:00 and Z denote the same instant and must parse identically"
        );
        assert_eq!(
            parse_rfc3339_utc_secs("2020-01-01T00:00:00.500+01:00"),
            Some(1_577_833_200)
        );

        // Malformed zones stay refused — and now that the caller fails closed on None, "refused"
        // means the verification is refused, not that the window check is skipped.
        assert_eq!(parse_rfc3339_utc_secs("2020-01-01T00:00:00+0200"), None);
        assert_eq!(parse_rfc3339_utc_secs("2020-01-01T00:00:00+99:00"), None);
        assert_eq!(parse_rfc3339_utc_secs("2020-01-01T00:00:00"), None);
        assert_eq!(parse_rfc3339_utc_secs("2020-01-01T00:00:00."), None);
    }

    // ─── July 2026 audit regressions ────────────────────────────────────────

    /// DIV §5: opting in to AUTO_APPROVED waives the SIGNATURE requirement (steps 6-7), never the
    /// target-binding and expiry steps (8 and 9). The accept used to sit immediately after the nonce
    /// comparison, so a receipt was attested having proven only that its nonce matched — an agent
    /// holding a nonce could get a trivial action auto-approved and present it for a destructive one.
    #[test]
    fn test_auto_approved_still_binds_target_and_params() {
        let requester = RequesterIdentity {
            did: "did:intyga:service:agent".to_string(),
            attestation: None,
        };
        // What was actually approved: a harmless read on a sandbox, long expired.
        let approved_params = json!({ "path": "/tmp" });
        let canonical = canonical_intent_payload(
            "sandbox-cluster",
            "listFiles",
            "List files",
            &approved_params,
            &requester,
            &default_requirement(),
            "c_nonce_1",
            "2020-01-01T00:00:00.000Z",
        )
        .expect("canonicalize");
        let receipt = ApprovalReceipt {
            canonical_payload: canonical,
            target: Some("sandbox-cluster".to_string()),
            action_type: Some("listFiles".to_string()),
            action_description: "List files".to_string(),
            params: approved_params.clone(),
            signer_did: None,
            signer_public_key: None,
            signature: None,
            sig_alg: Some("AUTO_APPROVED".to_string()),
            authenticator_data: None,
            client_data_json: None,
            requester: Some(requester),
            signatures: None,
            verification_code: "1234".to_string(),
        };

        // What the relying party is about to execute: something else entirely.
        let destructive = Expected {
            target: "prod-db-cluster-01".to_string(),
            nonce: "c_nonce_1".to_string(),
            action_type: "deleteDatabase".to_string(),
            params: json!({ "environment": "production" }),
            approvers: ApproverTrustAnchor::PublicKeys(vec![]),
        };
        let opted_in = VerifyOptions {
            allow_auto_approved: true,
            ..Default::default()
        };
        assert!(
            verify_approval_receipt_with_options(&receipt, &destructive, &opted_in).is_err(),
            "auto-approved receipt for a DIFFERENT action must not verify"
        );

        let matching = Expected {
            target: "sandbox-cluster".to_string(),
            nonce: "c_nonce_1".to_string(),
            action_type: "listFiles".to_string(),
            params: approved_params,
            approvers: ApproverTrustAnchor::PublicKeys(vec![]),
        };
        // Refused by default even when the action lines up.
        assert!(verify_approval_receipt(&receipt, &matching).is_err());
        // Still expiry-checked once opted in.
        assert!(
            verify_approval_receipt_with_options(&receipt, &matching, &opted_in).is_err(),
            "a 2020-expired auto-approval must not verify"
        );
        // The genuine case: matching action, opted in, expiry waived for re-verification.
        let forensic = VerifyOptions {
            allow_auto_approved: true,
            allow_expired: true,
            ..Default::default()
        };
        assert_eq!(
            verify_approval_receipt_with_options(&receipt, &matching, &forensic),
            Ok(())
        );
    }

    /// Build a signed OFFLINE proof (DIV §5a.2) with the given window endpoints.
    fn signed_offline_receipt(
        challenged_at: &str,
        expires_at: &str,
    ) -> (ApprovalReceipt, Expected) {
        let requester = RequesterIdentity {
            did: "did:intyga:service:pipeline".to_string(),
            attestation: None,
        };
        let params = json!({ "environment": "prod" });
        let canonical = canonical_offline_intent_payload(
            "prod-db",
            "deleteDatabase",
            "Drop prod",
            &params,
            &requester,
            &default_requirement(),
            "off-window-test",
            challenged_at,
            expires_at,
        )
        .expect("canonicalize offline fixture");
        let sk = test_signing_key();
        let sig: Signature = sk.sign(canonical.as_bytes());
        let spki = sk.verifying_key().to_public_key_der().expect("encode SPKI");
        let pub_b64 = STANDARD.encode(spki.as_bytes());

        let receipt = ApprovalReceipt {
            canonical_payload: canonical,
            target: Some("prod-db".to_string()),
            action_type: Some("deleteDatabase".to_string()),
            action_description: "Drop prod".to_string(),
            params: params.clone(),
            signer_did: Some("did:intyga:human:alice".to_string()),
            signer_public_key: Some(pub_b64.clone()),
            signature: Some(STANDARD.encode(sig.to_der().as_bytes())),
            sig_alg: Some("ES256".to_string()),
            authenticator_data: None,
            client_data_json: None,
            requester: Some(requester),
            signatures: None,
            verification_code: "1234".to_string(),
        };
        let expected = Expected {
            target: "prod-db".to_string(),
            nonce: "off-window-test".to_string(),
            action_type: "deleteDatabase".to_string(),
            params,
            approvers: ApproverTrustAnchor::PublicKeys(vec![pub_b64]),
        };
        (receipt, expected)
    }

    /// DIV §5a.3: the validity window is the ENTIRE revocation story for an offline proof, since an
    /// offline relying party has no channel to recall one. The cap used to sit inside
    /// `if let Some(expiry) = parse_rfc3339_utc_secs(&expires_at)`, so an unparseable value skipped
    /// it — and the only other place expiresAt is parsed is the expiry check, which `allow_expired`
    /// disables. `allow_offline + allow_expired` is the documented forensic re-verification mode and
    /// the only mode under which an offline proof is examined at all, so the window was unbounded.
    ///
    /// This port was the worst of the three affected: `+00:00` is valid RFC 3339 denoting UTC, and
    /// both the TS reference and the Go port accept it — only this parser did not, so a proof they
    /// would refuse for its window passed here.
    #[test]
    fn test_offline_window_refuses_unparseable_expiry() {
        let forensic = VerifyOptions {
            allow_offline: true,
            allow_expired: true,
            ..Default::default()
        };
        for expires_at in [
            "2036-01-01 00:00:00Z",
            "9999-99-99T99:99:99Z",
            "garbage",
            "2036-01-01T00:00:00",
        ] {
            let (receipt, expected) = signed_offline_receipt("2026-01-01T00:00:00Z", expires_at);
            let got = verify_approval_receipt_with_options(&receipt, &expected, &forensic);
            assert!(
                got.is_err(),
                "expiresAt {expires_at:?}: accepted a ~10-year window against a {MAX_OFFLINE_WINDOW_MINUTES}-minute cap"
            );
        }
    }

    #[test]
    fn test_offline_window_refuses_an_overlong_but_parseable_window() {
        let forensic = VerifyOptions {
            allow_offline: true,
            allow_expired: true,
            ..Default::default()
        };
        // The exact string that passed before: valid RFC 3339, ten years wide, non-Z offset.
        let (receipt, expected) =
            signed_offline_receipt("2026-01-01T00:00:00Z", "2036-01-01T00:00:00+00:00");
        let got = verify_approval_receipt_with_options(&receipt, &expected, &forensic);
        assert!(got.is_err(), "accepted a 10-year offline window");
        assert!(
            got.unwrap_err().contains("over the"),
            "refused for the wrong reason"
        );
    }

    #[test]
    fn test_offline_window_accepts_a_proof_inside_the_cap() {
        // The fix must not turn every offline proof into a refusal — including one written with a
        // numeric offset rather than Z, which the sibling ports accept.
        let forensic = VerifyOptions {
            allow_offline: true,
            allow_expired: true,
            ..Default::default()
        };
        let (receipt, expected) =
            signed_offline_receipt("2026-01-01T00:00:00Z", "2026-01-01T00:30:00+00:00");
        assert_eq!(
            verify_approval_receipt_with_options(&receipt, &expected, &forensic),
            Ok(())
        );
    }

    /// RFC 8785 §3.2.2.3 mandates ES6 Number::toString. serde_json prints whole-valued f64 with a
    /// decimal point, so a relying party building expected params from its own runtime (an f64
    /// struct field, `json!({"amount": 100.0})`) got a false "params do not match" on a valid
    /// receipt. Values parsed from JSON *text* stay integer-typed, which is why this was invisible.
    #[test]
    fn test_stable_stringify_whole_floats_match_javascript() {
        assert_eq!(stable_stringify(&json!(3.0)).unwrap(), "3");
        assert_eq!(stable_stringify(&json!(100.0)).unwrap(), "100");
        assert_eq!(stable_stringify(&json!(-7.0)).unwrap(), "-7");
        assert_eq!(stable_stringify(&json!(0.0)).unwrap(), "0");
        // -0.0 used to fold silently to "0"; it is now REFUSED, matching the TS producer
        // (isPortableNumber) — see test_stable_stringify_refuses_non_portable_numbers.
        // Genuine fractions are untouched.
        assert_eq!(stable_stringify(&json!(1.5)).unwrap(), "1.5");
        // Integer-typed values still render as before.
        assert_eq!(stable_stringify(&json!(3)).unwrap(), "3");

        // The end-to-end consequence: an f64-built param object canonicalizes to the same bytes as
        // the integer-typed one a signature was produced over.
        let requester = RequesterIdentity {
            did: "did:x".to_string(),
            attestation: None,
        };
        let from_runtime = canonical_intent_payload(
            "t",
            "a",
            "d",
            &json!({ "amount": 100.0 }),
            &requester,
            &default_requirement(),
            "n",
            "2026-01-01T00:00:00.000Z",
        )
        .expect("canonicalize");
        let from_json_text = canonical_intent_payload(
            "t",
            "a",
            "d",
            &serde_json::from_str::<Value>(r#"{"amount":100}"#).unwrap(),
            &requester,
            &default_requirement(),
            "n",
            "2026-01-01T00:00:00.000Z",
        )
        .expect("canonicalize");
        assert_eq!(from_runtime, from_json_text);
    }

    /// Parity with `isPortableNumber` (@intyga/mcp-schemas) / `NonCanonicalValue` (@intyga/verify):
    /// numbers whose canonical form diverges across the TS/Go/Rust/Python ports are REFUSED rather
    /// than serialized. serde_json would print several of these exactly — which is precisely the
    /// problem: a Rust RP would sign bytes the TS reference refuses to produce, and the mismatch
    /// would surface at a customer's site looking like tampering.
    #[test]
    fn test_stable_stringify_refuses_non_portable_numbers() {
        // f64 at/above 1e16: every implementation switches to exponent notation at its own threshold.
        assert!(stable_stringify(&json!(1e16)).is_err());
        assert!(stable_stringify(&json!(-1e16)).is_err());
        // The i64/u64 branches must reject the bound TOO: json!(10000000000000000i64) serialized
        // exactly before this change, while TS refuses it.
        assert!(stable_stringify(&json!(10_000_000_000_000_000i64)).is_err());
        assert!(stable_stringify(&json!(100_000_000_000_000_000i64)).is_err()); // 1e17
        assert!(stable_stringify(&json!(-100_000_000_000_000_000i64)).is_err());
        assert!(stable_stringify(&json!(10_000_000_000_000_000u64)).is_err());
        // Tiny non-integer magnitudes: Python's repr goes exponential below 1e-4.
        assert!(stable_stringify(&json!(0.00001)).is_err());
        // Negative zero: "-0.0" here, "0" in JS. Previously folded silently; now refused.
        assert!(stable_stringify(&json!(-0.0)).is_err());
        // The refusal reaches nested values.
        assert!(stable_stringify(&json!({ "a": [1, { "b": 1e16 }] })).is_err());
        // The reason text names the value so the caller can find it.
        let err = stable_stringify(&json!(1e16)).unwrap_err();
        assert!(
            err.contains("portable"),
            "reason must name portability: {err}"
        );

        // Boundary acceptances — the exact values the shared floats-portable vector pins.
        assert_eq!(
            stable_stringify(&json!(9999999999999998.0)).unwrap(),
            "9999999999999998"
        );
        assert_eq!(
            stable_stringify(&json!(9_999_999_999_999_998i64)).unwrap(),
            "9999999999999998"
        );
        assert_eq!(stable_stringify(&json!(0.0001)).unwrap(), "0.0001");
        assert_eq!(stable_stringify(&json!(0)).unwrap(), "0");
    }

    /// The builders propagate the refusal instead of emitting an unverifiable payload.
    #[test]
    fn test_builders_propagate_non_portable_params() {
        let requester = RequesterIdentity {
            did: "did:x".to_string(),
            attestation: None,
        };
        let bad = json!({ "amount": 1e16 });
        assert!(canonical_intent_payload(
            "t",
            "a",
            "d",
            &bad,
            &requester,
            &default_requirement(),
            "n",
            "2026-01-01T00:00:00.000Z",
        )
        .is_err());
        assert!(canonical_offline_intent_payload(
            "t",
            "a",
            "d",
            &bad,
            &requester,
            &default_requirement(),
            "n",
            "2026-01-01T00:00:00Z",
            "2026-01-01T00:30:00Z",
        )
        .is_err());
        assert!(canonical_delegation_payload(
            "t",
            "a",
            "d",
            &bad,
            &requester,
            &default_requirement(),
            &["did:intyga:sre-a".to_string()],
            1,
            "n",
            "2026-01-01T00:00:00Z",
            "2026-01-01T12:00:00Z",
        )
        .is_err());
    }

    /// A relying party whose OWN expected params contain a non-portable number gets a fail-closed
    /// refusal that says so — not the tampering-shaped "do not match what was approved", which
    /// would send an operator hunting for an attacker that does not exist.
    #[test]
    fn test_verify_fails_closed_on_non_portable_expected_params() {
        let (receipt, base) = signed_receipt();
        let expected = Expected {
            target: base.target,
            nonce: base.nonce,
            action_type: base.action_type,
            params: json!({ "environment": "staging", "amount": 1e16 }),
            approvers: base.approvers,
        };
        let err = verify_approval_receipt(&receipt, &expected).expect_err("must fail closed");
        assert!(
            err.contains("non-portable number"),
            "reason must name the cause: {err}"
        );
        assert!(
            !err.contains("do not match what was approved"),
            "must not read as tampering: {err}"
        );
    }

    // ─── Witness DoS bounds (MAX_WITNESSES / MAX_REPORTED_FAILURES) ─────────

    /// The single valid witness of `signed_receipt`, as an explicit list entry.
    fn witness_of(receipt: &ApprovalReceipt) -> ApprovalWitness {
        ApprovalWitness {
            signer_did: receipt.signer_did.clone().unwrap_or_default(),
            signer_public_key: receipt.signer_public_key.clone().unwrap_or_default(),
            signature: receipt.signature.clone().unwrap_or_default(),
            sig_alg: receipt.sig_alg.clone(),
            authenticator_data: None,
            client_data_json: None,
        }
    }

    /// The witness list is attacker-supplied and every entry costs an ECDSA verification per
    /// candidate key; a real quorum is single digits. A 20,000-witness receipt measured 3.6s of
    /// blocked verification in the TS reference, in the relying party's own process, immediately
    /// before the action it gates.
    #[test]
    fn test_witness_bound_refused_in_approval_path() {
        let (mut receipt, expected) = signed_receipt();
        let witness = witness_of(&receipt);
        receipt.signatures = Some(vec![witness.clone(); MAX_WITNESSES + 1]);
        let err =
            verify_approval_receipt(&receipt, &expected).expect_err("65 witnesses must be refused");
        assert!(
            err.contains(&format!("above the {MAX_WITNESSES}")),
            "unexpected reason: {err}"
        );

        // Exactly AT the bound is still processed — and 64 copies of one valid witness count as
        // ONE distinct approver, which satisfies the fixture's 1-of-1 quorum.
        receipt.signatures = Some(vec![witness; MAX_WITNESSES]);
        assert_eq!(verify_approval_receipt(&receipt, &expected), Ok(()));
    }

    /// Build a signed, in-window DELEGATION (DIV §5a.5) fixture.
    fn signed_delegation_receipt() -> (ApprovalReceipt, Expected) {
        let requester = RequesterIdentity {
            did: "did:intyga:service:pipeline".to_string(),
            attestation: None,
        };
        let params = json!({ "environment": "prod" });
        let delegated_to = vec![
            "did:intyga:sre-a".to_string(),
            "did:intyga:sre-b".to_string(),
        ];
        let canonical = canonical_delegation_payload(
            "prod-db",
            "deleteDatabase",
            "Drop prod",
            &params,
            &requester,
            &default_requirement(),
            &delegated_to,
            1,
            "del-witness-bound",
            "2026-01-01T00:00:00Z",
            "2026-01-02T00:00:00Z",
        )
        .expect("canonicalize delegation fixture");
        let sk = test_signing_key();
        let sig: Signature = sk.sign(canonical.as_bytes());
        let spki = sk.verifying_key().to_public_key_der().expect("encode SPKI");
        let pub_b64 = STANDARD.encode(spki.as_bytes());
        let receipt = ApprovalReceipt {
            canonical_payload: canonical,
            target: Some("prod-db".to_string()),
            action_type: Some("deleteDatabase".to_string()),
            action_description: "Drop prod".to_string(),
            params: params.clone(),
            signer_did: Some("did:intyga:human:alice".to_string()),
            signer_public_key: Some(pub_b64.clone()),
            signature: Some(STANDARD.encode(sig.to_der().as_bytes())),
            sig_alg: Some("ES256".to_string()),
            authenticator_data: None,
            client_data_json: None,
            requester: Some(requester),
            signatures: None,
            verification_code: "1234".to_string(),
        };
        let expected = Expected {
            target: "prod-db".to_string(),
            nonce: "del-witness-bound".to_string(),
            action_type: "deleteDatabase".to_string(),
            params,
            // DID mode: delegations refuse a key-set anchor outright (DIV §4.4.6), so the sealing
            // fixture must resolve identities the way a real deployment does.
            approvers: ApproverTrustAnchor::Dids {
                dids: vec!["did:intyga:human:alice".to_string()],
                resolve: Box::new(move |did| {
                    if did == "did:intyga:human:alice" {
                        Some(pub_b64.clone())
                    } else {
                        None
                    }
                }),
            },
        };
        (receipt, expected)
    }

    /// The delegation path processes the same attacker-supplied witness shape, so it carries the
    /// same bound.
    #[test]
    fn test_witness_bound_refused_in_delegation_path() {
        let (mut receipt, expected) = signed_delegation_receipt();
        // Evaluate within the delegation's 2026 window rather than waiving expiry.
        let opts = VerifyOptions {
            as_of_unix_secs: parse_rfc3339_utc_secs("2026-01-01T12:00:00Z"),
            ..Default::default()
        };
        assert!(
            verify_delegation(&receipt, &expected, &opts).is_ok(),
            "fixture must be valid before inflating the witness list"
        );
        let witness = witness_of(&receipt);
        receipt.signatures = Some(vec![witness; MAX_WITNESSES + 1]);
        let err = verify_delegation(&receipt, &expected, &opts)
            .expect_err("65-witness delegation must be refused");
        assert!(
            err.contains(&format!("above the {MAX_WITNESSES}")),
            "unexpected reason: {err}"
        );
    }

    /// Folding every per-witness failure into the reason string is what turned a long witness list
    /// into 1.16 MB of error text in the TS reference. The fold is capped at MAX_REPORTED_FAILURES
    /// entries with a "+N more" suffix.
    #[test]
    fn test_failure_string_is_bounded() {
        let (mut receipt, expected) = signed_receipt();
        let garbage: Vec<ApprovalWitness> = (0..MAX_WITNESSES)
            .map(|i| ApprovalWitness {
                signer_did: format!("did:intyga:unknown-{i}"),
                signer_public_key: "not-a-key".to_string(),
                signature: STANDARD.encode(b"garbage-signature"),
                sig_alg: Some("ES256".to_string()),
                authenticator_data: None,
                client_data_json: None,
            })
            .collect();
        receipt.signatures = Some(garbage);
        let err = verify_approval_receipt(&receipt, &expected)
            .expect_err("garbage witnesses cannot meet quorum");
        assert!(err.contains("quorum not met"), "unexpected reason: {err}");
        assert!(
            err.contains(&format!("+{} more", MAX_WITNESSES - MAX_REPORTED_FAILURES)),
            "elided-count suffix missing: {err}"
        );
        assert!(
            err.len() < 2048,
            "failure string not bounded: {} bytes",
            err.len()
        );
    }

    /// Byte-parity for the ORDINARY intent-payload builder against the shared golden vectors —
    /// the same `intentPayloads` cases the TS and Python suites consume. The offline and delegation
    /// builders were already pinned this way; the ordinary builder relied on local fixtures only.
    #[test]
    fn test_shared_intent_payload_vectors() {
        let doc = golden_vectors();
        let cases = doc["intentPayloads"]
            .as_array()
            .expect("intentPayloads array");
        assert!(!cases.is_empty(), "no intent-payload vectors present");

        for case in cases {
            let i = &case["input"];
            let requester: RequesterIdentity =
                serde_json::from_value(i["requester"].clone()).expect("requester");
            let got = canonical_intent_payload(
                i["target"].as_str().unwrap_or_default(),
                i["actionType"].as_str().unwrap_or_default(),
                i["actionDescription"].as_str().unwrap_or_default(),
                &i["params"],
                &requester,
                &vector_requirement(i),
                i["nonce"].as_str().unwrap_or_default(),
                i["expiresAt"].as_str().unwrap_or_default(),
            )
            .expect("canonicalize intent vector");
            assert_eq!(
                got,
                case["expected"].as_str().unwrap_or_default(),
                "intentPayloads[{}]",
                i["nonce"]
            );
            assert!(got.contains("\"type\":\"div-intent-verification\""));
        }
    }

    // ── Shared receipt-level vectors: quorum / offline / delegation ─────────
    // Mirrors packages/verify/src/vectors.test.ts. NOTE: canonical-vectors.json also carries a
    // `documentPayloads` section whose own `note` marks it TS-only (document signing is a
    // gateway-side ceremony, not part of the relying-party offline surface the Go/Rust/Python
    // ports implement) — this port deliberately has no consumer or builder for it.

    /// DID-mode multi-key trust anchor from a vector `approvers` table (`[{did, keys: [...]}]`).
    /// Multi-key matters: one vector identity deliberately holds TWO credentials, so a resolver
    /// returning all keys for a DID is required to exercise identity-counting rather than
    /// credential-counting.
    fn vector_did_anchor(approvers: &Value) -> ApproverTrustAnchor {
        let table: Vec<(String, Vec<String>)> = approvers
            .as_array()
            .expect("approvers array")
            .iter()
            .map(|a| {
                (
                    a["did"].as_str().expect("approver did").to_string(),
                    a["keys"]
                        .as_array()
                        .expect("approver keys")
                        .iter()
                        .filter_map(|k| k.as_str().map(String::from))
                        .collect(),
                )
            })
            .collect();
        let dids: Vec<String> = table.iter().map(|(d, _)| d.clone()).collect();
        ApproverTrustAnchor::DidsMultiKey {
            dids,
            resolve: Box::new(move |did: &str| {
                table
                    .iter()
                    .find(|(d, _)| d == did)
                    .map(|(_, keys)| keys.clone())
                    .unwrap_or_default()
            }),
        }
    }

    /// The expectation a relying party would assert, rebuilt from the receipt's echoes — target,
    /// actionType and params from the receipt fields, the nonce parsed out of canonicalPayload
    /// (exactly as the TS consumer's `expectationFor` does).
    fn vector_expectation(receipt: &ApprovalReceipt, approvers: ApproverTrustAnchor) -> Expected {
        Expected {
            target: receipt.target.clone().unwrap_or_default(),
            nonce: parse_nonce(&receipt.canonical_payload),
            action_type: receipt.action_type.clone().unwrap_or_default(),
            params: receipt.params.clone(),
            approvers,
        }
    }

    /// Consumes the shared `quorumReceipts` vectors: a quorum counts distinct approver IDENTITIES,
    /// never signature entries. All cases share one signed requirement (requiredApprovals: 2 +
    /// requesterCannotApprove) and differ only in who signed.
    ///
    /// Deviation from the TS consumer, stated plainly: the vectors carry `expectSigners`, but this
    /// port's `verify_approval_receipt` returns `Ok(())` with no verified-signer list, so there is
    /// nothing to compare it against. The property those signers express is still pinned — the
    /// one-approver-two-credentials case fails its 2-of-N quorum exactly because two of alice's
    /// keys resolve to ONE identity.
    #[test]
    fn test_shared_quorum_receipt_vectors() {
        let doc = golden_vectors();
        let q = &doc["quorumReceipts"];
        let cases = q["cases"].as_array().expect("quorumReceipts cases");
        assert!(!cases.is_empty(), "no quorum-receipt vectors present");
        for case in cases {
            let name = case["name"].as_str().unwrap_or("<unnamed>");
            let receipt: ApprovalReceipt =
                serde_json::from_value(case["receipt"].clone()).expect("deserialize receipt");
            let expected = vector_expectation(&receipt, vector_did_anchor(&q["approvers"]));
            let result = verify_approval_receipt(&receipt, &expected);
            let expect_ok = case["expectOk"].as_bool().unwrap_or(false);
            assert_eq!(result.is_ok(), expect_ok, "{name}: {result:?}");
            // Advisory in the vectors; asserted here because the Rust phrasing does contain it.
            if let Some(reason_part) = case["expectReasonIncludes"].as_str() {
                let err = result.expect_err("expectReasonIncludes only appears on refusals");
                assert!(
                    err.contains(reason_part),
                    "{name}: reason {err:?} should contain {reason_part:?}"
                );
            }
        }
    }

    /// Consumes the shared `offlineReceipts` vectors: an offline proof is refused without the
    /// `allow_offline` opt-in, and a validly SIGNED proof whose window exceeds the 60-minute cap
    /// fails even with it.
    #[test]
    fn test_shared_offline_receipt_vectors() {
        let doc = golden_vectors();
        let cases = doc["offlineReceipts"]
            .as_array()
            .expect("offlineReceipts array");
        assert!(!cases.is_empty(), "no offline-receipt vectors present");
        let signer_key = doc["signerKey"]["spkiB64"]
            .as_str()
            .expect("signerKey")
            .to_string();
        for case in cases {
            let name = case["name"].as_str().unwrap_or("<unnamed>");
            let receipt: ApprovalReceipt =
                serde_json::from_value(case["receipt"].clone()).expect("deserialize receipt");
            let expected = vector_expectation(
                &receipt,
                ApproverTrustAnchor::PublicKeys(vec![signer_key.clone()]),
            );
            let as_of = vector_as_of(name, case);
            let opts = VerifyOptions {
                allow_offline: true,
                as_of_unix_secs: Some(as_of),
                ..Default::default()
            };
            let with_opt_in = verify_approval_receipt_with_options(&receipt, &expected, &opts);
            let expect_ok = case["expectOkWithOptIn"].as_bool().unwrap_or(false);
            assert_eq!(with_opt_in.is_ok(), expect_ok, "{name}: {with_opt_in:?}");
            if case["refusedWithoutOptIn"].as_bool().unwrap_or(false) {
                let without = VerifyOptions {
                    as_of_unix_secs: Some(as_of),
                    ..Default::default()
                };
                assert!(
                    verify_approval_receipt_with_options(&receipt, &expected, &without).is_err(),
                    "{name} must be refused without the offline opt-in"
                );
            }
            // The forward-dating rule sits outside `allow_expired`'s reach: that override
            // re-examines a proof that WAS valid and has lapsed, never one dated in the future.
            if name == "offline-forward-dated-refused" {
                let audit = VerifyOptions {
                    allow_offline: true,
                    allow_expired: true,
                    as_of_unix_secs: Some(as_of),
                    ..Default::default()
                };
                let err = verify_approval_receipt_with_options(&receipt, &expected, &audit)
                    .expect_err("the audit override must not rescue a forward-dated proof");
                assert!(err.contains("challenged in the future"), "{name}: {err}");
            }
        }
    }

    /// Consumes the shared `delegationReceipts` vectors through `verify_delegation`: the sealing
    /// quorum (two ordinary approvers, one with two credentials), the reported delegated set and
    /// quorum on the positive case, and the 72-hour window cap on the negative one.
    #[test]
    fn test_shared_delegation_receipt_vectors() {
        let doc = golden_vectors();
        let d = &doc["delegationReceipts"];
        let cases = d["cases"].as_array().expect("delegationReceipts cases");
        assert!(!cases.is_empty(), "no delegation-receipt vectors present");
        for case in cases {
            let name = case["name"].as_str().unwrap_or("<unnamed>");
            let receipt: ApprovalReceipt =
                serde_json::from_value(case["receipt"].clone()).expect("deserialize receipt");
            let expected = vector_expectation(&receipt, vector_did_anchor(&d["approvers"]));
            let opts = VerifyOptions {
                as_of_unix_secs: Some(vector_as_of(name, case)),
                ..Default::default()
            };
            let result = verify_delegation(&receipt, &expected, &opts);
            let expect_ok = case["expectOk"].as_bool().unwrap_or(false);
            assert_eq!(result.is_ok(), expect_ok, "{name}: {result:?}");
            if expect_ok {
                let verified = result.expect("checked ok above");
                let want_to: Vec<String> = case["delegatedTo"]
                    .as_array()
                    .expect("positive case carries delegatedTo")
                    .iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect();
                assert_eq!(verified.delegated_to, want_to, "{name}");
                assert_eq!(
                    i64::from(verified.delegated_quorum),
                    case["delegatedQuorum"]
                        .as_i64()
                        .expect("positive case carries delegatedQuorum"),
                    "{name}"
                );
            }
        }
    }

    #[test]
    fn delegation_refuses_key_set_anchor_at_seal_verification() {
        // DIV §4.4.6: the sealing quorum names PEOPLE; a key-set anchor counts credentials and can
        // never associate identities, so seal verification must refuse it outright — previously
        // only delegatedTo enforcement at use time did.
        let receipt = ApprovalReceipt {
            canonical_payload: r#"{"v":1,"type":"div-delegation"}"#.to_string(),
            target: None,
            action_type: None,
            action_description: "irrelevant".to_string(),
            params: serde_json::json!({}),
            signer_did: None,
            signer_public_key: None,
            signature: None,
            sig_alg: None,
            authenticator_data: None,
            client_data_json: None,
            requester: None,
            signatures: None,
            verification_code: String::new(),
        };
        let expected = Expected {
            target: "t".to_string(),
            nonce: "n".to_string(),
            action_type: "x".to_string(),
            params: serde_json::json!({}),
            approvers: ApproverTrustAnchor::PublicKeys(vec!["a-listed-key".to_string()]),
        };
        let err = verify_delegation(&receipt, &expected, &VerifyOptions::default()).unwrap_err();
        assert!(err.contains("§4.4.6"), "{err}");
    }
}
