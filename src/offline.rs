//! Offline approval (docs/DIV.md §5a) — the relying-party half, and the approver's signing half.
//! A port of `packages/sdk/src/offline.ts`; the contract is docs/OFFLINE-APPROVAL-SDK.md and the
//! conformance suite is `packages/mcp-schemas/vectors/offline-approval-vectors.json`.
//!
//! When the gateway is unreachable, the relying party builds the challenge ITSELF, the humans review
//! and sign it on a disconnected device, and the result is verified by the ordinary §5 procedure. The
//! signing ceremony moves off the network; it does not move earlier in time. Pre-signing approvals
//! and holding them until needed would put a bearer capability on disk and capture a human judgment
//! about a hypothetical rather than the incident in progress (DIV §5a.1).
//!
//! Four properties are enforced structurally, because each is the kind of thing a reasonable-looking
//! refactor would quietly remove:
//!
//! 1. IT ONLY APPLIES WHEN WE COULD NOT ASK. The client fallback
//!    ([`crate::Client::require_approval_with_offline`]) is reachable only on a transport failure, a
//!    5xx, or five consecutive polling failures of those kinds. A DENIED or EXPIRED result means a human WAS reached and did
//!    not approve, and a 4xx is a verdict from a reachable gateway.
//! 2. IT RETURNS A DISTINCT STATUS. A fallback reports [`crate::ApprovalStatus::OfflineApproved`],
//!    never `Approved`, so the usual `if status != Approved { refuse }` guard keeps refusing until
//!    the call site is consciously changed.
//! 3. THE POLICY COMES FROM THE BUNDLE, NOT FROM HERE. The requirement is read from the signed trust
//!    bundle (§5a.4); there is no local default.
//! 4. NOTHING PERSISTS THAT AUTHORIZES ANYTHING. What is written to disk records that an approval
//!    HAPPENED (for reconciliation); no file written here can authorize a future action.

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use intyga_verify::{
    canonical_offline_intent_payload, verify_approval_receipt_with_options, verify_delegation,
    ApprovalReceipt, ApprovalRequirement, ApprovalWitness, Expected, RequesterIdentity,
    RequirementFloor, VerifiedDelegation, VerifyOptions, DIV_OFFLINE_INTENT_TYPE,
    MAX_OFFLINE_WINDOW_MINUTES,
};
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use serde::{Deserialize, Serialize, Serializer};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::support::{
    b64url, b64url_decode_strict, create_private_marker, ensure_private_dir, hex, iso_from_ms,
    js_trim, now_ms, parse_rfc3339_ms, random_uuid, system_time_from_ms, unix_ms,
    write_private_file,
};
use crate::trust_bundle::{
    approver_anchor, check_trust_bundle_freshness, load_trust_bundle, requirement_for,
    BundleAnchorPurpose, TrustBundle,
};

/// Wire prefix for a challenge travelling OUT to the approvers.
pub const CHALLENGE_ENVELOPE_PREFIX: &str = "DIV1:";
/// Wire prefix for a signature coming BACK from an approver.
pub const SIGNATURE_ENVELOPE_PREFIX: &str = "SIG1:";
/// Default validity window. Deliberately short: an offline approval is created and redeemed inside
/// one incident, and the window is the only bound on a proof no one can revoke.
pub const DEFAULT_OFFLINE_WINDOW_MINUTES: i64 = 15;

const PENDING_DIR: &str = ".pending";
const REDEEMED_DIR: &str = ".redeemed";

/// Format a time exactly as JavaScript's `toISOString()` does (`2026-10-06T12:00:00.123Z`), the
/// form every timestamp in an offline challenge takes.
pub fn iso_timestamp(t: SystemTime) -> String {
    iso_from_ms(unix_ms(t))
}

/// Parse an RFC 3339 timestamp (`YYYY-MM-DDTHH:MM:SS[.fff](Z|±HH:MM)`), to millisecond precision.
pub fn parse_timestamp(s: &str) -> Option<SystemTime> {
    parse_rfc3339_ms(s).map(system_time_from_ms)
}

/// Short code the approver reads back to the operator before signing (DIV §5a.8): the first eight
/// hex digits of SHA-256 over the canonical payload, uppercase, grouped `XXXX-XXXX`.
pub fn verification_code(canonical_payload: &str) -> String {
    let digest = hex(&Sha256::digest(canonical_payload.as_bytes())[..4]).to_uppercase();
    format!("{}-{}", &digest[0..4], &digest[4..8])
}

/// Nonces are generated locally, but they become path segments in the redemption store and the
/// reconciliation buffer — refuse anything that could leave those directories.
fn is_path_safe_nonce(nonce: &str) -> bool {
    (1..=200).contains(&nonce.len())
        && nonce
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
}

/// The action an offline approval is for — what the relying party is about to execute.
#[derive(Debug, Clone, PartialEq)]
pub struct OfflineAction {
    /// This relying party / execution environment (DIV Target Isolation).
    pub target: String,
    /// The exact action ID the bundle's policy is keyed on.
    pub action_type: String,
    /// What the approvers are shown. Never selects a rule.
    pub display: String,
    /// The exact parameters that will execute.
    pub params: Value,
}

/// A locally generated offline challenge, ready to hand to the approvers.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OfflineChallenge {
    /// Generated HERE, by the party that will redeem it (DIV §5a.2) — nobody else can enforce its use.
    pub nonce: String,
    /// The exact bytes the approvers will sign.
    pub canonical_payload: String,
    /// The code the approver MUST read back to the operator before signing (DIV §5a.8).
    pub verification_code: String,
    /// `DIV1:<base64url>` — what travels to the approver, by QR or copy-paste.
    pub envelope: String,
    pub challenged_at: String,
    pub expires_at: String,
    pub target: String,
    pub action_type: String,
    pub display: String,
    pub params: Value,
    pub requester: RequesterIdentity,
    pub requirement: ApprovalRequirement,
    /// Which approvers are eligible, per the bundle policy (or the delegation) behind `requirement`.
    pub approver_dids: Vec<String>,
}

/// Optional inputs to [`create_offline_challenge`].
#[derive(Debug, Clone, Default)]
pub struct ChallengeOptions {
    /// Whole minutes, clamped to `1..=60`. Defaults to [`DEFAULT_OFFLINE_WINDOW_MINUTES`]. The
    /// contract refuses a fractional window; an integer type is how this port refuses one, so a
    /// caller reading the value from configuration must reject a non-integer before it gets here.
    pub window_minutes: Option<i64>,
    /// Overrides "now", for tests and deterministic replay.
    pub as_of: Option<SystemTime>,
    /// Overrides the generated `off_<uuid>` nonce, for conformance vectors and replay. A supplied
    /// nonce is still this relying party's own, still single-use through the redemption store, and
    /// must be a safe path segment (`^[A-Za-z0-9._-]{1,200}$`). `Some("")` is refused, never
    /// replaced by a generated nonce.
    pub nonce: Option<String>,
    /// A delegation ALREADY verified with [`verify_delegation`], for when the ordinary approvers are
    /// unreachable too. Its `delegated_quorum` becomes the signed quorum and its `delegated_to` the
    /// eligible set (DIV §5a.6).
    pub delegation: Option<VerifiedDelegation>,
}

/// Build an offline challenge, taking the approval requirement from the trust bundle.
///
/// The requirement is NOT a parameter: a relying party that supplied its own would be choosing the
/// quorum its own action must clear (DIV §5a.3). Refuses an action the bundle has no unambiguous rule
/// for (there is no implicit 1-of-1), a rule that needs a hardware credential (which no offline key
/// can satisfy), a delegation whose quorum is below the rule's, an unsafe nonce, and a blank target.
pub fn create_offline_challenge(
    bundle: &TrustBundle,
    action: &OfflineAction,
    requester: &RequesterIdentity,
    opts: &ChallengeOptions,
) -> Result<OfflineChallenge, String> {
    // DIV §3 Invariant 5 (Target Isolation): a blank target binds no execution environment, so the
    // approval would verify at every relying party that also asserts it.
    if js_trim(&action.target).is_empty() {
        return Err("target is required (DIV Target Isolation)".into());
    }
    let resolved = requirement_for(bundle, &action.action_type, &action.display).ok_or_else(|| {
        format!(
            "the trust bundle has no approval rule matching \"{}\" that can be selected unambiguously — configure the rule or export a fresh bundle with rule-selection metadata (DIV §5a.3)",
            action.action_type
        )
    })?;

    // Refused at CHALLENGE time as well as at verification: sending approvers a payload nobody can
    // produce a valid signature for wastes the one resource an incident is short of.
    if resolved.requirement.requires_hardware_credential() {
        return Err(format!(
            "\"{}\" requires a hardware-backed WebAuthn credential, which cannot be produced offline — this action cannot be approved out of band (DIV §5a.3)",
            action.action_type
        ));
    }

    let window = opts
        .window_minutes
        .unwrap_or(DEFAULT_OFFLINE_WINDOW_MINUTES)
        .clamp(1, MAX_OFFLINE_WINDOW_MINUTES);
    let now = now_ms(opts.as_of);
    let challenged_at = iso_from_ms(now);
    let expires_at = iso_from_ms(now + window * 60_000);
    let nonce = match &opts.nonce {
        Some(n) => n.clone(),
        None => format!("off_{}", random_uuid()?),
    };
    if !is_path_safe_nonce(&nonce) {
        return Err("nonce must be a safe path segment".into());
    }

    // "Narrows who may approve, never the policy" has to be enforced (DIV §5a.5): `display` may
    // differ between sealing and use, so a delegation sealed against a permissive rule could
    // otherwise overwrite a strict rule's quorum with its own and still verify.
    if let Some(d) = &opts.delegation {
        if d.delegated_quorum < resolved.requirement.required_approvals {
            return Err(format!(
                "this delegation would lower the quorum for \"{}\" from {} to {}. A delegation may narrow WHO approves, never HOW MANY (DIV §5a.5)",
                action.action_type, resolved.requirement.required_approvals, d.delegated_quorum
            ));
        }
    }

    // Under a delegation the eligible set and the quorum are the DELEGATED ones; everything else in
    // the requirement still comes from the bundle.
    let mut requirement = resolved.requirement;
    let mut approver_dids = resolved.approver_dids;
    if let Some(d) = &opts.delegation {
        requirement.required_approvals = d.delegated_quorum;
        approver_dids = d.delegated_to.clone();
    }

    let canonical_payload = canonical_offline_intent_payload(
        &action.target,
        &action.action_type,
        &action.display,
        &action.params,
        requester,
        &requirement,
        &nonce,
        &challenged_at,
        &expires_at,
    )
    .map_err(|why| format!("the challenge cannot be canonicalized: {why}"))?;

    Ok(OfflineChallenge {
        verification_code: verification_code(&canonical_payload),
        envelope: format!(
            "{CHALLENGE_ENVELOPE_PREFIX}{}",
            b64url(canonical_payload.as_bytes())
        ),
        nonce,
        canonical_payload,
        challenged_at,
        expires_at,
        target: action.target.clone(),
        action_type: action.action_type.clone(),
        display: action.display.clone(),
        params: action.params.clone(),
        requester: requester.clone(),
        requirement,
        approver_dids,
    })
}

/// What an approver's signing tool shows before asking for confirmation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DecodedChallenge {
    pub canonical_payload: String,
    pub verification_code: String,
    pub target: String,
    pub action_type: String,
    pub display: String,
    pub params: Value,
    pub requester: RequesterIdentity,
    pub requirement: ApprovalRequirement,
    pub nonce: String,
    pub challenged_at: String,
    pub expires_at: String,
}

/// Decode a `DIV1:` envelope for review by the signing tool.
///
/// Only a `div-offline-intent` decodes: an approver's tool must never sign an ORDINARY intent someone
/// pasted in, because that signature would be a live approval outside the gateway's single-use
/// accounting. Surrounding whitespace is trimmed as JavaScript's `trim()` does (a BOM goes, U+0085
/// stays); the body must be strict base64url of a JSON object whose `target`, `actionType`,
/// `display`, `nonce`, `challengedAt` and `expiresAt` are strings, `target` not blank, `params` and
/// `requirement` objects and `requester` an object with a string `did`. And the payload must be
/// canonical — re-serializing it must reproduce the bytes — or a signature over it would verify
/// nowhere, over a payload the approver could not faithfully read.
pub fn decode_challenge_envelope(envelope: &str) -> Result<DecodedChallenge, String> {
    // `String.prototype.trim`, not `str::trim`: a BOM is stripped, U+0085 is not.
    let trimmed = js_trim(envelope);
    let Some(body) = trimmed.strip_prefix(CHALLENGE_ENVELOPE_PREFIX) else {
        return Err(format!(
            "not a challenge envelope (expected a {CHALLENGE_ENVELOPE_PREFIX} prefix)"
        ));
    };
    let bytes = b64url_decode_strict(body).ok_or("challenge envelope is not valid base64url")?;
    let canonical_payload = String::from_utf8_lossy(&bytes).into_owned();
    let parsed: Value = serde_json::from_str(&canonical_payload).map_err(|_| {
        "challenge envelope does not contain a JSON payload (truncated paste?)".to_string()
    })?;
    if !parsed.is_object() {
        return Err("challenge payload is not a JSON object".into());
    }
    match parsed.get("type") {
        Some(Value::String(t)) if t == DIV_OFFLINE_INTENT_TYPE => {}
        other => {
            let shown = match other {
                Some(Value::String(t)) => t.clone(),
                Some(v) => v.to_string(),
                None => "undefined".into(),
            };
            return Err(format!(
                "this is a {shown} payload, not an offline approval challenge — refusing to sign it"
            ));
        }
    }

    // Shapes before bytes. Canonicalization alone would accept `"target": 5` whenever it
    // re-serializes identically, and the approver would then review — and sign — something no
    // relying party builds. Every SDK refuses the same shapes (docs/OFFLINE-APPROVAL-SDK.md).
    let shape = |problem: &str| format!("challenge payload {problem} — refusing to sign it");
    let text = |key: &str| -> Result<String, String> {
        match parsed.get(key) {
            Some(Value::String(s)) => Ok(s.clone()),
            _ => Err(shape(&format!("field {key} is not a string"))),
        }
    };
    let target = text("target")?;
    let action_type = text("actionType")?;
    let display = text("display")?;
    let nonce = text("nonce")?;
    let challenged_at = text("challengedAt")?;
    let expires_at = text("expiresAt")?;
    if js_trim(&target).is_empty() {
        return Err(shape("has a blank target"));
    }
    let params = match parsed.get("params") {
        Some(p @ Value::Object(_)) => p.clone(),
        _ => return Err(shape("params is not a JSON object")),
    };
    let requester: RequesterIdentity = match parsed.get("requester") {
        Some(r @ Value::Object(o)) if o.get("did").is_some_and(Value::is_string) => {
            serde_json::from_value(r.clone()).map_err(|_| shape("requester is not an identity"))?
        }
        _ => return Err(shape("requester is not an identity")),
    };
    let requirement: ApprovalRequirement = match parsed.get("requirement") {
        Some(r @ Value::Object(_)) => serde_json::from_value(r.clone())
            .map_err(|_| shape("requirement is not a valid approval requirement"))?,
        _ => return Err(shape("requirement is not a JSON object")),
    };

    let rebuilt = canonical_offline_intent_payload(
        &target,
        &action_type,
        &display,
        &params,
        &requester,
        &requirement,
        &nonce,
        &challenged_at,
        &expires_at,
    )
    .map_err(|_| {
        "challenge payload carries values that cannot be canonicalized — refusing to sign it"
            .to_string()
    })?;
    if rebuilt != canonical_payload {
        return Err(
            "challenge payload is not canonical — re-serializing it produces different bytes, so a signature over it would verify nowhere"
                .into(),
        );
    }
    Ok(DecodedChallenge {
        verification_code: verification_code(&canonical_payload),
        canonical_payload,
        target,
        action_type,
        display,
        params,
        requester,
        requirement,
        nonce,
        challenged_at,
        expires_at,
    })
}

/// The `SIG1:` body. Field order is the wire format: `did`, `key`, `sig`, `alg`, no whitespace —
/// byte-identical to the reference's `JSON.stringify`.
#[derive(Serialize)]
struct CompactSignature<'a> {
    did: &'a str,
    key: &'a str,
    sig: &'a str,
    alg: &'a str,
}

/// Encode one approver's signature for the trip back to the relying party.
pub fn encode_signature_envelope(witness: &ApprovalWitness) -> String {
    let compact = CompactSignature {
        did: &witness.signer_did,
        key: &witness.signer_public_key,
        sig: &witness.signature,
        alg: witness.sig_alg.as_deref().unwrap_or("ES256"),
    };
    // Serializing four borrowed strings cannot fail.
    let json = serde_json::to_string(&compact).unwrap_or_default();
    format!("{SIGNATURE_ENVELOPE_PREFIX}{}", b64url(json.as_bytes()))
}

/// Decode a `SIG1:` envelope back into a witness. The body must be strict base64url of a JSON
/// object; `did`, `key` and `sig` must be non-empty strings; `alg`, when present, must be a non-empty
/// string, and a missing one means `ES256`. Every refusal is an `Err` for THIS envelope — one bad
/// paste is discarded, it never ends the ceremony.
pub fn decode_signature_envelope(envelope: &str) -> Result<ApprovalWitness, String> {
    // `String.prototype.trim`, not `str::trim`: a BOM is stripped, U+0085 is not.
    let trimmed = js_trim(envelope);
    let Some(body) = trimmed.strip_prefix(SIGNATURE_ENVELOPE_PREFIX) else {
        return Err(format!(
            "not a signature envelope (expected a {SIGNATURE_ENVELOPE_PREFIX} prefix)"
        ));
    };
    let unreadable =
        || "signature envelope is not valid base64url JSON (truncated paste?)".to_string();
    let bytes = b64url_decode_strict(body).ok_or_else(unreadable)?;
    let compact: Value =
        serde_json::from_str(&String::from_utf8_lossy(&bytes)).map_err(|_| unreadable())?;
    if !compact.is_object() {
        return Err("signature envelope is not a JSON object".into());
    }
    let field = |key: &str| {
        compact
            .get(key)
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    };
    let (Some(did), Some(key), Some(sig)) = (field("did"), field("key"), field("sig")) else {
        return Err("signature envelope is missing did, key or sig".into());
    };
    // Present means it must say something: `null`, `""` or a non-string is refused, not defaulted.
    let alg = match compact.get("alg") {
        None => "ES256".to_string(),
        Some(Value::String(a)) if !a.is_empty() => a.clone(),
        Some(_) => return Err("signature envelope alg must be a string".into()),
    };
    Ok(ApprovalWitness {
        signer_did: did,
        signer_public_key: key,
        signature: sig,
        sig_alg: Some(alg),
        authenticator_data: None,
        client_data_json: None,
    })
}

/// An approver's offline signing key: a P-256 private key.
pub enum OfflineSigningKey {
    /// PEM text: PKCS#8 (`BEGIN PRIVATE KEY`) or SEC1 (`BEGIN EC PRIVATE KEY`).
    Pem(String),
    /// PKCS#8 DER bytes (PEM bytes are also recognized).
    Der(Vec<u8>),
    /// An already-parsed key.
    P256(SigningKey),
}

impl std::fmt::Debug for OfflineSigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print key material.
        f.write_str(match self {
            OfflineSigningKey::Pem(_) => "OfflineSigningKey::Pem(..)",
            OfflineSigningKey::Der(_) => "OfflineSigningKey::Der(..)",
            OfflineSigningKey::P256(_) => "OfflineSigningKey::P256(..)",
        })
    }
}

fn signing_key_from_pem(pem: &str) -> Result<SigningKey, String> {
    use p256::pkcs8::DecodePrivateKey;
    const SEC1_BEGIN: &str = "-----BEGIN EC PRIVATE KEY-----";
    const SEC1_END: &str = "-----END EC PRIVATE KEY-----";
    if let Some(start) = pem.find(SEC1_BEGIN) {
        // `openssl ecparam -genkey` writes an `EC PARAMETERS` block before the key unless told not
        // to; take the key block alone, which is what a strict PEM parser accepts.
        let end = pem[start..]
            .find(SEC1_END)
            .map(|at| start + at + SEC1_END.len())
            .ok_or("the EC PRIVATE KEY block is not terminated")?;
        return p256::SecretKey::from_sec1_pem(&pem[start..end])
            .map(SigningKey::from)
            .map_err(|e| e.to_string());
    }
    SigningKey::from_pkcs8_pem(js_trim(pem)).map_err(|e| e.to_string())
}

impl OfflineSigningKey {
    fn signing_key(&self) -> Result<SigningKey, String> {
        use p256::pkcs8::DecodePrivateKey;
        match self {
            OfflineSigningKey::P256(k) => Ok(k.clone()),
            OfflineSigningKey::Pem(pem) => signing_key_from_pem(pem),
            OfflineSigningKey::Der(bytes) => match std::str::from_utf8(bytes) {
                Ok(text) if text.contains("-----BEGIN") => signing_key_from_pem(text),
                _ => SigningKey::from_pkcs8_der(bytes).map_err(|e| e.to_string()),
            },
        }
    }
}

/// Options for [`sign_challenge_envelope`].
#[derive(Debug)]
pub struct SignOptions {
    pub private_key: OfflineSigningKey,
    /// The approver's DID, as the trust bundle names them.
    pub signer_did: String,
    /// Overrides "now" for the expiry check.
    pub as_of: Option<SystemTime>,
}

/// A signed challenge: the `SIG1:` envelope to send back, and what was signed.
#[derive(Debug, Clone)]
pub struct SignedChallenge {
    pub envelope: String,
    pub challenge: DecodedChallenge,
}

/// Sign a `DIV1:` challenge as an approver — the library half of `intyga sign`.
///
/// Decodes first, so only a canonical `div-offline-intent` is ever signed, and refuses a challenge
/// whose `expiresAt` is unreadable or already past. It SHOWS NOTHING: the caller must have shown the
/// decoded challenge (see [`decode_challenge_envelope`]) to the approver and had them confirm the
/// verification code with the operator first (DIV §5a.8) — an approver who signs an opaque blob has
/// approved nothing. The signature is ES256 over the canonical payload's UTF-8 bytes, IEEE P1363
/// (r‖s), and the envelope's `key` is the signer's base64 SPKI.
pub fn sign_challenge_envelope(
    envelope: &str,
    opts: &SignOptions,
) -> Result<SignedChallenge, String> {
    let challenge = decode_challenge_envelope(envelope)?;
    // A timestamp we cannot read is not one we can say is still valid.
    let expiry = parse_rfc3339_ms(&challenge.expires_at)
        .ok_or("expiresAt is not a valid RFC3339 timestamp — refusing to sign")?;
    if expiry <= now_ms(opts.as_of) {
        return Err("this challenge has already expired — ask for a fresh one".into());
    }
    if !opts.signer_did.starts_with("did:") {
        return Err("signerDid must be a DID".into());
    }
    let key = opts.private_key.signing_key().map_err(|why| {
        format!("could not read the private key as a P-256 (prime256v1) private key: {why}")
    })?;
    let signature: Signature = key.sign(challenge.canonical_payload.as_bytes());
    let spki = {
        use p256::pkcs8::EncodePublicKey;
        p256::PublicKey::from(key.verifying_key())
            .to_public_key_der()
            .map_err(|e| format!("could not encode the signer's public key: {e}"))?
    };
    let envelope = encode_signature_envelope(&ApprovalWitness {
        signer_did: opts.signer_did.clone(),
        signer_public_key: STANDARD.encode(spki.as_bytes()),
        signature: STANDARD.encode(signature.to_bytes()),
        sig_alg: Some("ES256".into()),
        authenticator_data: None,
        client_data_json: None,
    });
    Ok(SignedChallenge {
        envelope,
        challenge,
    })
}

/// Assemble the collected witnesses into a receipt the ordinary verifier can check.
pub fn assemble_offline_receipt(
    challenge: &OfflineChallenge,
    witnesses: Vec<ApprovalWitness>,
) -> ApprovalReceipt {
    ApprovalReceipt {
        canonical_payload: challenge.canonical_payload.clone(),
        target: Some(challenge.target.clone()),
        action_type: Some(challenge.action_type.clone()),
        action_description: challenge.display.clone(),
        params: challenge.params.clone(),
        signatures: Some(witnesses),
        signer_did: None,
        signer_public_key: None,
        signature: None,
        sig_alg: None,
        authenticator_data: None,
        client_data_json: None,
        requester: Some(challenge.requester.clone()),
        verification_code: challenge.verification_code.clone(),
    }
}

/// Records which offline nonces this relying party has already redeemed.
///
/// Single use is inherently stateful and LOCAL (DIV §5 steps 9-10). Because the relying party
/// generates its own nonce, single use within it is fully enforceable — unlike a pre-signed token,
/// which two relying parties could each redeem unaware.
pub trait RedemptionStore {
    /// Claim `nonce`. MUST be atomic and MUST return false if it was already claimed.
    fn redeem(&self, nonce: &str) -> bool;
}

/// Default store: one `<nonce>.used` file per redeemed nonce, created with exclusive-create
/// (`O_CREAT|O_EXCL`), so two processes racing the same nonce cannot both succeed. A read-then-write
/// check would lose that race, which is the whole point of the store. The file holds the redemption
/// time; its existence is what counts.
#[derive(Debug, Clone)]
pub struct FileRedemptionStore {
    dir: PathBuf,
}

impl FileRedemptionStore {
    /// Create (or reuse) the store directory, private (`0700`). Refuses a symlinked directory.
    pub fn new(dir: impl Into<PathBuf>) -> Result<Self, String> {
        let dir = dir.into();
        ensure_private_dir(&dir)?;
        Ok(FileRedemptionStore { dir })
    }
}

impl RedemptionStore for FileRedemptionStore {
    fn redeem(&self, nonce: &str) -> bool {
        is_path_safe_nonce(nonce)
            && create_private_marker(
                &self.dir.join(format!("{nonce}.used")),
                &iso_timestamp(SystemTime::now()),
            )
    }
}

/// Collects the approvers' `SIG1:` strings for a challenge. `Err` aborts with that reason.
pub type CollectSignatures<'a> = Box<dyn Fn(&OfflineChallenge) -> Result<Vec<String>, String> + 'a>;

/// Receives every offline-approval warning.
pub type WarnSink<'a> = Box<dyn Fn(&str) + 'a>;

/// Options for [`use_offline_approval`] and the client's offline fallback.
pub struct OfflineApprovalOptions<'a> {
    /// Holds `trust-bundle.jws` and `gateway-key.jwk.json` (see [`crate::save_trust_bundle`]).
    pub bundle_dir: PathBuf,
    /// This workload's own identity, bound into the signed bytes so approvers see who is asking.
    pub requester_did: String,
    /// How the operator gets the challenge to the approvers and the signatures back. This is a seam,
    /// not a default: transporting the envelope is a human, site-specific act (a terminal prompt, a
    /// QR on a console, a phone read out over a bridge line).
    pub collect_signatures: CollectSignatures<'a>,
    /// Directory of pre-signed delegation receipts (`*.json`), for when the approvers are unreachable
    /// too. Only consulted when set.
    pub delegation_dir: Option<PathBuf>,
    /// Where redeemed nonces are recorded. Defaults to a [`FileRedemptionStore`] at
    /// `<bundle_dir>/.redeemed`.
    pub store: Option<Box<dyn RedemptionStore + 'a>>,
    /// Where approvals are buffered for reconciliation. Defaults to `<bundle_dir>/.pending`.
    pub buffer_dir: Option<PathBuf>,
    /// Validity window in minutes, clamped to `1..=60`.
    pub window_minutes: Option<i64>,
    /// The warning sink. Defaults to standard error — an offline approval must never be quiet.
    pub warn: Option<WarnSink<'a>>,
    /// Overrides "now", for tests and deterministic replay.
    pub as_of: Option<SystemTime>,
}

impl<'a> OfflineApprovalOptions<'a> {
    /// Options with the three required inputs and every default.
    pub fn new(
        bundle_dir: impl Into<PathBuf>,
        requester_did: impl Into<String>,
        collect_signatures: impl Fn(&OfflineChallenge) -> Result<Vec<String>, String> + 'a,
    ) -> Self {
        OfflineApprovalOptions {
            bundle_dir: bundle_dir.into(),
            requester_did: requester_did.into(),
            collect_signatures: Box::new(collect_signatures),
            delegation_dir: None,
            store: None,
            buffer_dir: None,
            window_minutes: None,
            warn: None,
            as_of: None,
        }
    }

    fn warn(&self, message: &str) {
        match &self.warn {
            Some(sink) => sink(message),
            None => eprintln!("{message}"),
        }
    }
}

/// A completed offline approval.
#[derive(Debug, Clone)]
pub struct OfflineApproval {
    pub receipt: ApprovalReceipt,
    pub nonce: String,
    /// Who actually signed, as verified against the trust bundle — distinct DIDs, sorted.
    pub signers: Vec<String>,
    /// The delegation's own nonce, when a delegation supplied the approver set.
    pub via_delegation: Option<String>,
}

/// Run a full offline approval: build the challenge, collect signatures out of band, verify, buffer,
/// redeem.
///
/// Verification is the verifier's, with `allow_offline` set, so every ordinary control still applies
/// — target isolation, exact parameter binding, the signed quorum held to the bundle rule's floor,
/// four-eyes, the trusted signer set, expiry and the window cap. This widens WHEN an approval may be
/// obtained, never WHAT it authorizes. The nonce is redeemed BEFORE returning: a proof that verifies
/// but cannot be claimed has already been used here, and is refused.
pub fn use_offline_approval(
    expected: &OfflineAction,
    opts: &OfflineApprovalOptions<'_>,
) -> Result<OfflineApproval, String> {
    let bundle = load_trust_bundle(&opts.bundle_dir, opts.as_of)?;

    // The tier-3 path, only consulted when a delegation directory is set. A delegation is verified
    // against the bundle's ORDINARY approver set: the people entitled to approve this action are the
    // ones who must have signed that entitlement away.
    let mut delegation: Option<VerifiedDelegation> = None;
    if let Some(dir) = &opts.delegation_dir {
        let (found, reason) = find_delegation(dir, &bundle, expected, opts.as_of);
        if let Some(reason) = reason {
            opts.warn(&format!("⚠ OFFLINE APPROVAL: {reason}"));
        }
        delegation = found;
    }

    let challenge = create_offline_challenge(
        &bundle,
        expected,
        &RequesterIdentity {
            did: opts.requester_did.clone(),
            attestation: None,
        },
        &ChallengeOptions {
            window_minutes: opts.window_minutes,
            as_of: opts.as_of,
            nonce: None,
            delegation: delegation.clone(),
        },
    )?;

    let raw = (opts.collect_signatures)(&challenge)
        .map_err(|why| format!("signature collection did not complete: {why}"))?;
    check_trust_bundle_freshness(&bundle, opts.as_of)?;
    if raw.is_empty() {
        return Err("no signatures were collected — the action is not approved".into());
    }

    let mut witnesses = Vec::new();
    let mut rejected = Vec::new();
    for envelope in &raw {
        match decode_signature_envelope(envelope) {
            Ok(w) => witnesses.push(w),
            Err(why) => rejected.push(why),
        }
    }
    if witnesses.is_empty() {
        return Err(format!("no usable signatures ({})", rejected.join("; ")));
    }

    let receipt = assemble_offline_receipt(&challenge, witnesses);
    // DIV §5 step 3d: the signed requirement is the signers' own statement, so it is held to the
    // bundle's ORDINARY rule, re-resolved here rather than read back from the challenge. Under a
    // delegation that is still the right floor: the delegated quorum was refused below it above.
    let ordinary = requirement_for(&bundle, &expected.action_type, &expected.display)
        .ok_or("no unambiguous approval rule applies to this action")?;
    let verified = verify_approval_receipt_with_options(
        &receipt,
        &Expected {
            target: expected.target.clone(),
            nonce: challenge.nonce.clone(),
            action_type: expected.action_type.clone(),
            params: expected.params.clone(),
            // Restricted to the approvers eligible for THIS action. The one place offline signing
            // keys count: this receipt is a div-offline-intent.
            approvers: approver_anchor(
                &bundle,
                Some(&challenge.approver_dids),
                BundleAnchorPurpose::OfflineIntent,
            ),
            requirement: Some(requirement_floor_of(&ordinary.requirement)),
        },
        &VerifyOptions {
            allow_offline: true,
            delegation: delegation.clone(),
            as_of_unix_secs: opts.as_of.map(|t| unix_ms(t).div_euclid(1_000)),
            ..Default::default()
        },
    );
    let signers = match verified {
        Ok(signers) => signers,
        Err(why) if rejected.is_empty() => return Err(why),
        Err(why) => return Err(format!("{why} (also discarded: {})", rejected.join("; "))),
    };

    let default_store;
    let store: &dyn RedemptionStore = match &opts.store {
        Some(store) => store.as_ref(),
        None => {
            default_store = FileRedemptionStore::new(opts.bundle_dir.join(REDEEMED_DIR))?;
            &default_store
        }
    };
    // Buffer BEFORE redeeming: a crash between the two must leave a pending record behind. A spurious
    // record reconciles harmlessly; the other order could leave a redeemed, executed approval
    // invisible to reconciliation forever.
    buffer_for_reconciliation(&challenge, &receipt, delegation.as_ref(), opts);
    if !store.redeem(&challenge.nonce) {
        clear_pending_approval(
            &challenge.nonce,
            &opts.bundle_dir,
            opts.buffer_dir.as_deref(),
        );
        return Err(format!(
            "nonce {} has already been redeemed here",
            challenge.nonce
        ));
    }
    opts.warn(&format!(
        "⚠ OFFLINE APPROVAL USED — \"{}\" ({} on {}). Approved out of band by {} because Intyga was unreachable{}. Nonce {} is buffered for reconciliation; report it when connectivity returns.",
        expected.display,
        expected.action_type,
        expected.target,
        signers.join(", "),
        delegation
            .as_ref()
            .map(|d| format!(", under delegation {}", d.nonce))
            .unwrap_or_default(),
        challenge.nonce
    ));
    Ok(OfflineApproval {
        receipt,
        nonce: challenge.nonce,
        signers,
        via_delegation: delegation.map(|d| d.nonce),
    })
}

/// The DIV §5 step 3d floor a bundle rule imposes on a signed requirement.
fn requirement_floor_of(rule: &ApprovalRequirement) -> RequirementFloor {
    RequirementFloor {
        required_approvals: rule.required_approvals,
        requester_cannot_approve: rule.requester_cannot_approve,
        require_hardware_key: rule.require_hardware_key,
    }
}

/// Every `*.json` entry in `dir`, in file-name order — UTF-16 code-unit order, as JavaScript's
/// `Array.prototype.sort` orders names — so every port tries delegations, and reports pending records,
/// in the same order. `None` when the directory cannot be read.
fn json_files_in_name_order(dir: &Path) -> Option<Vec<(String, PathBuf)>> {
    let mut files: Vec<(String, PathBuf)> = std::fs::read_dir(dir)
        .ok()?
        .filter_map(Result::ok)
        .map(|e| (e.file_name().to_string_lossy().into_owned(), e.path()))
        .filter(|(name, _)| name.ends_with(".json"))
        .collect();
    files.sort_by(|a, b| a.0.encode_utf16().cmp(b.0.encode_utf16()));
    Some(files)
}

/// Find and verify a delegation covering this exact action. A file that does not apply is REPORTED
/// (the second value), not silently skipped: a delegation the operator believes they hold but which
/// does not apply is exactly what they need told during an incident.
fn find_delegation(
    dir: &Path,
    bundle: &TrustBundle,
    expected: &OfflineAction,
    as_of: Option<SystemTime>,
) -> (Option<VerifiedDelegation>, Option<String>) {
    let Some(resolved) = requirement_for(bundle, &expected.action_type, &expected.display) else {
        return (
            None,
            Some(
                "no unambiguous ordinary approval rule applies to this delegation — export a fresh trust bundle"
                    .into(),
            ),
        );
    };
    let Some(files) = json_files_in_name_order(dir) else {
        return (None, None);
    };

    let ordinary = &resolved.requirement;
    let mut rejected = Vec::new();
    for (name, file) in files {
        let Some(receipt) = std::fs::read_to_string(&file)
            .ok()
            .and_then(|text| serde_json::from_str::<ApprovalReceipt>(&text).ok())
        else {
            rejected.push(format!("{name}: unreadable"));
            continue;
        };
        let verified = verify_delegation(
            &receipt,
            &Expected {
                target: expected.target.clone(),
                // A delegation carries its own nonce; the verifier does not read this one.
                nonce: String::new(),
                action_type: expected.action_type.clone(),
                params: expected.params.clone(),
                // The ORDINARY approver set — whoever may approve this action is who must have
                // delegated it. Ordinary keys only: an offline signing key never seals a delegation.
                approvers: approver_anchor(
                    bundle,
                    Some(&resolved.approver_dids),
                    BundleAnchorPurpose::Ordinary,
                ),
                // §5a.5: the sealing requirement may not be weaker than the ordinary rule. The AAGUID
                // comparison below stays, because the floor does not cover allowedAaguids.
                requirement: Some(requirement_floor_of(ordinary)),
            },
            &VerifyOptions {
                as_of_unix_secs: as_of.map(|t| unix_ms(t).div_euclid(1_000)),
                ..Default::default()
            },
        );
        let delegation = match verified {
            Ok(d) => d,
            Err(why) => {
                rejected.push(format!("{name}: {why}"));
                continue;
            }
        };
        // The verification above binds this requirement to the seal's signatures. An eligible person
        // must not seal a 3-of-N delegation with a 1-of-N ceremony, nor omit an ordinary four-eyes or
        // hardware restriction (DIV §5a.5).
        let sealed: Option<ApprovalRequirement> =
            serde_json::from_str::<Value>(&receipt.canonical_payload)
                .ok()
                .and_then(|v| v.get("requirement").cloned())
                .and_then(|v| serde_json::from_value(v).ok());
        let weaker = match &sealed {
            None => true,
            Some(sealed) => {
                let weaker_aaguids = !ordinary.allowed_aaguids.is_empty()
                    && (sealed.allowed_aaguids.is_empty()
                        || sealed
                            .allowed_aaguids
                            .iter()
                            .any(|a| !ordinary.allowed_aaguids.contains(a)));
                sealed.required_approvals < ordinary.required_approvals
                    || (ordinary.require_hardware_key && !sealed.require_hardware_key)
                    || (ordinary.requester_cannot_approve && !sealed.requester_cannot_approve)
                    || weaker_aaguids
            }
        };
        if weaker {
            rejected.push(format!(
                "{name}: delegation sealing requirement is weaker than the ordinary approval rule"
            ));
            continue;
        }
        return (Some(delegation), None);
    }
    if rejected.is_empty() {
        (None, None)
    } else {
        (
            None,
            Some(format!("no delegation applies ({})", rejected.join("; "))),
        )
    }
}

/// A buffered offline approval awaiting reconciliation — `<buffer_dir>/<nonce>.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingApproval {
    pub nonce: String,
    pub target: String,
    pub action_type: String,
    pub display: String,
    pub used_at: String,
    /// The full receipt, so the gateway can re-verify the approval rather than take our word for it.
    #[serde(serialize_with = "serialize_receipt")]
    pub receipt: ApprovalReceipt,
    /// The delegation's nonce, when one supplied the approver set. Omitted, never `null`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation_nonce: Option<String>,
}

/// Write a receipt the way the reference does: absent optional fields are left out rather than
/// written as `null`, so a record (or report) is the same shape whichever SDK produced it.
fn serialize_receipt<S: Serializer>(receipt: &ApprovalReceipt, s: S) -> Result<S::Ok, S::Error> {
    receipt_json(receipt).serialize(s)
}

/// A receipt as JSON with its absent optional fields left out (top level and per witness).
pub(crate) fn receipt_json(receipt: &ApprovalReceipt) -> Value {
    let mut value = serde_json::to_value(receipt).unwrap_or(Value::Null);
    strip_nulls(&mut value);
    if let Some(sigs) = value.get_mut("signatures").and_then(Value::as_array_mut) {
        sigs.iter_mut().for_each(strip_nulls);
    }
    value
}

fn strip_nulls(value: &mut Value) {
    if let Some(obj) = value.as_object_mut() {
        obj.retain(|_, v| !v.is_null());
    }
}

fn buffer_dir_of(bundle_dir: &Path, buffer_dir: Option<&Path>) -> PathBuf {
    buffer_dir.map_or_else(|| bundle_dir.join(PENDING_DIR), Path::to_path_buf)
}

/// Record the approval so it can be reported when the gateway is reachable again. Best effort by
/// design — a buffering failure must never block the emergency action — and warned about loudly,
/// because an unrecorded approval is exactly what reconciliation exists to surface.
fn buffer_for_reconciliation(
    challenge: &OfflineChallenge,
    receipt: &ApprovalReceipt,
    delegation: Option<&VerifiedDelegation>,
    opts: &OfflineApprovalOptions<'_>,
) {
    let record = PendingApproval {
        nonce: challenge.nonce.clone(),
        target: challenge.target.clone(),
        action_type: challenge.action_type.clone(),
        display: challenge.display.clone(),
        used_at: iso_timestamp(SystemTime::now()),
        receipt: receipt.clone(),
        delegation_nonce: delegation.map(|d| d.nonce.clone()),
    };
    let written = (|| -> Result<(), String> {
        if !is_path_safe_nonce(&challenge.nonce) {
            return Err("nonce is not a safe path segment".into());
        }
        let dir = buffer_dir_of(&opts.bundle_dir, opts.buffer_dir.as_deref());
        ensure_private_dir(&dir)?;
        let json = serde_json::to_string_pretty(&record).map_err(|e| e.to_string())?;
        write_private_file(
            &dir.join(format!("{}.json", challenge.nonce)),
            format!("{json}\n").as_bytes(),
        )
    })();
    if let Err(why) = written {
        opts.warn(&format!(
            "⚠ OFFLINE APPROVAL: could not buffer {} for reconciliation ({why}). Report this manually — an unreported approval is indistinguishable from an unauthorized one.",
            challenge.nonce
        ));
    }
}

/// The readable records with their paths, and the names of files that could not be read as one.
pub(crate) type PendingScan = (Vec<(PathBuf, PendingApproval)>, Vec<String>);

/// Every `*.json` in the buffer, sorted by file name.
pub(crate) fn scan_pending(bundle_dir: &Path, buffer_dir: Option<&Path>) -> PendingScan {
    let dir = buffer_dir_of(bundle_dir, buffer_dir);
    let Some(files) = json_files_in_name_order(&dir) else {
        return (Vec::new(), Vec::new());
    };
    let mut records = Vec::new();
    let mut unreadable = Vec::new();
    // Each record on its own: one unreadable file must not hide the others.
    for (name, file) in files {
        match std::fs::read_to_string(&file)
            .ok()
            .and_then(|text| serde_json::from_str::<PendingApproval>(&text).ok())
        {
            Some(record) => records.push((file, record)),
            None => unreadable.push(name),
        }
    }
    (records, unreadable)
}

/// The offline approvals buffered by [`use_offline_approval`] and not yet reported. `buffer_dir`
/// defaults to `<bundle_dir>/.pending`. A file that is not a readable record is skipped here;
/// [`crate::Client::reconcile_offline_approvals`] reports it as a failure instead.
pub fn pending_approvals(
    bundle_dir: impl AsRef<Path>,
    buffer_dir: Option<&Path>,
) -> Vec<PendingApproval> {
    scan_pending(bundle_dir.as_ref(), buffer_dir)
        .0
        .into_iter()
        .map(|(_, record)| record)
        .collect()
}

/// Clear a buffered approval once the gateway has acknowledged it.
///
/// Only call this on a definite acknowledgement: dropping the record on a network error would turn
/// a retryable report into a permanently unreported approval. An unsafe nonce is ignored — it may
/// have been echoed back by someone else, and must never name a path outside the buffer.
pub fn clear_pending_approval(
    nonce: &str,
    bundle_dir: impl AsRef<Path>,
    buffer_dir: Option<&Path>,
) {
    if !is_path_safe_nonce(nonce) {
        return;
    }
    let dir = buffer_dir_of(bundle_dir.as_ref(), buffer_dir);
    let _ = std::fs::remove_file(dir.join(format!("{nonce}.json")));
}
