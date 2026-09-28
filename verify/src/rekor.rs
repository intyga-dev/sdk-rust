use crate::ledger::{decode_public_key, SignedAnchor};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use p256::{
    ecdsa::{signature::Verifier, Signature, VerifyingKey},
    pkcs8::DecodePublicKey,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct RekorEvidence {
    pub uuid: Option<String>,
    pub body: Option<String>,
    #[serde(rename = "logID")]
    pub log_id: Option<String>,
    pub log_index: Option<u64>,
    pub integrated_time: Option<u64>,
    pub verification: Option<RekorEvidenceVerification>,
}
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct RekorEvidenceVerification {
    pub signed_entry_timestamp: Option<String>,
    pub inclusion_proof: Option<serde_json::Value>,
}
#[derive(Debug, Clone, Default)]
pub struct RekorVerification {
    pub ok: bool,
    pub reason: Option<String>,
    pub log_index: Option<u64>,
    pub log_id: Option<String>,
    pub integrated_time: Option<u64>,
}
pub fn parse_rekor_evidence(raw: Option<&str>) -> Option<RekorEvidence> {
    let b = STANDARD.decode(raw?).ok()?;
    serde_json::from_slice(&b).ok()
}
pub fn rekor_payload_hash_for(a: &SignedAnchor) -> String {
    format!("{:x}", Sha256::digest(a.digest()))
}
/// Verify the SET and the logged payload hash, without pinning who submitted the entry.
pub fn verify_rekor_anchor(
    e: &RekorEvidence,
    a: &SignedAnchor,
    key_b64: &str,
) -> RekorVerification {
    verify_rekor_anchor_pinned(e, a, key_b64, &[])
}

/// The hashedrekord was submitted under one of the caller-pinned producer keys, and that key's ES256
/// signature covers the anchor digest. Rekor logs a submission under ANY key, so without this anyone
/// who can compute the digest (built from public fields) can have it logged. `publicKey.content` is
/// base64 of the PEM text.
fn submitted_by_pinned_key(v: &serde_json::Value, a: &SignedAnchor, pinned: &[String]) -> bool {
    let sig = &v["spec"]["signature"];
    let (Some(pk_b64), Some(sig_b64)) = (sig["publicKey"]["content"].as_str(), sig["content"].as_str()) else {
        return false;
    };
    let Some(submitted) = STANDARD
        .decode(pk_b64)
        .ok()
        .and_then(|pem| String::from_utf8(pem).ok())
        .and_then(|pem| decode_public_key(&pem))
    else {
        return false;
    };
    if !pinned.iter().any(|k| decode_public_key(k).as_deref() == Some(submitted.as_slice())) {
        return false;
    }
    let (Some(key), Ok(sig_bytes)) = (crate::parse_p256_public_key(&submitted), STANDARD.decode(sig_b64)) else {
        return false;
    };
    crate::verify_p256_signature(&key, &a.digest(), &sig_bytes)
}

/// `verify_rekor_anchor`, additionally requiring (when `submitter_keys` is non-empty) that the
/// entry was submitted under a pinned producer key with a valid signature over this anchor.
pub fn verify_rekor_anchor_pinned(
    e: &RekorEvidence,
    a: &SignedAnchor,
    key_b64: &str,
    submitter_keys: &[String],
) -> RekorVerification {
    let fail = |s: &str| RekorVerification {
        ok: false,
        reason: Some(s.into()),
        ..Default::default()
    };
    let Some(body) = &e.body else {
        return fail("rekor evidence carries no entry body");
    };
    let Some(set) = e
        .verification
        .as_ref()
        .and_then(|v| v.signed_entry_timestamp.as_ref())
    else {
        return fail("rekor evidence carries no signedEntryTimestamp (SET)");
    };
    if e.log_index.is_none() || e.integrated_time.is_none() {
        return fail("rekor evidence is missing logIndex/integratedTime");
    }
    let Ok(decoded) = STANDARD.decode(body) else {
        return fail("rekor entry body is not a readable hashedrekord");
    };
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(&decoded) else {
        return fail("rekor entry body is not a readable hashedrekord");
    };
    if v.get("kind").and_then(|x| x.as_str()) != Some("hashedrekord") {
        return fail("rekor entry body is not a readable hashedrekord");
    };
    let hash = &v["spec"]["data"]["hash"];
    if hash["algorithm"].as_str() != Some("sha256") {
        return fail("rekor entry body is not a readable hashedrekord");
    };
    let Some(logged) = hash["value"].as_str() else {
        return fail("rekor entry body is not a readable hashedrekord");
    };
    if logged.to_ascii_lowercase() != rekor_payload_hash_for(a) {
        return fail("rekor entry attests a different payload");
    }
    if !submitter_keys.is_empty() && !submitted_by_pinned_key(&v, a, submitter_keys) {
        return fail("rekor entry was not submitted under a pinned producer key with a valid signature over this anchor");
    }
    let payload=serde_json::json!({"body":body,"integratedTime":e.integrated_time,"logID":e.log_id,"logIndex":e.log_index}).to_string();
    let encoded = if key_b64.contains("BEGIN") {
        key_b64
            .lines()
            .filter(|line| !line.starts_with("---"))
            .collect::<String>()
    } else {
        key_b64.to_owned()
    };
    let Ok(kb) = STANDARD.decode(encoded) else {
        return fail("rekor public key is invalid");
    };
    let Ok(key) = VerifyingKey::from_public_key_der(&kb) else {
        return fail("rekor public key is not an EC key");
    };
    let Ok(sb) = STANDARD.decode(set) else {
        return fail("rekor SET verification failed");
    };
    let Ok(sig) = Signature::from_der(&sb) else {
        return fail("rekor SET verification failed");
    };
    if key.verify(payload.as_bytes(), &sig).is_err() {
        return fail("rekor SET does not verify under the supplied log key");
    }
    RekorVerification {
        ok: true,
        reason: None,
        log_index: e.log_index,
        log_id: e.log_id.clone(),
        integrated_time: e.integrated_time,
    }
}
