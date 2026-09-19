use crate::ledger::{self, AnchorPolicy, ExternalAnchorKeys, ProofBounds, ProofStep, SignedAnchor};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use serde_json::Value;
pub const BUNDLE_KIND: &str = "dewp.audit.inclusion-proof";
pub const EVIDENCE_BUNDLE_KIND: &str = "dewp.audit.evidence-bundle";
pub const AUDIT_PROFILE: &str = "trust.intyga.audit.v1";
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InclusionProof {
    pub seq: String,
    pub leaf: String,
    pub block_index: String,
    pub block_root: String,
    pub block_proof: Vec<WireProofStep>,
    pub leaf_index: usize,
    pub block_leaf_count: usize,
    pub checkpoint_id: Option<String>,
    pub checkpoint_root: Option<String>,
    pub checkpoint_proof: Vec<WireProofStep>,
    pub checkpoint_leaf_index: usize,
    pub checkpoint_leaf_count: usize,
    pub anchor_ref: Option<String>,
    pub anchored: bool,
    #[serde(default)]
    pub externally_anchored: Option<bool>,
    #[serde(default)]
    pub externally_anchored_required: Option<usize>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WireProofStep {
    pub sibling_hash: String,
    pub sibling_position: String,
}
impl InclusionProof {
    fn verify(&self, root: &str) -> bool {
        let cv = |v: &[WireProofStep]| {
            v.iter()
                .map(|s| ProofStep {
                    sibling_hash: s.sibling_hash.clone(),
                    sibling_position: s.sibling_position.clone(),
                })
                .collect::<Vec<_>>()
        };
        ledger::verify_inclusion_proof(
            &self.leaf,
            &cv(&self.block_proof),
            &self.block_root,
            ProofBounds {
                index: self.leaf_index,
                leaf_count: self.block_leaf_count,
            },
            &cv(&self.checkpoint_proof),
            root,
            ProofBounds {
                index: self.checkpoint_leaf_index,
                leaf_count: self.checkpoint_leaf_count,
            },
        )
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BundleEvent {
    pub seq: String,
    #[serde(default)]
    pub id: Option<String>,
    pub created_at: String,
    #[serde(rename = "type")]
    pub event_type: String,
    pub outcome: String,
    pub detail: Option<String>,
    pub actor_did: Option<String>,
    pub subject_did: Option<String>,
    pub signer_did: Option<String>,
    pub signature: Option<String>,
    pub sig_alg: Option<String>,
    #[serde(default)]
    pub canonical: Option<Value>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LegacyAnchor {
    pub daily_root: Option<String>,
    pub anchor_ref: Option<String>,
    pub anchored: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProofBundle {
    pub kind: String,
    pub version: Value,
    #[serde(default)]
    pub protocol: Option<String>,
    #[serde(default)]
    pub profile: Option<String>,
    pub exported_at: String,
    pub event: BundleEvent,
    pub proof: InclusionProof,
    #[serde(default)]
    pub anchor: Option<SignedAnchor>,
    #[serde(default)]
    pub anchors: Vec<SignedAnchor>,
    #[serde(default)]
    pub anchor_ref: Option<String>,
    #[serde(default)]
    pub anchored: Option<bool>,
    #[serde(default)]
    pub externally_anchored: Option<bool>,
    #[serde(default)]
    pub externally_anchored_required: Option<usize>,
    #[serde(default)]
    pub legacy_anchor: Option<LegacyAnchor>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationLevel {
    Invalid,
    CommitmentVerified,
    ContentVerified,
    SignatureVerified,
    FullyVerified,
}
#[derive(Debug, Clone, Default)]
pub struct VerificationProperties {
    pub commitment_verified: bool,
    pub content_verified: bool,
    pub signature_verified: bool,
    pub anchor_verified: bool,
}
#[derive(Debug, Clone)]
pub struct CheckResult {
    pub pass: Option<bool>,
    pub detail: String,
}
#[derive(Debug, Clone)]
pub struct BundleVerification {
    pub ok: bool,
    pub daily_root: Option<String>,
    pub root_source: &'static str,
    pub properties: VerificationProperties,
    pub verification_level: VerificationLevel,
    pub inclusion: CheckResult,
    pub root_consistency: CheckResult,
    pub leaf_binding: CheckResult,
    pub header_binding: CheckResult,
    pub notes: Vec<String>,
}
pub struct BundleVerifyOptions<'a, F: Fn(&SignedAnchor) -> Option<String>> {
    pub trusted_root: Option<String>,
    pub anchors: Option<Vec<SignedAnchor>>,
    pub anchor_policy: Option<AnchorPolicy>,
    pub resolve_anchor_key: Option<&'a F>,
    pub external_keys: ExternalAnchorKeys,
}
impl<'a, F: Fn(&SignedAnchor) -> Option<String>> Default for BundleVerifyOptions<'a, F> {
    fn default() -> Self {
        Self {
            trusted_root: None,
            anchors: None,
            anchor_policy: None,
            resolve_anchor_key: None,
            external_keys: ExternalAnchorKeys::default(),
        }
    }
}
pub fn verify_embedded_signature(c: &Value) -> bool {
    if c["sigAlg"].as_str() != Some("ES256") {
        return false;
    }
    let (Some(k), Some(s), Some(p)) = (
        c["signerPublicKey"].as_str(),
        c["signature"].as_str(),
        c["signedPayload"].as_str(),
    ) else {
        return false;
    };
    let (Ok(k), Ok(s)) = (STANDARD.decode(k), STANDARD.decode(s)) else {
        return false;
    };
    crate::parse_p256_public_key(&k)
        .is_some_and(|key| crate::verify_p256_signature(&key, p.as_bytes(), &s))
}
pub fn derive_verification_level(
    p: &VerificationProperties,
    has_signer: bool,
) -> VerificationLevel {
    if !p.commitment_verified {
        VerificationLevel::Invalid
    } else if !p.content_verified {
        VerificationLevel::CommitmentVerified
    } else if p.anchor_verified && (p.signature_verified || !has_signer) {
        VerificationLevel::FullyVerified
    } else if p.signature_verified {
        VerificationLevel::SignatureVerified
    } else {
        VerificationLevel::ContentVerified
    }
}
fn check(pass: Option<bool>, yes: &str, no: &str) -> CheckResult {
    CheckResult {
        pass,
        detail: if pass == Some(true) { yes } else { no }.into(),
    }
}
fn shown_matches(e: &BundleEvent, c: &Value, p: &InclusionProof) -> bool {
    let eq = |shown: Option<&str>, key: &str| {
        shown.is_none() || shown == c.get(key).and_then(Value::as_str)
    };
    eq(Some(&e.seq), "seq")
        && eq(Some(&p.seq), "seq")
        && eq(Some(&e.created_at), "createdAt")
        && eq(Some(&e.event_type), "event")
        && eq(Some(&e.outcome), "outcome")
        && eq(e.detail.as_deref(), "detail")
        && eq(e.signer_did.as_deref(), "signerDid")
        && eq(e.signature.as_deref(), "signature")
        && eq(e.sig_alg.as_deref(), "sigAlg")
}
pub fn verify_bundle<F: Fn(&SignedAnchor) -> Option<String>>(
    b: &ProofBundle,
    o: &BundleVerifyOptions<F>,
) -> BundleVerification {
    let mut notes = Vec::new();
    let kind_ok = b.kind == BUNDLE_KIND;
    if !kind_ok {
        notes.push(format!(
            "Refusing bundle kind {:?} (expected {BUNDLE_KIND:?}) — DEWP §6.5.",
            b.kind
        ))
    }
    let self_root = b
        .anchor
        .as_ref()
        .map(|a| a.daily_root.clone())
        .or_else(|| b.legacy_anchor.as_ref().and_then(|a| a.daily_root.clone()))
        .or_else(|| b.proof.checkpoint_root.clone());
    let (root, source) = if let Some(r) = &o.trusted_root {
        (Some(r.clone()), "independent")
    } else if self_root.is_some() {
        notes.push("No independent root supplied — internal consistency only.".into());
        (self_root, "self-asserted")
    } else {
        (None, "none")
    };
    let inc = root.as_ref().map(|r| b.proof.verify(r));
    let inclusion = check(
        inc,
        "Event leaf recomputes to the daily root.",
        "Recomputed root does not match.",
    );
    let consistency = root
        .as_ref()
        .map(|r| b.proof.checkpoint_root.as_deref() == Some(r));
    let root_consistency = check(
        consistency,
        "Checkpoint root matches.",
        "Checkpoint root differs.",
    );
    let unknown = b.profile.as_deref().is_some_and(|p| p != AUDIT_PROFILE);
    let leaf = if unknown {
        None
    } else {
        b.event
            .canonical
            .as_ref()
            .map(|c| ledger::leaf_hash(c) == b.proof.leaf)
    };
    let leaf_binding = check(
        leaf,
        "Leaf hash matches canonical content.",
        "Leaf hash does not match canonical content.",
    );
    let header = b
        .event
        .canonical
        .as_ref()
        .map(|c| shown_matches(&b.event, c, &b.proof));
    let header_binding = check(
        header,
        "Displayed fields match committed content.",
        "Displayed fields differ from committed content.",
    );
    let commitment = inc == Some(true) && consistency == Some(true);
    let content = commitment && leaf == Some(true) && header != Some(false);
    let signature = content
        && b.event
            .canonical
            .as_ref()
            .is_some_and(verify_embedded_signature);
    let has_signer = b.event.canonical.as_ref().is_some_and(|c| {
        c["signature"].as_str().is_some_and(|s| !s.is_empty())
            && c["signerPublicKey"].as_str().is_some_and(|s| !s.is_empty())
    });
    let mut anchor_verified = false;
    let mut divergence = false;
    if let (Some(policy), Some(resolve), Some(r)) =
        (&o.anchor_policy, o.resolve_anchor_key, root.as_deref())
    {
        let candidates = o.anchors.clone().unwrap_or_else(|| {
            let mut a = b.anchors.clone();
            if let Some(x) = &b.anchor {
                a.push(x.clone())
            }
            a
        });
        let div = o.anchors.as_deref().unwrap_or(&[]);
        let q =
            ledger::verify_anchor_quorum(&candidates, r, policy, resolve, div, &o.external_keys);
        anchor_verified = commitment && q.ok;
        divergence = q.divergence;
        if let Some(n) = q.reason {
            notes.push(n)
        }
        if let Some(n) = q.note {
            notes.push(n)
        }
    }
    let props = VerificationProperties {
        commitment_verified: commitment,
        content_verified: content,
        signature_verified: signature,
        anchor_verified,
    };
    let level = if !kind_ok || divergence {
        VerificationLevel::Invalid
    } else {
        derive_verification_level(&props, has_signer)
    };
    let base = kind_ok
        && source == "independent"
        && commitment
        && leaf != Some(false)
        && header != Some(false)
        && (!b.event.canonical.is_some() || leaf == Some(true));
    let ok = base && !divergence && (o.anchor_policy.is_none() || anchor_verified);
    BundleVerification {
        ok,
        daily_root: root,
        root_source: source,
        properties: props,
        verification_level: level,
        inclusion,
        root_consistency,
        leaf_binding,
        header_binding,
        notes,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceEntry {
    pub event: EvidenceEvent,
    pub proof: InclusionProof,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceEvent {
    pub seq: String,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(rename = "type", default)]
    pub event_type: Option<String>,
    #[serde(default)]
    pub outcome: Option<String>,
    #[serde(default)]
    pub signer_did: Option<String>,
    #[serde(default)]
    pub sig_alg: Option<String>,
    #[serde(default)]
    pub tenant_seq: Option<String>,
    #[serde(default)]
    pub canonical: Option<Value>,
    #[serde(default)]
    pub redacted: Option<bool>,
    #[serde(default)]
    pub redaction: Option<RedactionRecord>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RedactionRecord {
    pub mode: String,
    #[serde(default)]
    pub commitment: Option<RedactionCommitment>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RedactionCommitment {
    pub leaf: String,
    #[serde(default)]
    pub tenant_seq: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceCheckpoint {
    #[serde(default)]
    pub id: Option<String>,
    pub root: String,
    #[serde(default)]
    pub anchor_ref: Option<String>,
    #[serde(default)]
    pub anchors: Vec<SignedAnchor>,
    #[serde(default)]
    pub seq_start: Option<String>,
    #[serde(default)]
    pub seq_end: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceBundle {
    pub kind: String,
    #[serde(default)]
    pub profile: Option<String>,
    pub tenant: Value,
    pub entries: Vec<EvidenceEntry>,
    pub checkpoints: Vec<EvidenceCheckpoint>,
    #[serde(default)]
    pub tenant_sequence_commitment: Option<Value>,
}
#[derive(Debug, Clone, Default)]
pub struct EvidenceVerification {
    pub ok: bool,
    pub total: usize,
    pub content_verified: usize,
    pub commitment_only: usize,
    pub failed: Vec<(String, String)>,
    pub notes: Vec<String>,
    pub roots: Vec<EvidenceRoot>,
    pub signatures: EvidenceSignatures,
}
pub struct EvidenceVerifyOptions<'a, F: Fn(&SignedAnchor) -> Option<String>> {
    pub trusted_roots: Option<&'a [String]>,
    /// Caller-fetched anchors. The keyed form attributes each list to a checkpoint id or root,
    /// which is required for a meaningful divergence verdict on multi-checkpoint bundles.
    pub anchors: Option<EvidenceAnchorSet>,
    pub anchor_policy: Option<AnchorPolicy>,
    pub resolve_anchor_key: Option<&'a F>,
    pub external_keys: ExternalAnchorKeys,
}
#[derive(Debug, Clone)]
pub enum EvidenceAnchorSet {
    Flat(Vec<SignedAnchor>),
    ByCheckpoint(std::collections::BTreeMap<String, Vec<SignedAnchor>>),
}
#[derive(Debug, Clone)]
pub struct EvidenceRoot {
    pub root: String,
    pub anchor_ref: Option<String>,
    pub anchor_verified: Option<bool>,
    pub verified_issuers: Vec<String>,
}
#[derive(Debug, Clone, Default)]
pub struct EvidenceSignatures {
    pub verified: usize,
    pub invalid: Vec<String>,
    pub not_checkable: usize,
}

fn parse_counter(raw: &str) -> Option<i128> {
    let digits = raw.strip_prefix('-').unwrap_or(raw);
    if digits.is_empty() || digits.len() > 20 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    raw.parse().ok()
}

pub fn verify_evidence_bundle(
    b: &EvidenceBundle,
    trusted_roots: Option<&[String]>,
) -> EvidenceVerification {
    let mut r = EvidenceVerification {
        total: b.entries.len(),
        ..Default::default()
    };
    if b.kind != EVIDENCE_BUNDLE_KIND {
        r.failed.push(("-".into(), "refusing bundle kind".into()))
    }
    let roots = b
        .checkpoints
        .iter()
        .map(|c| c.root.as_str())
        .collect::<std::collections::HashSet<_>>();
    let trusted = trusted_roots.map(|x| {
        x.iter()
            .map(String::as_str)
            .collect::<std::collections::HashSet<_>>()
    });
    let unknown_profile = b.profile.as_deref().is_some_and(|p| p != AUDIT_PROFILE);
    for e in &b.entries {
        let Some(root) = e.proof.checkpoint_root.as_deref() else {
            r.failed
                .push((e.event.seq.clone(), "no checkpoint root".into()));
            continue;
        };
        if !roots.contains(root)
            || trusted.as_ref().is_some_and(|t| !t.contains(root))
            || !e.proof.verify(root)
        {
            r.failed.push((
                e.event.seq.clone(),
                "inclusion proof invalid or root untrusted".into(),
            ));
            continue;
        }
        if let Some(c) = &e.event.canonical {
            if unknown_profile {
                r.commitment_only += 1
            } else if ledger::leaf_hash(c) != e.proof.leaf {
                r.failed
                    .push((e.event.seq.clone(), "leaf binding failed".into()));
                continue;
            } else {
                let mismatch = |k: &str, shown: Option<&String>| {
                    shown.is_some()
                        && shown != c.get(k).and_then(Value::as_str).map(str::to_owned).as_ref()
                };
                if mismatch("seq", Some(&e.event.seq))
                    || mismatch("createdAt", e.event.created_at.as_ref())
                    || mismatch("event", e.event.event_type.as_ref())
                    || mismatch("outcome", e.event.outcome.as_ref())
                    || mismatch("signerDid", e.event.signer_did.as_ref())
                    || mismatch("sigAlg", e.event.sig_alg.as_ref())
                    || mismatch("tenantSeq", e.event.tenant_seq.as_ref())
                {
                    r.failed.push((
                        e.event.seq.clone(),
                        "displayed event fields differ from committed content".into(),
                    ));
                    continue;
                }
                if let Some(id) = b.tenant.get("id").and_then(Value::as_str) {
                    if c.get("tenantId")
                        .and_then(Value::as_str)
                        .is_some_and(|x| x != id)
                    {
                        r.failed.push((
                            e.event.seq.clone(),
                            "entry belongs to a different tenant".into(),
                        ));
                        continue;
                    }
                }
                r.content_verified += 1;
                if c.get("sigAlg").and_then(Value::as_str) == Some("ES256")
                    && c.get("signature").and_then(Value::as_str).is_some()
                    && c.get("signerPublicKey").and_then(Value::as_str).is_some()
                {
                    if verify_embedded_signature(c) {
                        r.signatures.verified += 1
                    } else {
                        r.signatures.invalid.push(e.event.seq.clone())
                    }
                } else {
                    r.signatures.not_checkable += 1
                }
            }
        } else if match e.event.redaction.as_ref() {
            Some(redaction) => redaction.mode == "COMMITMENT_ONLY",
            None => e.event.redacted == Some(true),
        } {
            if let Some(c) = &e
                .event
                .redaction
                .as_ref()
                .and_then(|x| x.commitment.as_ref())
            {
                if c.leaf != e.proof.leaf {
                    r.failed.push((
                        e.event.seq.clone(),
                        "redaction commitment leaf does not match proof leaf".into(),
                    ));
                    continue;
                }
            }
            r.commitment_only += 1
        } else if unknown_profile {
            r.commitment_only += 1
        } else {
            r.failed.push((
                e.event.seq.clone(),
                "unredacted entry is missing its canonical preimage".into(),
            ));
            continue;
        }
    }

    // Completeness counters are evaluated independently of content/proof failures so a malformed
    // entry cannot make the verifier silently skip the range check as a side effect of `continue`.
    let mut first: Option<i128> = None;
    let mut last: Option<i128> = None;
    let mut saw_uncounted = false;
    let mut saw_unbound = false;
    for e in &b.entries {
        let bound = e
            .event
            .canonical
            .as_ref()
            .and_then(|c| c.get("tenantSeq").and_then(Value::as_str));
        let raw = bound
            .or_else(|| {
                e.event
                    .redaction
                    .as_ref()
                    .and_then(|x| x.commitment.as_ref())
                    .and_then(|x| x.tenant_seq.as_deref())
            })
            .or(e.event.tenant_seq.as_deref());
        if bound.is_none() && raw.is_some() {
            saw_unbound = true;
        }
        if let Some(s) = raw {
            let Some(n) = parse_counter(s) else {
                r.failed.push((
                    e.event.seq.clone(),
                    format!("tenantSeq {s:?} is not a valid integer counter"),
                ));
                continue;
            };
            if let Some(p) = last {
                if n != p + 1 {
                    r.failed.push((
                        e.event.seq.clone(),
                        if n <= p {
                            "per-tenant sequence is not strictly increasing".into()
                        } else {
                            "per-tenant omission detected".into()
                        },
                    ))
                }
            }
            first.get_or_insert(n);
            last = Some(n);
        } else {
            saw_uncounted = true;
        }
    }
    if saw_uncounted {
        r.notes.push("Some entries carry no tenantSeq, so gapless completeness could not be checked across them.".into());
    }
    if saw_unbound {
        r.notes.push("Some entries' tenantSeq is not covered by the Merkle leaf; completeness across those counters rests on the producer's redaction record.".into());
    }

    if let Some(commitment) = &b.tenant_sequence_commitment {
        match (first, last) {
            (Some(first_seen), Some(last_seen)) => {
                let claimed_first = commitment
                    .get("firstTenantSeq")
                    .and_then(Value::as_str)
                    .and_then(parse_counter);
                let claimed_last = commitment
                    .get("lastTenantSeq")
                    .and_then(Value::as_str)
                    .and_then(parse_counter);
                match (claimed_first, claimed_last) {
                    (Some(claimed_first), Some(claimed_last)) => {
                        if claimed_first != first_seen {
                            r.failed.push((
                                b.entries.first().map_or("?", |e| e.event.seq.as_str()).into(),
                                format!("bundle claims it starts at tenantSeq {claimed_first} but the first entry is {first_seen}"),
                            ));
                        }
                        if claimed_last != last_seen {
                            r.failed.push((
                                b.entries.last().map_or("?", |e| e.event.seq.as_str()).into(),
                                format!("bundle claims it ends at tenantSeq {claimed_last} but the last entry is {last_seen}"),
                            ));
                        }
                    }
                    _ => r.failed.push((
                        b.entries.first().map_or("?", |e| e.event.seq.as_str()).into(),
                        "tenantSequenceCommitment carries a non-numeric firstTenantSeq/lastTenantSeq".into(),
                    )),
                }
                if commitment.get("tenantId") != b.tenant.get("id") {
                    r.notes.push("tenantSequenceCommitment names a different tenant than the evidence bundle".into());
                }
            }
            _ => r.notes.push("Bundle declares a tenantSequenceCommitment but no entry carries a tenantSeq to check it against.".into()),
        }
    }
    r.roots = b
        .checkpoints
        .iter()
        .map(|c| EvidenceRoot {
            root: c.root.clone(),
            anchor_ref: c.anchor_ref.clone(),
            anchor_verified: None,
            verified_issuers: Vec::new(),
        })
        .collect();
    r.ok = r.failed.is_empty() && !b.entries.is_empty() && trusted.is_some();
    r
}

#[cfg(test)]
mod parity_tests {
    use super::*;
    use crate::chain::{verify_roots_chain, RootsChainEntry};
    #[test]
    fn shared_verifier_parity_vectors_are_loaded_in_full() {
        let p = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/vectors/verifier-parity-vectors.json"
        );
        let v: Value = serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap();
        for key in [
            "keys",
            "agentAuthority",
            "platform",
            "evidence",
            "rootsChain",
            "bundles",
        ] {
            assert!(v.get(key).is_some(), "missing parity section {key}");
        }
        for c in v["evidence"]["cases"].as_array().unwrap() {
            let b: EvidenceBundle = serde_json::from_value(c["bundle"].clone()).unwrap();
            let roots: Vec<String> = c["options"]["trustedRoots"]
                .as_array()
                .unwrap_or(&vec![])
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect();
            let policy = c.get("policy").map(|p| AnchorPolicy {
                required_anchors: p["requiredAnchors"].as_u64().unwrap() as usize,
                trusted_issuers: serde_json::from_value(p["trustedIssuers"].clone()).unwrap(),
                quorum: if p["quorum"] == "ALL_MUST_AGREE" {
                    ledger::AnchorQuorum::AllMustAgree
                } else {
                    ledger::AnchorQuorum::NOfM
                },
            });
            let resolver = |a: &SignedAnchor| {
                v["keys"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|k| k["id"].as_str() == Some(&a.key_id))
                    .and_then(|k| k["spkiB64"].as_str())
                    .map(str::to_owned)
            };
            let anchors = c["options"].get("anchors").map(|a| {
                if a.is_array() {
                    EvidenceAnchorSet::Flat(serde_json::from_value(a.clone()).unwrap())
                } else {
                    EvidenceAnchorSet::ByCheckpoint(serde_json::from_value(a.clone()).unwrap())
                }
            });
            let opts = EvidenceVerifyOptions {
                trusted_roots: Some(&roots),
                anchors,
                anchor_policy: policy,
                resolve_anchor_key: Some(&resolver),
                external_keys: ExternalAnchorKeys::default(),
            };
            let got = verify_evidence_bundle_with_options(&b, &opts);
            assert_eq!(got.ok, c["ok"].as_bool().unwrap(), "evidence {}", c["name"]);
            if let Some(n) = c.get("total").and_then(Value::as_u64) {
                assert_eq!(got.total, n as usize);
            }
            if let Some(n) = c.get("contentVerified").and_then(Value::as_u64) {
                assert_eq!(got.content_verified, n as usize);
            }
            if let Some(n) = c.get("commitmentOnly").and_then(Value::as_u64) {
                assert_eq!(got.commitment_only, n as usize);
            }
        }
        for c in v["rootsChain"]["cases"].as_array().unwrap() {
            let entries: Vec<RootsChainEntry> =
                serde_json::from_value(c["entries"].clone()).unwrap();
            let got = verify_roots_chain(&entries);
            assert_eq!(got.ok, c["ok"].as_bool().unwrap(), "chain {}", c["name"]);
            assert_eq!(got.unchained, c["unchained"].as_bool().unwrap());
            assert_eq!(
                got.broken_at,
                c["brokenAt"].as_i64().unwrap() as isize,
                "chain {} brokenAt",
                c["name"]
            );
            if let Some(n) = c.get("verifiedCount").and_then(Value::as_u64) {
                assert_eq!(
                    got.verified_count, n as usize,
                    "chain {} verifiedCount",
                    c["name"]
                );
            }
        }
        for c in v["bundles"]["cases"].as_array().unwrap() {
            let b: ProofBundle = serde_json::from_value(c["bundle"].clone()).unwrap();
            let root = c["options"]["trustedRoot"].as_str().map(str::to_owned);
            let policy = c.get("policy").unwrap_or(&v["bundles"]["anchorPolicy"]);
            let resolver = |a: &SignedAnchor| {
                v["keys"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|k| k["id"].as_str() == Some(&a.key_id))
                    .and_then(|k| k["spkiB64"].as_str())
                    .map(str::to_owned)
            };
            let rekor = c["options"]["rekorKeyId"].as_str().and_then(|id| {
                v["keys"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|k| k["id"].as_str() == Some(id))
                    .and_then(|k| k["spkiB64"].as_str())
                    .map(str::to_owned)
            });
            let o = BundleVerifyOptions {
                trusted_root: root,
                anchors: c["options"]
                    .get("divergenceAnchors")
                    .map(|a| serde_json::from_value(a.clone()).unwrap()),
                anchor_policy: Some(AnchorPolicy {
                    required_anchors: policy["requiredAnchors"].as_u64().unwrap() as usize,
                    trusted_issuers: serde_json::from_value(policy["trustedIssuers"].clone())
                        .unwrap(),
                    quorum: if policy["quorum"] == "ALL_MUST_AGREE" {
                        ledger::AnchorQuorum::AllMustAgree
                    } else {
                        ledger::AnchorQuorum::NOfM
                    },
                }),
                resolve_anchor_key: Some(&resolver),
                external_keys: ExternalAnchorKeys { rekor },
            };
            let got = verify_bundle(&b, &o);
            assert_eq!(
                got.ok,
                c["ok"].as_bool().unwrap(),
                "bundle {}: {:?}",
                c["name"],
                got.notes
            );
            if let Some(expected) = c["verificationLevel"].as_str() {
                let actual = match got.verification_level {
                    VerificationLevel::Invalid => "INVALID",
                    VerificationLevel::CommitmentVerified => "COMMITMENT_VERIFIED",
                    VerificationLevel::ContentVerified => "CONTENT_VERIFIED",
                    VerificationLevel::SignatureVerified => "SIGNATURE_VERIFIED",
                    VerificationLevel::FullyVerified => "FULLY_VERIFIED",
                };
                assert_eq!(actual, expected, "{}", c["name"]);
            }
            if let Some(properties) = c["properties"].as_object() {
                for (key, expected) in properties {
                    let actual = match key.as_str() {
                        "commitmentVerified" => got.properties.commitment_verified,
                        "contentVerified" => got.properties.content_verified,
                        "signatureVerified" => got.properties.signature_verified,
                        "anchorVerified" => got.properties.anchor_verified,
                        _ => panic!("unknown property {key}"),
                    };
                    assert_eq!(actual, expected.as_bool().unwrap(), "{}:{key}", c["name"]);
                }
            }
        }
    }
}

/// Extended entry point. Anchor quorum evaluation is performed per checkpoint when a policy and
/// resolver are supplied; the legacy function above remains available for Core Profile callers.
pub fn verify_evidence_bundle_with_options<F: Fn(&SignedAnchor) -> Option<String>>(
    b: &EvidenceBundle,
    o: &EvidenceVerifyOptions<F>,
) -> EvidenceVerification {
    let mut r = verify_evidence_bundle(b, o.trusted_roots);
    let mut by_root = std::collections::BTreeMap::<String, Vec<SignedAnchor>>::new();
    let mut checkpoint_key_to_root = std::collections::BTreeMap::<String, String>::new();
    for cp in &b.checkpoints {
        by_root.insert(cp.root.clone(), cp.anchors.clone());
        if let Some(id) = &cp.id {
            checkpoint_key_to_root.insert(id.clone(), cp.root.clone());
        }
    }
    // A root key wins over a colliding checkpoint id, matching the reference implementation.
    for cp in &b.checkpoints {
        checkpoint_key_to_root.insert(cp.root.clone(), cp.root.clone());
    }
    let known_roots = by_root
        .keys()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    let mut caller_anchors = Vec::new();
    let mut caller_by_root = std::collections::BTreeMap::<String, Vec<SignedAnchor>>::new();
    let mut caller_keyed = false;
    let mut unattributed_keys = false;
    if let Some(anchors) = &o.anchors {
        match anchors {
            EvidenceAnchorSet::Flat(list) => caller_anchors.extend(list.iter().cloned()),
            EvidenceAnchorSet::ByCheckpoint(keyed) => {
                caller_keyed = true;
                for (key, list) in keyed {
                    caller_anchors.extend(list.iter().cloned());
                    if let Some(root) = checkpoint_key_to_root.get(key) {
                        caller_by_root
                            .entry(root.clone())
                            .or_default()
                            .extend(list.iter().cloned());
                    } else if !list.is_empty() {
                        unattributed_keys = true;
                    }
                }
            }
        }
    }
    if let (Some(policy), Some(resolve)) = (&o.anchor_policy, o.resolve_anchor_key) {
        for root in by_root.keys() {
            let candidates = if caller_anchors.is_empty() {
                by_root.get(root).map(Vec::as_slice).unwrap_or(&[])
            } else {
                caller_anchors.as_slice()
            };
            let flat_divergence;
            let divergence = if caller_keyed {
                caller_by_root.get(root).map(Vec::as_slice).unwrap_or(&[])
            } else {
                flat_divergence = caller_anchors
                    .iter()
                    .filter(|a| a.daily_root == *root || !known_roots.contains(&a.daily_root))
                    .cloned()
                    .collect::<Vec<_>>();
                flat_divergence.as_slice()
            };
            let q = ledger::verify_anchor_quorum(
                candidates,
                root,
                policy,
                resolve,
                divergence,
                &o.external_keys,
            );
            if let Some(x) = r.roots.iter_mut().find(|x| &x.root == root) {
                x.anchor_verified = Some(q.ok);
                x.verified_issuers = q.verified_issuers.clone();
            }
            if q.divergence {
                r.failed.push((
                    "-".into(),
                    q.reason.unwrap_or_else(|| "anchor divergence".into()),
                ));
            } else if !q.ok {
                r.notes
                    .push(q.reason.unwrap_or_else(|| "anchor quorum not met".into()));
            }
        }
    }
    if caller_keyed && unattributed_keys {
        r.notes.push("Some supplied anchors are keyed to a checkpoint id/root this bundle does not contain; they can count toward quorum but cannot establish divergence.".into());
    }
    if !caller_keyed && !caller_anchors.is_empty() && known_roots.len() > 1 {
        r.notes.push("Caller anchors were supplied as one flat list for a multi-checkpoint bundle; use EvidenceAnchorSet::ByCheckpoint for per-checkpoint divergence attribution.".into());
    }
    let trusted = o.trusted_roots.is_some();
    r.ok = r.failed.is_empty()
        && !b.entries.is_empty()
        && trusted
        && o.anchor_policy.as_ref().map_or(true, |_| {
            r.roots.iter().all(|x| x.anchor_verified == Some(true))
        });
    r
}
