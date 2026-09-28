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
    #[serde(default)]
    pub version: Value,
    #[serde(default, deserialize_with = "present_registry")]
    pub algorithm_registry: Option<Value>,
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
    /// "caller-supplied", "self-asserted" or "none". A supplied root is never labelled "independent":
    /// the verifier cannot tell one recorded independently from one copied out of the bundle.
    pub root_source: &'static str,
    /// Authenticated external witness time per anchor issuer (Unix seconds).
    pub witness_times: std::collections::BTreeMap<String, i64>,
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
    /// The caller's record of the proof's checkpoint (its roots-file line). A single proof carries no
    /// checkpoint, so without it no EXTERNAL anchor counts: the §5.3 time bound would be measured
    /// against the anchor's own producer-chosen timestamp. Its root stands in for `trusted_root` when
    /// that is absent and must equal it otherwise; its entry count bounds the proof's leaf counts.
    pub trusted_checkpoint: Option<ledger::TrustedCheckpoint>,
}
impl<'a, F: Fn(&SignedAnchor) -> Option<String>> Default for BundleVerifyOptions<'a, F> {
    fn default() -> Self {
        Self {
            trusted_root: None,
            anchors: None,
            anchor_policy: None,
            resolve_anchor_key: None,
            external_keys: ExternalAnchorKeys::default(),
            trusted_checkpoint: None,
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
    let kind_ok = b.kind == BUNDLE_KIND && supported_envelope(b.protocol.as_deref(), &b.version, b.algorithm_registry.as_ref());
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
    let tc = o.trusted_checkpoint.as_ref();
    let conflict = matches!((tc, &o.trusted_root), (Some(t), Some(r)) if &t.root != r);
    if conflict {
        notes.push("The supplied trusted checkpoint names a different root than the trusted root; refusing to pick one.".into());
    }
    let caller_root = o.trusted_root.clone().or_else(|| tc.map(|t| t.root.clone()));
    let (root, source) = if let Some(r) = &caller_root {
        (Some(r.clone()), "caller-supplied")
    } else if self_root.is_some() {
        notes.push("No root supplied — internal consistency only; use a root obtained earlier or from the published roots file.".into());
        (self_root, "self-asserted")
    } else {
        (None, "none")
    };
    // DEWP §17.3: the proof's own leaf counts are bound to the trusted checkpoint's entry count.
    let count_mismatch = match (tc, root.as_deref()) {
        (Some(t), Some(r)) if t.root == r => ledger::leaf_count_mismatch(
            b.proof.block_leaf_count,
            b.proof.checkpoint_leaf_count,
            t.entry_count,
        ),
        _ => None,
    };
    if let Some(m) = &count_mismatch {
        notes.push(m.clone());
    }
    let inc = root.as_ref().map(|r| count_mismatch.is_none() && b.proof.verify(r));
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
    let mut witness_times = std::collections::BTreeMap::new();
    if let (Some(policy), Some(r)) = (&o.anchor_policy, root.as_deref()) {
        let candidates = o.anchors.clone().unwrap_or_else(|| {
            let mut a = b.anchors.clone();
            if let Some(x) = &b.anchor {
                a.push(x.clone())
            }
            a
        });
        let div = o.anchors.as_deref().unwrap_or(&[]);
        let resolve = |a: &SignedAnchor| o.resolve_anchor_key.and_then(|f| f(a));
        // The caller's record is the only position and time an anchor over a single proof can be held
        // to; an empty expectation keeps external witnesses from counting without one.
        let expected = tc
            .map(|t| ledger::ExpectedCheckpoint {
                seq_start: t.seq_start.clone(),
                seq_end: t.seq_end.clone(),
                chain_hash: t.chain_hash.clone(),
                anchored_at: t.anchored_at.clone(),
            })
            .unwrap_or_default();
        let q = ledger::verify_anchor_quorum_for(
            &candidates,
            r,
            policy,
            &resolve,
            div,
            &o.external_keys,
            Some(&expected),
        );
        anchor_verified = commitment && q.ok;
        divergence = q.divergence;
        witness_times = q.witness_times.clone();
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
        && !conflict
        && source == "caller-supplied"
        && commitment
        && leaf != Some(false)
        && header != Some(false)
        && (!b.event.canonical.is_some() || leaf == Some(true));
    let ok = base && !divergence && (o.anchor_policy.is_none() || anchor_verified);
    BundleVerification {
        ok,
        daily_root: root,
        root_source: source,
        witness_times,
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
    #[serde(default)]
    pub anchored_at: Option<String>,
    /// §5.4 chain fields: every anchor binds `chain_hash` (§5.2), and the verifier recomputes it.
    #[serde(default)]
    pub entry_count: Option<u64>,
    #[serde(default)]
    pub prev_chain_hash: Option<String>,
    #[serde(default)]
    pub chain_hash: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceBundle {
    pub kind: String,
    #[serde(default)]
    pub version: Value,
    #[serde(default)]
    pub protocol: Option<String>,
    #[serde(default, deserialize_with = "present_registry")]
    pub algorithm_registry: Option<Value>,
    #[serde(default)]
    pub profile: Option<String>,
    /// Absent or with a null `id`, any entry that names a tenant is refused (DEWP §7.2).
    #[serde(default)]
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
    /// Checkpoint records YOU hold (chain-verified roots-file lines, DEWP §5.4.1). Their roots are
    /// trusted roots; a bundle checkpoint over one must agree with it on every field both state, and
    /// anchors are held to the record's range, chain hash and time (§5.3).
    pub trusted_checkpoints: Option<&'a [ledger::TrustedCheckpoint]>,
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
    /// Authenticated external witness time per issuer (Unix seconds).
    pub witness_times: std::collections::BTreeMap<String, i64>,
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
    verify_evidence_entries(b, trusted_roots, None)
}

/// The position and time anchors over a checkpoint are held to — the caller's record where it states
/// a field, the bundle's checkpoint otherwise — and the entry count that bounds its proofs.
fn effective_checkpoint(
    c: Option<&EvidenceCheckpoint>,
    t: Option<&ledger::TrustedCheckpoint>,
) -> (ledger::ExpectedCheckpoint, Option<u64>) {
    let pick = |held: Option<&Option<String>>, shown: Option<&Option<String>>| {
        held.cloned().flatten().or_else(|| shown.cloned().flatten())
    };
    (
        ledger::ExpectedCheckpoint {
            seq_start: pick(t.map(|t| &t.seq_start), c.map(|c| &c.seq_start)),
            seq_end: pick(t.map(|t| &t.seq_end), c.map(|c| &c.seq_end)),
            chain_hash: pick(t.map(|t| &t.chain_hash), c.map(|c| &c.chain_hash)),
            anchored_at: pick(t.map(|t| &t.anchored_at), c.map(|c| &c.anchored_at)),
        },
        t.and_then(|t| t.entry_count).or_else(|| c.and_then(|c| c.entry_count)),
    )
}

fn verify_evidence_entries(
    b: &EvidenceBundle,
    trusted_roots: Option<&[String]>,
    trusted_checkpoints: Option<&[ledger::TrustedCheckpoint]>,
) -> EvidenceVerification {
    let mut r = EvidenceVerification {
        total: b.entries.len(),
        ..Default::default()
    };
    if b.kind != EVIDENCE_BUNDLE_KIND || !supported_envelope(b.protocol.as_deref(), &b.version, b.algorithm_registry.as_ref()) {
        r.failed.push(("-".into(), "refusing bundle kind".into()))
    }
    // §5.4 chain fields, where carried: the chain hash every anchor binds must recompute.
    for c in &b.checkpoints {
        let Some(claimed) = &c.chain_hash else { continue };
        let id = c.id.as_deref().unwrap_or("?");
        match (&c.prev_chain_hash, &c.anchored_at, c.entry_count, &c.seq_start, &c.seq_end) {
            (Some(prev), Some(at), Some(count), Some(start), Some(end)) => {
                let recomputed = crate::chain::chain_hash(&crate::chain::ChainInput {
                    prev_chain_hash: prev.clone(),
                    root: c.root.clone(),
                    seq_start: start.clone(),
                    seq_end: end.clone(),
                    entry_count: count,
                    anchored_at: at.clone(),
                });
                if &recomputed != claimed {
                    r.failed.push(("-".into(), format!("checkpoint {id} chainHash does not recompute")));
                }
            }
            _ => r.failed.push(("-".into(), format!("checkpoint {id} chainHash lacks the fields it commits to"))),
        }
    }
    let mut records = std::collections::BTreeMap::<&str, &ledger::TrustedCheckpoint>::new();
    for t in trusted_checkpoints.unwrap_or(&[]) {
        records.entry(t.root.as_str()).or_insert(t);
    }
    // A checkpoint the caller holds a record for must agree with it on every field both state: a
    // re-dated anchoredAt with a self-consistent chain over a made-up predecessor recomputes above.
    for c in &b.checkpoints {
        let Some(t) = records.get(c.root.as_str()) else { continue };
        let differs = |shown: &Option<String>, held: &Option<String>| matches!((shown, held), (Some(s), Some(h)) if s != h);
        let id = c.id.as_deref().unwrap_or("?");
        for (field, bad) in [
            ("seqStart", differs(&c.seq_start, &t.seq_start)),
            ("seqEnd", differs(&c.seq_end, &t.seq_end)),
            ("entryCount", matches!((c.entry_count, t.entry_count), (Some(s), Some(h)) if s != h)),
            ("anchoredAt", differs(&c.anchored_at, &t.anchored_at)),
            ("chainHash", differs(&c.chain_hash, &t.chain_hash)),
        ] {
            if bad {
                r.failed.push(("-".into(), format!("checkpoint {id} {field} contradicts your trusted checkpoint record for its root")));
            }
        }
    }
    let roots = b
        .checkpoints
        .iter()
        .map(|c| c.root.as_str())
        .collect::<std::collections::HashSet<_>>();
    let trusted = (trusted_roots.is_some() || trusted_checkpoints.is_some()).then(|| {
        trusted_roots
            .unwrap_or(&[])
            .iter()
            .map(String::as_str)
            .chain(records.keys().copied())
            .collect::<std::collections::HashSet<_>>()
    });
    let unknown_profile = b.profile.as_deref().is_some_and(|p| p != AUDIT_PROFILE);
    let bundle_tenant = b.tenant.get("id").and_then(Value::as_str);
    let mut seen_leaves = std::collections::HashSet::<&str>::new();
    let mut seen_seqs = std::collections::HashSet::<&str>::new();
    let mut block_counts = std::collections::HashMap::<&str, usize>::new();
    let mut checkpoint_counts = std::collections::HashMap::<&str, usize>::new();
    for e in &b.entries {
        // One committed event appears once; a genuine leaf used twice can otherwise fill two holes.
        if !seen_leaves.insert(e.proof.leaf.as_str()) | !seen_seqs.insert(e.event.seq.as_str()) {
            r.failed.push((
                e.event.seq.clone(),
                "duplicate entry: this leaf or seq already appears in the bundle".into(),
            ));
            continue;
        }
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
        // DEWP §17.3: leaf counts are prover-supplied; bind them to each other and to the entry count.
        let inconsistent = block_counts
            .get(e.proof.block_root.as_str())
            .is_some_and(|n| *n != e.proof.block_leaf_count)
            || checkpoint_counts
                .get(root)
                .is_some_and(|n| *n != e.proof.checkpoint_leaf_count);
        let (_, entry_count) = effective_checkpoint(
            b.checkpoints.iter().find(|c| c.root == root),
            records.get(root).copied(),
        );
        let count_bad = if inconsistent {
            Some("proofs into the same block or checkpoint disagree on its leaf count".to_string())
        } else {
            ledger::leaf_count_mismatch(e.proof.block_leaf_count, e.proof.checkpoint_leaf_count, entry_count)
        };
        if let Some(reason) = count_bad {
            r.failed.push((e.event.seq.clone(), reason));
            continue;
        }
        block_counts.insert(e.proof.block_root.as_str(), e.proof.block_leaf_count);
        checkpoint_counts.insert(root, e.proof.checkpoint_leaf_count);
        if let Some(c) = &e.event.canonical {
            if unknown_profile {
                // A preimage cannot be bound under a layout this verifier does not implement, and
                // passing it would let the producer switch leaf binding off (DEWP §4.5/§7.2 rule 1).
                r.failed.push((
                    e.event.seq.clone(),
                    "canonical preimage under an unknown profile cannot be bound to its leaf".into(),
                ));
                continue;
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
                // The redaction record is unsigned and is no counter source where a preimage exists.
                let redaction_seq = e
                    .event
                    .redaction
                    .as_ref()
                    .and_then(|x| x.commitment.as_ref())
                    .and_then(|x| x.tenant_seq.as_ref());
                if mismatch("tenantSeq", redaction_seq) {
                    r.failed.push((
                        e.event.seq.clone(),
                        "redaction record tenantSeq does not match the committed value".into(),
                    ));
                    continue;
                }
                // A bundle naming no tenant has none for a tenant-bound entry to belong to.
                if let Some(entry_tenant) = c.get("tenantId").and_then(Value::as_str) {
                    if Some(entry_tenant) != bundle_tenant {
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
    // An entry WITH a preimage reads its counter from it alone — null there means no counter
    // (§7.2 rule 5); only an entry without one falls back to the unsigned redaction record and the
    // display copy (rule 2).
    let mut first: Option<i128> = None;
    let mut last: Option<i128> = None;
    let mut saw_uncounted = false;
    let mut saw_unbound = false;
    for e in &b.entries {
        let raw = match &e.event.canonical {
            // Not leaf-bound under an unknown profile; that entry already failed above.
            Some(_) if unknown_profile => continue,
            Some(c) => c.get("tenantSeq").and_then(Value::as_str),
            None => {
                let fallback = e
                    .event
                    .redaction
                    .as_ref()
                    .and_then(|x| x.commitment.as_ref())
                    .and_then(|x| x.tenant_seq.as_deref())
                    .or(e.event.tenant_seq.as_deref());
                saw_unbound |= fallback.is_some();
                fallback
            }
        };
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
    if unknown_profile {
        r.notes.push("Unknown canonical profile; content cannot be bound to its leaf, so an entry carrying a preimage fails.".into());
    }
    if saw_uncounted {
        r.notes.push("Some entries carry no tenantSeq, so gapless completeness could not be checked across them.".into());
    }
    if saw_unbound {
        r.notes.push("Some entries carry no canonical preimage (COMMITMENT_ONLY), so their tenantSeq was read from the redaction record or display copy and is NOT covered by the Merkle leaf.".into());
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
            witness_times: std::collections::BTreeMap::new(),
        })
        .collect();
    r.ok = r.failed.is_empty() && !b.entries.is_empty() && trusted.is_some();
    r
}

#[cfg(test)]
mod parity_tests {
    use super::*;
    use crate::chain::{verify_roots_chain, RootsChainEntry};
    use crate::rfc3161::Rfc3161Trust;

    fn key_spki(keys: &Value, id: &str) -> Option<String> {
        keys.as_array()
            .unwrap()
            .iter()
            .find(|k| k["id"].as_str() == Some(id))
            .and_then(|k| k["spkiB64"].as_str())
            .map(str::to_owned)
    }
    fn policy_from(p: &Value) -> AnchorPolicy {
        AnchorPolicy {
            required_anchors: p["requiredAnchors"].as_u64().unwrap() as usize,
            trusted_issuers: serde_json::from_value(p["trustedIssuers"].clone()).unwrap(),
            quorum: if p["quorum"] == "ALL_MUST_AGREE" {
                ledger::AnchorQuorum::AllMustAgree
            } else {
                ledger::AnchorQuorum::NOfM
            },
            max_anchor_lag_seconds: p["maxAnchorLagSeconds"].as_i64(),
        }
    }
    fn external_from(options: &Value, keys: &Value) -> ExternalAnchorKeys {
        ExternalAnchorKeys {
            rekor: options["rekorKeyId"].as_str().and_then(|id| key_spki(keys, id)),
            rekor_issuer: options["rekorIssuer"].as_str().map(str::to_owned),
            rekor_submitter_keys: options["rekorSubmitterKeyIds"]
                .as_array()
                .map(|ids| ids.iter().filter_map(|id| id.as_str().and_then(|id| key_spki(keys, id))).collect())
                .unwrap_or_default(),
            ..Default::default()
        }
    }

    fn run_evidence_cases(cases: &Value, keys: &Value) {
        for c in cases.as_array().unwrap() {
            let b: EvidenceBundle = serde_json::from_value(c["bundle"].clone()).unwrap();
            let roots: Option<Vec<String>> = c["options"]["trustedRoots"]
                .as_array()
                .map(|a| a.iter().filter_map(Value::as_str).map(str::to_owned).collect());
            let records: Option<Vec<ledger::TrustedCheckpoint>> = c["options"]
                .get("trustedCheckpoints")
                .map(|v| serde_json::from_value(v.clone()).unwrap());
            let resolver = |a: &SignedAnchor| key_spki(keys, &a.key_id);
            let anchors = c["options"].get("anchors").map(|a| {
                if a.is_array() {
                    EvidenceAnchorSet::Flat(serde_json::from_value(a.clone()).unwrap())
                } else {
                    EvidenceAnchorSet::ByCheckpoint(serde_json::from_value(a.clone()).unwrap())
                }
            });
            let opts = EvidenceVerifyOptions {
                trusted_roots: roots.as_deref(),
                anchors,
                anchor_policy: c.get("policy").map(policy_from),
                resolve_anchor_key: Some(&resolver),
                external_keys: external_from(&c["options"], keys),
                trusted_checkpoints: records.as_deref(),
            };
            let got = verify_evidence_bundle_with_options(&b, &opts);
            assert_eq!(got.ok, c["ok"].as_bool().unwrap(), "evidence {}: {:?} {:?}", c["name"], got.failed, got.notes);
            if let Some(n) = c.get("total").and_then(Value::as_u64) {
                assert_eq!(got.total, n as usize, "{}", c["name"]);
            }
            if let Some(n) = c.get("contentVerified").and_then(Value::as_u64) {
                assert_eq!(got.content_verified, n as usize, "{}", c["name"]);
            }
            if let Some(n) = c.get("commitmentOnly").and_then(Value::as_u64) {
                assert_eq!(got.commitment_only, n as usize, "{}", c["name"]);
            }
        }
    }

    /// `default_policy` is the `bundles` section's; the hardening section applies a policy only when a
    /// case carries one.
    fn run_bundle_cases(cases: &Value, keys: &Value, default_policy: Option<&Value>) {
        for c in cases.as_array().unwrap() {
            let b: ProofBundle = serde_json::from_value(c["bundle"].clone()).unwrap();
            let resolver = |a: &SignedAnchor| key_spki(keys, &a.key_id);
            let o = BundleVerifyOptions {
                trusted_root: c["options"]["trustedRoot"].as_str().map(str::to_owned),
                anchors: c["options"]
                    .get("divergenceAnchors")
                    .map(|a| serde_json::from_value(a.clone()).unwrap()),
                anchor_policy: c.get("policy").or(default_policy).map(policy_from),
                resolve_anchor_key: Some(&resolver),
                external_keys: external_from(&c["options"], keys),
                trusted_checkpoint: c["options"]
                    .get("trustedCheckpoint")
                    .map(|v| serde_json::from_value(v.clone()).unwrap()),
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
            if let Some(want) = c["witnessTimes"].as_object() {
                let want: std::collections::BTreeMap<String, i64> =
                    want.iter().map(|(k, v)| (k.clone(), v.as_i64().unwrap())).collect();
                assert_eq!(got.witness_times, want, "bundle {} witnessTimes", c["name"]);
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
            "dewpEvidenceHardening",
        ] {
            assert!(v.get(key).is_some(), "missing parity section {key}");
        }
        run_evidence_cases(&v["evidence"]["cases"], &v["keys"]);
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
        run_bundle_cases(&v["bundles"]["cases"], &v["keys"], Some(&v["bundles"]["anchorPolicy"]));
        // The DEWP evidence-hardening section carries its own keys.
        let h = &v["dewpEvidenceHardening"];
        assert!(!h["bundles"]["cases"].as_array().unwrap().is_empty());
        assert!(!h["evidence"]["cases"].as_array().unwrap().is_empty());
        run_bundle_cases(&h["bundles"]["cases"], &h["keys"], None);
        run_evidence_cases(&h["evidence"]["cases"], &h["keys"]);
        // Verifier input hardening (2026-09-27 review I8): RSA-PSS profile and divergence
        // admission. Own keys; its receipt sub-sections run in parity_receipts_test.rs.
        let ih = &v["verifierInputHardening"];
        assert!(!ih["bundles"]["cases"].as_array().unwrap().is_empty());
        run_bundle_cases(&ih["bundles"]["cases"], &ih["keys"], None);
    }

    #[test]
    fn external_rfc3161_trust_does_not_require_self_key_resolver() {
        let parity: Value = serde_json::from_str(include_str!("../vectors/verifier-parity-vectors.json")).unwrap();
        let rfc: Value = serde_json::from_str(include_str!("../vectors/rfc3161-vectors.json")).unwrap();
        let mut anchor: SignedAnchor = serde_json::from_value(rfc["cases"][2]["anchor"].clone()).unwrap();
        let trust: Rfc3161Trust = serde_json::from_value(rfc["cases"][0]["trust"].clone()).unwrap();
        let issuer=anchor.issuer.clone();let policy=AnchorPolicy{required_anchors:1,trusted_issuers:vec![issuer.clone()],quorum:ledger::AnchorQuorum::NOfM,max_anchor_lag_seconds:None};
        let mut external=ExternalAnchorKeys::default();external.rfc3161.insert(issuer,trust);

        let bundle:ProofBundle=serde_json::from_value(parity["bundles"]["cases"][0]["bundle"].clone()).unwrap();
        anchor.daily_root=bundle.proof.checkpoint_root.clone().unwrap();
        let options:BundleVerifyOptions<'_,fn(&SignedAnchor)->Option<String>>=BundleVerifyOptions{trusted_root:Some(anchor.daily_root.clone()),anchors:Some(vec![anchor.clone()]),anchor_policy:Some(policy.clone()),resolve_anchor_key:None,external_keys:external.clone(),trusted_checkpoint:None};
        let got=verify_bundle(&bundle,&options);assert!(got.notes.iter().any(|n|n.contains("not verified")),"{:?}",got.notes);

        let evidence:EvidenceBundle=serde_json::from_value(parity["evidence"]["cases"][0]["bundle"].clone()).unwrap();
        let roots=evidence.checkpoints.iter().map(|c|c.root.clone()).collect::<Vec<_>>();anchor.daily_root=roots[0].clone();
        // Hold the (tampered) TSA anchor to this checkpoint's position so it is the token, not the
        // position, that fails — the note under test is about unverifiable evidence.
        let cp=&evidence.checkpoints[0];anchor.seq_start=cp.seq_start.clone().unwrap();anchor.seq_end=cp.seq_end.clone().unwrap();anchor.chain_hash=cp.chain_hash.clone().unwrap();anchor.timestamp=cp.anchored_at.clone().unwrap();
        let options:EvidenceVerifyOptions<'_,fn(&SignedAnchor)->Option<String>>=EvidenceVerifyOptions{trusted_roots:Some(&roots),anchors:Some(EvidenceAnchorSet::Flat(vec![anchor])),anchor_policy:Some(policy),resolve_anchor_key:None,external_keys:external,trusted_checkpoints:None};
        let got=verify_evidence_bundle_with_options(&evidence,&options);assert!(got.notes.iter().any(|n|n.contains("not verified")),"{:?}",got.notes);
    }
}

/// Extended entry point. Anchor quorum evaluation is performed per checkpoint when a policy is
/// supplied. The key resolver is optional when all relevant anchors use configured external trust.
pub fn verify_evidence_bundle_with_options<F: Fn(&SignedAnchor) -> Option<String>>(
    b: &EvidenceBundle,
    o: &EvidenceVerifyOptions<F>,
) -> EvidenceVerification {
    let mut r = verify_evidence_entries(b, o.trusted_roots, o.trusted_checkpoints);
    let mut by_root = std::collections::BTreeMap::<String, Vec<SignedAnchor>>::new();
    let mut expected_by_root = std::collections::BTreeMap::<String, ledger::ExpectedCheckpoint>::new();
    let mut checkpoint_key_to_root = std::collections::BTreeMap::<String, String>::new();
    for cp in &b.checkpoints {
        by_root.insert(cp.root.clone(), cp.anchors.clone());
        // Anchors are held to the caller's record where it states a field (DEWP §5.3).
        let record = o.trusted_checkpoints.and_then(|x| x.iter().find(|t| t.root == cp.root));
        expected_by_root.insert(cp.root.clone(), effective_checkpoint(Some(cp), record).0);
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
    if let Some(policy) = &o.anchor_policy {
        let resolve = |a: &SignedAnchor| o.resolve_anchor_key.and_then(|f| f(a));
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
            let q = ledger::verify_anchor_quorum_for(
                candidates,
                root,
                policy,
                &resolve,
                divergence,
                &o.external_keys,
                expected_by_root.get(root),
            );
            // §5.3/§6.3: a checkpoint stating no chain hash or time (and no record supplying them)
            // cannot hold its anchors to anything, so it never counts as anchored.
            let position_unknown = expected_by_root
                .get(root)
                .map_or(true, |e| e.chain_hash.is_none() || e.anchored_at.is_none());
            if position_unknown {
                r.notes.push(format!("checkpoint for root {root} carries no chainHash/anchoredAt and no trusted checkpoint record supplies them; its anchors cannot be held to a position and time (DEWP §5.3), so it is not anchored"));
            }
            if let Some(x) = r.roots.iter_mut().find(|x| &x.root == root) {
                x.anchor_verified = Some(q.ok && !position_unknown);
                x.verified_issuers = if position_unknown { Vec::new() } else { q.verified_issuers.clone() };
                x.witness_times = q.witness_times.clone();
            }
            if let Some(note) = q.note.clone() {
                r.notes.push(note);
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
    let trusted = o.trusted_roots.is_some() || o.trusted_checkpoints.is_some();
    r.ok = r.failed.is_empty()
        && !b.entries.is_empty()
        && trusted
        && o.anchor_policy.as_ref().map_or(true, |_| {
            r.roots.iter().all(|x| x.anchor_verified == Some(true))
        });
    r
}

// DEWP §7/§12: only numeric revisions 1 and 2 without a protocol is a legacy export.
fn supported_envelope(protocol: Option<&str>, version: &Value, registry: Option<&Value>) -> bool {
    if protocol.is_some() && protocol != Some("DEWP") { return false; }
    if version.as_str() != Some("1.0") && !(protocol.is_none() && matches!(version.as_f64(), Some(1.0 | 2.0))) { return false; }
    registry.map_or(true, |a| a["hashAlgorithm"] == "SHA-256" && a["serialization"] == "RFC8785-JCS" && a["merkleVersion"].as_f64() == Some(1.0))
}

fn present_registry<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<Value>, D::Error> {
    Value::deserialize(d).map(Some)
}
