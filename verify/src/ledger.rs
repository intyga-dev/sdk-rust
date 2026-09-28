//! DEWP audit-ledger verification (docs/DEWP.md) — Rust port.
//!
//! Byte-identical to `@intyga/verify` (ledger-*.ts) and the Go/Python ports, locked by the shared
//! vectors (packages/mcp-schemas/vectors/ledger-vectors.json).
//!
//! Domain separation: 0x00 leaf, 0x01 node, 0x02 empty root, 0x03 anchor. Node children are hex-decoded
//! to raw bytes before hashing; the leaf `metadata` element is an RFC 8785 JCS string, serialized by
//! [`jcs_stringify`] with keys sorted by UTF-16 code units. (serde_json's BTreeMap `to_string` was
//! used here before and is NOT JCS: it sorts by UTF-8/code points, which diverges on non-BMP keys.)

use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn from_hex(s: &str) -> Vec<u8> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut i = 0;
    while i + 1 < bytes.len() {
        let hi = (bytes[i] as char).to_digit(16);
        let lo = (bytes[i + 1] as char).to_digit(16);
        match (hi, lo) {
            (Some(h), Some(l)) => out.push(((h << 4) | l) as u8),
            _ => break,
        }
        i += 2;
    }
    out
}

fn sha256_hex_bytes(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    to_hex(&h.finalize())
}

/// sha256(0x00 || UTF8(preimage)).
pub fn hash_leaf(preimage: &str) -> String {
    let mut buf = vec![0x00u8];
    buf.extend_from_slice(preimage.as_bytes());
    sha256_hex_bytes(&buf)
}

/// sha256(0x01 || rawBytes(left) || rawBytes(right)). Order encodes position.
pub fn hash_pair(left_hex: &str, right_hex: &str) -> String {
    let mut buf = vec![0x01u8];
    buf.extend_from_slice(&from_hex(left_hex));
    buf.extend_from_slice(&from_hex(right_hex));
    sha256_hex_bytes(&buf)
}

/// sha256(0x02) (DEWP §5.1.1).
pub fn empty_root() -> String {
    sha256_hex_bytes(&[0x02u8])
}

/// Merkle root over ordered leaves (duplicate-last on odd levels). Empty ⇒ empty_root().
pub fn merkle_root(leaves: &[String]) -> String {
    if leaves.is_empty() {
        return empty_root();
    }
    let mut level: Vec<String> = leaves.to_vec();
    while level.len() > 1 {
        let mut next: Vec<String> = Vec::with_capacity((level.len() + 1) / 2);
        let mut i = 0;
        while i < level.len() {
            let left = &level[i];
            let right = if i + 1 < level.len() {
                &level[i + 1]
            } else {
                left
            };
            next.push(hash_pair(left, right));
            i += 2;
        }
        level = next;
    }
    level[0].clone()
}

/// One leaf→root Merkle path step (DEWP §5.1.6).
pub struct ProofStep {
    pub sibling_hash: String,
    pub sibling_position: String, // "LEFT" | "RIGHT"
}

/// The leaf's position and its tree's leaf count. REQUIRED, per DEWP §3 invariant 3 ("The bounds
/// are REQUIRED, not advisory") and §11.1.
#[derive(Debug, Clone, Copy)]
pub struct ProofBounds {
    pub index: usize,
    pub leaf_count: usize,
}

/// Audit-path length for a duplicate-last tree of `leaf_count` leaves: ceil(log2(n)), 0 when n <= 1.
pub fn expected_path_length(leaf_count: usize) -> usize {
    if leaf_count <= 1 {
        return 0;
    }
    let mut n = 0usize;
    let mut size = leaf_count;
    while size > 1 {
        size = size.div_ceil(2);
        n += 1;
    }
    n
}

/// True when `s` is exactly 64 lowercase hex characters (DEWP §4.4). `from_hex` silently stops at
/// the first bad nibble and drops a trailing odd one, so distinct proof strings could otherwise
/// decode to the same bytes.
fn is_hash64(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

/// Recompute the root from a leaf + its leaf→root proof, bounded by the leaf's position
/// (DEWP §11.2 reference implementation).
///
/// Bounds are what make this a proof of MEMBERSHIP rather than a proof that A path exists. This tree
/// pads an unpaired trailing node by hashing it against ITSELF, so merkle_root([a,b,c]) equals
/// merkle_root([a,b,c,c]) and a path built for the nonexistent index 3 recomputes the 3-leaf root
/// exactly. DEWP §11.1 states outright that an implementation stopping at root recomputation is
/// non-conformant — this port did exactly that, and its own golden vector encoded the gap.
pub fn verify_merkle_proof(
    leaf: &str,
    proof: &[ProofStep],
    root: &str,
    bounds: ProofBounds,
) -> bool {
    if !is_hash64(leaf) || !is_hash64(root) {
        return false;
    }
    if bounds.leaf_count < 1 || bounds.index >= bounds.leaf_count {
        return false;
    }
    if proof.len() != expected_path_length(bounds.leaf_count) {
        return false;
    }
    let mut idx = bounds.index;
    let mut level_size = bounds.leaf_count;
    let mut node = leaf.to_string();
    for step in proof {
        if !is_hash64(&step.sibling_hash) {
            return false;
        }
        // The side follows from the index; a prover-chosen side would restore the flexibility the
        // length check just removed.
        let expected_side = if idx % 2 == 1 { "LEFT" } else { "RIGHT" };
        if step.sibling_position != expected_side {
            return false;
        }
        // Self-pairing is legitimate ONLY at the unpaired end of an odd-sized level. Anywhere else
        // it is the signature of an index pointing into padding — the check that actually closes the
        // forgery, since leaf_count arrives inside the proof and a prover can inflate it.
        let self_paired = step.sibling_hash == node;
        let legitimately_unpaired = idx == level_size - 1 && level_size % 2 == 1;
        if self_paired && !legitimately_unpaired {
            return false;
        }
        node = if step.sibling_position == "LEFT" {
            hash_pair(&step.sibling_hash, &node)
        } else {
            hash_pair(&node, &step.sibling_hash)
        };
        idx /= 2;
        level_size = level_size.div_ceil(2);
    }
    node == root
}

/// Read a leaf-row field as a JSON Value (String or Null), from the DEWP intyga.v1 profile row.
fn field<'a>(row: &'a Value, key: &str) -> Value {
    row.get(key).cloned().unwrap_or(Value::Null)
}

/// RFC 8785 JCS stringify for the leaf `metadata` element (DEWP §4.2 index 5): keys sorted
/// recursively by **UTF-16 code units** (RFC 8785 §3.2.3 — the surrogate-pair emoji U+1F600 sorts
/// BEFORE U+FFFD, exactly where serde_json's BTreeMap UTF-8/code-point order diverges), and numbers
/// printed as ES6 `Number::toString` where one portable form exists: whole-valued floats fold to
/// integer text (`100.0` → `"100"`, `-0.0` → `"0"`), matching `JSON.stringify` and the TS reference
/// (`jcsStringify` in ledger-leaf.ts), pinned cross-port by the `metadata-utf16-key-order` vector.
///
/// DELIBERATELY different from lib.rs's `stable_stringify` in one way: NO portability refusal. The
/// TS reference has no guard here, and a verifier that throws on a leaf it should merely fail to
/// match is wrong — the caller needs "hash differs", not a crash.
///
/// The producer refuses to COMMIT a number outside the portable range (`assertPortableJson` in
/// packages/db), so an Intyga-issued leaf never carries one. This function still has to agree with
/// the TS reference on values a third-party or legacy producer may have committed. Below 2^53 it
/// does exactly: every integral double's exact expansion IS the shortest round trip. `f as i64`
/// cannot be used for the whole range — it saturates above i64::MAX (≈9.2e18) — hence the
/// fixed-precision format.
///
/// Residuals, bounded and stated: in (2^53, 1e21) `{:.0}` prints the double's EXACT decimal
/// expansion while ES prints the SHORTEST round-trip digits, so bytes can diverge (2^60 →
/// "1152921504606846976" here, "1152921504606847000" in ES — powers of ten agree, most other
/// values do not); and at |x| ≥ 1e21 ES switches to exponent notation (`1e+21`) where serde prints
/// digits. Both live outside the portable range: no Intyga leaf can reach them (the producer
/// guard), no vector pins them, and a mismatch reports as an ordinary content mismatch.
fn jcs_stringify(value: &Value) -> String {
    match value {
        Value::Null => "null".to_string(),
        Value::Bool(b) => if *b { "true" } else { "false" }.to_string(),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                return i.to_string();
            }
            if let Some(u) = n.as_u64() {
                return u.to_string();
            }
            if let Some(f) = n.as_f64() {
                // JS has no int/float distinction: JSON.stringify prints 100.0 as "100" and -0 as
                // "0", where serde_json's Display prints "100.0" / "-0.0". Integers are exact
                // below 1e16.
                if f == 0.0 {
                    return "0".to_string(); // covers -0.0, exactly as JSON.stringify(-0) does
                }
                if f.fract() == 0.0 && f.abs() < 1e21 {
                    // Every f64 at or above 2^53 is already integral, so this branch covers all of
                    // [1e16, 1e21) too — the range where serde would print `1e20` in exponent
                    // notation. Fixed precision instead of `as i64`, which saturates. NOTE: above
                    // 2^53 this prints the EXACT expansion, not ES's shortest round trip — see the
                    // doc comment's residuals.
                    return format!("{:.0}", f);
                }
            }
            n.to_string()
        }
        Value::String(s) => serde_json::to_string(s).unwrap_or_else(|_| "null".to_string()),
        Value::Array(arr) => {
            let elems: Vec<String> = arr.iter().map(jcs_stringify).collect();
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
                    format!(
                        "{}:{}",
                        serde_json::to_string(k).unwrap_or_else(|_| "null".to_string()),
                        jcs_stringify(&obj[k])
                    )
                })
                .collect();
            format!("{{{}}}", parts.join(","))
        }
    }
}

/// The 18-element JCS canonical preimage. `metadata` is embedded as its own JCS string.
pub fn canonical_preimage(row: &Value) -> String {
    let metadata = row.get("metadata").cloned().unwrap_or(Value::Null);
    let metadata_str = jcs_stringify(&metadata);
    let is_billable = row
        .get("isBillable")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let arr = Value::Array(vec![
        field(row, "seq"),
        field(row, "createdAt"),
        field(row, "event"),
        field(row, "outcome"),
        field(row, "detail"),
        Value::String(metadata_str),
        field(row, "signerDid"),
        field(row, "signerPublicKey"),
        field(row, "signedPayload"),
        field(row, "signature"),
        field(row, "sigAlg"),
        Value::Bool(is_billable),
        field(row, "tenantId"),
        field(row, "actorNodeId"),
        field(row, "subjectNodeId"),
        field(row, "edgeId"),
        field(row, "challengeId"),
        field(row, "tenantSeq"),
    ]);
    serde_json::to_string(&arr).unwrap_or_default()
}

pub fn leaf_hash(row: &Value) -> String {
    hash_leaf(&canonical_preimage(row))
}

/// Two-hop DEWP inclusion proof: leaf → block root, then hashLeaf(block root) → daily root, each hop
/// bounded by its position (DEWP §3 invariant 3, steps 1 and 2).
#[allow(clippy::too_many_arguments)]
pub fn verify_inclusion_proof(
    leaf: &str,
    block_proof: &[ProofStep],
    block_root: &str,
    block_bounds: ProofBounds,
    checkpoint_proof: &[ProofStep],
    daily_root: &str,
    checkpoint_bounds: ProofBounds,
) -> bool {
    if !verify_merkle_proof(leaf, block_proof, block_root, block_bounds) {
        return false;
    }
    verify_merkle_proof(
        &hash_leaf(block_root),
        checkpoint_proof,
        daily_root,
        checkpoint_bounds,
    )
}

/// JCS of [dailyRoot, timestamp, issuer, algorithm, seqStart, seqEnd, chainHash]. The last three bind
/// the checkpoint's POSITION (DEWP §5.2): without them an external witness attests only a root string
/// that could be recomputed and witnessed at any later time.
#[allow(clippy::too_many_arguments)]
pub fn anchor_preimage(
    daily_root: &str,
    timestamp: &str,
    issuer: &str,
    algorithm: &str,
    seq_start: &str,
    seq_end: &str,
    chain_hash: &str,
) -> String {
    serde_json::to_string(&vec![
        daily_root, timestamp, issuer, algorithm, seq_start, seq_end, chain_hash,
    ])
    .unwrap_or_default()
}

/// sha256(0x03 || UTF8(anchor_preimage)) as RAW bytes — the exact message an anchor issuer signs.
/// DEWP §5.2: the signature is over these 32 raw bytes, never their 64-character hex text. An
/// implementation that signs the hex matches the digest vector and still fails to interoperate,
/// which is why the shared `signedAnchor` vectors exist.
#[allow(clippy::too_many_arguments)]
pub(crate) fn anchor_digest_bytes(
    daily_root: &str,
    timestamp: &str,
    issuer: &str,
    algorithm: &str,
    seq_start: &str,
    seq_end: &str,
    chain_hash: &str,
) -> [u8; 32] {
    let mut buf = vec![0x03u8];
    buf.extend_from_slice(
        anchor_preimage(daily_root, timestamp, issuer, algorithm, seq_start, seq_end, chain_hash)
            .as_bytes(),
    );
    let mut h = Sha256::new();
    h.update(&buf);
    h.finalize().into()
}

/// sha256(0x03 || UTF8(anchor_preimage)).
#[allow(clippy::too_many_arguments)]
pub fn anchor_digest_hex(
    daily_root: &str,
    timestamp: &str,
    issuer: &str,
    algorithm: &str,
    seq_start: &str,
    seq_end: &str,
    chain_hash: &str,
) -> String {
    to_hex(&anchor_digest_bytes(
        daily_root, timestamp, issuer, algorithm, seq_start, seq_end, chain_hash,
    ))
}

/// Milliseconds since the epoch for an exact DEWP §4.3 timestamp (`YYYY-MM-DDTHH:mm:ss.sssZ`), or None.
/// Strict so every port reads the same instant from the same bytes (no offsets, no leap second, no
/// 30 February rolled into March).
pub fn parse_anchor_timestamp_ms(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    if b.len() != 24 {
        return None;
    }
    for (i, c) in b.iter().enumerate() {
        let ok = match i {
            4 | 7 => *c == b'-',
            10 => *c == b'T',
            13 | 16 => *c == b':',
            19 => *c == b'.',
            23 => *c == b'Z',
            _ => c.is_ascii_digit(),
        };
        if !ok {
            return None;
        }
    }
    let num = |r: std::ops::Range<usize>| s[r].parse::<i64>().ok();
    let (y, mo, d, h, mi, se, ms) = (
        num(0..4)?,
        num(5..7)?,
        num(8..10)?,
        num(11..13)?,
        num(14..16)?,
        num(17..19)?,
        num(20..23)?,
    );
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let dim = match mo {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return None,
    };
    if d < 1 || d > dim || h > 23 || mi > 59 || se > 59 {
        return None;
    }
    let yy = y - if mo <= 2 { 1 } else { 0 };
    let era = (if yy >= 0 { yy } else { yy - 399 }) / 400;
    let yoe = yy - era * 400;
    let mp = if mo > 2 { mo - 3 } else { mo + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    Some(((days * 86400 + h * 3600 + mi * 60 + se) * 1000) + ms)
}

fn is_seq(s: &str) -> bool {
    (1..=20).contains(&s.len()) && s.bytes().all(|c| c.is_ascii_digit())
}

/// Verify one anchor's ES256 signature (DEWP §5.2 — single anchor, Core Profile).
///
/// The signed MESSAGE is the raw 32-byte anchor digest; ECDSA-P256/SHA-256 hashes it again
/// internally, matching the TS reference (`crypto.sign` over the digest bytes, `dsaEncoding:
/// "der"`). The key is base64 SPKI resolved by the CALLER from its own trust policy — never taken
/// from the anchor. This helper accepts ES256 only; use `verify_signed_anchor` for ES256, Ed25519 or
/// RSA-PSS, and `verify_anchor_quorum` for caller-policy quorum evaluation.
#[allow(clippy::too_many_arguments)]
pub fn verify_anchor_signature(
    daily_root: &str,
    timestamp: &str,
    issuer: &str,
    algorithm: &str,
    seq_start: &str,
    seq_end: &str,
    chain_hash: &str,
    signature_b64: &str,
    trusted_spki_b64: &str,
) -> bool {
    if algorithm != "ES256" {
        return false;
    }
    let anchor = SignedAnchor {
        daily_root: daily_root.into(),
        timestamp: timestamp.into(),
        issuer: issuer.into(),
        algorithm: algorithm.into(),
        key_id: String::new(),
        signature: signature_b64.into(),
        kind: None,
        evidence: None,
        seq_start: seq_start.into(),
        seq_end: seq_end.into(),
        chain_hash: chain_hash.into(),
    };
    verify_signed_anchor(&anchor, trusted_spki_b64)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedAnchor {
    pub daily_root: String,
    pub timestamp: String,
    pub issuer: String,
    pub algorithm: String,
    pub key_id: String,
    pub signature: String,
    #[serde(default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub evidence: Option<String>,
    /// The checkpoint's POSITION, part of the signed preimage (DEWP §5.2). Missing on the wire ⇒
    /// empty ⇒ not well-formed ⇒ never verifies.
    #[serde(default)]
    pub seq_start: String,
    #[serde(default)]
    pub seq_end: String,
    #[serde(default)]
    pub chain_hash: String,
}
impl SignedAnchor {
    /// The raw 32-byte anchor digest over all seven signed fields.
    pub fn digest(&self) -> [u8; 32] {
        anchor_digest_bytes(
            &self.daily_root,
            &self.timestamp,
            &self.issuer,
            &self.algorithm,
            &self.seq_start,
            &self.seq_end,
            &self.chain_hash,
        )
    }
    /// All seven signed fields have the shapes DEWP §5.2 requires. A missing position field is
    /// refused rather than hashed.
    pub fn is_well_formed(&self) -> bool {
        // §5.2 algorithm registry: the label is signed, so any other one is not a §5.2 anchor.
        matches!(self.algorithm.as_str(), "ES256" | "Ed25519" | "RSA-PSS")
            && is_hash64(&self.daily_root)
            && parse_anchor_timestamp_ms(&self.timestamp).is_some()
            && is_seq(&self.seq_start)
            && is_seq(&self.seq_end)
            && is_hash64(&self.chain_hash)
    }
}
#[derive(Debug, Clone)]
pub enum AnchorQuorum {
    AllMustAgree,
    NOfM,
}
#[derive(Debug, Clone)]
pub struct AnchorPolicy {
    pub required_anchors: usize,
    pub trusted_issuers: Vec<String>,
    pub quorum: AnchorQuorum,
    /// Bound on how long after the checkpoint's claimed time an EXTERNAL witness (Rekor
    /// integratedTime, TSA genTime) may first have seen the anchor. None ⇒ the DEWP §5.3 default.
    pub max_anchor_lag_seconds: Option<i64>,
}
/// DEWP §5.3 default time bound. An anchor witnessed later proves only that the root existed when it
/// was finally witnessed — exactly what re-anchoring a rewritten old root today produces.
pub const DEFAULT_MAX_ANCHOR_LAG_SECONDS: i64 = 86_400;
/// Tolerated witness time BEFORE the checkpoint's claimed time (producer clock ahead of the witness).
pub const ANCHOR_CLOCK_SKEW_SECONDS: i64 = 300;
#[derive(Debug, Clone, Default)]
pub struct ExternalAnchorKeys {
    pub rekor: Option<String>,
    pub rekor_issuer: Option<String>,
    /// The producer's Rekor submission key(s) (PEM or base64 SPKI). When non-empty, an entry counts
    /// only if submitted under one of them with a valid ES256 signature over the anchor digest.
    pub rekor_submitter_keys: Vec<String>,
    pub rfc3161: std::collections::BTreeMap<String, crate::rfc3161::Rfc3161Trust>,
}
/// The checkpoint anchors are counted FOR; every known field must equal the anchor's signed field
/// (`anchored_at` against the anchor's timestamp). An expected checkpoint with no `anchored_at`
/// counts no EXTERNAL witness: its time bound would have nothing trusted to be measured against.
#[derive(Debug, Clone, Default)]
pub struct ExpectedCheckpoint {
    pub seq_start: Option<String>,
    pub seq_end: Option<String>,
    pub chain_hash: Option<String>,
    pub anchored_at: Option<String>,
}
/// A checkpoint record the CALLER holds — normally a chain-verified line of the published roots
/// file (DEWP §5.4.1). Every field but `root` is optional; a present field is binding.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrustedCheckpoint {
    pub root: String,
    #[serde(default)]
    pub seq_start: Option<String>,
    #[serde(default)]
    pub seq_end: Option<String>,
    #[serde(default)]
    pub entry_count: Option<u64>,
    #[serde(default)]
    pub anchored_at: Option<String>,
    #[serde(default)]
    pub chain_hash: Option<String>,
}
/// Why a proof's prover-supplied leaf counts cannot belong to a checkpoint committing `entry_count`
/// events (the sum of its blocks' leaf counts), or `None` (DEWP §17.3).
pub fn leaf_count_mismatch(block_leaf_count: usize, checkpoint_leaf_count: usize, entry_count: Option<u64>) -> Option<String> {
    let n = entry_count? as u128;
    let (block, cps) = (block_leaf_count as u128, checkpoint_leaf_count as u128);
    if cps > n || block + cps > n + 1 || (cps == 1 && block != n) {
        Some(format!(
            "proof claims {block} leaves in its block and {cps} block(s) under the checkpoint, which cannot sum to the checkpoint's {n} committed events"
        ))
    } else {
        None
    }
}
#[derive(Debug, Clone, Default)]
pub struct AnchorQuorumResult {
    pub ok: bool,
    pub verified_issuers: Vec<String>,
    pub divergence: bool,
    pub reason: Option<String>,
    pub note: Option<String>,
    /// Authenticated external witness time per issuer (Unix seconds, earliest per issuer),
    /// including witnesses refused by the time bound.
    pub witness_times: std::collections::BTreeMap<String, i64>,
}

pub(crate) fn decode_public_key(s: &str) -> Option<Vec<u8>> {
    if s.contains("BEGIN") {
        let joined = s
            .lines()
            .filter(|l| !l.starts_with("---"))
            .collect::<String>();
        STANDARD.decode(joined).ok()
    } else {
        STANDARD.decode(s).ok()
    }
}

pub fn verify_signed_anchor(anchor: &SignedAnchor, trusted_key: &str) -> bool {
    if !anchor.is_well_formed() {
        return false;
    }
    let Some(key) = decode_public_key(trusted_key) else {
        return false;
    };
    let Ok(sig) = STANDARD.decode(&anchor.signature) else {
        return false;
    };
    let digest = anchor.digest();
    match anchor.algorithm.as_str() {
        "ES256" => crate::parse_p256_public_key(&key)
            .is_some_and(|k| crate::verify_p256_signature(&k, &digest, &sig)),
        "Ed25519" => {
            use ed25519_dalek::{pkcs8::DecodePublicKey, Signature, Verifier, VerifyingKey};
            VerifyingKey::from_public_key_der(&key)
                .ok()
                .and_then(|k| {
                    Signature::from_slice(&sig)
                        .ok()
                        .map(|s| k.verify(&digest, &s).is_ok())
                })
                .unwrap_or(false)
        }
        "RSA-PSS" => {
            use rsa::signature::Verifier;
            use rsa::{
                pkcs8::DecodePublicKey,
                pss::{Signature, VerifyingKey},
                RsaPublicKey,
            };
            use rsa::traits::PublicKeyParts;
            // DEWP §5.2 RSA-PSS profile: a modulus of at least 2048 bits, SHA-256 with MGF1-SHA-256
            // and a salt exactly the hash length (32). The salt used to be recovered from the
            // signature and accepted at any length.
            RsaPublicKey::from_public_key_der(&key)
                .ok()
                .filter(|k| k.n().bits() >= 2048)
                .and_then(|k| {
                    Signature::try_from(sig.as_slice()).ok().map(|s| {
                        VerifyingKey::<Sha256>::new_with_salt_len(k, 32)
                            .verify(&digest, &s)
                            .is_ok()
                    })
                })
                .unwrap_or(false)
        }
        _ => false,
    }
}

pub fn verify_anchor_quorum<F>(
    anchors: &[SignedAnchor],
    daily_root: &str,
    policy: &AnchorPolicy,
    resolve: &F,
    divergence_anchors: &[SignedAnchor],
    external: &ExternalAnchorKeys,
) -> AnchorQuorumResult
where
    F: Fn(&SignedAnchor) -> Option<String>,
{
    verify_anchor_quorum_for(anchors, daily_root, policy, resolve, divergence_anchors, external, None)
}

fn position_mismatch(a: &SignedAnchor, e: Option<&ExpectedCheckpoint>) -> Option<&'static str> {
    let e = e?;
    let differs = |want: &Option<String>, got: &str| want.as_deref().is_some_and(|w| w != got);
    if differs(&e.seq_start, &a.seq_start) {
        Some("seqStart")
    } else if differs(&e.seq_end, &a.seq_end) {
        Some("seqEnd")
    } else if differs(&e.chain_hash, &a.chain_hash) {
        Some("chainHash")
    } else if differs(&e.anchored_at, &a.timestamp) {
        Some("timestamp")
    } else {
        None
    }
}

/// Count an anchor only when its evidence verifies under caller trust, its signed position matches
/// `expected` where known, and an external witness time lies within
/// [-ANCHOR_CLOCK_SKEW_SECONDS, max lag] of the checkpoint's claimed time (DEWP §5.3).
#[allow(clippy::too_many_arguments)]
pub fn verify_anchor_quorum_for<F>(
    anchors: &[SignedAnchor],
    daily_root: &str,
    policy: &AnchorPolicy,
    resolve: &F,
    divergence_anchors: &[SignedAnchor],
    external: &ExternalAnchorKeys,
    expected: Option<&ExpectedCheckpoint>,
) -> AnchorQuorumResult
where
    F: Fn(&SignedAnchor) -> Option<String>,
{
    let trusted = |a: &SignedAnchor| policy.trusted_issuers.iter().any(|i| i == &a.issuer);
    let trusted_issuer_count = policy.trusted_issuers.iter().collect::<std::collections::BTreeSet<_>>().len();
    // (verified, authenticated witness time in Unix seconds for external anchors)
    let verify = |a: &SignedAnchor| -> (bool, Option<i64>) {
        if !a.is_well_formed() {
            return (false, None);
        }
        match a.kind.as_deref() {
            Some("REKOR") => {
                let scoped = rekor_issuer_allowed(external.rekor_issuer.as_deref(), &a.issuer, trusted_issuer_count);
                if !scoped { return (false, None); }
                if let (Some(k), Some(e)) = (&external.rekor, crate::rekor::parse_rekor_evidence(a.evidence.as_deref())) {
                    let v = crate::rekor::verify_rekor_anchor_pinned(&e, a, k, &external.rekor_submitter_keys);
                    let t = v.integrated_time.and_then(|t| i64::try_from(t).ok());
                    (v.ok && t.is_some(), t)
                } else { (false, None) }
            }
            Some("RFC3161") => match external.rfc3161.get(&a.issuer) {
                Some(t) => {
                    let v = crate::rfc3161::verify_rfc3161_anchor(a, t);
                    (v.ok && v.gen_time.is_some(), v.gen_time)
                }
                None => (false, None),
            },
            None | Some("SELF") => (resolve(a).is_some_and(|k| verify_signed_anchor(a, &k)), None),
            _ => (false, None),
        }
    };
    let max_lag = policy.max_anchor_lag_seconds.unwrap_or(DEFAULT_MAX_ANCHOR_LAG_SECONDS);
    // (lag in ms, inside the §5.3 window around the anchor's own signed checkpoint time)
    let within_bound = |a: &SignedAnchor, witness: i64| -> (i64, bool) {
        let claimed = parse_anchor_timestamp_ms(&a.timestamp).unwrap_or(i64::MIN / 2);
        let lag = witness.saturating_mul(1000).saturating_sub(claimed);
        (lag, lag >= -ANCHOR_CLOCK_SKEW_SECONDS * 1000 && lag <= max_lag.saturating_mul(1000))
    };
    // Divergence is fatal, so its evidence meets the quorum rules (DEWP §5.3): this checkpoint's seq
    // range, an external witness inside the time bound of the anchor's signed time, and — for Rekor,
    // which logs any digest anyone submits — a pinned producer submission key. Chain hash and claimed
    // time are not compared: both commit to the root, so a rewritten checkpoint differs in them.
    for a in divergence_anchors
        .iter()
        .filter(|a| trusted(a) && a.daily_root != daily_root)
    {
        // An anchor whose own signed range names another checkpoint is not divergence evidence.
        if let Some(e) = expected {
            if e.seq_start.as_deref().is_some_and(|s| s != a.seq_start)
                || e.seq_end.as_deref().is_some_and(|s| s != a.seq_end)
            {
                continue;
            }
        }
        if a.kind.as_deref() == Some("REKOR") && external.rekor_submitter_keys.is_empty() {
            continue;
        }
        let (ok, witness) = verify(a);
        if ok && witness.is_some_and(|w| !within_bound(a, w).1) {
            continue;
        }
        if ok {
            return AnchorQuorumResult {
                divergence: true,
                reason: Some(format!(
                    "anchor divergence: issuer {} signed a different root for this checkpoint",
                    a.issuer
                )),
                ..Default::default()
            };
        }
    }
    let mut issuers = std::collections::BTreeSet::new();
    let mut witness_times = std::collections::BTreeMap::<String, i64>::new();
    let mut notes = Vec::<String>::new();
    let mut tsa = 0;
    for a in anchors
        .iter()
        .filter(|a| trusted(a) && a.daily_root == daily_root)
    {
        if let Some(m) = position_mismatch(a, expected) {
            notes.push(format!("anchor from {} binds a different checkpoint {m}; it does not count", a.issuer));
            continue;
        }
        let (verified, witness) = verify(a);
        if a.kind.as_deref()==Some("RFC3161") && !verified { tsa += 1; }
        if !verified {
            continue;
        }
        if let Some(w) = witness {
            let entry = witness_times.entry(a.issuer.clone()).or_insert(w);
            if w < *entry {
                *entry = w;
            }
            // A checkpoint named without its time leaves only the anchor's producer-chosen timestamp
            // to bound the witness against, which bounds nothing (DEWP §5.3).
            if expected.is_some_and(|e| e.anchored_at.is_none()) {
                notes.push(format!(
                    "anchor from {} has an external witness time but no trusted checkpoint time to hold it to (DEWP §5.3); it does not count",
                    a.issuer
                ));
                continue;
            }
            let (lag, inside) = within_bound(a, w);
            if !inside {
                notes.push(format!(
                    "anchor from {} was witnessed {}s from its checkpoint time; it does not count",
                    a.issuer,
                    lag / 1000
                ));
                continue;
            }
        }
        issuers.insert(a.issuer.clone());
    }
    let present = anchors
        .iter()
        .filter(|a| trusted(a) && a.daily_root == daily_root)
        .map(|a| &a.issuer)
        .collect::<std::collections::BTreeSet<_>>()
        .len();
    let need = match policy.quorum {
        AnchorQuorum::AllMustAgree => policy.required_anchors.max(present),
        AnchorQuorum::NOfM => policy.required_anchors,
    };
    let count = issuers.len();
    let ok = count >= need && count >= 1;
    if tsa > 0 {
        notes.push(format!("{tsa} RFC 3161 TSA anchor(s) over this root are not verified; configure RFC3161 trust/OpenSSL or inspect evidence"));
    }
    AnchorQuorumResult {
        ok,
        verified_issuers: issuers.into_iter().collect(),
        divergence: false,
        reason: if ok {
            None
        } else {
            Some(format!("anchor quorum not met ({count}/{need})"))
        },
        note: if notes.is_empty() { None } else { Some(notes.join("; ")) },
        witness_times,
    }
}

fn rekor_issuer_allowed(configured: Option<&str>, anchor_issuer: &str, trusted_issuer_count: usize) -> bool {
    configured == Some(anchor_issuer) || (configured.is_none() && trusted_issuer_count == 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rekor_trust_cannot_be_reattributed_across_issuers() {
        assert!(!rekor_issuer_allowed(Some("rekor.example"), "tsa.example", 2));
        assert!(!rekor_issuer_allowed(None, "rekor.example", 2));
        assert!(rekor_issuer_allowed(None, "rekor.example", 1));
    }

    fn vectors() -> Value {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/vectors/ledger-vectors.json"
        );
        serde_json::from_str(&std::fs::read_to_string(path).expect("read ledger vectors")).unwrap()
    }

    fn steps(v: &Value) -> Vec<ProofStep> {
        v.as_array()
            .unwrap()
            .iter()
            .map(|s| ProofStep {
                sibling_hash: s["siblingHash"].as_str().unwrap().to_string(),
                sibling_position: s["siblingPosition"].as_str().unwrap().to_string(),
            })
            .collect()
    }

    /// The shared negative inclusion cases. This port previously had no leaf index or leaf count at
    /// all, so a path to a leaf slot that never existed recomputed the real root and verified —
    /// DEWP §11.1 calls that non-conformant outright.
    #[test]
    fn inclusion_negative_vectors_are_refused() {
        let v = vectors();
        let cases = v["inclusionNegative"]
            .as_array()
            .expect("ledger-vectors.json carries no inclusionNegative cases");
        assert!(!cases.is_empty());
        for c in cases {
            let bounds = ProofBounds {
                index: c["bounds"]["index"].as_u64().unwrap() as usize,
                leaf_count: c["bounds"]["leafCount"].as_u64().unwrap() as usize,
            };
            let got = verify_merkle_proof(
                c["leaf"].as_str().unwrap(),
                &steps(&c["proof"]),
                c["root"].as_str().unwrap(),
                bounds,
            );
            assert_eq!(
                got,
                c["expected"].as_bool().unwrap(),
                "{} — {}",
                c["name"],
                c["reason"]
            );
        }
    }

    #[test]
    fn primitives_match_vectors() {
        let v = vectors();
        for c in v["sha256Hex"].as_array().unwrap() {
            assert_eq!(
                sha256_hex_bytes(c["input"].as_str().unwrap().as_bytes()),
                c["expected"].as_str().unwrap()
            );
        }
        for c in v["hashLeaf"].as_array().unwrap() {
            assert_eq!(
                hash_leaf(c["input"].as_str().unwrap()),
                c["expected"].as_str().unwrap()
            );
        }
        for c in v["hashPair"].as_array().unwrap() {
            assert_eq!(
                hash_pair(c["left"].as_str().unwrap(), c["right"].as_str().unwrap()),
                c["expected"].as_str().unwrap()
            );
        }
        assert_eq!(empty_root(), v["emptyRoot"].as_str().unwrap());
        for c in v["merkleRoots"].as_array().unwrap() {
            let leaves: Vec<String> = c["leaves"]
                .as_array()
                .unwrap()
                .iter()
                .map(|x| x.as_str().unwrap().to_string())
                .collect();
            assert_eq!(
                merkle_root(&leaves),
                c["expected"].as_str().unwrap(),
                "{}",
                c["name"]
            );
        }
    }

    #[test]
    fn leaf_preimage_matches_vectors() {
        let v = vectors();
        for c in v["leafPreimage"].as_array().unwrap() {
            assert_eq!(
                canonical_preimage(&c["row"]),
                c["canonical"].as_str().unwrap(),
                "{}",
                c["name"]
            );
            assert_eq!(
                leaf_hash(&c["row"]),
                c["leafHash"].as_str().unwrap(),
                "{}",
                c["name"]
            );
        }
    }

    /// The f64 path the shared vector CANNOT reach: values parsed from vector JSON text stay
    /// integer-typed in serde_json, so a runtime-built row with an f64 metadata value is the only
    /// way to pin that whole-valued floats fold to integer text (`100.0` → `"100"`), matching
    /// `JSON.stringify` in the TS reference. Same silent-divergence class as lib.rs's
    /// `test_stable_stringify_whole_floats_match_javascript`, on the ledger path.
    #[test]
    fn metadata_whole_floats_fold_like_javascript() {
        // Direct: folding, -0.0 → "0" (no portability refusal on this path), UTF-16 key order.
        let m = serde_json::json!({ "amount": 100.0, "i": 3, "neg": -0.0, "ratio": 1.5 });
        assert_eq!(
            jcs_stringify(&m),
            r#"{"amount":100,"i":3,"neg":0,"ratio":1.5}"#
        );

        // Through the full preimage: the same metadata bytes as a row whose JSON text says 100.
        let row_f64 = serde_json::json!({
            "seq": "1", "tenantSeq": "2", "createdAt": "2026-07-24T12:00:00.000Z",
            "event": "ACTION_APPROVED", "outcome": "SUCCESS", "detail": "d",
            "metadata": { "amount": 100.0 },
            "signerDid": null, "signerPublicKey": null, "signedPayload": null,
            "signature": null, "sigAlg": null, "isBillable": false,
            "tenantId": "t", "actorNodeId": null, "subjectNodeId": null,
            "edgeId": null, "challengeId": null
        });
        let mut row_int = row_f64.clone();
        row_int["metadata"] =
            serde_json::from_str::<Value>(r#"{"amount":100}"#).expect("parse metadata");
        assert_eq!(canonical_preimage(&row_f64), canonical_preimage(&row_int));
        assert!(canonical_preimage(&row_f64).contains(r#"{\"amount\":100}"#));
    }

    #[test]
    fn large_whole_numbers_print_digits_like_json_stringify() {
        // The producer refuses to commit these (packages/db assertPortableJson), but a third-party
        // or legacy leaf can still carry them, and this port used to print serde's `1e20` where the
        // TS reference prints the digits — a silent leaf-hash divergence that reads as tampering.
        // 1e20 exceeds u64::MAX, so serde hands it over as f64 and the fold branch has to handle it.
        for (json, expected) in [
            (r#"{"n":10000000000000000}"#, r#"{"n":10000000000000000}"#), // 1e16
            (r#"{"n":100000000000000000}"#, r#"{"n":100000000000000000}"#), // 1e17
            (
                r#"{"n":100000000000000000000}"#,
                r#"{"n":100000000000000000000}"#,
            ), // 1e20, past u64::MAX
        ] {
            let v: Value = serde_json::from_str(json).expect("parse");
            assert_eq!(jcs_stringify(&v), expected, "input {json}");
        }
    }

    #[test]
    fn inclusion_and_anchor_match_vectors() {
        let v = vectors();
        let inc = &v["inclusion"];
        let daily = inc["dailyRoot"].as_str().unwrap();
        let usize_at = |k: &str| {
            inc[k]
                .as_u64()
                .unwrap_or_else(|| panic!("vector missing {k}")) as usize
        };
        let block_bounds = ProofBounds {
            index: usize_at("leafIndex"),
            leaf_count: usize_at("blockLeafCount"),
        };
        let checkpoint_bounds = ProofBounds {
            index: usize_at("checkpointLeafIndex"),
            leaf_count: usize_at("checkpointLeafCount"),
        };
        assert!(verify_inclusion_proof(
            inc["leaf"].as_str().unwrap(),
            &steps(&inc["blockProof"]),
            inc["blockRoot"].as_str().unwrap(),
            block_bounds,
            &steps(&inc["checkpointProof"]),
            daily,
            checkpoint_bounds,
        ));
        assert!(!verify_inclusion_proof(
            inc["leaf"].as_str().unwrap(),
            &steps(&inc["blockProof"]),
            inc["blockRoot"].as_str().unwrap(),
            block_bounds,
            &steps(&inc["checkpointProof"]),
            &"0".repeat(64),
            checkpoint_bounds,
        ));
        // A proof that cannot say where its leaf sits does not establish inclusion (§3 invariant 3).
        assert!(!verify_inclusion_proof(
            inc["leaf"].as_str().unwrap(),
            &steps(&inc["blockProof"]),
            inc["blockRoot"].as_str().unwrap(),
            ProofBounds {
                index: 0,
                leaf_count: 0
            },
            &steps(&inc["checkpointProof"]),
            daily,
            checkpoint_bounds,
        ));
        let a = &v["anchor"]["input"];
        assert_eq!(
            anchor_digest_hex(
                a["dailyRoot"].as_str().unwrap(),
                a["timestamp"].as_str().unwrap(),
                a["issuer"].as_str().unwrap(),
                a["algorithm"].as_str().unwrap(),
                a["seqStart"].as_str().unwrap(),
                a["seqEnd"].as_str().unwrap(),
                a["chainHash"].as_str().unwrap(),
            ),
            v["anchor"]["digestHex"].as_str().unwrap()
        );
    }

    /// Consumes the shared `signedAnchor` vectors — the same section the TS suite pins in
    /// ledger-anchor.test.ts. The `anchor` section above pins only the DIGEST; this one pins the
    /// SIGNING, which is where the §5.2 trap lives: an implementation that signs the 64-char hex
    /// text instead of the 32 raw digest bytes matches `digestHex` and fails exactly here.
    #[test]
    fn signed_anchor_vectors_verify() {
        let v = vectors();
        let sa = &v["signedAnchor"];
        let spki = sa["signerKey"]["spkiB64"]
            .as_str()
            .expect("signedAnchor signer key");
        let cases = sa["cases"].as_array().expect("signedAnchor cases");
        assert!(!cases.is_empty());
        for c in cases {
            let name = c["name"].as_str().unwrap_or("<unnamed>");
            let a = &c["anchor"];
            let daily_root = a["dailyRoot"].as_str().unwrap();
            let timestamp = a["timestamp"].as_str().unwrap();
            let issuer = a["issuer"].as_str().unwrap();
            let algorithm = a["algorithm"].as_str().unwrap();
            let (seq_start, seq_end, chain_hash) = (
                a["seqStart"].as_str().unwrap(),
                a["seqEnd"].as_str().unwrap(),
                a["chainHash"].as_str().unwrap(),
            );
            if let Some(digest_hex) = c["digestHex"].as_str() {
                assert_eq!(
                    anchor_digest_hex(daily_root, timestamp, issuer, algorithm, seq_start, seq_end, chain_hash),
                    digest_hex,
                    "{name}"
                );
            }
            let got = verify_anchor_signature(
                daily_root,
                timestamp,
                issuer,
                algorithm,
                seq_start,
                seq_end,
                chain_hash,
                a["signature"].as_str().unwrap(),
                spki,
            );
            assert_eq!(got, c["expectOk"].as_bool().unwrap(), "{name}");
        }

        // Fail-closed pins outside the committed cases: an unsupported algorithm and a garbage key
        // must refuse rather than guess.
        let a = &cases[0]["anchor"];
        let s = |k: &str| a[k].as_str().unwrap();
        assert!(!verify_anchor_signature(
            s("dailyRoot"), s("timestamp"), s("issuer"), "Ed25519",
            s("seqStart"), s("seqEnd"), s("chainHash"), s("signature"), spki,
        ));
        assert!(!verify_anchor_signature(
            s("dailyRoot"), s("timestamp"), s("issuer"), s("algorithm"),
            s("seqStart"), s("seqEnd"), s("chainHash"), s("signature"), "not-base64!!",
        ));
        // The position is signed and required: an anchor without its chain hash never verifies.
        assert!(!verify_anchor_signature(
            s("dailyRoot"), s("timestamp"), s("issuer"), s("algorithm"),
            s("seqStart"), s("seqEnd"), "", s("signature"), spki,
        ));
    }

    #[test]
    fn anchor_timestamps_are_parsed_strictly() {
        assert_eq!(parse_anchor_timestamp_ms("1970-01-01T00:00:01.500Z"), Some(1500));
        assert_eq!(parse_anchor_timestamp_ms("2026-09-01T12:00:00.000Z"), Some(1_788_264_000_000));
        assert_eq!(parse_anchor_timestamp_ms("2026-02-30T00:00:00.000Z"), None);
        assert_eq!(parse_anchor_timestamp_ms("2026-09-16T00:00:00Z"), None);
        assert_eq!(parse_anchor_timestamp_ms("2026-09-16T00:00:60.000Z"), None);
        assert_eq!(parse_anchor_timestamp_ms("2028-02-29T00:00:00.000Z").is_some(), true);
    }
}
