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
/// the TS reference on values a third-party or legacy producer may have committed, and up to 1e21
/// it does: `JSON.stringify` prints full digits for every finite double below that, so whole values
/// fold to digit text here too. `f as i64` cannot be used for the whole range — it saturates above
/// i64::MAX (≈9.2e18) — hence the fixed-precision format.
///
/// Residual, bounded and stated: at |x| ≥ 1e21 ES6 switches to exponent notation (`1e+21`) and
/// serde prints digits, so bytes diverge there. No Intyga leaf can reach that (the producer guard),
/// and no vector pins it.
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
                    // [1e16, 1e21) too — the range where serde would print `1e20` and JSON.stringify
                    // prints the digits. Fixed precision instead of `as i64`, which saturates.
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

/// JCS of [dailyRoot, timestamp, issuer, algorithm].
pub fn anchor_preimage(daily_root: &str, timestamp: &str, issuer: &str, algorithm: &str) -> String {
    serde_json::to_string(&vec![daily_root, timestamp, issuer, algorithm]).unwrap_or_default()
}

/// sha256(0x03 || UTF8(anchor_preimage)) as RAW bytes — the exact message an anchor issuer signs.
/// DEWP §5.2: the signature is over these 32 raw bytes, never their 64-character hex text. An
/// implementation that signs the hex matches the digest vector and still fails to interoperate,
/// which is why the shared `signedAnchor` vectors exist.
fn anchor_digest_raw(daily_root: &str, timestamp: &str, issuer: &str, algorithm: &str) -> [u8; 32] {
    let mut buf = vec![0x03u8];
    buf.extend_from_slice(anchor_preimage(daily_root, timestamp, issuer, algorithm).as_bytes());
    let mut h = Sha256::new();
    h.update(&buf);
    h.finalize().into()
}

/// sha256(0x03 || UTF8(anchor_preimage)).
pub fn anchor_digest_hex(
    daily_root: &str,
    timestamp: &str,
    issuer: &str,
    algorithm: &str,
) -> String {
    to_hex(&anchor_digest_raw(daily_root, timestamp, issuer, algorithm))
}

/// Verify one anchor's ES256 signature (DEWP §5.2 — single anchor, Core Profile).
///
/// The signed MESSAGE is the raw 32-byte anchor digest; ECDSA-P256/SHA-256 hashes it again
/// internally, matching the TS reference (`crypto.sign` over the digest bytes, `dsaEncoding:
/// "der"`). The key is base64 SPKI resolved by the CALLER from its own trust policy — never taken
/// from the anchor. Non-`ES256` algorithms fail closed: this port supports the one algorithm the
/// gateway emits, and refusing beats guessing.
///
/// SCOPE: this is the single-anchor primitive only. Evaluating `requiredAnchors` / issuer trust
/// across multiple anchors (§5.3 quorum) stays out of scope for this Core Profile port — see the
/// README's DEWP conformance section; use `@intyga/verify` for the Extended Profile.
pub fn verify_anchor_signature(
    daily_root: &str,
    timestamp: &str,
    issuer: &str,
    algorithm: &str,
    signature_b64: &str,
    trusted_spki_b64: &str,
) -> bool {
    if algorithm != "ES256" {
        return false;
    }
    let Ok(pub_bytes) = STANDARD.decode(trusted_spki_b64) else {
        return false;
    };
    let Ok(sig_bytes) = STANDARD.decode(signature_b64) else {
        return false;
    };
    let Some(key) = crate::parse_p256_public_key(&pub_bytes) else {
        return false;
    };
    // Reuses the receipt path's parsing/verification machinery: SPKI or SEC1 keys, DER or raw
    // P1363 signatures.
    crate::verify_p256_signature(
        &key,
        &anchor_digest_raw(daily_root, timestamp, issuer, algorithm),
        &sig_bytes,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vectors() -> Value {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../mcp-schemas/vectors/ledger-vectors.json"
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
            if let Some(digest_hex) = c["digestHex"].as_str() {
                assert_eq!(
                    anchor_digest_hex(daily_root, timestamp, issuer, algorithm),
                    digest_hex,
                    "{name}"
                );
            }
            let got = verify_anchor_signature(
                daily_root,
                timestamp,
                issuer,
                algorithm,
                a["signature"].as_str().unwrap(),
                spki,
            );
            assert_eq!(got, c["expectOk"].as_bool().unwrap(), "{name}");
        }

        // Fail-closed pins outside the committed cases: an unsupported algorithm and a garbage key
        // must refuse rather than guess.
        let a = &cases[0]["anchor"];
        assert!(!verify_anchor_signature(
            a["dailyRoot"].as_str().unwrap(),
            a["timestamp"].as_str().unwrap(),
            a["issuer"].as_str().unwrap(),
            "Ed25519",
            a["signature"].as_str().unwrap(),
            spki,
        ));
        assert!(!verify_anchor_signature(
            a["dailyRoot"].as_str().unwrap(),
            a["timestamp"].as_str().unwrap(),
            a["issuer"].as_str().unwrap(),
            a["algorithm"].as_str().unwrap(),
            a["signature"].as_str().unwrap(),
            "not-base64!!",
        ));
    }
}
