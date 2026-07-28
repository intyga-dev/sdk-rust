//! DEWP audit-ledger verification (docs/DEWP.md) — Rust port.
//!
//! Byte-identical to `@intyga/verify` (ledger-*.ts) and the Go/Python ports, locked by the shared
//! vectors (packages/mcp-schemas/vectors/ledger-vectors.json).
//!
//! Domain separation: 0x00 leaf, 0x01 node, 0x02 empty root, 0x03 anchor. Node children are hex-decoded
//! to raw bytes before hashing; the leaf `metadata` element is a JCS string. serde_json's default `Map`
//! is a BTreeMap (sorted keys) and does not HTML-escape, so `to_string` yields JCS for ASCII keys.

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
            let right = if i + 1 < level.len() { &level[i + 1] } else { left };
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

/// Recompute the root from a leaf + its leaf→root proof.
pub fn verify_merkle_proof(leaf: &str, proof: &[ProofStep], root: &str) -> bool {
    let mut h = leaf.to_string();
    for step in proof {
        h = if step.sibling_position == "LEFT" {
            hash_pair(&step.sibling_hash, &h)
        } else {
            hash_pair(&h, &step.sibling_hash)
        };
    }
    h == root
}

/// Read a leaf-row field as a JSON Value (String or Null), from the DEWP intyga.v1 profile row.
fn field<'a>(row: &'a Value, key: &str) -> Value {
    row.get(key).cloned().unwrap_or(Value::Null)
}

/// The 18-element JCS canonical preimage. `metadata` is embedded as its own JCS string.
pub fn canonical_preimage(row: &Value) -> String {
    let metadata = row.get("metadata").cloned().unwrap_or(Value::Null);
    let metadata_str = if metadata.is_null() {
        "null".to_string()
    } else {
        serde_json::to_string(&metadata).unwrap_or_else(|_| "null".to_string())
    };
    let is_billable = row.get("isBillable").and_then(Value::as_bool).unwrap_or(false);
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

/// Two-hop DEWP inclusion proof: leaf → block root, then hashLeaf(block root) → daily root.
pub fn verify_inclusion_proof(
    leaf: &str,
    block_proof: &[ProofStep],
    block_root: &str,
    checkpoint_proof: &[ProofStep],
    daily_root: &str,
) -> bool {
    if !verify_merkle_proof(leaf, block_proof, block_root) {
        return false;
    }
    verify_merkle_proof(&hash_leaf(block_root), checkpoint_proof, daily_root)
}

/// JCS of [dailyRoot, timestamp, issuer, algorithm].
pub fn anchor_preimage(daily_root: &str, timestamp: &str, issuer: &str, algorithm: &str) -> String {
    serde_json::to_string(&vec![daily_root, timestamp, issuer, algorithm]).unwrap_or_default()
}

/// sha256(0x03 || UTF8(anchor_preimage)).
pub fn anchor_digest_hex(daily_root: &str, timestamp: &str, issuer: &str, algorithm: &str) -> String {
    let mut buf = vec![0x03u8];
    buf.extend_from_slice(anchor_preimage(daily_root, timestamp, issuer, algorithm).as_bytes());
    sha256_hex_bytes(&buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vectors() -> Value {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../mcp-schemas/vectors/ledger-vectors.json");
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

    #[test]
    fn primitives_match_vectors() {
        let v = vectors();
        for c in v["sha256Hex"].as_array().unwrap() {
            assert_eq!(sha256_hex_bytes(c["input"].as_str().unwrap().as_bytes()), c["expected"].as_str().unwrap());
        }
        for c in v["hashLeaf"].as_array().unwrap() {
            assert_eq!(hash_leaf(c["input"].as_str().unwrap()), c["expected"].as_str().unwrap());
        }
        for c in v["hashPair"].as_array().unwrap() {
            assert_eq!(
                hash_pair(c["left"].as_str().unwrap(), c["right"].as_str().unwrap()),
                c["expected"].as_str().unwrap()
            );
        }
        assert_eq!(empty_root(), v["emptyRoot"].as_str().unwrap());
        for c in v["merkleRoots"].as_array().unwrap() {
            let leaves: Vec<String> =
                c["leaves"].as_array().unwrap().iter().map(|x| x.as_str().unwrap().to_string()).collect();
            assert_eq!(merkle_root(&leaves), c["expected"].as_str().unwrap(), "{}", c["name"]);
        }
    }

    #[test]
    fn leaf_preimage_matches_vectors() {
        let v = vectors();
        for c in v["leafPreimage"].as_array().unwrap() {
            assert_eq!(canonical_preimage(&c["row"]), c["canonical"].as_str().unwrap(), "{}", c["name"]);
            assert_eq!(leaf_hash(&c["row"]), c["leafHash"].as_str().unwrap(), "{}", c["name"]);
        }
    }

    #[test]
    fn inclusion_and_anchor_match_vectors() {
        let v = vectors();
        let inc = &v["inclusion"];
        let daily = inc["dailyRoot"].as_str().unwrap();
        assert!(verify_inclusion_proof(
            inc["leaf"].as_str().unwrap(),
            &steps(&inc["blockProof"]),
            inc["blockRoot"].as_str().unwrap(),
            &steps(&inc["checkpointProof"]),
            daily,
        ));
        assert!(!verify_inclusion_proof(
            inc["leaf"].as_str().unwrap(),
            &steps(&inc["blockProof"]),
            inc["blockRoot"].as_str().unwrap(),
            &steps(&inc["checkpointProof"]),
            &"0".repeat(64),
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
}
