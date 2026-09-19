use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const CHAIN_TAG: u8 = 0x04;
pub const GENESIS_PREV_CHAIN_HASH: &str = "";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RootsChainEntry {
    pub seq_start: String,
    pub seq_end: String,
    pub entry_count: u64,
    pub root: String,
    pub anchored_at: String,
    #[serde(default)]
    pub prev_chain_hash: Option<String>,
    #[serde(default)]
    pub chain_hash: Option<String>,
}
#[derive(Debug, Clone)]
pub struct ChainInput {
    pub prev_chain_hash: String,
    pub root: String,
    pub seq_start: String,
    pub seq_end: String,
    pub entry_count: u64,
    pub anchored_at: String,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainVerification {
    pub ok: bool,
    pub verified_count: usize,
    pub broken_at: isize,
    pub unchained: bool,
    pub reason: Option<String>,
}

pub fn chain_preimage(c: &ChainInput) -> String {
    serde_json::to_string(&[
        c.prev_chain_hash.as_str(),
        c.root.as_str(),
        c.seq_start.as_str(),
        c.seq_end.as_str(),
        &c.entry_count.to_string(),
        c.anchored_at.as_str(),
    ])
    .unwrap_or_default()
}
pub fn chain_hash(c: &ChainInput) -> String {
    let mut h = Sha256::new();
    h.update([CHAIN_TAG]);
    h.update(chain_preimage(c));
    format!("{:x}", h.finalize())
}
fn fail(at: usize, why: String, count: usize) -> ChainVerification {
    ChainVerification {
        ok: false,
        verified_count: count,
        broken_at: at as isize,
        unchained: false,
        reason: Some(why),
    }
}
pub fn verify_roots_chain(entries: &[RootsChainEntry]) -> ChainVerification {
    if entries.is_empty() {
        return ChainVerification {
            ok: true,
            verified_count: 0,
            broken_at: -1,
            unchained: false,
            reason: None,
        };
    }
    let chained = entries.iter().filter(|e| e.chain_hash.is_some()).count();
    if chained == 0 {
        return ChainVerification{ok:false,verified_count:0,broken_at:-1,unchained:true,reason:Some("roots file carries no chain hashes (pre-DEWP-5.4 v1 file); continuity cannot be checked".into())};
    }
    if chained != entries.len() {
        return fail(
            entries
                .iter()
                .position(|e| e.chain_hash.is_none())
                .unwrap_or(0),
            "roots file mixes chained and unchained entries".into(),
            0,
        );
    }
    for (i, e) in entries.iter().enumerate() {
        let expected = if i == 0 {
            ""
        } else {
            entries[i - 1].chain_hash.as_deref().unwrap_or("")
        };
        let declared = e.prev_chain_hash.as_deref().unwrap_or("");
        if declared != expected {
            return fail(i, format!("chain link broken at seqEnd={}", e.seq_end), i);
        }
        let input = ChainInput {
            prev_chain_hash: declared.into(),
            root: e.root.clone(),
            seq_start: e.seq_start.clone(),
            seq_end: e.seq_end.clone(),
            entry_count: e.entry_count,
            anchored_at: e.anchored_at.clone(),
        };
        if e.chain_hash.as_deref() != Some(chain_hash(&input).as_str()) {
            return fail(i, format!("chain hash mismatch at seqEnd={}", e.seq_end), i);
        }
        let start = e.seq_start.parse::<u128>();
        let end = e.seq_end.parse::<u128>();
        if start.is_err() || end.is_err() {
            return fail(i, format!("non-integer seq range at index {i}"), i);
        }
        let (start, end) = (start.unwrap(), end.unwrap());
        if end < start {
            return fail(
                i,
                format!("seq range inverted: seqStart={start} > seqEnd={end}"),
                i,
            );
        }
        if i > 0 {
            let Ok(prev) = entries[i - 1].seq_end.parse::<u128>() else {
                return fail(i, format!("non-integer seq range at index {i}"), i);
            };
            if start <= prev {
                return fail(i,format!("seq ranges overlap or regress: entry starts at {start} but predecessor ended at {prev}"),i);
            }
        }
    }
    ChainVerification {
        ok: true,
        verified_count: entries.len(),
        broken_at: -1,
        unchained: false,
        reason: None,
    }
}
