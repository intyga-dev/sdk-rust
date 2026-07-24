//! WebAuthn (passkey) receipt verification.
//!
//! Mirrors the TypeScript (`@sakra-trust/verify`) and Python verifiers byte-for-byte: a minimal
//! CBOR reader walks the COSE_Key, the assertion is pinned to the expected origin and RP ID, user
//! presence/verification is enforced, the challenge must equal base64url(canonicalPayload), and the
//! ES256 signature is checked over `authenticatorData ‖ SHA-256(clientDataJSON)`.

use crate::{parse_p256_public_key, verify_p256_signature, ApprovalReceipt, VerifyOptions};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use p256::ecdsa::VerifyingKey;
use sha2::{Digest, Sha256};

// WebAuthn authenticatorData flag bits (WebAuthn L3 §6.1).
const AUTH_DATA_FLAG_UP: u8 = 0x01; // User Present
const AUTH_DATA_FLAG_UV: u8 = 0x04; // User Verified

// ─── Minimal CBOR reader (COSE_Key only) ─────────────────────────────────────
// Just enough CBOR to walk a COSE_Key map: ints, byte/text strings, arrays, maps. Anything outside
// that subset is rejected rather than guessed.

enum Cbor {
    Int(i64),
    Bytes(Vec<u8>),
    // Text and Array are part of the CBOR grammar we must consume to walk a COSE_Key correctly,
    // but their contents are never read for a P-256 key — only the integer labels and byte-string
    // coordinates matter.
    #[allow(dead_code)]
    Text(String),
    #[allow(dead_code)]
    Array(Vec<Cbor>),
    Map(Vec<(Cbor, Cbor)>),
}

struct CborReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> CborReader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        CborReader { buf, pos: 0 }
    }

    fn require(&self, n: usize) -> Result<(), String> {
        if self.pos + n > self.buf.len() {
            return Err("invalid COSE public key format: truncated CBOR item".to_string());
        }
        Ok(())
    }

    /// Read a CBOR head, returning (major type, argument value).
    fn read_head(&mut self) -> Result<(u8, u64), String> {
        self.require(1)?;
        let initial = self.buf[self.pos];
        self.pos += 1;
        let major = initial >> 5;
        let info = initial & 0x1f;
        let value = match info {
            0..=23 => info as u64,
            24 => {
                self.require(1)?;
                let v = self.buf[self.pos] as u64;
                self.pos += 1;
                v
            }
            25 => {
                self.require(2)?;
                let v = u16::from_be_bytes([self.buf[self.pos], self.buf[self.pos + 1]]) as u64;
                self.pos += 2;
                v
            }
            26 => {
                self.require(4)?;
                let v = u32::from_be_bytes([
                    self.buf[self.pos],
                    self.buf[self.pos + 1],
                    self.buf[self.pos + 2],
                    self.buf[self.pos + 3],
                ]) as u64;
                self.pos += 4;
                v
            }
            // 27 = 64-bit, 28-30 reserved, 31 = indefinite. No COSE_Key needs any of them.
            _ => {
                return Err(
                    "invalid COSE public key format: unsupported CBOR length encoding".to_string(),
                )
            }
        };
        Ok((major, value))
    }

    fn decode_item(&mut self) -> Result<Cbor, String> {
        let (major, value) = self.read_head()?;
        match major {
            0 => Ok(Cbor::Int(value as i64)),
            1 => Ok(Cbor::Int(-1 - value as i64)),
            2 => {
                self.require(value as usize)?;
                let b = self.buf[self.pos..self.pos + value as usize].to_vec();
                self.pos += value as usize;
                Ok(Cbor::Bytes(b))
            }
            3 => {
                self.require(value as usize)?;
                let s = String::from_utf8(self.buf[self.pos..self.pos + value as usize].to_vec())
                    .map_err(|_| {
                    "invalid COSE public key format: bad UTF-8 text".to_string()
                })?;
                self.pos += value as usize;
                Ok(Cbor::Text(s))
            }
            4 => {
                let mut items = Vec::with_capacity(value as usize);
                for _ in 0..value {
                    items.push(self.decode_item()?);
                }
                Ok(Cbor::Array(items))
            }
            5 => {
                let mut pairs = Vec::with_capacity(value as usize);
                for _ in 0..value {
                    let k = self.decode_item()?;
                    let v = self.decode_item()?;
                    pairs.push((k, v));
                }
                Ok(Cbor::Map(pairs))
            }
            _ => Err(format!(
                "invalid COSE public key format: unsupported CBOR major type {}",
                major
            )),
        }
    }
}

/// Extract the P-256 public key from a WebAuthn COSE_Key. Pins kty EC2 (2), crv P-256 (1) and, if
/// present, alg ES256 (-7), so a key for another curve can never be reinterpreted as P-256.
fn parse_cose_p256_key(cose_buf: &[u8]) -> Result<VerifyingKey, String> {
    let item = CborReader::new(cose_buf).decode_item()?;
    let pairs = match item {
        Cbor::Map(pairs) => pairs,
        _ => return Err("invalid COSE public key format: expected a CBOR map".to_string()),
    };

    let get = |label: i64| -> Option<&Cbor> {
        pairs.iter().find_map(|(k, v)| match k {
            Cbor::Int(i) if *i == label => Some(v),
            _ => None,
        })
    };

    match get(1) {
        Some(Cbor::Int(2)) => {}
        _ => return Err("invalid COSE public key format: expected kty EC2 (2)".to_string()),
    }
    match get(-1) {
        Some(Cbor::Int(1)) => {}
        _ => return Err("invalid COSE public key format: expected crv P-256 (1)".to_string()),
    }
    if let Some(alg) = get(3) {
        match alg {
            Cbor::Int(-7) => {}
            _ => return Err("invalid COSE public key format: expected alg ES256 (-7)".to_string()),
        }
    }

    let coord = |label: i64, name: &str| -> Result<Vec<u8>, String> {
        match get(label) {
            Some(Cbor::Bytes(b)) if b.len() == 32 => Ok(b.clone()),
            Some(Cbor::Bytes(b)) => Err(format!(
                "invalid COSE public key format: {} coordinate must be 32 bytes, got {}",
                name,
                b.len()
            )),
            _ => Err(format!(
                "invalid COSE public key format: missing {} coordinate",
                name
            )),
        }
    };
    let x = coord(-2, "x")?;
    let y = coord(-3, "y")?;

    // Build an uncompressed SEC1 point (0x04 ‖ x ‖ y); from_sec1_bytes validates it is on-curve.
    let mut sec1 = Vec::with_capacity(65);
    sec1.push(0x04);
    sec1.extend_from_slice(&x);
    sec1.extend_from_slice(&y);
    parse_p256_public_key(&sec1)
        .ok_or_else(|| "invalid COSE public key format: point is not a valid P-256 key".to_string())
}

#[derive(serde::Deserialize)]
struct ClientData {
    #[serde(rename = "type")]
    type_: String,
    #[serde(default)]
    challenge: String,
    #[serde(default)]
    origin: String,
}

/// Verify a WEBAUTHN receipt. Requires `opts.expected_origin` and `opts.expected_rp_id`.
pub(crate) fn verify_webauthn(
    receipt: &ApprovalReceipt,
    opts: &VerifyOptions,
) -> Result<(), String> {
    let authenticator_data = receipt
        .authenticator_data
        .as_ref()
        .ok_or("WebAuthn receipt missing authenticatorData or clientDataJSON")?;
    let client_data_json = receipt
        .client_data_json
        .as_ref()
        .ok_or("WebAuthn receipt missing authenticatorData or clientDataJSON")?;

    // FAIL CLOSED: without an expected origin and RP ID there is nothing to pin the assertion to.
    let expected_origin = opts.expected_origin.as_deref().filter(|s| !s.is_empty());
    let expected_rp_id = opts.expected_rp_id.as_deref().filter(|s| !s.is_empty());
    let (expected_origin, expected_rp_id) = match (expected_origin, expected_rp_id) {
        (Some(o), Some(r)) => (o, r),
        _ => {
            return Err("WebAuthn receipts require expected_origin and expected_rp_id — without them an assertion from any relying party would verify".to_string())
        }
    };

    let client_data_buf = STANDARD
        .decode(client_data_json)
        .map_err(|_| "invalid clientDataJSON base64".to_string())?;
    let client_data: ClientData = serde_json::from_slice(&client_data_buf)
        .map_err(|_| "clientDataJSON is not valid JSON".to_string())?;

    // An assertion, not a registration: webauthn.create signs a different ceremony over the same
    // challenge bytes and must never be accepted as approval.
    if client_data.type_ != "webauthn.get" {
        return Err("clientDataJSON is not a webauthn.get assertion".to_string());
    }
    if client_data.origin != expected_origin {
        return Err("assertion origin does not match expected_origin".to_string());
    }
    let expected_challenge = URL_SAFE_NO_PAD.encode(receipt.canonical_payload.as_bytes());
    let client_challenge = client_data.challenge.trim_end_matches('=');
    if client_challenge != expected_challenge {
        return Err("clientDataJSON challenge does not match canonical payload".to_string());
    }

    let auth_data = STANDARD
        .decode(authenticator_data)
        .map_err(|_| "invalid authenticatorData base64".to_string())?;
    if auth_data.len() < 37 {
        return Err("authenticatorData is too short".to_string());
    }
    let rp_id_hash = Sha256::digest(expected_rp_id.as_bytes());
    // Constant-time compare of the 32-byte rpIdHash.
    if !constant_time_eq(&auth_data[..32], &rp_id_hash) {
        return Err("authenticatorData rpIdHash does not match expected_rp_id".to_string());
    }
    let flags = auth_data[32];
    if flags & AUTH_DATA_FLAG_UP == 0 {
        return Err("authenticatorData user-present flag is not set".to_string());
    }
    let require_uv = opts.require_user_verification.unwrap_or(true);
    if require_uv && flags & AUTH_DATA_FLAG_UV == 0 {
        return Err("authenticatorData user-verified flag is not set".to_string());
    }

    let public_key_b64 = receipt
        .signer_public_key
        .as_ref()
        .ok_or("missing signature or public key")?;
    let cose_buf = STANDARD
        .decode(public_key_b64)
        .map_err(|_| "invalid signerPublicKey base64".to_string())?;
    let verifying_key = parse_cose_p256_key(&cose_buf)?;

    let signature_b64 = receipt
        .signature
        .as_ref()
        .ok_or("missing signature or public key")?;
    let sig_bytes = STANDARD
        .decode(signature_b64)
        .map_err(|_| "invalid signature base64".to_string())?;

    let client_data_hash = Sha256::digest(&client_data_buf);
    let mut signed_data = auth_data.clone();
    signed_data.extend_from_slice(&client_data_hash);

    if verify_p256_signature(&verifying_key, &signed_data, &sig_bytes) {
        Ok(())
    } else {
        Err("WebAuthn signature does not verify against signer key".to_string())
    }
}

/// Constant-time equality for equal-length byte slices.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}
