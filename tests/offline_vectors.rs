//! The Rust SDK against the shared offline-approval conformance vectors
//! (packages/mcp-schemas/vectors/offline-approval-vectors.json, docs/OFFLINE-APPROVAL-SDK.md), run
//! section by section the way the reference harness `packages/sdk/src/offline-vectors.test.ts` runs
//! them. Every section and every case must pass.

mod common;

use std::cell::Cell;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use common::*;
use intyga_sdk::{
    approver_anchor, create_offline_challenge, decode_challenge_envelope,
    decode_signature_envelope, encode_signature_envelope, parse_trust_anchor_file, requirement_for,
    sign_challenge_envelope, trust_anchor_approvers, use_offline_approval, verify_trust_bundle,
    ApprovalWitness, ApproverTrustAnchor, BundleAnchorPurpose, ChallengeOptions, OfflineAction,
    OfflineApprovalOptions, OfflineSigningKey, RequesterIdentity, SignOptions, TrustAnchorPurpose,
    TrustBundle, VerifiedDelegation,
};
use p256::ecdsa::signature::Verifier;
use p256::pkcs8::DecodePublicKey;
use serde_json::{json, Map, Value};

fn cases(section: &str) -> &'static Vec<Value> {
    let cases = v()[section]
        .as_array()
        .unwrap_or_else(|| panic!("section {section} is missing"));
    // An emptied section would otherwise pass by running nothing.
    assert!(!cases.is_empty(), "section {section} has no cases");
    cases
}

fn name(c: &Value) -> &str {
    c["name"].as_str().unwrap_or("(unnamed)")
}

fn ok(c: &Value) -> bool {
    c["ok"].as_bool().expect("case.ok")
}

/// `{dids, keys: {did: resolveKey(did) ?? null}}` for every DID in `probe`.
fn anchor_view(anchor: &ApproverTrustAnchor, probe: &[String]) -> (Value, Map<String, Value>) {
    let ApproverTrustAnchor::DidsMultiKey { dids, resolve } = anchor else {
        panic!("expected a DID-mode multi-key anchor");
    };
    let mut keys = Map::new();
    for did in probe {
        let resolved = resolve(did);
        keys.insert(
            did.clone(),
            if resolved.is_empty() {
                Value::Null
            } else {
                json!(resolved)
            },
        );
    }
    (json!(dids), keys)
}

fn bundle() -> TrustBundle {
    serde_json::from_value(v()["bundle"].clone()).expect("the vectors' bundle parses")
}

#[test]
fn derives_every_published_key_from_its_seed() {
    for (id, p) in v()["people"].as_object().unwrap() {
        for (kind, k) in p["keys"].as_object().unwrap() {
            let derived = spki_of(&key_from_seed(str_of(&k["seed"])));
            assert_eq!(derived, str_of(&k["spki"]), "{id}/{kind}");
        }
    }
}

#[test]
fn trust_bundle() {
    for c in cases("trustBundle") {
        // A case may pin its own gateway key (e.g. `pinned-key-not-rsa`); otherwise the shared one.
        let jwk = c.get("gatewayJwk").unwrap_or(&v()["gatewayJwk"]);
        let r = verify_trust_bundle(str_of(&c["jws"]), jwk, Some(at(str_of(&c["asOf"]))));
        assert_eq!(r.is_ok(), ok(c), "{}: {:?}", name(c), r.as_ref().err());
        if let Ok(b) = r {
            assert_eq!(
                serde_json::to_value(&b).unwrap(),
                c["bundle"],
                "{}",
                name(c)
            );
        }
    }
}

#[test]
fn bundle_anchor() {
    let b = bundle();
    for c in cases("bundleAnchor") {
        let limit: Option<Vec<String>> = serde_json::from_value(c["limitToDids"].clone()).unwrap();
        let purpose = match str_of(&c["purpose"]) {
            "ordinary" => BundleAnchorPurpose::Ordinary,
            "offline-intent" => BundleAnchorPurpose::OfflineIntent,
            other => panic!("unknown purpose {other}"),
        };
        let anchor = approver_anchor(&b, limit.as_deref(), purpose);
        let probe: Vec<String> = c["expect"]["keys"]
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect();
        let (dids, keys) = anchor_view(&anchor, &probe);
        assert_eq!(dids, c["expect"]["dids"], "{c}");
        assert_eq!(Value::Object(keys), c["expect"]["keys"], "{c}");
    }
}

#[test]
fn requirement_for_section() {
    for c in cases("requirementFor") {
        let mut raw = v()["bundle"].clone();
        raw["policy"] = c["policy"].clone();
        raw["unmatchedActionPolicy"] = c["unmatchedActionPolicy"].clone();
        // A bundle the type system cannot hold is one requirement_for could never select from.
        let got = serde_json::from_value::<TrustBundle>(raw)
            .ok()
            .and_then(|b| requirement_for(&b, str_of(&c["actionType"]), str_of(&c["display"])))
            .map(|r| serde_json::to_value(r).unwrap())
            .unwrap_or(Value::Null);
        assert_eq!(got, c["expect"], "{}", name(c));
    }
}

#[test]
fn trust_anchor_file() {
    for c in cases("trustAnchorFile") {
        let purpose = match c["purpose"].as_str() {
            Some("offline") => TrustAnchorPurpose::Offline,
            Some("online") | None => TrustAnchorPurpose::Online,
            Some(other) => panic!("unknown purpose {other}"),
        };
        let got = parse_trust_anchor_file(str_of(&c["text"]), purpose).map(|parsed| {
            let anchor = trust_anchor_approvers(&parsed, None);
            let ApproverTrustAnchor::DidsMultiKey { dids, .. } = &anchor else {
                panic!("expected a DID-mode multi-key anchor");
            };
            let (dids, keys) = anchor_view(&anchor, &dids.clone());
            json!({
                "purpose": parsed.purpose.as_str(),
                "epoch": parsed.epoch,
                "dids": dids,
                "keys": keys,
            })
        });
        assert_eq!(got.is_ok(), ok(c), "{}: {:?}", name(c), got.as_ref().err());
        if let Ok(got) = got {
            assert_eq!(got, c["expect"], "{}", name(c));
        }
    }
}

#[test]
fn create_challenge() {
    let b = bundle();
    for c in cases("createChallenge") {
        let input = &c["input"];
        let action = OfflineAction {
            target: str_of(&input["target"]).into(),
            action_type: str_of(&input["actionType"]).into(),
            display: str_of(&input["display"]).into(),
            params: input["params"].clone(),
        };
        let requester: RequesterIdentity =
            serde_json::from_value(input["requester"].clone()).unwrap();
        let delegation = input.get("delegation").map(|d| VerifiedDelegation {
            delegated_to: serde_json::from_value(d["delegatedTo"].clone()).unwrap(),
            delegated_quorum: d["delegatedQuorum"].as_u64().unwrap() as u32,
            nonce: str_of(&d["nonce"]).into(),
            target: action.target.clone(),
            action_type: action.action_type.clone(),
            params: action.params.clone(),
            signers: Vec::new(),
            ..Default::default()
        });
        // `window_minutes` is an integer, so a fractional window (`fractional-window`, 2.5) cannot
        // reach the API at all: the type boundary is this port's refusal, and the case must still
        // end refused. Anything else non-integral would be a harness bug, so it fails loudly.
        let window_minutes = match input.get("windowMinutes") {
            None => Ok(None),
            Some(w) => match w.as_i64() {
                Some(n) => Ok(Some(n)),
                None => {
                    let f = w.as_f64().expect("windowMinutes is a number");
                    assert!(
                        f.fract() != 0.0,
                        "{}: unexpected windowMinutes {w}",
                        name(c)
                    );
                    Err(format!(
                        "windowMinutes must be a whole number of minutes, got {w}"
                    ))
                }
            },
        };
        let r = window_minutes.and_then(|window_minutes| {
            create_offline_challenge(
                &b,
                &action,
                &requester,
                &ChallengeOptions {
                    window_minutes,
                    as_of: Some(at(str_of(&input["asOf"]))),
                    nonce: input.get("nonce").map(|n| str_of(n).to_string()),
                    delegation,
                },
            )
        });
        assert_eq!(r.is_ok(), ok(c), "{}: {:?}", name(c), r.as_ref().err());
        let Ok(challenge) = r else { continue };
        let got = serde_json::to_value(&challenge).unwrap();
        for (field, want) in c["expect"].as_object().unwrap() {
            assert_eq!(&got[field], want, "{}.{field}", name(c));
        }
    }
}

#[test]
fn challenge_envelope() {
    for c in cases("challengeEnvelope") {
        let r = decode_challenge_envelope(str_of(&c["envelope"]));
        assert_eq!(r.is_ok(), ok(c), "{}: {:?}", name(c), r.as_ref().err());
        if let Ok(decoded) = r {
            assert_eq!(
                serde_json::to_value(&decoded).unwrap(),
                c["expect"],
                "{}",
                name(c)
            );
        }
    }
}

fn witness_view(w: &ApprovalWitness) -> Value {
    json!({
        "signerDid": w.signer_did,
        "signerPublicKey": w.signer_public_key,
        "signature": w.signature,
        "sigAlg": w.sig_alg,
    })
}

#[test]
fn signature_envelope() {
    for c in v()["signatureEnvelope"]["encode"].as_array().unwrap() {
        let witness: ApprovalWitness = serde_json::from_value(c["witness"].clone()).unwrap();
        assert_eq!(encode_signature_envelope(&witness), str_of(&c["envelope"]));
    }
    for c in v()["signatureEnvelope"]["decode"].as_array().unwrap() {
        let r = decode_signature_envelope(str_of(&c["envelope"]));
        assert_eq!(r.is_ok(), ok(c), "{}: {:?}", name(c), r.as_ref().err());
        if let Ok(w) = r {
            assert_eq!(witness_view(&w), c["witness"], "{}", name(c));
        }
    }
}

#[test]
fn sign_challenge() {
    for c in cases("signChallenge") {
        let signer = &c["signer"];
        let r = sign_challenge_envelope(
            str_of(&c["envelope"]),
            &SignOptions {
                private_key: OfflineSigningKey::P256(key_from_seed(seed_of(
                    str_of(&signer["person"]),
                    str_of(&signer["key"]),
                ))),
                signer_did: str_of(&c["signerDid"]).into(),
                as_of: Some(at(str_of(&c["asOf"]))),
            },
        );
        assert_eq!(r.is_ok(), ok(c), "{}: {:?}", name(c), r.as_ref().err());
        let Ok(signed) = r else { continue };
        let w = decode_signature_envelope(&signed.envelope).unwrap();
        let expect = &c["expect"];
        assert_eq!(w.signer_did, str_of(&expect["signerDid"]), "{}", name(c));
        assert_eq!(
            w.signer_public_key,
            str_of(&expect["signerPublicKey"]),
            "{}",
            name(c)
        );
        assert_eq!(
            w.sig_alg.as_deref(),
            Some(str_of(&expect["sigAlg"])),
            "{}",
            name(c)
        );
        let payload = decode_challenge_envelope(str_of(&c["envelope"]))
            .unwrap()
            .canonical_payload;
        let key = p256::ecdsa::VerifyingKey::from_public_key_der(
            &STANDARD.decode(str_of(&expect["signerPublicKey"])).unwrap(),
        )
        .unwrap();
        let sig =
            p256::ecdsa::Signature::from_slice(&STANDARD.decode(&w.signature).unwrap()).unwrap();
        assert!(key.verify(payload.as_bytes(), &sig).is_ok(), "{}", name(c));
    }
}

#[test]
fn offline_approval() {
    for c in cases("offlineApproval") {
        let dir = bundle_dir("vectors");
        let delegation_dir = c["delegation"].as_str().map(|which| {
            let d = dir.path().join("delegations");
            std::fs::create_dir(&d).unwrap();
            std::fs::write(
                d.join(format!("{which}.json")),
                serde_json::to_string(&v()["delegations"][which]).unwrap(),
            )
            .unwrap();
            d
        });
        let action = OfflineAction {
            target: str_of(&c["action"]["target"]).into(),
            action_type: str_of(&c["action"]["actionType"]).into(),
            display: str_of(&c["action"]["display"]).into(),
            params: c["action"]["params"].clone(),
        };
        let collected = Cell::new(false);
        let mut opts =
            OfflineApprovalOptions::new(dir.path(), str_of(&v()["requesterDid"]), |challenge| {
                collected.set(true);
                Ok(c["signers"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|s| match s.get("raw") {
                        Some(raw) => str_of(raw).to_string(),
                        None => {
                            let id = str_of(&s["person"]);
                            let claim = s.get("claimDid").map_or(id, str_of);
                            sig1(id, str_of(&s["key"]), claim, &challenge.canonical_payload)
                        }
                    })
                    .collect())
            });
        opts.delegation_dir = delegation_dir;
        opts.as_of = Some(at(str_of(&c["asOf"])));
        opts.warn = Some(Box::new(|_: &str| {}));

        let r = use_offline_approval(&action, &opts);
        assert_eq!(r.is_ok(), ok(c), "{}: {:?}", name(c), r.as_ref().err());
        let Ok(approval) = r else { continue };
        assert!(collected.get());
        let mut signers = approval.signers.clone();
        signers.sort();
        assert_eq!(json!(signers), c["expect"]["signers"], "{}", name(c));
        assert_eq!(
            json!(approval.via_delegation),
            c["expect"]["viaDelegation"],
            "{}",
            name(c)
        );
    }
}

#[test]
fn every_section_is_exercised() {
    // A section added to the vectors without a harness here would otherwise pass by omission.
    let known = [
        "version",
        "generated",
        "note",
        "keyDerivation",
        "people",
        "gatewayJwk",
        "bundle",
        "bundleJws",
        "trustBundle",
        "bundleAnchor",
        "requirementFor",
        "trustAnchorFile",
        "createChallenge",
        "challengeEnvelope",
        "signatureEnvelope",
        "signChallenge",
        "delegations",
        "requesterDid",
        "offlineApproval",
    ];
    for key in v().as_object().unwrap().keys() {
        assert!(
            known.contains(&key.as_str()),
            "unhandled vector section {key}"
        );
    }
}
