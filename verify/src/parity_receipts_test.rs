use super::*;
use std::collections::BTreeMap;

fn merged(base: &Value, overrides: &Value) -> Value {
    let mut result = base.clone();
    if let Some(fields) = overrides.as_object() {
        result.as_object_mut().unwrap().extend(fields.clone());
    }
    result
}

fn options(raw: &Value) -> VerifyOptions {
    VerifyOptions {
        expected_origin: raw["expectedOrigin"].as_str().map(str::to_owned),
        expected_rp_id: raw["expectedRpId"].as_str().map(str::to_owned),
        as_of_unix_secs: raw["asOf"]
            .as_str()
            .map(|s| parse_rfc3339_utc_secs(s).unwrap()),
        clock_skew_seconds: raw["clockSkewSeconds"].as_i64(),
        ..Default::default()
    }
}

#[test]
fn shared_platform_and_authority_receipts() {
    let vectors: Value = serde_json::from_str(
        &std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/vectors/verifier-parity-vectors.json"
        ))
        .unwrap(),
    )
    .unwrap();
    let keys: BTreeMap<String, Value> = vectors["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|key| (key["id"].as_str().unwrap().to_owned(), key.clone()))
        .collect();
    let section = &vectors["approvals"];
    for case in section["cases"].as_array().unwrap() {
        let e = merged(&section["expected"], &case["expected"]);
        let expected = Expected {
            target: e["target"].as_str().unwrap().into(),
            nonce: e["nonce"].as_str().unwrap().into(),
            action_type: e["actionType"].as_str().unwrap().into(),
            params: e["params"].clone(),
            approvers: ApproverTrustAnchor::PublicKeys(
                e["approverKeyIds"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|id| {
                        keys[id.as_str().unwrap()]["spkiB64"]
                            .as_str()
                            .unwrap()
                            .to_owned()
                    })
                    .collect(),
            ),
        };
        let receipt: ApprovalReceipt = serde_json::from_value(case["receipt"].clone()).unwrap();
        let result = verify_approval_receipt_with_options(
            &receipt,
            &expected,
            &options(&merged(&section["options"], &case["options"])),
        );
        assert_eq!(
            result.is_ok(),
            case["ok"].as_bool().unwrap(),
            "{}: {:?}",
            case["name"],
            result
        );
        // A refusal that lands for the wrong reason, or an acceptance crediting the wrong
        // identities, is the divergence these fixtures exist to catch.
        if let Some(fragment) = case["reasonIncludes"].as_str() {
            let reason = result.clone().unwrap_err();
            assert!(
                reason.contains(fragment),
                "{}: reason {reason:?} does not contain {fragment:?}",
                case["name"]
            );
        }
        if let Some(signers) = case.get("signers") {
            assert_eq!(
                serde_json::to_value(result.unwrap()).unwrap(),
                *signers,
                "{}",
                case["name"]
            );
        }
    }
    let section = &vectors["platform"];
    for case in section["cases"].as_array().unwrap() {
        let e = merged(&section["expected"], &case["expected"]);
        let expected = PlatformReceiptExpectation {
            approvers: ApproverTrustAnchor::PublicKeys(
                e["approverKeyIds"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|id| {
                        keys[id.as_str().unwrap()]["coseB64"]
                            .as_str()
                            .unwrap()
                            .to_owned()
                    })
                    .collect(),
            ),
            payload_hash: e["payloadHash"].as_str().unwrap().into(),
            rp_id: e["rpId"].as_str().unwrap().into(),
            nonce: e["nonce"].as_str().unwrap().into(),
            subject_external_id: e["subjectExternalId"].as_str().map(str::to_owned),
        };
        let receipt: PlatformReceipt = serde_json::from_value(case["receipt"].clone()).unwrap();
        let result = verify_platform_receipt(
            &receipt,
            &expected,
            &options(&merged(&section["options"], &case["options"])),
        );
        assert_eq!(
            result.is_ok(),
            case["ok"].as_bool().unwrap(),
            "{}: {:?}",
            case["name"],
            result
        );
        if let Some(signers) = case.get("signers") {
            assert_eq!(
                serde_json::to_value(result.unwrap()).unwrap(),
                *signers,
                "{}",
                case["name"]
            );
        }
    }
    let section = &vectors["agentAuthority"];
    for case in section["cases"].as_array().unwrap() {
        let e = merged(&section["expected"], &case["expected"]);
        let mappings: BTreeMap<String, Vec<String>> = e["approverDids"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(did, ids)| {
                (
                    did.clone(),
                    ids.as_array()
                        .unwrap()
                        .iter()
                        .map(|id| {
                            keys[id.as_str().unwrap()]["spkiB64"]
                                .as_str()
                                .unwrap()
                                .to_owned()
                        })
                        .collect(),
                )
            })
            .collect();
        let expected = AgentAuthorityExpectation {
            approvers: if let Some(ids) = e["approverKeyIds"].as_array() {
                ApproverTrustAnchor::PublicKeys(
                    ids.iter()
                        .map(|id| {
                            keys[id.as_str().unwrap()]["spkiB64"]
                                .as_str()
                                .unwrap()
                                .to_owned()
                        })
                        .collect(),
                )
            } else {
                ApproverTrustAnchor::DidsMultiKey {
                    dids: mappings.keys().cloned().collect(),
                    resolve: Box::new(move |did| mappings.get(did).cloned().unwrap_or_default()),
                }
            },
            target: e["target"].as_str().unwrap().into(),
            agent_did: e["agentDid"].as_str().unwrap().into(),
        };
        let receipt: ApprovalReceipt = serde_json::from_value(case["receipt"].clone()).unwrap();
        let result = verify_agent_authority(
            &receipt,
            &expected,
            &options(&merged(&section["options"], &case["options"])),
        );
        assert_eq!(
            result.is_ok(),
            case["ok"].as_bool().unwrap(),
            "{}: {:?}",
            case["name"],
            result
        );
        if let Ok(authority) = result {
            if let Some(signers) = case.get("signers") {
                assert_eq!(
                    serde_json::to_value(authority.signers).unwrap(),
                    *signers,
                    "{}",
                    case["name"]
                );
            }
            if let Some(patterns) = case.get("actionPatterns") {
                assert_eq!(
                    serde_json::to_value(authority.action_patterns).unwrap(),
                    *patterns,
                    "{}",
                    case["name"]
                );
            }
        }
    }
}

#[test]
fn shared_canonical_authority_and_platform_builders() {
    let v: Value = serde_json::from_str(
        &std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/vectors/canonical-vectors.json"
        ))
        .unwrap(),
    )
    .unwrap();
    for item in v["agentAuthorityPayloads"].as_array().unwrap() {
        let i = &item["input"];
        let requester: RequesterIdentity = serde_json::from_value(i["requester"].clone()).unwrap();
        let requirement: ApprovalRequirement =
            serde_json::from_value(i["requirement"].clone()).unwrap();
        let patterns: Vec<String> = serde_json::from_value(i["actionPatterns"].clone()).unwrap();
        let got = canonical_agent_authority_payload(
            i["target"].as_str().unwrap(),
            &patterns,
            i["actionDescription"].as_str().unwrap(),
            i["agentDid"].as_str().unwrap(),
            &requester,
            &requirement,
            i["nonce"].as_str().unwrap(),
            i["sealedAt"].as_str().unwrap(),
            i["expiresAt"].as_str().unwrap(),
        )
        .unwrap();
        assert_eq!(got, item["expected"].as_str().unwrap());
    }
    for item in v["platformIntentPayloads"]["cases"].as_array().unwrap() {
        let i = &item["input"];
        let got = canonical_platform_intent_payload(
            i["payloadHash"].as_str().unwrap(),
            i["rpId"].as_str().unwrap(),
            i["subjectExternalId"].as_str().unwrap(),
            i["signedAt"].as_str().unwrap(),
            i["expiresAt"].as_str().unwrap(),
            i["nonce"].as_str().unwrap(),
        )
        .unwrap();
        assert_eq!(got, item["expected"].as_str().unwrap());
    }
}
