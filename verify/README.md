# intyga-verify — Offline INTYGA receipt verification for Rust

[![Release gated by INTYGA](https://www.intyga.com/badges/release-gated-by-intyga.svg)](https://www.intyga.com/use-cases/package-publishing)

Independently confirm that a human cryptographically approved **exactly** the action you are about to run — in your own process, with no INTYGA secret and no network call. You recompute the canonical payload from your own parameters, check it byte-matches what was signed, and verify the human's **ES256** or **WebAuthn** signature.

Depends only on the standard Rust crypto crates (`p256`, `sha2`, …) — no bespoke cryptography. Its canonicalization is held byte-identical to the TypeScript, Python, Go, and Java verifiers by shared cross-language test vectors, for portable content (DIV §4.1.1). One known exception inside the portable range: an integer in `(2^53, 1e16)` canonicalizes to its exact digits here, as it does in Java and Python, while a double-based parser (TypeScript, Go) rounds it at parse time — the same document then yields different bytes and the mismatch reads as tampering. Keep integers within `±2^53` or carry larger values as decimal strings.

> Part of the INTYGA multi-language verifier set (TypeScript, Python, Go, Rust, Java).

## Add it

```sh
cargo add intyga-verify
```

## Verify an approval receipt

```rust
use intyga_verify::{verify_approval_receipt_with_options, ApproverTrustAnchor, Expected, VerifyOptions};
use serde_json::json;

// `expected` is what you are ABOUT to execute. `target` is YOUR OWN identifier (Target
// Isolation), `nonce` is the challenge YOU issued, and `approvers` is the key set YOU trust —
// all required, and none of them ever read from the receipt.
let expected = Expected {
    target: "prod-db-cluster-01".into(),
    nonce: nonce.clone(),
    action_type: "wipe_production".into(),
    params: json!({ "target": "prod-db-1" }),
    approvers: ApproverTrustAnchor::PublicKeys(vec![approver_spki_b64]),
};
// On success you get the DISTINCT approver identities whose signatures verified, sorted — the
// keys themselves in `PublicKeys` mode, the DIDs in identity mode. Empty for an AUTO_APPROVED
// receipt, because no human signed it.
// REQUIRED for passkey receipts (the normal flow): the approval console's exact origin and RP ID,
// from the trust-anchor file exported in the console (its `webauthn` block).
let opts = VerifyOptions {
    expected_origin: std::env::var("INTYGA_WEBAUTHN_ORIGIN").ok(),
    expected_rp_id: std::env::var("INTYGA_WEBAUTHN_RP_ID").ok(),
    ..Default::default()
};
let signers = verify_approval_receipt_with_options(&receipt, &expected, &opts)?;
```

**Quorum trust.** Key-only trust is accepted only for a one-approval requirement without
`requesterCannotApprove`. Multi-approver quorums and separation of duties require a DID/identity
anchor and otherwise fail closed (DIV §5 step 3b). Several credentials for one DID count as one
approver. Delegations require identity trust regardless of quorum size.

**Requirement floor (DIV §5 step 3d).** The signed `requirement` is the signers' own statement: its
signature stops a third party from altering it, not the approvers it constrains from writing a weaker
one. One approver who is also the requester can sign a 1-of-1 payload alone. **Without a floor this
verifier proves only the quorum the signers stated.** When you know the rule, set
`Expected { requirement: Some(RequirementFloor { required_approvals: 3, requester_cannot_approve: true, require_hardware_key: false }), .. }`
(`AgentAuthorityExpectation::requirement` for seals). `None` keeps the previous behaviour; the field
is new, so existing struct literals need `requirement: None`.
A signed requirement weaker on any field — fewer approvals, no four-eyes or no hardware key where the
floor demands one — is refused before any signature is counted, with a reason starting "signed
requirement is weaker than the relying party's policy"; an equal or stricter one passes. A malformed
floor (quorum below 1) is refused rather than ignored. The same field exists on the delegation
expectation (pass the ordinary rule) and the agent-authority expectation (your sealing policy).

`verify_approval_receipt(&receipt, &expected)` is a shorthand for ES256 receipts. One byte of drift — a swapped target, an appended region — and verification fails, because the signature was over the exact bytes you just recomputed.

## WebAuthn (passkey) receipts

A passkey assertion harvested at *any* relying party would otherwise verify, so WebAuthn receipts require you to pin the expected origin and RP ID:

```rust
let opts = VerifyOptions {
    expected_origin: Some("https://app.example.com".into()),
    expected_rp_id: Some("app.example.com".into()),
    ..Default::default()
};
verify_approval_receipt_with_options(&receipt, &expected, &opts)?;
```

`require_user_verification` defaults to true (demands the User-Verified flag); set `Some(false)` to accept mere user presence (`verify_platform_receipt` ignores it: DIV §5c.3 requires user verification unconditionally). Policy `AUTO_APPROVED` receipts carry no human signature and fail closed unless you opt in with `allow_auto_approved: true`.

## Receipt and audit verification

Use `verify_platform_receipt` and `verify_agent_authority` for the additional DIV receipt types.
`bundle::verify_bundle` verifies single proofs; `bundle::verify_evidence_bundle_with_options`
adds caller-policy anchoring to multi-event exports. The existing `verify_evidence_bundle` entry
point remains available for callers that only pin roots. Supply `EvidenceAnchorSet::ByCheckpoint`
for checkpoint-attributed caller anchors, or `Flat` for a flat candidate list.
`chain::verify_roots_chain` checks continuity; `ledger::verify_signed_anchor` supports all three
anchor signature algorithms, while the existing `verify_anchor_signature` ES256 helper remains.

The five language verifiers support the same receipt and audit verification features, pinned by
`canonical-vectors.json`, `ledger-vectors.json` and `verifier-parity-vectors.json`:

- DIV approval/offline/delegation receipts, agent-authority seals (§5b), and platform receipts (§5c).
  Platform receipts require WebAuthn and caller-pinned digest, RP, nonce, origin and subject keys.
  Authority/delegation verification never substitutes for approval of an action.
- Self-certifying DIDs, with explicit caller key mappings taking precedence.
- DEWP single-event and multi-event proof bundles: inclusion, canonical content/header binding,
  embedded ES256 signatures, tenant identity, sequence gaps/duplicates and claimed range endpoints.
- Checkpoint continuity (§5.4), and anchor quorum (§5.3) under the caller's policy: ES256, Ed25519,
  RSA-PSS, Rekor SET/payload verification, and opt-in RFC 3161/CMS verification.

Set `ExternalAnchorKeys::rekor_issuer` whenever a policy trusts multiple issuers. Legacy unscoped
Rekor trust is accepted only when the policy has one unique trusted issuer.

Trust inputs must come from the caller. A root carried in the bundle proves only internal
consistency; a producer's `externallyAnchored` flag is a claim, not verification. Bundle-carried
anchors can count under caller-trusted keys, but only independently fetched, checkpoint-attributed
anchors may establish divergence. For multi-checkpoint exports, key caller anchors by checkpoint ID
or root; a flat list cannot establish exact attribution across checkpoints.

RFC 3161 anchors count only with issuer-specific `ExternalAnchorKeys::rfc3161` trust and OpenSSL 3.
`rfc3161::verify_rfc3161_anchor` isolates OpenSSL from host trust and network fetching, pins the
signer certificate, and requires offline CRL checking or explicit `unchecked` revocation.
CMS signer digests are restricted to SHA-256, SHA-384, or SHA-512. `verification_time` is
caller-selected; its default rounds up by at most one second for fresh
fractional timestamps. Historical results depend on retained CA, intermediate, and CRL material.
Limits remain explicit: no NDJSON evidence streaming and no WEBHOOK anchor verifier. WEBHOOK anchors
do not count toward quorum. No implementation claims the complete
DEWP Extended Profile (§9.2). WebAuthn audit signatures require profile-carried assertion data and caller trust; verify the
full DIV receipt separately for authorization and quorum. Offline authority verification checks the seal, not subsequent online
revocation. Verification does not consume a nonce or prove execution.

The short DIV display-code derivation and document-signing canonical builder remain outside this
port's API; neither is used to authenticate a receipt. Portable-number limits are unchanged.

## Also available in
- TypeScript — [`@intyga/verify`](https://github.com/intyga-dev/verify)
- Python — [`verify-python`](https://github.com/intyga-dev/verify-python)
- Go — [`verify-go`](https://github.com/intyga-dev/verify-go)
- Java — [`verify-java`](https://github.com/intyga-dev/verify-java)

For a full client that *requests* approvals (not just verifies them), see [`sdk-rust`](https://github.com/intyga-dev/sdk-rust) — it bundles this verifier, so you don't need both.

## License

Apache-2.0.


### Audit event signatures

The `trust.intyga.audit.v1` profile carries WebAuthn assertion data in the committed
`canonical.metadata.webauthn.authenticatorData` and `clientDataJSON` fields. Both single-proof and
bulk-evidence verification check these assertions when given caller-owned signer trust. This is a
signature over the exact `signedPayload`, not approval quorum, action authorization, hardware
attestation, current credential status or proof that the deploy executed. Verify the full DIV receipt
against the expected operation and approval policy for those authorization checks.

The per-event signature result distinguishes `verified`, `invalid`, `not_checked` (missing trust,
missing material or unsupported algorithm) and `not_applicable` (unsigned/system or AUTO_APPROVED).
A reason accompanies each status. `trusted: true` requires a valid signature under a caller-supplied
key mapped to that signer DID. WebAuthn requires caller-selected origin and RP ID, user presence and
user verification, and refuses cross-origin assertions. Supply COSE keys for WebAuthn and SPKI keys
for ES256. Multiple keys per DID support deliberate key rotation; the evidence's key is never added
to the caller's trusted set.

Without a signature policy, legacy ES256 checks still use the embedded key and report `trusted: false`;
WebAuthn reports `not_checked`. Diagnostic ledger validity does not imply signature validity. The
strict signature option requires **every selected entry** to have a verified, caller-trusted signature;
unsigned, redacted, incomplete and invalid entries fail that option. Anchor quorum is a separate policy.

Set `signature_policy: Some(AuditSignaturePolicy { trusted_signers, expected_origin, expected_rp_id })`
and `require_signatures: true` in bundle/evidence options.
