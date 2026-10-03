# Changelog

All notable changes to `intyga-verify` (Rust) are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [SemVer](https://semver.org/).

## [Unreleased]

## [1.1.0]

- No code change. The matched set moves together (`pnpm test:versions`); this release carries the
  new `@intyga/sdk` CLI options and the `require-approval` Action update.

## [1.0.0]

- Verify profile-carried WebAuthn audit signatures with caller-trusted signer keys, origin and RP ID.
  Report explicit per-event signature status and key trust; add strict signature acceptance for
  single and bulk evidence. Audit signature checks do not replace full approval-receipt verification.

- **DIV/DEWP 1.0 pre-release correction (2026-09-27 review L15-L18, I7, I8):** signed timestamps use one
  strict RFC 3339 grammar (the parser accepted lowercase `t`/`z`, a comma fraction, any number of
  fraction digits, `:60` and day 31 of every month). A WebAuthn `topOrigin` differing from `origin`
  is refused. `verify_platform_receipt` ignores `require_user_verification: Some(false)`. A key
  mapped to two DIDs counts once toward a quorum. RSA-PSS anchors require a 32-byte salt and a
  2048-bit modulus (the salt used to be recovered from the signature). Divergence evidence is held
  to the quorum's seq-range and witness-time rules; a Rekor entry establishes divergence only with
  submitter keys pinned. Pinned in all five languages by the `verifierInputHardening` parity vectors; no canonical bytes change for valid input.
- **Breaking (DIV 1.0 pre-release correction, H1):** `Expected` and `AgentAuthorityExpectation` gain
  `requirement: Option<RequirementFloor>`, applied by `verify_approval_receipt*`, `verify_delegation`
  and `verify_agent_authority`; existing struct literals need `requirement: None`. Export
  `WEAKER_REQUIREMENT_REASON`. The signed `requirement` is authored by the signers, so one approver
  (possibly the requester) could self-compose a 1-of-1 receipt for a 3-of-3 four-eyes action and it
  verified. A weaker signed requirement is now refused before any signature is counted when the caller
  supplies its own rule (DIV §5 step 3d), on approval, offline, delegation and agent-authority
  verification; the reason starts "signed requirement is weaker than the relying party's policy".
  Omitting the floor keeps the previous behaviour, which proves only the quorum the signers stated. No
  signed byte changes; shared parity vectors pin it in all five languages.
- **DEWP evidence verification (1.0 pre-release correction, Sep 2026):** an entry with a canonical
  preimage reads `tenantSeq` only from it (null ⇒ no counter) and fails when its redaction counter
  disagrees; a tenant-bound entry fails when the bundle declares no tenant (`tenant` may now be
  absent); a preimage under an unknown profile fails; repeated leaves/seqs and inconsistent leaf
  counts fail; a checkpoint with no `chain_hash`/`anchored_at` is never anchored. New
  `EvidenceVerifyOptions::trusted_checkpoints` and `BundleVerifyOptions::trusted_checkpoint`
  (`ledger::TrustedCheckpoint`) take caller-held roots-file records; a single proof counts a
  Rekor/TSA anchor only against one. `SignedAnchor::is_well_formed` requires a registered algorithm.
  Pinned by the shared `dewpEvidenceHardening` vectors.
- **DIV 1.0 pre-release correction (PK-11):** under a signed `requireHardwareKey`, a WEBAUTHN witness
  whose signed authenticatorData carries the Backup Eligible or Backup State flag no longer counts
  toward the quorum (DIV §4.4.5 rule 6) — a relying party now catches an issuer that let a synced
  passkey sign a hardware-pinned action. No signed byte changes; shared parity vectors pin it in all
  five languages.
- **Breaking (DEWP 1.0 pre-release correction):** the anchored preimage is now
  `[dailyRoot, timestamp, issuer, algorithm, seqStart, seqEnd, chainHash]`; anchors lacking the
  position fields never verify. External witness times (Rekor `integratedTime`, TSA `genTime`) must
  fall within `maxAnchorLagSeconds` (default 86400) after — or 300 s before — the checkpoint's claimed
  time; anchors must match the checkpoint's seq range, chain hash and `anchoredAt`; evidence-bundle
  chain hashes are recomputed; verdicts expose per-issuer witness times; an optional pinned Rekor
  submitter key is enforced. A supplied root is reported as `rootSource: "caller-supplied"` (was
  `"independent"`).
- A non-empty `allowedAaguids` is refused exactly like `requireHardwareKey`: bare-key witnesses do not
  count and offline proofs are rejected (DIV §4.3.2/§5a.3).

- Add opt-in RFC 3161/CMS verification and quorum/divergence integration through an isolated
  OpenSSL 3 adapter with signer-certificate pinning and explicit CRL or unchecked revocation.
- Bind Rekor trust to `rekor_issuer` for multi-issuer policies so one log cannot impersonate several
  quorum identities; legacy unscoped keys remain valid only for single-issuer policies.

- Enforce DIV §5 identity trust for multi-approver quorums; preserve DIV §4.4.2 ES256
  compatibility for absent/null/unknown witness labels, while refusing AUTO_APPROVED witnesses.
- Validate DEWP protocol, version and declared hash/serialization/Merkle algorithms before
  accepting proof or evidence bundles. Legacy numeric revisions 1/2 remain supported without
  a protocol declaration. Shared cross-language fixtures cover these contracts.

- **Wire format: DIV v1 agent intents now sign `action`, `agent`, `session`, `nbf`, and `exp` instead of ordinary `expiresAt`; `div-agent-authority` requires `parentReceiptHash` (null for a root).** Older §5b seals lacking that key cannot verify under this pre-release profile and must be re-sealed. All canonical producers, five verifier ports and vectors must move together; the ordinary HUMAN/SERVICE intent keeps `expiresAt`.

- **Wire format: the DIV Intent Payload gained a REQUIRED `evidence` field, and it must be `null`.**
  `div-intent-verification` and `div-offline-intent` now carry `"evidence":null` in the signed bytes
  (DIV §4.3.4); `div-delegation`, `div-agent-authority` and `div-platform-intent` deliberately do
  not. `null` is signed and load-bearing, exactly as `requester.attestation`'s null is: it is the
  payload's explicit statement that the authorization was not conditioned on any external fact.
  Verification refuses a payload whose `evidence` key is absent, and refuses any non-`null` value
  rather than treating it as unconditioned — the same fail-closed-on-unknown rule as the
  `signerClass` registry, and checked before Local Payload Reconstruction so an unsupported payload
  shape does not surface as a parameter mismatch. Absent and `null` are distinguished explicitly;
  collapsing them would make the check a no-op. All golden vectors were regenerated.

- Align cross-language receipt and audit verification: platform receipts, agent-authority seals,
  self-certifying DID trust, single/multi-event bundles, embedded ES256 signatures, tenant sequence
  checks, checkpoint continuity, anchor quorum and Rekor. Shared executable fixtures cover valid
  artifacts and refusals; no wire format changes.
- Refuse unknown witness signature algorithms. Require identity-bound trust when the signed
  `requesterCannotApprove` rule is set; key-only trust cannot enforce requester identity.
- **BREAKING: `verify_approval_receipt` and `verify_approval_receipt_with_options` return
  `Result<Vec<String>, String>`** — the distinct approver identities whose signatures verified,
  sorted, as the TypeScript, Go, Java and Python verifiers already did. The set was computed and
  discarded, so Rust alone could not answer "who approved this". The identity is the key in
  `PublicKeys` mode and the DID in identity mode; it is empty for an `AUTO_APPROVED` receipt,
  because no human signed it. Call sites using `?` or `.is_err()` are unaffected; only a comparison
  against `Ok(())` needs updating.

- Recheck a verified delegation's expiry when it is used, under the approval call's
  `as_of_unix_secs`, clock skew and explicit `allow_expired` forensic override.
- **Refuse a forward-dated offline proof or delegation (DIV §5a.3 rule 3, §5a.6 step 1).** The
  window caps bounded a proof's WIDTH but never its POSITION, so a quorum-signed proof dated years
  ahead with a compliant 60-minute (or 72-hour) window verified today and kept verifying until that
  date. The check is unconditional — the audit/`allow_expired` override re-examines a proof that was
  valid and has lapsed, and does not reach one dated in the future.
- **Refuse a signed `requirement.requiredApprovals` below 1 (DIV §4.3.2).** §5 step 7's "at least
  `requiredApprovals`" is satisfied vacuously by 0, so the minimum is now enforced explicitly
  instead of by an undocumented floor.


Initial public release.

- Offline approval-receipt verification (ES256 and WebAuthn) against a caller-supplied trust
  anchor — no INTYGA secret, no network. Standard Rust crypto crates (`p256`, `sha2`, …), no
  bespoke cryptography.
- DEWP Core Profile primitives and §5.2 single-anchor signature verification, pinned by the shared
  cross-language golden vectors. §5.3 anchor-quorum evaluation and evidence-bundle parsing are
  deliberately out of scope — see the README's limits section.
