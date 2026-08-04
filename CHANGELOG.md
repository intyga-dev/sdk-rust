# Changelog

All notable changes to `intyga-sdk` (Rust) are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [SemVer](https://semver.org/).

## [Unreleased]

- Re-export `ApproverTrustAnchor` alongside `Expected` — `Expected.approvers` is a required field
  of that type, so verification was previously unconstructable from this crate's re-exports alone.

## [0.1.0]

Initial public release.

- Blocking client with a pluggable `Transport` (built-in `ureq` transport behind the default
  `ureq-transport` feature); `target` is required (DIV Target Isolation).
- Re-exports the `intyga-verify` offline receipt verifier.
