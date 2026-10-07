//! Rust client for Intyga. The primitive is uniform: request a challenge → a human approves with a
//! passkey or security key → poll until resolved. It works for AI agents, humans, and any backend
//! service; the only difference is which API key/token you hold.
//!
//! Offline receipt verification lives in the standalone `intyga-verify` crate and is re-exported here so
//! a relying party can re-verify what was signed without a second dependency.
//!
//! Offline approval (DIV §5a) — trust bundles, challenge and signature envelopes, signing as an
//! approver, single-use redemption and reconciliation — lives in [`offline`], [`trust_bundle`],
//! [`trust_anchor`] and [`approval_policy`], re-exported at the crate root. The client's fallback is
//! [`Client::require_approval_with_offline`]. Contract: docs/OFFLINE-APPROVAL-SDK.md.

use std::path::Path;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub mod approval_policy;
pub mod offline;
mod support;
pub mod trust_anchor;
pub mod trust_bundle;

pub use approval_policy::{
    lost_approval_constraints, select_approval_rule, valid_approval_action_id,
    validate_exact_approval_policy, ApprovalPolicyConflict,
};
pub use offline::{
    assemble_offline_receipt, clear_pending_approval, create_offline_challenge,
    decode_challenge_envelope, decode_signature_envelope, encode_signature_envelope,
    iso_timestamp, parse_timestamp, pending_approvals, sign_challenge_envelope,
    use_offline_approval, verification_code, ChallengeOptions, CollectSignatures,
    DecodedChallenge, FileRedemptionStore, OfflineAction, OfflineApproval,
    OfflineApprovalOptions, OfflineChallenge, OfflineSigningKey, PendingApproval,
    RedemptionStore, SignOptions, SignedChallenge, WarnSink, CHALLENGE_ENVELOPE_PREFIX,
    DEFAULT_OFFLINE_WINDOW_MINUTES, SIGNATURE_ENVELOPE_PREFIX,
};
pub use trust_anchor::{
    parse_trust_anchor_file, trust_anchor_approvers, TrustAnchorFile, TrustAnchorPurpose,
    WebAuthnExpectation, TRUST_ANCHOR_FILE_TYPE,
};
pub use trust_bundle::{
    approver_anchor, check_trust_bundle_freshness, load_trust_bundle, requirement_for,
    save_trust_bundle, verify_trust_bundle, BundleAnchorPurpose, BundleApprover, BundlePolicy,
    ResolvedRequirement, TrustBundle, TrustBundleFiles, UnmatchedActionPolicy,
    DIV_TRUST_BUNDLE_TYPE, MAX_TRUST_BUNDLE_AGE_DAYS,
};

// Re-export the offline verifier so SDK consumers can check receipts in-process.
// ApproverTrustAnchor is part of this set deliberately: `Expected.approvers` is a required field of
// that type, so without the re-export no SDK consumer could construct a verification call at all
// without adding the verifier as a second direct dependency. The offline-approval types travel with
// it for the same reason: `create_offline_challenge` takes a RequesterIdentity, a delegation is a
// VerifiedDelegation, and a receipt carries ApprovalWitness and ApprovalRequirement values.
pub use intyga_verify::{
    verify_approval_receipt, verify_approval_receipt_with_options, verify_delegation,
    ApprovalReceipt, ApprovalRequirement, ApprovalWitness, ApproverTrustAnchor, Expected,
    RequesterIdentity, RequirementFloor, VerifiedDelegation, VerifyOptions,
};

/// The lifecycle state of a challenge.
///
/// `Consumed` means the approval was real but has ALREADY BEEN REDEEMED — single-use is enforced by
/// the gateway. Treat it as not authorized: only `Approved` permits execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApprovalStatus {
    #[serde(rename = "APPROVED")]
    Approved,
    #[serde(rename = "CONSUMED")]
    Consumed,
    #[serde(rename = "DENIED")]
    Denied,
    #[serde(rename = "EXPIRED")]
    Expired,
    #[serde(rename = "PENDING")]
    Pending,
    /// An OFFLINE APPROVAL authorized this — real human signatures collected out of band at incident
    /// time because the gateway could not be reached (DIV §5a). Only
    /// [`Client::require_approval_with_offline`] returns it; the gateway never does.
    ///
    /// Deliberately NOT `Approved`. The usual guard is `if r.status != ApprovalStatus::Approved`, so
    /// a distinct status means adding offline approval to a service cannot silently start permitting
    /// things — handling it is a conscious change at the call site.
    #[serde(rename = "OFFLINE_APPROVED")]
    OfflineApproved,
}

/// Structured, WYSIWYS-bound details of an approval request.
#[derive(Debug, Clone, Default)]
pub struct AuthorizeOptions {
    /// The relying party / execution environment this approval is bound to (DIV §3 Invariant 5,
    /// Target Isolation). REQUIRED, and asserted from YOUR own identity.
    ///
    /// Leaving it `None` is not neutral: the gateway defaults a missing target to the literal
    /// `"global"`, so the signed intent binds no environment and an approval minted for this
    /// service verifies at every other relying party that also asserts `"global"` — the exact
    /// cross-service replay Target Isolation exists to prevent. Refused client-side rather than
    /// quietly defaulted, because `intyga_verify::Expected` has no default for it either.
    pub target: Option<String>,
    /// Action identifier, e.g. "wire_transfer". Bound into the signed payload.
    pub action_type: Option<String>,
    /// The exact structured variables that will execute — displayed to the approver AND signed.
    pub params: Option<Value>,
    /// RP-asserted continuity context for an AI agent; the PEP must recheck it at execution.
    pub agent_context: Option<Value>,
    /// Optional override for the server's default challenge TTL, in seconds.
    pub timeout_seconds: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuthorizeResponse {
    pub nonce: String,
    pub status: ApprovalStatus,
    #[serde(rename = "agentContext", default)]
    pub agent_context: Option<Value>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ConsumeResult {
    pub ok: bool,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ApprovalResult {
    pub status: ApprovalStatus,
    /// Issuer context retained from challenge creation, independently of the receipt.
    #[serde(rename = "agentContext", default)]
    pub agent_context: Option<Value>,
    #[serde(rename = "signatureHash", default)]
    pub signature_hash: Option<String>,
    #[serde(default)]
    pub receipt: Option<ApprovalReceipt>,
    /// The challenge this result belongs to. Set by [`Client::require_approval`] so callers can pass it
    /// as `expected.nonce` to the verifier and record it as redeemed for their own single-use check.
    #[serde(default)]
    pub nonce: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct VerifyResult {
    pub verified: bool,
    pub status: String,
    #[serde(rename = "documentHash")]
    pub document_hash: String,
    #[serde(rename = "signerDid", default)]
    pub signer_did: Option<String>,
    #[serde(rename = "signedAt", default)]
    pub signed_at: Option<String>,
    #[serde(rename = "signatureHash", default)]
    pub signature_hash: Option<String>,
}

/// A minimal HTTP response the [`Transport`] returns.
pub struct HttpResponse {
    pub status: u16,
    pub body: String,
}

/// Why a [`Transport`] could not return an [`HttpResponse`].
///
/// The variant is a security decision, not a detail: [`TransportError::NoResponse`] is the ONLY
/// failure that tells [`Client::require_approval_with_offline`] the gateway could not be asked, and
/// so the only one that may start an out-of-band approval (DIV §5a). Everything else — including any
/// error built from a plain `String` — is treated as an answer, and never routes offline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportError {
    /// No HTTP response was received: DNS failure, connection refused or reset, TLS handshake
    /// failure, a timeout before the status line. Never use it for a request that got a status back.
    NoResponse(String),
    /// A response arrived but its body could not be read: an I/O error mid-body, a body over the
    /// transport's size limit, invalid UTF-8. Something answered; never "could not ask".
    UnreadableBody(String),
    /// Any other failure: an unparseable status line or header, a local configuration problem, or
    /// an error this transport did not classify. Never "could not ask".
    Other(String),
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransportError::NoResponse(m)
            | TransportError::UnreadableBody(m)
            | TransportError::Other(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for TransportError {}

/// An unclassified error is [`TransportError::Other`], which fails CLOSED: a transport that maps its
/// errors with `.map_err(|e| e.to_string().into())` can never route a refusal offline.
impl From<String> for TransportError {
    fn from(message: String) -> Self {
        TransportError::Other(message)
    }
}

impl From<&str> for TransportError {
    fn from(message: &str) -> Self {
        TransportError::Other(message.to_string())
    }
}

/// Pluggable HTTP transport, so the client logic is testable without real sockets and users can bring
/// their own async/proxy/instrumented client. `headers` is a list of (name, value) pairs.
///
/// **Every HTTP status — 3xx, 4xx and 5xx included — MUST come back as `Ok(HttpResponse)`.** The
/// client decides what a status means: a 4xx is the gateway refusing, and it must reach the client
/// as a status so it is never mistaken for an outage. Many HTTP libraries (ureq among them) return
/// `Err` for a non-2xx by default; unwrap their status error into an `HttpResponse` as the
/// built-in `UreqTransport` does. Return [`TransportError::NoResponse`] only when no HTTP response was
/// received at all, [`TransportError::UnreadableBody`] when the body of a response could not be read,
/// and [`TransportError::Other`] for anything else. Do not follow redirects.
pub trait Transport {
    fn request(
        &self,
        method: &str,
        url: &str,
        headers: &[(&str, &str)],
        body: Option<&str>,
    ) -> Result<HttpResponse, TransportError>;
}

/// Options for constructing a [`Client`].
#[derive(Debug, Clone, Default)]
pub struct ClientOptions {
    /// Must be `https://`. Plain `http://` is accepted only for a loopback host (`localhost`,
    /// `127.0.0.0/8`, `::1`) for local development; anything else is refused at construction,
    /// because every request carries a bearer token or client secret.
    pub gateway_url: String,
    /// A pre-minted bearer token (agent or human). If None, `client_id`/`client_secret` are exchanged.
    pub token: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
}

/// Controls for [`Client::require_approval`].
#[derive(Debug, Clone)]
pub struct RequireApprovalOptions {
    pub authorize: AuthorizeOptions,
    /// Total wait window. Defaults to 120s. Also sent to the gateway as the challenge TTL so the
    /// challenge cannot outlive the wait.
    pub timeout: Duration,
    /// Poll interval. Defaults to 2s.
    pub interval: Duration,
}

impl Default for RequireApprovalOptions {
    fn default() -> Self {
        RequireApprovalOptions {
            authorize: AuthorizeOptions::default(),
            timeout: Duration::from_secs(120),
            interval: Duration::from_secs(2),
        }
    }
}

/// What [`Client::reconcile_offline_approvals`] reported.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReconcileReport {
    /// Acknowledged by the gateway (2xx) and cleared locally.
    pub reported: usize,
    /// Not acknowledged — left buffered for the next attempt — or not readable as a record.
    pub failed: usize,
    /// One line per failure, prefixed with the nonce (or file name).
    pub reasons: Vec<String>,
}

/// Why a gateway call failed — the distinction the offline fallback turns on.
///
/// Every public method still returns `Result<_, String>`; this only lets `require_approval_with_offline`
/// tell "the gateway could not be asked" from "the gateway answered no". A 4xx (403 in particular,
/// the gateway's own fail-closed "cannot resolve the approval requirement") is a verdict, and routing
/// a verdict to an out-of-band ceremony would turn a policy denial into a different approval route.
#[derive(Debug)]
enum CallError {
    /// No HTTP response was received ([`TransportError::NoResponse`]).
    NoResponse(String),
    /// The gateway answered with a non-2xx status. `message` is the full error text.
    Status { status: u16, body: String, message: String },
    /// A response whose body could not be read, or a 2xx whose body is not what the gateway sends —
    /// a proxy page, a truncated response.
    BadResponse(String),
    /// Any other transport failure ([`TransportError::Other`]).
    TransportOther(String),
    /// Decided before anything was sent: invalid input or missing credentials.
    Local(String),
}

impl From<TransportError> for CallError {
    fn from(e: TransportError) -> Self {
        match e {
            TransportError::NoResponse(m) => CallError::NoResponse(m),
            TransportError::UnreadableBody(m) => CallError::BadResponse(m),
            TransportError::Other(m) => CallError::TransportOther(m),
        }
    }
}

impl CallError {
    /// The gateway could not be ASKED: no HTTP response at all, or a 5xx, and nothing else. A 4xx is
    /// a verdict; a local mistake asked nothing; an unreadable body came back from something that
    /// answered; and an unclassified transport error may be a refusal a custom transport turned into
    /// an `Err` — an offline ceremony would bind whatever was wrong in each case.
    fn could_not_ask(&self) -> bool {
        match self {
            CallError::NoResponse(_) => true,
            CallError::Status { status, .. } => *status >= 500,
            CallError::BadResponse(_) | CallError::TransportOther(_) | CallError::Local(_) => false,
        }
    }
}

impl std::fmt::Display for CallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CallError::NoResponse(m)
            | CallError::BadResponse(m)
            | CallError::TransportOther(m)
            | CallError::Local(m) => f.write_str(m),
            CallError::Status { message, .. } => f.write_str(message),
        }
    }
}

/// How many back-to-back polling failures before `require_approval` declares the gateway unreachable.
const MAX_POLL_ERRORS: u32 = 5;

/// The most a cached exchange is refreshed ahead of its advertised expiry. The margin is
/// `min(60s, expires_in / 10)`, so a short-lived token still gets a proportionate head start.
const MAX_REFRESH_MARGIN: Duration = Duration::from_secs(60);

/// A bearer obtained by client-credentials exchange, with the expiry the gateway advertised.
struct CachedToken {
    token: String,
    /// `None` when the response carried no usable `expires_in`: the token is then kept until the
    /// gateway refuses it with a 401, which is the pre-refresh behaviour.
    expires_at: Option<Instant>,
    /// How far ahead of `expires_at` the cache stops being served.
    margin: Duration,
}

/// A Intyga gateway client generic over its HTTP [`Transport`].
pub struct Client<T: Transport> {
    opts: ClientOptions,
    transport: T,
    cached: Option<CachedToken>,
    /// Monotonic clock behind the refresh margin. A plain fn pointer so tests can swap it without a
    /// dependency; production always uses `Instant::now`.
    now: fn() -> Instant,
}

impl<T: Transport> Client<T> {
    /// Construct a client over a caller-supplied [`Transport`]. Errs unless `gateway_url` is
    /// `https://` (or `http://` to a loopback host), so a misconfiguration fails before any
    /// credential is sent.
    pub fn with_transport(mut opts: ClientOptions, transport: T) -> Result<Self, String> {
        opts.gateway_url = validate_gateway_url(&opts.gateway_url)?;
        Ok(Client {
            opts,
            transport,
            cached: None,
            now: Instant::now,
        })
    }

    /// Resolve a bearer token: the provided one, a cached exchange, or a fresh client-credentials exchange.
    ///
    /// An exchanged token is cached until shortly before the `expires_in` the gateway reported
    /// (`min(60s, expires_in / 10)` ahead of it), then re-exchanged on the next call. Because every
    /// poll in [`Client::require_approval`] goes through here, a wait longer than the token's
    /// lifetime keeps working. An explicit [`ClientOptions::token`] is returned as-is: there is
    /// nothing to re-exchange it with.
    pub fn token(&mut self) -> Result<String, String> {
        self.token_inner().map_err(|e| e.to_string())
    }

    fn token_inner(&mut self) -> Result<String, CallError> {
        if let Some(t) = &self.opts.token {
            return Ok(t.clone());
        }
        if let Some(c) = &self.cached {
            let fresh = match c.expires_at {
                None => true,
                // `now + margin < expires_at` is `now < expires_at - margin` without the
                // subtraction, which would panic if the margin ever exceeded the Instant.
                Some(expires_at) => (self.now)() + c.margin < expires_at,
            };
            if fresh {
                return Ok(c.token.clone());
            }
        }
        let (id, secret) = match (&self.opts.client_id, &self.opts.client_secret) {
            (Some(id), Some(secret)) => (id, secret),
            _ => {
                return Err(CallError::Local(
                    "provide token, or client_id + client_secret".to_string(),
                ))
            }
        };
        let basic = base64_encode(format!("{}:{}", id, secret).as_bytes());
        let res = self
            .transport
            .request(
                "POST",
                &format!("{}/oauth/token", self.opts.gateway_url),
                &[("authorization", &format!("Basic {}", basic))],
                None,
            )
            .map_err(CallError::from)?;
        if !(200..300).contains(&res.status) {
            return Err(CallError::Status {
                status: res.status,
                message: format!("token exchange failed: {} {}", res.status, res.body),
                body: res.body,
            });
        }
        let data: Value = serde_json::from_str(&res.body)
            .map_err(|e| CallError::BadResponse(format!("bad token response: {}", e)))?;
        let token = data
            .get("access_token")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                CallError::BadResponse("token response missing access_token".to_string())
            })?
            .to_string();
        // `expires_in` is seconds (RFC 6749 §5.1). Anything absent, non-numeric, non-positive or
        // too large to represent is "no expiry known" rather than an error: the token is still
        // usable, we just fall back to refreshing on a 401.
        let (expires_at, margin) = match data.get("expires_in").and_then(Value::as_f64) {
            Some(secs) if secs.is_finite() && secs > 0.0 => {
                let margin = Duration::try_from_secs_f64(secs / 10.0)
                    .map(|m| m.min(MAX_REFRESH_MARGIN))
                    .unwrap_or(MAX_REFRESH_MARGIN);
                let expires_at = Duration::try_from_secs_f64(secs)
                    .ok()
                    .and_then(|d| (self.now)().checked_add(d));
                (expires_at, margin)
            }
            _ => (None, Duration::ZERO),
        };
        self.cached = Some(CachedToken {
            token: token.clone(),
            expires_at,
            margin,
        });
        Ok(token)
    }

    /// Create an approval challenge and return its nonce and initial status.
    pub fn authorize(
        &mut self,
        action_description: &str,
        opts: &AuthorizeOptions,
    ) -> Result<AuthorizeResponse, String> {
        self.authorize_inner(action_description, opts)
            .map_err(|e| e.to_string())
    }

    fn authorize_inner(
        &mut self,
        action_description: &str,
        opts: &AuthorizeOptions,
    ) -> Result<AuthorizeResponse, CallError> {
        // `String.prototype.trim`, as every INTYGA client trims the target it sends.
        let target = opts.target.as_deref().map(support::js_trim).filter(|t| !t.is_empty()).ok_or_else(|| {
            CallError::Local(
                "intyga: AuthorizeOptions.target is required (DIV Target Isolation): name the \
                 relying party / execution environment this approval is bound to"
                    .to_string(),
            )
        })?;
        let mut body = json!({
            "target": target,
            "actionDescription": action_description,
            "params": opts.params.clone().unwrap_or_else(|| json!({})),
        });
        if let Some(action_type) = &opts.action_type {
            body["actionType"] = json!(action_type);
        }
        if let Some(context) = &opts.agent_context {
            body["agentContext"] = context.clone();
        }
        if let Some(t) = opts.timeout_seconds {
            body["timeout"] = json!(t);
        }
        let res = self.do_json_inner("POST", "/authorize", Some(&body))?;
        serde_json::from_str(&res)
            .map_err(|e| CallError::BadResponse(format!("bad authorize response: {}", e)))
    }

    /// Execution-time re-binding: after APPROVED, call this immediately before running the action so the
    /// gateway confirms the approved signature matches the exact instruction and marks it single-use.
    ///
    /// `target` is REQUIRED by the gateway's `authorizationConsume` schema. Omitting it was a 400 on
    /// every call, which made single-use redemption unreachable from this crate entirely: the
    /// challenge stayed APPROVED rather than CONSUMED, and remained replayable by any holder of the
    /// same token until it expired naturally.
    pub fn consume(
        &mut self,
        nonce: &str,
        target: &str,
        action_type: &str,
        params: Option<Value>,
    ) -> Result<ConsumeResult, String> {
        if target.trim().is_empty() {
            return Err(
                "intyga: consume requires the same target the approval was bound to".to_string(),
            );
        }
        let body = json!({
            "nonce": nonce,
            "target": target,
            "actionType": action_type,
            "params": params.unwrap_or_else(|| json!({})),
        });
        let res = self.do_json("POST", "/authorize/verify", Some(&body))?;
        serde_json::from_str(&res).map_err(|e| format!("bad consume response: {}", e))
    }

    /// Poll a challenge's current state (non-blocking).
    pub fn status(&mut self, nonce: &str) -> Result<ApprovalResult, String> {
        self.status_inner(nonce).map_err(|e| e.to_string())
    }

    fn status_inner(&mut self, nonce: &str) -> Result<ApprovalResult, CallError> {
        let path = format!("/authorize/{}", urlencode(nonce));
        let res = self.do_json_inner("GET", &path, None)?;
        serde_json::from_str(&res)
            .map_err(|e| CallError::BadResponse(format!("bad status response: {}", e)))
    }

    /// The core zero-trust gate: call immediately before a high-risk action. It creates the challenge and
    /// blocks until the human approves/denies with their passkey (or it times out).
    pub fn require_approval(
        &mut self,
        action_description: &str,
        opts: &RequireApprovalOptions,
    ) -> Result<ApprovalResult, String> {
        self.require_approval_inner(action_description, opts, None)
    }

    /// [`Client::require_approval`], plus the OFFLINE APPROVAL fallback (DIV §5a) for THIS call.
    ///
    /// The offline options are per call, never a client default: a process-wide default would make
    /// every gated action in the service accept an out-of-band approval, which is the difference
    /// between an emergency mechanism and a hole.
    ///
    /// It falls back ONLY when the gateway could not be asked — a connection failure, a timeout, a
    /// 5xx, or five consecutive polling failures of those kinds — and runs [`use_offline_approval`]
    /// with the same target, action type, params and description. A 4xx, `DENIED` or `EXPIRED` is
    /// never routed offline: a human or the gateway's policy WAS reached and did not approve. A
    /// polling streak containing any such refusal returns its first refusal, even when the later
    /// errors were 5xx. Neither is a local error (a blank target, missing credentials) or an
    /// unreadable 2xx body. A request carrying `agent_context` never falls back (an offline proof has
    /// no session chain). A completed fallback returns [`ApprovalStatus::OfflineApproved`] with the
    /// offline receipt and nonce — never `Approved`.
    pub fn require_approval_with_offline(
        &mut self,
        action_description: &str,
        opts: &RequireApprovalOptions,
        offline: &OfflineApprovalOptions<'_>,
    ) -> Result<ApprovalResult, String> {
        self.require_approval_inner(action_description, opts, Some(offline))
    }

    fn require_approval_inner(
        &mut self,
        action_description: &str,
        opts: &RequireApprovalOptions,
        offline: Option<&OfflineApprovalOptions<'_>>,
    ) -> Result<ApprovalResult, String> {
        let timeout = if opts.timeout.is_zero() {
            Duration::from_secs(120)
        } else {
            opts.timeout
        };
        let interval = if opts.interval.is_zero() {
            Duration::from_secs(2)
        } else {
            opts.interval
        };

        // Clone the caller's options and override only the timeout. Rebuilding this struct
        // field-by-field silently drops anything added to AuthorizeOptions later — which is how
        // `target` would have gone missing here even after being made required.
        let authorize = AuthorizeOptions {
            // Ceil to whole seconds so the challenge TTL covers the full local wait.
            timeout_seconds: Some((timeout.as_secs_f64().ceil()) as u64),
            ..opts.authorize.clone()
        };
        let deadline = Instant::now().checked_add(timeout).ok_or("approval timeout is too large")?;
        let auth_res = match self.authorize_inner(action_description, &authorize) {
            Ok(r) => r,
            // Could not even raise the challenge — the clearest "gateway is unreachable" signal
            // there is, unless the gateway in fact answered, which `offline_fallback` refuses.
            Err(e) => {
                return offline_fallback(
                    e.to_string(),
                    format!("could not reach Intyga to request approval: {e}"),
                    &e,
                    action_description,
                    &opts.authorize,
                    offline,
                )
            }
        };
        let nonce = auth_res.nonce;

        let expired = || ApprovalResult {
            status: ApprovalStatus::Expired, signature_hash: None, receipt: None,
            nonce: Some(nonce.clone()), agent_context: auth_res.agent_context.clone(),
        };
        let mut consecutive_errors = 0u32;
        // The first error in the current streak that was NOT "could not ask" (a 4xx, an unreadable
        // 2xx body). If the streak reaches the limit, that error is returned and nothing routes
        // offline, whatever the later errors were: a gateway that answered 404 once and then went
        // quiet was reached, and its answer was not an outage. A successful poll clears it.
        let mut streak_refusal: Option<String> = None;
        loop {
            if Instant::now() >= deadline { return Ok(expired()); }
            // A human approval can outlast a transient 502 — don't discard the whole wait over one bad poll.
            match self.status_inner(&nonce) {
                Ok(mut r) => {
                    if Instant::now() >= deadline { return Ok(expired()); }
                    consecutive_errors = 0;
                    streak_refusal = None;
                    if r.status != ApprovalStatus::Pending {
                        r.nonce = Some(nonce);
                        r.agent_context = auth_res.agent_context;
                        return Ok(r);
                    }
                }
                Err(e) => {
                    consecutive_errors += 1;
                    if !e.could_not_ask() && streak_refusal.is_none() {
                        streak_refusal = Some(e.to_string());
                    }
                    if consecutive_errors >= MAX_POLL_ERRORS {
                        if let Some(refusal) = streak_refusal {
                            return Err(refusal);
                        }
                        // Every error in the streak was "could not ask": the gateway went away
                        // mid-wait, and the same fallback applies as when the challenge could not
                        // be raised at all.
                        let cause = format!(
                            "polling failed after {} consecutive errors: {}",
                            MAX_POLL_ERRORS, e
                        );
                        return offline_fallback(
                            cause.clone(),
                            cause,
                            &e,
                            action_description,
                            &opts.authorize,
                            offline,
                        );
                    }
                }
            }
            if Instant::now() >= deadline {
                return Ok(ApprovalResult {
                    status: ApprovalStatus::Expired,
                    agent_context: auth_res.agent_context,
                    signature_hash: None,
                    receipt: None,
                    nonce: Some(nonce),
                });
            }
            std::thread::sleep(interval.min(deadline.saturating_duration_since(Instant::now())));
        }
    }

    /// Public witness lookup: has this document hash been signed, by whom, and when?
    pub fn verify(&mut self, document_hash: &str) -> Result<VerifyResult, String> {
        let url = format!("{}/verify/{}", self.opts.gateway_url, urlencode(document_hash));
        let res = self
            .transport
            .request("GET", &url, &[], None)
            .map_err(|e| e.to_string())?;
        if !(200..300).contains(&res.status) {
            return Err(format!("verify failed: {}", res.status));
        }
        serde_json::from_str(&res.body).map_err(|e| format!("bad verify response: {}", e))
    }

    /// Report offline approvals that happened while the gateway was unreachable (DIV §5a.7):
    /// `POST /offline-approval/reconcile` once per buffered record, with this client's ordinary
    /// authentication and the body `{nonce, usedAt, target, actionType, display, receipt,
    /// delegationNonce}` (`delegationNonce` omitted when no delegation was used).
    ///
    /// Call it on reconnect — a scheduled retry, a health-check hook, service start. Until an approval
    /// is reported it exists only on this relying party's disk, and an unreported approval is
    /// indistinguishable from an unauthorized action. A record is cleared ONLY on a 2xx; anything
    /// else leaves it queued for the next attempt. A file in the buffer that is not a readable record
    /// is counted as failed, so it is never silently ignored. `buffer_dir` defaults to
    /// `<bundle_dir>/.pending`.
    pub fn reconcile_offline_approvals(
        &mut self,
        bundle_dir: impl AsRef<Path>,
        buffer_dir: Option<&Path>,
    ) -> Result<ReconcileReport, String> {
        // Resolve credentials up front, so a misconfigured client is an error rather than one
        // "failed" report per buffered approval.
        self.token()?;
        let (records, unreadable) = offline::scan_pending(bundle_dir.as_ref(), buffer_dir);
        let mut report = ReconcileReport::default();
        for name in unreadable {
            report.failed += 1;
            report
                .reasons
                .push(format!("{name}: unreadable pending record — report it by hand"));
        }
        for (file, record) in records {
            // The full receipt travels with the report so the gateway can RE-VERIFY the approval
            // rather than take the reporter's word for it — we are reporting on ourselves.
            let body = match serde_json::to_value(&record) {
                Ok(body) => body,
                Err(e) => {
                    report.failed += 1;
                    report.reasons.push(format!("{}: {e}", record.nonce));
                    continue;
                }
            };
            match self.do_json_inner("POST", "/offline-approval/reconcile", Some(&body)) {
                Ok(_) => {
                    // The file just reported, not a path rebuilt from the nonce it contains.
                    let _ = std::fs::remove_file(&file);
                    report.reported += 1;
                }
                Err(CallError::Status { status, body, .. }) => {
                    report.failed += 1;
                    report
                        .reasons
                        .push(format!("{}: {status} {body}", record.nonce));
                }
                Err(e) => {
                    report.failed += 1;
                    report.reasons.push(format!("{}: {e}", record.nonce));
                }
            }
        }
        Ok(report)
    }

    /// Perform an authenticated JSON request, returning the response body on 2xx.
    ///
    /// A 401 on a token this client exchanged itself drops the cache and retries exactly once with
    /// a fresh exchange — it covers clock skew against the refresh margin and a gateway that
    /// shortened its lifetimes after the token was minted. An explicit `ClientOptions::token` is
    /// never retried: a 401 on it is the caller's to handle.
    fn do_json(
        &mut self,
        method: &str,
        path: &str,
        body: Option<&Value>,
    ) -> Result<String, String> {
        self.do_json_inner(method, path, body)
            .map_err(|e| e.to_string())
    }

    fn do_json_inner(
        &mut self,
        method: &str,
        path: &str,
        body: Option<&Value>,
    ) -> Result<String, CallError> {
        let url = format!("{}{}", self.opts.gateway_url, path);
        let body_str = body.map(|b| b.to_string());
        let mut retried = false;
        loop {
            let token = self.token_inner()?;
            let auth = format!("Bearer {}", token);
            let mut headers: Vec<(&str, &str)> = vec![("authorization", &auth)];
            if body_str.is_some() {
                headers.push(("content-type", "application/json"));
            }
            let res = self
                .transport
                .request(method, &url, &headers, body_str.as_deref())
                .map_err(CallError::from)?;
            if res.status == 401 && self.opts.token.is_none() && !retried {
                self.cached = None;
                retried = true;
                continue;
            }
            if !(200..300).contains(&res.status) {
                return Err(CallError::Status {
                    status: res.status,
                    message: format!("{} {} failed: {} {}", method, path, res.status, res.body),
                    body: res.body,
                });
            }
            return Ok(res.body);
        }
    }
}

/// The DIV §5a fallback decision for [`Client::require_approval_with_offline`].
///
/// `refusal` is what the call returns when it does not fall back (exactly what
/// [`Client::require_approval`] returns); `cause` prefixes the error when the offline approval
/// itself does not complete.
fn offline_fallback(
    refusal: String,
    cause: String,
    err: &CallError,
    action_description: &str,
    authorize: &AuthorizeOptions,
    offline: Option<&OfflineApprovalOptions<'_>>,
) -> Result<ApprovalResult, String> {
    let Some(offline) = offline else {
        return Err(refusal);
    };
    // DIV §5a exists for the case where we could not ASK. A 4xx means the gateway was reached and
    // refused; treating a refusal as unreachability turns a policy denial into a different approval
    // route, which is worse than having no gate at all (DIV §3.4).
    if !err.could_not_ask() {
        return Err(refusal);
    }
    if authorize.agent_context.is_some() {
        return Err(
            "agent continuity requests cannot fall back to an unchained offline proof".to_string(),
        );
    }
    let action = OfflineAction {
        target: authorize.target.clone().unwrap_or_default(),
        action_type: authorize.action_type.clone().unwrap_or_default(),
        display: action_description.to_string(),
        params: authorize.params.clone().unwrap_or_else(|| json!({})),
    };
    match use_offline_approval(&action, offline) {
        Ok(approval) => Ok(ApprovalResult {
            status: ApprovalStatus::OfflineApproved,
            agent_context: None,
            signature_hash: None,
            receipt: Some(approval.receipt),
            nonce: Some(approval.nonce),
        }),
        Err(reason) => Err(format!(
            "{cause} — and the offline approval did not complete: {reason}"
        )),
    }
}

#[cfg(feature = "ureq-transport")]
impl Client<UreqTransport> {
    /// Construct a client using the built-in blocking `ureq` transport. Errs unless `gateway_url`
    /// is `https://` (or `http://` to a loopback host, for local development).
    pub fn new(opts: ClientOptions) -> Result<Self, String> {
        Client::with_transport(opts, UreqTransport)
    }
}

/// Return `raw` without trailing slashes, or an error unless it is `https://` or `http://` to a
/// loopback host. The same rule every Intyga client applies (TypeScript, Go, Python, Java): change
/// them together. Parsed by hand to keep the crate free of a URL dependency.
fn validate_gateway_url(raw: &str) -> Result<String, String> {
    let refuse = |shown: &str| {
        format!(
            "gateway_url must use https:// (got {shown}): Intyga clients send credentials on every \
             request and refuse plain http except to a loopback host (localhost, 127.0.0.0/8, ::1) \
             for local development"
        )
    };
    let (scheme, rest) = raw
        .split_once("://")
        .ok_or_else(|| format!("gateway_url is not a valid absolute URL: {raw:?}"))?;
    // Authority ends at the first '/', '?' or '#'; userinfo (if any) ends at the last '@'.
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host_port = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    if host_port.is_empty() {
        return Err(format!("gateway_url is not a valid absolute URL: {raw:?}"));
    }
    let trimmed = raw.trim_end_matches('/').to_string();
    match scheme.to_ascii_lowercase().as_str() {
        "https" => Ok(trimmed),
        "http" if is_loopback_host(host_port) => Ok(trimmed),
        _ => Err(refuse(&format!("{scheme}://{host_port}"))),
    }
}

/// `host_port` is the URL authority without userinfo: `host`, `host:port`, `[v6]` or `[v6]:port`.
fn is_loopback_host(host_port: &str) -> bool {
    let host = if let Some(v6) = host_port.strip_prefix('[') {
        match v6.split_once(']') {
            Some((addr, _)) => return addr.parse::<std::net::Ipv6Addr>().is_ok_and(|a| a.is_loopback()),
            None => return false,
        }
    } else {
        host_port.split(':').next().unwrap_or("")
    };
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    host.parse::<std::net::Ipv4Addr>().is_ok_and(|a| a.octets()[0] == 127)
}

/// The built-in blocking HTTP transport, backed by `ureq`.
#[cfg(feature = "ureq-transport")]
pub struct UreqTransport;

/// The largest response body the built-in transport reads — ureq's own `into_string` cap (10 MB).
#[cfg(feature = "ureq-transport")]
const MAX_RESPONSE_BODY_BYTES: u64 = 10 * 1024 * 1024;

#[cfg(feature = "ureq-transport")]
impl Transport for UreqTransport {
    fn request(
        &self,
        method: &str,
        url: &str,
        headers: &[(&str, &str)],
        body: Option<&str>,
    ) -> Result<HttpResponse, TransportError> {
        let agent = ureq::AgentBuilder::new().timeout(Duration::from_secs(30)).redirects(0).build();
        let mut req = agent.request(method, url);
        for (k, v) in headers {
            req = req.set(k, v);
        }
        let result = match body {
            Some(b) => req.send_string(b),
            None => req.call(),
        };
        let resp = match result {
            Ok(resp) => resp,
            // ureq returns Err for a non-2xx. That is a STATUS, and it goes back as one: the client
            // must see a 4xx as the gateway refusing, never as the gateway being unreachable.
            Err(ureq::Error::Status(_, resp)) => resp,
            Err(ureq::Error::Transport(t)) => return Err(classify_ureq_transport_error(&t)),
        };
        let status = resp.status();
        // Read separately, and strictly: a body that cannot be read (an I/O error mid-body, over the
        // size cap, invalid UTF-8) came from something that answered, so it is never "could not
        // ask". Not `into_string`, which replaces invalid UTF-8 rather than refusing it.
        let unreadable = |why: String| {
            TransportError::UnreadableBody(format!(
                "HTTP {status}: could not read the response body: {why}"
            ))
        };
        let mut bytes = Vec::new();
        std::io::Read::read_to_end(
            &mut std::io::Read::take(resp.into_reader(), MAX_RESPONSE_BODY_BYTES + 1),
            &mut bytes,
        )
        .map_err(|e| unreadable(e.to_string()))?;
        if bytes.len() as u64 > MAX_RESPONSE_BODY_BYTES {
            return Err(unreadable(format!(
                "it is larger than {MAX_RESPONSE_BODY_BYTES} bytes"
            )));
        }
        let body = String::from_utf8(bytes).map_err(|e| unreadable(e.to_string()))?;
        Ok(HttpResponse { status, body })
    }
}

/// Only failures that leave no HTTP response behind are [`TransportError::NoResponse`]. A garbled
/// status line or header means something answered; a bad URL or proxy setting is local.
#[cfg(feature = "ureq-transport")]
fn classify_ureq_transport_error(t: &ureq::Transport) -> TransportError {
    use ureq::ErrorKind;
    let message = t.to_string();
    match t.kind() {
        ErrorKind::Dns | ErrorKind::ConnectionFailed | ErrorKind::ProxyConnect | ErrorKind::Io => {
            TransportError::NoResponse(message)
        }
        _ => TransportError::Other(message),
    }
}

/// Minimal standard base64 (for the Basic auth header) — avoids pulling a crate for one small use.
fn base64_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | (b[2] as u32);
        out.push(ALPHABET[((n >> 18) & 63) as usize] as char);
        out.push(ALPHABET[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[((n >> 6) & 63) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

/// Percent-encode a path segment (nonce / document hash) conservatively.
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};

    // Fake monotonic clock for the refresh-margin tests. Thread-local because each test runs on
    // its own thread, so tests cannot see each other's time.
    thread_local! {
        static FAKE_NOW: Cell<Option<Instant>> = const { Cell::new(None) };
    }

    fn fake_now() -> Instant {
        FAKE_NOW.with(|c| c.get().expect("set_now() before using the fake clock"))
    }

    fn set_now(t: Instant) {
        FAKE_NOW.with(|c| c.set(Some(t)));
    }

    // How many client-credentials exchanges and bearer-authenticated calls the transport saw.
    fn count_auth(seen: &[String]) -> (usize, Vec<String>) {
        let basics = seen.iter().filter(|a| a.starts_with("Basic ")).count();
        let bearers = seen
            .iter()
            .filter(|a| a.starts_with("Bearer "))
            .cloned()
            .collect();
        (basics, bearers)
    }

    // A route is (method, path_suffix, response-sequence); each response is a (status, body) pair
    // consumed per matching call.
    type MockRoute = (String, String, Vec<(u16, String)>);

    // In-process mock transport: matches (method, path-suffix) and returns a canned response. Path is a
    // suffix match so tests don't hardcode the gateway URL. No sockets, no child processes.
    struct MockTransport {
        routes: RefCell<Vec<MockRoute>>,
        seen_auth: RefCell<Vec<String>>,
        seen_bodies: RefCell<Vec<Option<String>>>,
    }

    impl MockTransport {
        fn new() -> Self {
            MockTransport {
                routes: RefCell::new(Vec::new()),
                seen_auth: RefCell::new(Vec::new()),
                seen_bodies: RefCell::new(Vec::new()),
            }
        }
        fn on(mut self, method: &str, path_suffix: &str, responses: Vec<(u16, &str)>) -> Self {
            self.routes.get_mut().push((
                method.to_string(),
                path_suffix.to_string(),
                responses
                    .into_iter()
                    .map(|(s, b)| (s, b.to_string()))
                    .collect(),
            ));
            self
        }
    }

    impl Transport for MockTransport {
        fn request(
            &self,
            method: &str,
            url: &str,
            headers: &[(&str, &str)],
            body: Option<&str>,
        ) -> Result<HttpResponse, TransportError> {
            self.seen_bodies.borrow_mut().push(body.map(str::to_string));
            for (name, value) in headers {
                if *name == "authorization" {
                    self.seen_auth.borrow_mut().push(value.to_string());
                }
            }
            let mut routes = self.routes.borrow_mut();
            for (m, suffix, responses) in routes.iter_mut() {
                if m == method && url.ends_with(suffix.as_str()) {
                    let (status, body) = if responses.len() > 1 {
                        responses.remove(0)
                    } else {
                        responses[0].clone()
                    };
                    return Ok(HttpResponse { status, body });
                }
            }
            Err(format!("no mock route for {} {}", method, url).into())
        }
    }

    #[test]
    fn authorize_omits_unset_action_type_and_preserves_explicit_value() {
        let transport = MockTransport::new().on(
            "POST",
            "/authorize",
            vec![(200, r#"{"nonce":"n_1","status":"PENDING"}"#)],
        );
        let mut client = Client::with_transport(
            ClientOptions {
                gateway_url: "https://gw.example".into(),
                token: Some("t".into()),
                ..Default::default()
            },
            transport,
        ).unwrap();
        client
            .authorize(
                "wire",
                &AuthorizeOptions {
                    target: Some("prod".into()),
                    ..Default::default()
                },
            )
            .unwrap();
        client
            .authorize(
                "wire",
                &AuthorizeOptions {
                    target: Some("prod".into()),
                    action_type: Some("transfer".into()),
                    ..Default::default()
                },
            )
            .unwrap();
        let bodies = client.transport.seen_bodies.borrow();
        let omitted: Value = serde_json::from_str(bodies[0].as_ref().unwrap()).unwrap();
        let explicit: Value = serde_json::from_str(bodies[1].as_ref().unwrap()).unwrap();
        assert!(omitted.get("actionType").is_none());
        assert_eq!(explicit["actionType"], "transfer");
    }

    #[test]
    fn authorize_trims_the_target_as_javascript_does() {
        let transport = MockTransport::new().on(
            "POST",
            "/authorize",
            vec![(200, r#"{"nonce":"n_1","status":"PENDING"}"#)],
        );
        let mut client = Client::with_transport(
            ClientOptions { gateway_url: "https://gw.example".into(), token: Some("t".into()), ..Default::default() },
            transport,
        ).unwrap();
        let with = |target: &str| AuthorizeOptions { target: Some(target.into()), ..Default::default() };
        client.authorize("wire", &with("\u{feff} prod\u{3000}")).unwrap();
        // A BOM and spaces alone are blank to every INTYGA client.
        assert!(client.authorize("wire", &with("\u{feff} \u{2028}")).is_err());
        let bodies = client.transport.seen_bodies.borrow();
        assert_eq!(bodies.len(), 1);
        let sent: Value = serde_json::from_str(bodies[0].as_ref().unwrap()).unwrap();
        assert_eq!(sent["target"], "prod");
    }

    fn fast_opts(a: AuthorizeOptions) -> RequireApprovalOptions {
        RequireApprovalOptions {
            authorize: a,
            timeout: Duration::from_secs(5),
            interval: Duration::from_millis(5),
        }
    }

    #[test]
    #[cfg(feature = "ureq-transport")]
    fn default_transport_returns_redirect_without_following() {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf).unwrap();
            stream.write_all(b"HTTP/1.1 307 Temporary Redirect\r\nLocation: /sink\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
        });
        let result = UreqTransport.request("POST", &format!("http://{addr}/oauth/token"),
            &[("authorization", "Basic test")], None).unwrap();
        assert_eq!(result.status, 307);
        server.join().unwrap();
    }

    /// Serve one canned raw HTTP response on a loopback port and return its address.
    #[cfg(feature = "ureq-transport")]
    fn serve_once(response: &'static [u8]) -> (std::net::SocketAddr, std::thread::JoinHandle<()>) {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf).unwrap();
            stream.write_all(response).unwrap();
        });
        (addr, server)
    }

    // The fallback turns on these three distinctions, so the built-in transport is pinned to them:
    // a refusal is a STATUS, a body that cannot be read is not an outage, and only a request with no
    // response at all is.
    #[test]
    #[cfg(feature = "ureq-transport")]
    fn default_transport_classifies_what_it_could_not_return() {
        let (addr, server) = serve_once(
            b"HTTP/1.1 403 Forbidden\r\nContent-Length: 6\r\nConnection: close\r\n\r\ndenied",
        );
        let refused = UreqTransport.request("GET", &format!("http://{addr}/authorize/n"), &[], None);
        let refused = refused.expect("a 4xx must come back as Ok(HttpResponse)");
        assert_eq!((refused.status, refused.body.as_str()), (403, "denied"));
        server.join().unwrap();

        let (addr, server) = serve_once(
            b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\n\xff\xfe\xfd\xfc",
        );
        let unreadable = UreqTransport.request("GET", &format!("http://{addr}/authorize/n"), &[], None);
        assert!(
            matches!(unreadable, Err(TransportError::UnreadableBody(_))),
            "{:?}",
            unreadable.map(|r| r.status)
        );
        server.join().unwrap();

        // The connection closes four bytes into a ten-byte body: an I/O error mid-body.
        let (addr, server) = serve_once(
            b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\n{\"ok\"",
        );
        let cut = UreqTransport.request("GET", &format!("http://{addr}/authorize/n"), &[], None);
        assert!(
            matches!(cut, Err(TransportError::UnreadableBody(_))),
            "{:?}",
            cut.map(|r| r.status)
        );
        server.join().unwrap();

        // A port nothing listens on: the connection is refused, so no response was received.
        let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
        let down = UreqTransport.request("GET", &format!("http://{closed}/authorize/n"), &[], None);
        assert!(
            matches!(down, Err(TransportError::NoResponse(_))),
            "{:?}",
            down.map(|r| r.status)
        );
    }

    #[test]
    fn an_unclassified_transport_error_fails_closed() {
        assert_eq!(
            TransportError::from("403 Forbidden".to_string()),
            TransportError::Other("403 Forbidden".into())
        );
        assert!(!CallError::from(TransportError::Other("x".into())).could_not_ask());
        assert!(!CallError::from(TransportError::UnreadableBody("x".into())).could_not_ask());
        assert!(CallError::from(TransportError::NoResponse("x".into())).could_not_ask());
    }

    #[test]
    fn construction_refuses_a_non_https_gateway() {
        struct Never;
        impl Transport for Never {
            fn request(&self, _: &str, _: &str, _: &[(&str, &str)], _: Option<&str>) -> Result<HttpResponse, TransportError> {
                panic!("no request may be sent")
            }
        }
        let build = |url: &str| {
            Client::with_transport(ClientOptions { gateway_url: url.into(), token: Some("t".into()), ..Default::default() }, Never)
        };
        for bad in [
            "http://gw.example",
            "http://10.0.0.5:8787",
            "http://128.0.0.1",
            "http://localhost.evil.example",
            "http://127.0.0.1.nip.io",
            "http://[::2]",
            "http://localhost@gw.example",
            "ftp://gw.example",
            "gw.example",
            "https://",
            "",
        ] {
            assert!(build(bad).is_err(), "accepted {bad:?}");
        }
        let err = build("http://gw.example").err().unwrap();
        assert!(err.contains("must use https://"), "{err}");
        for ok in [
            "https://gw.example",
            "HTTPS://gw.example",
            "http://localhost:8787",
            "http://LOCALHOST",
            "http://127.0.0.1:8787",
            "http://127.200.3.4",
            "http://[::1]:8787",
        ] {
            assert!(build(ok).is_ok(), "refused {ok:?}");
        }
        assert_eq!(build("https://gw.example//").unwrap().opts.gateway_url, "https://gw.example");
    }

    #[test]
    fn late_approval_is_expired() {
        struct Slow;
        impl Transport for Slow {
            fn request(&self, method: &str, _: &str, _: &[(&str, &str)], _: Option<&str>) -> Result<HttpResponse, TransportError> {
                if method == "POST" {
                    return Ok(HttpResponse { status: 200, body: r#"{"nonce":"late","status":"PENDING"}"#.into() });
                }
                std::thread::sleep(Duration::from_millis(30));
                Ok(HttpResponse { status: 200, body: r#"{"status":"APPROVED"}"#.into() })
            }
        }
        let mut client = Client::with_transport(ClientOptions { gateway_url: "https://gw.example".into(), token: Some("t".into()), ..Default::default() }, Slow).unwrap();
        let result = client.require_approval("wire", &RequireApprovalOptions {
            authorize: AuthorizeOptions { target: Some("prod".into()), ..Default::default() },
            timeout: Duration::from_millis(10), interval: Duration::from_millis(1),
        }).unwrap();
        assert_eq!(result.status, ApprovalStatus::Expired);
        assert_eq!(result.nonce.as_deref(), Some("late"));
    }

    #[test]
    fn issued_context_survives_poll_and_public_lookup_needs_no_credentials() {
        let transport = MockTransport::new()
            .on("POST", "/authorize", vec![(200, r#"{"nonce":"ctx","status":"PENDING","agentContext":{"nbf":"issued"}}"#)])
            .on("GET", "/authorize/ctx", vec![(200, r#"{"status":"APPROVED","agentContext":{"nbf":"wrong"}}"#)]);
        let mut client = Client::with_transport(ClientOptions {
            gateway_url: "https://gw.example".into(), token: Some("t".into()), ..Default::default()
        }, transport).unwrap();
        let result = client.require_approval("wire", &fast_opts(AuthorizeOptions {
            target: Some("prod".into()), ..Default::default()
        })).unwrap();
        assert_eq!(result.agent_context.unwrap()["nbf"], "issued");
        let transport = MockTransport::new().on("GET", "/verify/hash", vec![(200,
            r#"{"verified":true,"status":"SIGNED","documentHash":"hash"}"#)]);
        let mut public = Client::with_transport(ClientOptions {
            gateway_url: "https://gw.example".into(), ..Default::default()
        }, transport).unwrap();
        assert!(public.verify("hash").unwrap().verified);
        assert!(public.transport.seen_auth.borrow().is_empty());
    }

    #[test]
    fn require_approval_happy_path() {
        let transport = MockTransport::new()
            .on("POST", "/authorize", vec![(200, r#"{"nonce":"n_abc","status":"PENDING"}"#)])
            .on(
                "GET",
                "/authorize/n_abc",
                vec![
                    (200, r#"{"status":"PENDING"}"#),
                    (
                        200,
                        r#"{"status":"APPROVED","signatureHash":"deadbeef","receipt":{"canonicalPayload":"{}","actionDescription":"x","params":{},"verificationCode":"AAAA-BBBB"}}"#,
                    ),
                ],
            );
        let mut client = Client::with_transport(
            ClientOptions {
                gateway_url: "https://gw.example".into(),
                token: Some("t".into()),
                ..Default::default()
            },
            transport,
        ).unwrap();
        let res = client
            .require_approval(
                "Wire $5,000 to Acme Corp",
                &fast_opts(AuthorizeOptions {
                    target: Some("prod-payments".into()),
                    action_type: Some("wire_transfer".into()),
                    params: Some(json!({"to":"Acme Corp","amount":5000})),
                    ..Default::default()
                }),
            )
            .expect("require_approval");
        assert_eq!(res.status, ApprovalStatus::Approved);
        assert_eq!(res.nonce.as_deref(), Some("n_abc"));
        assert!(res.receipt.is_some());
    }

    #[test]
    fn denied_stops_polling() {
        let transport = MockTransport::new()
            .on(
                "POST",
                "/authorize",
                vec![(200, r#"{"nonce":"n_d","status":"PENDING"}"#)],
            )
            .on(
                "GET",
                "/authorize/n_d",
                vec![(200, r#"{"status":"DENIED"}"#)],
            );
        let mut client = Client::with_transport(
            ClientOptions {
                gateway_url: "https://gw.example".into(),
                token: Some("t".into()),
                ..Default::default()
            },
            transport,
        ).unwrap();
        let res = client
            .require_approval(
                "delete prod",
                &fast_opts(AuthorizeOptions {
                    target: Some("prod-db".into()),
                    ..Default::default()
                }),
            )
            .unwrap();
        assert_eq!(res.status, ApprovalStatus::Denied);
    }

    #[test]
    fn token_exchange_and_cache() {
        let transport = MockTransport::new().on(
            "POST",
            "/oauth/token",
            vec![(200, r#"{"access_token":"exchanged"}"#)],
        );
        let mut client = Client::with_transport(
            ClientOptions {
                gateway_url: "https://gw.example".into(),
                client_id: Some("cid".into()),
                client_secret: Some("secret".into()),
                ..Default::default()
            },
            transport,
        ).unwrap();
        assert_eq!(client.token().unwrap(), "exchanged");
        // Second call is served from cache (mock has a single-use route but cache avoids re-calling).
        assert_eq!(client.token().unwrap(), "exchanged");
        // No `expires_in` means no expiry is known: the cache is kept however much time passes,
        // and only a 401 (see `retries_once_with_a_fresh_token_after_401`) will replace it.
        let base = Instant::now();
        set_now(base);
        client.now = fake_now;
        set_now(base + Duration::from_secs(10 * 24 * 3600));
        assert_eq!(client.token().unwrap(), "exchanged");
        let (exchanges, _) = count_auth(&client.transport.seen_auth.borrow());
        assert_eq!(
            exchanges, 1,
            "absent expires_in must still mean one exchange"
        );
    }

    #[test]
    fn token_refreshes_before_advertised_expiry() {
        let transport = MockTransport::new().on(
            "POST",
            "/oauth/token",
            vec![
                (200, r#"{"access_token":"a","expires_in":100}"#),
                (200, r#"{"access_token":"b","expires_in":100}"#),
            ],
        );
        let mut client = Client::with_transport(
            ClientOptions {
                gateway_url: "https://gw.example".into(),
                client_id: Some("cid".into()),
                client_secret: Some("secret".into()),
                ..Default::default()
            },
            transport,
        ).unwrap();
        let base = Instant::now();
        set_now(base);
        client.now = fake_now;

        assert_eq!(client.token().unwrap(), "a");
        // expires_in=100 → margin is min(60, 100/10) = 10s, so the cache is served up to t=90s.
        set_now(base + Duration::from_secs(89));
        assert_eq!(
            client.token().unwrap(),
            "a",
            "inside the margin: still cached"
        );
        set_now(base + Duration::from_secs(91));
        assert_eq!(
            client.token().unwrap(),
            "b",
            "past expires_in - margin: re-exchanged"
        );
        // And the new token is itself cached against its own expiry.
        set_now(base + Duration::from_secs(150));
        assert_eq!(client.token().unwrap(), "b");
        let (exchanges, _) = count_auth(&client.transport.seen_auth.borrow());
        assert_eq!(exchanges, 2);
    }

    #[test]
    fn retries_once_with_a_fresh_token_after_401() {
        let transport = MockTransport::new()
            .on(
                "POST",
                "/oauth/token",
                vec![
                    (200, r#"{"access_token":"a","expires_in":3600}"#),
                    (200, r#"{"access_token":"b","expires_in":3600}"#),
                ],
            )
            .on(
                "POST",
                "/authorize",
                vec![
                    (401, r#"{"error":"Invalid token: ERR_JWT_EXPIRED"}"#),
                    (200, r#"{"nonce":"n_r","status":"PENDING"}"#),
                ],
            );
        let mut client = Client::with_transport(
            ClientOptions {
                gateway_url: "https://gw.example".into(),
                client_id: Some("cid".into()),
                client_secret: Some("secret".into()),
                ..Default::default()
            },
            transport,
        ).unwrap();
        let res = client
            .authorize(
                "wire",
                &AuthorizeOptions {
                    target: Some("prod-payments".into()),
                    ..Default::default()
                },
            )
            .expect("the 401 should have been retried with a re-exchanged token");
        assert_eq!(res.nonce, "n_r");
        let (exchanges, bearers) = count_auth(&client.transport.seen_auth.borrow());
        assert_eq!(exchanges, 2);
        assert_eq!(bearers, vec!["Bearer a", "Bearer b"]);
    }

    #[test]
    fn a_second_401_is_not_retried_again() {
        let transport = MockTransport::new()
            .on(
                "POST",
                "/oauth/token",
                vec![
                    (200, r#"{"access_token":"a"}"#),
                    (200, r#"{"access_token":"b"}"#),
                ],
            )
            .on(
                "GET",
                "/authorize/n_x",
                vec![(401, r#"{"error":"Invalid token"}"#)],
            );
        let mut client = Client::with_transport(
            ClientOptions {
                gateway_url: "https://gw.example".into(),
                client_id: Some("cid".into()),
                client_secret: Some("secret".into()),
                ..Default::default()
            },
            transport,
        ).unwrap();
        let err = client
            .status("n_x")
            .expect_err("a 401 after the one retry must surface, not loop");
        assert!(err.contains("401"), "unexpected error: {}", err);
        let (exchanges, bearers) = count_auth(&client.transport.seen_auth.borrow());
        assert_eq!(exchanges, 2, "exactly one re-exchange");
        assert_eq!(bearers, vec!["Bearer a", "Bearer b"]);
    }

    #[test]
    fn explicit_token_is_never_re_exchanged_on_401() {
        // No /oauth/token route at all: an exchange attempt would fail with "no mock route".
        let transport = MockTransport::new().on(
            "POST",
            "/authorize",
            vec![(401, r#"{"error":"Invalid token"}"#)],
        );
        let mut client = Client::with_transport(
            ClientOptions {
                gateway_url: "https://gw.example".into(),
                // Credentials are present too, so a re-exchange WOULD be possible — the explicit
                // token must still win and never be swapped out behind the caller's back.
                token: Some("t".into()),
                client_id: Some("cid".into()),
                client_secret: Some("secret".into()),
            },
            transport,
        ).unwrap();
        let err = client
            .authorize(
                "wire",
                &AuthorizeOptions {
                    target: Some("prod-payments".into()),
                    ..Default::default()
                },
            )
            .expect_err("a 401 on an explicit token is the caller's to handle");
        assert!(err.contains("401"), "unexpected error: {}", err);
        let (exchanges, bearers) = count_auth(&client.transport.seen_auth.borrow());
        assert_eq!(exchanges, 0);
        assert_eq!(bearers, vec!["Bearer t"]);
    }

    #[test]
    fn consume_rebinding() {
        let transport =
            MockTransport::new().on("POST", "/authorize/verify", vec![(200, r#"{"ok":true}"#)]);
        let mut client = Client::with_transport(
            ClientOptions {
                gateway_url: "https://gw.example".into(),
                token: Some("t".into()),
                ..Default::default()
            },
            transport,
        ).unwrap();
        let out = client
            .consume(
                "n_1",
                "prod-payments",
                "wire_transfer",
                Some(json!({"amount":5000})),
            )
            .unwrap();
        assert!(out.ok);
    }

    // DIV §3 Invariant 5: an approval that names no target binds no execution environment, and the
    // gateway silently defaults a missing one to "global" — so refusing here is the only place the
    // caller ever finds out. `consume` without it was simply a 400, making redemption unreachable.
    #[test]
    fn target_is_required() {
        let mut client = Client::with_transport(
            ClientOptions {
                gateway_url: "https://gw.example".into(),
                token: Some("t".into()),
                ..Default::default()
            },
            MockTransport::new(),
        ).unwrap();

        let err = client
            .authorize(
                "wire",
                &AuthorizeOptions {
                    action_type: Some("wire".into()),
                    ..Default::default()
                },
            )
            .expect_err(
                "authorize accepted an empty target; the gateway would have signed target=global",
            );
        assert!(
            err.contains("target is required"),
            "unexpected error: {}",
            err
        );

        let err = client.consume("n_1", "   ", "wire", None).expect_err(
            "consume accepted a blank target; the gateway would have rejected it with a 400",
        );
        assert!(err.contains("target"), "unexpected error: {}", err);
    }

    #[test]
    fn base64_matches_known_vector() {
        assert_eq!(base64_encode(b"cid:secret"), "Y2lkOnNlY3JldA==");
    }
}
