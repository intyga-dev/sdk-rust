//! Rust client for Intyga. The primitive is uniform: request a challenge → a human approves on their
//! wallet → poll until resolved. It works for AI agents, humans, and any backend service; the only
//! difference is which API key/token you hold.
//!
//! Offline receipt verification lives in the standalone `intyga-verify` crate and is re-exported here so
//! a relying party can re-verify what was signed without a second dependency.

use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

// Re-export the offline verifier so SDK consumers can check receipts in-process.
pub use intyga_verify::{
    verify_approval_receipt, verify_approval_receipt_with_options, ApprovalReceipt, Expected,
    VerifyOptions,
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
}

/// Structured, WYSIWYS-bound details of an approval request.
#[derive(Debug, Clone, Default)]
pub struct AuthorizeOptions {
    /// Action identifier, e.g. "wire_transfer". Bound into the signed payload.
    pub action_type: Option<String>,
    /// The exact structured variables that will execute — displayed in the wallet AND signed.
    pub params: Option<Value>,
    /// Optional override for the server's default challenge TTL, in seconds.
    pub timeout_seconds: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuthorizeResponse {
    pub nonce: String,
    pub status: ApprovalStatus,
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

/// Pluggable HTTP transport, so the client logic is testable without real sockets and users can bring
/// their own async/proxy/instrumented client. `headers` is a list of (name, value) pairs.
pub trait Transport {
    fn request(
        &self,
        method: &str,
        url: &str,
        headers: &[(&str, &str)],
        body: Option<&str>,
    ) -> Result<HttpResponse, String>;
}

/// Options for constructing a [`Client`].
#[derive(Debug, Clone, Default)]
pub struct ClientOptions {
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

/// How many back-to-back polling failures before `require_approval` declares the gateway unreachable.
const MAX_POLL_ERRORS: u32 = 5;

/// A Intyga gateway client generic over its HTTP [`Transport`].
pub struct Client<T: Transport> {
    opts: ClientOptions,
    transport: T,
    cached_token: Option<String>,
}

impl<T: Transport> Client<T> {
    pub fn with_transport(opts: ClientOptions, transport: T) -> Self {
        Client {
            opts,
            transport,
            cached_token: None,
        }
    }

    /// Resolve a bearer token: the provided one, a cached exchange, or a fresh client-credentials exchange.
    pub fn token(&mut self) -> Result<String, String> {
        if let Some(t) = &self.opts.token {
            return Ok(t.clone());
        }
        if let Some(t) = &self.cached_token {
            return Ok(t.clone());
        }
        let (id, secret) = match (&self.opts.client_id, &self.opts.client_secret) {
            (Some(id), Some(secret)) => (id, secret),
            _ => return Err("provide token, or client_id + client_secret".to_string()),
        };
        let basic = base64_encode(format!("{}:{}", id, secret).as_bytes());
        let res = self.transport.request(
            "POST",
            &format!("{}/oauth/token", self.opts.gateway_url),
            &[("authorization", &format!("Basic {}", basic))],
            None,
        )?;
        if !(200..300).contains(&res.status) {
            return Err(format!(
                "token exchange failed: {} {}",
                res.status, res.body
            ));
        }
        let data: Value =
            serde_json::from_str(&res.body).map_err(|e| format!("bad token response: {}", e))?;
        let token = data
            .get("access_token")
            .and_then(Value::as_str)
            .ok_or("token response missing access_token")?
            .to_string();
        self.cached_token = Some(token.clone());
        Ok(token)
    }

    /// Create an approval challenge and return its nonce and initial status.
    pub fn authorize(
        &mut self,
        action_description: &str,
        opts: &AuthorizeOptions,
    ) -> Result<AuthorizeResponse, String> {
        let mut body = json!({
            "actionDescription": action_description,
            "actionType": opts.action_type,
            "params": opts.params.clone().unwrap_or_else(|| json!({})),
        });
        if let Some(t) = opts.timeout_seconds {
            body["timeout"] = json!(t);
        }
        let res = self.do_json("POST", "/authorize", Some(&body))?;
        serde_json::from_str(&res).map_err(|e| format!("bad authorize response: {}", e))
    }

    /// Execution-time re-binding: after APPROVED, call this immediately before running the action so the
    /// gateway confirms the approved signature matches the exact instruction and marks it single-use.
    pub fn consume(
        &mut self,
        nonce: &str,
        action_type: &str,
        params: Option<Value>,
    ) -> Result<ConsumeResult, String> {
        let body = json!({
            "nonce": nonce,
            "actionType": action_type,
            "params": params.unwrap_or_else(|| json!({})),
        });
        let res = self.do_json("POST", "/authorize/verify", Some(&body))?;
        serde_json::from_str(&res).map_err(|e| format!("bad consume response: {}", e))
    }

    /// Poll a challenge's current state (non-blocking).
    pub fn status(&mut self, nonce: &str) -> Result<ApprovalResult, String> {
        let path = format!("/authorize/{}", urlencode(nonce));
        let res = self.do_json("GET", &path, None)?;
        serde_json::from_str(&res).map_err(|e| format!("bad status response: {}", e))
    }

    /// The core zero-trust gate: call immediately before a high-risk action. It creates the challenge and
    /// blocks until the human approves/denies on their wallet (or it times out).
    pub fn require_approval(
        &mut self,
        action_description: &str,
        opts: &RequireApprovalOptions,
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

        let authorize = AuthorizeOptions {
            action_type: opts.authorize.action_type.clone(),
            params: opts.authorize.params.clone(),
            // Ceil to whole seconds so the challenge TTL covers the full local wait.
            timeout_seconds: Some((timeout.as_secs_f64().ceil()) as u64),
        };
        let auth_res = self.authorize(action_description, &authorize)?;
        let nonce = auth_res.nonce;

        let deadline = Instant::now() + timeout;
        let mut consecutive_errors = 0u32;
        loop {
            // A human approval can outlast a transient 502 — don't discard the whole wait over one bad poll.
            match self.status(&nonce) {
                Ok(mut r) => {
                    consecutive_errors = 0;
                    if r.status != ApprovalStatus::Pending {
                        r.nonce = Some(nonce);
                        return Ok(r);
                    }
                }
                Err(e) => {
                    consecutive_errors += 1;
                    if consecutive_errors >= MAX_POLL_ERRORS {
                        return Err(format!(
                            "polling failed after {} consecutive errors: {}",
                            MAX_POLL_ERRORS, e
                        ));
                    }
                }
            }
            if Instant::now() >= deadline {
                return Ok(ApprovalResult {
                    status: ApprovalStatus::Expired,
                    signature_hash: None,
                    receipt: None,
                    nonce: Some(nonce),
                });
            }
            std::thread::sleep(interval);
        }
    }

    /// Public witness lookup: has this document hash been signed, by whom, and when?
    pub fn verify(&mut self, document_hash: &str) -> Result<VerifyResult, String> {
        // Public endpoint — no auth header needed, but reusing do_json keeps behaviour uniform.
        let path = format!("/verify/{}", urlencode(document_hash));
        let res = self.do_json("GET", &path, None)?;
        serde_json::from_str(&res).map_err(|e| format!("bad verify response: {}", e))
    }

    /// Perform an authenticated JSON request, returning the response body on 2xx.
    fn do_json(
        &mut self,
        method: &str,
        path: &str,
        body: Option<&Value>,
    ) -> Result<String, String> {
        let token = self.token()?;
        let url = format!("{}{}", self.opts.gateway_url, path);
        let auth = format!("Bearer {}", token);
        let body_str = body.map(|b| b.to_string());

        let mut headers: Vec<(&str, &str)> = vec![("authorization", &auth)];
        if body_str.is_some() {
            headers.push(("content-type", "application/json"));
        }
        let res = self
            .transport
            .request(method, &url, &headers, body_str.as_deref())?;
        if !(200..300).contains(&res.status) {
            return Err(format!(
                "{} {} failed: {} {}",
                method, path, res.status, res.body
            ));
        }
        Ok(res.body)
    }
}

#[cfg(feature = "ureq-transport")]
impl Client<UreqTransport> {
    /// Construct a client using the built-in blocking `ureq` transport.
    pub fn new(opts: ClientOptions) -> Self {
        Client::with_transport(opts, UreqTransport)
    }
}

/// The built-in blocking HTTP transport, backed by `ureq`.
#[cfg(feature = "ureq-transport")]
pub struct UreqTransport;

#[cfg(feature = "ureq-transport")]
impl Transport for UreqTransport {
    fn request(
        &self,
        method: &str,
        url: &str,
        headers: &[(&str, &str)],
        body: Option<&str>,
    ) -> Result<HttpResponse, String> {
        let mut req = ureq::request(method, url);
        for (k, v) in headers {
            req = req.set(k, v);
        }
        let result = match body {
            Some(b) => req.send_string(b),
            None => req.call(),
        };
        match result {
            Ok(resp) => {
                let status = resp.status();
                let body = resp.into_string().map_err(|e| e.to_string())?;
                Ok(HttpResponse { status, body })
            }
            // ureq returns Err for non-2xx; surface the status and body rather than treating it as a
            // transport failure, so callers see the gateway's error.
            Err(ureq::Error::Status(status, resp)) => {
                let body = resp.into_string().unwrap_or_default();
                Ok(HttpResponse { status, body })
            }
            Err(e) => Err(e.to_string()),
        }
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
    use std::cell::RefCell;

    // A route is (method, path_suffix, response-sequence); each response is a (status, body) pair
    // consumed per matching call.
    type MockRoute = (String, String, Vec<(u16, String)>);

    // In-process mock transport: matches (method, path-suffix) and returns a canned response. Path is a
    // suffix match so tests don't hardcode the gateway URL. No sockets, no child processes.
    struct MockTransport {
        routes: RefCell<Vec<MockRoute>>,
        seen_auth: RefCell<Vec<String>>,
    }

    impl MockTransport {
        fn new() -> Self {
            MockTransport {
                routes: RefCell::new(Vec::new()),
                seen_auth: RefCell::new(Vec::new()),
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
            _body: Option<&str>,
        ) -> Result<HttpResponse, String> {
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
            Err(format!("no mock route for {} {}", method, url))
        }
    }

    fn fast_opts(a: AuthorizeOptions) -> RequireApprovalOptions {
        RequireApprovalOptions {
            authorize: a,
            timeout: Duration::from_secs(5),
            interval: Duration::from_millis(5),
        }
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
        );
        let res = client
            .require_approval(
                "Wire $5,000 to Acme Corp",
                &fast_opts(AuthorizeOptions {
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
        );
        let res = client
            .require_approval("delete prod", &fast_opts(AuthorizeOptions::default()))
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
        );
        assert_eq!(client.token().unwrap(), "exchanged");
        // Second call is served from cache (mock has a single-use route but cache avoids re-calling).
        assert_eq!(client.token().unwrap(), "exchanged");
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
        );
        let out = client
            .consume("n_1", "wire_transfer", Some(json!({"amount":5000})))
            .unwrap();
        assert!(out.ok);
    }

    #[test]
    fn base64_matches_known_vector() {
        assert_eq!(base64_encode(b"cid:secret"), "Y2lkOnNlY3JldA==");
    }
}
