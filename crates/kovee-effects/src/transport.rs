//! The narrow egress transport: the only code in Kovee that opens a socket
//! to a model provider, and the only code that ever sees a
//! [`Credential`].
//!
//! The [`Transport`] trait exists so the enforcement chain is testable
//! without a provider account, and so the broker cannot accidentally grow a
//! second egress path: the broker sends through one [`Egress`] and has no
//! other way to move bytes.
//!
//! [`HttpsTransport`] is the live one:
//!
//! - **TLS 1.3 only**, rustls with the pure-Rust `rustls-rustcrypto`
//!   provider and the compiled-in Mozilla root bundle (no ambient
//!   filesystem trust store), resumption and early data disabled;
//! - **the address is re-checked at connection time**, after resolution and
//!   before the handshake, so a provider name that resolves inward (SSRF /
//!   DNS rebinding) never gets a TLS session;
//! - **no redirects, ever** — a `3xx` is returned as-is and the driver
//!   treats it as a provider error, so a redirect cannot move the
//!   destination away from the authorized origin;
//! - **the credential is injected here**, from the resolved `Credential`,
//!   into exactly one header, and is not part of the request record.
//!
//! `RecordingTransport` is the test double: it records the origin, headers,
//! and body it was asked to send and returns a scripted response. An effect
//! dispatched through it records `transport_profile: recording-test-double`,
//! so a receipt can never silently claim a real provider call. It exists
//! **only** under `cfg(test)` or the `testing` feature — a production build
//! has no such type to pass (R3-B02).
//!
//! # The seal (R3-B02)
//!
//! R3's confirmation compiled an outside program that called
//! `HttpsTransport::new()` and then `Transport::send(...)` with a
//! `PreparedRequest` of its own and a credential from `resolve` — no permit,
//! no plan, no ledger. That is now impossible, and by absence rather than by
//! discipline:
//!
//! - [`Transport`], [`HttpsTransport`], [`RawResponse`] and [`TransportError`]
//!   are **crate-private**. Outside this crate there is no trait to call, no
//!   type to construct, and no `send` to name.
//! - …and this **module is private too**. That is the second half, and it was
//!   missing: while `transport` was a public module, `pub` on any raw item
//!   here republished the whole bypass through `kovee_effects::transport::*`
//!   — which R3's confirmation did, recompiling the old no-permit consumer
//!   while the compile gate, checking only root re-exports, stayed green.
//!   `tests/compile_gate.rs` now asserts rustc's own "module `transport` is
//!   private" diagnostic, so re-publishing it fails the gate.
//! - The one public egress value is [`Egress`], and it has exactly one
//!   production constructor, [`Egress::live`], which hands back the process's
//!   single wire — one value per process, not one per call
//!   (`the_live_wire_is_one_transport_per_process`) — without ever exposing
//!   it.
//! - An `Egress` does nothing on its own. The only function that moves a byte
//!   through one is [`crate::dispatch`], which needs an
//!   [`ExecutionPermit`](crate::ExecutionPermit) by value and claims its
//!   single use in the [`ConsumptionAuthority`](crate::ConsumptionAuthority)'s
//!   own durable ledger first.
//!
//! So the reachable surface for a caller holding a valid provider credential
//! is: obtain an `Egress`, and be unable to do anything with it but pass it to
//! the gate.
//!
//! What you write:
//! ```no_run
//! use kovee_effects::Egress;
//! let egress = Egress::live();
//! assert_eq!(egress.profile(), kovee_effects::PROFILE_HTTPS);
//! // …and the only thing that can be done with it is `dispatch(.., permit, &egress, ..)`.
//! ```

use std::io::{Read as _, Write as _};
use std::net::{IpAddr, TcpStream, ToSocketAddrs as _};
use std::sync::Arc;
#[cfg(any(test, feature = "testing"))]
use std::sync::Mutex;
use std::time::Duration;

use crate::credential::Credential;
use crate::driver::PreparedRequest;
use crate::egress::{check_resolved_for, EgressPolicy, Origin};

/// The transport profile recorded on an effect: which wire actually carried
/// it. An audit can therefore tell a real provider call from a test one.
pub const PROFILE_HTTPS: &str = "https-tls13";
/// The recording double's profile.
pub const PROFILE_RECORDING: &str = "recording-test-double";

/// The §11.8-shaped cap on a provider response body. A model that answers
/// with more than this is refused rather than buffered.
pub const RESPONSE_MAX_BYTES: usize = 4 * 1024 * 1024;

/// One raw provider response. Crate-private: nothing outside can hold the
/// result of a send, because nothing outside can perform one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RawResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

/// Why a send failed — and, decisively, whether bytes may have left.
#[derive(Debug, thiserror::Error)]
pub(crate) enum TransportError {
    /// Nothing was transmitted: the destination was refused, resolution
    /// failed, or the connection never opened. Safe to classify `failed`.
    #[error("no request was transmitted: {0}")]
    NotSent(String),
    /// The request was (or may have been) transmitted and the outcome is
    /// unknown. This is the `ambiguous` case: never auto-retried.
    #[error("the request may have been transmitted; the outcome is unknown: {0}")]
    Uncertain(String),
}

impl TransportError {
    /// Whether this failure leaves the effect `ambiguous` rather than
    /// cleanly `failed`.
    pub(crate) fn is_uncertain(&self) -> bool {
        matches!(self, TransportError::Uncertain(_))
    }
}

/// The one egress path (§16.3 step 5). Object-safe, and **crate-private**:
/// outside this crate there is no `send` to call (R3-B02).
pub(crate) trait Transport: Send + Sync {
    /// The profile recorded on the effect.
    fn profile(&self) -> &'static str;

    /// Sends the prepared request to `origin`, injecting `credential`.
    fn send(
        &self,
        origin: &Origin,
        request: &PreparedRequest,
        credential: &Credential,
        timeout: Duration,
    ) -> Result<RawResponse, TransportError>;
}

// ------------------------------------------------------------- the seal ----

/// The sealed egress: the only value [`crate::dispatch`] will send bytes
/// through, and the only egress-shaped thing that exists outside this crate.
///
/// There is no `From<&dyn Transport>`, no way to name the trait, and no way
/// to construct the live wire: [`Egress::live`] hands back the process's one
/// [`HttpsTransport`], created on first use and never exposed. Under
/// `cfg(test)` or the `testing` feature there is additionally the recording
/// double. That is what "the live transport is sealed inside the Daemon"
/// means as a type rather than a habit (R3-B02).
#[derive(Debug)]
pub struct Egress<'a> {
    wire: Wire<'a>,
}

#[derive(Debug)]
enum Wire<'a> {
    Live(&'a HttpsTransport),
    #[cfg(any(test, feature = "testing"))]
    Recording(&'a RecordingTransport),
}

/// The process's single live wire. Building a rustls client config reads the
/// compiled-in Mozilla root bundle, so it is done once; and because the value
/// never leaves this module, "who may send" is not a question a caller gets
/// to answer.
static LIVE: std::sync::OnceLock<HttpsTransport> = std::sync::OnceLock::new();

impl Egress<'static> {
    /// The live TLS 1.3 wire. It carries no destination and no credential of
    /// its own: both arrive at [`crate::dispatch`], from the permit and from
    /// the daemon's secret table respectively.
    pub fn live() -> Egress<'static> {
        Egress {
            wire: Wire::Live(LIVE.get_or_init(HttpsTransport::new)),
        }
    }
}

impl<'a> Egress<'a> {
    /// The profile recorded on the effect, so an audit can tell a real
    /// provider call from a test one.
    pub fn profile(&self) -> &'static str {
        self.transport().profile()
    }

    /// Crate-private: nothing outside this crate can extract the wire and
    /// send bytes through it directly.
    pub(crate) fn transport(&self) -> &dyn Transport {
        match self.wire {
            Wire::Live(transport) => transport,
            #[cfg(any(test, feature = "testing"))]
            Wire::Recording(transport) => transport,
        }
    }

    /// The recording double — test configuration only.
    #[cfg(any(test, feature = "testing"))]
    pub fn recording(transport: &'a RecordingTransport) -> Egress<'a> {
        Egress {
            wire: Wire::Recording(transport),
        }
    }
}

#[cfg(any(test, feature = "testing"))]
impl<'a> From<&'a RecordingTransport> for Egress<'a> {
    fn from(transport: &'a RecordingTransport) -> Egress<'a> {
        Egress::recording(transport)
    }
}

// ----------------------------------------------------------------- https ----

/// The live TLS 1.3 transport. Crate-private, and reachable only as the one
/// value [`Egress::live`] wraps.
pub(crate) struct HttpsTransport {
    config: Arc<rustls::ClientConfig>,
}

impl std::fmt::Debug for HttpsTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HttpsTransport")
    }
}

impl HttpsTransport {
    fn new() -> HttpsTransport {
        HttpsTransport {
            config: Arc::new(client_config()),
        }
    }
}

/// The rustls client config: TLS 1.3 only, Mozilla roots compiled in, no
/// client certificate (public providers authenticate with a bearer
/// credential, not mTLS), no resumption, no early data.
fn client_config() -> rustls::ClientConfig {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let provider = Arc::new(rustls_rustcrypto::provider());
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap_or_else(|_| {
            // The provider always supports TLS 1.3; this arm exists only so
            // the daemon does not panic if a future provider drops it.
            rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        })
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.resumption = rustls::client::Resumption::disabled();
    config.enable_early_data = false;
    config
}

impl Transport for HttpsTransport {
    fn profile(&self) -> &'static str {
        PROFILE_HTTPS
    }

    fn send(
        &self,
        origin: &Origin,
        request: &PreparedRequest,
        credential: &Credential,
        timeout: Duration,
    ) -> Result<RawResponse, TransportError> {
        // 1. Resolve, then check EVERY address the name resolves to. The
        //    check is on the address the connection will use, which is what
        //    makes a rebinding answer useless.
        let policy = EgressPolicy::allowing([origin.clone()]);
        let addresses: Vec<IpAddr> = (origin.host.as_str(), origin.port)
            .to_socket_addrs()
            .map_err(|e| TransportError::NotSent(format!("resolve {}: {e}", origin.host)))?
            .map(|sa| sa.ip())
            .collect();
        if addresses.is_empty() {
            return Err(TransportError::NotSent(format!(
                "{} resolved to no address",
                origin.host
            )));
        }
        for addr in &addresses {
            check_resolved_for(origin, *addr, &policy)
                .map_err(|e| TransportError::NotSent(e.to_string()))?;
        }

        // 2. Connect and handshake. Nothing has been transmitted yet.
        let addr = addresses
            .first()
            .copied()
            .ok_or_else(|| TransportError::NotSent("no address".to_owned()))?;
        let tcp = TcpStream::connect_timeout(&(addr, origin.port).into(), timeout)
            .map_err(|e| TransportError::NotSent(format!("connect {addr}: {e}")))?;
        tcp.set_read_timeout(Some(timeout))
            .and_then(|()| tcp.set_write_timeout(Some(timeout)))
            .map_err(|e| TransportError::NotSent(e.to_string()))?;
        let server_name = rustls_pki_types::ServerName::try_from(origin.host.clone())
            .map_err(|e| TransportError::NotSent(format!("server name: {e}")))?;
        let connection = rustls::ClientConnection::new(Arc::clone(&self.config), server_name)
            .map_err(|e| TransportError::NotSent(format!("tls setup: {e}")))?;
        let mut stream = rustls::StreamOwned::new(connection, tcp);

        // 3. Write the request. From the first flush onward, a failure is
        //    UNCERTAIN: the provider may have received and billed it.
        let wire = wire_bytes(origin, request, credential);
        let sent = stream
            .write_all(&wire)
            .and_then(|()| stream.flush())
            .map_err(|e| TransportError::Uncertain(format!("write: {e}")));
        // The credential exists only inside `wire`; scrub it now rather
        // than leaving the whole request in a buffer for the read phase.
        let mut wire = wire;
        wire.iter_mut().for_each(|b| *b = 0);
        sent?;

        // 4. Read the response under the cap.
        let mut raw = Vec::new();
        let mut buffer = [0u8; 16 * 1024];
        loop {
            match stream.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => {
                    raw.extend_from_slice(&buffer[..n]);
                    if raw.len() > RESPONSE_MAX_BYTES {
                        return Err(TransportError::Uncertain(format!(
                            "the provider response exceeded the {RESPONSE_MAX_BYTES}-byte cap"
                        )));
                    }
                    if let Some(response) = try_parse(&raw) {
                        return Ok(response);
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(TransportError::Uncertain(format!("read: {e}"))),
            }
        }
        try_parse(&raw)
            .ok_or_else(|| TransportError::Uncertain("the provider closed mid-response".to_owned()))
    }
}

/// The HTTP/1.1 request bytes. `connection: close` keeps this a single
/// exchange per effect attempt — no pooled socket outliving the permit.
fn wire_bytes(origin: &Origin, request: &PreparedRequest, credential: &Credential) -> Vec<u8> {
    let (auth_header, prefix) = request.auth.header();
    let mut head = String::new();
    head.push_str(&format!("{} {} HTTP/1.1\r\n", request.method, request.path));
    head.push_str(&format!("host: {}\r\n", origin.host_header()));
    head.push_str("accept: application/json\r\n");
    head.push_str("content-type: application/json\r\n");
    head.push_str("connection: close\r\n");
    head.push_str(&format!("content-length: {}\r\n", request.body.len()));
    for (name, value) in &request.headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    // The single point where a credential is written out.
    head.push_str(&format!(
        "{auth_header}: {prefix}{}\r\n",
        credential.expose()
    ));
    head.push_str("\r\n");
    let mut wire = head.into_bytes();
    wire.extend_from_slice(&request.body);
    wire
}

/// Parses a complete HTTP/1.1 response, or `None` when more bytes are
/// needed. Only what a JSON provider reply needs: status line, headers,
/// then either `content-length` or chunked body.
fn try_parse(raw: &[u8]) -> Option<RawResponse> {
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n")?;
    let head = std::str::from_utf8(raw.get(..split)?).ok()?;
    let mut lines = head.split("\r\n");
    let status: u16 = lines.next()?.split(' ').nth(1)?.parse().ok()?;
    let mut content_length: Option<usize> = None;
    let mut chunked = false;
    for line in lines {
        let (name, value) = line.split_once(':')?;
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim();
        if name == "content-length" {
            content_length = value.parse().ok();
        } else if name == "transfer-encoding" && value.eq_ignore_ascii_case("chunked") {
            chunked = true;
        }
    }
    let body = raw.get(split + 4..)?;
    if chunked {
        let decoded = dechunk(body)?;
        return Some(RawResponse {
            status,
            body: decoded,
        });
    }
    let length = content_length?;
    if body.len() < length {
        return None;
    }
    Some(RawResponse {
        status,
        body: body.get(..length)?.to_vec(),
    })
}

/// Decodes a complete `Transfer-Encoding: chunked` body, or `None` when the
/// terminal zero-length chunk has not arrived.
fn dechunk(mut body: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let line_end = body.windows(2).position(|w| w == b"\r\n")?;
        let size_line = std::str::from_utf8(body.get(..line_end)?).ok()?;
        let size = usize::from_str_radix(size_line.split(';').next()?.trim(), 16).ok()?;
        body = body.get(line_end + 2..)?;
        if size == 0 {
            return Some(out);
        }
        out.extend_from_slice(body.get(..size)?);
        body = body.get(size + 2..)?;
    }
}

// ------------------------------------------------------------- recording ----

/// One recorded send: everything the transport was asked to transmit,
/// including the credential header, so a test can prove the key reached the
/// wire and *only* the wire.
#[cfg(any(test, feature = "testing"))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SentRequest {
    pub origin: Origin,
    pub method: &'static str,
    pub path: &'static str,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

#[cfg(any(test, feature = "testing"))]
impl SentRequest {
    /// The value of one header, case-insensitively.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// A [`Transport`] that records instead of dialing. It is how the
/// enforcement chain is proven: "zero sends" is a machine-checkable fact.
/// Test configuration only: a production build has no such type, so nothing
/// there can hand the broker a wire of its own (R3-B02).
#[cfg(any(test, feature = "testing"))]
#[derive(Debug, Default)]
pub struct RecordingTransport {
    sent: Mutex<Vec<SentRequest>>,
    script: Mutex<Vec<Result<RawResponse, String>>>,
}

#[cfg(any(test, feature = "testing"))]
impl RecordingTransport {
    /// A transport that answers `200` with `body` for every send.
    pub fn answering(body: &[u8]) -> RecordingTransport {
        RecordingTransport::responding(200, body)
    }

    /// A transport that answers `status` with `body` for every send.
    pub fn responding(status: u16, body: &[u8]) -> RecordingTransport {
        RecordingTransport {
            sent: Mutex::new(Vec::new()),
            script: Mutex::new(vec![Ok(RawResponse {
                status,
                body: body.to_vec(),
            })]),
        }
    }

    /// A transport whose next send fails with an UNCERTAIN outcome — the
    /// `ambiguous` path.
    pub fn uncertain(reason: &str) -> RecordingTransport {
        RecordingTransport {
            sent: Mutex::new(Vec::new()),
            script: Mutex::new(vec![Err(reason.to_owned())]),
        }
    }

    /// Everything this transport was asked to send.
    pub fn sent(&self) -> Vec<SentRequest> {
        self.sent.lock().map(|s| s.clone()).unwrap_or_default()
    }

    /// How many requests actually left. Zero is the proof that a refusal
    /// happened before egress.
    pub fn send_count(&self) -> usize {
        self.sent.lock().map(|s| s.len()).unwrap_or(0)
    }
}

#[cfg(any(test, feature = "testing"))]
impl Transport for RecordingTransport {
    fn profile(&self) -> &'static str {
        PROFILE_RECORDING
    }

    fn send(
        &self,
        origin: &Origin,
        request: &PreparedRequest,
        credential: &Credential,
        _timeout: Duration,
    ) -> Result<RawResponse, TransportError> {
        let (auth_header, prefix) = request.auth.header();
        let mut headers = request.headers.clone();
        headers.push((
            auth_header.to_owned(),
            format!("{prefix}{}", credential.expose()),
        ));
        if let Ok(mut sent) = self.sent.lock() {
            sent.push(SentRequest {
                origin: origin.clone(),
                method: request.method,
                path: request.path,
                headers,
                body: request.body.clone(),
            });
        }
        let scripted = self.script.lock().ok().and_then(|mut s| {
            if s.len() > 1 {
                s.pop()
            } else {
                s.first().cloned()
            }
        });
        match scripted {
            Some(Ok(response)) => Ok(response),
            Some(Err(reason)) => Err(TransportError::Uncertain(reason)),
            None => Err(TransportError::NotSent("no scripted response".to_owned())),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::driver::{ModelDriver, ModelRequest, ANTHROPIC, OPENAI};

    fn prepared() -> PreparedRequest {
        ANTHROPIC
            .build(&ModelRequest {
                model: "claude-haiku-4-5-20251001",
                system: None,
                prompt: "Say OK.",
                max_output_tokens: 16,
            })
            .unwrap()
    }

    #[test]
    fn the_wire_carries_exactly_one_credential_header_and_no_url() {
        let origin = Origin::https("api.anthropic.com", 443);
        let wire = wire_bytes(&origin, &prepared(), &Credential::new("sk-ant-secret"));
        let text = String::from_utf8_lossy(&wire);
        assert!(text.starts_with("POST /v1/messages HTTP/1.1\r\n"));
        assert!(text.contains("host: api.anthropic.com\r\n"));
        assert!(text.contains("anthropic-version: 2023-06-01\r\n"));
        assert!(text.contains("connection: close\r\n"));
        assert_eq!(text.matches("sk-ant-secret").count(), 1);
        assert!(text.contains("x-api-key: sk-ant-secret\r\n"));
        // The request line is a PATH; no absolute URL is ever written.
        assert!(!text.contains("https://"));
    }

    #[test]
    fn the_openai_credential_is_a_bearer_token() {
        let origin = Origin::https("api.openai.com", 443);
        let request = OPENAI
            .build(&ModelRequest {
                model: "gpt-4o-mini",
                system: None,
                prompt: "hi",
                max_output_tokens: 8,
            })
            .unwrap();
        let wire = wire_bytes(&origin, &request, &Credential::new("sk-openai"));
        let text = String::from_utf8_lossy(&wire);
        assert!(text.contains("authorization: Bearer sk-openai\r\n"));
    }

    #[test]
    fn a_content_length_response_parses_when_complete() {
        let raw = b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 7\r\n\r\n{\"a\":1}";
        assert_eq!(
            try_parse(raw).unwrap(),
            RawResponse {
                status: 200,
                body: br#"{"a":1}"#.to_vec()
            }
        );
        // One byte short: keep reading rather than parsing a truncation.
        assert!(try_parse(&raw[..raw.len() - 1]).is_none());
        // Headers only: not complete.
        assert!(try_parse(b"HTTP/1.1 200 OK\r\ncontent-length: 7\r\n").is_none());
    }

    #[test]
    fn a_chunked_response_parses_only_after_its_terminator() {
        let complete = b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n4\r\n{\"a\"\r\n3\r\n:1}\r\n0\r\n\r\n";
        assert_eq!(
            try_parse(complete).unwrap(),
            RawResponse {
                status: 200,
                body: br#"{"a":1}"#.to_vec()
            }
        );
        let partial = b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n4\r\n{\"a\"\r\n";
        assert!(try_parse(partial).is_none());
    }

    #[test]
    fn a_non_2xx_status_is_parsed_not_followed() {
        // A redirect is returned as-is; the transport never follows it, so a
        // 3xx cannot move the destination away from the authorized origin.
        let raw = b"HTTP/1.1 302 Found\r\nlocation: https://elsewhere.example/\r\ncontent-length: 0\r\n\r\n";
        let response = try_parse(raw).unwrap();
        assert_eq!(response.status, 302);
        assert!(response.body.is_empty());
    }

    #[test]
    fn the_recording_double_counts_sends_and_names_its_profile() {
        let transport = RecordingTransport::answering(br#"{"ok":true}"#);
        assert_eq!(transport.send_count(), 0);
        assert_eq!(transport.profile(), PROFILE_RECORDING);
        let origin = Origin::https("api.anthropic.com", 443);
        let response = transport
            .send(
                &origin,
                &prepared(),
                &Credential::new("sk-ant-secret"),
                Duration::from_secs(1),
            )
            .unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(transport.send_count(), 1);
        let sent = transport.sent().pop().unwrap();
        assert_eq!(sent.origin, origin);
        assert_eq!(sent.path, "/v1/messages");
        assert_eq!(sent.header("x-api-key"), Some("sk-ant-secret"));
    }

    #[test]
    fn an_uncertain_send_is_flagged_uncertain() {
        let transport = RecordingTransport::uncertain("connection reset after write");
        let error = transport
            .send(
                &Origin::https("api.anthropic.com", 443),
                &prepared(),
                &Credential::new("k"),
                Duration::from_secs(1),
            )
            .unwrap_err();
        assert!(error.is_uncertain());
        // It still counts as a send: bytes may have left.
        assert_eq!(transport.send_count(), 1);
        assert!(!TransportError::NotSent("refused".into()).is_uncertain());
    }

    #[test]
    fn the_live_config_is_tls13_only_with_no_resumption() {
        let config = client_config();
        assert!(!config.enable_early_data, "no 0-RTT");
        // Every negotiable suite is a TLS 1.3 suite: the config was built
        // with exactly one protocol version.
        let versions: Vec<_> = config
            .crypto_provider()
            .cipher_suites
            .iter()
            .map(|s| s.version().version)
            .collect();
        assert!(!versions.is_empty(), "the provider offers suites");
        assert!(
            versions
                .iter()
                .all(|v| *v == rustls::ProtocolVersion::TLSv1_3),
            "TLS 1.3 only, got {versions:?}"
        );
    }

    /// The live wire is **one value per process**, not one per `Egress::live()`.
    ///
    /// It is a claim the module makes ("created on first use and never
    /// exposed", "who may send is not a question a caller gets to answer"),
    /// and R3's confirmation showed nothing checked it: replacing the
    /// singleton with a fresh transport per call left every claimed test
    /// green. Identity is the only observable difference, so identity is what
    /// this asserts.
    #[test]
    fn the_live_wire_is_one_transport_per_process() {
        fn live() -> *const HttpsTransport {
            match Egress::live().wire {
                Wire::Live(transport) => transport as *const HttpsTransport,
                #[cfg(any(test, feature = "testing"))]
                Wire::Recording(_) => panic!("`live` handed back a recording double"),
            }
        }
        assert_eq!(
            live(),
            live(),
            "every `Egress::live()` must wrap the SAME wire: a per-call \
             transport is a per-call rustls config, and a second place bytes \
             can leave from"
        );
        // …and it is the singleton, not merely some stable address.
        assert_eq!(
            live(),
            LIVE.get().expect("the singleton is initialized") as *const HttpsTransport
        );
        assert_eq!(Egress::live().profile(), PROFILE_HTTPS);
    }

    #[test]
    fn an_inward_resolving_provider_host_never_gets_a_handshake() {
        // `localhost` resolves to loopback; the address-class check refuses
        // it before the connection, so this is NotSent, never Uncertain.
        let transport = HttpsTransport::new();
        let error = transport
            .send(
                &Origin::https("localhost", 443),
                &prepared(),
                &Credential::new("k"),
                Duration::from_millis(200),
            )
            .unwrap_err();
        assert!(!error.is_uncertain(), "nothing was transmitted: {error}");
        assert!(
            error.to_string().contains("loopback") || error.to_string().contains("resolve"),
            "{error}"
        );
    }
}
