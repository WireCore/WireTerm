//! Sign-in through WireCloud (the backend's "WireCloud" mode).
//!
//! A backend in WireCloud mode has no sign-in of its own: whoever wants to use
//! it identifies with a short-lived token from WireCloud. This module fetches
//! it. The flow is the one from `VERTRAG.md` 10.1 (WireCloud repository,
//! `docs/`), following RFC 8252 (native apps) and RFC 7636 (PKCE):
//!
//! 1. The client creates a `code_verifier`, from it the `code_challenge`
//!    (S256), and a random `state`. It opens a listener on `127.0.0.1` with a
//!    free port.
//! 2. It opens WireCloud's consent page in the **system browser**. The person
//!    signs in there (also with a second factor) and consents.
//! 3. WireCloud redirects back to the listener with `code` and `state`. The
//!    client checks `state` and exchanges the code for an access and a
//!    refresh token.
//! 4. With the access token it fetches **tool tokens** for this backend; with
//!    the tool token as `Authorization: Bearer` it talks to WireTerm.
//!
//! What applies here and why:
//!
//! - **There is exactly one redirect.** The listener accepts exactly one
//!   request that matches `state` and is closed afterwards. Everything else
//!   (wrong path, wrong `state`, wrong `Host`) gets a rejection and changes
//!   nothing: a foreign program on the computer cannot abort the sign-in this
//!   way, and with the `state` cannot get anything accepted anyway.
//! - **The refresh token is replaced on every use**, and presenting a
//!   replaced one again ends the whole session at WireCloud. That is why
//!   there is exactly one renewal at a time here ([`Wc`]), and all copies of a
//!   [`Jar`](super::http::Jar) share the same state: a copy that kept a long
//!   replaced token would be one session less.
//! - **Only the refresh token is stored on disk**, and only encrypted with the
//!   device key: the whole `Jar` is stored that way (`account::seal_sessions`).
//!   Access and tool tokens exist only in memory.
//! - **No token and no code in a message.** Error texts name the operation,
//!   never the value.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use rust_i18n::t;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;
use zeroize::Zeroize;

use super::http::{query_string, Api, ApiError, Jar, Server};

/// This client's ID at WireCloud (fixed list there, `lib/clientAuth.ts`).
pub const CLIENT_ID: &str = "wireterm-desktop";

/// The page the browser shows after the sign-in (styled like wirecore.net,
/// everything embedded, so the Content-Security-Policy need not allow loading anything).
const CALLBACK_PAGE: &str = include_str!("callback_page.html");

const CALLBACK_PATH: &str = "/callback";

/// How long to wait for the redirect. The person has to sign in, perhaps find
/// a second factor, and consent.
const LOGIN_TIMEOUT: Duration = Duration::from_secs(5 * 60);

/// How long a single connection to the listener has to send its request. A
/// browser does so immediately; anyone slower only holds things up.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// The listener tolerates no more requests than this that do not belong to the sign-in.
const MAX_REJECTED: usize = 20;

/// Length from which a request to the listener is too large.
const MAX_REQUEST: usize = 8 * 1024;

/// Time buffer: a token about to expire counts as expired. Otherwise it would
/// arrive at the server expired.
const ACCESS_MARGIN: Duration = Duration::from_secs(30);
const TOOL_MARGIN: Duration = Duration::from_secs(60);

// ---- PKCE and state ----------------------------------------------------------

/// Verifier and challenge of a sign-in attempt.
#[derive(Clone)]
pub struct Pkce {
    pub verifier: String,
    pub challenge: String,
}

impl Pkce {
    /// 32 random bytes, base64url without padding: 43 characters, exactly the
    /// lower bound of RFC 7636 and the length WireCloud expects.
    pub fn generate() -> Result<Self, String> {
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes)
            .map_err(|e| t!("wirecloud.no_randomness", error = e).to_string())?;
        let verifier = URL_SAFE_NO_PAD.encode(bytes);
        bytes.zeroize();
        Ok(Self::from_verifier(&verifier))
    }

    pub fn from_verifier(verifier: &str) -> Self {
        Self {
            verifier: verifier.to_string(),
            challenge: challenge_for(verifier),
        }
    }
}

/// `base64url(SHA-256(verifier))` without padding (S256).
pub fn challenge_for(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

/// The `state`: 16 random bytes as 32 hex characters. WireCloud requires at
/// least eight visible ASCII characters.
pub fn new_state() -> Result<String, String> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes)
        .map_err(|e| t!("wirecloud.no_randomness", error = e).to_string())?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

/// Same length and equal, without the timing revealing how far they match.
/// The length may show: the `state` always has the same one.
fn same(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |diff, (x, y)| diff | (x ^ y)) == 0
}

// ---- The address of the consent page -----------------------------------------

/// The address that opens in the system browser.
pub fn authorize_url(base: &str, redirect_uri: &str, challenge: &str, state: &str) -> String {
    let query = query_string(&[
        ("response_type", "code".to_string()),
        ("client_id", CLIENT_ID.to_string()),
        ("redirect_uri", redirect_uri.to_string()),
        ("code_challenge", challenge.to_string()),
        ("code_challenge_method", "S256".to_string()),
        ("state", state.to_string()),
    ]);
    format!("{base}/v1/client-auth/authorize?{query}")
}

// ---- The redirect ------------------------------------------------------------

/// Why a request to the listener is not accepted.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Rejection {
    Method,
    Path,
    Host,
    State,
    Malformed,
}

/// What a request to the listener means.
#[derive(Debug, PartialEq, Eq)]
pub enum Callback {
    /// The person consented: the code.
    Code(String),
    /// The person declined.
    Denied,
    /// WireCloud reports another error (identifier characters only, truncated).
    Error(String),
    /// Does not belong to this sign-in.
    Reject(Rejection),
}

fn decode(value: &str) -> String {
    // `+` in an address is a `+`, not a space; WireCloud writes `%20`. A `+`
    // would remain a valid character in the code for us either way.
    percent_encoding::percent_decode_str(value)
        .decode_utf8_lossy()
        .into_owned()
}

/// Reads the head of a request to the listener (request line and headers).
///
/// Only `GET /callback?…` to exactly `127.0.0.1:<port>` with the right
/// `state` and either a code in the form WireCloud issues or an error is
/// accepted. Everything else is rejected.
pub fn parse_callback(head: &str, port: u16, expected_state: &str) -> Callback {
    let mut lines = head.split("\r\n");
    let Some(request_line) = lines.next() else {
        return Callback::Reject(Rejection::Malformed);
    };
    let mut parts = request_line.split(' ');
    let (Some(method), Some(target), Some(version)) = (parts.next(), parts.next(), parts.next())
    else {
        return Callback::Reject(Rejection::Malformed);
    };
    if parts.next().is_some() || !version.starts_with("HTTP/1.") {
        return Callback::Reject(Rejection::Malformed);
    }
    if method != "GET" {
        return Callback::Reject(Rejection::Method);
    }

    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    if path != CALLBACK_PATH {
        return Callback::Reject(Rejection::Path);
    }

    // A browser sends the host under which it reaches the listener. Another
    // host would mean that a page on the net reaches the listener through a
    // redirected name (DNS rebinding).
    let host = lines
        .by_ref()
        .take_while(|line| !line.is_empty())
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.trim()
                .eq_ignore_ascii_case("host")
                .then(|| value.trim())
        });
    if host != Some(format!("127.0.0.1:{port}").as_str()) {
        return Callback::Reject(Rejection::Host);
    }

    let mut code = None;
    let mut error = None;
    let mut state = None;
    for pair in query.split('&').filter(|pair| !pair.is_empty()) {
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        match name {
            "code" => code = Some(decode(value)),
            "error" => error = Some(decode(value)),
            "state" => state = Some(decode(value)),
            _ => {}
        }
    }

    match state {
        Some(state) if same(&state, expected_state) => {}
        _ => return Callback::Reject(Rejection::State),
    }

    if let Some(error) = error {
        if error == "access_denied" {
            return Callback::Denied;
        }
        let safe: String = error
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
            .take(64)
            .collect();
        return Callback::Error(safe);
    }

    match code {
        // This is what a code from WireCloud looks like: 43 characters
        // base64url. The limit is generous, the characters are not: nothing
        // else gets through.
        Some(code)
            if !code.is_empty()
                && code.len() <= 256
                && code
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') =>
        {
            Callback::Code(code)
        }
        _ => Callback::Reject(Rejection::Malformed),
    }
}

/// How a sign-in attempt ends when it does not succeed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlowError {
    Cancelled,
    Timeout,
    Denied,
    /// WireCloud redirected back with an error.
    Failed(String),
    /// Too many requests that do not belong.
    Flooded,
    Io(String),
    /// Exchanging the code failed.
    Exchange(String),
}

impl std::fmt::Display for FlowError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cancelled => write!(f, "{}", t!("wirecloud.cancelled")),
            Self::Timeout => write!(f, "{}", t!("wirecloud.timeout")),
            Self::Denied => write!(f, "{}", t!("wirecloud.denied")),
            Self::Failed(code) => write!(f, "{}", t!("wirecloud.failed", code = code)),
            Self::Flooded => write!(f, "{}", t!("wirecloud.flooded")),
            Self::Io(detail) => write!(f, "{}", t!("wirecloud.io", detail = detail)),
            Self::Exchange(detail) => write!(f, "{detail}"),
        }
    }
}

/// The listener WireCloud redirects to. Listens only on `127.0.0.1`.
pub struct CallbackServer {
    listener: TcpListener,
    port: u16,
}

impl CallbackServer {
    /// Opens the listener on a free port of `127.0.0.1`.
    pub async fn bind() -> Result<Self, FlowError> {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .map_err(|e| FlowError::Io(e.to_string()))?;
        let port = listener
            .local_addr()
            .map_err(|e| FlowError::Io(e.to_string()))?
            .port();
        Ok(Self { listener, port })
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// The redirect address WireCloud sees in the request and in the
    /// exchange. It must be the same in both cases.
    pub fn redirect_uri(&self) -> String {
        format!("http://127.0.0.1:{}{CALLBACK_PATH}", self.port)
    }

    /// Waits for the redirect and returns the code. Accepts exactly one
    /// matching request and is closed afterwards (the listener is dropped on
    /// leaving).
    pub async fn wait(
        self,
        state: &str,
        timeout: Duration,
        cancel: &Notify,
    ) -> Result<String, FlowError> {
        let deadline = tokio::time::Instant::now() + timeout;
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Option<Callback>>();
        let mut rejected = 0usize;
        loop {
            tokio::select! {
                _ = cancel.notified() => return Err(FlowError::Cancelled),
                _ = tokio::time::sleep_until(deadline) => return Err(FlowError::Timeout),
                accepted = self.listener.accept() => {
                    // Each connection on its own: one that stays open and sends
                    // nothing does not hold up the right one.
                    if let Ok((stream, _)) = accepted {
                        let tx = tx.clone();
                        let port = self.port;
                        let state = state.to_string();
                        tokio::spawn(async move {
                            let _ = tx.send(serve(stream, port, &state).await);
                        });
                    }
                }
                // The sender stays in this function; `recv` therefore never ends with `None`.
                outcome = rx.recv() => match outcome.flatten() {
                    Some(Callback::Code(code)) => return Ok(code),
                    Some(Callback::Denied) => return Err(FlowError::Denied),
                    Some(Callback::Error(code)) => return Err(FlowError::Failed(code)),
                    Some(Callback::Reject(_)) | None => {
                        rejected += 1;
                        if rejected >= MAX_REJECTED {
                            return Err(FlowError::Flooded);
                        }
                    }
                },
            }
        }
    }
}

/// Reads a request, answers it and says what it was. `None` if no usable
/// request arrived at all.
async fn serve(mut stream: TcpStream, port: u16, state: &str) -> Option<Callback> {
    let head = tokio::time::timeout(REQUEST_TIMEOUT, read_head(&mut stream))
        .await
        .ok()??;
    let outcome = parse_callback(&head, port, state);

    // Heading, text and mark of the page; all fixed texts in the active
    // language, nothing of it comes from the request.
    let (status, page, mark) = match &outcome {
        Callback::Code(_) => ("200 OK", "done", "✓"),
        Callback::Denied => ("200 OK", "denied", "×"),
        Callback::Error(_) => ("200 OK", "failed", "×"),
        Callback::Reject(Rejection::Path) => ("404 Not Found", "not_found", "×"),
        Callback::Reject(Rejection::Method) => ("405 Method Not Allowed", "not_allowed", "×"),
        Callback::Reject(_) => ("400 Bad Request", "bad_request", "×"),
    };
    let heading = t!(format!("wirecloud.page_{page}_heading"));
    let text = t!(format!("wirecloud.page_{page}_text"));
    let page = CALLBACK_PAGE
        .replace("{{lang}}", &crate::locale::current())
        .replace("{{label}}", &t!("wirecloud.page_label"))
        .replace("{{heading}}", &heading)
        .replace("{{text}}", &text)
        .replace("{{mark}}", mark);
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\n\
         Cache-Control: no-store\r\nReferrer-Policy: no-referrer\r\n\
         Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'\r\nConnection: close\r\n\r\n{page}",
        page.len()
    );
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.shutdown().await;
    Some(outcome)
}

/// Reads up to the end of the headers, at most [`MAX_REQUEST`] bytes.
async fn read_head(stream: &mut TcpStream) -> Option<String> {
    let mut buffer = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    loop {
        let read = stream.read(&mut chunk).await.ok()?;
        if read == 0 {
            return None;
        }
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(end) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            return String::from_utf8(buffer[..end].to_vec()).ok();
        }
        if buffer.len() > MAX_REQUEST {
            return None;
        }
    }
}

// ---- Detecting the mode ------------------------------------------------------

/// What a backend in WireCloud mode reveals about itself
/// (`GET /.well-known/wirecloud-tool.json`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Discovery {
    /// This backend's ID at WireCloud (`aud` of the tool tokens).
    pub audience: String,
    /// Where WireCloud is reachable for clients, without a trailing slash.
    pub wirecloud_url: String,
}

/// Whether a WireCloud address is acceptable: HTTPS, or HTTP only to one's
/// own computer (development). Without credentials, query and fragment.
///
/// The address comes from the backend the person typed in. A backend that
/// entered a foreign site here would send the browser there; with HTTP into
/// the open net, credentials would travel in plaintext.
pub fn valid_wirecloud_url(value: &str) -> Option<String> {
    let url = reqwest::Url::parse(value.trim()).ok()?;
    if !url.username().is_empty() || url.password().is_some() {
        return None;
    }
    if url.query().is_some() || url.fragment().is_some() {
        return None;
    }
    if url.path() != "/" && !url.path().is_empty() {
        return None;
    }
    let host = url.host_str()?;
    let local = matches!(host, "localhost" | "127.0.0.1" | "[::1]");
    match url.scheme() {
        "https" => {}
        "http" if local => {}
        _ => return None,
    }
    Some(url.as_str().trim_end_matches('/').to_string())
}

/// Reads the description. `None` means: no WireCloud mode.
pub fn parse_discovery(value: &Value) -> Option<Discovery> {
    let audience = value.get("audience")?.as_str()?.trim();
    if audience.is_empty() {
        return None;
    }
    let wirecloud_url = valid_wirecloud_url(value.get("wirecloud_url")?.as_str()?)?;
    Some(Discovery {
        audience: audience.to_string(),
        wirecloud_url,
    })
}

/// Asks the backend whether it runs in WireCloud mode. If it does not answer,
/// answers without JSON or without `wirecloud_url`, it is not: the previous
/// way with email and sign-in password then applies as before.
pub async fn discover(server: &Server) -> Option<Discovery> {
    let api = Api::new(server).ok()?;
    let value = api
        .get("/.well-known/wirecloud-tool.json", &[], &mut Jar::default())
        .await
        .ok()?;
    parse_discovery(&value)
}

// ---- Tokens ------------------------------------------------------------------

/// A secret that appears in no `Debug` output and is overwritten when
/// dropped.
#[derive(Clone)]
struct Secret(String);

impl Drop for Secret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Secret(…)")
    }
}

/// The response of `POST /v1/client-auth/token`.
#[derive(Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    #[serde(default)]
    pub expires_in: u64,
    pub refresh_token: String,
}

impl std::fmt::Debug for TokenResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TokenResponse(…)")
    }
}

/// The response of `POST /v1/tool-tokens`.
#[derive(Deserialize)]
pub struct ToolTokenResponse {
    pub token: String,
    #[serde(default)]
    pub expires_in: u64,
}

/// What can go wrong when fetching and renewing tokens.
#[derive(Debug, Clone)]
pub enum WcError {
    /// The session at WireCloud is no longer valid (`invalid_grant`, signed
    /// out, revoked). Only a new sign-in helps here.
    Ended,
    /// The access token was rejected. Internal: renew and try again.
    Unauthorized,
    Offline(String),
    Api(ApiError),
}

impl From<WcError> for ApiError {
    fn from(error: WcError) -> Self {
        match error {
            WcError::Ended | WcError::Unauthorized => ApiError::Unauthorized,
            WcError::Offline(detail) => ApiError::Offline(detail),
            WcError::Api(error) => error,
        }
    }
}

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// The two calls to WireCloud that [`Wc`] needs. A trait, so that renewal can
/// be tested without a network.
pub trait Endpoint: Send + Sync {
    fn refresh<'a>(
        &'a self,
        refresh_token: &'a str,
    ) -> BoxFuture<'a, Result<TokenResponse, WcError>>;
    fn tool_token<'a>(
        &'a self,
        access_token: &'a str,
        audience: &'a str,
    ) -> BoxFuture<'a, Result<ToolTokenResponse, WcError>>;
    fn revoke<'a>(&'a self, refresh_token: &'a str) -> BoxFuture<'a, ()>;
}

/// The real way: HTTPS to WireCloud.
pub struct HttpEndpoint {
    server: Server,
    api: OnceLock<Result<Api, String>>,
}

impl HttpEndpoint {
    pub fn new(url: &str, accept_invalid_cert: bool) -> Self {
        Self {
            server: Server {
                url: url.to_string(),
                accept_invalid_cert,
            },
            api: OnceLock::new(),
        }
    }

    fn api(&self) -> Result<&Api, WcError> {
        self.api
            .get_or_init(|| Api::new(&self.server))
            .as_ref()
            .map_err(|e| {
                WcError::Api(ApiError::Api {
                    status: 0,
                    code: "WC-TLS".to_string(),
                    detail: e.clone(),
                })
            })
    }

    /// Exchanges the code from the redirect for tokens.
    pub async fn exchange(
        &self,
        code: &str,
        verifier: &str,
        redirect_uri: &str,
    ) -> Result<TokenResponse, WcError> {
        let answer = self
            .api()?
            .post(
                "/v1/client-auth/token",
                json!({
                    "grant_type": "authorization_code",
                    "code": code,
                    "code_verifier": verifier,
                    "client_id": CLIENT_ID,
                    "redirect_uri": redirect_uri,
                }),
                &mut Jar::default(),
            )
            .await
            .map_err(token_error)?;
        parse_tokens(answer)
    }
}

/// The image from the response of `/v1/me/profile`: only a data URL of an
/// image of the allowed kinds. Everything else (no image, another type) counts
/// as "no image", so that nothing but an image ever reaches the UI.
fn image_of(profile: &Value) -> Option<String> {
    const ALLOWED: [&str; 3] = [
        "data:image/png;base64,",
        "data:image/jpeg;base64,",
        "data:image/webp;base64,",
    ];
    profile
        .get("image")
        .and_then(Value::as_str)
        .filter(|image| ALLOWED.iter().any(|prefix| image.starts_with(prefix)))
        .map(str::to_string)
}

/// `invalid_grant` ends the session, everything else is not an end (yet):
/// no network, a rate limit, a server error.
fn token_error(error: ApiError) -> WcError {
    match error {
        ApiError::Offline(detail) => WcError::Offline(detail),
        ApiError::Unauthorized => WcError::Unauthorized,
        ApiError::Api { ref code, .. } if code == "invalid_grant" => WcError::Ended,
        other => WcError::Api(other),
    }
}

fn parse_tokens(value: Value) -> Result<TokenResponse, WcError> {
    serde_json::from_value(value).map_err(|_| {
        WcError::Api(ApiError::Api {
            status: 200,
            code: "I-IP".to_string(),
            detail: t!("wirecloud.response_unreadable").to_string(),
        })
    })
}

impl Endpoint for HttpEndpoint {
    fn refresh<'a>(
        &'a self,
        refresh_token: &'a str,
    ) -> BoxFuture<'a, Result<TokenResponse, WcError>> {
        Box::pin(async move {
            let answer = self
                .api()?
                .post(
                    "/v1/client-auth/token",
                    json!({
                        "grant_type": "refresh_token",
                        "refresh_token": refresh_token,
                        "client_id": CLIENT_ID,
                    }),
                    &mut Jar::default(),
                )
                .await
                .map_err(token_error)?;
            parse_tokens(answer)
        })
    }

    fn tool_token<'a>(
        &'a self,
        access_token: &'a str,
        audience: &'a str,
    ) -> BoxFuture<'a, Result<ToolTokenResponse, WcError>> {
        Box::pin(async move {
            let answer = self
                .api()?
                .post_bearer(
                    "/v1/tool-tokens",
                    json!({ "audience": audience }),
                    access_token,
                )
                .await
                .map_err(|error| match error {
                    ApiError::Offline(detail) => WcError::Offline(detail),
                    ApiError::Unauthorized => WcError::Unauthorized,
                    other => WcError::Api(other),
                })?;
            serde_json::from_value(answer).map_err(|_| {
                WcError::Api(ApiError::Api {
                    status: 200,
                    code: "I-IP".to_string(),
                    detail: t!("wirecloud.response_unreadable").to_string(),
                })
            })
        })
    }

    fn revoke<'a>(&'a self, refresh_token: &'a str) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            // Whether WireCloud notices is secondary: locally the session is
            // thrown away either way. If it keeps running there, it ends by itself.
            if let Ok(api) = self.api() {
                let _ = api
                    .post(
                        "/v1/client-auth/revoke",
                        json!({ "refresh_token": refresh_token }),
                        &mut Jar::default(),
                    )
                    .await;
            }
        })
    }
}

// ---- The session -------------------------------------------------------------

#[derive(Default)]
struct TokenState {
    refresh: Option<Secret>,
    access: Option<(Secret, Instant)>,
    tool: Option<(Secret, Instant)>,
    /// Counts every successful renewal. Whoever presented a token that was
    /// rejected only renews if nobody has done so in the meantime.
    generation: u64,
    /// The local user ID in the backend (not WireCloud's `sub`).
    user_id: String,
}

struct Shared {
    url: String,
    audience: String,
    accept_invalid_cert: bool,
    state: Mutex<TokenState>,
    /// Holds every renewal back while one is running: a refresh token must
    /// never be presented twice.
    gate: tokio::sync::Mutex<()>,
    endpoint: Arc<dyn Endpoint>,
}

/// An account's sign-in at WireCloud.
///
/// All copies (`Clone`) share the same state. That is intentional: an
/// account's [`Jar`](super::http::Jar) is copied often, and a copy with an
/// outdated refresh token would end the session.
#[derive(Clone)]
pub struct Wc(Arc<Shared>);

impl std::fmt::Debug for Wc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Wc({})", self.0.url)
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    // A panic in one thread must not lock the sign-in permanently.
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// If the lifetime is missing in a response, `default` applies: a token that
/// counted as expired right away would be a session that never starts.
fn later(seconds: u64, default: u64, margin: Duration) -> Instant {
    let ttl = Duration::from_secs(if seconds == 0 { default } else { seconds });
    Instant::now() + ttl.saturating_sub(margin)
}

impl Wc {
    /// A new sign-in from what the code exchange delivered.
    pub fn new(discovery: &Discovery, accept_invalid_cert: bool, tokens: TokenResponse) -> Self {
        let endpoint = HttpEndpoint::new(&discovery.wirecloud_url, accept_invalid_cert);
        Self::with_endpoint(
            discovery.wirecloud_url.clone(),
            discovery.audience.clone(),
            accept_invalid_cert,
            Arc::new(endpoint),
            Some(tokens),
            String::new(),
            None,
        )
    }

    fn with_endpoint(
        url: String,
        audience: String,
        accept_invalid_cert: bool,
        endpoint: Arc<dyn Endpoint>,
        tokens: Option<TokenResponse>,
        user_id: String,
        stored_refresh: Option<String>,
    ) -> Self {
        let mut state = TokenState {
            user_id,
            ..TokenState::default()
        };
        if let Some(tokens) = tokens {
            state.access = Some((
                Secret(tokens.access_token.clone()),
                later(tokens.expires_in, 300, ACCESS_MARGIN),
            ));
            state.refresh = Some(Secret(tokens.refresh_token.clone()));
        } else if let Some(refresh) = stored_refresh {
            state.refresh = Some(Secret(refresh));
        }
        Self(Arc::new(Shared {
            url,
            audience,
            accept_invalid_cert,
            state: Mutex::new(state),
            gate: tokio::sync::Mutex::new(()),
            endpoint,
        }))
    }

    /// For tests: with its own way to WireCloud.
    #[cfg(test)]
    pub(super) fn for_test(endpoint: Arc<dyn Endpoint>, refresh: &str) -> Self {
        Self::with_endpoint(
            "http://127.0.0.1:1".to_string(),
            "http://backend.test".to_string(),
            false,
            endpoint,
            None,
            "u1".to_string(),
            Some(refresh.to_string()),
        )
    }

    pub fn url(&self) -> &str {
        &self.0.url
    }

    pub fn audience(&self) -> &str {
        &self.0.audience
    }

    pub fn user_id(&self) -> String {
        lock(&self.0.state).user_id.clone()
    }

    pub fn set_user_id(&self, id: &str) {
        lock(&self.0.state).user_id = id.to_string();
    }

    /// Whether a refresh token is still there. Without one the session has ended.
    pub fn is_active(&self) -> bool {
        lock(&self.0.state).refresh.is_some()
    }

    /// The current refresh token, only for storing.
    #[cfg(test)]
    fn refresh_token(&self) -> Option<String> {
        lock(&self.0.state).refresh.as_ref().map(|s| s.0.clone())
    }

    /// Throws everything away, for all copies too.
    pub fn forget(&self) {
        let mut state = lock(&self.0.state);
        state.refresh = None;
        state.access = None;
        state.tool = None;
    }

    /// Signs the session out at WireCloud and forgets it here.
    pub async fn sign_out(&self) {
        let refresh = lock(&self.0.state).refresh.as_ref().map(|s| s.0.clone());
        if let Some(refresh) = refresh {
            self.0.endpoint.revoke(&refresh).await;
        }
        self.forget();
    }

    fn cached_access(&self) -> Option<(String, u64)> {
        let state = lock(&self.0.state);
        match &state.access {
            Some((token, expires)) if *expires > Instant::now() => {
                Some((token.0.clone(), state.generation))
            }
            _ => None,
        }
    }

    fn cached_tool(&self) -> Option<String> {
        match &lock(&self.0.state).tool {
            Some((token, expires)) if *expires > Instant::now() => Some(token.0.clone()),
            _ => None,
        }
    }

    /// A valid access token and the version of the state it comes from.
    async fn access_token(&self) -> Result<(String, u64), WcError> {
        if let Some(found) = self.cached_access() {
            return Ok(found);
        }
        let seen = lock(&self.0.state).generation;
        self.refresh(seen).await?;
        self.cached_access().ok_or(WcError::Ended)
    }

    /// Renews the tokens — **exactly one renewal at a time**.
    ///
    /// `seen` is the version on which the caller had its token. If someone has
    /// already renewed while it was waiting, there is nothing left to do: a
    /// second attempt with the old refresh token would be a reuse and would
    /// end the session.
    async fn refresh(&self, seen: u64) -> Result<(), WcError> {
        let _gate = self.0.gate.lock().await;

        let refresh = {
            let state = lock(&self.0.state);
            if state.generation != seen {
                return Ok(());
            }
            match &state.refresh {
                Some(token) => token.0.clone(),
                None => return Err(WcError::Ended),
            }
        };

        match self.0.endpoint.refresh(&refresh).await {
            Ok(tokens) => {
                let mut state = lock(&self.0.state);
                state.refresh = Some(Secret(tokens.refresh_token.clone()));
                state.access = Some((
                    Secret(tokens.access_token.clone()),
                    later(tokens.expires_in, 300, ACCESS_MARGIN),
                ));
                state.generation += 1;
                Ok(())
            }
            Err(WcError::Ended) => {
                self.forget();
                Err(WcError::Ended)
            }
            Err(other) => Err(other),
        }
    }

    /// The account's profile image at WireCloud as a data URL, `None` without
    /// an image. If the network is missing or the token is not valid, that is
    /// an error: the UI then keeps showing the initials and asks again later.
    pub async fn profile_image(&self) -> Result<Option<String>, WcError> {
        let (token, _) = self.access_token().await?;
        let api = Api::new(&Server {
            url: self.0.url.clone(),
            accept_invalid_cert: self.0.accept_invalid_cert,
        })
        .map_err(|detail| {
            WcError::Api(ApiError::Api {
                status: 0,
                code: "WC-TLS".to_string(),
                detail,
            })
        })?;
        let profile = api
            .get_bearer("/v1/me/profile", &token)
            .await
            .map_err(token_error)?;
        Ok(image_of(&profile))
    }

    /// A tool token for this backend. `force` fetches a new one even if the
    /// remembered one is still valid (after a rejection by the backend).
    pub async fn tool_token(&self, force: bool) -> Result<String, WcError> {
        if !force {
            if let Some(token) = self.cached_tool() {
                return Ok(token);
            }
        }
        for attempt in 0..2 {
            let (access, generation) = self.access_token().await?;
            match self.0.endpoint.tool_token(&access, &self.0.audience).await {
                Ok(answer) => {
                    lock(&self.0.state).tool = Some((
                        Secret(answer.token.clone()),
                        later(answer.expires_in, 600, TOOL_MARGIN),
                    ));
                    return Ok(answer.token);
                }
                // WireCloud rejects the access token (expired, or the session
                // was ended): renew once and try again. If the session really
                // has ended, the renewal says so.
                Err(WcError::Unauthorized) if attempt == 0 => {
                    self.refresh(generation).await?;
                }
                Err(WcError::Unauthorized) => return Err(WcError::Ended),
                Err(other) => return Err(other),
            }
        }
        Err(WcError::Ended)
    }
}

// On disk: only address, ID and the refresh token. The whole `Jar` is stored
// encrypted with the device key, see `account::seal_sessions`.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Persisted {
    url: String,
    audience: String,
    refresh: String,
    #[serde(default)]
    accept_invalid_cert: bool,
    #[serde(default)]
    user_id: String,
}

impl Serialize for Wc {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let state = lock(&self.0.state);
        Persisted {
            url: self.0.url.clone(),
            audience: self.0.audience.clone(),
            refresh: state
                .refresh
                .as_ref()
                .map(|s| s.0.clone())
                .unwrap_or_default(),
            accept_invalid_cert: self.0.accept_invalid_cert,
            user_id: state.user_id.clone(),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Wc {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let stored = Persisted::deserialize(deserializer)?;
        let endpoint = HttpEndpoint::new(&stored.url, stored.accept_invalid_cert);
        Ok(Self::with_endpoint(
            stored.url,
            stored.audience,
            stored.accept_invalid_cert,
            Arc::new(endpoint),
            None,
            stored.user_id,
            (!stored.refresh.is_empty()).then_some(stored.refresh),
        ))
    }
}

// ---- Who this is -------------------------------------------------------------

/// What a tool token says about the person. For display only: it is verified
/// by the backend, here it is only read.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Claims {
    pub email: String,
    pub name: String,
}

pub fn claims_of(token: &str) -> Option<Claims> {
    let payload = token.split('.').nth(1)?;
    let bytes = URL_SAFE_NO_PAD.decode(payload).ok()?;
    let value: Value = serde_json::from_slice(&bytes).ok()?;
    let account = value.get("acct")?;
    Some(Claims {
        email: account.get("email")?.as_str()?.to_string(),
        name: account
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
    })
}

// ---- The whole sign-in -------------------------------------------------------

static CURRENT: Mutex<Option<Arc<Notify>>> = Mutex::new(None);

/// Begins a sign-in and returns what it can be cancelled with. One still
/// running is cancelled in the process: there is at most one.
pub fn begin() -> Arc<Notify> {
    let next = Arc::new(Notify::new());
    if let Some(previous) = lock(&CURRENT).replace(next.clone()) {
        previous.notify_waiters();
    }
    next
}

/// Cancels the running sign-in, if there is one.
pub fn cancel() {
    if let Some(current) = lock(&CURRENT).take() {
        current.notify_waiters();
    }
}

/// Signs in: listener, browser, code, exchange. `open` opens the address in
/// the system browser (if there is none, the error text comes back).
pub async fn login(
    discovery: &Discovery,
    accept_invalid_cert: bool,
    open: impl FnOnce(&str) -> Result<(), String>,
    cancel: &Notify,
) -> Result<Wc, FlowError> {
    let server = CallbackServer::bind().await?;
    let pkce = Pkce::generate().map_err(FlowError::Io)?;
    let state = new_state().map_err(FlowError::Io)?;
    let redirect_uri = server.redirect_uri();

    let url = authorize_url(
        &discovery.wirecloud_url,
        &redirect_uri,
        &pkce.challenge,
        &state,
    );
    open(&url).map_err(|e| FlowError::Io(t!("wirecloud.browser_failed", error = e).to_string()))?;

    let code = server.wait(&state, LOGIN_TIMEOUT, cancel).await?;

    let endpoint = HttpEndpoint::new(&discovery.wirecloud_url, accept_invalid_cert);
    let tokens = endpoint
        .exchange(&code, &pkce.verifier, &redirect_uri)
        .await
        .map_err(|error| {
            FlowError::Exchange(match error {
                WcError::Ended | WcError::Unauthorized => {
                    t!("wirecloud.exchange_rejected").to_string()
                }
                WcError::Offline(detail) => {
                    t!("wirecloud.unreachable", detail = detail).to_string()
                }
                WcError::Api(error) => error.to_string(),
            })
        })?;
    Ok(Wc::new(discovery, accept_invalid_cert, tokens))
}

// ---- Test helpers ------------------------------------------------------------

/// A way to WireCloud that always succeeds and counts: for tests of other
/// modules that need a tool token but no network.
#[cfg(test)]
pub(super) struct CountingEndpoint {
    pub tools: std::sync::atomic::AtomicUsize,
    pub refreshes: std::sync::atomic::AtomicUsize,
}

#[cfg(test)]
impl CountingEndpoint {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            tools: Default::default(),
            refreshes: Default::default(),
        })
    }
}

#[cfg(test)]
impl Endpoint for CountingEndpoint {
    fn refresh<'a>(
        &'a self,
        _refresh_token: &'a str,
    ) -> BoxFuture<'a, Result<TokenResponse, WcError>> {
        Box::pin(async move {
            let n = self
                .refreshes
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                + 1;
            Ok(TokenResponse {
                access_token: format!("access-{n}"),
                expires_in: 300,
                refresh_token: format!("refresh-{n}"),
            })
        })
    }

    fn tool_token<'a>(
        &'a self,
        _access_token: &'a str,
        _audience: &'a str,
    ) -> BoxFuture<'a, Result<ToolTokenResponse, WcError>> {
        Box::pin(async move {
            let n = self.tools.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
            Ok(ToolTokenResponse {
                token: format!("tool-{n}"),
                expires_in: 600,
            })
        })
    }

    fn revoke<'a>(&'a self, _refresh_token: &'a str) -> BoxFuture<'a, ()> {
        Box::pin(async {})
    }
}

// ---- Tests -------------------------------------------------------------------

#[cfg(test)]
mod tests {
    #[test]
    fn profile_image_accepts_only_image_data_urls() {
        let png = json!({ "image": "data:image/png;base64,AAAA" });
        assert_eq!(
            image_of(&png).as_deref(),
            Some("data:image/png;base64,AAAA")
        );
        assert!(image_of(&json!({ "image": "data:image/webp;base64,AAAA" })).is_some());
        assert_eq!(image_of(&json!({ "image": null })), None);
        assert_eq!(image_of(&json!({})), None);
        assert_eq!(
            image_of(&json!({ "image": "https://evil.example/x.png" })),
            None
        );
        assert_eq!(
            image_of(&json!({ "image": "data:text/html;base64,AAAA" })),
            None
        );
        assert_eq!(
            image_of(&json!({ "image": "data:image/svg+xml;base64,AAAA" })),
            None
        );
    }

    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// As in the rest of the project: a normal test that uses Tauri's async
    /// runtime.
    fn run<F: Future>(future: F) -> F::Output {
        tauri::async_runtime::block_on(future)
    }

    const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    // ---- PKCE and state

    #[test]
    fn pkce_follows_rfc_7636_appendix_b() {
        assert_eq!(challenge_for(VERIFIER), CHALLENGE);
        assert_eq!(Pkce::from_verifier(VERIFIER).challenge, CHALLENGE);
    }

    #[test]
    fn generated_verifier_has_the_allowed_shape() {
        let a = Pkce::generate().unwrap();
        let b = Pkce::generate().unwrap();
        assert_ne!(a.verifier, b.verifier);
        assert_eq!(a.verifier.len(), 43);
        assert!(a
            .verifier
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-._~".contains(c)));
        // The challenge belongs to the verifier and is a hash, not the verifier itself.
        assert_eq!(a.challenge, challenge_for(&a.verifier));
        assert_eq!(a.challenge.len(), 43);
        assert_ne!(a.challenge, a.verifier);
    }

    #[test]
    fn state_is_random_visible_and_long_enough() {
        let a = new_state().unwrap();
        let b = new_state().unwrap();
        assert_ne!(a, b);
        assert!(a.len() >= 8);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn authorize_url_carries_every_parameter_encoded() {
        let url = authorize_url(
            "https://cloud.test",
            "http://127.0.0.1:53682/callback",
            CHALLENGE,
            "abc123def456",
        );
        assert!(url.starts_with("https://cloud.test/v1/client-auth/authorize?"));
        for part in [
            "response_type=code",
            "client_id=wireterm-desktop",
            "redirect_uri=http%3A%2F%2F127.0.0.1%3A53682%2Fcallback",
            &format!("code_challenge={CHALLENGE}"),
            "code_challenge_method=S256",
            "state=abc123def456",
        ] {
            assert!(url.contains(part), "{part} missing in {url}");
        }
    }

    // ---- Redirect

    fn request(target: &str, host: &str) -> String {
        format!("GET {target} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: test\r\nAccept: */*")
    }

    #[test]
    fn accepts_the_callback_with_the_right_state() {
        let head = request("/callback?code=abc_DEF-123&state=s3cret", "127.0.0.1:5000");
        assert_eq!(
            parse_callback(&head, 5000, "s3cret"),
            Callback::Code("abc_DEF-123".to_string())
        );
    }

    #[test]
    fn reports_a_denial_and_other_errors() {
        let head = request(
            "/callback?error=access_denied&state=s3cret",
            "127.0.0.1:5000",
        );
        assert_eq!(parse_callback(&head, 5000, "s3cret"), Callback::Denied);
        let head = request(
            "/callback?error=server_error&state=s3cret",
            "127.0.0.1:5000",
        );
        assert_eq!(
            parse_callback(&head, 5000, "s3cret"),
            Callback::Error("server_error".to_string())
        );
        // Nothing but identifier characters gets into a message.
        let head = request(
            "/callback?error=%3Cscript%3E&state=s3cret",
            "127.0.0.1:5000",
        );
        assert_eq!(
            parse_callback(&head, 5000, "s3cret"),
            Callback::Error("script".to_string())
        );
    }

    #[test]
    fn rejects_a_wrong_or_missing_state() {
        for target in [
            "/callback?code=abc&state=other",
            "/callback?code=abc",
            "/callback?code=abc&state=",
            "/callback?code=abc&state=s3cre",
            "/callback?code=abc&state=s3crets",
            "/callback?error=access_denied&state=wrong",
        ] {
            assert_eq!(
                parse_callback(&request(target, "127.0.0.1:5000"), 5000, "s3cret"),
                Callback::Reject(Rejection::State),
                "{target}"
            );
        }
    }

    #[test]
    fn rejects_a_wrong_path_method_or_host() {
        let ok = "/callback?code=abc&state=s3cret";
        assert_eq!(
            parse_callback(&request("/favicon.ico", "127.0.0.1:5000"), 5000, "s3cret"),
            Callback::Reject(Rejection::Path)
        );
        assert_eq!(
            parse_callback(
                &request("/callback/x?code=abc&state=s3cret", "127.0.0.1:5000"),
                5000,
                "s3cret"
            ),
            Callback::Reject(Rejection::Path)
        );
        assert_eq!(
            parse_callback(
                &request("/?code=abc&state=s3cret", "127.0.0.1:5000"),
                5000,
                "s3cret"
            ),
            Callback::Reject(Rejection::Path)
        );
        assert_eq!(
            parse_callback(
                &format!("POST {ok} HTTP/1.1\r\nHost: 127.0.0.1:5000"),
                5000,
                "s3cret"
            ),
            Callback::Reject(Rejection::Method)
        );
        // Wrong port, foreign name, redirected name, missing host.
        for host in [
            "127.0.0.1:5001",
            "localhost:5000",
            "evil.example:5000",
            "127.0.0.1",
        ] {
            assert_eq!(
                parse_callback(&request(ok, host), 5000, "s3cret"),
                Callback::Reject(Rejection::Host),
                "{host}"
            );
        }
        assert_eq!(
            parse_callback(&format!("GET {ok} HTTP/1.1"), 5000, "s3cret"),
            Callback::Reject(Rejection::Host)
        );
    }

    #[test]
    fn rejects_malformed_requests_and_codes() {
        for head in [
            "",
            "GET",
            "GET /callback",
            "GET /callback HTTP/1.1 extra",
            "GET /callback FTP/1.0",
        ] {
            assert_eq!(
                parse_callback(head, 5000, "s3cret"),
                Callback::Reject(Rejection::Malformed),
                "{head:?}"
            );
        }
        for target in [
            "/callback?state=s3cret",
            "/callback?code=&state=s3cret",
            "/callback?code=a%20b&state=s3cret",
            "/callback?code=a%3Cb&state=s3cret",
            &format!("/callback?code={}&state=s3cret", "a".repeat(257)),
        ] {
            assert_eq!(
                parse_callback(&request(target, "127.0.0.1:5000"), 5000, "s3cret"),
                Callback::Reject(Rejection::Malformed),
                "{target}"
            );
        }
    }

    async fn send(port: u16, text: &str) -> String {
        let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        stream.write_all(text.as_bytes()).await.unwrap();
        let mut answer = String::new();
        let _ = stream.read_to_string(&mut answer).await;
        answer
    }

    #[test]
    fn listener_takes_exactly_one_matching_request_and_then_closes() {
        run(async {
            let server = CallbackServer::bind().await.unwrap();
            let port = server.port();
            assert_eq!(
                server.redirect_uri(),
                format!("http://127.0.0.1:{port}/callback")
            );
            let cancel = Notify::new();
            let waiting = tokio::spawn(async move {
                server
                    .wait("s3cret", Duration::from_secs(10), &cancel)
                    .await
            });

            // First foreign requests: wrong path, wrong state, wrong host. All
            // are rejected, and the sign-in keeps running.
            let a = send(
                port,
                &format!(
                    "{}\r\n\r\n",
                    request("/favicon.ico", &format!("127.0.0.1:{port}"))
                ),
            )
            .await;
            assert!(a.starts_with("HTTP/1.1 404"), "{a}");
            let b = send(
                port,
                &format!(
                    "{}\r\n\r\n",
                    request("/callback?code=x&state=wrong", &format!("127.0.0.1:{port}"))
                ),
            )
            .await;
            assert!(b.starts_with("HTTP/1.1 400"), "{b}");
            let c = send(
                port,
                &format!(
                    "{}\r\n\r\n",
                    request("/callback?code=x&state=s3cret", "evil.example")
                ),
            )
            .await;
            assert!(c.starts_with("HTTP/1.1 400"), "{c}");
            assert!(!waiting.is_finished());

            // Then the right one: it is answered and delivers the code.
            let ok = send(
                port,
                &format!(
                    "{}\r\n\r\n",
                    request(
                        "/callback?code=good_123&state=s3cret",
                        &format!("127.0.0.1:{port}")
                    )
                ),
            )
            .await;
            assert!(ok.starts_with("HTTP/1.1 200"), "{ok}");
            assert!(ok.contains("Referrer-Policy: no-referrer"));
            assert!(ok.contains("Cache-Control: no-store"));
            // Styled like WireCloud's pages; style and mark are embedded, the
            // policy allows only that (no script, no foreign resources).
            assert!(ok.contains("<h1>Sign-in complete</h1>"), "{ok}");
            assert!(ok.contains("<svg"), "{ok}");
            assert!(
                ok.contains("default-src 'none'; style-src 'unsafe-inline'"),
                "{ok}"
            );
            assert!(!ok.contains("<script"), "{ok}");
            assert!(!ok.contains("{{"), "{ok}");
            assert_eq!(waiting.await.unwrap(), Ok("good_123".to_string()));

            // Afterwards the port is closed: a second redirect arrives nowhere.
            assert!(TcpStream::connect(("127.0.0.1", port)).await.is_err());
        });
    }

    #[test]
    fn listener_reports_a_denial() {
        run(async {
            let server = CallbackServer::bind().await.unwrap();
            let port = server.port();
            let cancel = Notify::new();
            let waiting = tokio::spawn(async move {
                server
                    .wait("s3cret", Duration::from_secs(10), &cancel)
                    .await
            });
            send(
                port,
                &format!(
                    "{}\r\n\r\n",
                    request(
                        "/callback?error=access_denied&state=s3cret",
                        &format!("127.0.0.1:{port}")
                    )
                ),
            )
            .await;
            assert_eq!(waiting.await.unwrap(), Err(FlowError::Denied));
        });
    }

    #[test]
    fn listener_gives_up_after_the_timeout() {
        run(async {
            let server = CallbackServer::bind().await.unwrap();
            let cancel = Notify::new();
            let result = server
                .wait("s3cret", Duration::from_millis(100), &cancel)
                .await;
            assert_eq!(result, Err(FlowError::Timeout));
        });
    }

    #[test]
    fn listener_can_be_cancelled() {
        run(async {
            let server = CallbackServer::bind().await.unwrap();
            let cancel = Arc::new(Notify::new());
            let trigger = cancel.clone();
            let waiting = tokio::spawn(async move {
                server
                    .wait("s3cret", Duration::from_secs(10), &cancel)
                    .await
            });
            tokio::time::sleep(Duration::from_millis(50)).await;
            trigger.notify_waiters();
            assert_eq!(waiting.await.unwrap(), Err(FlowError::Cancelled));
        });
    }

    #[test]
    fn listener_stops_after_too_many_foreign_requests() {
        run(async {
            let server = CallbackServer::bind().await.unwrap();
            let port = server.port();
            let cancel = Notify::new();
            let waiting = tokio::spawn(async move {
                server
                    .wait("s3cret", Duration::from_secs(30), &cancel)
                    .await
            });
            for _ in 0..MAX_REJECTED {
                send(
                    port,
                    &format!("{}\r\n\r\n", request("/x", &format!("127.0.0.1:{port}"))),
                )
                .await;
            }
            assert_eq!(waiting.await.unwrap(), Err(FlowError::Flooded));
        });
    }

    #[test]
    fn listener_ignores_a_connection_that_never_sends() {
        run(async {
            let server = CallbackServer::bind().await.unwrap();
            let port = server.port();
            let cancel = Notify::new();
            let waiting = tokio::spawn(async move {
                server
                    .wait("s3cret", Duration::from_secs(15), &cancel)
                    .await
            });
            // A connection that only stays open does not hold up the sign-in
            // (here: after the short read deadline the right one still gets through).
            let _idle = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
            let ok = send(
                port,
                &format!(
                    "{}\r\n\r\n",
                    request(
                        "/callback?code=ok1&state=s3cret",
                        &format!("127.0.0.1:{port}")
                    )
                ),
            )
            .await;
            assert!(ok.starts_with("HTTP/1.1 200"));
            assert_eq!(waiting.await.unwrap(), Ok("ok1".to_string()));
        });
    }

    // ---- Mode

    #[test]
    fn discovers_wirecloud_mode() {
        let found = parse_discovery(&json!({
            "contract_version": 1,
            "audience": "https://wireterm.example",
            "wirecloud_url": "https://api.wirecloud.example/"
        }))
        .unwrap();
        assert_eq!(found.audience, "https://wireterm.example");
        assert_eq!(found.wirecloud_url, "https://api.wirecloud.example");
    }

    #[test]
    fn is_not_wirecloud_mode_without_a_usable_address() {
        for value in [
            json!({}),
            json!({ "audience": "x" }),
            json!({ "audience": "x", "wirecloud_url": null }),
            json!({ "audience": "x", "wirecloud_url": "" }),
            json!({ "audience": "", "wirecloud_url": "https://a.example" }),
            json!({ "wirecloud_url": "https://a.example" }),
            json!("text"),
            json!([]),
        ] {
            assert_eq!(parse_discovery(&value), None, "{value}");
        }
    }

    #[test]
    fn only_trustworthy_addresses_are_followed() {
        for url in [
            "https://api.wirecloud.example",
            "https://api.wirecloud.example/",
            "http://localhost:8200",
            "http://127.0.0.1:8200",
            "http://[::1]:8200",
        ] {
            assert!(valid_wirecloud_url(url).is_some(), "{url}");
        }
        for url in [
            "http://api.wirecloud.example",
            "http://localhost.evil.example",
            "ftp://api.wirecloud.example",
            "javascript:alert(1)",
            "https://user:pw@api.wirecloud.example",
            "https://api.wirecloud.example/v1",
            "https://api.wirecloud.example?x=1",
            "https://api.wirecloud.example#x",
            "api.wirecloud.example",
            "",
        ] {
            assert_eq!(valid_wirecloud_url(url), None, "{url}");
        }
    }

    // ---- Who this is

    #[test]
    fn reads_name_and_address_from_a_tool_token() {
        let payload = URL_SAFE_NO_PAD.encode(
            json!({ "sub": "acc", "acct": { "email": "max@example.test", "name": "Max" } })
                .to_string(),
        );
        let token = format!("e30.{payload}.sig");
        assert_eq!(
            claims_of(&token),
            Some(Claims {
                email: "max@example.test".to_string(),
                name: "Max".to_string()
            })
        );
        assert_eq!(claims_of("no-token"), None);
        assert_eq!(claims_of("a.%%%.c"), None);
    }

    // ---- Renewal without network

    /// A way to WireCloud that counts and treats the refresh token like the
    /// real server: each may be presented exactly once.
    struct Fake {
        counter: AtomicUsize,
        valid_refresh: Mutex<String>,
        refresh_calls: AtomicUsize,
        reused: AtomicUsize,
        tool_calls: AtomicUsize,
        delay: Duration,
        /// Whether the first tool token call is rejected.
        reject_first_tool_call: bool,
        end_session: Mutex<bool>,
        offline: Mutex<bool>,
    }

    impl Fake {
        fn new(first_refresh: &str) -> Arc<Self> {
            Arc::new(Self {
                counter: AtomicUsize::new(0),
                valid_refresh: Mutex::new(first_refresh.to_string()),
                refresh_calls: AtomicUsize::new(0),
                reused: AtomicUsize::new(0),
                tool_calls: AtomicUsize::new(0),
                delay: Duration::from_millis(40),
                reject_first_tool_call: false,
                end_session: Mutex::new(false),
                offline: Mutex::new(false),
            })
        }
    }

    impl Endpoint for Fake {
        fn refresh<'a>(
            &'a self,
            refresh_token: &'a str,
        ) -> BoxFuture<'a, Result<TokenResponse, WcError>> {
            Box::pin(async move {
                self.refresh_calls.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(self.delay).await;
                if *lock(&self.offline) {
                    return Err(WcError::Offline("no connection".to_string()));
                }
                let mut valid = lock(&self.valid_refresh);
                if *lock(&self.end_session) || *valid != refresh_token {
                    // A replaced or foreign token: this is how WireCloud ends the session.
                    self.reused.fetch_add(1, Ordering::SeqCst);
                    *lock(&self.end_session) = true;
                    return Err(WcError::Ended);
                }
                let n = self.counter.fetch_add(1, Ordering::SeqCst) + 1;
                *valid = format!("refresh-{n}");
                Ok(TokenResponse {
                    access_token: format!("access-{n}"),
                    expires_in: 300,
                    refresh_token: valid.clone(),
                })
            })
        }

        fn tool_token<'a>(
            &'a self,
            access_token: &'a str,
            _audience: &'a str,
        ) -> BoxFuture<'a, Result<ToolTokenResponse, WcError>> {
            Box::pin(async move {
                let n = self.tool_calls.fetch_add(1, Ordering::SeqCst) + 1;
                if self.reject_first_tool_call && n == 1 {
                    return Err(WcError::Unauthorized);
                }
                if *lock(&self.end_session) {
                    return Err(WcError::Unauthorized);
                }
                Ok(ToolTokenResponse {
                    token: format!("tool-{n}-for-{access_token}"),
                    expires_in: 600,
                })
            })
        }

        fn revoke<'a>(&'a self, _refresh_token: &'a str) -> BoxFuture<'a, ()> {
            Box::pin(async move {
                *lock(&self.end_session) = true;
            })
        }
    }

    #[test]
    fn concurrent_callers_cause_exactly_one_refresh() {
        run(async {
            let fake = Fake::new("refresh-0");
            let wc = Wc::for_test(fake.clone(), "refresh-0");
            // No access token there: all ten need one.
            let mut tasks = Vec::new();
            for _ in 0..10 {
                let wc = wc.clone();
                tasks.push(tokio::spawn(async move { wc.tool_token(false).await }));
            }
            for task in tasks {
                let token = task.await.unwrap().unwrap();
                assert!(token.starts_with("tool-"));
            }
            assert_eq!(fake.refresh_calls.load(Ordering::SeqCst), 1);
            assert_eq!(fake.reused.load(Ordering::SeqCst), 0);
            assert_eq!(wc.refresh_token().as_deref(), Some("refresh-1"));
        });
    }

    #[test]
    fn copies_share_one_state_so_no_stale_refresh_token_survives() {
        run(async {
            let fake = Fake::new("refresh-0");
            let first = Wc::for_test(fake.clone(), "refresh-0");
            let copy = first.clone();
            first.tool_token(false).await.unwrap();
            // The copy sees the renewed token, not the replaced one.
            assert_eq!(copy.refresh_token().as_deref(), Some("refresh-1"));
            // When the access token runs short, both renew one after the other, never with the old one.
            lock(&first.0.state).access = None;
            copy.tool_token(true).await.unwrap();
            lock(&copy.0.state).access = None;
            first.tool_token(true).await.unwrap();
            assert_eq!(fake.reused.load(Ordering::SeqCst), 0);
            assert!(first.is_active());
        });
    }

    #[test]
    fn rejected_access_token_is_refreshed_once_and_retried() {
        run(async {
            let mut fake = Fake::new("refresh-0");
            Arc::get_mut(&mut fake).unwrap().reject_first_tool_call = true;
            let wc = Wc::for_test(fake.clone(), "refresh-0");
            let token = wc.tool_token(false).await.unwrap();
            assert!(token.starts_with("tool-2-"));
            // Once for the missing one, once after the rejection: never more.
            assert_eq!(fake.refresh_calls.load(Ordering::SeqCst), 2);
            assert_eq!(fake.tool_calls.load(Ordering::SeqCst), 2);
        });
    }

    #[test]
    fn tool_token_is_remembered_until_forced() {
        run(async {
            let fake = Fake::new("refresh-0");
            let wc = Wc::for_test(fake.clone(), "refresh-0");
            let a = wc.tool_token(false).await.unwrap();
            let b = wc.tool_token(false).await.unwrap();
            assert_eq!(a, b);
            assert_eq!(fake.tool_calls.load(Ordering::SeqCst), 1);
            let c = wc.tool_token(true).await.unwrap();
            assert_ne!(a, c);
            assert_eq!(fake.tool_calls.load(Ordering::SeqCst), 2);
        });
    }

    #[test]
    fn ended_session_forgets_everything_and_says_so() {
        run(async {
            let fake = Fake::new("refresh-0");
            let wc = Wc::for_test(fake.clone(), "something-else");
            let error = wc.tool_token(false).await.unwrap_err();
            assert!(matches!(error, WcError::Ended), "{error:?}");
            assert!(!wc.is_active());
            assert_eq!(wc.refresh_token(), None);
            // Afterwards there is nothing left to renew, and the backend is not asked.
            let before = fake.refresh_calls.load(Ordering::SeqCst);
            assert!(matches!(wc.tool_token(false).await, Err(WcError::Ended)));
            assert_eq!(fake.refresh_calls.load(Ordering::SeqCst), before);
            assert!(matches!(
                ApiError::from(WcError::Ended),
                ApiError::Unauthorized
            ));
        });
    }

    #[test]
    fn lost_connection_keeps_the_session() {
        run(async {
            let fake = Fake::new("refresh-0");
            *lock(&fake.offline) = true;
            let wc = Wc::for_test(fake.clone(), "refresh-0");
            let error = wc.tool_token(false).await.unwrap_err();
            assert!(matches!(error, WcError::Offline(_)), "{error:?}");
            // The refresh token is still there and valid as soon as the network is back.
            assert!(wc.is_active());
            *lock(&fake.offline) = false;
            assert!(wc.tool_token(false).await.is_ok());
        });
    }

    #[test]
    fn signing_out_revokes_and_forgets() {
        run(async {
            let fake = Fake::new("refresh-0");
            let wc = Wc::for_test(fake.clone(), "refresh-0");
            let copy = wc.clone();
            wc.tool_token(false).await.unwrap();
            wc.sign_out().await;
            assert!(*lock(&fake.end_session));
            // The copy has nothing left either.
            assert!(!copy.is_active());
            assert_eq!(copy.cached_tool(), None);
        });
    }

    #[test]
    fn only_the_refresh_token_goes_to_disk_and_never_shows_in_a_log() {
        let fake = Fake::new("refresh-0");
        let wc = Wc::for_test(fake, "refresh-classified");
        lock(&wc.0.state).access = Some((
            Secret("access-classified".to_string()),
            Instant::now() + Duration::from_secs(60),
        ));
        lock(&wc.0.state).tool = Some((
            Secret("tool-classified".to_string()),
            Instant::now() + Duration::from_secs(60),
        ));

        let json = serde_json::to_string(&wc).unwrap();
        assert!(json.contains("refresh-classified"));
        assert!(!json.contains("access-classified"));
        assert!(!json.contains("tool-classified"));

        for text in [
            format!("{wc:?}"),
            format!("{:?}", Secret("x-classified".to_string())),
        ] {
            assert!(!text.contains("classified"), "{text}");
        }

        // And back: only the refresh token is there, the others are missing.
        let back: Wc = serde_json::from_str(&json).unwrap();
        assert_eq!(back.refresh_token().as_deref(), Some("refresh-classified"));
        assert_eq!(back.cached_tool(), None);
        assert_eq!(back.url(), "http://127.0.0.1:1");
        assert_eq!(back.audience(), "http://backend.test");
        assert_eq!(back.user_id(), "u1");
    }

    #[test]
    fn only_one_sign_in_runs_at_a_time() {
        let first = begin();
        let second = begin();
        // The first is cancelled when the second begins; whoever waits on it
        // is woken. Enough here: they are different triggers.
        assert!(!Arc::ptr_eq(&first, &second));
        cancel();
        cancel();
    }
}

/// The whole way against running servers.
///
/// Much can be checked without servers (see above), but not what matters:
/// that WireCloud and a backend in WireCloud mode really work together with
/// this client, and that WireCloud's rules (refresh token only once, signing
/// out takes effect) apply the way this module assumes.
///
/// The test plays the browser itself: it signs in to WireCloud, consents on
/// the consent page and follows the redirect, just like a browser.
///
/// ```text
/// # 1. WireCloud is running (backend on 8200, Maildev on 8202), plus a backend
/// #    in WireCloud mode with its own database, audience http://localhost:18080
/// #    and WIRECLOUD_URL=http://localhost:8200,
/// #    WIRECLOUD_ISSUER=http://wirecloud_backend:8080 on port 18080.
/// # 2. Set up a throwaway admin, account and access; the credentials go into a
/// #    file (mode 0600), never to the output:
/// WIRECLOUD_ENV_FILE=/path/live.env node scripts/live-wirecloud.mjs
/// set -a; . /path/live.env; set +a
/// # 3. Tests, one after the other (WireCloud rate-limits sign-ins per IP):
/// cargo test --lib cloud::wirecloud::live -- --ignored --test-threads=1 --nocapture
/// ```
#[cfg(test)]
mod live {
    use super::*;
    use crate::cloud::api;
    use reqwest::header::{COOKIE, LOCATION, SET_COOKIE};

    fn run<F: Future>(future: F) -> F::Output {
        tauri::async_runtime::block_on(future)
    }

    fn env(name: &str) -> String {
        std::env::var(name)
            .unwrap_or_else(|_| panic!("{name} is not set (see scripts/live-wirecloud.mjs)"))
    }

    fn wirecloud_api() -> String {
        std::env::var("WIRECLOUD_API").unwrap_or_else(|_| "http://localhost:8200".to_string())
    }

    fn backend() -> Server {
        let url = std::env::var("WIRETERM_BACKEND")
            .unwrap_or_else(|_| "http://localhost:18080".to_string());
        Server::resolve(&url, false).expect("the backend address")
    }

    fn http() -> reqwest::Client {
        reqwest::Client::builder()
            .tls_backend_preconfigured(crate::tls::config(false).expect("TLS"))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("client")
    }

    /// The hidden fields of the consent page, as a browser submits them.
    fn hidden_fields(page: &str) -> Vec<(String, String)> {
        let mut fields = Vec::new();
        for part in page.split("<input type=\"hidden\"").skip(1) {
            let attribute = |name: &str| {
                let marker = format!("{name}=\"");
                let start = part.find(&marker)? + marker.len();
                let end = part[start..].find('"')?;
                Some(part[start..start + end].to_string())
            };
            if let (Some(name), Some(value)) = (attribute("name"), attribute("value")) {
                fields.push((name, value));
            }
        }
        fields
    }

    /// A browser: signs in to WireCloud, consents (or declines) and follows the
    /// redirect to the client's listener.
    async fn browser(url: String, decision: &'static str) {
        let (email, password) = (env("WIRECLOUD_TEST_EMAIL"), env("WIRECLOUD_TEST_PASSWORD"));
        let api = wirecloud_api();
        let client = http();

        // WireCloud rate-limits sign-ins (3 per 10 seconds and IP): wait on `429`.
        let mut cookie = String::new();
        for _ in 0..4 {
            let response = client
                .post(format!("{api}/api/auth/sign-in/email"))
                .header("Origin", "http://localhost:5173")
                .header("Content-Type", "application/json")
                .body(json!({ "email": email, "password": password }).to_string())
                .send()
                .await
                .expect("sign-in at WireCloud");
            if response.status() == 429 {
                tokio::time::sleep(Duration::from_secs(11)).await;
                continue;
            }
            assert_eq!(response.status(), 200, "sign-in at WireCloud");
            cookie = response
                .headers()
                .get_all(SET_COOKIE)
                .iter()
                .filter_map(|v| v.to_str().ok())
                .filter_map(|v| v.split(';').next())
                .filter(|pair| !pair.ends_with('='))
                .collect::<Vec<_>>()
                .join("; ");
            break;
        }
        assert!(!cookie.is_empty(), "no session at WireCloud");

        let page = client
            .get(&url)
            .header(COOKIE, &cookie)
            .send()
            .await
            .expect("consent page")
            .text()
            .await
            .expect("text");
        let mut fields = hidden_fields(&page);
        assert!(
            fields.iter().any(|(name, _)| name == "csrf"),
            "no consent page: {page}"
        );
        fields.push(("decision".to_string(), decision.to_string()));
        let pairs: Vec<(&str, String)> = fields
            .iter()
            .map(|(name, value)| (name.as_str(), value.clone()))
            .collect();

        let answer = client
            .post(format!("{api}/v1/client-auth/authorize"))
            .header(COOKIE, &cookie)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(crate::cloud::http::query_string(&pairs))
            .send()
            .await
            .expect("decision");
        assert_eq!(answer.status(), 302, "no redirect");
        let location = answer.headers()[LOCATION]
            .to_str()
            .expect("address")
            .to_string();
        assert!(location.starts_with("http://127.0.0.1:"), "{location}");
        // The browser follows the redirect to the client's listener.
        let _ = client.get(location).send().await;
    }

    async fn sign_in(decision: &'static str) -> Result<(Wc, Server, Discovery), FlowError> {
        let server = backend();
        let discovery = discover(&server)
            .await
            .expect("the backend runs in WireCloud mode");
        assert_eq!(discovery.wirecloud_url, wirecloud_api());
        let cancel = Notify::new();
        let wc = login(
            &discovery,
            false,
            |url| {
                let url = url.to_string();
                tokio::spawn(browser(url, decision));
                Ok(())
            },
            &cancel,
        )
        .await?;
        Ok((wc, server, discovery))
    }

    fn expire(wc: &Wc) {
        let mut state = lock(&wc.0.state);
        state.access = None;
        state.tool = None;
    }

    fn generation(wc: &Wc) -> u64 {
        lock(&wc.0.state).generation
    }

    #[test]
    #[ignore]
    fn the_whole_way_against_the_running_servers() {
        run(async {
            let (wc, server, discovery) = sign_in("allow").await.expect("signs in");
            let client = Api::new(&server).expect("backend");
            let mut jar = Jar::default();
            jar.set_wirecloud(wc.clone());

            // Who is this? The name is in the token, the local ID in the backend.
            let token = wc.tool_token(true).await.expect("tool token");
            let claims = claims_of(&token).expect("claims");
            assert_eq!(claims.email, env("WIRECLOUD_TEST_EMAIL"));
            let user = api::own_user(&client, &mut jar).await.expect("local ID");
            assert!(!user.id.is_empty());
            wc.set_user_id(&user.id);
            println!("local user ID: {}", user.id);

            // The backend accepts the tool token: it knows the personal workspace.
            let rows = api::workspaces(&client, &mut jar)
                .await
                .expect("workspaces");
            assert!(rows
                .iter()
                .any(|row| row.kind == super::super::model::WorkspaceKind::Personal));

            // The stored session is valid.
            let me = api::session(&client, &mut jar)
                .await
                .expect("answers")
                .expect("signed in");
            assert_eq!(me.id, user.id);

            // Access token expired: one renewal, and it goes on.
            let before = generation(&wc);
            expire(&wc);
            api::workspaces(&client, &mut jar)
                .await
                .expect("after renewal");
            assert_eq!(generation(&wc), before + 1);

            // Eight concurrent requests with an expired token: exactly one
            // renewal, and the session stays alive at WireCloud (presenting the
            // same refresh token a second time would have ended it).
            let before = generation(&wc);
            expire(&wc);
            let mut tasks = Vec::new();
            for _ in 0..8 {
                let (client, mut jar) = (client.clone(), jar.clone());
                tasks.push(tokio::spawn(async move {
                    api::workspaces(&client, &mut jar).await
                }));
            }
            for task in tasks {
                task.await.expect("task").expect("concurrent");
            }
            assert_eq!(generation(&wc), before + 1);
            expire(&wc);
            api::workspaces(&client, &mut jar)
                .await
                .expect("session still alive");

            // Presenting a replaced refresh token again ends the session at
            // WireCloud, and the client notices and asks anew.
            let old = wc.refresh_token().expect("refresh token");
            expire(&wc);
            wc.tool_token(true).await.expect("renewed again");
            let endpoint = HttpEndpoint::new(&discovery.wirecloud_url, false);
            assert!(matches!(
                Endpoint::refresh(&endpoint, &old).await,
                Err(WcError::Ended)
            ));
            expire(&wc);
            let error = api::workspaces(&client, &mut jar)
                .await
                .expect_err("session ended");
            assert!(matches!(error, ApiError::Unauthorized), "{error:?}");
            assert!(!wc.is_active());
        });
    }

    #[test]
    #[ignore]
    fn signing_out_ends_the_session_at_wirecloud() {
        run(async {
            let (wc, _, discovery) = sign_in("allow").await.expect("signs in");
            let refresh = wc.refresh_token().expect("refresh token");
            wc.sign_out().await;
            assert!(!wc.is_active());
            // At WireCloud the refresh token is no longer valid.
            let endpoint = HttpEndpoint::new(&discovery.wirecloud_url, false);
            assert!(matches!(
                Endpoint::refresh(&endpoint, &refresh).await,
                Err(WcError::Ended)
            ));
        });
    }

    #[test]
    #[ignore]
    fn a_denial_in_the_browser_ends_the_attempt() {
        run(async {
            let error = sign_in("deny").await.err().expect("declined");
            assert_eq!(error, FlowError::Denied);
        });
    }

    #[test]
    #[ignore]
    fn cancelling_stops_the_wait_and_opens_nothing_else() {
        run(async {
            let server = backend();
            let discovery = discover(&server).await.expect("WireCloud mode");
            let cancel = Arc::new(Notify::new());
            let trigger = cancel.clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(300)).await;
                trigger.notify_waiters();
            });
            let error = login(&discovery, false, |_| Ok(()), &cancel)
                .await
                .err()
                .expect("cancelled");
            assert_eq!(error, FlowError::Cancelled);
        });
    }
}
