//! The line to the backend: address, session, errors.
//!
//! Signing in goes through the better-auth session, i.e. a cookie — or, if
//! the backend runs in WireCloud mode, with a tool token from WireCloud
//! (see [`super::wirecloud`]). Which way applies depends on the [`Jar`]: if it
//! holds a WireCloud session, `Authorization: Bearer` goes out, otherwise the
//! cookie. A desktop client has no browser that keeps one — hence there is a
//! [`Jar`] here that can do exactly as much as needed: remember what
//! `Set-Cookie` says and send it back. It can be stored, and that is why a
//! sign-in survives a restart.
//!
//! The second task is the distinction that everywhere decides what happens
//! next: **no network** means keep working from the local copy, **401** means
//! sign in again, and a `{code, detail}` from the backend means the request
//! was wrong and repeating it changes nothing. See [`ApiError`].

use std::collections::BTreeMap;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use reqwest::header::{CONTENT_TYPE, SET_COOKIE};
use reqwest::{Method, StatusCode};
use rust_i18n::t;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Long enough for a first sync over a slow line, short enough that a stalled
/// server does not hold up the UI.
const TIMEOUT: Duration = Duration::from_secs(60);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// The address of the hosted version — see [`Server::is_cloud`]. The UI
/// fetches it through `cloud_url`.
///
/// In the form [`Server::resolve`] makes of it: with scheme, without `/` at
/// the end.
pub const CLOUD_URL: &str = "https://api.wireterm.wirecore.net";

/// Where the backend is.
///
/// "Cloud" and "own backend" differ only here: the cloud brings its address
/// along, for an own backend someone types it in. Everything else — sign-in,
/// encryption, sync — is the same, and that is why there is only this one
/// type for it.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct Server {
    /// With scheme and without a trailing slash: `https://wireterm.example`.
    pub url: String,
    /// For a self-signed certificate in front of one's own instance — the same
    /// trade-off as with FTPS, S3 and Vaultwarden, see [`crate::tls`].
    #[serde(default)]
    pub accept_invalid_cert: bool,
}

impl Server {
    /// Turns what someone types into an address.
    ///
    /// A missing scheme means HTTPS: that is what is meant, it is rarely
    /// typed. `http://` stays — an instance on one's own computer often has
    /// none, and silently turning it into HTTPS would lead to an error
    /// message in which the address looks different from the field.
    pub fn resolve(url: &str, accept_invalid_cert: bool) -> Result<Self, String> {
        let url = url.trim().trim_end_matches('/');
        if url.is_empty() {
            return Err(t!("cloud.address_missing").to_string());
        }
        let url = if url.contains("://") {
            url.to_string()
        } else {
            format!("https://{url}")
        };
        if !url.starts_with("http://") && !url.starts_with("https://") {
            return Err(t!("cloud.address_scheme").to_string());
        }
        Ok(Self {
            url,
            accept_invalid_cert,
        })
    }

    /// Whether this is the hosted version.
    ///
    /// It differs in nothing but the address; the answer therefore depends on
    /// nothing else. Without a fixed domain it is always `false`, and
    /// everything is an own backend.
    pub fn is_cloud(&self) -> bool {
        !CLOUD_URL.is_empty() && self.url == CLOUD_URL
    }

    /// How the address appears in a list — without scheme, that is noise.
    /// The cloud appears under its name.
    pub fn label(&self) -> String {
        if self.is_cloud() {
            return "WireCloud".to_string();
        }
        self.url
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .to_string()
    }
}

/// The cookies of a session.
///
/// Deliberately dumb: name and value, nothing more. There is exactly one
/// server per account and exactly one path being worked on — interpreting
/// domain, path and SameSite would mean rebuilding a browser that decides
/// nothing here.
///
/// Expiry times are therefore not stored either: an expired cookie shows up
/// as `401`, and that has to be handled anyway — also when the server ended
/// the session early.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Jar {
    #[serde(default)]
    cookies: BTreeMap<String, String>,
    /// The sign-in at WireCloud, if the backend runs in that mode. With such a
    /// session the bearer way applies instead of the cookie; it never occurs
    /// together with `cookies`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    wirecloud: Option<super::wirecloud::Wc>,
}

impl Jar {
    pub fn is_empty(&self) -> bool {
        self.cookies.is_empty() && !self.wirecloud.as_ref().is_some_and(|wc| wc.is_active())
    }

    /// Throws the session away. A WireCloud session is forgotten for **all**
    /// copies, not just this one: otherwise the others would be left with a
    /// refresh token that nobody needs any more.
    pub fn clear(&mut self) {
        self.cookies.clear();
        if let Some(wc) = self.wirecloud.take() {
            wc.forget();
        }
    }

    pub fn wirecloud(&self) -> Option<&super::wirecloud::Wc> {
        self.wirecloud.as_ref()
    }

    pub fn set_wirecloud(&mut self, wc: super::wirecloud::Wc) {
        self.cookies.clear();
        self.wirecloud = Some(wc);
    }

    fn header(&self) -> Option<String> {
        if self.cookies.is_empty() {
            return None;
        }
        Some(
            self.cookies
                .iter()
                .map(|(name, value)| format!("{name}={value}"))
                .collect::<Vec<_>>()
                .join("; "),
        )
    }

    /// Takes in what a response sets.
    ///
    /// better-auth extends the session on its own by setting the cookie
    /// again. Because every response passes through here, the sign-in holds
    /// without further ado — as long as the app is used regularly.
    fn absorb(&mut self, response: &reqwest::Response) {
        for raw in response.headers().get_all(SET_COOKIE) {
            let Ok(text) = raw.to_str() else { continue };
            let mut parts = text.split(';');
            let Some(pair) = parts.next() else { continue };
            let Some((name, value)) = pair.split_once('=') else {
                continue;
            };
            let name = name.trim();
            if name.is_empty() {
                continue;
            }

            // `Max-Age=0` is how a server takes a cookie back — on sign-out
            // exactly what should happen.
            let removed = parts.any(|attribute| {
                let attribute = attribute.trim();
                attribute.eq_ignore_ascii_case("max-age=0")
            });
            if removed {
                self.cookies.remove(name);
            } else {
                self.cookies
                    .insert(name.to_string(), value.trim().to_string());
            }
        }
    }
}

/// What can go wrong, and what to do about it.
#[derive(Debug, Clone)]
pub enum ApiError {
    /// The server could not be reached. No reason to discard anything: the
    /// change stays in the queue and goes up next time.
    Offline(String),
    /// The session is no longer valid. Only a new sign-in helps here.
    Unauthorized,
    /// The backend answered, and it refused. `code` is the short form from
    /// `CLIENT.md` (`R-CF`, `K-EX`, `P-NF`, …) or, with better-auth, its own.
    Api {
        status: u16,
        code: String,
        detail: String,
    },
}

impl ApiError {
    pub fn code(&self) -> &str {
        match self {
            Self::Offline(_) => "OFFLINE",
            Self::Unauthorized => "A-NA",
            Self::Api { code, .. } => code,
        }
    }

    pub fn is_offline(&self) -> bool {
        matches!(self, Self::Offline(_))
    }

    /// Whether another attempt can change anything at all.
    ///
    /// Only a missing network, a server error and the rate limit (`429`) are
    /// temporary. A rejected request stays rejected, and keeping it in the
    /// queue would mean that nothing behind it ever goes up again.
    pub fn is_temporary(&self) -> bool {
        match self {
            Self::Offline(_) => true,
            Self::Unauthorized => false,
            Self::Api { status, .. } => *status >= 500 || *status == 429,
        }
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Offline(detail) => {
                write!(f, "{}", t!("cloud.backend_unreachable", detail = detail))
            }
            Self::Unauthorized => write!(f, "{}", t!("cloud.signed_out")),
            Self::Api { code, detail, .. } if detail.is_empty() => {
                write!(f, "{}", friendly(code).unwrap_or_else(|| code.clone()))
            }
            Self::Api { code, detail, .. } => {
                write!(f, "{}", friendly(code).unwrap_or_else(|| detail.clone()))
            }
        }
    }
}

/// Understandable texts for the errors that occur in WireCloud mode. The
/// backend only sends the short form (`WC-LD`); what it means is up to the client.
fn friendly(code: &str) -> Option<String> {
    let key = match code {
        "WC-EC" => "cloud.code_wc_ec",
        "WC-LD" => "cloud.code_wc_ld",
        "WC-NV" => "cloud.code_wc_nv",
        "WC-NN" => "cloud.code_wc_nn",
        "WC-RL" => "cloud.code_wc_rl",
        "RL" => "cloud.code_rl",
        "WC-UR" => "cloud.code_wc_ur",
        "WC-MANAGED" => "cloud.code_wc_managed",
        "no_grant" => "cloud.code_no_grant",
        "account_suspended" => "cloud.code_account_suspended",
        "unknown_audience" => "cloud.code_unknown_audience",
        _ => return None,
    };
    Some(t!(key).to_string())
}

impl From<ApiError> for String {
    fn from(error: ApiError) -> Self {
        error.to_string()
    }
}

/// A connection to a backend.
///
/// Holds only the HTTP client and the address; the caller passes the session
/// along, because it belongs to the *account* and not to the line — two
/// accounts on the same server share the client, but not the sign-in.
#[derive(Clone)]
pub struct Api {
    http: reqwest::Client,
    base: String,
}

impl Api {
    pub fn new(server: &Server) -> Result<Self, String> {
        let http = reqwest::Client::builder()
            // As with S3 and Bitwarden: the configuration is passed on as
            // `Any` and recognized by downcast, so exactly this type and not
            // inside an `Arc`.
            .tls_backend_preconfigured(crate::tls::config(server.accept_invalid_cert)?)
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(TIMEOUT)
            .build()
            .map_err(|e| t!("cloud.connection_failed", error = e).to_string())?;
        Ok(Self {
            http,
            base: server.url.clone(),
        })
    }

    pub async fn get(
        &self,
        path: &str,
        query: &[(&str, String)],
        jar: &mut Jar,
    ) -> Result<Value, ApiError> {
        self.send(Method::GET, path, query, None, jar).await
    }

    pub async fn post(&self, path: &str, body: Value, jar: &mut Jar) -> Result<Value, ApiError> {
        self.send(Method::POST, path, &[], Some(body), jar).await
    }

    pub async fn put(&self, path: &str, body: Value, jar: &mut Jar) -> Result<Value, ApiError> {
        self.send(Method::PUT, path, &[], Some(body), jar).await
    }

    pub async fn patch(&self, path: &str, body: Value, jar: &mut Jar) -> Result<Value, ApiError> {
        self.send(Method::PATCH, path, &[], Some(body), jar).await
    }

    pub async fn delete(&self, path: &str, jar: &mut Jar) -> Result<Value, ApiError> {
        self.send(Method::DELETE, path, &[], None, jar).await
    }

    /// A POST with a token, without a session: this is how the client gets a
    /// tool token from WireCloud with its access token.
    pub async fn post_bearer(
        &self,
        path: &str,
        body: Value,
        token: &str,
    ) -> Result<Value, ApiError> {
        self.send_raw(Method::POST, path, &[], Some(&body), Auth::Bearer(token))
            .await
    }

    /// A GET with a token, without a session: this is how the client gets its
    /// account's profile from WireCloud with the access token.
    pub async fn get_bearer(&self, path: &str, token: &str) -> Result<Value, ApiError> {
        self.send_raw(Method::GET, path, &[], None, Auth::Bearer(token))
            .await
    }

    /// An image with a token, as a data URL: how the client gets the picture
    /// of a WireCloud company. `None` when there is none (`404` — WireCloud
    /// says the same when the account may not see it), and for anything that
    /// is not a PNG, JPEG or WebP of reasonable size: only an image ever
    /// reaches the UI.
    pub async fn get_image_bearer(
        &self,
        path: &str,
        token: &str,
    ) -> Result<Option<String>, ApiError> {
        const ALLOWED: [&str; 3] = ["image/png", "image/jpeg", "image/webp"];
        const MAX_BYTES: usize = 2 * 1024 * 1024;

        let response = self
            .http
            .request(Method::GET, format!("{}{path}", self.base))
            .header("Accept", ALLOWED.join(", "))
            .header("Authorization", format!("Bearer {token}"))
            .send()
            .await
            .map_err(|e| ApiError::Offline(short(&e)))?;

        let status = response.status();
        if status == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if status == StatusCode::UNAUTHORIZED {
            return Err(ApiError::Unauthorized);
        }
        if !status.is_success() {
            let text = response.text().await.unwrap_or_default();
            return Err(problem(status.as_u16(), &text));
        }
        let mime = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .map(|value| value.trim().to_ascii_lowercase())
            .unwrap_or_default();
        if !ALLOWED.contains(&mime.as_str()) {
            return Ok(None);
        }
        let bytes = response
            .bytes()
            .await
            .map_err(|e| ApiError::Offline(short(&e)))?;
        if bytes.is_empty() || bytes.len() > MAX_BYTES {
            return Ok(None);
        }
        Ok(Some(format!(
            "data:{mime};base64,{}",
            BASE64.encode(&bytes)
        )))
    }

    async fn send(
        &self,
        method: Method,
        path: &str,
        query: &[(&str, String)],
        body: Option<Value>,
        jar: &mut Jar,
    ) -> Result<Value, ApiError> {
        // With a WireCloud session there is no cookie and nothing from
        // better-auth either: sign-in, organizations, teams and invitations
        // are managed by WireCloud. Instead of a 404 from the backend, the
        // hint where this belongs comes right away.
        if let Some(wc) = jar.wirecloud().cloned() {
            if path.starts_with("/api/auth/") {
                return Err(ApiError::Api {
                    status: 400,
                    code: "WC-MANAGED".to_string(),
                    detail: String::new(),
                });
            }
            return self
                .send_bearer(&wc, method, path, query, body.as_ref())
                .await;
        }
        self.send_raw(method, path, query, body.as_ref(), Auth::Cookies(jar))
            .await
    }

    /// With a tool token. If the backend rejects it (`401`), a new one is
    /// fetched **once** and the request repeated; if `401` comes again, the
    /// sign-in is no longer valid.
    async fn send_bearer(
        &self,
        wc: &super::wirecloud::Wc,
        method: Method,
        path: &str,
        query: &[(&str, String)],
        body: Option<&Value>,
    ) -> Result<Value, ApiError> {
        let token = wc.tool_token(false).await.map_err(ApiError::from)?;
        match self
            .send_raw(method.clone(), path, query, body, Auth::Bearer(&token))
            .await
        {
            Err(ApiError::Unauthorized) => {
                let fresh = wc.tool_token(true).await.map_err(ApiError::from)?;
                self.send_raw(method, path, query, body, Auth::Bearer(&fresh))
                    .await
            }
            other => other,
        }
    }

    async fn send_raw(
        &self,
        method: Method,
        path: &str,
        query: &[(&str, String)],
        body: Option<&Value>,
        auth: Auth<'_>,
    ) -> Result<Value, ApiError> {
        let mut url = format!("{}{path}", self.base);
        if !query.is_empty() {
            url.push('?');
            url.push_str(&query_string(query));
        }

        let mut request = self
            .http
            .request(method, url)
            .header("Accept", "application/json")
            // Mails to someone without an account go out in this language.
            .header("Accept-Language", crate::locale::current());

        if let Some(body) = body {
            // By hand instead of through `RequestBuilder::json`: reqwest is
            // included here without default features — see `Cargo.toml`, where
            // the TLS backend is the reason — and brings neither the JSON
            // serializer nor the one for query strings.
            request = request
                .header("Content-Type", "application/json")
                .body(body.to_string());
        }
        match &auth {
            Auth::Cookies(jar) => {
                if let Some(cookies) = jar.header() {
                    request = request.header("Cookie", cookies);
                }
            }
            Auth::Bearer(token) => {
                request = request.header("Authorization", format!("Bearer {token}"));
            }
        }

        let response = request
            .send()
            .await
            .map_err(|e| ApiError::Offline(short(&e)))?;

        if let Auth::Cookies(jar) = auth {
            jar.absorb(&response);
        }

        let status = response.status();
        let text = response.text().await.unwrap_or_default();

        if status == StatusCode::UNAUTHORIZED {
            return Err(ApiError::Unauthorized);
        }
        if status.is_success() {
            if text.trim().is_empty() {
                return Ok(Value::Null);
            }
            return serde_json::from_str(&text).map_err(|e| ApiError::Api {
                status: status.as_u16(),
                code: "I-IP".to_string(),
                detail: t!("cloud.response_unreadable", error = e).to_string(),
            });
        }

        Err(problem(status.as_u16(), &text))
    }
}

/// What a request identifies itself with.
enum Auth<'a> {
    Cookies(&'a mut Jar),
    Bearer(&'a str),
}

/// `since=17&organizationId=abc`.
///
/// The character set is that of a form field: everything except letters,
/// digits and `-_.~` is percent-encoded. A `+` for a space would be the other
/// spelling — it applies in a form body, not in a URL.
pub(super) fn query_string(query: &[(&str, String)]) -> String {
    const UNRESERVED: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC
        .remove(b'-')
        .remove(b'_')
        .remove(b'.')
        .remove(b'~');

    query
        .iter()
        .map(|(name, value)| {
            let value = percent_encoding::utf8_percent_encode(value, UNRESERVED);
            format!("{name}={value}")
        })
        .collect::<Vec<_>>()
        .join("&")
}

/// Reads from a negative response what can be read from it.
///
/// Two forms are to be expected: `{code, detail}` from our own routes and
/// `{code, message}` from better-auth. A third — no JSON at all — comes from
/// anything in front: a reverse proxy that says 502 does so in HTML.
fn problem(status: u16, text: &str) -> ApiError {
    let parsed: Option<Value> = serde_json::from_str(text).ok();
    let field = |name: &str| -> Option<String> {
        parsed
            .as_ref()?
            .get(name)?
            .as_str()
            .map(|value| value.to_string())
    };

    // Three forms: `{code, detail}` (own routes), `{code, message}`
    // (better-auth) and `{error, error_description}` (the clients' sign-in at
    // WireCloud, following OAuth).
    let code = field("code")
        .or_else(|| field("error"))
        .unwrap_or_else(|| format!("HTTP-{status}"));
    let has_key = field("code").is_some() || field("error").is_some();
    let detail = field("detail")
        .or_else(|| field("message"))
        .or_else(|| field("error_description"))
        .unwrap_or_else(|| {
            if has_key {
                // A key without text: it is enough, and `Display` shows it (or
                // its understandable text) instead of the raw JSON.
                String::new()
            } else if text.trim().is_empty() {
                t!("cloud.backend_status", status = status).to_string()
            } else {
                // What is not JSON may be a whole HTML page.
                text.chars().take(200).collect()
            }
        });

    ApiError::Api {
        status,
        code,
        detail,
    }
}

/// The cause of a failed request in one sentence.
///
/// `reqwest`'s own message appends the whole chain, including the URL —
/// that is too much for an error bar under a workspace tile.
fn short(error: &reqwest::Error) -> String {
    if error.is_timeout() {
        return t!("cloud.timeout").to_string();
    }
    if error.is_connect() {
        return t!("cloud.no_connection").to_string();
    }
    let mut source: &dyn std::error::Error = error;
    while let Some(inner) = source.source() {
        source = inner;
    }
    source.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_address_without_scheme_means_https() {
        let server = Server::resolve("wireterm.example", false).expect("resolves");
        assert_eq!(server.url, "https://wireterm.example");
    }

    /// An instance on one's own computer often has no TLS. Silently turning
    /// it into HTTPS would give an error message in which the address looks
    /// different from the field.
    #[test]
    fn http_stays_http() {
        let server = Server::resolve("http://localhost:3000/", false).expect("resolves");
        assert_eq!(server.url, "http://localhost:3000");
    }

    #[test]
    fn an_empty_address_is_an_error() {
        assert!(Server::resolve("   ", false).is_err());
    }

    /// The UI sends `CLOUD_URL` through `resolve` — if it looked different
    /// from what `resolve` returns, no account would ever be the cloud.
    #[test]
    fn the_cloud_address_is_the_cloud() {
        assert!(Server::resolve(CLOUD_URL, false)
            .expect("resolves")
            .is_cloud());
    }

    #[test]
    fn the_cloud_is_called_wirecloud_in_lists() {
        let cloud = Server::resolve(CLOUD_URL, false).expect("resolves");
        assert_eq!(cloud.label(), "WireCloud");
        let own = Server::resolve("https://wireterm.example", false).expect("resolves");
        assert_eq!(own.label(), "wireterm.example");
    }

    /// The reason a sign-in survives a restart: the contents of the jar can
    /// be stored and taken up again.
    #[test]
    fn a_jar_can_be_stored_and_restored() {
        let mut jar = Jar::default();
        jar.cookies.insert(
            "better-auth.session_token".to_string(),
            "abc.def".to_string(),
        );

        let written = serde_json::to_string(&jar).expect("writes");
        let back: Jar = serde_json::from_str(&written).expect("reads");
        assert_eq!(
            back.header().as_deref(),
            Some("better-auth.session_token=abc.def")
        );
    }

    #[test]
    fn an_empty_jar_sends_nothing() {
        assert_eq!(Jar::default().header(), None);
    }

    /// Our own routes answer with `{code, detail}`, better-auth with
    /// `{code, message}`, and a reverse proxy with no JSON at all. All three
    /// must end up in the same line.
    #[test]
    fn all_three_error_forms_yield_a_message() {
        let own = problem(
            409,
            r#"{"code":"R-CF","detail":"The revision no longer matches"}"#,
        );
        assert_eq!(own.code(), "R-CF");
        assert_eq!(own.to_string(), "The revision no longer matches");

        let auth = problem(
            400,
            r#"{"code":"USER_ALREADY_EXISTS","message":"User already exists"}"#,
        );
        assert_eq!(auth.code(), "USER_ALREADY_EXISTS");
        assert_eq!(auth.to_string(), "User already exists");

        let proxy = problem(502, "<html><body>Bad Gateway</body></html>");
        assert_eq!(proxy.code(), "HTTP-502");
        assert!(proxy.to_string().contains("Bad Gateway"));
    }

    /// What a second attempt changes and what not — that decides whether a
    /// change stays in the queue or is discarded.
    /// The clients' sign-in at WireCloud answers with `{error,
    /// error_description}`, following OAuth. `invalid_grant` must arrive as
    /// the key: whether the session has ended depends on it.
    #[test]
    fn the_oauth_error_form_yields_the_key() {
        let oauth = problem(
            400,
            r#"{"error":"invalid_grant","error_description":"expired"}"#,
        );
        assert_eq!(oauth.code(), "invalid_grant");
        assert_eq!(oauth.to_string(), "expired");
        // Without a description the key is shown.
        assert_eq!(
            problem(400, r#"{"error":"invalid_grant"}"#).to_string(),
            "invalid_grant"
        );
    }

    /// In WireCloud mode the backend only sends the short form; what it means
    /// the client says, in a way that tells the person what to do.
    #[test]
    fn the_short_forms_from_wirecloud_mode_have_understandable_texts() {
        for code in [
            "WC-EC",
            "WC-LD",
            "WC-NV",
            "WC-NN",
            "WC-RL",
            "WC-UR",
            "RL",
            "no_grant",
            "account_suspended",
        ] {
            let text = problem(403, &format!(r#"{{"code":"{code}"}}"#)).to_string();
            assert!(text.len() > code.len() + 10, "{code}: {text}");
            assert!(!text.contains(code), "{code}: {text}");
        }
        // An unknown key stays as it is.
        assert_eq!(problem(409, r#"{"code":"R-CF"}"#).to_string(), "R-CF");
        // And a text from the server is never covered by one of our own where
        // we do not know the key.
        assert_eq!(
            problem(409, r#"{"code":"R-CF","detail":"Revision"}"#).to_string(),
            "Revision"
        );
    }

    #[test]
    fn a_wirecloud_session_counts_as_signed_in_and_closes_when_cleared() {
        let wc = crate::cloud::wirecloud::Wc::for_test(
            crate::cloud::wirecloud::CountingEndpoint::new(),
            "refresh-0",
        );
        let mut jar = Jar::default();
        assert!(jar.is_empty());
        jar.set_wirecloud(wc.clone());
        assert!(!jar.is_empty());
        let mut copy = jar.clone();

        copy.clear();
        assert!(copy.is_empty());
        // The original has nothing left either: otherwise a copy with a
        // refresh token that nobody uses any more would remain.
        assert!(jar.is_empty());
        assert!(!wc.is_active());
    }

    /// The jar only stores the refresh token and never an access or tool token.
    #[test]
    fn a_jar_with_a_wirecloud_session_stores_only_the_refresh_token() {
        let wc = crate::cloud::wirecloud::Wc::for_test(
            crate::cloud::wirecloud::CountingEndpoint::new(),
            "refresh-secret",
        );
        let mut jar = Jar::default();
        jar.set_wirecloud(wc);
        let written = serde_json::to_string(&jar).expect("writes");
        assert!(written.contains("refresh-secret"));
        assert!(!written.contains("cookies\":{\"")); // no cookies next to it
        let back: Jar = serde_json::from_str(&written).expect("reads");
        assert!(!back.is_empty());
        assert!(back.wirecloud().is_some());
        assert!(!format!("{back:?}").contains("secret"));
    }

    #[test]
    fn only_network_and_server_errors_are_temporary() {
        assert!(ApiError::Offline("no connection".into()).is_temporary());
        assert!(problem(503, "").is_temporary());
        assert!(problem(429, r#"{"code":"RL"}"#).is_temporary());
        assert!(!problem(409, r#"{"code":"P-EX"}"#).is_temporary());
        assert!(!ApiError::Unauthorized.is_temporary());
    }
}

/// The bearer way against a small real server: what goes over the line, and
/// what happens on a `401`.
#[cfg(test)]
mod bearer_tests {
    use super::*;
    use crate::cloud::test_server::server;
    use crate::cloud::wirecloud::{CountingEndpoint, Wc};
    use std::sync::atomic::Ordering;
    use std::sync::Arc;

    fn run<F: std::future::Future>(future: F) -> F::Output {
        tauri::async_runtime::block_on(future)
    }

    fn api(url: &str) -> Api {
        Api::new(&Server::resolve(url, false).expect("resolves")).expect("builds")
    }

    fn with_wirecloud() -> (Jar, Arc<CountingEndpoint>) {
        let endpoint = CountingEndpoint::new();
        let mut jar = Jar::default();
        jar.set_wirecloud(Wc::for_test(endpoint.clone(), "refresh-0"));
        (jar, endpoint)
    }

    #[test]
    fn an_image_comes_back_as_data_url_and_anything_else_as_none() {
        run(async {
            let (url, seen) = server(vec![
                (200, "Content-Type: image/png\r\n", "png-bytes"),
                (404, "", r#"{"code":"NOT_FOUND"}"#),
                (200, "Content-Type: text/html\r\n", "<script>"),
            ])
            .await;
            let client = api(&url);
            let image = client
                .get_image_bearer("/v1/companies/c1/image", "access-1")
                .await
                .expect("answers");
            assert_eq!(
                image,
                Some(format!(
                    "data:image/png;base64,{}",
                    BASE64.encode("png-bytes")
                ))
            );
            for _ in 0..2 {
                let none = client.get_image_bearer("/x", "access-1").await;
                assert_eq!(none.expect("answers"), None);
            }
            let seen = seen.lock().unwrap();
            assert_eq!(seen[0].path, "/v1/companies/c1/image");
            assert_eq!(seen[0].authorization, "Bearer access-1");
        });
    }

    #[test]
    fn with_wirecloud_a_tool_token_goes_out_and_no_cookie() {
        run(async {
            let (url, seen) = server(vec![(200, "", r#"{"ok":true}"#)]).await;
            let (mut jar, _) = with_wirecloud();
            let answer = api(&url)
                .get("/api/workspaces", &[], &mut jar)
                .await
                .expect("answers");
            assert_eq!(answer["ok"], true);
            let seen = seen.lock().unwrap();
            assert_eq!(seen.len(), 1);
            assert_eq!(seen[0].authorization, "Bearer tool-1");
            assert_eq!(seen[0].cookie, "");
        });
    }

    #[test]
    fn the_tool_token_is_reused_instead_of_fetched_for_every_request() {
        run(async {
            let (url, seen) = server(vec![(200, "", "{}"), (200, "", "{}"), (200, "", "{}")]).await;
            let (mut jar, endpoint) = with_wirecloud();
            let client = api(&url);
            for _ in 0..3 {
                client.get("/x", &[], &mut jar).await.expect("answers");
            }
            assert_eq!(endpoint.tools.load(Ordering::SeqCst), 1);
            assert!(seen
                .lock()
                .unwrap()
                .iter()
                .all(|s| s.authorization == "Bearer tool-1"));
        });
    }

    #[test]
    fn on_401_a_new_token_is_fetched_once_and_the_request_repeated() {
        run(async {
            let (url, seen) = server(vec![(401, "", ""), (200, "", r#"{"ok":true}"#)]).await;
            let (mut jar, endpoint) = with_wirecloud();
            let answer = api(&url).get("/x", &[], &mut jar).await.expect("answers");
            assert_eq!(answer["ok"], true);
            let seen = seen.lock().unwrap();
            assert_eq!(
                seen.iter()
                    .map(|s| s.authorization.as_str())
                    .collect::<Vec<_>>(),
                ["Bearer tool-1", "Bearer tool-2"]
            );
            assert_eq!(endpoint.tools.load(Ordering::SeqCst), 2);
        });
    }

    #[test]
    fn if_401_comes_again_after_the_new_token_the_sign_in_is_no_longer_valid() {
        run(async {
            let (url, seen) = server(vec![(401, "", ""), (401, "", ""), (200, "", "{}")]).await;
            let (mut jar, _) = with_wirecloud();
            let error = api(&url).get("/x", &[], &mut jar).await.expect_err("fails");
            assert!(matches!(error, ApiError::Unauthorized), "{error:?}");
            // Two requests, not three: it is not repeated endlessly.
            assert_eq!(seen.lock().unwrap().len(), 2);
        });
    }

    #[test]
    fn a_rejected_request_is_no_reason_for_a_new_token() {
        run(async {
            let (url, seen) = server(vec![(409, "", r#"{"code":"WC-EC"}"#)]).await;
            let (mut jar, endpoint) = with_wirecloud();
            let error = api(&url).get("/x", &[], &mut jar).await.expect_err("fails");
            assert_eq!(error.code(), "WC-EC");
            assert!(error.to_string().contains("linked"), "{error}");
            assert_eq!(seen.lock().unwrap().len(), 1);
            assert_eq!(endpoint.tools.load(Ordering::SeqCst), 1);
        });
    }

    #[test]
    fn better_auth_does_not_exist_in_wirecloud_mode_and_nothing_is_sent() {
        run(async {
            let (url, seen) = server(vec![(200, "", "{}")]).await;
            let (mut jar, endpoint) = with_wirecloud();
            let client = api(&url);
            for path in [
                "/api/auth/organization/get-full-organization",
                "/api/auth/get-session",
                "/api/auth/sign-in/email",
            ] {
                let error = client.get(path, &[], &mut jar).await.expect_err("blocked");
                assert_eq!(error.code(), "WC-MANAGED", "{path}");
                assert!(error.to_string().contains("WireCloud"));
            }
            // Neither a request to the backend nor a token.
            assert_eq!(seen.lock().unwrap().len(), 0);
            assert_eq!(endpoint.tools.load(Ordering::SeqCst), 0);
        });
    }

    #[test]
    fn without_wirecloud_the_cookie_way_stays_as_it_was() {
        run(async {
            let (url, seen) = server(vec![
                (
                    200,
                    "Set-Cookie: better-auth.session_token=abc; Path=/\r\n",
                    "{}",
                ),
                (200, "", "{}"),
            ])
            .await;
            let mut jar = Jar::default();
            let client = api(&url);
            client
                .post("/api/auth/sign-in/email", serde_json::json!({}), &mut jar)
                .await
                .expect("answers");
            client
                .get("/api/workspaces", &[], &mut jar)
                .await
                .expect("answers");
            let seen = seen.lock().unwrap();
            // Never a bearer, the second request carries the cookie.
            assert!(seen.iter().all(|s| s.authorization.is_empty()));
            assert_eq!(seen[1].cookie, "better-auth.session_token=abc");
            // And in cookie mode `/api/auth/` is of course allowed.
            assert!(jar.wirecloud().is_none());
        });
    }

    #[test]
    fn the_session_is_not_silently_cleared_on_401_after_the_second_attempt() {
        // Cleaning up is the caller's job (`jar.clear()` on Unauthorized, as
        // with the cookie): here the session stays.
        run(async {
            let (url, _) = server(vec![(401, "", ""), (401, "", "")]).await;
            let (mut jar, _) = with_wirecloud();
            let _ = api(&url).get("/x", &[], &mut jar).await;
            assert!(!jar.is_empty());
        });
    }
}
