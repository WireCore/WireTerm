//! The HTTP side of Bitwarden: endpoints, sign-in, sync.
//!
//! Everything here only talks to the server and decrypts nothing — that is in
//! [`super::crypto`]. Responses come back as `serde_json::Value` instead of
//! typed structs, for a reason given further down at [`normalize`].

use std::time::{Duration, Instant};

use percent_encoding::{utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use rust_i18n::t;
use serde_json::{json, Value};

use super::crypto::{b64_url, Kdf};

/// What WireTerm calls itself towards the server. Shows up in the account's
/// device list, which is why it should be named like a device and not like a
/// script.
const DEVICE_NAME: &str = "WireTerm";

/// Bitwarden's device classes. A desktop client is neither a CLI nor a server,
/// and the account should see in its device list what WireTerm is.
pub const DEVICE_TYPE: u32 = if cfg!(target_os = "windows") {
    6 // WindowsDesktop
} else if cfg!(target_os = "macos") {
    7 // MacOsDesktop
} else {
    8 // LinuxDesktop
};

/// One of the client names Bitwarden accepts. "desktop" is the one that
/// matches [`DEVICE_TYPE`].
const CLIENT_ID: &str = "desktop";

/// Enough for a sync over a slow line, too little for a stalled server to
/// block the UI.
const TIMEOUT: Duration = Duration::from_secs(60);

/// How long before its expiry a token counts as expired. Covers the time a
/// request is in transit.
const EXPIRY_MARGIN: Duration = Duration::from_secs(60);

/// Characters that may stay unchanged in a form field.
const FORM: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');

/// Where a server's identity and data services live.
///
/// For a self-hosted instance — Vaultwarden or Bitwarden — both hang under the
/// same address. For Bitwarden itself they are two separate host names, and
/// they exist twice: in the US and in Europe.
#[derive(Clone, Debug, PartialEq)]
pub struct Endpoints {
    pub identity: String,
    pub api: String,
}

impl Endpoints {
    /// Derives the endpoints from what is in the workspace.
    ///
    /// Empty means Bitwarden in the US — the default of the official clients.
    /// Anything else is read as the address of the own instance, including a
    /// subpath: Vaultwarden behind `/vault` is a common setup, and
    /// `<address>/identity` is then correct.
    pub fn resolve(server: &str) -> Result<Self, String> {
        let server = server.trim().trim_end_matches('/');
        let cloud = |region: &str| Self {
            identity: format!("https://identity.bitwarden.{region}"),
            api: format!("https://api.bitwarden.{region}"),
        };

        if server.is_empty() {
            return Ok(cloud("com"));
        }

        let server = if server.contains("://") {
            server.to_string()
        } else {
            // An address without a scheme is what was meant, not a typo: HTTPS
            // is the only thing a vault may be read over.
            format!("https://{server}")
        };

        let host = server
            .split("://")
            .nth(1)
            .map(|rest| rest.split('/').next().unwrap_or("").to_lowercase())
            .unwrap_or_default();
        if host.is_empty() {
            return Err(t!("vault.bw_not_an_address", server = server).into_owned());
        }
        if !server.starts_with("https://") {
            return Err(t!("vault.bw_https_required").into_owned());
        }

        // The two hosted instances are recognised, so nobody has to look up
        // their endpoint names.
        match host.as_str() {
            "vault.bitwarden.com" | "bitwarden.com" => return Ok(cloud("com")),
            "vault.bitwarden.eu" | "bitwarden.eu" => return Ok(cloud("eu")),
            _ => {}
        }

        let base = server.trim_end_matches('/');
        Ok(Self {
            identity: format!("{base}/identity"),
            api: format!("{base}/api"),
        })
    }
}

/// The access tokens of a running session.
pub struct Session {
    pub access: String,
    /// Empty if the server issued none. The session then ends when the access
    /// token expires instead of renewing itself.
    pub refresh: String,
    expires_at: Instant,
}

impl Session {
    pub fn expired(&self) -> bool {
        Instant::now() + EXPIRY_MARGIN >= self.expires_at
    }
}

/// How a sign-in turns out.
pub enum Login {
    Done(Session),
    /// The server wants a second factor. The numbers are its method numbers,
    /// see [`TwoFactor`].
    TwoFactor(Vec<u32>),
}

/// The two-factor methods WireTerm can handle — all three come down to
/// "enter a code", and that is exactly what the dialog can ask.
///
/// What is missing is everything with a flow of its own: Duo (numbers 2 and 6)
/// sends you to someone else's UI, WebAuthn (7) wants a device on the USB port.
/// Both would need a browser window, and that is a piece of work of its own.
pub struct TwoFactor;

impl TwoFactor {
    pub const AUTHENTICATOR: u32 = 0;
    pub const EMAIL: u32 = 1;
    pub const YUBIKEY: u32 = 3;

    /// The method WireTerm takes from the offered ones: the authenticator
    /// first, because it works without the server's involvement.
    pub fn choose(offered: &[u32]) -> Option<u32> {
        [Self::AUTHENTICATOR, Self::YUBIKEY, Self::EMAIL]
            .into_iter()
            .find(|wanted| offered.contains(wanted))
    }

    pub fn label(provider: u32) -> String {
        match provider {
            Self::AUTHENTICATOR => t!("vault.bw_two_factor_authenticator").into_owned(),
            Self::EMAIL => t!("vault.bw_two_factor_email").into_owned(),
            Self::YUBIKEY => "YubiKey".to_string(),
            _ => t!("vault.bw_two_factor_other").into_owned(),
        }
    }
}

/// Asks how the account derives its master key.
///
/// Two addresses, because the endpoint has moved: it lives under `/identity`
/// today, it used to live under `/api`, and both are found in the wild.
pub async fn prelogin(
    http: &reqwest::Client,
    endpoints: &Endpoints,
    email: &str,
) -> Result<Kdf, String> {
    let body = json!({ "email": email.trim().to_lowercase() }).to_string();
    let mut last = String::new();

    for base in [&endpoints.identity, &endpoints.api] {
        let response = http
            .post(format!("{base}/accounts/prelogin"))
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .timeout(TIMEOUT)
            .body(body.clone())
            .send()
            .await;

        match response {
            Ok(response) if response.status().is_success() => {
                let value = read_json(response).await?;
                return kdf_from(&value);
            }
            Ok(response) => {
                last = t!(
                    "vault.bw_endpoint_status",
                    endpoint = base,
                    status = response.status()
                )
                .into_owned()
            }
            Err(e) => {
                last = t!("vault.bw_endpoint_unreachable", endpoint = base, error = e).into_owned()
            }
        }
    }

    Err(t!("vault.bw_no_answer", detail = last).into_owned())
}

fn kdf_from(value: &Value) -> Result<Kdf, String> {
    let number = |key: &str, fallback: u32| {
        value
            .get(key)
            .and_then(Value::as_u64)
            .map(|n| n as u32)
            .unwrap_or(fallback)
    };
    match value.get("kdf").and_then(Value::as_u64).unwrap_or(0) {
        0 => Ok(Kdf::Pbkdf2 {
            iterations: number("kdfIterations", 600_000),
        }),
        1 => Ok(Kdf::Argon2id {
            iterations: number("kdfIterations", 3),
            memory_mib: number("kdfMemory", 64),
            parallelism: number("kdfParallelism", 4),
        }),
        other => Err(t!("vault.bw_unknown_kdf", kdf = other).into_owned()),
    }
}

/// Signs in with the master password hash, with a second factor if needed.
pub async fn login(
    http: &reqwest::Client,
    endpoints: &Endpoints,
    email: &str,
    password_hash: &str,
    device_id: &str,
    two_factor: Option<(u32, &str)>,
) -> Result<Login, String> {
    let email = email.trim().to_lowercase();
    let mut form = vec![
        ("grant_type", "password".to_string()),
        ("username", email.clone()),
        ("password", password_hash.to_string()),
        ("scope", "api offline_access".to_string()),
        ("client_id", CLIENT_ID.to_string()),
        ("deviceType", DEVICE_TYPE.to_string()),
        ("deviceIdentifier", device_id.to_string()),
        ("deviceName", DEVICE_NAME.to_string()),
    ];
    if let Some((provider, code)) = two_factor {
        form.push(("twoFactorProvider", provider.to_string()));
        form.push(("twoFactorToken", code.trim().to_string()));
        // No "remember": that would store a second token on this device, and
        // nothing is stored here.
        form.push(("twoFactorRemember", "0".to_string()));
    }

    let response = http
        .post(format!("{}/connect/token", endpoints.identity))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("Accept", "application/json")
        // Bitwarden counts failed attempts per account and needs the address
        // for that even when the attempt fails.
        .header("Auth-Email", b64_url(email.as_bytes()))
        .header("Device-Type", DEVICE_TYPE.to_string())
        .timeout(TIMEOUT)
        .body(encode_form(&form))
        .send()
        .await
        .map_err(|e| t!("vault.bw_unreachable", error = e).into_owned())?;

    let status = response.status();
    let value = read_json(response).await?;

    if status.is_success() {
        return Ok(Login::Done(session_from(&value)?));
    }

    // A missing second factor comes back as a perfectly ordinary 400 and differs
    // from a wrong password only by this field.
    if let Some(providers) = value.get("twoFactorProviders2").and_then(Value::as_object) {
        let offered = providers
            .keys()
            .filter_map(|key| key.parse::<u32>().ok())
            .collect::<Vec<_>>();
        if !offered.is_empty() {
            return Ok(Login::TwoFactor(offered));
        }
    }

    Err(message(&value)
        .unwrap_or_else(|| t!("vault.bw_login_refused", status = status).into_owned()))
}

/// Has the code sent for the email method. Without this, nothing reaches the
/// user that they could wait for.
pub async fn send_email_code(
    http: &reqwest::Client,
    endpoints: &Endpoints,
    email: &str,
    password_hash: &str,
    device_id: &str,
) -> Result<(), String> {
    let body = json!({
        "email": email.trim().to_lowercase(),
        "masterPasswordHash": password_hash,
        "deviceIdentifier": device_id,
    })
    .to_string();

    let response = http
        .post(format!("{}/two-factor/send-email-login", endpoints.api))
        .header("Content-Type", "application/json")
        .header("Accept", "application/json")
        .timeout(TIMEOUT)
        .body(body)
        .send()
        .await
        .map_err(|e| t!("vault.bw_unreachable", error = e).into_owned())?;

    if response.status().is_success() {
        return Ok(());
    }
    let value = read_json(response).await?;
    Err(message(&value).unwrap_or_else(|| t!("vault.bw_code_not_sent").into_owned()))
}

/// Renews an expired access token without asking for the password.
pub async fn refresh(
    http: &reqwest::Client,
    endpoints: &Endpoints,
    refresh_token: &str,
) -> Result<Session, String> {
    let form = [
        ("grant_type", "refresh_token".to_string()),
        ("client_id", CLIENT_ID.to_string()),
        ("refresh_token", refresh_token.to_string()),
    ];

    let response = http
        .post(format!("{}/connect/token", endpoints.identity))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("Accept", "application/json")
        .timeout(TIMEOUT)
        .body(encode_form(&form))
        .send()
        .await
        .map_err(|e| t!("vault.bw_unreachable", error = e).into_owned())?;

    if !response.status().is_success() {
        return Err(t!("vault.bw_session_not_renewed").into_owned());
    }
    session_from(&read_json(response).await?)
}

/// Fetches the whole vault in encrypted form.
///
/// There is no endpoint that delivers only the titles: whoever wants to know
/// what an entry is called gets all of it. What of it stays in memory is
/// therefore decided by [`super`] and not by the server.
pub async fn sync(
    http: &reqwest::Client,
    endpoints: &Endpoints,
    access: &str,
) -> Result<Value, String> {
    get(http, endpoints, access, "/sync?excludeDomains=true").await
}

/// Fetches a single entry — the way a secret is read.
pub async fn cipher(
    http: &reqwest::Client,
    endpoints: &Endpoints,
    access: &str,
    id: &str,
) -> Result<Value, String> {
    get(http, endpoints, access, &format!("/ciphers/{id}")).await
}

async fn get(
    http: &reqwest::Client,
    endpoints: &Endpoints,
    access: &str,
    path: &str,
) -> Result<Value, String> {
    let response = http
        .get(format!("{}{path}", endpoints.api))
        .header("Authorization", format!("Bearer {access}"))
        .header("Accept", "application/json")
        .header("Device-Type", DEVICE_TYPE.to_string())
        .timeout(TIMEOUT)
        .send()
        .await
        .map_err(|e| t!("vault.bw_unreachable", error = e).into_owned())?;

    let status = response.status();
    let value = read_json(response).await?;
    if status.is_success() {
        return Ok(value);
    }
    if status == reqwest::StatusCode::UNAUTHORIZED {
        return Err(super::EXPIRED.to_string());
    }
    Err(message(&value).unwrap_or_else(|| t!("vault.bw_status", status = status).into_owned()))
}

fn session_from(value: &Value) -> Result<Session, String> {
    let string = |key: &str| {
        value
            .get(key)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    };
    let access = string("access_token");
    if access.is_empty() {
        return Err(t!("vault.bw_no_access_token").into_owned());
    }
    let seconds = value
        .get("expires_in")
        .and_then(Value::as_u64)
        .unwrap_or(3600);
    Ok(Session {
        access,
        refresh: string("refresh_token"),
        expires_at: Instant::now() + Duration::from_secs(seconds),
    })
}

/// Pulls the error message out of a response, in whichever of the three forms
/// it appears — the endpoints have not stayed consistent over the years.
fn message(value: &Value) -> Option<String> {
    for key in ["errorModel", "error_description", "message"] {
        match value.get(key) {
            Some(Value::String(text)) if !text.is_empty() => return Some(text.clone()),
            Some(Value::Object(_)) => {
                if let Some(Value::String(text)) = value[key].get("message") {
                    if !text.is_empty() {
                        return Some(text.clone());
                    }
                }
            }
            _ => {}
        }
    }
    None
}

async fn read_json(response: reqwest::Response) -> Result<Value, String> {
    let body = response
        .text()
        .await
        .map_err(|e| t!("vault.bw_answer_unreadable", error = e).into_owned())?;
    // Not an error if this is not a JSON response: on a failure, a reverse
    // proxy in front of the own instance likes to answer with an HTML page,
    // and then the status code is the more useful information — which the
    // caller already has.
    match serde_json::from_str::<Value>(&body) {
        Ok(value) => Ok(normalize(value)),
        Err(_) => Ok(Value::Null),
    }
}

/// Gives every object key a lowercase first letter.
///
/// Bitwarden switched its API from `PascalCase` to `camelCase`, and
/// Vaultwarden followed only later. Both spellings are therefore found in the
/// wild, sometimes mixed within one response. Instead of allowing two names
/// for every field, this unifies once — afterwards every field is named the
/// way the rest of the module reads it.
///
/// Values stay untouched: the name of a custom field is in a key's *value*,
/// not in the key, and may keep its capitalisation.
fn normalize(value: Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.into_iter()
                .map(|(key, value)| {
                    let mut chars = key.chars();
                    let key = match chars.next() {
                        Some(first) => first.to_lowercase().collect::<String>() + chars.as_str(),
                        None => key,
                    };
                    (key, normalize(value))
                })
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.into_iter().map(normalize).collect()),
        other => other,
    }
}

fn encode_form(fields: &[(&str, String)]) -> String {
    fields
        .iter()
        .map(|(name, value)| format!("{name}={}", utf8_percent_encode(value, FORM)))
        .collect::<Vec<_>>()
        .join("&")
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Endpoints ------------------------------------------------------------
    //
    // The one piece of information the user gives, and three forms it arrives
    // in: not at all, as a hosted instance, as an own one. A mistake here shows
    // up as "server unreachable" and so looks like a network problem.

    fn resolved(server: &str) -> Endpoints {
        Endpoints::resolve(server).expect("should resolve")
    }

    #[test]
    fn nothing_given_means_bitwardens_own_service() {
        let endpoints = resolved("");
        assert_eq!(endpoints.identity, "https://identity.bitwarden.com");
        assert_eq!(endpoints.api, "https://api.bitwarden.com");
    }

    #[test]
    fn the_hosted_instances_are_recognised_by_name() {
        assert_eq!(resolved("https://vault.bitwarden.com"), resolved(""));
        assert_eq!(
            resolved("https://vault.bitwarden.eu").api,
            "https://api.bitwarden.eu"
        );
    }

    #[test]
    fn an_own_instance_hangs_both_services_under_its_address() {
        let endpoints = resolved("https://vault.intern.de");
        assert_eq!(endpoints.identity, "https://vault.intern.de/identity");
        assert_eq!(endpoints.api, "https://vault.intern.de/api");
    }

    #[test]
    fn a_subpath_is_kept_because_vaultwarden_is_often_mounted_under_one() {
        assert_eq!(
            resolved("https://intern.de/vaultwarden/").api,
            "https://intern.de/vaultwarden/api"
        );
    }

    #[test]
    fn an_address_without_a_scheme_is_read_as_https() {
        assert_eq!(
            resolved("vault.intern.de"),
            resolved("https://vault.intern.de")
        );
    }

    #[test]
    fn plain_http_is_refused_rather_than_silently_upgraded() {
        assert!(Endpoints::resolve("http://vault.intern.de").is_err());
    }

    // ---- Spelling -------------------------------------------------------------

    #[test]
    fn both_spellings_of_the_api_end_up_as_one() {
        let pascal = normalize(json!({
            "Profile": { "Key": "2.abc", "Organizations": [{ "Id": "o1" }] },
        }));
        let camel = normalize(json!({
            "profile": { "key": "2.abc", "organizations": [{ "id": "o1" }] },
        }));
        assert_eq!(pascal, camel);
        assert_eq!(pascal["profile"]["organizations"][0]["id"], "o1");
    }

    #[test]
    fn only_the_keys_are_touched_and_never_the_values() {
        // The name of a custom field is in the value. If it were lowercased
        // too, every reference to it would point nowhere.
        let value = normalize(json!({ "Fields": [{ "Name": "API-Token" }] }));
        assert_eq!(value["fields"][0]["name"], "API-Token");
    }

    // ---- Form -----------------------------------------------------------------

    #[test]
    fn form_fields_are_escaped_so_a_password_hash_survives_intact() {
        let encoded = encode_form(&[("password", "a+b/c=".to_string())]);
        assert_eq!(encoded, "password=a%2Bb%2Fc%3D");
    }
}
