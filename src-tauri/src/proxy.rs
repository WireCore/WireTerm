//! Connecting through a proxy — SOCKS5 or HTTP CONNECT, for SSH, FTP and S3.
//!
//! Two levels:
//!
//! - The **default proxy** belongs to this device, not to a workspace:
//!   whether a proxy is needed depends on the network the machine is in right
//!   now. It lives in `proxy.json`, its password encrypted with the device key
//!   like the other local secrets.
//! - A **connection** can deviate from it: direct, or through a proxy of its
//!   own. That travels with the connection, also through the backend — and
//!   therefore without a login, because a connection has exactly one secret.
//!
//! For SSH and FTP, [`connect`] opens the TCP connection through the proxy;
//! the protocol runs over it as if the proxy were not in between. S3 goes
//! through reqwest, which can do both itself, see [`reqwest_proxy`].

use std::net::IpAddr;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use rust_i18n::t;
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::local_secrets::{self, LocalVault};

const FILE: &str = "proxy.json";
const AAD: &str = "wireterm/proxy/default/password";
/// Until the proxy accepts the TCP connection, and as long again until it has
/// put the connection through to the target.
const TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum ProxyKind {
    /// SOCKS5; the target's name is only resolved at the proxy.
    Socks5,
    /// HTTP CONNECT, as corporate proxies speak it.
    Http,
}

/// A proxy as it is set on a connection.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Proxy {
    pub kind: ProxyKind,
    pub host: String,
    pub port: u16,
}

/// What a connection says about its proxy. If the field is missing, this
/// device's default proxy applies.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(tag = "mode", rename_all = "camelCase")]
pub enum ProxySetting {
    /// Without a proxy, even if a default proxy is set.
    Direct,
    Custom(Proxy),
}

/// The route actually taken — and at the same time the default proxy as the
/// UI edits it.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Route {
    pub kind: ProxyKind,
    pub host: String,
    pub port: u16,
    /// Empty means without a login.
    #[serde(default)]
    pub user: String,
    /// Encrypted in `proxy.json`, in plain text in the UI.
    #[serde(default)]
    pub password: String,
}

impl Route {
    fn label(&self) -> String {
        address(&self.host, self.port)
    }
}

/// `host:port`, an IPv6 address in brackets.
fn address(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

// ---- Which route --------------------------------------------------------------

/// The proxy for a connection, or `None` for direct.
pub fn route(app: &AppHandle, setting: Option<&ProxySetting>) -> Result<Option<Route>, String> {
    match setting {
        Some(ProxySetting::Direct) => Ok(None),
        Some(ProxySetting::Custom(proxy)) if proxy.host.trim().is_empty() => {
            Err(t!("core.proxy_custom_without_host").to_string())
        }
        Some(ProxySetting::Custom(proxy)) => Ok(Some(Route {
            kind: proxy.kind,
            host: proxy.host.trim().to_string(),
            port: proxy.port,
            user: String::new(),
            password: String::new(),
        })),
        None => load_default(app),
    }
}

fn file(app: &AppHandle) -> Result<std::path::PathBuf, String> {
    Ok(crate::paths::app_data_dir(app)?.join(FILE))
}

fn load_default(app: &AppHandle) -> Result<Option<Route>, String> {
    let path = file(app)?;
    let raw = match std::fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(t!("core.read_failed", path = format!("{path:?}"), error = e).to_string())
        }
    };
    let mut route: Route = serde_json::from_str(&raw)
        .map_err(|e| t!("core.damaged", path = format!("{path:?}"), error = e).to_string())?;
    if !route.password.is_empty() {
        let key = app
            .state::<LocalVault>()
            .key(app)
            .ok_or_else(|| t!("core.proxy_password_locked").to_string())?;
        route.password = local_secrets::open_text(&key, AAD, &route.password)?;
    }
    Ok(Some(route))
}

/// This device's default proxy, with the password in plain text.
#[tauri::command]
pub fn proxy_default_get(app: AppHandle) -> Result<Option<Route>, String> {
    load_default(&app)
}

/// Sets the default proxy, or removes it with `None`.
#[tauri::command]
pub fn proxy_default_set(app: AppHandle, proxy: Option<Route>) -> Result<(), String> {
    let path = file(&app)?;
    let Some(mut route) = proxy else {
        return match std::fs::remove_file(&path) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                Err(t!("core.delete_failed", path = format!("{path:?}"), error = e).to_string())
            }
            _ => Ok(()),
        };
    };
    route.host = route.host.trim().to_string();
    if route.host.is_empty() {
        return Err(t!("core.proxy_needs_host").to_string());
    }
    if route.user.is_empty() {
        route.password.clear();
    }
    if !route.password.is_empty() {
        let key = app
            .state::<LocalVault>()
            .key(&app)
            .ok_or_else(|| t!("core.proxy_password_needs_key").to_string())?;
        route.password = local_secrets::seal_text(&key, AAD, &route.password)?;
    }
    crate::cloud::account::write_json(&path, &route)
}

// ---- Through the proxy ------------------------------------------------------------

/// A TCP connection to `host:port`, opened through the proxy. Whatever runs
/// over it afterwards, the proxy only sees as bytes.
pub async fn connect(route: &Route, host: &str, port: u16) -> Result<TcpStream, String> {
    let mut stream = timeout(
        TIMEOUT,
        TcpStream::connect((route.host.as_str(), route.port)),
    )
    .await
    .map_err(|_| t!("core.proxy_no_answer", proxy = route.label()).to_string())?
    .map_err(|e| t!("core.proxy_unreachable", proxy = route.label(), error = e).to_string())?;
    let handshake = async {
        match route.kind {
            ProxyKind::Socks5 => socks5(&mut stream, route, host, port).await,
            ProxyKind::Http => http_connect(&mut stream, route, host, port).await,
        }
    };
    timeout(TIMEOUT, handshake)
        .await
        .map_err(|_| t!("core.proxy_not_through", proxy = route.label()).to_string())?
        .map_err(|e| t!("core.proxy_error", proxy = route.label(), error = e).to_string())?;
    Ok(stream)
}

/// RFC 1928, with user name and password per RFC 1929.
async fn socks5<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    route: &Route,
    host: &str,
    port: u16,
) -> Result<(), String> {
    let io = |e: std::io::Error| e.to_string();
    let auth = !route.user.is_empty();
    let greeting: &[u8] = if auth {
        &[5, 2, 0x00, 0x02]
    } else {
        &[5, 1, 0x00]
    };
    stream.write_all(greeting).await.map_err(io)?;
    let mut choice = [0u8; 2];
    stream.read_exact(&mut choice).await.map_err(io)?;
    if choice[0] != 5 {
        return Err(t!("core.proxy_not_socks5").to_string());
    }
    match choice[1] {
        0x00 => {}
        0x02 if auth => {
            let (user, password) = (route.user.as_bytes(), route.password.as_bytes());
            if user.len() > 255 || password.len() > 255 {
                return Err(t!("core.proxy_credentials_too_long").to_string());
            }
            let mut request = vec![1, user.len() as u8];
            request.extend_from_slice(user);
            request.push(password.len() as u8);
            request.extend_from_slice(password);
            stream.write_all(&request).await.map_err(io)?;
            let mut status = [0u8; 2];
            stream.read_exact(&mut status).await.map_err(io)?;
            if status[1] != 0 {
                return Err(t!("core.proxy_login_rejected").to_string());
            }
        }
        _ if !auth => return Err(t!("core.proxy_login_required").to_string()),
        _ => return Err(t!("core.proxy_no_accepted_method").to_string()),
    }

    let mut request = vec![5, 1, 0];
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => {
            request.push(1);
            request.extend_from_slice(&ip.octets());
        }
        Ok(IpAddr::V6(ip)) => {
            request.push(4);
            request.extend_from_slice(&ip.octets());
        }
        // As a name: it is resolved at the proxy, which knows the network behind it.
        Err(_) => {
            let name = host.as_bytes();
            if name.len() > 255 {
                return Err(t!("core.proxy_host_name_too_long").to_string());
            }
            request.push(3);
            request.push(name.len() as u8);
            request.extend_from_slice(name);
        }
    }
    request.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&request).await.map_err(io)?;

    let mut reply = [0u8; 4];
    stream.read_exact(&mut reply).await.map_err(io)?;
    if reply[1] != 0 {
        return Err(match reply[1] {
            2 => t!("core.proxy_target_forbidden").to_string(),
            3 => t!("core.proxy_network_unreachable").to_string(),
            4 => t!("core.proxy_host_unreachable", host = host).to_string(),
            5 => t!(
                "core.proxy_connection_refused",
                target = address(host, port)
            )
            .to_string(),
            6 => t!("core.proxy_timed_out").to_string(),
            code => t!("core.proxy_error_code", code = code).to_string(),
        });
    }
    // The address the proxy has bound for itself — it is not needed, but it
    // comes before the target's first bytes.
    let skip = match reply[3] {
        1 => 4,
        4 => 16,
        3 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await.map_err(io)?;
            usize::from(len[0])
        }
        _ => return Err(t!("core.proxy_reply_unreadable").to_string()),
    };
    let mut rest = vec![0u8; skip + 2];
    stream.read_exact(&mut rest).await.map_err(io)?;
    Ok(())
}

/// `CONNECT host:port` — the proxy answers with a status line and headers,
/// after that the line belongs to the target.
async fn http_connect<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    route: &Route,
    host: &str,
    port: u16,
) -> Result<(), String> {
    let io = |e: std::io::Error| e.to_string();
    let target = address(host, port);
    let mut request = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n");
    if !route.user.is_empty() {
        let credentials = BASE64.encode(format!("{}:{}", route.user, route.password));
        request.push_str(&format!("Proxy-Authorization: Basic {credentials}\r\n"));
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes()).await.map_err(io)?;

    // Byte by byte up to the blank line: whatever comes after it already
    // belongs to the target and must not be read along here.
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() > 16 * 1024 {
            return Err(t!("core.proxy_reply_endless").to_string());
        }
        stream.read_exact(&mut byte).await.map_err(io)?;
        head.push(byte[0]);
    }
    let head = String::from_utf8_lossy(&head);
    let status_line = head.lines().next().unwrap_or_default();
    let mut parts = status_line.splitn(3, ' ');
    let (version, status) = (
        parts.next().unwrap_or_default(),
        parts.next().unwrap_or_default(),
    );
    if !version.starts_with("HTTP/") {
        return Err(t!("core.proxy_not_http").to_string());
    }
    match status {
        s if s.starts_with('2') => Ok(()),
        // 407 is the textbook answer; tinyproxy sends 401.
        "407" | "401" if route.user.is_empty() => Err(t!("core.proxy_login_required").to_string()),
        "407" | "401" => Err(t!("core.proxy_login_rejected").to_string()),
        _ => Err(t!("core.proxy_answers", status = status_line.trim()).to_string()),
    }
}

/// The same proxy for reqwest. `socks5h`, so that there too the proxy resolves
/// the name.
pub fn reqwest_proxy(route: &Route) -> Result<reqwest::Proxy, String> {
    let scheme = match route.kind {
        ProxyKind::Socks5 => "socks5h",
        ProxyKind::Http => "http",
    };
    let mut url = reqwest::Url::parse(&format!("{scheme}://{}", route.label()))
        .map_err(|e| t!("core.proxy_error", proxy = route.label(), error = e).to_string())?;
    if !route.user.is_empty() {
        url.set_username(&route.user)
            .and_then(|_| url.set_password(Some(&route.password)))
            .map_err(|_| t!("core.proxy_login_not_in_url", proxy = route.label()).to_string())?;
    }
    reqwest::Proxy::all(url)
        .map_err(|e| t!("core.proxy_error", proxy = route.label(), error = e).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    fn test_route(kind: ProxyKind, user: &str) -> Route {
        Route {
            kind,
            host: "proxy".into(),
            port: 1080,
            user: user.into(),
            password: if user.is_empty() {
                String::new()
            } else {
                "secret".into()
            },
        }
    }

    fn run(test: impl std::future::Future<Output = ()>) {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(test);
    }

    #[test]
    fn socks5_without_login_sends_the_name_to_the_proxy() {
        run(async {
            let (mut client, mut proxy) = duplex(1024);
            let server = tokio::spawn(async move {
                let mut greeting = [0u8; 3];
                proxy.read_exact(&mut greeting).await.unwrap();
                assert_eq!(greeting, [5, 1, 0]);
                proxy.write_all(&[5, 0]).await.unwrap();
                let mut head = [0u8; 5];
                proxy.read_exact(&mut head).await.unwrap();
                assert_eq!(head, [5, 1, 0, 3, 13]);
                let mut rest = [0u8; 15];
                proxy.read_exact(&mut rest).await.unwrap();
                assert_eq!(&rest[..13], b"internal.lan.");
                assert_eq!(u16::from_be_bytes([rest[13], rest[14]]), 22);
                proxy
                    .write_all(&[5, 0, 0, 1, 10, 0, 0, 1, 0, 80, b'S', b'S', b'H'])
                    .await
                    .unwrap();
            });
            socks5(
                &mut client,
                &test_route(ProxyKind::Socks5, ""),
                "internal.lan.",
                22,
            )
            .await
            .expect("put through");
            // Whatever comes after belongs to the target.
            let mut banner = [0u8; 3];
            client.read_exact(&mut banner).await.unwrap();
            assert_eq!(&banner, b"SSH");
            server.await.unwrap();
        });
    }

    #[test]
    fn socks5_logs_in_and_sends_an_ip_as_an_ip() {
        run(async {
            let (mut client, mut proxy) = duplex(1024);
            let server = tokio::spawn(async move {
                let mut greeting = [0u8; 4];
                proxy.read_exact(&mut greeting).await.unwrap();
                assert_eq!(greeting, [5, 2, 0, 2]);
                proxy.write_all(&[5, 2]).await.unwrap();
                let mut login = [0u8; 2 + 4 + 1 + 6];
                proxy.read_exact(&mut login).await.unwrap();
                assert_eq!(&login, b"\x01\x04anna\x06secret");
                proxy.write_all(&[1, 0]).await.unwrap();
                let mut request = [0u8; 4 + 4 + 2];
                proxy.read_exact(&mut request).await.unwrap();
                assert_eq!(request, [5, 1, 0, 1, 192, 168, 1, 7, 0, 21]);
                proxy.write_all(&[5, 0, 0, 3, 1, b'x', 0, 0]).await.unwrap();
            });
            socks5(
                &mut client,
                &test_route(ProxyKind::Socks5, "anna"),
                "192.168.1.7",
                21,
            )
            .await
            .expect("put through");
            server.await.unwrap();
        });
    }

    #[test]
    fn socks5_says_why_it_fails() {
        run(async {
            let (mut client, mut proxy) = duplex(1024);
            tokio::spawn(async move {
                let mut greeting = [0u8; 3];
                proxy.read_exact(&mut greeting).await.unwrap();
                proxy.write_all(&[5, 0xFF]).await.unwrap();
            });
            let error = socks5(
                &mut client,
                &test_route(ProxyKind::Socks5, ""),
                "target",
                22,
            )
            .await
            .expect_err("refused");
            assert!(error.contains("login"), "{error}");

            let (mut client, mut proxy) = duplex(1024);
            tokio::spawn(async move {
                let mut greeting = [0u8; 3];
                proxy.read_exact(&mut greeting).await.unwrap();
                proxy.write_all(&[5, 0]).await.unwrap();
                let mut request = [0u8; 4 + 1 + 6 + 2];
                proxy.read_exact(&mut request).await.unwrap();
                proxy
                    .write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0])
                    .await
                    .unwrap();
            });
            let error = socks5(
                &mut client,
                &test_route(ProxyKind::Socks5, ""),
                "target",
                22,
            )
            .await
            .expect_err("refused");
            assert!(error.contains("refused"), "{error}");
        });
    }

    #[test]
    fn http_connect_with_login_does_not_read_past_the_blank_line() {
        run(async {
            let (mut client, mut proxy) = duplex(4096);
            let server = tokio::spawn(async move {
                let mut request = Vec::new();
                let mut byte = [0u8; 1];
                while !request.ends_with(b"\r\n\r\n") {
                    proxy.read_exact(&mut byte).await.unwrap();
                    request.push(byte[0]);
                }
                let request = String::from_utf8(request).unwrap();
                assert!(
                    request.starts_with("CONNECT [2001:db8::1]:22 HTTP/1.1\r\n"),
                    "{request}"
                );
                // anna:secret
                assert!(request.contains("Proxy-Authorization: Basic YW5uYTpzZWNyZXQ=\r\n"));
                proxy
                    .write_all(b"HTTP/1.1 200 Connection established\r\nVia: squid\r\n\r\nSSH-2.0")
                    .await
                    .unwrap();
            });
            http_connect(
                &mut client,
                &test_route(ProxyKind::Http, "anna"),
                "2001:db8::1",
                22,
            )
            .await
            .expect("put through");
            let mut banner = [0u8; 7];
            client.read_exact(&mut banner).await.unwrap();
            assert_eq!(&banner, b"SSH-2.0");
            server.await.unwrap();
        });
    }

    #[test]
    fn http_connect_407_means_login() {
        run(async {
            let (mut client, mut proxy) = duplex(4096);
            tokio::spawn(async move {
                let mut buffer = [0u8; 256];
                let _ = proxy.read(&mut buffer).await;
                proxy
                    .write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
                    .await
                    .unwrap();
            });
            let error = http_connect(&mut client, &test_route(ProxyKind::Http, ""), "target", 22)
                .await
                .expect_err("refused");
            assert!(error.contains("requires a login"), "{error}");
        });
    }

    #[test]
    fn a_connections_setting_as_json() {
        let custom: ProxySetting =
            serde_json::from_str(r#"{"mode":"custom","kind":"socks5","host":"p","port":1080}"#)
                .expect("reads");
        assert_eq!(
            custom,
            ProxySetting::Custom(Proxy {
                kind: ProxyKind::Socks5,
                host: "p".into(),
                port: 1080
            })
        );
        let direct: ProxySetting = serde_json::from_str(r#"{"mode":"direct"}"#).expect("reads");
        assert_eq!(direct, ProxySetting::Direct);
    }

    #[test]
    fn reqwest_gets_the_login_in_the_address() {
        assert!(reqwest_proxy(&test_route(ProxyKind::Socks5, "an na")).is_ok());
        assert!(reqwest_proxy(&test_route(ProxyKind::Http, "")).is_ok());
    }

    /// Against real proxies: Dante and tinyproxy from `scripts/proxy`, in the
    /// network from `scripts/ssh-jump`. `ziel` and `web` are only reachable
    /// there.
    #[test]
    #[ignore]
    fn through_real_proxies() {
        run(async {
            for (kind, port) in [(ProxyKind::Socks5, 21080), (ProxyKind::Http, 23128)] {
                let route = Route {
                    kind,
                    host: "127.0.0.1".into(),
                    port,
                    user: "anna".into(),
                    password: "geheim".into(),
                };

                // SSH and FTP: a TCP connection the protocol runs over.
                let mut stream = connect(&route, "ziel", 22)
                    .await
                    .expect("through the proxy");
                let mut banner = [0u8; 8];
                stream.read_exact(&mut banner).await.unwrap();
                assert_eq!(&banner, b"SSH-2.0-", "{kind:?}");

                // S3: reqwest with the same proxy.
                let http = reqwest::Client::builder()
                    .tls_backend_preconfigured(crate::tls::config(false).expect("tls"))
                    .proxy(reqwest_proxy(&route).expect("proxy"))
                    .build()
                    .expect("client");
                let answer = http
                    .get("http://web/")
                    .send()
                    .await
                    .expect("through the proxy");
                assert!(
                    answer.status().is_success(),
                    "{kind:?}: {}",
                    answer.status()
                );

                // Wrong password.
                let wrong = Route {
                    password: "wrong".into(),
                    ..route
                };
                let error = connect(&wrong, "ziel", 22).await.expect_err("refused");
                assert!(error.contains("login"), "{kind:?}: {error}");
            }
        });
    }
}
