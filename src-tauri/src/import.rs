//! Taking over connections from other programs.
//!
//! Every source yields the same: a list of [`ImportedHost`], from which the
//! UI makes connections, and what could not be taken over.
//!
//! - **`~/.ssh/config`** — see [`crate::ssh_config`].
//! - **PuTTY** — the saved sessions, on Windows from the registry
//!   (`HKCU\Software\SimonTatham\PuTTY\Sessions`), otherwise from
//!   `~/.putty/sessions`. A `.ppk` as the key file reads the login
//!   directly.
//! - **MobaXterm** — the `MobaXterm.ini` or an exported
//!   `.mxtsessions`. The format is not documented; what is read is what can
//!   be said for sure: SSH sessions with host, port, user, key and
//!   gateway.
//! - **CSV** — with a header line, comma, semicolon or tab. This is also the
//!   way for Termius and everything else that can export a table.

use std::collections::HashMap;

use rust_i18n::t;
use serde::Serialize;
use tauri::{AppHandle, Manager};

use crate::proxy::{Proxy, ProxyKind, ProxySetting};
use crate::storage::{Forward, ForwardKind, FtpSecurity};

/// What kind of connection it becomes.
#[derive(Serialize, Debug, PartialEq, Clone, Copy)]
#[serde(rename_all = "camelCase")]
pub enum ImportKind {
    Ssh,
    Ftp,
}

/// How the connection logs in — the same spellings as
/// `SshAuth`/`FtpAuth`, so the UI can use it unchanged.
#[derive(Serialize, Debug, PartialEq, Clone)]
#[serde(tag = "source", rename_all = "camelCase")]
pub enum ImportAuth {
    KeyFile {
        path: String,
    },
    Agent,
    /// Ask for the password when connecting — no import takes over passwords,
    /// none of these sources holds them readably.
    Prompt,
}

/// A host as it would arrive in WireTerm.
#[derive(Serialize, Debug, PartialEq, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ImportedHost {
    /// Becomes the connection's name.
    pub alias: String,
    pub kind: ImportKind,
    pub host: String,
    pub port: u16,
    pub user: String,
    pub auth: ImportAuth,
    /// Only for FTP.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security: Option<FtpSecurity>,
    /// Folder or group in the source. For display only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    /// Set if the host can only be reached through another one — the
    /// `ProxyJump` or `ProxyCommand` as written. For display.
    pub proxy: Option<String>,
    /// The hops, first one first, as names — what can be mapped onto other
    /// hosts.
    pub proxy_jump: Vec<String>,
    pub forwards: Vec<Forward>,
    pub agent_forwarding: bool,
    /// A SOCKS5 or HTTP proxy for the connection.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection_proxy: Option<ProxySetting>,
    /// What does not come along.
    pub notes: Vec<String>,
}

impl ImportedHost {
    pub fn new(
        kind: ImportKind,
        alias: &str,
        host: &str,
        port: u16,
        user: &str,
        auth: ImportAuth,
    ) -> Self {
        ImportedHost {
            alias: alias.to_string(),
            kind,
            host: host.to_string(),
            port,
            user: user.to_string(),
            auth,
            security: None,
            group: None,
            proxy: None,
            proxy_jump: Vec::new(),
            forwards: Vec::new(),
            agent_forwarding: false,
            connection_proxy: None,
            notes: Vec::new(),
        }
    }
}

/// An entry that cannot become a connection — Telnet, RDP, serial.
#[derive(Serialize, Debug, PartialEq, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Skipped {
    pub name: String,
    pub reason: String,
}

#[derive(Serialize, Debug, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ImportResult {
    pub hosts: Vec<ImportedHost>,
    pub skipped: Vec<Skipped>,
}

// ---- Shared ---------------------------------------------------------------------

/// `host:port`, `[v6]:port` or just `port` — for forwardings.
pub fn endpoint(text: &str) -> Option<(String, u16)> {
    let text = text.trim();
    if let Some(rest) = text.strip_prefix('[') {
        let (host, port) = rest.split_once("]:")?;
        return Some((host.to_string(), port.parse().ok()?));
    }
    match text.rsplit_once(':') {
        Some((host, port)) => Some((host.to_string(), port.parse().ok()?)),
        None => Some((String::new(), text.parse().ok()?)),
    }
}

/// `*` as the address means, for OpenSSH and PuTTY: on all interfaces.
pub fn bind_host(host: String) -> String {
    if host == "*" {
        "0.0.0.0".to_string()
    } else {
        host
    }
}

/// Text from a file another program wrote: UTF-8 with or without a BOM,
/// UTF-16 with a BOM, and otherwise Windows-1252 — that is how MobaXterm and
/// Excel write on Windows.
pub fn decode_text(bytes: &[u8]) -> String {
    if let Some(rest) = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]) {
        return String::from_utf8_lossy(rest).into_owned();
    }
    if let Some(rest) = bytes.strip_prefix(&[0xFF, 0xFE]) {
        let units: Vec<u16> = rest
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u16::from_le_bytes(*pair))
            .collect();
        return String::from_utf16_lossy(&units);
    }
    if let Ok(text) = std::str::from_utf8(bytes) {
        return text.to_string();
    }
    bytes.iter().map(|&byte| windows_1252(byte)).collect()
}

fn windows_1252(byte: u8) -> char {
    const HIGH: [char; 32] = [
        '€', '\u{81}', '‚', 'ƒ', '„', '…', '†', '‡', 'ˆ', '‰', 'Š', '‹', 'Œ', '\u{8D}', 'Ž',
        '\u{8F}', '\u{90}', '‘', '’', '“', '”', '•', '–', '—', '˜', '™', 'š', '›', 'œ', '\u{9D}',
        'ž', 'Ÿ',
    ];
    match byte {
        0x80..=0x9F => HIGH[usize::from(byte - 0x80)],
        _ => char::from(byte),
    }
}

// ---- PuTTY ------------------------------------------------------------------------

/// A saved session from its values. On Windows they come from the registry,
/// otherwise from a file with one `key=value` per line — the names are the
/// same.
pub fn putty_session(
    name: &str,
    values: &HashMap<String, String>,
) -> Result<ImportedHost, Skipped> {
    let value = |key: &str| values.get(key).map(|v| v.trim()).unwrap_or_default();
    let skipped = |reason: String| Skipped {
        name: name.to_string(),
        reason,
    };

    let protocol = value("Protocol");
    if !protocol.is_empty() && protocol != "ssh" {
        return Err(skipped(
            t!("import.instead_of_ssh", protocol = protocol).to_string(),
        ));
    }
    let (user_in_host, host) = match value("HostName").rsplit_once('@') {
        Some((user, host)) => (user.to_string(), host.to_string()),
        None => (String::new(), value("HostName").to_string()),
    };
    if host.is_empty() {
        return Err(skipped(t!("import.no_host").to_string()));
    }
    let user = match value("UserName") {
        "" => user_in_host,
        user => user.to_string(),
    };
    let port = value("PortNumber").parse().unwrap_or(22);
    let auth = match value("PublicKeyFile") {
        "" => ImportAuth::Prompt,
        path => ImportAuth::KeyFile {
            path: path.to_string(),
        },
    };

    let mut imported = ImportedHost::new(ImportKind::Ssh, name, &host, port, &user, auth);
    imported.agent_forwarding = value("AgentFwd") == "1";
    imported.forwards = putty_forwards(value("PortForwardings"), &mut imported.notes);

    let proxy_host = value("ProxyHost");
    let proxy_port = value("ProxyPort").parse().unwrap_or(0);
    let proxy = |kind| {
        Some(ProxySetting::Custom(Proxy {
            kind,
            host: proxy_host.to_string(),
            port: proxy_port,
        }))
    };
    match value("ProxyMethod") {
        "" | "0" => {}
        "2" if !proxy_host.is_empty() => imported.connection_proxy = proxy(ProxyKind::Socks5),
        "3" if !proxy_host.is_empty() => imported.connection_proxy = proxy(ProxyKind::Http),
        // From 0.77 on: an SSH connection as the proxy, i.e. a jump host.
        "6" if !proxy_host.is_empty() => {
            imported.proxy = Some(proxy_host.to_string());
            imported.proxy_jump = vec![proxy_host.to_string()];
        }
        "1" => imported
            .notes
            .push(t!("import.socks4_not_imported").to_string()),
        _ => imported
            .notes
            .push(t!("import.proxy_command_not_imported").to_string()),
    }
    if imported.connection_proxy.is_some() && !value("ProxyUsername").is_empty() {
        imported
            .notes
            .push(t!("import.proxy_login_not_imported").to_string());
    }
    Ok(imported)
}

/// `L8080=localhost:80,R2222=localhost:22,D1080` — optionally preceded by `4`
/// or `6` for the address family, optionally an address before the port.
fn putty_forwards(text: &str, notes: &mut Vec<String>) -> Vec<Forward> {
    let mut forwards = Vec::new();
    for entry in text.split(',').map(str::trim).filter(|e| !e.is_empty()) {
        let entry = entry.trim_start_matches(['4', '6']);
        let (kind, rest) = entry.split_at(entry.chars().next().map_or(0, char::len_utf8));
        let (bind, target) = match rest.split_once(['=', '\t']) {
            Some((bind, target)) => (bind, Some(target)),
            None => (rest, None),
        };
        let parsed = endpoint(bind).and_then(|(address, bind_port)| {
            let kind = match kind {
                "L" => ForwardKind::Local,
                "R" => ForwardKind::Remote,
                "D" => ForwardKind::Dynamic,
                _ => return None,
            };
            let (target_host, target_port) = match (kind, target) {
                (ForwardKind::Dynamic, _) => (String::new(), 0),
                (_, Some(target)) => endpoint(target).filter(|(host, _)| !host.is_empty())?,
                (_, None) => return None,
            };
            Some(Forward {
                kind,
                bind_host: bind_host(address),
                bind_port,
                target_host,
                target_port,
            })
        });
        match parsed {
            Some(forward) => forwards.push(forward),
            None => notes.push(t!("import.forward_not_understood", entry = entry).to_string()),
        }
    }
    forwards
}

/// `%20` and relatives in the session names.
fn putty_name(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 3 <= bytes.len() {
            let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or_default();
            if let Ok(byte) = u8::from_str_radix(hex, 16) {
                out.push(byte);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    decode_text(&out)
}

/// Saved sessions: the name as it stands in the source, and the values.
type Sessions = Vec<(String, HashMap<String, String>)>;

/// The saved sessions as name and values, without "Default Settings".
fn putty_sessions(app: &AppHandle) -> Result<Sessions, String> {
    let mut sessions = putty_sessions_from_registry()?;
    let home = app
        .path()
        .home_dir()
        .map_err(|e| t!("import.no_home_dir", error = e).to_string())?;
    let dir = home.join(".putty").join("sessions");
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let Ok(bytes) = std::fs::read(entry.path()) else {
                continue;
            };
            let values = decode_text(&bytes)
                .lines()
                .filter_map(|line| line.split_once('='))
                .map(|(key, value)| (key.to_string(), value.to_string()))
                .collect();
            sessions.push((entry.file_name().to_string_lossy().into_owned(), values));
        }
    }
    sessions.retain(|(name, _)| name != "Default%20Settings");
    Ok(sessions)
}

#[cfg(windows)]
fn putty_sessions_from_registry() -> Result<Sessions, String> {
    use winreg::enums::HKEY_CURRENT_USER;
    use winreg::types::FromRegValue;
    use winreg::RegKey;

    let Ok(root) =
        RegKey::predef(HKEY_CURRENT_USER).open_subkey("Software\\SimonTatham\\PuTTY\\Sessions")
    else {
        return Ok(Vec::new());
    };
    let mut sessions = Vec::new();
    for name in root.enum_keys().flatten() {
        let Ok(key) = root.open_subkey(&name) else {
            continue;
        };
        let values = key
            .enum_values()
            .flatten()
            .filter_map(|(value_name, value)| {
                let text = String::from_reg_value(&value)
                    .ok()
                    .or_else(|| u32::from_reg_value(&value).ok().map(|n| n.to_string()))?;
                Some((value_name, text))
            })
            .collect();
        sessions.push((name, values));
    }
    Ok(sessions)
}

#[cfg(not(windows))]
fn putty_sessions_from_registry() -> Result<Sessions, String> {
    Ok(Vec::new())
}

#[tauri::command]
pub fn import_putty(app: AppHandle) -> Result<ImportResult, String> {
    let mut result = ImportResult::default();
    for (raw, values) in putty_sessions(&app)? {
        match putty_session(&putty_name(&raw), &values) {
            Ok(host) => result.hosts.push(host),
            Err(skipped) => result.skipped.push(skipped),
        }
    }
    result.hosts.sort_by_key(|host| host.alias.to_lowercase());
    Ok(result)
}

// ---- MobaXterm --------------------------------------------------------------------

/// The sessions from a `MobaXterm.ini` or `.mxtsessions`.
///
/// A session is a line `Name=#Icon#Settings#Terminal#…` in a section
/// `[Bookmarks…]`, whose `SubRep` is the folder. The settings are separated
/// by `%`: type (0 = SSH), host, port, user; at 8 to 10 the gateway (host,
/// port, user), at 14 the private key.
pub fn mobaxterm(text: &str, home: &str) -> ImportResult {
    let mut result = ImportResult::default();
    let mut in_bookmarks = false;
    let mut group: Option<String> = None;
    for line in text.lines().map(str::trim) {
        if line.starts_with('[') {
            in_bookmarks = line.to_ascii_lowercase().starts_with("[bookmarks");
            group = None;
            continue;
        }
        if !in_bookmarks {
            continue;
        }
        let Some((name, value)) = line.split_once('=') else {
            continue;
        };
        if name.eq_ignore_ascii_case("SubRep") {
            group = Some(value.replace('\\', " / ")).filter(|g| !g.is_empty());
            continue;
        }
        if name.eq_ignore_ascii_case("ImgNum") || !value.starts_with('#') {
            continue;
        }
        let Some(settings) = value.split('#').nth(2) else {
            continue;
        };
        let fields: Vec<&str> = settings.split('%').collect();
        let field = |index: usize| fields.get(index).copied().unwrap_or_default().trim();
        if field(0) != "0" {
            result.skipped.push(Skipped {
                name: name.to_string(),
                reason: t!("import.session_type_instead_of_ssh", kind = field(0)).to_string(),
            });
            continue;
        }
        if field(1).is_empty() {
            result.skipped.push(Skipped {
                name: name.to_string(),
                reason: t!("import.no_host").to_string(),
            });
            continue;
        }
        let auth = match field(14) {
            "" => ImportAuth::Prompt,
            path => ImportAuth::KeyFile {
                path: mobaxterm_path(path, home),
            },
        };
        let mut host = ImportedHost::new(
            ImportKind::Ssh,
            name.trim(),
            field(1),
            field(2).parse().unwrap_or(22),
            field(3),
            auth,
        );
        host.group = group.clone();
        if !field(8).is_empty() {
            host.proxy = Some(field(8).to_string());
            host.proxy_jump = vec![field(8).to_string()];
        }
        result.hosts.push(host);
    }
    result
}

/// MobaXterm writes paths with placeholders, so that a portable version works
/// from a USB stick.
fn mobaxterm_path(path: &str, home: &str) -> String {
    path.replace("_ProfileDir_", home)
        .replace("_MyDocuments_", &format!("{home}\\Documents"))
        .replace("_CurrentDrive_", "C:")
}

// ---- CSV --------------------------------------------------------------------------

/// Columns are recognized by their heading, not by their position.
fn column(header: &str) -> Option<&'static str> {
    let header = header.trim().trim_start_matches('\u{feff}').to_lowercase();
    Some(match header.as_str() {
        "name" | "label" | "alias" | "title" | "titel" | "session" | "sitzung" => "name",
        "host" | "hostname" | "hostname/ip" | "address" | "adresse" | "ip" | "server" => "host",
        "port" => "port",
        "user" | "username" | "user name" | "login" | "benutzer" | "benutzername" => "user",
        "protocol" | "protokoll" | "type" | "typ" => "protocol",
        "key" | "keyfile" | "key file" | "identityfile" | "identity file" | "private key"
        | "privatekey" | "schlüssel" | "schlüsseldatei" => "key",
        "group" | "groups" | "folder" | "ordner" | "gruppe" => "group",
        _ => return None,
    })
}

/// RFC 4180: quoted fields may contain the separator, line breaks and
/// doubled quotes.
fn csv_rows(text: &str, separator: char) -> Vec<Vec<String>> {
    let mut rows = Vec::new();
    let mut row = Vec::new();
    let mut field = String::new();
    let mut quoted = false;
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' if quoted && chars.peek() == Some(&'"') => {
                field.push('"');
                chars.next();
            }
            '"' => quoted = !quoted,
            c if c == separator && !quoted => row.push(std::mem::take(&mut field)),
            '\r' if !quoted => {}
            '\n' if !quoted => {
                row.push(std::mem::take(&mut field));
                rows.push(std::mem::take(&mut row));
            }
            c => field.push(c),
        }
    }
    if !field.is_empty() || !row.is_empty() {
        row.push(field);
        rows.push(row);
    }
    rows.retain(|row| row.iter().any(|field| !field.trim().is_empty()));
    rows
}

pub fn csv(text: &str) -> Result<ImportResult, String> {
    let first = text.lines().next().unwrap_or_default();
    let separator = [';', '\t', ',']
        .into_iter()
        .max_by_key(|sep| first.matches(*sep).count())
        .unwrap_or(',');
    let mut rows = csv_rows(text, separator).into_iter();
    let header = rows
        .next()
        .ok_or_else(|| t!("import.csv_empty").to_string())?;
    let columns: Vec<Option<&str>> = header.iter().map(|h| column(h)).collect();
    if !columns.contains(&Some("host")) {
        return Err(t!("import.csv_no_host_column").to_string());
    }

    let mut result = ImportResult::default();
    for (index, row) in rows.enumerate() {
        let get = |name: &str| -> String {
            columns
                .iter()
                .position(|c| *c == Some(name))
                .and_then(|i| row.get(i))
                .map(|v| v.trim().to_string())
                .unwrap_or_default()
        };
        let host = get("host");
        let name = Some(get("name"))
            .filter(|n| !n.is_empty())
            .unwrap_or_else(|| host.clone());
        if host.is_empty() {
            result.skipped.push(Skipped {
                name: if name.is_empty() {
                    t!("import.row", number = index + 2).to_string()
                } else {
                    name
                },
                reason: t!("import.no_host").to_string(),
            });
            continue;
        }
        let protocol = get("protocol").to_lowercase();
        let (kind, security, default_port) = match protocol.as_str() {
            "" | "ssh" | "sftp" => (ImportKind::Ssh, None, 22),
            "ftp" => (ImportKind::Ftp, Some(FtpSecurity::Plain), 21),
            "ftps" => (ImportKind::Ftp, Some(FtpSecurity::Explicit), 21),
            other => {
                result.skipped.push(Skipped {
                    name,
                    reason: t!("import.instead_of_ssh_or_ftp", protocol = other).to_string(),
                });
                continue;
            }
        };
        let key = get("key");
        let auth = if key.is_empty() || kind == ImportKind::Ftp {
            ImportAuth::Prompt
        } else {
            ImportAuth::KeyFile { path: key }
        };
        let port = get("port").parse().unwrap_or(default_port);
        let mut imported = ImportedHost::new(kind, &name, &host, port, &get("user"), auth);
        imported.security = security;
        imported.group = Some(get("group")).filter(|g| !g.is_empty());
        result.hosts.push(imported);
    }
    Ok(result)
}

/// Reads a file in the given format: `mobaxterm` or `csv`.
#[tauri::command]
pub fn import_file(app: AppHandle, path: String, format: String) -> Result<ImportResult, String> {
    let bytes = std::fs::read(&path)
        .map_err(|e| t!("import.read_failed", path = path, error = e).to_string())?;
    let text = decode_text(&bytes);
    match format.as_str() {
        "mobaxterm" => {
            let home = app
                .path()
                .home_dir()
                .map_err(|e| t!("import.no_home_dir", error = e).to_string())?;
            Ok(mobaxterm(&text, &home.to_string_lossy()))
        }
        "csv" => csv(&text),
        other => Err(t!("import.unknown_format", format = other).to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn values(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn a_putty_session_with_everything() {
        let host = putty_session(
            "web01",
            &values(&[
                ("Protocol", "ssh"),
                ("HostName", "deploy@web01.example"),
                ("PortNumber", "2222"),
                ("UserName", ""),
                ("PublicKeyFile", "C:\\keys\\web.ppk"),
                ("AgentFwd", "1"),
                (
                    "PortForwardings",
                    "L8080=localhost:80,4L127.0.0.1:5433=db:5432,R2222=localhost:22,D1080,X1=y",
                ),
                ("ProxyMethod", "2"),
                ("ProxyHost", "proxy.internal"),
                ("ProxyPort", "1080"),
            ]),
        )
        .expect("an SSH session");
        assert_eq!(host.host, "web01.example");
        assert_eq!(host.user, "deploy");
        assert_eq!(host.port, 2222);
        assert_eq!(
            host.auth,
            ImportAuth::KeyFile {
                path: "C:\\keys\\web.ppk".into()
            }
        );
        assert!(host.agent_forwarding);
        let kinds: Vec<_> = host
            .forwards
            .iter()
            .map(|f| (f.kind, f.bind_host.as_str(), f.bind_port))
            .collect();
        assert_eq!(
            kinds,
            [
                (ForwardKind::Local, "", 8080),
                (ForwardKind::Local, "127.0.0.1", 5433),
                (ForwardKind::Remote, "", 2222),
                (ForwardKind::Dynamic, "", 1080),
            ]
        );
        assert_eq!(host.forwards[1].target_host, "db");
        assert_eq!(host.forwards[1].target_port, 5432);
        assert_eq!(host.notes, ["Forwarding \"X1=y\" not understood"]);
        assert_eq!(
            host.connection_proxy,
            Some(ProxySetting::Custom(Proxy {
                kind: ProxyKind::Socks5,
                host: "proxy.internal".into(),
                port: 1080
            }))
        );
    }

    #[test]
    fn putty_without_a_key_prompts_and_telnet_stays_out() {
        let host = putty_session(
            "a",
            &values(&[("HostName", "a.example"), ("UserName", "root")]),
        )
        .expect("ssh");
        assert_eq!(host.auth, ImportAuth::Prompt);
        assert_eq!(host.port, 22);

        let telnet = putty_session(
            "old",
            &values(&[("Protocol", "telnet"), ("HostName", "old")]),
        );
        assert_eq!(telnet.expect_err("not SSH").reason, "telnet instead of SSH");
    }

    /// Against this machine's registry — prints only numbers, no names.
    #[cfg(windows)]
    #[test]
    #[ignore]
    fn putty_from_the_registry() {
        let sessions = putty_sessions_from_registry().expect("reads");
        assert!(!sessions.is_empty(), "no PuTTY sessions on this machine");
        let (mut ssh, mut skipped, mut keys, mut forwards) = (0, 0, 0, 0);
        for (raw, values) in &sessions {
            match putty_session(&putty_name(raw), values) {
                Ok(host) => {
                    ssh += 1;
                    assert!(!host.host.is_empty());
                    keys += usize::from(matches!(host.auth, ImportAuth::KeyFile { .. }));
                    forwards += host.forwards.len();
                }
                Err(_) => skipped += 1,
            }
        }
        println!(
            "{} sessions: {ssh} SSH ({keys} with a key, {forwards} forwardings), {skipped} skipped",
            sessions.len()
        );
    }

    #[test]
    fn putty_names_are_encoded() {
        assert_eq!(putty_name("My%20Server%20%2F%20Prod"), "My Server / Prod");
        assert_eq!(putty_name("end%2"), "end%2");
    }

    const MOBA: &str = "[Misc]\r\nfoo=bar\r\n[Bookmarks]\r\nSubRep=\r\nImgNum=42\r\nweb01=#109#0%web01.example%2222%deploy%%-1%-1%%bastion%22%jump%0%0%0%_ProfileDir_\\.ssh\\id_ed25519%%-1%0%0%0%%1080%%0%0%1#MobaFont%10#0# #-1\r\n[Bookmarks_1]\r\nSubRep=Customers\\North\r\nImgNum=41\r\nnas=#109#0%nas.local%22%admin%%-1%-1%%%22%%0%0%0%%%-1%0%0%0%%1080%%0%0%1#MobaFont#0# #-1\r\nrdp1=#91#4%win.local%3389%user%#MobaFont#0# #-1\r\n";

    #[test]
    fn mobaxterm_ssh_sessions_with_folder_key_and_gateway() {
        let result = mobaxterm(MOBA, "C:\\Users\\anna");
        assert_eq!(result.hosts.len(), 2);
        let web = &result.hosts[0];
        assert_eq!(
            (
                web.alias.as_str(),
                web.host.as_str(),
                web.port,
                web.user.as_str()
            ),
            ("web01", "web01.example", 2222, "deploy")
        );
        assert_eq!(
            web.auth,
            ImportAuth::KeyFile {
                path: "C:\\Users\\anna\\.ssh\\id_ed25519".into()
            }
        );
        assert_eq!(web.proxy_jump, ["bastion"]);
        assert_eq!(web.group, None);

        let nas = &result.hosts[1];
        assert_eq!(nas.auth, ImportAuth::Prompt);
        assert_eq!(nas.group.as_deref(), Some("Customers / North"));
        assert!(nas.proxy_jump.is_empty());

        assert_eq!(result.skipped.len(), 1);
        assert_eq!(result.skipped[0].name, "rdp1");
    }

    #[test]
    fn csv_with_semicolon_quotes_and_its_own_headings() {
        let text = "\u{feff}Label;Hostname/IP;Port;Username;Protocol;Groups\r\n\"Web; Prod\";web01;2222;root;ssh;Customers\r\nstorage;files.example;;ftpuser;FTPS;\r\n;;;;;\r\nrdp;win;3389;u;rdp;\r\nhostless;;22;u;ssh;\r\n";
        let result = csv(text).expect("reads");
        assert_eq!(result.hosts.len(), 2);
        let web = &result.hosts[0];
        assert_eq!(
            (web.alias.as_str(), web.host.as_str(), web.port),
            ("Web; Prod", "web01", 2222)
        );
        assert_eq!(web.kind, ImportKind::Ssh);
        assert_eq!(web.group.as_deref(), Some("Customers"));

        let storage = &result.hosts[1];
        assert_eq!(storage.kind, ImportKind::Ftp);
        assert_eq!(storage.port, 21);
        assert_eq!(storage.security, Some(FtpSecurity::Explicit));

        let reasons: Vec<_> = result
            .skipped
            .iter()
            .map(|s| (s.name.as_str(), s.reason.as_str()))
            .collect();
        assert_eq!(
            reasons,
            [
                ("rdp", "rdp instead of SSH or FTP"),
                ("hostless", "no host")
            ]
        );
    }

    #[test]
    fn csv_with_comma_and_line_break_in_a_field() {
        let text = "name,host,user,key\n\"two\nlines\",h,\"a \"\"b\"\"\",~/.ssh/id\n";
        let result = csv(text).expect("reads");
        assert_eq!(result.hosts[0].alias, "two\nlines");
        assert_eq!(result.hosts[0].user, "a \"b\"");
        assert_eq!(
            result.hosts[0].auth,
            ImportAuth::KeyFile {
                path: "~/.ssh/id".into()
            }
        );
    }

    #[test]
    fn csv_without_a_host_column_says_so() {
        assert!(csv("name,port\nx,22\n")
            .expect_err("no host")
            .contains("column for the host"));
    }

    #[test]
    fn windows_1252_and_utf16_are_read() {
        assert_eq!(decode_text(b"Gr\xfc\xdfe \x80"), "Grüße €");
        assert_eq!(decode_text(&[0xFF, 0xFE, b'a', 0, 0xFC, 0]), "aü");
        assert_eq!(
            decode_text("already utf-8: ü".as_bytes()),
            "already utf-8: ü"
        );
    }
}
