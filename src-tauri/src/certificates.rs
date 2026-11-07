//! TLS certificates trusted here even though the system does not trust them.
//!
//! The counterpart of [`crate::known_hosts`] for FTPS and S3: a server with a
//! self-signed certificate could so far only be reached with "Don't verify
//! certificate", and that accepts *any* certificate — including that of
//! someone listening in. Here instead exactly one is remembered, after the
//! person has seen its fingerprint and confirmed it.
//!
//! One file beside `workspaces.json`, one line per host and port:
//! `host port sha256hex`. One certificate per address, since a server shows
//! one; when it is renewed, the new answer replaces the old one.
//!
//! In a workspace on a backend the answer belongs to the workspace, as with
//! host keys: it is stored there as an entry in `known_host_key` with the type
//! [`ALGORITHM`] and the fingerprint as hex in place of the key. Older clients
//! skip such entries, because they are not OpenSSH keys.

use std::fs;
use std::path::{Path, PathBuf};

use rust_i18n::t;
use serde::Serialize;
use tauri::{AppHandle, Manager};

use crate::ssh::{ask_host_key, next_question_id, HostKeyPrompts, HostKeyQuestion};
use crate::tls::{fingerprint_text, Fingerprint, Pinning, Refused};

const FILE_NAME: &str = "trusted_certificates";

/// What a certificate is called in a workspace, beside the SSH key types.
pub const ALGORITHM: &str = "x509-sha256";

fn app_file(app: &AppHandle) -> Result<PathBuf, String> {
    Ok(crate::paths::app_data_dir(app)?.join(FILE_NAME))
}

fn parse_hex(text: &str) -> Option<Fingerprint> {
    if text.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(text.get(index * 2..index * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

/// The form in the file and in the workspace: 64 characters, lower case.
fn hex(fingerprint: &Fingerprint) -> String {
    fingerprint
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Whether a line is about this address.
fn is_about(line: &str, host: &str, port: u16) -> bool {
    let mut fields = line.split_whitespace();
    fields
        .next()
        .is_some_and(|name| name.eq_ignore_ascii_case(host))
        && fields.next() == Some(port.to_string().as_str())
}

/// An entry from the file, as the host key management shows it.
#[derive(Serialize, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Entry {
    pub host: String,
    pub port: u16,
    /// `AB:CD:…`, as `openssl` writes it.
    pub fingerprint: String,
}

fn entries(text: &str) -> Vec<Entry> {
    text.lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let host = fields.next()?.to_string();
            let port = fields.next()?.parse().ok()?;
            let fingerprint = fingerprint_text(&parse_hex(fields.next()?)?);
            Some(Entry {
                host,
                port,
                fingerprint,
            })
        })
        .collect()
}

/// What is remembered for this address. A missing or unreadable file means
/// "nothing": then the user is asked, and that is the safe direction.
fn pins_in(path: &Path, host: &str, port: u16) -> Vec<Fingerprint> {
    let Ok(text) = fs::read_to_string(path) else {
        return Vec::new();
    };
    text.lines()
        .filter(|line| is_about(line, host, port))
        .filter_map(|line| parse_hex(line.split_whitespace().nth(2)?))
        .collect()
}

/// Rewrites the file: without the lines for this address, and with `added`
/// where one is being added.
fn rewrite(path: &Path, host: &str, port: u16, added: Option<&Fingerprint>) -> Result<(), String> {
    let text = fs::read_to_string(path).unwrap_or_default();
    let mut lines: Vec<String> = text
        .lines()
        .filter(|line| !is_about(line, host, port))
        .map(str::to_string)
        .collect();
    if let Some(fingerprint) = added {
        lines.push(format!(
            "{} {port} {}",
            host.to_lowercase(),
            hex(fingerprint)
        ));
    }

    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)
            .map_err(|e| t!("tls.create_failed", path = dir : {:?}, error = e).into_owned())?;
    }
    let mut out = lines.join("\n");
    if !out.is_empty() {
        out.push('\n');
    }
    fs::write(path, out)
        .map_err(|e| t!("tls.write_failed", path = path : {:?}, error = e).into_owned())
}

/// Remembers the certificate for this address, replacing whatever was there
/// before.
fn trust_in(path: &Path, host: &str, port: u16, fingerprint: &Fingerprint) -> Result<(), String> {
    rewrite(path, host, port, Some(fingerprint))
}

fn forget_in(path: &Path, host: &str, port: u16) -> Result<(), String> {
    rewrite(path, host, port, None)
}

pub fn pins(app: &AppHandle, host: &str, port: u16) -> Result<Vec<Fingerprint>, String> {
    Ok(pins_in(&app_file(app)?, host, port))
}

/// Takes over an entry from a workspace. A colleague has already answered
/// the question; confirming the same certificate once more would add no
/// security, only one more click.
///
/// Already remembered: then nothing is written — this runs on every sync. An
/// unreadable fingerprint is an error the sync skips.
pub fn trust_hex(app: &AppHandle, host: &str, port: u16, text: &str) -> Result<(), String> {
    let fingerprint =
        parse_hex(text.trim()).ok_or_else(|| t!("tls.fingerprint_unreadable").into_owned())?;
    let path = app_file(app)?;
    if pins_in(&path, host, port).contains(&fingerprint) {
        return Ok(());
    }
    trust_in(&path, host, port, &fingerprint)
}

/// Asks about a certificate the system does not trust — in the same dialog
/// as for an unknown host key — and remembers it on a yes. Returns what the
/// second attempt should connect with.
///
/// `tried` is what the first attempt connected with: if a certificate for
/// this address was already in there, this is a different one, and the
/// question is "has changed".
pub async fn ask_and_trust(
    app: &AppHandle,
    host: &str,
    port: u16,
    refused: &Refused,
    tried: &Pinning,
) -> Result<Pinning, String> {
    let question = HostKeyQuestion {
        id: next_question_id(),
        kind: "tls",
        host: host.to_string(),
        port,
        algorithm: ALGORITHM.to_string(),
        fingerprint: fingerprint_text(&refused.fingerprint),
        changed: !tried.pins.is_empty(),
        reason: refused.reason.clone(),
        // What goes into the workspace if it lives on a backend.
        public_key: hex(&refused.fingerprint),
    };
    let prompts = app.state::<HostKeyPrompts>().inner().clone();
    if !ask_host_key(app, &prompts, &question).await {
        return Err(t!(
            "tls.certificate_rejected",
            host = host,
            reason = refused.reason
        )
        .into_owned());
    }
    trust_in(&app_file(app)?, host, port, &refused.fingerprint)?;
    Ok(Pinning::new(vec![refused.fingerprint]))
}

/// What is in the app's own file.
#[tauri::command]
pub fn certificates_list(app: AppHandle) -> Result<Vec<Entry>, String> {
    Ok(fs::read_to_string(app_file(&app)?)
        .map(|text| entries(&text))
        .unwrap_or_default())
}

/// Forgets an address's certificate on this device. The next connection asks
/// again.
#[tauri::command]
pub fn certificates_forget(app: AppHandle, host: String, port: u16) -> Result<(), String> {
    forget_in(&app_file(&app)?, &host, port)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_file(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "wireterm-certificates-{name}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        dir.join(FILE_NAME)
    }

    #[test]
    fn a_remembered_certificate_holds_only_for_its_address() {
        let file = temp_file("address");
        let one = [1u8; 32];
        assert!(pins_in(&file, "ftp.example.test", 21).is_empty());

        trust_in(&file, "FTP.example.test", 21, &one).expect("written");
        assert_eq!(pins_in(&file, "ftp.example.test", 21), vec![one]);
        assert!(pins_in(&file, "ftp.example.test", 990).is_empty());
        assert!(pins_in(&file, "other.example.test", 21).is_empty());
        let _ = fs::remove_dir_all(file.parent().unwrap());
    }

    #[test]
    fn a_new_certificate_replaces_the_old_and_leaves_others_alone() {
        let file = temp_file("replace");
        let (old, new, foreign) = ([1u8; 32], [2u8; 32], [3u8; 32]);
        trust_in(&file, "ftp.example.test", 21, &old).unwrap();
        trust_in(&file, "other.example.test", 21, &foreign).unwrap();
        trust_in(&file, "ftp.example.test", 21, &new).unwrap();

        assert_eq!(pins_in(&file, "ftp.example.test", 21), vec![new]);
        assert_eq!(pins_in(&file, "other.example.test", 21), vec![foreign]);
        let _ = fs::remove_dir_all(file.parent().unwrap());
    }

    #[test]
    fn forgetting_takes_only_the_one_address() {
        let file = temp_file("forget");
        trust_in(&file, "ftp.example.test", 21, &[1u8; 32]).unwrap();
        trust_in(&file, "s3.example.test", 443, &[2u8; 32]).unwrap();
        forget_in(&file, "FTP.example.test", 21).unwrap();

        assert!(pins_in(&file, "ftp.example.test", 21).is_empty());
        let rest = entries(&fs::read_to_string(&file).unwrap());
        assert_eq!(rest.len(), 1);
        assert_eq!(rest[0].host, "s3.example.test");
        assert_eq!(rest[0].port, 443);
        assert!(rest[0].fingerprint.starts_with("02:02:"));

        forget_in(&file, "s3.example.test", 443).unwrap();
        assert_eq!(fs::read_to_string(&file).unwrap(), "");
        let _ = fs::remove_dir_all(file.parent().unwrap());
    }

    #[test]
    fn the_hex_form_makes_the_round_trip() {
        let fingerprint: Fingerprint = core::array::from_fn(|i| i as u8 * 7);
        assert_eq!(parse_hex(&hex(&fingerprint)), Some(fingerprint));
        assert_eq!(
            parse_hex(&hex(&fingerprint).to_uppercase()),
            Some(fingerprint)
        );
        assert_eq!(parse_hex("zz"), None);
    }

    #[test]
    fn unreadable_lines_are_skipped() {
        let file = temp_file("broken");
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        fs::write(&file, "ftp.example.test 21 too-short\nftp.example.test\n\n").unwrap();
        assert!(pins_in(&file, "ftp.example.test", 21).is_empty());
        let _ = fs::remove_dir_all(file.parent().unwrap());
    }
}
