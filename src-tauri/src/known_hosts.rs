//! Which server keys are trusted, and where that is recorded.
//!
//! Two files are consulted. The app keeps its own `known_hosts` beside
//! `workspaces.json`, and that is the only one it ever writes to. The user's
//! `~/.ssh/known_hosts` is read as well, so a host already trusted in a normal
//! terminal does not have to be confirmed a second time — but never changed:
//! a GUI app has no business editing the file every other SSH client on the
//! machine depends on.
//!
//! Where both have something to say, the app's own file wins. An answer the
//! user gave here must not be overruled by a stale entry somewhere else.

use std::fs;
use std::path::{Path, PathBuf};

use russh::keys::known_hosts::{known_host_keys_path, learn_known_hosts_path};
use russh::keys::{Algorithm, HashAlg, PublicKey};
use rust_i18n::t;
use serde::Serialize;
use tauri::{AppHandle, Manager};

const FILE_NAME: &str = "known_hosts";

/// What the stores say about the key a server just offered.
#[derive(PartialEq)]
pub enum Verdict {
    /// Recorded, and the same key. Connect without asking.
    Known,
    /// Nothing recorded for this host and key type. First contact.
    Unknown,
    /// A *different* key of this type is recorded. Either the server was
    /// rebuilt, or this is not the server it claims to be.
    Changed,
}

/// `known_hosts` in the app's data directory, beside the workspaces — see
/// [`crate::paths`].
fn app_file(app: &AppHandle) -> Result<PathBuf, String> {
    let dir = crate::paths::app_data_dir(app)?;
    Ok(dir.join(FILE_NAME))
}

/// `None` where the platform has no home directory to speak of.
fn user_file(app: &AppHandle) -> Option<PathBuf> {
    Some(app.path().home_dir().ok()?.join(".ssh").join(FILE_NAME))
}

/// How a host is written into a `known_hosts` line, and therefore what has to
/// be matched to take one out again.
fn host_pattern(host: &str, port: u16) -> String {
    if port == 22 {
        host.to_string()
    } else {
        format!("[{host}]:{port}")
    }
}

/// One file's verdict, or `None` where it holds nothing about this host and
/// key type and so has no opinion.
///
/// A file that cannot be read or parsed counts as silent rather than as an
/// error: most machines have no `~/.ssh` at all, and the app's own file does
/// not exist until the first host is trusted. Staying quiet means the user is
/// asked, which is the safe direction.
fn verdict_of(path: &Path, host: &str, port: u16, offered: &PublicKey) -> Option<Verdict> {
    let recorded = known_host_keys_path(host, port, path).unwrap_or_default();

    // Compared on the key material alone: a line read back from a file carries
    // no comment, the key off the wire carries none either, and a difference
    // in one must not read as a different key.
    if recorded
        .iter()
        .any(|(_, key)| key.key_data() == offered.key_data())
    {
        return Some(Verdict::Known);
    }
    // Only an entry of the same type contradicts this one. A host that also
    // has an RSA key on file says nothing about the Ed25519 key it just
    // offered — OpenSSH treats that as unknown too, not as a change.
    if recorded
        .iter()
        .any(|(_, key)| key.algorithm() == offered.algorithm())
    {
        return Some(Verdict::Changed);
    }
    None
}

pub fn lookup(
    app: &AppHandle,
    host: &str,
    port: u16,
    offered: &PublicKey,
) -> Result<Verdict, String> {
    if let Some(verdict) = verdict_of(&app_file(app)?, host, port, offered) {
        return Ok(verdict);
    }
    if let Some(verdict) = user_file(app).and_then(|path| verdict_of(&path, host, port, offered)) {
        return Ok(verdict);
    }
    Ok(Verdict::Unknown)
}

/// Records a key as trusted, replacing whatever was on file for this host and
/// key type.
///
/// Replacing rather than appending: a key the user accepted in place of one
/// that had changed must not leave the old entry behind, or the next
/// connection asks the same question again.
pub fn trust(app: &AppHandle, host: &str, port: u16, key: &PublicKey) -> Result<(), String> {
    let path = app_file(app)?;
    forget(&path, host, port, &key.algorithm())?;

    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)
            .map_err(|e| t!("ssh.create_failed", path = dir : {:?}, error = e).into_owned())?;
    }
    learn_known_hosts_path(host, port, key, &path)
        .map_err(|e| t!("ssh.write_failed", path = path : {:?}, error = e).into_owned())
}

/// Drops the app's entries for one host and key type.
///
/// Only the shape this app writes is recognised — a plain host pattern, one
/// key per line — which is exactly what `learn_known_hosts_path` produces. The
/// user's file is never touched, so nothing else has to be understood.
fn forget(path: &Path, host: &str, port: u16, algorithm: &Algorithm) -> Result<(), String> {
    // Nothing recorded yet, nothing to take out.
    let Ok(raw) = fs::read_to_string(path) else {
        return Ok(());
    };

    let pattern = host_pattern(host, port);
    let kept: Vec<&str> = raw
        .lines()
        .filter(|line| {
            let mut fields = line.split_whitespace();
            !(fields.next() == Some(pattern.as_str()) && fields.next() == Some(algorithm.as_str()))
        })
        .collect();

    if kept.len() == raw.lines().count() {
        return Ok(());
    }

    let mut text = kept.join("\n");
    if !text.is_empty() {
        text.push('\n');
    }
    fs::write(path, text)
        .map_err(|e| t!("ssh.rewrite_failed", path = path : {:?}, error = e).into_owned())
}

/// Records a key in the form it arrives in over the wire: an
/// `authorized_keys` line, `ssh-ed25519 AAAA…`.
///
/// That is the way from a workspace to here. A colleague has already answered
/// the question; asking it here a second time would gain no security, only
/// one more chance to click "yes" without looking.
pub fn trust_openssh(app: &AppHandle, host: &str, port: u16, openssh: &str) -> Result<(), String> {
    let key = PublicKey::from_openssh(openssh.trim())
        .map_err(|e| t!("ssh.host_key_unreadable", error = e).into_owned())?;

    // Already on disk: then touch nothing. `trust` rewrites the file, and
    // doing that on every sync would be one write per known host and pass.
    if lookup(app, host, port, &key)? == Verdict::Known {
        return Ok(());
    }
    trust(app, host, port, &key)
}

// ---- Viewing and removing ------------------------------------------------------

/// An entry from the app's own file, as the UI shows it.
#[derive(Serialize, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Entry {
    pub host: String,
    pub port: u16,
    pub algorithm: String,
    /// `SHA256:…`, as `ssh` shows it on first connecting — that is how a key
    /// is recognised, not by its base64 characters.
    pub fingerprint: String,
}

/// The lines this app writes: `host` or `[host]:port`, type, key. Anything
/// that looks different — a comment, a hashed line — is skipped; this app did
/// not write it.
fn entries(text: &str) -> Vec<Entry> {
    text.lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let pattern = fields.next()?;
            let algorithm = fields.next()?;
            let key = fields.next()?;
            let (host, port) = match pattern.strip_prefix('[') {
                Some(rest) => {
                    let (host, port) = rest.split_once("]:")?;
                    (host.to_string(), port.parse().ok()?)
                }
                None => (pattern.to_string(), 22),
            };
            let fingerprint = fingerprint(&format!("{algorithm} {key}")).ok()?;
            Some(Entry {
                host,
                port,
                algorithm: algorithm.to_string(),
                fingerprint,
            })
        })
        .collect()
}

pub fn fingerprint(openssh: &str) -> Result<String, String> {
    let key = PublicKey::from_openssh(openssh.trim())
        .map_err(|e| t!("ssh.host_key_unreadable", error = e).into_owned())?;
    Ok(key.fingerprint(HashAlg::Sha256).to_string())
}

/// What is in the app's own `known_hosts`. `~/.ssh/known_hosts` is only read
/// and not shown here — the app has nothing to decide there.
#[tauri::command]
pub fn known_hosts_list(app: AppHandle) -> Result<Vec<Entry>, String> {
    let path = app_file(&app)?;
    Ok(fs::read_to_string(path)
        .map(|text| entries(&text))
        .unwrap_or_default())
}

/// Withdraws trust from a key on this device. The next connection asks again
/// — unless `~/.ssh/known_hosts` knows it.
#[tauri::command]
pub fn known_hosts_forget(
    app: AppHandle,
    host: String,
    port: u16,
    algorithm: String,
) -> Result<(), String> {
    let algorithm = Algorithm::new(&algorithm)
        .map_err(|e| t!("ssh.unknown_key_algorithm", error = e).into_owned())?;
    forget(&app_file(&app)?, &host, port, &algorithm)
}

/// The fingerprint of a key from a workspace — the same display as for the
/// app's own.
#[tauri::command]
pub fn host_key_fingerprint(public_key: String) -> Result<String, String> {
    fingerprint(&public_key)
}

/// The form in which a key goes into a workspace.
pub fn to_openssh(key: &PublicKey) -> Result<String, String> {
    key.to_openssh()
        .map_err(|e| t!("ssh.host_key_write_failed", error = e).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ED25519: &str = "AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";

    #[test]
    fn the_own_file_reads_with_fingerprint() {
        let text = format!(
            "web01 ssh-ed25519 {ED25519}\n[storage.example]:23 ssh-ed25519 {ED25519}\n# comment\n|1|hashed ssh-ed25519 {ED25519}\n"
        );
        let list = entries(&text);
        assert_eq!(
            list.len(),
            3,
            "the comment is dropped, the hashed line is not: {list:?}"
        );
        assert_eq!(list[0].host, "web01");
        assert_eq!(list[0].port, 22);
        assert_eq!(list[1].host, "storage.example");
        assert_eq!(list[1].port, 23);
        assert!(
            list[0].fingerprint.starts_with("SHA256:"),
            "{}",
            list[0].fingerprint
        );
    }

    #[test]
    fn removing_hits_only_host_and_type() {
        let dir = std::env::temp_dir().join(format!("wireterm-kh-{}", std::process::id()));
        fs::create_dir_all(&dir).expect("directory");
        let path = dir.join("known_hosts");
        fs::write(
            &path,
            format!("web01 ssh-ed25519 {ED25519}\n[web01]:2222 ssh-ed25519 {ED25519}\n"),
        )
        .expect("write");

        forget(&path, "web01", 22, &Algorithm::Ed25519).expect("remove");
        let rest = entries(&fs::read_to_string(&path).expect("read"));
        assert_eq!(rest.len(), 1);
        assert_eq!(rest[0].port, 2222, "the other port stays");
        let _ = fs::remove_dir_all(dir);
    }
}
