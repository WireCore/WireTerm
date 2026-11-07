//! Accounts, sessions and the vault that closes after a quarter of an hour.
//!
//! An account is a user on a backend. Because an account can have several
//! organizations and each of them is a workspace, several workspaces belong
//! to one account — whoever adds two workspaces of the same backend still
//! signs in only once.
//!
//! Two passwords, and the difference carries the whole module:
//!
//! |               | sign-in password          | master password                   |
//! | ------------- | ------------------------- | --------------------------------- |
//! | used for      | signing in to the server  | opening the secrets               |
//! | where it lies | as a hash on the server   | **nowhere**, not even as a hash   |
//! | resettable    | yes, by email             | no — the recovery codes are for that |
//!
//! If both were the same, the server could read along at sign-in what the
//! secrets are sealed with. The master password therefore goes nowhere —
//! neither into a file nor over the wire. What is derived from it is held in
//! [`Unlocked`] and lives as long as the session or a quarter of an hour in
//! which nothing happened at the computer.

use std::fs;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use rust_i18n::t;
use serde::{Deserialize, Serialize};
use tauri::AppHandle;

use super::crypto::Secret32;
use super::http::{Api, Jar, Server};

/// After how long of inactivity **at the computer** the private key is taken
/// out of memory and the master password has to be asked for again.
///
/// The same quarter of an hour as in the Bitwarden module in the tree, for the
/// same reason: an unattended computer should not stay open, and a short walk
/// to the printer should not lead to a password prompt.
///
/// What counts is the time without input at the computer, not the time
/// without access to the vault — see [`super::idle`].
pub const LOCK_AFTER: Duration = Duration::from_secs(15 * 60);

/// A user on a backend.
///
/// Lives in `cloud-accounts.json` next to `workspaces.json`. What it holds is
/// the address, the name — and the session, encrypted with the device key
/// ([`seal_sessions`]). No password, neither the one nor the other.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Account {
    pub id: String,
    pub server: Server,
    pub email: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub user_id: String,
    /// The session. The reason a sign-in survives a restart.
    /// On disk it is not stored here but encrypted in
    /// [`Account::session`]; a `jar` in the file is plaintext from an
    /// earlier version.
    #[serde(default, skip_serializing_if = "Jar::is_empty")]
    pub jar: Jar,
    /// [`Account::jar`], encrypted with the device key. Stays in place as
    /// long as it cannot be opened — otherwise the session would be gone
    /// after the next save, although only the app password was missing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<String>,
}

impl Account {
    /// Whether there is a session at all. Whether it is still valid only the
    /// server knows; that shows up as a `401`.
    pub fn signed_in(&self) -> bool {
        !self.jar.is_empty()
    }

    pub fn api(&self) -> Result<Api, String> {
        Api::new(&self.server)
    }
}

/// How an account appears in the UI.
#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct AccountView {
    pub id: String,
    pub server: String,
    pub url: String,
    pub email: String,
    pub name: String,
    pub user_id: String,
    pub signed_in: bool,
    /// The WireCloud address, if the account is signed in through it. Then
    /// WireCloud manages members, teams and invitations, not this program,
    /// and the UI hides the corresponding parts.
    pub managed_by: Option<String>,
    /// Whether a key pair for this user already exists on this server.
    /// `None` as long as nobody has checked.
    pub has_keys: Option<bool>,
    /// Whether the master password has already been entered in this run.
    pub unlocked: bool,
}

/// What is derived from the master password.
///
/// Only in memory, for the duration of the session — never on disk. That
/// holds only as long as this type does not start to implement `Serialize`.
pub struct Unlocked {
    /// The user's private key, X25519.
    pub private: Secret32,
    pub public: [u8; 32],
    /// When it was last used. Decides the lock on platforms that do not
    /// reveal their idle time.
    touched: Instant,
}

impl Unlocked {
    pub fn new(private: Secret32, public: [u8; 32]) -> Self {
        Self {
            private,
            public,
            touched: Instant::now(),
        }
    }

    pub fn expired(&self) -> bool {
        match super::idle::since_last_input() {
            Some(idle) => idle >= LOCK_AFTER,
            None => self.touched.elapsed() >= LOCK_AFTER,
        }
    }

    pub fn touch(&mut self) {
        self.touched = Instant::now();
    }
}

// ---- Where it lives ----------------------------------------------------------

const ACCOUNTS_FILE: &str = "cloud-accounts.json";
const CACHE_DIR: &str = "cloud";

pub fn accounts_path(app: &AppHandle) -> Result<PathBuf, String> {
    Ok(crate::paths::app_data_dir(app)?.join(ACCOUNTS_FILE))
}

/// One workspace per file instead of all in one: the sync writes after every
/// run, and a workspace with a thousand connections should not be written
/// along with every change of another one.
pub fn cache_path(app: &AppHandle, workspace_id: &str) -> Result<PathBuf, String> {
    let dir = crate::paths::app_data_dir(app)?.join(CACHE_DIR);
    Ok(dir.join(format!("{}.json", sanitize(workspace_id))))
}

pub fn cache_dir(app: &AppHandle) -> Result<PathBuf, String> {
    Ok(crate::paths::app_data_dir(app)?.join(CACHE_DIR))
}

/// An organization ID comes from the server and is a file name.
///
/// better-auth assigns characters from `[A-Za-z0-9]` there, but that is not
/// relied upon: a `..` in a file name would lead out of the folder, and that
/// is too costly for the saving.
fn sanitize(id: &str) -> String {
    id.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

pub fn read_json<T: serde::de::DeserializeOwned>(path: &PathBuf) -> Result<Option<T>, String> {
    if !path.is_file() {
        return Ok(None);
    }
    let raw = fs::read_to_string(path).map_err(|e| {
        t!(
            "cloud.file_unreadable",
            path = format!("{path:?}"),
            error = e
        )
        .to_string()
    })?;
    serde_json::from_str(&raw)
        .map(Some)
        .map_err(|e| t!("cloud.file_damaged", path = format!("{path:?}"), error = e).to_string())
}

/// Writes next to it and renames, so that an aborted write does not leave a
/// half file where the copy of the workspace was.
/// Opens the encrypted sessions. Returns whether one was still in the file
/// as plaintext.
pub fn open_sessions(accounts: &mut [Account], key: Option<&[u8; 32]>) -> bool {
    let mut plaintext = false;
    for account in accounts {
        match &account.session {
            Some(sealed) => {
                let aad = crate::local_secrets::account_aad(&account.id);
                let opened = key
                    .and_then(|key| crate::local_secrets::open_text(key, &aad, sealed).ok())
                    .and_then(|json| serde_json::from_str::<Jar>(&json).ok());
                if let Some(jar) = opened {
                    account.jar = jar;
                    account.session = None;
                }
            }
            None => plaintext |= !account.jar.is_empty(),
        }
    }
    plaintext
}

/// What of the accounts goes to disk: the session encrypted.
///
/// Without a device key a new session is not written at all instead of in
/// plaintext — it then lasts until the app quits, and after that the user
/// signs in again.
pub fn seal_sessions(accounts: &[Account], key: Option<&[u8; 32]>) -> Result<Vec<Account>, String> {
    let mut out = accounts.to_vec();
    for account in &mut out {
        if account.jar.is_empty() {
            continue;
        }
        if let Some(key) = key {
            let json = serde_json::to_string(&account.jar).map_err(|e| e.to_string())?;
            let aad = crate::local_secrets::account_aad(&account.id);
            account.session = Some(crate::local_secrets::seal_text(key, &aad, &json)?);
        }
        account.jar = Jar::default();
    }
    Ok(out)
}

pub fn write_json<T: serde::Serialize>(path: &PathBuf, value: &T) -> Result<(), String> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).map_err(|e| {
            t!(
                "cloud.dir_create_failed",
                path = format!("{dir:?}"),
                error = e
            )
            .to_string()
        })?;
    }
    let json = serde_json::to_string_pretty(value).map_err(|e| e.to_string())?;
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, json).map_err(|e| {
        t!(
            "cloud.file_write_failed",
            path = format!("{tmp:?}"),
            error = e
        )
        .to_string()
    })?;
    fs::rename(&tmp, path).map_err(|e| {
        t!(
            "cloud.file_replace_failed",
            path = format!("{path:?}"),
            error = e
        )
        .to_string()
    })
}

pub fn remove_file(path: &PathBuf) -> Result<(), String> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(t!(
            "cloud.file_remove_failed",
            path = format!("{path:?}"),
            error = e
        )
        .to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An ID comes from the server and becomes a file name here. A `..`
    /// in it would lead out of the folder.
    #[test]
    fn an_id_becomes_a_harmless_file_name() {
        assert_eq!(sanitize("abc123-XYZ_9"), "abc123-XYZ_9");
        assert_eq!(sanitize("../../etc/passwd"), "______etc_passwd");
        assert_eq!(sanitize("a/b\\c"), "a_b_c");
    }

    /// A freshly unlocked vault is open, and the lock depends on the last
    /// use, not on the unlocking.
    #[test]
    fn a_freshly_unlocked_vault_is_open() {
        let mut vault = Unlocked::new(zeroize::Zeroizing::new([7u8; 32]), [8u8; 32]);
        assert!(!vault.expired());
        vault.touch();
        assert!(!vault.expired());
    }

    fn account(jar: Jar) -> Account {
        Account {
            id: "acc-1".into(),
            server: Server::resolve("https://wireterm.example", true).expect("address"),
            email: "anna@example.com".into(),
            name: "Anna".into(),
            user_id: "u1".into(),
            jar,
            session: None,
        }
    }

    fn signed_in() -> Jar {
        serde_json::from_str(r#"{"cookies":{"better-auth.session_token":"SECRET"}}"#).expect("jar")
    }

    #[test]
    fn the_session_is_stored_encrypted_in_the_file() {
        let key = [5u8; 32];
        let on_disk = seal_sessions(&[account(signed_in())], Some(&key)).expect("encrypted");
        let json = serde_json::to_string(&on_disk).expect("json");
        assert!(!json.contains("SECRET"), "{json}");

        let mut read: Vec<Account> = serde_json::from_str(&json).expect("reads");
        assert!(!open_sessions(&mut read, Some(&key)));
        assert!(read[0].signed_in());
        assert!(read[0].session.is_none());
    }

    /// Without a key the session does not go to disk at all — better to sign
    /// in again than a cookie in plaintext.
    #[test]
    fn without_a_key_the_session_is_not_written() {
        let on_disk = seal_sessions(&[account(signed_in())], None).expect("writes");
        let json = serde_json::to_string(&on_disk).expect("json");
        assert!(!json.contains("SECRET"), "{json}");
    }

    /// Loaded while locked: the ciphertext stays and is written back as it
    /// was.
    #[test]
    fn a_sealed_session_is_kept() {
        let key = [5u8; 32];
        let on_disk = seal_sessions(&[account(signed_in())], Some(&key)).expect("encrypted");
        let mut locked = on_disk.clone();
        open_sessions(&mut locked, None);
        assert!(!locked[0].signed_in());
        let again = seal_sessions(&locked, None).expect("writes");
        assert_eq!(again[0].session, on_disk[0].session);
    }

    #[test]
    fn an_old_plaintext_session_is_detected() {
        let mut old = vec![account(signed_in())];
        assert!(open_sessions(&mut old, Some(&[5u8; 32])));
    }
}
