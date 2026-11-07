//! The secrets of local storage — encrypted with a device key.
//!
//! `workspaces.json` contains entered keys, passwords and secret access keys,
//! `cloud-accounts.json` the session with the backend. Neither is on disk in
//! plain text any more, but as `wtenc:v1:…`, encrypted with
//! XChaCha20-Poly1305 under **one** device key.
//!
//! The device key itself is in the system keyring
//! ([`store::SystemKeyring`]). One entry instead of one per secret: the
//! Windows Credential Manager holds at most 2560 bytes, and an RSA-4096 key is
//! larger. Where there is no keyring — Linux without Secret Service, i.e.
//! servers, WSL, lightweight window managers — the device key is instead
//! stored in `local-key.json`, wrapped with an **app password**, and asked for
//! at startup.
//!
//! `local-key.json` exists in both cases. It says where the key is, and so
//! prevents a keyring that does not answer *once* from silently leading to a
//! new key — and with that to secrets nobody can open any more.
//!
//! What this protects: the file in a backup, in a synced folder, in the hands
//! of another user. What it does not: malware running as the same user — it
//! asks the keyring just as WireTerm does.

pub mod store;

use std::sync::Mutex;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use rust_i18n::t;
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager, State};
use zeroize::Zeroizing;

use crate::cloud::crypto::{self, KdfParams};
use store::{DeviceKey, Lookup, SystemKeyring};

/// What marks an encrypted field. Anything without it is plain text from a
/// version before this encryption.
const PREFIX: &str = "wtenc:v1:";
const MARKER_FILE: &str = "local-key.json";
/// Binds the wrapped device key to this purpose.
const WRAP_AAD: &[u8] = b"wireterm/device-key/v1";

// ---- Fields ------------------------------------------------------------------

pub fn is_sealed(value: &str) -> bool {
    value.starts_with(PREFIX)
}

/// `aad` binds the ciphertext to its place — a connection and a field. A
/// ciphertext someone copies into another connection does not open there.
pub fn seal_text(key: &[u8; 32], aad: &str, plaintext: &str) -> Result<String, String> {
    let nonce = crypto::new_nonce()?;
    let mut sealed = nonce.clone();
    sealed.extend(crypto::seal(
        key,
        &nonce,
        plaintext.as_bytes(),
        aad.as_bytes(),
    )?);
    Ok(format!("{PREFIX}{}", BASE64.encode(sealed)))
}

pub fn open_text(key: &[u8; 32], aad: &str, stored: &str) -> Result<String, String> {
    let raw = stored
        .strip_prefix(PREFIX)
        .ok_or_else(|| t!("secrets.not_sealed").into_owned())?;
    let bytes = BASE64
        .decode(raw)
        .map_err(|_| t!("secrets.sealed_field_damaged").into_owned())?;
    if bytes.len() < 24 {
        return Err(t!("secrets.sealed_field_damaged").into_owned());
    }
    let (nonce, ciphertext) = bytes.split_at(24);
    let plain = crypto::open(key, nonce, ciphertext, aad.as_bytes())?;
    String::from_utf8(plain).map_err(|_| t!("secrets.field_not_text").into_owned())
}

pub fn connection_aad(connection_id: &str, field: &str) -> String {
    format!("wireterm/connection/{connection_id}/{field}")
}

pub fn account_aad(account_id: &str) -> String {
    format!("wireterm/account/{account_id}/session")
}

// ---- local-key.json ------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(tag = "store", rename_all = "camelCase")]
enum Marker {
    /// The key is in the system keyring.
    Keyring,
    /// The key is here, wrapped with the app password.
    #[serde(rename_all = "camelCase")]
    Password {
        kdf_params: KdfParams,
        /// base64.
        salt: String,
        /// base64.
        nonce: String,
        /// base64.
        wrapped: String,
    },
}

fn wrap_with_password(key: &[u8; 32], password: &str) -> Result<Marker, String> {
    let params = KdfParams::default();
    let salt = crypto::new_salt()?;
    let nonce = crypto::new_nonce()?;
    let derived = crypto::derive_key(password.as_bytes(), &salt, params)?;
    let wrapped = crypto::seal(&derived, &nonce, key, WRAP_AAD)?;
    Ok(Marker::Password {
        kdf_params: params,
        salt: BASE64.encode(salt),
        nonce: BASE64.encode(nonce),
        wrapped: BASE64.encode(wrapped),
    })
}

fn unwrap_with_password(marker: &Marker, password: &str) -> Result<DeviceKey, String> {
    let Marker::Password {
        kdf_params,
        salt,
        nonce,
        wrapped,
    } = marker
    else {
        return Err(t!("secrets.not_password_wrapped").into_owned());
    };
    let decode = |value: &str| {
        BASE64
            .decode(value)
            .map_err(|_| t!("secrets.marker_damaged", file = MARKER_FILE).into_owned())
    };
    let derived = crypto::derive_key(password.as_bytes(), &decode(salt)?, *kdf_params)?;
    let key = crypto::open(&derived, &decode(nonce)?, &decode(wrapped)?, WRAP_AAD)
        .map_err(|_| t!("secrets.wrong_app_password").into_owned())?;
    let key = Zeroizing::new(key);
    <[u8; 32]>::try_from(key.as_slice())
        .map(Zeroizing::new)
        .map_err(|_| t!("secrets.marker_damaged", file = MARKER_FILE).into_owned())
}

fn marker_path(app: &AppHandle) -> Result<std::path::PathBuf, String> {
    Ok(crate::paths::app_data_dir(app)?.join(MARKER_FILE))
}

fn read_marker(app: &AppHandle) -> Result<Option<Marker>, String> {
    let path = marker_path(app)?;
    if !path.is_file() {
        return Ok(None);
    }
    let raw = std::fs::read_to_string(&path).map_err(|e| format!("{path:?}: {e}"))?;
    serde_json::from_str(&raw).map(Some).map_err(|e| {
        t!(
            "secrets.marker_damaged_detail",
            file = MARKER_FILE,
            error = e
        )
        .into_owned()
    })
}

fn write_marker(app: &AppHandle, marker: &Marker) -> Result<(), String> {
    let path = marker_path(app)?;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("{dir:?}: {e}"))?;
    }
    let json = serde_json::to_string_pretty(marker).map_err(|e| e.to_string())?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, json).map_err(|e| format!("{tmp:?}: {e}"))?;
    std::fs::rename(&tmp, &path).map_err(|e| format!("{path:?}: {e}"))
}

/// `de.example.wireterm`, with `-dev` in a development build — otherwise both
/// would share the key, but not the files encrypted with it.
fn service_name(app: &AppHandle) -> String {
    let id = app.config().identifier.clone();
    if cfg!(debug_assertions) {
        format!("{id}-dev")
    } else {
        id
    }
}

// ---- The state -----------------------------------------------------------------

enum Vault {
    Ready {
        key: DeviceKey,
        keyring: bool,
    },
    /// `local-key.json` says app password, and it has not been entered yet.
    Locked,
    /// No key anywhere yet, and no keyring that would take one.
    NeedsSetup(String),
    /// `local-key.json` says keyring, but it does not answer. No new key — the
    /// old one just cannot be reached right now.
    Unavailable(String),
}

/// How the system keyring leads to the state — without Tauri, so it can be
/// tested without a window.
///
/// `save` puts a new key into the keyring and `mark` writes `local-key.json`;
/// both only when a new one is really needed.
fn resolve(
    marker: Option<&Marker>,
    lookup: impl FnOnce() -> Lookup,
    save: impl FnOnce(&[u8; 32]) -> Result<(), String>,
    mark: impl FnOnce() -> Result<(), String>,
) -> Result<Vault, String> {
    match marker {
        Some(Marker::Password { .. }) => Ok(Vault::Locked),
        Some(Marker::Keyring) => match lookup() {
            Lookup::Found(key) => Ok(Vault::Ready { key, keyring: true }),
            // The entry is gone — deleted, or the files have moved to another
            // computer. Whatever was encrypted with it can no longer be read;
            // newly entered data should be readable again, though.
            Lookup::Missing => {
                let key = crypto::new_project_key()?;
                match save(&key) {
                    Ok(()) => Ok(Vault::Ready { key, keyring: true }),
                    Err(reason) => Ok(Vault::Unavailable(reason)),
                }
            }
            Lookup::Unavailable(reason) => Ok(Vault::Unavailable(reason)),
        },
        None => match lookup() {
            Lookup::Found(key) => {
                mark()?;
                Ok(Vault::Ready { key, keyring: true })
            }
            Lookup::Missing => {
                let key = crypto::new_project_key()?;
                match save(&key) {
                    Ok(()) => {
                        mark()?;
                        Ok(Vault::Ready { key, keyring: true })
                    }
                    Err(reason) => Ok(Vault::NeedsSetup(reason)),
                }
            }
            Lookup::Unavailable(reason) => Ok(Vault::NeedsSetup(reason)),
        },
    }
}

/// `None` means: not looked up yet. It is looked up on first need, not at
/// startup — on macOS that is a prompt from the system, and it should only
/// come once the window is up.
#[derive(Default)]
pub struct LocalVault(Mutex<Option<Vault>>);

/// What the UI needs to know about the device key.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultStatus {
    /// `ready`, `locked`, `setup` or `unavailable`.
    state: &'static str,
    /// Whether the key is in the keyring (otherwise under the app password).
    keyring: bool,
    /// Why there is no keyring, in its own words.
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
}

impl LocalVault {
    fn ensure(&self, app: &AppHandle) -> Result<std::sync::MutexGuard<'_, Option<Vault>>, String> {
        let mut guard = self
            .0
            .lock()
            .map_err(|_| "local vault poisoned".to_string())?;
        if guard.is_none() {
            let keyring = SystemKeyring::new(&service_name(app));
            let marker = read_marker(app)?;
            let vault = resolve(
                marker.as_ref(),
                || keyring.load(),
                |key| keyring.save(key),
                || write_marker(app, &Marker::Keyring),
            )?;
            *guard = Some(vault);
        }
        Ok(guard)
    }

    /// The device key, if it is available right now.
    pub fn key(&self, app: &AppHandle) -> Option<DeviceKey> {
        let guard = self.ensure(app).ok()?;
        match guard.as_ref() {
            Some(Vault::Ready { key, .. }) => Some(key.clone()),
            _ => None,
        }
    }

    fn status(&self, app: &AppHandle) -> Result<VaultStatus, String> {
        let guard = self.ensure(app)?;
        Ok(match guard.as_ref() {
            Some(Vault::Ready { keyring, .. }) => VaultStatus {
                state: "ready",
                keyring: *keyring,
                reason: None,
            },
            Some(Vault::Locked) | None => VaultStatus {
                state: "locked",
                keyring: false,
                reason: None,
            },
            Some(Vault::NeedsSetup(reason)) => VaultStatus {
                state: "setup",
                keyring: false,
                reason: Some(reason.clone()),
            },
            Some(Vault::Unavailable(reason)) => VaultStatus {
                state: "unavailable",
                keyring: true,
                reason: Some(reason.clone()),
            },
        })
    }
}

/// After unlocking, the session with the backend has to be read again too —
/// until just now it was locked away in `cloud-accounts.json`.
async fn reopened(app: &AppHandle) {
    app.state::<crate::cloud::CloudState>()
        .forget_loaded()
        .await;
}

#[tauri::command]
pub fn local_vault_status(
    app: AppHandle,
    vault: State<'_, LocalVault>,
) -> Result<VaultStatus, String> {
    vault.status(&app)
}

/// After "keyring unreachable": look again.
#[tauri::command]
pub async fn local_vault_retry(
    app: AppHandle,
    vault: State<'_, LocalVault>,
) -> Result<VaultStatus, String> {
    if let Ok(mut guard) = vault.0.lock() {
        *guard = None;
    }
    let status = vault.status(&app)?;
    reopened(&app).await;
    Ok(status)
}

#[tauri::command]
pub async fn local_vault_unlock(
    app: AppHandle,
    vault: State<'_, LocalVault>,
    password: String,
) -> Result<(), String> {
    let password = Zeroizing::new(password);
    let marker = read_marker(&app)?.ok_or_else(|| t!("secrets.no_app_password").into_owned())?;
    // Argon2id with 64 MiB takes a while; not on the thread that serves the
    // UI.
    let key =
        tauri::async_runtime::spawn_blocking(move || unwrap_with_password(&marker, &password))
            .await
            .map_err(|e| e.to_string())??;
    {
        let mut guard = vault.0.lock().map_err(|_| "local vault poisoned")?;
        *guard = Some(Vault::Ready {
            key,
            keyring: false,
        });
    }
    reopened(&app).await;
    Ok(())
}

/// Without a keyring: create a device key and wrap it with the app password.
#[tauri::command]
pub async fn local_vault_setup(
    app: AppHandle,
    vault: State<'_, LocalVault>,
    password: String,
) -> Result<(), String> {
    if !matches!(vault.ensure(&app)?.as_ref(), Some(Vault::NeedsSetup(_))) {
        return Err(t!("secrets.already_set_up").into_owned());
    }
    let password = Zeroizing::new(password);
    let (key, marker) = tauri::async_runtime::spawn_blocking(move || {
        let key = crypto::new_project_key()?;
        let marker = wrap_with_password(&key, &password)?;
        Ok::<_, String>((key, marker))
    })
    .await
    .map_err(|e| e.to_string())??;
    write_marker(&app, &marker)?;
    {
        let mut guard = vault.0.lock().map_err(|_| "local vault poisoned")?;
        *guard = Some(Vault::Ready {
            key,
            keyring: false,
        });
    }
    reopened(&app).await;
    Ok(())
}

/// A new app password. The device key stays the same — only its wrapping in
/// `local-key.json` changes, and nothing else has to be re-encrypted.
#[tauri::command]
pub async fn local_vault_change_password(
    app: AppHandle,
    vault: State<'_, LocalVault>,
    old: String,
    new: String,
) -> Result<(), String> {
    let old = Zeroizing::new(old);
    let new = Zeroizing::new(new);
    if new.chars().count() < 8 {
        return Err(t!("secrets.new_app_password_too_short").into_owned());
    }
    let marker = read_marker(&app)?.ok_or_else(|| t!("secrets.no_app_password").into_owned())?;
    let (key, marker) = tauri::async_runtime::spawn_blocking(move || {
        let key = unwrap_with_password(&marker, &old)?;
        let marker = wrap_with_password(&key, &new)?;
        Ok::<_, String>((key, marker))
    })
    .await
    .map_err(|e| e.to_string())??;
    write_marker(&app, &marker)?;
    let mut guard = vault.0.lock().map_err(|_| "local vault poisoned")?;
    *guard = Some(Vault::Ready {
        key,
        keyring: false,
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    fn test_key() -> [u8; 32] {
        [7u8; 32]
    }

    #[test]
    fn a_field_goes_there_and_back() {
        let key = test_key();
        let aad = connection_aad("c1", "key");
        let sealed = seal_text(&key, &aad, "PRIVATE KEY").expect("encrypts");
        assert!(is_sealed(&sealed));
        assert!(!sealed.contains("PRIVATE"));
        assert_eq!(
            open_text(&key, &aad, &sealed).expect("decrypts"),
            "PRIVATE KEY"
        );
    }

    #[test]
    fn the_same_text_twice_gives_different_ciphertexts() {
        let key = test_key();
        let aad = connection_aad("c1", "key");
        let a = seal_text(&key, &aad, "x").expect("a");
        let b = seal_text(&key, &aad, "x").expect("b");
        assert_ne!(a, b, "every save takes a new nonce");
    }

    /// Copied into another connection, it does not open — and not with another
    /// key either.
    #[test]
    fn a_ciphertext_belongs_to_its_place() {
        let key = test_key();
        let sealed = seal_text(&key, &connection_aad("c1", "key"), "secret").expect("a");
        assert!(open_text(&key, &connection_aad("c2", "key"), &sealed).is_err());
        assert!(open_text(&key, &connection_aad("c1", "password"), &sealed).is_err());
        assert!(open_text(&[8u8; 32], &connection_aad("c1", "key"), &sealed).is_err());
    }

    #[test]
    fn the_app_password_wraps_and_unwraps_the_key() {
        let key = test_key();
        let marker = wrap_with_password(&key, "hunter2").expect("wraps");
        let json = serde_json::to_string(&marker).expect("serializes");
        assert!(json.contains("\"store\":\"password\""), "{json}");
        let back: Marker = serde_json::from_str(&json).expect("deserializes");
        assert_eq!(*unwrap_with_password(&back, "hunter2").expect("opens"), key);
        assert!(unwrap_with_password(&back, "wrong").is_err());
    }

    #[test]
    fn first_start_with_a_keyring_creates_a_key() {
        let saved = Cell::new(false);
        let marked = Cell::new(false);
        let vault = resolve(
            None,
            || Lookup::Missing,
            |_| {
                saved.set(true);
                Ok(())
            },
            || {
                marked.set(true);
                Ok(())
            },
        )
        .expect("resolves");
        assert!(matches!(vault, Vault::Ready { keyring: true, .. }));
        assert!(saved.get() && marked.get());
    }

    #[test]
    fn first_start_without_a_keyring_asks_for_an_app_password() {
        let vault = resolve(
            None,
            || Lookup::Unavailable("no Secret Service".into()),
            |_| panic!("without a keyring nothing is put into it"),
            || panic!("and nothing is marked"),
        )
        .expect("resolves");
        assert!(matches!(vault, Vault::NeedsSetup(reason) if reason.contains("Secret Service")));
    }

    /// The case `local-key.json` exists for in the first place: the keyring
    /// does not answer once. Then no new key — that would make everything
    /// encrypted unreadable.
    #[test]
    fn a_silent_keyring_does_not_lead_to_a_new_key() {
        let vault = resolve(
            Some(&Marker::Keyring),
            || Lookup::Unavailable("locked".into()),
            |_| panic!("no new key"),
            || panic!("no new marker"),
        )
        .expect("resolves");
        assert!(matches!(vault, Vault::Unavailable(_)));
    }

    /// A new app password changes the wrapping, not the key — everything
    /// encrypted with it stays readable, the old password opens nothing any
    /// more.
    #[test]
    fn a_new_app_password_keeps_the_key() {
        let key = test_key();
        let old = wrap_with_password(&key, "old password").expect("wraps");
        let opened = unwrap_with_password(&old, "old password").expect("opens");
        let new = wrap_with_password(&opened, "new password").expect("wraps again");
        assert_eq!(
            *unwrap_with_password(&new, "new password").expect("opens"),
            key
        );
        assert!(unwrap_with_password(&new, "old password").is_err());
    }

    #[test]
    fn with_an_app_password_it_starts_out_locked() {
        let marker = wrap_with_password(&test_key(), "pw").expect("wraps");
        let vault = resolve(
            Some(&marker),
            || panic!("the keyring is not even asked"),
            |_| panic!("nothing"),
            || panic!("nothing"),
        )
        .expect("resolves");
        assert!(matches!(vault, Vault::Locked));
    }
}
