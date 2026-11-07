//! Access to Bitwarden and Vaultwarden.
//!
//! Unlike 1Password there is no sidecar here: Bitwarden's official SDKs only
//! cover the *Secrets Manager* — a different product that Vaultwarden does not
//! know at all. There is none for the password vault. So this module speaks
//! the HTTP API directly and decrypts by itself; the crypto is in [`crypto`],
//! the endpoints in [`api`].
//!
//! That also drops the prerequisite 1Password brings along: nothing has to be
//! installed and nothing has to be enabled. What is needed is the server's
//! address, the sign-in address and the master password.
//!
//! **What sits in memory.** After unlocking, this module holds the access
//! tokens, the user key, the account's private key and the organizations'
//! keys — and a snapshot of the vault from which *all values are deliberately
//! removed*: only titles, field names and field lengths remain, exactly as
//! with the 1Password sidecar. A secret is read individually when a connection
//! needs it, and not kept.
//!
//! None of it is on disk. Restarting the app means: unlock again. The same
//! after [`IDLE_LOCK`] without access.

pub mod api;
pub mod crypto;

use std::collections::HashMap;
use std::fs;
use std::time::{Duration, Instant};

use rust_i18n::t;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tauri::AppHandle;
use tokio::sync::Mutex;

use crate::vault::{Field, Item, Vault};
use api::{Endpoints, Login, Session, TwoFactor};
use crypto::{MasterKey, SymmetricKey};

/// No account set up in the workspace. The UI asks for one instead of showing
/// this text.
pub const NO_ACCOUNT: &str = "bw:no-account";

/// The vault is closed — never unlocked, or unused since [`IDLE_LOCK`].
/// The UI asks for the master password.
pub const LOCKED: &str = "bw:locked";

/// The server wants a second factor. Which one follows the colon.
pub const TWO_FACTOR: &str = "bw:two-factor";

/// The server rejected the access token. Internal to the module: the caller
/// renews it or locks the vault.
pub(crate) const EXPIRED: &str = "bw:expired";

/// How long the vault stays open without access.
///
/// The same reasoning as with 1Password, which lets its authorization expire
/// after ten minutes: a vault that stays open until the app quits is an open
/// vault on an unattended computer.
const IDLE_LOCK: Duration = Duration::from_secs(15 * 60);

/// How long the vault snapshot is valid before it is synced again. It only
/// feeds the picker in the form; a secret is fetched individually and fresh
/// anyway.
const SNAPSHOT_TTL: Duration = Duration::from_secs(5 * 60);

/// Which vault in the picker is the personal one. An organization has a UUID,
/// the own vault has none — so it gets this name.
const PERSONAL: &str = "personal";

/// A workspace's Bitwarden account.
///
/// Per workspace and not per device, for the same reason as the 1Password
/// account: which credentials a collection of connections is read with belongs
/// to the connections.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Account {
    /// The address of the own instance. Empty means Bitwarden itself; see
    /// [`Endpoints::resolve`].
    #[serde(default)]
    pub server: String,
    #[serde(default)]
    pub email: String,
    /// For a self-signed certificate in front of the own Vaultwarden
    /// instance — the same trade-off as with FTPS and S3, see [`crate::tls`].
    #[serde(default)]
    pub accept_invalid_cert: bool,
}

impl Account {
    pub fn is_empty(&self) -> bool {
        self.email.trim().is_empty()
    }
}

/// The keys that unlock everything else after unlocking.
struct Keys {
    user: SymmetricKey,
    /// The account's private RSA key. Missing only for an account without a
    /// key pair, which no longer happens for newly created ones.
    private: Option<rsa::RsaPrivateKey>,
    /// One key per organization, unwrapped with the private one.
    orgs: HashMap<String, SymmetricKey>,
}

impl Keys {
    /// The key an entry is encrypted with: the organization's, or the own one.
    fn for_cipher(&self, organization_id: Option<&str>) -> Result<&SymmetricKey, String> {
        match organization_id {
            None => Ok(&self.user),
            Some(id) => self
                .orgs
                .get(id)
                .ok_or_else(|| t!("vault.bw_org_key_missing", id = id).into_owned()),
        }
    }
}

/// An entry in the picker.
///
/// `raw` is the entry as the server sent it — that is, encrypted. Only the
/// title is decrypted from it, because without it nobody can pick anything;
/// the fields only once this one entry has been clicked, and a field's value
/// never. Unlike 1Password, which hands out an entry individually, Bitwarden's
/// sync delivers the whole vault at once — if everything were decrypted here
/// wholesale, every password of the account would sit in memory.
struct ItemMeta {
    vault_id: String,
    id: String,
    title: String,
    category: String,
    raw: Value,
}

/// The snapshot that feeds the picker in the form.
struct Snapshot {
    vaults: Vec<Vault>,
    items: Vec<ItemMeta>,
    taken: Instant,
}

#[derive(Default)]
struct Inner {
    /// What the open workspace names. Empty until one with an account is open.
    account: Account,
    /// Resolved from [`Account::server`], so that does not happen again in
    /// every call.
    endpoints: Option<Endpoints>,
    /// Built for the account configuration — the certificate question is part
    /// of it.
    http: Option<reqwest::Client>,
    session: Option<Session>,
    keys: Option<Keys>,
    snapshot: Option<Snapshot>,
    /// The method the server asked for on the last attempt. Kept here so the
    /// second attempt files the code correctly right away.
    two_factor: Option<u32>,
    /// When something was last read, for [`IDLE_LOCK`].
    last_use: Option<Instant>,
}

impl Inner {
    /// Throws away everything that hangs on the master password. The account
    /// details stay — they are not a secret and are in the workspace anyway.
    fn lock(&mut self) {
        self.session = None;
        self.keys = None;
        self.snapshot = None;
        self.last_use = None;
    }
}

/// Holds account, session and keys of the open workspace.
#[derive(Default)]
pub struct BwState(Mutex<Inner>);

/// Tells the backend which Bitwarden account applies. A different account
/// locks the vault: the keys in memory belong to the previous one.
pub async fn set_account(state: &BwState, account: Account) {
    let mut inner = state.0.lock().await;
    if inner.account == account {
        return;
    }
    inner.lock();
    inner.endpoints = None;
    inner.http = None;
    inner.two_factor = None;
    inner.account = account;
}

/// Unlocks the vault with the master password.
///
/// `code` is the second factor, if one is already at hand. If the server asks
/// for one and none is there, the call ends with [`TWO_FACTOR`] — and for a
/// code by email, that one is then already on its way.
#[tauri::command]
pub async fn bw_unlock(
    app: AppHandle,
    state: tauri::State<'_, BwState>,
    password: String,
    code: String,
) -> Result<(), String> {
    let mut inner = state.0.lock().await;
    if inner.account.is_empty() {
        return Err(NO_ACCOUNT.to_string());
    }

    let account = inner.account.clone();
    let endpoints = endpoints(&mut inner)?;
    let http = http(&mut inner)?;

    let kdf = api::prelogin(&http, &endpoints, &account.email).await?;
    let master = MasterKey::derive(&password, &account.email, kdf)?;
    let hash = master.password_hash(&password);
    let device = device_id(&app)?;
    let code = code.trim().to_string();

    // At most two rounds: the first may end with "which method?", and if the
    // code is already at hand, the second is the answer to that.
    let mut provider = inner.two_factor;
    let mut session = None;
    for _ in 0..2 {
        let second = match (provider, code.is_empty()) {
            (Some(p), false) => Some((p, code.as_str())),
            _ => None,
        };
        match api::login(&http, &endpoints, &account.email, &hash, &device, second).await? {
            Login::Done(ready) => {
                session = Some(ready);
                break;
            }
            Login::TwoFactor(offered) => {
                let chosen = TwoFactor::choose(&offered)
                    .ok_or_else(|| t!("vault.bw_two_factor_needs_browser").into_owned())?;
                inner.two_factor = Some(chosen);
                if code.is_empty() {
                    if chosen == TwoFactor::EMAIL {
                        api::send_email_code(&http, &endpoints, &account.email, &hash, &device)
                            .await?;
                    }
                    return Err(format!("{TWO_FACTOR}:{}", TwoFactor::label(chosen)));
                }
                // The code was already there, only the method was still unknown.
                provider = Some(chosen);
            }
        }
    }
    let session = session.ok_or_else(|| t!("vault.bw_two_factor_rejected").into_owned())?;

    // Only here, once everything has held: a failed attempt must not leave a
    // half session behind.
    let profile = api::sync(&http, &endpoints, &session.access).await?;
    let mut keys = unwrap_keys(&profile, &master)?;
    update_org_keys(&mut keys, &profile);
    inner.snapshot = Some(snapshot(&profile, &keys)?);
    inner.keys = Some(keys);
    inner.session = Some(session);
    inner.two_factor = None;
    inner.last_use = Some(Instant::now());
    Ok(())
}

/// Locks the vault by hand. Whatever comes next asks for the master password
/// again.
#[tauri::command]
pub async fn bw_lock(state: tauri::State<'_, BwState>) -> Result<(), String> {
    state.0.lock().await.lock();
    Ok(())
}

/// Whether the vault is currently unlocked — for the display in the workspace
/// dialog.
#[tauri::command]
pub async fn bw_unlocked(state: tauri::State<'_, BwState>) -> Result<bool, String> {
    let inner = state.0.lock().await;
    Ok(inner.keys.is_some() && !idle(&inner))
}

/// The vaults: the own one and one per organization.
pub async fn vaults(state: &BwState) -> Result<Vec<Vault>, String> {
    let mut inner = state.0.lock().await;
    ensure(&mut inner).await?;
    refresh_snapshot(&mut inner).await?;
    Ok(inner
        .snapshot
        .as_ref()
        .map(|s| s.vaults.clone())
        .unwrap_or_default())
}

pub async fn items(state: &BwState, vault_id: &str) -> Result<Vec<Item>, String> {
    let mut inner = state.0.lock().await;
    ensure(&mut inner).await?;
    refresh_snapshot(&mut inner).await?;
    Ok(inner
        .snapshot
        .as_ref()
        .map(|s| {
            s.items
                .iter()
                .filter(|item| item.vault_id == vault_id)
                .map(|item| Item {
                    id: item.id.clone(),
                    title: item.title.clone(),
                    category: item.category.clone(),
                })
                .collect()
        })
        .unwrap_or_default())
}

pub async fn fields(state: &BwState, vault_id: &str, item_id: &str) -> Result<Vec<Field>, String> {
    let mut inner = state.0.lock().await;
    ensure(&mut inner).await?;
    refresh_snapshot(&mut inner).await?;

    let item = inner
        .snapshot
        .as_ref()
        .and_then(|s| {
            s.items
                .iter()
                .find(|item| item.id == item_id && item.vault_id == vault_id)
        })
        .ok_or_else(|| t!("vault.bw_entry_gone").into_owned())?;
    let keys = inner.keys.as_ref().ok_or_else(|| LOCKED.to_string())?;
    let key = keys.for_cipher(Some(item.vault_id.as_str()).filter(|id| *id != PERSONAL))?;
    Ok(field_list(&item.raw, key))
}

/// Resolves `bw://<vault>/<item>/<field>`.
///
/// The entry is fetched individually and fresh for that, not read from the
/// snapshot: there are no values in it, and that is on purpose.
pub async fn resolve(state: &BwState, reference: &str) -> Result<String, String> {
    let (_, item_id, field_id) = parse_reference(reference)?;

    let mut inner = state.0.lock().await;
    ensure(&mut inner).await?;

    let endpoints = endpoints(&mut inner)?;
    let http = http(&mut inner)?;
    let access = inner
        .session
        .as_ref()
        .map(|s| s.access.clone())
        .ok_or_else(|| LOCKED.to_string())?;

    let cipher = match api::cipher(&http, &endpoints, &access, &item_id).await {
        Ok(cipher) => cipher,
        Err(e) if e == EXPIRED => {
            inner.lock();
            return Err(LOCKED.to_string());
        }
        Err(e) => return Err(e),
    };

    let organization = cipher
        .get("organizationId")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty());
    let keys = inner.keys.as_ref().ok_or_else(|| LOCKED.to_string())?;
    let key = keys.for_cipher(organization)?;
    field_value(&cipher, key, &field_id)
}

// ---- Session ----------------------------------------------------------------

fn idle(inner: &Inner) -> bool {
    inner.last_use.is_none_or(|last| last.elapsed() > IDLE_LOCK)
}

/// Makes sure a usable session is in place, or says what is missing.
async fn ensure(inner: &mut Inner) -> Result<(), String> {
    if inner.account.is_empty() {
        return Err(NO_ACCOUNT.to_string());
    }
    if inner.keys.is_none() {
        return Err(LOCKED.to_string());
    }
    if idle(inner) {
        inner.lock();
        return Err(LOCKED.to_string());
    }

    // An expired access token does not cost a new password prompt: that is
    // what the refresh token is for. Only when that no longer works either is
    // the vault closed again — the keys in memory are useless without a server.
    let stale = inner.session.as_ref().is_none_or(Session::expired);
    if stale {
        let token = inner
            .session
            .as_ref()
            .map(|s| s.refresh.clone())
            .unwrap_or_default();
        if token.is_empty() {
            inner.lock();
            return Err(LOCKED.to_string());
        }
        let endpoints = endpoints(inner)?;
        let http = http(inner)?;
        match api::refresh(&http, &endpoints, &token).await {
            Ok(session) => inner.session = Some(session),
            Err(_) => {
                inner.lock();
                return Err(LOCKED.to_string());
            }
        }
    }

    inner.last_use = Some(Instant::now());
    Ok(())
}

fn endpoints(inner: &mut Inner) -> Result<Endpoints, String> {
    if inner.endpoints.is_none() {
        inner.endpoints = Some(Endpoints::resolve(&inner.account.server)?);
    }
    Ok(inner.endpoints.clone().expect("just ensured"))
}

fn http(inner: &mut Inner) -> Result<reqwest::Client, String> {
    if inner.http.is_none() {
        let client = reqwest::Client::builder()
            // As with S3: the configuration is passed on as `Any` and
            // recognised by downcast, so exactly this type and not inside an
            // `Arc`.
            .tls_backend_preconfigured(crate::tls::config(inner.account.accept_invalid_cert)?)
            .connect_timeout(Duration::from_secs(15))
            .build()
            .map_err(|e| t!("vault.bw_http_client_failed", error = e).into_owned())?;
        inner.http = Some(client);
    }
    Ok(inner.http.clone().expect("just ensured"))
}

/// Syncs when the snapshot is too old. The snapshot is only there for the
/// picker.
async fn refresh_snapshot(inner: &mut Inner) -> Result<(), String> {
    let fresh = inner
        .snapshot
        .as_ref()
        .is_some_and(|s| s.taken.elapsed() < SNAPSHOT_TTL);
    if fresh {
        return Ok(());
    }

    let endpoints = endpoints(inner)?;
    let http = http(inner)?;
    let access = inner
        .session
        .as_ref()
        .map(|s| s.access.clone())
        .ok_or_else(|| LOCKED.to_string())?;

    let profile = match api::sync(&http, &endpoints, &access).await {
        Ok(profile) => profile,
        Err(e) if e == EXPIRED => {
            inner.lock();
            return Err(LOCKED.to_string());
        }
        Err(e) => return Err(e),
    };

    let keys = inner.keys.as_mut().ok_or_else(|| LOCKED.to_string())?;
    update_org_keys(keys, &profile);
    let built = snapshot(&profile, keys)?;
    inner.snapshot = Some(built);
    Ok(())
}

// ---- Keys and snapshot ------------------------------------------------------

/// Unwraps the key chain from the sync response: user key, private key,
/// organization keys.
fn unwrap_keys(profile: &Value, master: &MasterKey) -> Result<Keys, String> {
    let profile = profile
        .get("profile")
        .ok_or_else(|| t!("vault.bw_no_profile").into_owned())?;

    let wrapped = profile
        .get("key")
        .and_then(Value::as_str)
        .ok_or_else(|| t!("vault.bw_no_vault_key").into_owned())?;
    let user =
        SymmetricKey::from_bytes(&crypto::EncString::parse(wrapped)?.decrypt(&master.stretched())?)
            .map_err(|e| t!("vault.bw_wrong_master_password", error = e).into_owned())?;

    let private = match profile.get("privateKey").and_then(Value::as_str) {
        Some(wrapped) if !wrapped.is_empty() => {
            let der = crypto::EncString::parse(wrapped)?.decrypt(&user)?;
            Some(crypto::private_key(&der)?)
        }
        _ => None,
    };

    Ok(Keys {
        user,
        private,
        orgs: HashMap::new(),
    })
}

/// Unwraps the keys of the organizations the account belongs to.
///
/// On every sync and not only when unlocking: whoever is added to an
/// organization during a running session should see its entries without
/// restarting the app.
fn update_org_keys(keys: &mut Keys, profile: &Value) {
    let Some(private) = keys.private.as_ref() else {
        return;
    };
    for organization in profile
        .get("profile")
        .and_then(|p| p.get("organizations"))
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default()
    {
        let (Some(id), Some(wrapped)) = (
            organization.get("id").and_then(Value::as_str),
            organization.get("key").and_then(Value::as_str),
        ) else {
            continue;
        };
        if keys.orgs.contains_key(id) {
            continue;
        }
        // An organization whose key cannot be unwrapped is no reason to refuse
        // the whole vault — its entries are then simply missing from the
        // picker.
        if let Ok(bytes) = crypto::EncString::parse(wrapped).and_then(|e| e.decrypt_rsa(private)) {
            if let Ok(key) = SymmetricKey::from_bytes(&bytes) {
                keys.orgs.insert(id.to_string(), key);
            }
        }
    }
}

/// Builds the picker list from the sync response — **without values**.
fn snapshot(profile: &Value, keys: &Keys) -> Result<Snapshot, String> {
    let mut items = Vec::new();

    for cipher in profile
        .get("ciphers")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default()
    {
        // In the trash, so of no use for a connection.
        if !matches!(cipher.get("deletedDate"), None | Some(Value::Null)) {
            continue;
        }
        let Some(id) = cipher.get("id").and_then(Value::as_str) else {
            continue;
        };
        let organization = cipher
            .get("organizationId")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty());
        let Ok(key) = keys.for_cipher(organization) else {
            continue;
        };

        items.push(ItemMeta {
            vault_id: organization.unwrap_or(PERSONAL).to_string(),
            id: id.to_string(),
            title: crypto::decrypt_optional(cipher.get("name").and_then(Value::as_str), key),
            category: category(cipher).to_string(),
            raw: cipher.clone(),
        });
    }

    let mut vaults = vec![Vault {
        id: PERSONAL.to_string(),
        title: t!("vault.bw_my_vault").into_owned(),
        item_count: items.iter().filter(|i| i.vault_id == PERSONAL).count() as u32,
    }];
    for organization in profile
        .get("profile")
        .and_then(|p| p.get("organizations"))
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default()
    {
        let Some(id) = organization.get("id").and_then(Value::as_str) else {
            continue;
        };
        // An organization whose key is missing does not belong in the list:
        // its entries cannot be read here.
        if !keys.orgs.contains_key(id) {
            continue;
        }
        vaults.push(Vault {
            id: id.to_string(),
            title: organization
                .get("name")
                .and_then(Value::as_str)
                .map(str::to_string)
                .unwrap_or_else(|| t!("vault.bw_organization").into_owned()),
            item_count: items.iter().filter(|i| i.vault_id == id).count() as u32,
        });
    }

    Ok(Snapshot {
        vaults,
        items,
        taken: Instant::now(),
    })
}

/// Bitwarden's entry types, named the way 1Password names them.
///
/// Not for convenience: the picker in the form puts SSH keys at the top and
/// preselects the matching field. That both providers use the same names is
/// exactly what lets this one piece of logic apply to both.
fn category(cipher: &Value) -> &'static str {
    match cipher.get("type").and_then(Value::as_u64).unwrap_or(0) {
        1 => "Login",
        2 => "SecureNote",
        3 => "Card",
        4 => "Identity",
        5 => "SshKey",
        _ => "Item",
    }
}

/// Which fields an entry has, with length instead of value.
///
/// The field ids are the one place where Bitwarden and 1Password really
/// differ: 1Password assigns a UUID to every field, in Bitwarden the built-in
/// fields have fixed names and the custom ones only their title. Hence
/// `password` instead of a UUID — and hence `custom.<name>`, with everything
/// that comes with it: if a custom field is renamed, the reference points
/// nowhere, and two fields of the same name cannot be told apart. There is
/// nothing more stable in Bitwarden to point at.
fn field_list(cipher: &Value, key: &SymmetricKey) -> Vec<Field> {
    let mut fields = Vec::new();
    let mut add = |id: &str, title: &str, field_type: &str, value: Option<&str>| {
        let Some(value) = value.filter(|v| !v.is_empty()) else {
            return;
        };
        fields.push(Field {
            id: id.to_string(),
            title: title.to_string(),
            field_type: field_type.to_string(),
            value_length: crypto::decrypt_str(value, key)
                .map(|v| v.chars().count() as u32)
                .unwrap_or(0),
        });
    };

    let string = |parent: Option<&Value>, name: &str| -> Option<String> {
        parent?
            .get(name)
            .and_then(Value::as_str)
            .map(str::to_string)
    };

    let login = cipher.get("login");
    add(
        "username",
        &*t!("vault.bw_field_username"),
        "String",
        string(login, "username").as_deref(),
    );
    add(
        "password",
        &*t!("vault.bw_field_password"),
        "Concealed",
        string(login, "password").as_deref(),
    );

    let ssh = cipher.get("sshKey");
    add(
        "sshKey.privateKey",
        &*t!("vault.bw_field_private_key"),
        "SshKey",
        string(ssh, "privateKey").as_deref(),
    );
    add(
        "sshKey.publicKey",
        &*t!("vault.bw_field_public_key"),
        "String",
        string(ssh, "publicKey").as_deref(),
    );

    add(
        "notes",
        &*t!("vault.bw_field_notes"),
        "String",
        cipher.get("notes").and_then(Value::as_str),
    );

    for custom in cipher
        .get("fields")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default()
    {
        // Type 3 is a "linked field": it points at another field and has no
        // value of its own.
        let kind = custom.get("type").and_then(Value::as_u64).unwrap_or(0);
        if kind == 3 {
            continue;
        }
        let name = crypto::decrypt_optional(custom.get("name").and_then(Value::as_str), key);
        if name.is_empty() {
            continue;
        }
        add(
            &format!("custom.{}", encode_name(&name)),
            &name,
            match kind {
                1 => "Concealed",
                2 => "Boolean",
                _ => "String",
            },
            custom.get("value").and_then(Value::as_str),
        );
    }

    fields
}

// ---- References -------------------------------------------------------------

/// Splits `bw://<vault>/<item>/<field>`.
///
/// The vault is part of it even though the entry is enough to resolve it: a
/// reference should say readably where it points, and the shape mirrors
/// 1Password's so both can stand side by side in the same field.
fn parse_reference(reference: &str) -> Result<(String, String, String), String> {
    let rest = reference
        .trim()
        .strip_prefix("bw://")
        .ok_or_else(|| t!("vault.bw_not_a_reference", reference = reference).into_owned())?;
    let mut parts = rest.splitn(3, '/');
    let (Some(vault), Some(item), Some(field)) = (parts.next(), parts.next(), parts.next()) else {
        return Err(t!("vault.bw_reference_incomplete", reference = reference).into_owned());
    };
    if item.is_empty() || field.is_empty() {
        return Err(t!("vault.bw_reference_incomplete", reference = reference).into_owned());
    }
    Ok((vault.to_string(), item.to_string(), field.to_string()))
}

/// Gets a value from an entry. The ids are the ones from [`field_list`].
fn field_value(cipher: &Value, key: &SymmetricKey, field_id: &str) -> Result<String, String> {
    let at = |path: &[&str]| -> Option<String> {
        let mut node = cipher;
        for step in path {
            node = node.get(step)?;
        }
        node.as_str().filter(|v| !v.is_empty()).map(str::to_string)
    };

    let raw = match field_id {
        "username" => at(&["login", "username"]),
        "password" => at(&["login", "password"]),
        "totp" => at(&["login", "totp"]),
        "notes" => at(&["notes"]),
        "sshKey.privateKey" => at(&["sshKey", "privateKey"]),
        "sshKey.publicKey" => at(&["sshKey", "publicKey"]),
        other => {
            let wanted = other
                .strip_prefix("custom.")
                .map(decode_name)
                .ok_or_else(|| t!("vault.bw_unknown_field", field = other).into_owned())?;
            cipher
                .get("fields")
                .and_then(Value::as_array)
                .map(Vec::as_slice)
                .unwrap_or_default()
                .iter()
                .find(|field| {
                    crypto::decrypt_optional(field.get("name").and_then(Value::as_str), key)
                        == wanted
                })
                .and_then(|field| field.get("value"))
                .and_then(Value::as_str)
                .filter(|v| !v.is_empty())
                .map(str::to_string)
        }
    };

    let raw =
        raw.ok_or_else(|| t!("vault.bw_entry_has_no_field", field = field_id).into_owned())?;
    crypto::decrypt_str(&raw, key)
}

/// Percent-encoding for a field name in a reference: the name may contain
/// spaces and slashes, the reference may not.
fn encode_name(name: &str) -> String {
    use percent_encoding::{utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
    const SET: &AsciiSet = &NON_ALPHANUMERIC
        .remove(b'-')
        .remove(b'_')
        .remove(b'.')
        .remove(b'~');
    utf8_percent_encode(name, SET).to_string()
}

fn decode_name(encoded: &str) -> String {
    percent_encoding::percent_decode_str(encoded)
        .decode_utf8_lossy()
        .into_owned()
}

// ---- Device id --------------------------------------------------------------

const DEVICE_FILE: &str = "bitwarden-device";

/// The id under which WireTerm appears in the account's device list.
///
/// It is kept because Bitwarden sends a warning mail for every *new* device: a
/// freshly rolled id per start would mean one mail per start. It is not a
/// secret — it only names, it authorizes nothing.
fn device_id(app: &AppHandle) -> Result<String, String> {
    let dir = crate::paths::app_data_dir(app)?;
    let path = dir.join(DEVICE_FILE);

    if let Ok(existing) = fs::read_to_string(&path) {
        let existing = existing.trim().to_string();
        if !existing.is_empty() {
            return Ok(existing);
        }
    }

    let id = new_uuid()?;
    fs::create_dir_all(&dir)
        .map_err(|e| t!("vault.bw_create_dir_failed", path = dir : {:?}, error = e).into_owned())?;
    fs::write(&path, &id)
        .map_err(|e| t!("vault.bw_write_failed", path = path : {:?}, error = e).into_owned())?;
    Ok(id)
}

/// A version 4 UUID. No crate of its own for it: ring is in the tree anyway
/// and supplies the random bytes, the rest is two bit fields set.
fn new_uuid() -> Result<String, String> {
    use ring::rand::{SecureRandom, SystemRandom};

    let mut bytes = [0u8; 16];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| t!("vault.bw_no_randomness").into_owned())?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;

    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ---- References ------------------------------------------------------------

    #[test]
    fn a_reference_names_vault_entry_and_field() {
        let (vault, item, field) =
            parse_reference("bw://personal/2f1c/password").expect("should parse");
        assert_eq!(vault, PERSONAL);
        assert_eq!(item, "2f1c");
        assert_eq!(field, "password");
    }

    #[test]
    fn a_field_may_carry_a_dot_because_the_built_in_ones_do() {
        let (_, _, field) =
            parse_reference("bw://personal/2f1c/sshKey.privateKey").expect("should parse");
        assert_eq!(field, "sshKey.privateKey");
    }

    #[test]
    fn a_reference_for_the_other_manager_is_refused_here() {
        assert!(parse_reference("op://vault/item/field").is_err());
    }

    #[test]
    fn an_incomplete_reference_says_what_it_should_look_like() {
        for reference in ["bw://personal/2f1c", "bw://personal/2f1c/", "bw://"] {
            let message = parse_reference(reference).expect_err("should be refused");
            assert!(message.contains("bw://vault/item/field"), "{message}");
        }
    }

    // ---- Field names -----------------------------------------------------------

    #[test]
    fn a_custom_field_name_survives_the_slashes_a_reference_is_split_on() {
        for name in ["API-Token", "path/to/thing", "with spaces", "résumé"] {
            assert_eq!(decode_name(&encode_name(name)), name);
            assert!(!encode_name(name).contains('/'));
        }
    }

    // ---- Entry types -----------------------------------------------------------

    #[test]
    fn entry_types_are_reported_under_the_names_the_picker_sorts_by() {
        assert_eq!(category(&json!({ "type": 1 })), "Login");
        assert_eq!(category(&json!({ "type": 5 })), "SshKey");
        // Something Bitwarden only invents later must not swallow the entry —
        // it just gets no place of its own in the sort order.
        assert_eq!(category(&json!({ "type": 99 })), "Item");
    }
}
