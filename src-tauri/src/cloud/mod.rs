//! Workspaces that do not live on this disk.
//!
//! "Cloud" and "own backend" are the same thing: the same protocol, the same
//! encryption, the same sync. The only difference is where the address comes
//! from — the cloud brings its own, for an own backend someone types it in.
//! That is why there are not two ways here, but one with one field more.
//!
//! ## What lives where
//!
//! | where                     | what                                              |
//! | ------------------------- | ------------------------------------------------- |
//! | `cloud-accounts.json`     | address, email, session                           |
//! | `cloud/<org>.json`        | the copy of the workspace, secrets as ciphertext  |
//! | only in memory            | the private key and every project key             |
//!
//! The third row is the one that matters. The master password goes nowhere,
//! and what is derived from it survives neither a restart nor a quarter of an
//! hour of inactivity.
//!
//! ## The path through the modules
//!
//! ```text
//! storage::workspaces_save  ──▶ diff::plan  ──▶ cache::Pending  ──▶ sync::flush
//!                                    │                                   │
//!                              crypto::seal                          api::put_*
//!
//! storage::workspaces_load  ◀── cache::tree ◀── cache::apply  ◀── sync::run
//!                                    │
//!                              crypto::open
//! ```

pub mod account;
pub mod api;
pub mod cache;
pub mod crypto;
pub mod diff;
pub mod http;
pub mod idle;
#[cfg(test)]
mod live;
pub mod model;
pub mod org;
pub mod rotate;
pub mod sync;
#[cfg(test)]
pub(crate) mod test_server;
pub mod wirecloud;

use std::collections::HashMap;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use rust_i18n::t;
use serde::Serialize;
use tauri::{AppHandle, Manager, State};
use tokio::sync::Mutex;
use zeroize::Zeroizing;

use account::{Account, AccountView, Unlocked};
use api::{KeyMaterial, RecoveryRow, WrappedKey};
use cache::Cached;
use crypto::KdfParams;
use http::{Api, ApiError, Jar, Server};
use model::{Role, ShareRole, WorkspaceKind};

use crate::local_secrets::LocalVault;
use crate::storage::{Remote, StorageKind, Workspace};

/// How many recovery codes are generated.
///
/// Eight is the recommendation from `CLIENT.md`: enough to have one on paper,
/// one in the safe and a few in reserve, few enough that someone actually
/// copies them down.
const RECOVERY_CODES: usize = 8;

#[derive(Default)]
pub struct CloudState(Mutex<Inner>);

#[derive(Default)]
struct Inner {
    loaded: bool,
    accounts: Vec<Account>,
    caches: Vec<Cached>,
    /// Open vaults, one per account. Only here — never in a file.
    vaults: HashMap<String, Unlocked>,
    /// Sign-ins through WireCloud that wait for the password of the existing
    /// account (linking). Only in memory and only briefly.
    pending_wirecloud: HashMap<String, PendingWirecloud>,
}

/// A WireCloud sign-in for which the local account already exists and the
/// person still has to prove that it is theirs.
struct PendingWirecloud {
    server: Server,
    jar: Jar,
    email: String,
    since: std::time::Instant,
}

/// How long such a sign-in lasts until the person enters the password.
const PENDING_LIFETIME: std::time::Duration = std::time::Duration::from_secs(15 * 60);

impl Inner {
    fn account(&self, id: &str) -> Result<&Account, String> {
        self.accounts
            .iter()
            .find(|account| account.id == id)
            .ok_or_else(|| t!("cloud.account_gone").to_string())
    }

    fn account_mut(&mut self, id: &str) -> Result<&mut Account, String> {
        self.accounts
            .iter_mut()
            .find(|account| account.id == id)
            .ok_or_else(|| t!("cloud.account_gone").to_string())
    }

    fn cached(&self, workspace: &str) -> Result<&Cached, String> {
        self.caches
            .iter()
            .find(|cached| cached.id == workspace)
            .ok_or_else(|| t!("cloud.workspace_missing").to_string())
    }

    /// Takes expired vaults out of memory.
    ///
    /// On every access, not on a timer: a timer that fires exactly when nobody
    /// is looking adds concurrency and closes no gap — as long as nobody
    /// accesses it, the key just lies there anyway.
    fn sweep(&mut self) {
        self.vaults.retain(|_, vault| !vault.expired());
    }

    fn unlocked(&mut self, account_id: &str) -> Option<&Unlocked> {
        self.sweep();
        let vault = self.vaults.get_mut(account_id)?;
        vault.touch();
        Some(&*vault)
    }
}

// ---- Loading and storing -----------------------------------------------------

fn load(app: &AppHandle, inner: &mut Inner) -> Result<(), String> {
    if inner.loaded {
        return Ok(());
    }
    inner.accounts = account::read_json(&account::accounts_path(app)?)?.unwrap_or_default();
    let key = app.state::<LocalVault>().key(app);
    let plaintext = account::open_sessions(&mut inner.accounts, key.as_deref());
    // A plaintext session from an earlier version: write it encrypted right
    // away, not only at the next sign-in.
    if plaintext && key.is_some() {
        store_accounts(app, inner)?;
    }

    inner.caches.clear();
    let dir = account::cache_dir(app)?;
    if dir.is_dir() {
        let entries = std::fs::read_dir(&dir).map_err(|e| format!("{dir:?}: {e}"))?;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            // A damaged copy is no reason not to show all other workspaces —
            // the next sync fetches it anew.
            if let Ok(Some(cached)) = account::read_json::<Cached>(&path) {
                inner.caches.push(cached);
            }
        }
    }
    inner
        .caches
        .sort_by_key(|cached| cached.name.to_lowercase());
    inner.loaded = true;
    Ok(())
}

fn store_accounts(app: &AppHandle, inner: &Inner) -> Result<(), String> {
    let key = app.state::<LocalVault>().key(app);
    let on_disk = account::seal_sessions(&inner.accounts, key.as_deref())?;
    account::write_json(&account::accounts_path(app)?, &on_disk)
}

fn store_cache(app: &AppHandle, cached: &Cached) -> Result<(), String> {
    account::write_json(&account::cache_path(app, &cached.id)?, cached)
}

// ---- What the tree gets from here --------------------------------------------

impl CloudState {
    /// Reads accounts and copies anew on the next access — after unlocking the
    /// device key, so that the sessions open.
    pub async fn forget_loaded(&self) {
        self.0.lock().await.loaded = false;
    }

    /// The remote workspaces, ready for the tree.
    ///
    /// From the copy, not over the wire: the sync runs alongside and reports
    /// when it has something new. Without network the same tree comes out —
    /// only with `offline` in [`Remote`].
    pub async fn workspaces(&self, app: &AppHandle) -> Result<Vec<Workspace>, String> {
        let mut inner = self.0.lock().await;
        load(app, &mut inner)?;
        inner.sweep();

        let Inner {
            accounts,
            caches,
            vaults,
            ..
        } = &mut *inner;

        Ok(caches
            .iter()
            .map(|cached| {
                let account = accounts.iter().find(|a| a.id == cached.account_id);
                let private = vaults.get(&cached.account_id).map(|vault| &*vault.private);
                let (projects, missing) = cached.tree(private);

                Workspace {
                    id: cached.id.clone(),
                    name: cached.name.clone(),
                    // The only difference between the two: the address.
                    storage: match account.map(|a| a.server.is_cloud()) {
                        Some(true) => StorageKind::Cloud,
                        _ => StorageKind::CustomBackend,
                    },
                    one_password_account: cached.one_password_account(),
                    bitwarden: cached.bitwarden_account(),
                    remote: Some(Remote {
                        account_id: cached.account_id.clone(),
                        server: account.map(|a| a.server.label()).unwrap_or_default(),
                        email: account.map(|a| a.email.clone()).unwrap_or_default(),
                        kind: cached.kind,
                        role: cached.role,
                        admin: cached.role.is_admin(),
                        member_projects: cached.member_projects,
                        can_create_projects: cached.role.is_admin() || cached.member_projects,
                        own_projects: account
                            .map(|a| cached.own_projects(&a.user_id))
                            .unwrap_or_default(),
                        locked: private.is_none(),
                        secrets_missing: missing,
                        pending: cached.pending.len(),
                        revision: cached.revision.clone(),
                        error: cached.last_error.clone(),
                        conflicts: cached.conflicts.clone(),
                    }),
                    projects,
                    snippets: cached.snippet_list(),
                }
            })
            .collect())
    }

    /// Takes what the UI has changed.
    ///
    /// The copy is written first, then the queue is processed. The other way
    /// round, a crash between the two would lose the change, although it is
    /// already on the screen.
    pub async fn save(&self, app: &AppHandle, incoming: Vec<Workspace>) -> Result<(), String> {
        let mut inner = self.0.lock().await;
        load(app, &mut inner)?;
        inner.sweep();

        let mut touched = Vec::new();
        let mut trouble: Option<String> = None;

        for workspace in incoming {
            let Some(index) = inner.caches.iter().position(|c| c.id == workspace.id) else {
                continue;
            };
            let account_id = inner.caches[index].account_id.clone();
            let user_id = inner
                .accounts
                .iter()
                .find(|a| a.id == account_id)
                .map(|a| a.user_id.clone())
                .unwrap_or_default();

            let mut cached = inner.caches[index].clone();
            let unlocked = inner.vaults.get(&account_id);

            match diff::plan(&mut cached, &workspace, &user_id, unlocked) {
                Ok(ops) if ops.is_empty() => continue,
                Ok(ops) => {
                    cached.enqueue(ops);
                    store_cache(app, &cached)?;
                    inner.caches[index] = cached;
                    touched.push(workspace.id.clone());
                }
                Err(error) => trouble = Some(error),
            }
        }

        for id in touched {
            sync_one(app, &mut inner, &id).await;
        }

        match trouble {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

/// One run for a workspace, with everything around it: look up the account,
/// sync, store copy and session again.
async fn sync_one(app: &AppHandle, inner: &mut Inner, workspace_id: &str) {
    let Some(index) = inner.caches.iter().position(|c| c.id == workspace_id) else {
        return;
    };
    let account_id = inner.caches[index].account_id.clone();
    let Some(position) = inner.accounts.iter().position(|a| a.id == account_id) else {
        return;
    };

    let Ok(client) = inner.accounts[position].api() else {
        return;
    };
    let mut jar = inner.accounts[position].jar.clone();
    let user_id = inner.accounts[position].user_id.clone();
    let mut cached = inner.caches[index].clone();

    // The vault is copied, not borrowed: the sync runs across `await`, and
    // `inner` would otherwise stay borrowed for the whole duration.
    let unlocked = inner
        .vaults
        .get(&account_id)
        .map(|vault| Unlocked::new(Zeroizing::new(*vault.private), vault.public));

    let outcome = sync::run(&client, &mut jar, &mut cached, unlocked.as_ref(), &user_id).await;

    // What the team has already confirmed is not asked again here.
    sync::write_known_hosts(app, &cached);

    if outcome.signed_out {
        jar.clear();
    }
    inner.accounts[position].jar = jar;
    let _ = store_accounts(app, inner);

    let _ = store_cache(app, &cached);
    if let Some(slot) = inner.caches.iter_mut().find(|c| c.id == workspace_id) {
        *slot = cached;
    }
}

// ---- Accounts ----------------------------------------------------------------

fn view(account: &Account, unlocked: bool) -> AccountView {
    AccountView {
        id: account.id.clone(),
        server: account.server.label(),
        url: account.server.url.clone(),
        email: account.email.clone(),
        name: account.name.clone(),
        user_id: account.user_id.clone(),
        signed_in: account.signed_in(),
        managed_by: account.jar.wirecloud().map(|wc| wc.url().to_string()),
        has_keys: None,
        unlocked,
    }
}

/// Checks for every account whether the stored session is still valid.
///
/// Once at startup. A session the server no longer knows would otherwise only
/// show up at the first sync — and then as an error bar above a workspace
/// instead of as a request to sign in.
#[tauri::command]
pub async fn cloud_check_sessions(
    app: AppHandle,
    state: State<'_, CloudState>,
) -> Result<Vec<AccountView>, String> {
    let mut inner = state.0.lock().await;
    load(&app, &mut inner)?;

    let accounts: Vec<Account> = inner.accounts.clone();
    for account in accounts {
        if !account.signed_in() {
            continue;
        }
        let Ok(client) = account.api() else { continue };
        let mut jar = account.jar.clone();

        match api::session(&client, &mut jar).await {
            // Expired or revoked: empty the jar, so that the UI asks for a
            // sign-in instead of for the reason.
            Ok(None) => jar.clear(),
            Ok(Some(user)) => {
                if let Ok(slot) = inner.account_mut(&account.id) {
                    slot.name = user.name;
                    slot.user_id = user.id;
                }
            }
            // No network: the session is valid until the opposite is certain.
            Err(_) => continue,
        }
        if let Ok(slot) = inner.account_mut(&account.id) {
            slot.jar = jar;
        }
    }

    store_accounts(&app, &inner)?;
    inner.sweep();
    let open: Vec<String> = inner.vaults.keys().cloned().collect();
    Ok(inner
        .accounts
        .iter()
        .map(|account| view(account, open.contains(&account.id)))
        .collect())
}

#[tauri::command]
pub async fn cloud_accounts(
    app: AppHandle,
    state: State<'_, CloudState>,
) -> Result<Vec<AccountView>, String> {
    let mut inner = state.0.lock().await;
    load(&app, &mut inner)?;
    inner.sweep();
    let open: Vec<String> = inner.vaults.keys().cloned().collect();
    Ok(inner
        .accounts
        .iter()
        .map(|account| view(account, open.contains(&account.id)))
        .collect())
}

/// The profile image of an account signed in through WireCloud as a data URL.
/// `None` means: no image, no WireCloud account or currently unreachable; the
/// UI then shows the initials.
#[tauri::command]
pub async fn cloud_account_image(
    state: State<'_, CloudState>,
    account_id: String,
) -> Result<Option<String>, String> {
    let wc = {
        let inner = state.0.lock().await;
        inner.account(&account_id)?.jar.wirecloud().cloned()
    };
    let Some(wc) = wc else {
        return Ok(None);
    };
    Ok(wc.profile_image().await.unwrap_or(None))
}

/// The pictures of the WireCloud companies behind this account's workspaces,
/// by workspace (organization) ID. Without WireCloud, a picture or network an
/// entry is missing and the sidebar keeps the initials — as with the profile
/// image.
#[tauri::command]
pub async fn cloud_workspace_images(
    state: State<'_, CloudState>,
    account_id: String,
) -> Result<HashMap<String, String>, String> {
    let account = {
        let inner = state.0.lock().await;
        inner.account(&account_id)?.clone()
    };
    let Some(wc) = account.jar.wirecloud().cloned() else {
        return Ok(HashMap::new());
    };
    let client = account.api()?;
    let mut jar = account.jar.clone();
    let rows = api::workspaces(&client, &mut jar).await?;

    let mut images = HashMap::new();
    for row in rows {
        let Some(company) = row.wirecloud_company else {
            continue;
        };
        if let Ok(Some(image)) = wc.company_image(&company).await {
            images.insert(row.id, image);
        }
    }
    Ok(images)
}

/// The address of the cloud — so that it is written in only one place.
#[tauri::command]
pub fn cloud_url() -> &'static str {
    http::CLOUD_URL
}

// ---- Signing in through WireCloud ----------------------------------------------

/// What a backend in WireCloud mode says about itself.
#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct WireCloudInfo {
    /// Where WireCloud is reachable for clients.
    pub wirecloud_url: String,
    pub audience: String,
}

/// Asks a backend whether it runs in WireCloud mode. `None` means: no, or it
/// does not answer — then the previous way with email and sign-in password
/// applies. The UI asks before it asks for credentials.
#[tauri::command]
pub async fn cloud_wirecloud_detect(
    server: String,
    accept_invalid_cert: bool,
) -> Result<Option<WireCloudInfo>, String> {
    let server = Server::resolve(&server, accept_invalid_cert)?;
    Ok(wirecloud::discover(&server)
        .await
        .map(|found| WireCloudInfo {
            wirecloud_url: found.wirecloud_url,
            audience: found.audience,
        }))
}

/// How a sign-in through WireCloud turns out.
#[derive(Serialize, Clone, Debug)]
#[serde(
    tag = "status",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum WireCloudSignIn {
    SignedIn {
        account: AccountView,
    },
    /// For this address there already is an account here from the time before
    /// WireCloud. The person has to enter its **previous sign-in password**
    /// before both are linked (`cloud_wirecloud_link`). With `message` after a
    /// failed attempt: the password was wrong, another attempt is possible.
    NeedsLink {
        pending_id: String,
        email: String,
        message: Option<String>,
    },
}

/// Signs in to WireCloud through the system browser.
///
/// The browser part runs **without** the lock on the state: it takes as long
/// as the person needs, and meanwhile sync and UI should keep working.
#[tauri::command]
pub async fn cloud_wirecloud_sign_in(
    app: AppHandle,
    state: State<'_, CloudState>,
    server: String,
    accept_invalid_cert: bool,
) -> Result<WireCloudSignIn, String> {
    use tauri_plugin_opener::OpenerExt;

    let server = Server::resolve(&server, accept_invalid_cert)?;
    let discovery = wirecloud::discover(&server)
        .await
        .ok_or_else(|| t!("cloud.no_wirecloud").to_string())?;

    let cancel = wirecloud::begin();
    let wc = wirecloud::login(
        &discovery,
        accept_invalid_cert,
        |url| {
            app.opener()
                .open_url(url, None::<&str>)
                .map_err(|e| e.to_string())
        },
        &cancel,
    )
    .await
    .map_err(|e| e.to_string())?;

    finish_wirecloud(&app, &state, server, wc).await
}

/// After the code exchange: who is this in the backend, and is there an old
/// account that has to be linked first?
async fn finish_wirecloud(
    app: &AppHandle,
    state: &State<'_, CloudState>,
    server: Server,
    wc: wirecloud::Wc,
) -> Result<WireCloudSignIn, String> {
    let token = wc
        .tool_token(true)
        .await
        .map_err(|e| ApiError::from(e).to_string())?;
    let claims = wirecloud::claims_of(&token).unwrap_or_default();

    let mut jar = Jar::default();
    jar.set_wirecloud(wc.clone());
    let client = Api::new(&server)?;

    match api::own_user(&client, &mut jar).await {
        Ok(user) => {
            let mut inner = state.0.lock().await;
            load(app, &mut inner)?;
            complete_wirecloud(app, &mut inner, server, jar, user)
        }
        Err(ApiError::Api { ref code, .. }) if code == "WC-EC" => {
            let mut inner = state.0.lock().await;
            sweep_pending(&mut inner).await;
            let pending_id = uuid::Uuid::new_v4().to_string();
            inner.pending_wirecloud.insert(
                pending_id.clone(),
                PendingWirecloud {
                    server,
                    jar,
                    email: claims.email.clone(),
                    since: std::time::Instant::now(),
                },
            );
            Ok(WireCloudSignIn::NeedsLink {
                pending_id,
                email: claims.email,
                message: None,
            })
        }
        Err(error) => {
            // Not going on: sign the session out at WireCloud again instead of
            // leaving it lying around.
            wc.sign_out().await;
            Err(error.to_string())
        }
    }
}

fn complete_wirecloud(
    app: &AppHandle,
    inner: &mut Inner,
    server: Server,
    jar: Jar,
    user: api::User,
) -> Result<WireCloudSignIn, String> {
    if let Some(wc) = jar.wirecloud() {
        wc.set_user_id(&user.id);
    }
    let account = remember(app, inner, server, user, jar)?;
    Ok(WireCloudSignIn::SignedIn { account })
}

/// Throws away waiting sign-ins that have been lying around too long, and
/// signs them out at WireCloud.
async fn sweep_pending(inner: &mut Inner) {
    let expired: Vec<String> = inner
        .pending_wirecloud
        .iter()
        .filter(|(_, pending)| pending.since.elapsed() >= PENDING_LIFETIME)
        .map(|(id, _)| id.clone())
        .collect();
    for id in expired {
        if let Some(pending) = inner.pending_wirecloud.remove(&id) {
            if let Some(wc) = pending.jar.wirecloud() {
                wc.sign_out().await;
            }
        }
    }
}

/// Links the existing account to the WireCloud account after the person has
/// entered its previous sign-in password.
///
/// A wrong password allows another attempt (the backend counts and locks for
/// a quarter of an hour after five failed attempts), everything else ends the
/// sign-in.
#[tauri::command]
pub async fn cloud_wirecloud_link(
    app: AppHandle,
    state: State<'_, CloudState>,
    pending_id: String,
    password: String,
) -> Result<WireCloudSignIn, String> {
    let mut inner = state.0.lock().await;
    load(&app, &mut inner)?;
    sweep_pending(&mut inner).await;

    let mut pending = inner
        .pending_wirecloud
        .remove(&pending_id)
        .ok_or_else(|| t!("cloud.sign_in_expired").to_string())?;
    let client = Api::new(&pending.server)?;

    match api::link_wirecloud(&client, &mut pending.jar, &password).await {
        Ok(()) => {}
        // There is no old account any more that could be linked: then there is
        // nothing to link either, and the sign-in can simply go on.
        Err(ApiError::Api { ref code, .. }) if code == "WC-NN" => {}
        Err(error) => {
            let again = matches!(&error, ApiError::Api { code, .. } if code == "WC-LD");
            let message = error.to_string();
            if again {
                let email = pending.email.clone();
                inner.pending_wirecloud.insert(pending_id.clone(), pending);
                return Ok(WireCloudSignIn::NeedsLink {
                    pending_id,
                    email,
                    message: Some(message),
                });
            }
            if let Some(wc) = pending.jar.wirecloud() {
                wc.sign_out().await;
            }
            return Err(message);
        }
    }

    match api::own_user(&client, &mut pending.jar).await {
        Ok(user) => complete_wirecloud(&app, &mut inner, pending.server, pending.jar, user),
        Err(error) => {
            if let Some(wc) = pending.jar.wirecloud() {
                wc.sign_out().await;
            }
            Err(error.to_string())
        }
    }
}

/// Cancels a running sign-in: the wait for the browser and, if an ID is
/// given, also the one waiting for the password.
#[tauri::command]
pub async fn cloud_wirecloud_cancel(
    state: State<'_, CloudState>,
    pending_id: Option<String>,
) -> Result<(), String> {
    wirecloud::cancel();
    if let Some(id) = pending_id {
        let mut inner = state.0.lock().await;
        if let Some(pending) = inner.pending_wirecloud.remove(&id) {
            if let Some(wc) = pending.jar.wirecloud() {
                wc.sign_out().await;
            }
        }
    }
    Ok(())
}

/// Signs in — and creates the account if there is none yet for this address
/// and this email.
#[tauri::command]
pub async fn cloud_sign_in(
    app: AppHandle,
    state: State<'_, CloudState>,
    server: String,
    accept_invalid_cert: bool,
    email: String,
    password: String,
) -> Result<AccountView, String> {
    let server = Server::resolve(&server, accept_invalid_cert)?;
    let client = Api::new(&server)?;
    let mut jar = Jar::default();
    let user = api::sign_in(&client, &mut jar, email.trim(), &password).await?;
    // The language may have changed since the account was last used here.
    // Best effort: a backend without it (WireCloud mode) answers 404.
    let _ = api::set_locale(&client, &mut jar, &crate::locale::current()).await;

    let mut inner = state.0.lock().await;
    load(&app, &mut inner)?;
    remember(&app, &mut inner, server, user, jar)
}

/// Sends the UI language to every signed-in account after the user changed it.
///
/// Best effort: an account that is offline or on a backend without
/// `update-user` keeps its old language until the next sign-in.
#[tauri::command]
pub async fn cloud_push_locale(app: AppHandle, state: State<'_, CloudState>) -> Result<(), String> {
    let mut inner = state.0.lock().await;
    load(&app, &mut inner)?;
    let locale = crate::locale::current();
    let accounts: Vec<Account> = inner.accounts.clone();
    for account in accounts.into_iter().filter(|account| account.signed_in()) {
        let Ok(client) = account.api() else { continue };
        let mut jar = account.jar.clone();
        if api::set_locale(&client, &mut jar, &locale).await.is_ok() {
            if let Ok(slot) = inner.account_mut(&account.id) {
                slot.jar = jar;
            }
        }
    }
    store_accounts(&app, &inner)
}

#[tauri::command]
pub async fn cloud_sign_up(
    app: AppHandle,
    state: State<'_, CloudState>,
    server: String,
    accept_invalid_cert: bool,
    email: String,
    password: String,
    name: String,
) -> Result<AccountView, String> {
    let server = Server::resolve(&server, accept_invalid_cert)?;
    let client = Api::new(&server)?;
    let mut jar = Jar::default();
    let user = api::sign_up(&client, &mut jar, email.trim(), &password, name.trim()).await?;

    // Some setups do not sign in right after sign-up — for example when the
    // email has to be verified first.
    if jar.is_empty() {
        let _ = api::sign_in(&client, &mut jar, email.trim(), &password).await;
    }

    let mut inner = state.0.lock().await;
    load(&app, &mut inner)?;
    remember(&app, &mut inner, server, user, jar)
}

/// Records an account or refreshes the existing one.
///
/// The same address and the same email are the same account, even if it is
/// signed in once more through a second workspace — otherwise the same
/// credentials would be in the file twice and a sign-out would only work
/// halfway.
fn remember(
    app: &AppHandle,
    inner: &mut Inner,
    server: Server,
    user: api::User,
    jar: Jar,
) -> Result<AccountView, String> {
    let email = user.email.trim().to_lowercase();
    let existing = inner.accounts.iter().position(|account| {
        account.server.url == server.url && account.email.to_lowercase() == email
    });

    let id = match existing {
        Some(index) => {
            let account = &mut inner.accounts[index];
            account.server = server;
            account.name = user.name.clone();
            account.user_id = user.id.clone();
            account.jar = jar;
            account.id.clone()
        }
        None => {
            let id = uuid::Uuid::new_v4().to_string();
            inner.accounts.push(Account {
                id: id.clone(),
                server,
                email: user.email.clone(),
                name: user.name.clone(),
                user_id: user.id.clone(),
                jar,
                session: None,
            });
            id
        }
    };

    store_accounts(app, inner)?;
    let unlocked = inner.vaults.contains_key(&id);
    Ok(view(inner.account(&id)?, unlocked))
}

#[tauri::command]
pub async fn cloud_sign_out(
    app: AppHandle,
    state: State<'_, CloudState>,
    account_id: String,
) -> Result<(), String> {
    let mut inner = state.0.lock().await;
    load(&app, &mut inner)?;

    let account = inner.account(&account_id)?.clone();
    if let Ok(client) = account.api() {
        let mut jar = account.jar.clone();
        // Whether the server notices is secondary: here the session is thrown
        // away either way.
        let _ = api::sign_out(&client, &mut jar).await;
    }

    // And the vault along with it. Staying signed in and staying unlocked are
    // two things, but signed out and unlocked is neither.
    inner.vaults.remove(&account_id);
    if let Ok(account) = inner.account_mut(&account_id) {
        account.jar.clear();
    }
    store_accounts(&app, &inner)
}

/// Forgets an account together with all workspaces attached to it.
///
/// The copies go along: without the account they can neither be synced nor
/// opened, and leaving them would mean keeping ciphertexts nobody can get at
/// any more.
#[tauri::command]
pub async fn cloud_forget_account(
    app: AppHandle,
    state: State<'_, CloudState>,
    account_id: String,
) -> Result<(), String> {
    let mut inner = state.0.lock().await;
    load(&app, &mut inner)?;

    // Do not leave a session at WireCloud lying around.
    let wirecloud = inner
        .accounts
        .iter()
        .find(|account| account.id == account_id)
        .and_then(|account| account.jar.wirecloud().cloned());
    if let Some(wc) = wirecloud {
        wc.sign_out().await;
    }

    for cached in inner.caches.iter().filter(|c| c.account_id == account_id) {
        let _ = account::remove_file(&account::cache_path(&app, &cached.id)?);
    }
    inner
        .caches
        .retain(|cached| cached.account_id != account_id);
    inner.accounts.retain(|account| account.id != account_id);
    inner.vaults.remove(&account_id);
    store_accounts(&app, &inner)
}

/// Resets the **sign-in password**. The master password does not come back
/// this way — that is what the recovery codes are for.
#[tauri::command]
pub async fn cloud_request_password_reset(
    server: String,
    accept_invalid_cert: bool,
    email: String,
) -> Result<(), String> {
    let server = Server::resolve(&server, accept_invalid_cert)?;
    let client = Api::new(&server)?;
    let mut jar = Jar::default();
    api::request_password_reset(&client, &mut jar, email.trim())
        .await
        .map_err(String::from)
}

// ---- The key material --------------------------------------------------------

/// How far an account is set up.
#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct KeyStatus {
    /// Whether there is a key pair. `false` means: the setup is still ahead,
    /// and until then nobody can wrap anything for this user.
    pub has_keys: bool,
    pub unlocked: bool,
    pub recovery: Vec<RecoveryView>,
}

#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryView {
    pub id: String,
    /// The first group in plaintext — this is how the slip of paper is recognized.
    pub label: String,
    pub used_at: Option<String>,
}

#[tauri::command]
pub async fn cloud_key_status(
    app: AppHandle,
    state: State<'_, CloudState>,
    account_id: String,
) -> Result<KeyStatus, String> {
    let mut inner = state.0.lock().await;
    load(&app, &mut inner)?;
    inner.sweep();

    let account = inner.account(&account_id)?.clone();
    let client = account.api()?;
    let mut jar = account.jar.clone();
    let material = api::keys(&client, &mut jar).await?;
    persist_jar(&app, &mut inner, &account_id, jar)?;

    Ok(KeyStatus {
        has_keys: material.is_some(),
        unlocked: inner.vaults.contains_key(&account_id),
        recovery: material
            .map(|material| {
                material
                    .recovery_keys
                    .into_iter()
                    .map(|row| RecoveryView {
                        id: row.id,
                        label: row.label,
                        used_at: row.used_at,
                    })
                    .collect()
            })
            .unwrap_or_default(),
    })
}

/// Sets up the master password: create a key pair, wrap it, upload it — and
/// return the recovery codes, which are shown **once**.
///
/// Works exactly once per account. A second time would not be a fresh start
/// but a loss: every project key of this user is wrapped to the old public
/// key.
#[tauri::command]
pub async fn cloud_setup_master(
    app: AppHandle,
    state: State<'_, CloudState>,
    account_id: String,
    master_password: String,
) -> Result<Vec<String>, String> {
    if master_password.trim().is_empty() {
        return Err(t!("cloud.master_empty").to_string());
    }

    let mut inner = state.0.lock().await;
    load(&app, &mut inner)?;
    let account = inner.account(&account_id)?.clone();
    let client = account.api()?;
    let mut jar = account.jar.clone();

    let pair = crypto::new_key_pair()?;
    let master = wrap_private(&pair.private, master_password.as_bytes())?;
    let (codes, rows) = new_recovery_set(&pair.private)?;

    let result = api::create_keys(
        &client,
        &mut jar,
        crypto::KEY_ALGORITHM,
        &BASE64.encode(pair.public),
        &master,
        &rows,
    )
    .await;
    persist_jar(&app, &mut inner, &account_id, jar)?;

    match result {
        Ok(()) => {}
        Err(ApiError::Api { ref code, .. }) if code == "K-EX" => {
            return Err(t!("cloud.keys_exist").to_string())
        }
        Err(error) => return Err(error.into()),
    }

    inner
        .vaults
        .insert(account_id, Unlocked::new(pair.private, pair.public));
    Ok(codes)
}

#[tauri::command]
pub async fn cloud_unlock(
    app: AppHandle,
    state: State<'_, CloudState>,
    account_id: String,
    master_password: String,
) -> Result<(), String> {
    let mut inner = state.0.lock().await;
    load(&app, &mut inner)?;
    let account = inner.account(&account_id)?.clone();
    let client = account.api()?;
    let mut jar = account.jar.clone();

    let material = api::keys(&client, &mut jar).await?;
    persist_jar(&app, &mut inner, &account_id, jar)?;

    let material = material.ok_or_else(|| t!("cloud.no_master_yet").to_string())?;
    let private =
        open_private(&material.master, master_password.as_bytes()).map_err(|_| wrong_password())?;

    check_pair(&private, &material)?;
    let public = crypto::public_key_of(&private);
    inner
        .vaults
        .insert(account_id, Unlocked::new(private, public));
    Ok(())
}

/// A recovery code opens the same door as the master password — and that is
/// why redeeming it sets a new one right away **and creates a new set of
/// codes**: the old slip of paper would otherwise keep opening everything.
#[tauri::command]
pub async fn cloud_recover_master(
    app: AppHandle,
    state: State<'_, CloudState>,
    account_id: String,
    code: String,
    master_password: String,
) -> Result<Vec<String>, String> {
    if master_password.trim().is_empty() {
        return Err(t!("cloud.new_master_empty").to_string());
    }

    let mut inner = state.0.lock().await;
    load(&app, &mut inner)?;
    let account = inner.account(&account_id)?.clone();
    let client = account.api()?;
    let mut jar = account.jar.clone();

    let material = api::keys(&client, &mut jar).await?;
    let material = material.ok_or_else(|| t!("cloud.no_key_material").to_string())?;

    let normalized = crypto::normalize_recovery_code(&code);
    let label = crypto::recovery_label(&code);
    // The label finds the row, instead of trying eight Argon2id runs. If
    // several have the same label, they are simply tried in turn — 20 bits
    // collide rarely, but not never.
    let candidates: Vec<&RecoveryRow> = material
        .recovery_keys
        .iter()
        .filter(|row| row.label.eq_ignore_ascii_case(&label))
        .collect();
    if candidates.is_empty() {
        return Err(t!("cloud.recovery_code_unknown").to_string());
    }

    let mut opened = None;
    for row in &candidates {
        if let Ok(private) = open_private(&row.wrapped, normalized.as_bytes()) {
            opened = Some((row.id.clone(), private));
            break;
        }
    }
    let (row_id, private) = opened.ok_or_else(|| t!("cloud.recovery_code_wrong").to_string())?;
    check_pair(&private, &material)?;

    // Before rewrapping: `rewrap` replaces the whole set, afterwards the row
    // would no longer exist. Whether the note arrives is not critical — it is
    // for the UI, not for security.
    let _ = api::mark_recovery_used(&client, &mut jar, &row_id).await;

    let master = wrap_private(&private, master_password.as_bytes())?;
    let (codes, rows) = new_recovery_set(&private)?;
    let result = api::rewrap(&client, &mut jar, &master, Some(&rows)).await;
    persist_jar(&app, &mut inner, &account_id, jar)?;
    result?;

    let public = crypto::public_key_of(&private);
    inner
        .vaults
        .insert(account_id, Unlocked::new(private, public));
    Ok(codes)
}

/// The same `rewrap`, only that the private key comes from the old master
/// password instead of from a code. The key pair stays the same — that is
/// why all project keys stay valid.
#[tauri::command]
pub async fn cloud_change_master(
    app: AppHandle,
    state: State<'_, CloudState>,
    account_id: String,
    old_password: String,
    master_password: String,
) -> Result<Vec<String>, String> {
    if master_password.trim().is_empty() {
        return Err(t!("cloud.new_master_empty").to_string());
    }

    let mut inner = state.0.lock().await;
    load(&app, &mut inner)?;
    let account = inner.account(&account_id)?.clone();
    let client = account.api()?;
    let mut jar = account.jar.clone();

    let material = api::keys(&client, &mut jar).await?;
    let material = material.ok_or_else(|| t!("cloud.no_key_material").to_string())?;

    let private =
        open_private(&material.master, old_password.as_bytes()).map_err(|_| wrong_password())?;

    let master = wrap_private(&private, master_password.as_bytes())?;
    let (codes, rows) = new_recovery_set(&private)?;
    let result = api::rewrap(&client, &mut jar, &master, Some(&rows)).await;
    persist_jar(&app, &mut inner, &account_id, jar)?;
    result?;

    let public = crypto::public_key_of(&private);
    inner
        .vaults
        .insert(account_id, Unlocked::new(private, public));
    Ok(codes)
}

#[tauri::command]
pub async fn cloud_lock(state: State<'_, CloudState>, account_id: String) -> Result<(), String> {
    state.0.lock().await.vaults.remove(&account_id);
    Ok(())
}

/// Whether the vault is still open — and incidentally the place where the
/// lock actually snaps shut after a quarter of an hour.
#[tauri::command]
pub async fn cloud_unlocked(
    state: State<'_, CloudState>,
    account_id: String,
) -> Result<bool, String> {
    let mut inner = state.0.lock().await;
    Ok(inner.unlocked(&account_id).is_some())
}

fn wrong_password() -> String {
    // The server notices nothing of this and cannot check it either: it is
    // the decryption that fails.
    t!("cloud.master_wrong").to_string()
}

/// Checks that the unwrapped private key belongs to the stored public one.
///
/// The decryption alone does not say so: it says that the password fits
/// *this ciphertext*. If it belonged to another pair, everything would
/// seemingly be fine, and only the first secret would fail to open.
fn check_pair(private: &crypto::Secret32, material: &KeyMaterial) -> Result<(), String> {
    // The method is stored as text in the database so that it can be changed.
    // Until then, a different value is no reason to read it as X25519
    // anyway: that would yield a wrong public key, and the message would talk
    // about the password.
    if !material.algorithm.is_empty() && material.algorithm != crypto::KEY_ALGORITHM {
        return Err(t!("cloud.unknown_algorithm", algorithm = material.algorithm).to_string());
    }

    let expected = BASE64
        .decode(&material.public_key)
        .map_err(|_| t!("cloud.public_key_unreadable").to_string())?;
    if crypto::public_key_of(private).as_slice() != expected.as_slice() {
        return Err(t!("cloud.key_mismatch").to_string());
    }
    Ok(())
}

fn wrap_private(private: &crypto::Secret32, password: &[u8]) -> Result<WrappedKey, String> {
    let params = KdfParams::default();
    let salt = crypto::new_salt()?;
    let key = crypto::derive_key(password, &salt, params)?;
    let nonce = crypto::new_nonce()?;
    let sealed = crypto::seal(&key, &nonce, private.as_ref(), &[])?;

    Ok(WrappedKey {
        wrap_algorithm: crypto::WRAP_ALGORITHM.to_string(),
        nonce: BASE64.encode(&nonce),
        encrypted_private_key: BASE64.encode(&sealed),
        kdf: crypto::KDF.to_string(),
        kdf_salt: BASE64.encode(&salt),
        kdf_params: params.to_json(),
    })
}

/// The computation uses what is in the row — never a constant hard-wired
/// here. That is exactly why the parameters travel along.
fn open_private(wrapped: &WrappedKey, password: &[u8]) -> Result<crypto::Secret32, String> {
    let params = KdfParams::from_json(&wrapped.kdf_params)?;
    let salt = BASE64
        .decode(&wrapped.kdf_salt)
        .map_err(|_| t!("cloud.salt_unreadable").to_string())?;
    let nonce = BASE64
        .decode(&wrapped.nonce)
        .map_err(|_| t!("cloud.nonce_unreadable").to_string())?;
    let sealed = BASE64
        .decode(&wrapped.encrypted_private_key)
        .map_err(|_| t!("cloud.wrapped_key_unreadable").to_string())?;

    let key = crypto::derive_key(password, &salt, params)?;
    let opened = crypto::open(&key, &nonce, &sealed, &[])?;
    let bytes: [u8; 32] = opened
        .as_slice()
        .try_into()
        .map_err(|_| t!("cloud.private_key_length").to_string())?;
    Ok(Zeroizing::new(bytes))
}

/// Eight codes, each another wrapping of the same private key.
fn new_recovery_set(private: &crypto::Secret32) -> Result<(Vec<String>, Vec<RecoveryRow>), String> {
    let mut codes = Vec::with_capacity(RECOVERY_CODES);
    let mut rows = Vec::with_capacity(RECOVERY_CODES);

    for _ in 0..RECOVERY_CODES {
        let code = crypto::new_recovery_code()?;
        let normalized = crypto::normalize_recovery_code(&code);
        let wrapped = wrap_private(private, normalized.as_bytes())?;
        rows.push(RecoveryRow {
            id: String::new(),
            label: crypto::recovery_label(&code),
            wrapped,
            used_at: None,
        });
        codes.push(code);
    }
    Ok((codes, rows))
}

fn persist_jar(
    app: &AppHandle,
    inner: &mut Inner,
    account_id: &str,
    jar: Jar,
) -> Result<(), String> {
    if let Ok(account) = inner.account_mut(account_id) {
        account.jar = jar;
    }
    store_accounts(app, inner)
}

// ---- Workspaces --------------------------------------------------------------

/// An organization as it appears in the selection.
#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceOption {
    pub id: String,
    pub name: String,
    pub kind: WorkspaceKind,
    pub role: Role,
    /// Whether this workspace is already in the sidebar here.
    pub added: bool,
}

#[tauri::command]
pub async fn cloud_available_workspaces(
    app: AppHandle,
    state: State<'_, CloudState>,
    account_id: String,
) -> Result<Vec<WorkspaceOption>, String> {
    let mut inner = state.0.lock().await;
    load(&app, &mut inner)?;
    let account = inner.account(&account_id)?.clone();
    let client = account.api()?;
    let mut jar = account.jar.clone();

    let rows = api::workspaces(&client, &mut jar).await?;
    persist_jar(&app, &mut inner, &account_id, jar)?;

    Ok(rows
        .into_iter()
        .map(|row| WorkspaceOption {
            added: inner.caches.iter().any(|cached| cached.id == row.id),
            id: row.id,
            name: row.name,
            kind: row.kind,
            role: row.role,
        })
        .collect())
}

/// Adds an existing organization to the sidebar and fetches it once in
/// full.
#[tauri::command]
pub async fn cloud_add_workspace(
    app: AppHandle,
    state: State<'_, CloudState>,
    account_id: String,
    organization_id: String,
    name: String,
) -> Result<String, String> {
    let mut inner = state.0.lock().await;
    load(&app, &mut inner)?;
    inner.account(&account_id)?;

    if !inner
        .caches
        .iter()
        .any(|cached| cached.id == organization_id)
    {
        let cached = Cached::new(organization_id.clone(), account_id, name);
        store_cache(&app, &cached)?;
        inner.caches.push(cached);
    }

    sync_one(&app, &mut inner, &organization_id).await;
    Ok(organization_id)
}

/// Creates an organization and adds it right away.
#[tauri::command]
pub async fn cloud_create_workspace(
    app: AppHandle,
    state: State<'_, CloudState>,
    account_id: String,
    name: String,
) -> Result<String, String> {
    let mut inner = state.0.lock().await;
    load(&app, &mut inner)?;
    let account = inner.account(&account_id)?.clone();
    let client = account.api()?;
    let mut jar = account.jar.clone();

    let created = org::create(&client, &mut jar, name.trim()).await;
    persist_jar(&app, &mut inner, &account_id, jar)?;
    let created = created?;

    let cached = Cached::new(created.id.clone(), account_id, created.name.clone());
    store_cache(&app, &cached)?;
    inner.caches.push(cached);
    sync_one(&app, &mut inner, &created.id).await;
    Ok(created.id)
}

/// Deletes the organization on the server — or leaves it if one does not own
/// it.
///
/// The server refuses "Personal". That is not an error in the client, and the
/// message says so: otherwise someone would be left without any workspace
/// after one click.
#[tauri::command]
pub async fn cloud_delete_workspace(
    app: AppHandle,
    state: State<'_, CloudState>,
    workspace_id: String,
    leave_only: bool,
) -> Result<(), String> {
    let mut inner = state.0.lock().await;
    load(&app, &mut inner)?;
    let cached = inner.cached(&workspace_id)?.clone();
    let account = inner.account(&cached.account_id)?.clone();
    let client = account.api()?;
    let mut jar = account.jar.clone();

    let result = if leave_only {
        org::leave(&client, &mut jar, &workspace_id).await
    } else {
        org::delete(&client, &mut jar, &workspace_id).await
    };
    persist_jar(&app, &mut inner, &cached.account_id, jar)?;
    result?;

    account::remove_file(&account::cache_path(&app, &workspace_id)?)?;
    inner.caches.retain(|cached| cached.id != workspace_id);
    Ok(())
}

/// Removes a workspace from the sidebar only here, without touching it on
/// the server.
#[tauri::command]
pub async fn cloud_hide_workspace(
    app: AppHandle,
    state: State<'_, CloudState>,
    workspace_id: String,
) -> Result<(), String> {
    let mut inner = state.0.lock().await;
    load(&app, &mut inner)?;
    account::remove_file(&account::cache_path(&app, &workspace_id)?)?;
    inner.caches.retain(|cached| cached.id != workspace_id);
    Ok(())
}

/// Syncs — one workspace or all.
#[tauri::command]
pub async fn cloud_sync(
    app: AppHandle,
    state: State<'_, CloudState>,
    workspace_id: Option<String>,
) -> Result<(), String> {
    let mut inner = state.0.lock().await;
    load(&app, &mut inner)?;
    inner.sweep();

    let ids: Vec<String> = match workspace_id {
        Some(id) => vec![id],
        None => inner
            .caches
            .iter()
            .map(|cached| cached.id.clone())
            .collect(),
    };
    for id in ids {
        sync_one(&app, &mut inner, &id).await;
    }
    Ok(())
}

// ---- Members, teams, invitations ---------------------------------------------

/// Everything the management dialog needs, in one answer.
#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Members {
    pub organization: org::FullOrganization,
    /// Who has already set up a master password — whether anything can be
    /// wrapped for them at all depends on it.
    pub keys: Vec<model::MemberKey>,
    pub teams: Vec<org::TeamRow>,
    /// One's own role, so that the UI knows what it may offer.
    pub role: Role,
    pub kind: WorkspaceKind,
    pub own_user_id: String,
    /// The WireCloud address, if the account is signed in through it. Then
    /// members and roles come from the backend, the teams from the sync,
    /// there are no invitations here, and the UI only displays.
    pub managed_by: Option<String>,
}

#[tauri::command]
pub async fn cloud_members(
    app: AppHandle,
    state: State<'_, CloudState>,
    workspace_id: String,
) -> Result<Members, String> {
    let mut inner = state.0.lock().await;
    load(&app, &mut inner)?;
    let cached = inner.cached(&workspace_id)?.clone();
    let account = inner.account(&cached.account_id)?.clone();
    let client = account.api()?;
    let mut jar = account.jar.clone();

    let managed_by = jar.wirecloud().map(|wc| wc.url().to_string());

    // In WireCloud mode there is no `get-full-organization`. The members then
    // come from `member-keys` (the backend knows them itself), teams and
    // invitations are managed by WireCloud. The teams a project can be shared
    // with come along with the sync.
    let keys = api::member_keys(&client, &mut jar, &workspace_id).await;
    let (organization, teams) = if managed_by.is_some() {
        let keys = keys.clone().unwrap_or_default();
        let teams = cached
            .teams
            .iter()
            .map(|team| org::TeamRow {
                id: team.id.clone(),
                name: team.name.clone(),
                organization_id: workspace_id.clone(),
            })
            .collect();
        (
            Ok(organization_from_keys(&workspace_id, &cached.name, &keys)),
            Ok(teams),
        )
    } else {
        (
            org::full(&client, &mut jar, &workspace_id).await,
            org::teams(&client, &mut jar, &workspace_id).await,
        )
    };
    persist_jar(&app, &mut inner, &cached.account_id, jar)?;

    Ok(Members {
        organization: organization?,
        teams: teams.unwrap_or_default(),
        keys: keys.unwrap_or_default(),
        role: cached.role,
        kind: cached.kind,
        own_user_id: account.user_id,
        managed_by,
    })
}

/// Builds the member list from what the backend itself knows (`member-keys`)
/// where `get-full-organization` is missing. The backend does not know the
/// membership ID there; it is not needed anywhere in this mode, since roles
/// are changed by WireCloud.
fn organization_from_keys(
    workspace_id: &str,
    name: &str,
    keys: &[model::MemberKey],
) -> org::FullOrganization {
    org::FullOrganization {
        id: workspace_id.to_string(),
        name: name.to_string(),
        slug: String::new(),
        members: keys
            .iter()
            .map(|key| org::MemberRow {
                id: key.user_id.clone(),
                user_id: key.user_id.clone(),
                role: key.role.unwrap_or_default(),
                user: Some(org::MemberUser {
                    name: key.name.clone(),
                    email: key.email.clone(),
                }),
            })
            .collect(),
        invitations: Vec::new(),
        teams: Vec::new(),
    }
}

/// Runs a call against better-auth and stores the session again.
///
/// The pattern repeats for every management command; without this helper it
/// would be written out twelve times.
macro_rules! with_org {
    ($app:expr, $state:expr, $workspace:expr, |$client:ident, $jar:ident, $org:ident| $body:expr) => {{
        let mut inner = $state.0.lock().await;
        load(&$app, &mut inner)?;
        let cached = inner.cached(&$workspace)?.clone();
        let account = inner.account(&cached.account_id)?.clone();
        let $client = account.api()?;
        let mut $jar = account.jar.clone();
        let $org = $workspace.as_str();
        let result = $body.await;
        persist_jar(&$app, &mut inner, &cached.account_id, $jar)?;
        result.map_err(String::from)
    }};
}

#[tauri::command]
pub async fn cloud_invite(
    app: AppHandle,
    state: State<'_, CloudState>,
    workspace_id: String,
    email: String,
    role: Role,
    team_id: Option<String>,
) -> Result<org::InvitationRow, String> {
    with_org!(app, state, workspace_id, |client, jar, org| org::invite(
        &client,
        &mut jar,
        org,
        email.trim(),
        role,
        team_id.as_deref()
    ))
}

#[tauri::command]
pub async fn cloud_cancel_invitation(
    app: AppHandle,
    state: State<'_, CloudState>,
    workspace_id: String,
    invitation_id: String,
) -> Result<(), String> {
    with_org!(app, state, workspace_id, |client, jar, _org| {
        org::cancel_invitation(&client, &mut jar, &invitation_id)
    })
}

#[tauri::command]
pub async fn cloud_remove_member(
    app: AppHandle,
    state: State<'_, CloudState>,
    workspace_id: String,
    member: String,
) -> Result<(), String> {
    with_org!(app, state, workspace_id, |client, jar, org| {
        org::remove_member(&client, &mut jar, org, &member)
    })
}

#[tauri::command]
pub async fn cloud_set_member_role(
    app: AppHandle,
    state: State<'_, CloudState>,
    workspace_id: String,
    member_id: String,
    role: Role,
) -> Result<(), String> {
    with_org!(app, state, workspace_id, |client, jar, org| {
        org::set_role(&client, &mut jar, org, &member_id, role)
    })
}

#[tauri::command]
pub async fn cloud_create_team(
    app: AppHandle,
    state: State<'_, CloudState>,
    workspace_id: String,
    name: String,
) -> Result<org::TeamRow, String> {
    with_org!(app, state, workspace_id, |client, jar, org| {
        org::create_team(&client, &mut jar, org, name.trim())
    })
}

#[tauri::command]
pub async fn cloud_rename_team(
    app: AppHandle,
    state: State<'_, CloudState>,
    workspace_id: String,
    team_id: String,
    name: String,
) -> Result<(), String> {
    with_org!(app, state, workspace_id, |client, jar, _org| {
        org::rename_team(&client, &mut jar, &team_id, name.trim())
    })
}

#[tauri::command]
pub async fn cloud_remove_team(
    app: AppHandle,
    state: State<'_, CloudState>,
    workspace_id: String,
    team_id: String,
) -> Result<(), String> {
    with_org!(app, state, workspace_id, |client, jar, org| {
        org::remove_team(&client, &mut jar, org, &team_id)
    })
}

#[tauri::command]
pub async fn cloud_team_members(
    app: AppHandle,
    state: State<'_, CloudState>,
    workspace_id: String,
    team_id: String,
) -> Result<Vec<org::MemberRow>, String> {
    with_org!(app, state, workspace_id, |client, jar, _org| {
        org::team_members(&client, &mut jar, &team_id)
    })
}

#[tauri::command]
pub async fn cloud_add_team_member(
    app: AppHandle,
    state: State<'_, CloudState>,
    workspace_id: String,
    team_id: String,
    user_id: String,
) -> Result<(), String> {
    with_org!(app, state, workspace_id, |client, jar, org| {
        org::add_team_member(&client, &mut jar, org, &team_id, &user_id)
    })
}

#[tauri::command]
pub async fn cloud_remove_team_member(
    app: AppHandle,
    state: State<'_, CloudState>,
    workspace_id: String,
    team_id: String,
    user_id: String,
) -> Result<(), String> {
    with_org!(app, state, workspace_id, |client, jar, org| {
        org::remove_team_member(&client, &mut jar, org, &team_id, &user_id)
    })
}

// ---- Shares ------------------------------------------------------------------

#[tauri::command]
pub async fn cloud_shares(
    app: AppHandle,
    state: State<'_, CloudState>,
    workspace_id: String,
    project_id: String,
) -> Result<Vec<model::ApiShare>, String> {
    with_org!(app, state, workspace_id, |client, jar, org| {
        api::shares(&client, &mut jar, org, &project_id)
    })
}

/// Replaces the whole set — and then triggers a sync, so that the new ones get
/// their project keys right away. Without the second step they would see the
/// rows and nothing in them.
#[tauri::command]
pub async fn cloud_set_shares(
    app: AppHandle,
    state: State<'_, CloudState>,
    workspace_id: String,
    project_id: String,
    shares: Vec<ShareInput>,
) -> Result<(), String> {
    let list: Vec<(Option<String>, ShareRole)> = shares
        .into_iter()
        .map(|share| (share.team_id, share.role))
        .collect();

    let written: Result<(), String> = with_org!(app, state, workspace_id, |client, jar, org| {
        api::put_shares(&client, &mut jar, org, &project_id, &list)
    });
    written?;

    let mut inner = state.0.lock().await;
    sync_one(&app, &mut inner, &workspace_id).await;
    Ok(())
}

/// Lets members create projects in this workspace, or stops it. Projects
/// they created before stay theirs. The sync afterwards brings the setting
/// into the copy.
#[tauri::command]
pub async fn cloud_set_member_projects(
    app: AppHandle,
    state: State<'_, CloudState>,
    workspace_id: String,
    enabled: bool,
) -> Result<(), String> {
    let written: Result<(), String> = with_org!(app, state, workspace_id, |client, jar, org| {
        api::set_member_projects(&client, &mut jar, org, enabled)
    });
    written?;

    let mut inner = state.0.lock().await;
    sync_one(&app, &mut inner, &workspace_id).await;
    Ok(())
}

#[derive(serde::Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ShareInput {
    /// `None` means: the whole organization.
    #[serde(default)]
    pub team_id: Option<String>,
    pub role: ShareRole,
}

/// Takes the wrapped copy of the project key away from a user.
///
/// What they have read until then they still know — a new version of the
/// project key helps against that, see [`cloud_rotate_project_key`].
#[tauri::command]
pub async fn cloud_revoke_key(
    app: AppHandle,
    state: State<'_, CloudState>,
    workspace_id: String,
    project_id: String,
    user_id: String,
) -> Result<(), String> {
    with_org!(app, state, workspace_id, |client, jar, org| {
        api::revoke_key(&client, &mut jar, org, &project_id, &user_id)
    })
}

/// Which projects need a new version of the key after removing `user_id` —
/// see [`api::stale_keys`].
#[tauri::command]
pub async fn cloud_stale_keys(
    app: AppHandle,
    state: State<'_, CloudState>,
    workspace_id: String,
    user_id: String,
) -> Result<Vec<String>, String> {
    with_org!(app, state, workspace_id, |client, jar, org| {
        api::stale_keys(&client, &mut jar, org, &user_id)
    })
}

/// A new version of the project key, and all secrets of the project
/// re-encrypted under it — see [`rotate`].
///
/// What is still in the queue goes up first: a change that arrived under the
/// old version afterwards would partly undo the rotation. Afterwards a sync
/// runs, so that the copy here knows the new version and puts new secrets
/// under it.
#[tauri::command]
pub async fn cloud_rotate_project_key(
    app: AppHandle,
    state: State<'_, CloudState>,
    workspace_id: String,
    project_id: String,
) -> Result<rotate::Rotated, String> {
    let mut inner = state.0.lock().await;
    load(&app, &mut inner)?;

    sync_one(&app, &mut inner, &workspace_id).await;
    let cached = inner.cached(&workspace_id)?.clone();
    if !cached.pending.is_empty() {
        return Err(t!("cloud.rotate_pending").to_string());
    }
    let account = inner.account(&cached.account_id)?.clone();
    let unlocked = inner
        .unlocked(&cached.account_id)
        .map(|vault| Unlocked::new(Zeroizing::new(*vault.private), vault.public))
        .ok_or_else(|| t!("cloud.rotate_locked").to_string())?;

    let client = account.api()?;
    let mut jar = account.jar.clone();
    let result = rotate::rotate(
        &client,
        &mut jar,
        &cached,
        &unlocked,
        &account.user_id,
        &project_id,
    )
    .await;
    persist_jar(&app, &mut inner, &cached.account_id, jar)?;

    sync_one(&app, &mut inner, &workspace_id).await;
    result
}

// ---- Host-Keys ---------------------------------------------------------------

/// Records a confirmed host key in the workspace.
///
/// This is called from the host key dialog after it has been answered — not
/// from [`crate::ssh`]: a connection setup does not know which workspace the
/// connection comes from, the window does.
///
/// What does not get through here is no reason for a message: on this device
/// the key has long been recorded, and the next sync does not try again —
/// the second click at a colleague's is the price.
#[tauri::command]
pub async fn cloud_trust_host(
    app: AppHandle,
    state: State<'_, CloudState>,
    workspace_id: String,
    host: String,
    port: u16,
    algorithm: String,
    public_key: String,
) -> Result<(), String> {
    if public_key.trim().is_empty() {
        return Ok(());
    }
    with_org!(app, state, workspace_id, |client, jar, org| {
        api::add_known_host(
            &client,
            &mut jar,
            org,
            &host,
            port,
            &algorithm,
            public_key.trim(),
        )
    })
}

/// The host keys this workspace trusts.
#[tauri::command]
pub async fn cloud_known_hosts(
    app: AppHandle,
    state: State<'_, CloudState>,
    workspace_id: String,
) -> Result<Vec<model::ApiKnownHost>, String> {
    let mut inner = state.0.lock().await;
    load(&app, &mut inner)?;
    Ok(inner.cached(&workspace_id)?.known_hosts.clone())
}

/// Withdraws trust from a host key — for the whole workspace.
///
/// The local `known_hosts` stays as it is. It belongs to this device, and an
/// entry that someone confirmed here themselves must not disappear because
/// someone else removes it from the workspace.
#[tauri::command]
pub async fn cloud_forget_host(
    app: AppHandle,
    state: State<'_, CloudState>,
    workspace_id: String,
    id: String,
) -> Result<(), String> {
    let removed: Result<(), String> = with_org!(app, state, workspace_id, |client, jar, org| {
        api::remove_known_host(&client, &mut jar, org, &id)
    });
    removed?;

    let mut inner = state.0.lock().await;
    sync_one(&app, &mut inner, &workspace_id).await;
    Ok(())
}

/// "Got it" under a workspace's conflict messages.
#[tauri::command]
pub async fn cloud_dismiss_conflicts(
    app: AppHandle,
    state: State<'_, CloudState>,
    workspace_id: String,
) -> Result<(), String> {
    let mut inner = state.0.lock().await;
    load(&app, &mut inner)?;
    let Some(cached) = inner.caches.iter_mut().find(|c| c.id == workspace_id) else {
        return Ok(());
    };
    cached.conflicts.clear();
    let cached = cached.clone();
    store_cache(&app, &cached)
}

// ---- Invitations to oneself --------------------------------------------------

/// One's own open invitations — and whether the backend hands them out at
/// all.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MyInvitations {
    pub invitations: Vec<org::InvitationRow>,
    /// `false` as long as the email address is not verified. Then the list is
    /// not empty but unknown, and the dialog offers to request the
    /// verification email.
    pub email_verified: bool,
}

#[tauri::command]
pub async fn cloud_my_invitations(
    app: AppHandle,
    state: State<'_, CloudState>,
    account_id: String,
) -> Result<MyInvitations, String> {
    let mut inner = state.0.lock().await;
    load(&app, &mut inner)?;
    let account = inner.account(&account_id)?.clone();
    let client = account.api()?;
    let mut jar = account.jar.clone();

    let list = org::my_invitations(&client, &mut jar).await;
    persist_jar(&app, &mut inner, &account_id, jar)?;

    Ok(match list {
        Ok(list) => MyInvitations {
            invitations: list
                .into_iter()
                .filter(|invitation| invitation.status == "pending")
                .collect(),
            email_verified: true,
        },
        Err(error) if org::needs_verified_email(&error) => MyInvitations {
            invitations: Vec::new(),
            email_verified: false,
        },
        // Everything else is not worth mentioning: the dialog can do its work
        // without the list too.
        Err(_) => MyInvitations {
            invitations: Vec::new(),
            email_verified: true,
        },
    })
}

#[tauri::command]
pub async fn cloud_send_verification_email(
    app: AppHandle,
    state: State<'_, CloudState>,
    account_id: String,
) -> Result<(), String> {
    let mut inner = state.0.lock().await;
    load(&app, &mut inner)?;
    let account = inner.account(&account_id)?.clone();
    let client = account.api()?;
    let mut jar = account.jar.clone();

    let result = org::send_verification_email(&client, &mut jar, &account.email).await;
    persist_jar(&app, &mut inner, &account_id, jar)?;
    result.map_err(String::from)
}

#[tauri::command]
pub async fn cloud_accept_invitation(
    app: AppHandle,
    state: State<'_, CloudState>,
    account_id: String,
    invitation_id: String,
) -> Result<(), String> {
    let mut inner = state.0.lock().await;
    load(&app, &mut inner)?;
    let account = inner.account(&account_id)?.clone();
    let client = account.api()?;
    let mut jar = account.jar.clone();

    let accepted = org::accept_invitation(&client, &mut jar, &invitation_id).await;
    let rows = api::workspaces(&client, &mut jar).await;
    persist_jar(&app, &mut inner, &account_id, jar)?;

    if let Err(error) = accepted {
        if org::needs_verified_email(&error) {
            return Err(t!("cloud.invitation_needs_verified_email").to_string());
        }
        return Err(error.into());
    }

    // Add it right away: whoever accepts an invitation wants to see the
    // workspace and not search for it again afterwards.
    for row in rows.unwrap_or_default() {
        if inner.caches.iter().any(|cached| cached.id == row.id) {
            continue;
        }
        let cached = Cached::new(row.id.clone(), account_id.clone(), row.name.clone());
        store_cache(&app, &cached)?;
        inner.caches.push(cached);
        sync_one(&app, &mut inner, &row.id).await;
    }
    Ok(())
}

#[tauri::command]
pub async fn cloud_reject_invitation(
    app: AppHandle,
    state: State<'_, CloudState>,
    account_id: String,
    invitation_id: String,
) -> Result<(), String> {
    let mut inner = state.0.lock().await;
    load(&app, &mut inner)?;
    let account = inner.account(&account_id)?.clone();
    let client = account.api()?;
    let mut jar = account.jar.clone();

    let result = org::reject_invitation(&client, &mut jar, &invitation_id).await;
    persist_jar(&app, &mut inner, &account_id, jar)?;
    result.map_err(String::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The whole way of the setup: wrap, unwrap, check.
    #[test]
    fn a_master_password_wraps_the_private_key_and_unwraps_it_again() {
        let pair = crypto::new_key_pair().expect("creates a pair");
        let wrapped = wrap_private(&pair.private, b"hunter2").expect("wraps");

        let back = open_private(&wrapped, b"hunter2").expect("unwraps");
        assert_eq!(back.as_ref(), pair.private.as_ref());

        assert!(open_private(&wrapped, b"wrong").is_err());
    }

    /// The parameters are in the row, not in the code. Whoever raises them must
    /// still be able to open existing accounts.
    #[test]
    fn unwrapping_uses_the_parameters_from_the_row() {
        let pair = crypto::new_key_pair().expect("creates a pair");
        let mut wrapped = wrap_private(&pair.private, b"hunter2").expect("wraps");

        assert_eq!(wrapped.kdf_params, KdfParams::default().to_json());

        // Other parameters yield another key, and the ciphertext does not
        // open — exactly why they must not come from a constant.
        wrapped.kdf_params = KdfParams { m: 64, t: 1, p: 1 }.to_json();
        assert!(open_private(&wrapped, b"hunter2").is_err());
    }

    /// A recovery code opens the same door as the master password.
    #[test]
    fn every_recovery_code_unwraps_the_same_key() {
        let pair = crypto::new_key_pair().expect("creates a pair");
        let (codes, rows) = new_recovery_set(&pair.private).expect("creates a set");

        assert_eq!(codes.len(), RECOVERY_CODES);
        assert_eq!(rows.len(), RECOVERY_CODES);

        for (code, row) in codes.iter().zip(&rows) {
            assert_eq!(row.label, crypto::recovery_label(code));
            let normalized = crypto::normalize_recovery_code(code);
            let back = open_private(&row.wrapped, normalized.as_bytes()).expect("unwraps");
            assert_eq!(back.as_ref(), pair.private.as_ref());
        }
    }

    /// The codes must differ — eight slips with the same code would be one
    /// code.
    #[test]
    fn the_codes_differ() {
        let pair = crypto::new_key_pair().expect("creates a pair");
        let (codes, _) = new_recovery_set(&pair.private).expect("creates a set");
        let mut sorted = codes.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), codes.len());
    }

    /// The decryption alone only says that the password fits this
    /// ciphertext. If it belonged to another pair, only the first secret
    /// would fail to open — and nobody would know why.
    #[test]
    fn a_key_of_the_wrong_pair_is_noticed_at_once() {
        let pair = crypto::new_key_pair().expect("creates a pair");
        let foreign = crypto::new_key_pair().expect("creates a pair");

        let material = KeyMaterial {
            algorithm: crypto::KEY_ALGORITHM.into(),
            public_key: BASE64.encode(foreign.public),
            master: wrap_private(&pair.private, b"hunter2").expect("wraps"),
            recovery_keys: Vec::new(),
        };

        assert!(check_pair(&pair.private, &material).is_err());

        let material = KeyMaterial {
            public_key: BASE64.encode(pair.public),
            ..material
        };
        assert!(check_pair(&pair.private, &material).is_ok());
    }
}
