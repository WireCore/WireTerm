//! Workspaces, projects and connections, and where they are kept.
//!
//! The frontend owns the editing and hands the whole tree back with
//! [`workspaces_save`], whichever storage it came from. That is the one shape
//! the rest of the app knows, and it stays that way — a connection looks the
//! same whether it was read from a file here or from a backend.
//!
//! What differs is what happens behind these two commands:
//!
//! - [`StorageKind::Local`] writes `workspaces.json`, the whole document at
//!   once. It is small, single-user data, and this keeps the backend down to
//!   load and save instead of a command per entity.
//! - [`StorageKind::Cloud`] and [`StorageKind::CustomBackend`] go to
//!   [`crate::cloud`], which compares the tree against its own copy and turns
//!   the difference into single calls — because over there, someone else is
//!   editing too. The two differ in one thing only: where the address comes
//!   from.
//!
//! A remote workspace is therefore **not** in `workspaces.json`. It lives in
//! its own copy under `cloud/`, with the secrets as ciphertext — and the key
//! to them only in memory.

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use rust_i18n::t;
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager, State};

use crate::bitwarden;
use crate::cloud::model::{Role, WorkspaceKind};
use crate::cloud::CloudState;
use crate::local_secrets::{self, LocalVault};
use crate::proxy::ProxySetting;
use crate::vault::VaultProvider;

/// Where a workspace's data lives.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum StorageKind {
    /// On this device, in the app's data directory.
    Local,
    /// A backend the user runs themselves — see [`crate::cloud`].
    CustomBackend,
    /// Hosted, on an address the app brings along. Otherwise the same as
    /// [`StorageKind::CustomBackend`] in every respect.
    Cloud,
}

impl StorageKind {
    pub fn is_local(self) -> bool {
        matches!(self, Self::Local)
    }
}

/// What a remote workspace brings along besides its tree.
///
/// Only for the UI and only at runtime: none of it is written. `locked`, for
/// example, would not merely be superfluous in a file but wrong on the next
/// start.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Remote {
    /// Which account opened this workspace.
    pub account_id: String,
    /// The backend's address, without a scheme — for the tile.
    pub server: String,
    pub email: String,
    /// `personal` means: the workspace created at sign-up. No "manage
    /// members", no "delete".
    pub kind: WorkspaceKind,
    /// One's own role.
    pub role: Role,
    /// Whether this role may create, delete and share projects. From
    /// [`Role::is_admin`], so the UI does not have to write the rule down a
    /// second time — and differently.
    pub admin: bool,
    /// The vault is locked: the rows are there, the secrets are not.
    pub locked: bool,
    /// There are ciphertexts that could not be opened. With the vault open
    /// that means: nobody has wrapped a key for this version yet — "waiting
    /// for a share" and not "broken".
    pub secrets_missing: bool,
    /// How many changes still have to go up.
    pub pending: usize,
    pub revision: String,
    /// What the last sync failed on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Changes a conflict discarded — until someone dismisses them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conflicts: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Workspace {
    pub id: String,
    pub name: String,
    pub storage: StorageKind,
    /// Which 1Password account the connections in here are read with. The
    /// desktop-app integration signs every user in with their own account, so
    /// this is per user and per workspace rather than compiled in — see
    /// [`crate::op`]. Empty until one has been given.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub one_password_account: String,
    /// Which Bitwarden or Vaultwarden account, for the same reason and with
    /// the same reach — see [`crate::bitwarden`]. Absent until one has been
    /// given. Only the address and the login name are kept here; the master
    /// password is asked for and never written down.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bitwarden: Option<bitwarden::Account>,
    /// Filled for everything that does not come from this disk. Runtime
    /// knowledge only — see [`Remote`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote: Option<Remote>,
    #[serde(default)]
    pub projects: Vec<Project>,
    /// Saved commands, in the order they are in. Each belongs to one of the
    /// projects, see [`Snippet`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub snippets: Vec<Snippet>,
}

impl Workspace {
    /// Drops the snippets whose project — or connection — is not in this
    /// workspace. From a version in which snippets belonged to the workspace,
    /// they have no project at all.
    pub fn prune_snippets(&mut self) {
        let projects = &self.projects;
        self.snippets.retain(|snippet| {
            projects.iter().any(|project| {
                project.id == snippet.project_id
                    && snippet
                        .connection_id
                        .as_ref()
                        .is_none_or(|id| project.connections.iter().any(|c| &c.id == id))
            })
        });
    }
}

/// A saved command for the terminal. The UI replaces placeholders like
/// `{{connection.host}}` when sending.
///
/// It belongs to a project and is offered for all of its connections — or,
/// with `connection_id`, for just that one.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Snippet {
    pub id: String,
    #[serde(default)]
    pub project_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connection_id: Option<String>,
    /// Locked, only owner and admin change it — and only a locked one can be
    /// a startup command. In a workspace on this device always locked.
    #[serde(default = "locked")]
    pub locked: bool,
    pub name: String,
    /// `/`-separated; empty means top level.
    #[serde(default)]
    pub folder: String,
    pub command: String,
}

fn locked() -> bool {
    true
}

/// A named folder. Nothing more for now.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Project {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub connections: Vec<Connection>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Connection {
    pub id: String,
    pub name: String,
    /// Type-specific settings. The variant tag doubles as the connection type,
    /// so a new type means a new variant here and nothing else to keep in sync.
    pub settings: ConnectionSettings,
    /// What the target said about itself the last time it was reached. There
    /// is no way to know this before logging in once, so it is absent until
    /// then and refreshed on every connect.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub system: Option<RemoteSystem>,
    /// Lifts the connection to the top of the tab menu. A view preference, but
    /// one that belongs to the connection rather than to this device: whoever
    /// opens the workspace should get the same shortlist.
    #[serde(default, skip_serializing_if = "is_false")]
    pub bookmarked: bool,
    /// The secret is encrypted in `workspaces.json` but could not be opened on
    /// this device — the device key is missing or a different one. The field
    /// then arrives empty; if it stays empty, the old ciphertext stays in
    /// place on save. Runtime only, never written.
    #[serde(default, skip_serializing_if = "is_false")]
    pub secret_unreadable: bool,
}

fn is_false(value: &bool) -> bool {
    !*value
}

/// The target's own description of itself, read from `/etc/os-release` (or
/// `uname` where that file does not exist).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RemoteSystem {
    /// The os-release `ID`, lowercased: `ubuntu`, `debian`, `alpine`, … This
    /// is what picks the logo, so it stays machine-readable.
    pub id: String,
    /// `NAME`, e.g. `Ubuntu`.
    pub name: String,
    /// `VERSION_ID`, e.g. `24.04`. Empty on rolling releases.
    pub version: String,
    /// `PRETTY_NAME`, the whole line, for the tooltip.
    pub pretty: String,
}

/// What "Test connection" reports back.
///
/// Beside [`RemoteSystem`] rather than in one of the protocol modules because
/// both of them answer with it: the question — how long did it take, and what
/// is over there — is the same whether the login went over SSH or FTP.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Probe {
    /// How long reaching the target and logging in took together, in
    /// milliseconds.
    pub millis: u64,
    /// `None` where the target said nothing about itself.
    pub system: Option<RemoteSystem>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum ConnectionSettings {
    Ssh(SshSettings),
    Ftp(FtpSettings),
    S3(S3Settings),
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct SshSettings {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub auth: SshAuth,
    /// Where the terminal and the file browser go after connecting. Empty is
    /// the login directory.
    #[serde(default)]
    pub start_path: String,
    /// Which other SSH connection of this workspace the target is reached
    /// through — its ID. The jump host can have one of its own in turn; the UI
    /// resolves the chain when connecting, see [`SshSettings::via`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jump: Option<String>,
    /// Forwards the local SSH agent to the server, so that one can jump on
    /// from there with the same keys. Whoever is root on the server can use it
    /// too in the meantime.
    #[serde(default, skip_serializing_if = "is_false")]
    pub agent_forwarding: bool,
    /// The resolved chain of jump hosts, first hop first — only sent along
    /// when connecting, never saved.
    #[serde(default, skip_serializing)]
    pub via: Vec<SshSettings>,
    /// Port forwardings that start with the tab's terminal — see
    /// [`crate::forward`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub forwards: Vec<Forward>,
    /// Through which proxy — if missing, this device's default proxy applies.
    /// See [`crate::proxy`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy: Option<ProxySetting>,
    /// A locked snippet for this connection that is sent in the terminal after
    /// connecting — its ID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub startup_snippet: Option<String>,
}

/// A port forwarding, like `ssh -L`, `-R` and `-D`.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Forward {
    pub kind: ForwardKind,
    /// Where to listen — here for `local` and `dynamic`, on the server for
    /// `remote`. Empty means `127.0.0.1`: reachable only from this machine (or
    /// from the server itself).
    #[serde(default)]
    pub bind_host: String,
    /// 0 lets the system pick a free port.
    pub bind_port: u16,
    /// Where to: for `local` as seen from the server, for `remote` from here.
    /// For `dynamic` every connection says so itself.
    #[serde(default)]
    pub target_host: String,
    #[serde(default)]
    pub target_port: u16,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum ForwardKind {
    /// `-L`: a port here leads to a target behind the server.
    Local,
    /// `-R`: a port on the server leads to a target here.
    Remote,
    /// `-D`: a SOCKS5 proxy here that goes out through the server.
    Dynamic,
}

/// Where the private key — or the password — comes from.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "source", rename_all = "camelCase")]
pub enum SshAuth {
    /// Pasted by the user and stored in the workspace file — encrypted with
    /// the device key, see [`crate::local_secrets`].
    InlineKey { key: String },
    /// Read from disk at connect time; only the path is stored.
    KeyFile { path: String },
    /// Whatever keys the running SSH agent holds — the OpenSSH agent of
    /// Windows, or Pageant. Nothing is stored, not even which key.
    Agent,
    /// Read from a password manager at connect time. Only the reference is
    /// stored, so the key itself never touches this device's disk.
    ///
    /// The `onePassword` alias is what this variant was called while
    /// 1Password was the only one: a file written before Bitwarden existed
    /// here has no `provider` either, and [`VaultProvider::default`] is the
    /// answer to both. Written back in the new spelling on the next save.
    #[serde(rename = "vault", alias = "onePassword")]
    Vault {
        #[serde(default)]
        provider: VaultProvider,
        reference: String,
    },
    /// A password typed in and stored with the connection — on a backend under
    /// the project key, locally under the device key.
    Password { password: String },
    /// A password rather than a key, read from a password manager at connect
    /// time — for servers that take nothing else, like a Hetzner Storage Box.
    VaultPassword {
        #[serde(default)]
        provider: VaultProvider,
        reference: String,
    },
    /// A password asked for when the tab connects and kept in memory for as
    /// long as the tab lives. Nothing is written anywhere.
    Prompt,
}

/// Where an FTP connection goes and how it identifies itself.
///
/// Deliberately not a reuse of [`SshSettings`]: the two overlap in three
/// fields and disagree in everything else. FTP has no host key and no key
/// pair, but it does have a choice of transport security and of who opens the
/// data connection — neither of which SSH has to decide.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct FtpSettings {
    pub host: String,
    /// 21 for plain and explicit FTPS, 990 for implicit.
    pub port: u16,
    pub user: String,
    pub auth: FtpAuth,
    pub security: FtpSecurity,
    /// Whether the client opens the data connection (passive) or the server
    /// does (active). Passive is what works from behind NAT, which is nearly
    /// everywhere, so it is the default.
    #[serde(default = "yes")]
    pub passive: bool,
    /// Accept a server certificate the system does not vouch for.
    ///
    /// Only reachable with one of the TLS modes, and only worth setting for a
    /// self-signed certificate on a server one already knows. It turns off the
    /// part of TLS that tells the right server from an impostor; what is left
    /// is encryption against a passive listener.
    #[serde(default)]
    pub accept_invalid_cert: bool,
    /// Where the file browser goes after connecting. Empty is the login
    /// directory.
    #[serde(default)]
    pub start_path: String,
    /// Through which proxy — if missing, this device's default proxy applies.
    /// See [`crate::proxy`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy: Option<ProxySetting>,
}

fn yes() -> bool {
    true
}

/// How the login is proved.
///
/// FTP has nothing but a password, so the question is only where it comes
/// from — and, for public mirrors, whether there is one at all.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "source", rename_all = "camelCase")]
pub enum FtpAuth {
    /// `anonymous` with an e-mail address as the password, the convention on
    /// public servers. The user field is ignored.
    Anonymous,
    /// Typed in and stored in the workspace file, encrypted like
    /// [`SshAuth::InlineKey`].
    Password { password: String },
    /// Read from a password manager at connect time; only the reference is
    /// stored. Same variant, same two fields and the same alias as
    /// [`SshAuth::Vault`].
    #[serde(rename = "vault", alias = "onePassword")]
    Vault {
        #[serde(default)]
        provider: VaultProvider,
        reference: String,
    },
    /// Asked for when the connection is opened and kept in memory for as long
    /// as the tab lives. Nothing is written anywhere.
    Prompt,
}

/// What, if anything, encrypts the connection.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum FtpSecurity {
    /// Plain FTP. Password and file contents travel readable.
    Plain,
    /// `AUTH TLS` on the normal port — the current way to do FTPS.
    Explicit,
    /// TLS from the first byte, historically on port 990. Overhauled by
    /// explicit FTPS long ago, but still all some servers offer.
    Implicit,
}

/// Where an S3 endpoint is, which bucket it starts in and how it is addressed.
///
/// Deliberately not a reuse of [`FtpSettings`] either, but the three fields
/// every type shares are spelled the same way and mean the same thing: `host`
/// is the endpoint, `port` the port it listens on, and `user` the access key
/// id — which really is the name the request is made under, so the tab bar and
/// "Test connection" need to know nothing about S3 to say something true.
///
/// Everything below those three is S3's own: a bucket is not a directory, a
/// region is part of the signature rather than a route, and whether the bucket
/// belongs in the host name or in the path is the one setting that decides
/// whether a connection to anything other than AWS works at all.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct S3Settings {
    /// The endpoint's host name, without a scheme: `s3.eu-central-1.amazonaws.com`,
    /// `minio.intern.example`, `10.0.0.5`.
    pub host: String,
    /// 443 with TLS, 80 without, 9000 for a MinIO out of the box.
    pub port: u16,
    /// The access key id. Called "user" because that is what it is here: the
    /// name every request is signed under.
    pub user: String,
    pub auth: S3Auth,
    /// Part of the signature, not of the address. A wrong one is refused by
    /// AWS with a redirect naming the right one; most other implementations
    /// ignore it entirely, which is why `us-east-1` is a workable default.
    pub region: String,
    /// Where the file browser starts. Empty means the list of buckets, which
    /// is also the only way to reach another one — a login that may not list
    /// buckets therefore wants this set.
    #[serde(default)]
    pub bucket: String,
    /// A prefix inside the bucket to start in, without a leading slash.
    /// "Up" still goes above it: it is a starting point, not a jail.
    #[serde(default)]
    pub prefix: String,
    #[serde(default = "yes")]
    pub tls: bool,
    /// `https://host/bucket/key` instead of `https://bucket.host/key`.
    ///
    /// AWS wants the bucket in the host name and has been phasing the other
    /// form out for years; MinIO, Ceph and everything else reachable by IP
    /// need it in the path, because `bucket.10.0.0.5` resolves nowhere.
    #[serde(default)]
    pub path_style: bool,
    /// Accept a server certificate the system does not vouch for — the same
    /// setting, and the same trade-off, as [`FtpSettings::accept_invalid_cert`].
    #[serde(default)]
    pub accept_invalid_cert: bool,
    /// What uploads are stored as: `STANDARD`, `GLACIER_IR`, `ONEZONE_IA`, …
    /// Empty leaves it to the server, which is what anything other than AWS
    /// expects to hear.
    #[serde(default)]
    pub storage_class: String,
    /// Through which proxy — if missing, this device's default proxy applies.
    /// See [`crate::proxy`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy: Option<ProxySetting>,
}

/// Where the secret access key comes from.
///
/// There is no "anonymous" here, unlike FTP: an unsigned request only ever
/// reaches a bucket that is open to the whole internet, and a connection
/// entry for one is not what anybody is setting up. See TODO.md.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "source", rename_all = "camelCase")]
pub enum S3Auth {
    /// Typed in and stored in the workspace file, encrypted like
    /// [`SshAuth::InlineKey`].
    Secret { secret: String },
    /// Read from a password manager at connect time; only the reference is
    /// stored. Same variant, same two fields and the same alias as
    /// [`SshAuth::Vault`].
    #[serde(rename = "vault", alias = "onePassword")]
    Vault {
        #[serde(default)]
        provider: VaultProvider,
        reference: String,
    },
    /// Asked for when the connection is opened and kept in memory for as long
    /// as the tab lives. Nothing is written anywhere.
    Prompt,
}

const FILE_NAME: &str = "workspaces.json";

/// `workspaces.json` in the app's data directory — which is also where a
/// development build parts ways with the installed one, see [`crate::paths`].
/// Created on first save.
fn file_path(app: &AppHandle) -> Result<PathBuf, String> {
    let dir = crate::paths::app_data_dir(app)?;
    Ok(dir.join(FILE_NAME))
}

/// The file as it is on disk — secrets still encrypted.
fn read_local(app: &AppHandle) -> Result<Vec<Workspace>, String> {
    let path = file_path(app)?;
    if !path.is_file() {
        return Ok(Vec::new());
    }
    let raw = fs::read_to_string(&path)
        .map_err(|e| t!("core.read_failed", path = format!("{path:?}"), error = e).to_string())?;
    let mut workspaces: Vec<Workspace> = serde_json::from_str(&raw)
        .map_err(|e| t!("core.damaged", path = FILE_NAME, error = e).to_string())?;

    // A file from a version in which there were no remote workspaces yet can
    // contain some that ended up here later. They do not belong here — their
    // copy is under `cloud/`.
    workspaces.retain(|workspace| workspace.storage.is_local());
    for workspace in &mut workspaces {
        workspace.remote = None;
        workspace.prune_snippets();
    }
    Ok(workspaces)
}

/// The local workspaces with decrypted secrets.
///
/// If the file still holds plain text from a version before encryption, it is
/// rewritten encrypted right here — not only on the next save, which may not
/// come for a long time.
fn local_workspaces(app: &AppHandle) -> Result<Vec<Workspace>, String> {
    let mut workspaces = read_local(app)?;
    let key = app.state::<LocalVault>().key(app);
    let plaintext = open_secrets(&mut workspaces, key.as_deref());
    if plaintext && key.is_some() {
        write_local(app, workspaces.clone(), key.as_deref())?;
    }
    Ok(workspaces)
}

/// Which field of a connection carries its secret, and under which name it
/// appears in the `aad`.
fn secret_slot(settings: &mut ConnectionSettings) -> Option<(&'static str, &mut String)> {
    match settings {
        ConnectionSettings::Ssh(SshSettings {
            auth: SshAuth::InlineKey { key },
            ..
        }) => Some(("key", key)),
        ConnectionSettings::Ssh(SshSettings {
            auth: SshAuth::Password { password },
            ..
        })
        | ConnectionSettings::Ftp(FtpSettings {
            auth: FtpAuth::Password { password },
            ..
        }) => Some(("password", password)),
        ConnectionSettings::S3(S3Settings {
            auth: S3Auth::Secret { secret },
            ..
        }) => Some(("secret", secret)),
        _ => None,
    }
}

fn connections_mut(workspaces: &mut [Workspace]) -> impl Iterator<Item = &mut Connection> {
    workspaces
        .iter_mut()
        .flat_map(|workspace| workspace.projects.iter_mut())
        .flat_map(|project| project.connections.iter_mut())
}

/// Decrypts what can be decrypted. What does not open arrives empty and with
/// [`Connection::secret_unreadable`]. Returns whether the file still held
/// plain text.
fn open_secrets(workspaces: &mut [Workspace], key: Option<&[u8; 32]>) -> bool {
    let mut plaintext = false;
    for connection in connections_mut(workspaces) {
        let id = connection.id.clone();
        let Some((field, value)) = secret_slot(&mut connection.settings) else {
            continue;
        };
        if local_secrets::is_sealed(value) {
            let aad = local_secrets::connection_aad(&id, field);
            match key.and_then(|key| local_secrets::open_text(key, &aad, value).ok()) {
                Some(plain) => *value = plain,
                None => {
                    value.clear();
                    connection.secret_unreadable = true;
                }
            }
        } else if !value.is_empty() {
            plaintext = true;
        }
    }
    plaintext
}

/// The encrypted fields as they are in the file so far.
fn sealed_fields(workspaces: &mut [Workspace]) -> HashMap<(String, &'static str), String> {
    let mut found = HashMap::new();
    for connection in connections_mut(workspaces) {
        let id = connection.id.clone();
        if let Some((field, value)) = secret_slot(&mut connection.settings) {
            if local_secrets::is_sealed(value) {
                found.insert((id, field), value.clone());
            }
        }
    }
    found
}

/// Encrypts every secret for the disk.
///
/// A field that arrives empty because it did not open on load gets its old
/// ciphertext back: otherwise a save without the right key would delete every
/// secret that was encrypted with it.
fn seal_secrets(
    workspaces: &mut [Workspace],
    key: Option<&[u8; 32]>,
    previous: &HashMap<(String, &'static str), String>,
) -> Result<(), String> {
    for connection in connections_mut(workspaces) {
        let unreadable = std::mem::take(&mut connection.secret_unreadable);
        let id = connection.id.clone();
        let Some((field, value)) = secret_slot(&mut connection.settings) else {
            continue;
        };
        if value.is_empty() {
            if unreadable {
                if let Some(old) = previous.get(&(id, field)) {
                    *value = old.clone();
                }
            }
            continue;
        }
        if local_secrets::is_sealed(value) {
            continue;
        }
        let key = key.ok_or_else(|| t!("core.local_key_locked").to_string())?;
        let aad = local_secrets::connection_aad(&id, field);
        let sealed = local_secrets::seal_text(key, &aad, value)?;
        // The cross-check before writing: what does not open again does not
        // take the place of the plain text.
        if local_secrets::open_text(key, &aad, &sealed).as_deref() != Ok(value.as_str()) {
            return Err(t!("core.seal_check_failed").to_string());
        }
        *value = sealed;
    }
    Ok(())
}

/// Writes the local workspaces, secrets encrypted.
fn write_local(
    app: &AppHandle,
    mut local: Vec<Workspace>,
    key: Option<&[u8; 32]>,
) -> Result<(), String> {
    let previous = sealed_fields(&mut read_local(app).unwrap_or_default());
    seal_secrets(&mut local, key, &previous)?;

    let path = file_path(app)?;
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).map_err(|e| {
            t!("core.create_failed", path = format!("{dir:?}"), error = e).to_string()
        })?;
    }

    let json = serde_json::to_string_pretty(&local).map_err(|e| e.to_string())?;

    // Write beside the target and rename, so an interrupted save cannot leave
    // a half-written file where the workspaces used to be.
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, json)
        .map_err(|e| t!("core.write_failed", path = format!("{tmp:?}"), error = e).to_string())?;
    fs::rename(&tmp, &path)
        .map_err(|e| t!("core.replace_failed", path = format!("{path:?}"), error = e).to_string())
}

/// The local workspaces first, then the remote ones.
///
/// The rest of the app treats both the same; only [`Workspace::remote`] says
/// where one comes from.
#[tauri::command]
pub async fn workspaces_load(
    app: AppHandle,
    cloud: State<'_, CloudState>,
) -> Result<Vec<Workspace>, String> {
    let mut workspaces = local_workspaces(&app)?;
    // A backend that does not answer must not take the local workspaces down
    // with it: they live here and have nothing to do with it.
    match cloud.workspaces(&app).await {
        Ok(remote) => workspaces.extend(remote),
        Err(error) => eprintln!("cloud workspaces could not be read: {error}"),
    }
    Ok(workspaces)
}

#[tauri::command]
pub async fn workspaces_save(
    app: AppHandle,
    cloud: State<'_, CloudState>,
    workspaces: Vec<Workspace>,
) -> Result<(), String> {
    let (local, remote): (Vec<Workspace>, Vec<Workspace>) = workspaces
        .into_iter()
        .partition(|workspace| workspace.remote.is_none() && workspace.storage.is_local());

    let key = app.state::<LocalVault>().key(&app);
    write_local(&app, local, key.as_deref())?;

    cloud.save(&app, remote).await
}

/// Shown in the UI so the user can find the file.
#[tauri::command]
pub fn workspaces_location(app: AppHandle) -> Result<String, String> {
    Ok(file_path(&app)?.to_string_lossy().into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Migration -------------------------------------------------------------
    //
    // A `workspaces.json` written before Bitwarden calls the source
    // "onePassword" and knows no `provider`. If that is read wrongly, it is not
    // one setting that is gone but every one of the user's connections —
    // which is why this is here and not only in the comment on the enum.

    #[test]
    fn an_old_key_source_still_reads_and_means_1password() {
        let old = r#"{"source":"onePassword","reference":"op://v/i/f?ssh-format=openssh"}"#;
        let auth: SshAuth = serde_json::from_str(old).expect("an old file must still open");
        let SshAuth::Vault {
            provider,
            reference,
        } = auth
        else {
            panic!("the old source belongs to the vault variant");
        };
        assert_eq!(provider, VaultProvider::OnePassword);
        assert_eq!(reference, "op://v/i/f?ssh-format=openssh");
    }

    #[test]
    fn the_same_holds_for_the_other_two_protocols() {
        let ftp: FtpAuth =
            serde_json::from_str(r#"{"source":"onePassword","reference":"op://v/i/f"}"#)
                .expect("an old FTP connection must still open");
        assert!(matches!(
            ftp,
            FtpAuth::Vault {
                provider: VaultProvider::OnePassword,
                ..
            }
        ));

        let s3: S3Auth =
            serde_json::from_str(r#"{"source":"onePassword","reference":"op://v/i/f"}"#)
                .expect("an old S3 connection must still open");
        assert!(matches!(
            s3,
            S3Auth::Vault {
                provider: VaultProvider::OnePassword,
                ..
            }
        ));
    }

    #[test]
    fn a_workspace_without_a_bitwarden_account_reads_and_writes_without_one() {
        let old = r#"{"id":"w1","name":"Test","storage":"local","projects":[]}"#;
        let workspace: Workspace = serde_json::from_str(old).expect("an old workspace opens");
        assert!(workspace.bitwarden.is_none());

        // And it does not reappear as `null` on save either.
        let written = serde_json::to_string(&workspace).expect("serialises");
        assert!(!written.contains("bitwarden"), "{written}");
    }

    #[test]
    fn what_is_written_back_is_the_new_spelling_and_reads_again() {
        let auth = SshAuth::Vault {
            provider: VaultProvider::Bitwarden,
            reference: "bw://personal/2f1c/sshKey.privateKey".to_string(),
        };
        let written = serde_json::to_string(&auth).expect("serialises");
        assert!(written.contains(r#""source":"vault""#), "{written}");
        assert!(written.contains(r#""provider":"bitwarden""#), "{written}");

        let back: SshAuth = serde_json::from_str(&written).expect("round trip");
        assert!(matches!(
            back,
            SshAuth::Vault {
                provider: VaultProvider::Bitwarden,
                ..
            }
        ));
    }

    // ---- Encrypted secrets ---------------------------------------------------

    const KEY: [u8; 32] = [3u8; 32];

    fn with_key(key: &str) -> Vec<Workspace> {
        vec![Workspace {
            id: "ws".into(),
            name: "Company".into(),
            storage: StorageKind::Local,
            one_password_account: String::new(),
            bitwarden: None,
            remote: None,
            projects: vec![Project {
                id: "p".into(),
                name: "Production".into(),
                connections: vec![Connection {
                    id: "c1".into(),
                    name: "web01".into(),
                    settings: ConnectionSettings::Ssh(SshSettings {
                        host: "web01".into(),
                        port: 22,
                        user: "root".into(),
                        auth: SshAuth::InlineKey { key: key.into() },
                        start_path: String::new(),
                        jump: None,
                        agent_forwarding: false,
                        via: Vec::new(),
                        forwards: Vec::new(),
                        proxy: None,
                        startup_snippet: None,
                    }),
                    system: None,
                    bookmarked: false,
                    secret_unreadable: false,
                }],
            }],
            snippets: Vec::new(),
        }]
    }

    fn secret_of(workspaces: &mut [Workspace]) -> String {
        let connection = &mut workspaces[0].projects[0].connections[0];
        secret_slot(&mut connection.settings)
            .map(|(_, value)| value.clone())
            .unwrap_or_default()
    }

    #[test]
    fn no_plain_text_on_disk_but_in_the_form() {
        let mut tree = with_key("PRIVATE KEY");
        seal_secrets(&mut tree, Some(&KEY), &HashMap::new()).expect("encrypted");
        let json = serde_json::to_string(&tree).expect("json");
        assert!(!json.contains("PRIVATE"), "{json}");
        assert!(json.contains("wtenc:v1:"));

        let mut read: Vec<Workspace> = serde_json::from_str(&json).expect("reads");
        assert!(
            !open_secrets(&mut read, Some(&KEY)),
            "no plain text any more"
        );
        assert_eq!(secret_of(&mut read), "PRIVATE KEY");
        assert!(!read[0].projects[0].connections[0].secret_unreadable);
    }

    #[test]
    fn plain_text_from_an_old_file_is_detected() {
        let mut old = with_key("PRIVATE KEY");
        assert!(open_secrets(&mut old, Some(&KEY)));
        assert_eq!(secret_of(&mut old), "PRIVATE KEY", "and stays readable");
    }

    /// The case all of this is built against: a different key or none, the
    /// field arrives empty, someone saves. The ciphertext must stay.
    #[test]
    fn an_unreadable_secret_survives_saving() {
        let mut tree = with_key("PRIVATE KEY");
        seal_secrets(&mut tree, Some(&KEY), &HashMap::new()).expect("encrypted");
        let before = sealed_fields(&mut tree.clone());

        let mut foreign = tree.clone();
        open_secrets(&mut foreign, Some(&[9u8; 32]));
        assert_eq!(secret_of(&mut foreign), "");
        assert!(foreign[0].projects[0].connections[0].secret_unreadable);

        seal_secrets(&mut foreign, Some(&[9u8; 32]), &before).expect("saves");
        assert_eq!(
            secret_of(&mut foreign),
            secret_of(&mut tree),
            "the old ciphertext is back in place"
        );
        assert!(
            !foreign[0].projects[0].connections[0].secret_unreadable,
            "the marker does not go to disk"
        );
    }

    #[test]
    fn newly_entered_replaces_the_unreadable() {
        let mut tree = with_key("OLD");
        seal_secrets(&mut tree, Some(&KEY), &HashMap::new()).expect("encrypted");
        let before = sealed_fields(&mut tree.clone());

        let mut new = with_key("NEW");
        new[0].projects[0].connections[0].secret_unreadable = true;
        seal_secrets(&mut new, Some(&[9u8; 32]), &before).expect("saves");
        open_secrets(&mut new, Some(&[9u8; 32]));
        assert_eq!(secret_of(&mut new), "NEW");
    }

    #[test]
    fn without_a_key_no_new_secret_is_written() {
        let mut tree = with_key("PRIVATE KEY");
        let error = seal_secrets(&mut tree, None, &HashMap::new()).expect_err("refused");
        assert!(error.contains("app password"), "{error}");
    }
}
