//! The shape in which the tree goes over the wire — and how it relates to the
//! one it has in the client.
//!
//! One difference carries the whole module: in the client the secret sits
//! **inside** the connection (`SshAuth::InlineKey { key }`); on the server
//! there is only a note next to it saying *where* it comes from
//! (`authSource: "inlineKey"`) — the bytes themselves lie in a separate row
//! and are encrypted. So the server knows that a connection uses an entered
//! key, but never which one.
//!
//! That is why no connection goes through [`to_settings`] without its secret,
//! and none comes out of [`from_settings`] without it.

use rust_i18n::t;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::storage::{
    ConnectionSettings, FtpAuth, FtpSecurity, FtpSettings, RemoteSystem, S3Auth, S3Settings,
    SshAuth, SshSettings,
};
use crate::vault::VaultProvider;

/// An organization's change counter.
///
/// As a string, not a number: `JSON.stringify` throws on a BigInt, and an `f64`
/// would be wrong from 2^53 on. It is still compared numerically — `"9"` is
/// greater than `"10"` when comparing strings.
pub type Revision = String;

pub fn revision_value(revision: &str) -> u64 {
    revision.parse().unwrap_or(0)
}

/// The newer of two revisions.
pub fn newer(a: &str, b: &str) -> String {
    if revision_value(a) >= revision_value(b) {
        a.to_string()
    } else {
        b.to_string()
    }
}

// ---- What `GET /api/workspaces` returns --------------------------------------

/// How a workspace came into being.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub enum WorkspaceKind {
    /// Created at registration, belongs to one person only. No "Manage
    /// members", no "Delete" — but renaming and inviting are allowed.
    Personal,
    #[default]
    Organization,
}

/// The role in the organization. It decides which *rows* someone gets — even
/// an `owner` only gets at the secrets if someone has wrapped the project key
/// for them.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub enum Role {
    Owner,
    Admin,
    #[default]
    Member,
}

impl Role {
    /// Who may create, delete and share projects.
    pub fn is_admin(self) -> bool {
        matches!(self, Self::Owner | Self::Admin)
    }
}

#[derive(Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceRow {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub slug: String,
    #[serde(default)]
    pub kind: WorkspaceKind,
    #[serde(default)]
    pub role: Role,
    /// The WireCloud company this organization stands for — only from a
    /// backend in WireCloud mode. Its picture comes from WireCloud.
    #[serde(default)]
    pub wirecloud_company: Option<String>,
}

// ---- What `GET …/sync` returns -----------------------------------------------

#[derive(Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct SyncResponse {
    pub workspace: WorkspaceRow,
    pub revision: Revision,
    #[serde(default)]
    pub projects: Vec<ApiProject>,
    #[serde(default)]
    pub connections: Vec<ApiConnection>,
    #[serde(default)]
    pub secrets: Vec<ApiSecret>,
    #[serde(default)]
    pub vault_accounts: Vec<ApiVaultAccount>,
    #[serde(default)]
    pub known_hosts: Vec<ApiKnownHost>,
    #[serde(default)]
    pub snippets: Vec<ApiSnippet>,
    /// Not a delta: always arrives in full. A key missing because of a `since`
    /// that was too high would make a project unreadable.
    #[serde(default)]
    pub project_keys: Vec<ApiProjectKey>,
    /// Also in full, for the same reason.
    #[serde(default)]
    pub shares: Vec<ApiShare>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ApiProject {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub position: i64,
    #[serde(default)]
    pub created_by_id: Option<String>,
    #[serde(default)]
    pub revision: Revision,
    /// Nothing is deleted; a tombstone is set. A device that has been offline
    /// since the deletion would otherwise never learn about it.
    #[serde(default)]
    pub deleted_at: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ApiConnection {
    pub id: String,
    #[serde(default)]
    pub project_id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub bookmarked: bool,
    #[serde(default)]
    pub position: i64,
    #[serde(default)]
    pub system: Option<RemoteSystem>,
    #[serde(default)]
    pub revision: Revision,
    #[serde(default)]
    pub deleted_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh: Option<SshBody>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ftp: Option<FtpBody>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub s3: Option<S3Body>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct SshBody {
    pub host: String,
    #[serde(default = "port_22")]
    pub port: u16,
    #[serde(default)]
    pub user: String,
    /// `inlineKey` | `keyFile` | `vault` | `password` | `vaultPassword` |
    /// `prompt` | `agent`. Only `inlineKey` and `password` have a secret;
    /// `keyFile` stores a path, `vault` and `vaultPassword` a reference,
    /// `prompt` and `agent` nothing.
    pub auth_source: String,
    // Omitted instead of written as `null` — and that is not a cosmetic
    // detail: the route's schema is set to `additionalProperties: false`,
    // knows no `null` and allows exactly two values for `vaultProvider`. A
    // `"vaultProvider": null` is therefore a 400 there, not an ignored field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_file_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vault_provider: Option<VaultProvider>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vault_reference: Option<String>,
    #[serde(default)]
    pub start_path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jump_connection_id: Option<String>,
    // Only `true` is sent: a backend from before the field would not accept it otherwise.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub agent_forwarding: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub startup_snippet_id: Option<String>,
    /// `null` for rows from before the field — then none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forwards: Option<Vec<crate::storage::Forward>>,
    /// Missing for rows from before the field and for connections through the
    /// device's default proxy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy: Option<crate::proxy::ProxySetting>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct FtpBody {
    pub host: String,
    #[serde(default = "port_21")]
    pub port: u16,
    #[serde(default)]
    pub user: String,
    /// `anonymous` | `password` | `vault` | `prompt`.
    pub auth_source: String,
    /// Omitted instead of `null` — see [`SshBody`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vault_provider: Option<VaultProvider>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vault_reference: Option<String>,
    #[serde(default = "explicit")]
    pub security: FtpSecurity,
    #[serde(default = "yes")]
    pub passive: bool,
    #[serde(default)]
    pub accept_invalid_cert: bool,
    #[serde(default)]
    pub start_path: String,
    /// Missing for rows from before the field and for connections through the
    /// device's default proxy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy: Option<crate::proxy::ProxySetting>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct S3Body {
    pub host: String,
    #[serde(default = "port_443")]
    pub port: u16,
    #[serde(default)]
    pub user: String,
    /// `secret` | `vault` | `prompt`.
    pub auth_source: String,
    /// Omitted instead of `null` — see [`SshBody`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vault_provider: Option<VaultProvider>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vault_reference: Option<String>,
    #[serde(default)]
    pub region: String,
    #[serde(default)]
    pub bucket: String,
    #[serde(default)]
    pub prefix: String,
    #[serde(default = "yes")]
    pub tls: bool,
    #[serde(default)]
    pub path_style: bool,
    #[serde(default)]
    pub accept_invalid_cert: bool,
    #[serde(default)]
    pub storage_class: String,
    /// Missing for rows from before the field and for connections through the
    /// device's default proxy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy: Option<crate::proxy::ProxySetting>,
}

fn port_22() -> u16 {
    22
}
fn port_21() -> u16 {
    21
}
fn port_443() -> u16 {
    443
}
fn yes() -> bool {
    true
}
fn explicit() -> FtpSecurity {
    FtpSecurity::Explicit
}

/// A ciphertext as it lies on the server. The server does not see what is in it.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ApiSecret {
    pub connection_id: String,
    #[serde(default)]
    pub algorithm: String,
    pub key_id: String,
    /// base64.
    pub nonce: String,
    /// base64.
    pub ciphertext: String,
    #[serde(default)]
    pub revision: Revision,
    #[serde(default)]
    pub deleted_at: Option<String>,
}

/// The project key, wrapped for exactly one user.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ApiProjectKey {
    pub project_id: String,
    pub user_id: String,
    pub key_id: String,
    #[serde(default)]
    pub algorithm: String,
    pub ephemeral_public_key: String,
    pub nonce: String,
    pub wrapped_key: String,
}

/// Who may access a project. `team_id: None` means: the whole organization.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ApiShare {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub project_id: String,
    #[serde(default)]
    pub team_id: Option<String>,
    #[serde(default)]
    pub team_name: Option<String>,
    pub role: ShareRole,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum ShareRole {
    Editor,
    Viewer,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ApiVaultAccount {
    #[serde(default)]
    pub id: String,
    pub provider: VaultProvider,
    #[serde(default)]
    pub account: String,
    #[serde(default)]
    pub server: String,
    #[serde(default)]
    pub accept_invalid_cert: bool,
    #[serde(default)]
    pub revision: Revision,
    #[serde(default)]
    pub deleted_at: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ApiKnownHost {
    pub id: String,
    pub host: String,
    #[serde(default = "port_22")]
    pub port: u16,
    pub algorithm: String,
    pub public_key: String,
    #[serde(default)]
    pub trusted_by_id: Option<String>,
    #[serde(default)]
    pub revision: Revision,
    #[serde(default)]
    pub deleted_at: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ApiSnippet {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub folder: String,
    pub command: String,
    #[serde(default)]
    pub position: i64,
    #[serde(default)]
    pub revision: Revision,
    #[serde(default)]
    pub deleted_at: Option<String>,
}

/// A member together with their public key — or without one, as long as they
/// have not set up a master password yet.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct MemberKey {
    pub user_id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub role: Option<Role>,
    /// `None` means: this person has not set up a master password yet. Nothing
    /// can be wrapped for them — that is not an error but information for the
    /// UI ("waiting for setup").
    #[serde(default)]
    pub key: Option<PublicKeyRow>,
    /// Which key versions they already have for this project. Only filled for
    /// `…/key-requests`.
    #[serde(default)]
    pub key_ids: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyRow {
    #[serde(default)]
    pub algorithm: String,
    /// base64.
    pub public_key: String,
}

// ---- Server shape <-> client tree --------------------------------------------

/// Builds the settings, as the rest of the app knows them, from a server row
/// and the decrypted secret.
///
/// `secret` is `None` when there is none (`keyFile`, `vault`, `prompt`,
/// `anonymous`) — and also when there is one, but the vault is locked or the
/// project key has not been wrapped yet. Both end in an empty field; which of
/// the two cases applies is answered not by this function but by the
/// workspace's lock state.
pub fn to_settings(
    connection: &ApiConnection,
    secret: Option<String>,
) -> Result<ConnectionSettings, String> {
    match connection.kind.as_str() {
        "ssh" => {
            let body = connection
                .ssh
                .as_ref()
                .ok_or_else(|| t!("cloud_sync.missing_ssh_settings").into_owned())?;
            let auth = match body.auth_source.as_str() {
                "inlineKey" => SshAuth::InlineKey {
                    key: secret.unwrap_or_default(),
                },
                "keyFile" => SshAuth::KeyFile {
                    path: body.key_file_path.clone().unwrap_or_default(),
                },
                "vault" => SshAuth::Vault {
                    provider: body.vault_provider.unwrap_or_default(),
                    reference: body.vault_reference.clone().unwrap_or_default(),
                },
                "password" => SshAuth::Password {
                    password: secret.unwrap_or_default(),
                },
                "vaultPassword" => SshAuth::VaultPassword {
                    provider: body.vault_provider.unwrap_or_default(),
                    reference: body.vault_reference.clone().unwrap_or_default(),
                },
                "prompt" => SshAuth::Prompt,
                "agent" => SshAuth::Agent,
                other => {
                    return Err(t!("cloud_sync.unknown_key_source", source = other).into_owned())
                }
            };
            Ok(ConnectionSettings::Ssh(SshSettings {
                host: body.host.clone(),
                port: body.port,
                user: body.user.clone(),
                auth,
                start_path: body.start_path.clone(),
                jump: body.jump_connection_id.clone(),
                agent_forwarding: body.agent_forwarding,
                via: Vec::new(),
                forwards: body.forwards.clone().unwrap_or_default(),
                proxy: body.proxy.clone(),
                startup_snippet: body.startup_snippet_id.clone(),
            }))
        }
        "ftp" => {
            let body = connection
                .ftp
                .as_ref()
                .ok_or_else(|| t!("cloud_sync.missing_ftp_settings").into_owned())?;
            let auth = match body.auth_source.as_str() {
                "anonymous" => FtpAuth::Anonymous,
                "password" => FtpAuth::Password {
                    password: secret.unwrap_or_default(),
                },
                "vault" => FtpAuth::Vault {
                    provider: body.vault_provider.unwrap_or_default(),
                    reference: body.vault_reference.clone().unwrap_or_default(),
                },
                "prompt" => FtpAuth::Prompt,
                other => {
                    return Err(
                        t!("cloud_sync.unknown_password_source", source = other).into_owned()
                    )
                }
            };
            Ok(ConnectionSettings::Ftp(FtpSettings {
                host: body.host.clone(),
                port: body.port,
                user: body.user.clone(),
                auth,
                security: body.security,
                passive: body.passive,
                accept_invalid_cert: body.accept_invalid_cert,
                start_path: body.start_path.clone(),
                proxy: body.proxy.clone(),
            }))
        }
        "s3" => {
            let body = connection
                .s3
                .as_ref()
                .ok_or_else(|| t!("cloud_sync.missing_s3_settings").into_owned())?;
            let auth = match body.auth_source.as_str() {
                "secret" => S3Auth::Secret {
                    secret: secret.unwrap_or_default(),
                },
                "vault" => S3Auth::Vault {
                    provider: body.vault_provider.unwrap_or_default(),
                    reference: body.vault_reference.clone().unwrap_or_default(),
                },
                "prompt" => S3Auth::Prompt,
                other => {
                    return Err(t!("cloud_sync.unknown_key_source", source = other).into_owned())
                }
            };
            Ok(ConnectionSettings::S3(S3Settings {
                host: body.host.clone(),
                port: body.port,
                user: body.user.clone(),
                auth,
                region: body.region.clone(),
                bucket: body.bucket.clone(),
                prefix: body.prefix.clone(),
                tls: body.tls,
                path_style: body.path_style,
                accept_invalid_cert: body.accept_invalid_cert,
                storage_class: body.storage_class.clone(),
                proxy: body.proxy.clone(),
            }))
        }
        other => Err(t!("cloud_sync.unknown_connection_type", kind = other).into_owned()),
    }
}

/// A connection's type, as the server writes it.
pub fn type_of(settings: &ConnectionSettings) -> &'static str {
    match settings {
        ConnectionSettings::Ssh(_) => "ssh",
        ConnectionSettings::Ftp(_) => "ftp",
        ConnectionSettings::S3(_) => "s3",
    }
}

/// The secret that has to be extracted from the settings — or `None` if the
/// source has none at all.
///
/// An empty value counts as none: a workspace that was loaded locked and then
/// saved must not replace the ciphertext on the server with an empty string.
/// That is the one place where data loss would otherwise go unnoticed.
pub fn secret_of(settings: &ConnectionSettings) -> Option<&str> {
    let secret = match settings {
        ConnectionSettings::Ssh(SshSettings {
            auth: SshAuth::InlineKey { key: secret } | SshAuth::Password { password: secret },
            ..
        }) => secret.as_str(),
        ConnectionSettings::Ftp(FtpSettings {
            auth: FtpAuth::Password { password },
            ..
        }) => password.as_str(),
        ConnectionSettings::S3(S3Settings {
            auth: S3Auth::Secret { secret },
            ..
        }) => secret.as_str(),
        _ => return None,
    };
    (!secret.is_empty()).then_some(secret)
}

/// Whether this connection's source has a secret at all.
///
/// The difference from [`secret_of`] matters when deleting: a connection that
/// was switched from `inlineKey` to `keyFile` no longer has one — and the
/// ciphertext still lying on the server has to go.
pub fn has_secret_source(settings: &ConnectionSettings) -> bool {
    matches!(
        settings,
        ConnectionSettings::Ssh(SshSettings {
            auth: SshAuth::InlineKey { .. } | SshAuth::Password { .. },
            ..
        }) | ConnectionSettings::Ftp(FtpSettings {
            auth: FtpAuth::Password { .. },
            ..
        }) | ConnectionSettings::S3(S3Settings {
            auth: S3Auth::Secret { .. },
            ..
        })
    )
}

/// The settings in the notation the server expects: one group, named like the
/// type. The secret has already been taken out here.
pub fn settings_body(settings: &ConnectionSettings) -> Value {
    match settings {
        ConnectionSettings::Ssh(ssh) => {
            let (source, key_file_path, provider, reference) = match &ssh.auth {
                SshAuth::InlineKey { .. } => ("inlineKey", None, None, None),
                SshAuth::Password { .. } => ("password", None, None, None),
                SshAuth::KeyFile { path } => ("keyFile", Some(path.clone()), None, None),
                SshAuth::Vault {
                    provider,
                    reference,
                } => ("vault", None, Some(*provider), Some(reference.clone())),
                SshAuth::VaultPassword {
                    provider,
                    reference,
                } => (
                    "vaultPassword",
                    None,
                    Some(*provider),
                    Some(reference.clone()),
                ),
                SshAuth::Prompt => ("prompt", None, None, None),
                SshAuth::Agent => ("agent", None, None, None),
            };
            let mut body = json!({
                "host": ssh.host,
                "port": ssh.port,
                "user": ssh.user,
                "authSource": source,
            });
            put(&mut body, "keyFilePath", key_file_path);
            put_provider(&mut body, provider);
            put(&mut body, "startPath", non_empty(&ssh.start_path));
            put(&mut body, "vaultReference", reference);
            put(&mut body, "jumpConnectionId", ssh.jump.clone());
            put(&mut body, "startupSnippetId", ssh.startup_snippet.clone());
            if ssh.agent_forwarding {
                body["agentForwarding"] = json!(true);
            }
            if !ssh.forwards.is_empty() {
                body["forwards"] = json!(ssh.forwards);
            }
            if let Some(proxy) = &ssh.proxy {
                body["proxy"] = json!(proxy);
            }
            json!({ "ssh": body })
        }
        ConnectionSettings::Ftp(ftp) => {
            let (source, provider, reference) = match &ftp.auth {
                FtpAuth::Anonymous => ("anonymous", None, None),
                FtpAuth::Password { .. } => ("password", None, None),
                FtpAuth::Vault {
                    provider,
                    reference,
                } => ("vault", Some(*provider), Some(reference.clone())),
                FtpAuth::Prompt => ("prompt", None, None),
            };
            let mut body = json!({
                "host": ftp.host,
                "port": ftp.port,
                "user": ftp.user,
                "authSource": source,
                "security": ftp.security,
                "passive": ftp.passive,
                "acceptInvalidCert": ftp.accept_invalid_cert,
            });
            put_provider(&mut body, provider);
            put(&mut body, "startPath", non_empty(&ftp.start_path));
            put(&mut body, "vaultReference", reference);
            if let Some(proxy) = &ftp.proxy {
                body["proxy"] = json!(proxy);
            }
            json!({ "ftp": body })
        }
        ConnectionSettings::S3(s3) => {
            let (source, provider, reference) = match &s3.auth {
                S3Auth::Secret { .. } => ("secret", None, None),
                S3Auth::Vault {
                    provider,
                    reference,
                } => ("vault", Some(*provider), Some(reference.clone())),
                S3Auth::Prompt => ("prompt", None, None),
            };
            let mut body = json!({
                "host": s3.host,
                "port": s3.port,
                "user": s3.user,
                "authSource": source,
                "region": s3.region,
                "bucket": s3.bucket,
                "prefix": s3.prefix,
                "tls": s3.tls,
                "pathStyle": s3.path_style,
                "acceptInvalidCert": s3.accept_invalid_cert,
                "storageClass": s3.storage_class,
            });
            put_provider(&mut body, provider);
            put(&mut body, "vaultReference", reference);
            if let Some(proxy) = &s3.proxy {
                body["proxy"] = json!(proxy);
            }
            json!({ "s3": body })
        }
    }
}

/// Sets a field only if there is something to set.
///
/// The route's schema allows no additional properties and knows no `null` —
/// sending a `"keyFilePath": null` would therefore not be the same as omitting
/// it, but a `400`.
fn put(body: &mut Value, name: &str, value: Option<String>) {
    if let (Some(object), Some(value)) = (body.as_object_mut(), value) {
        object.insert(name.to_string(), Value::String(value));
    }
}

/// Empty means omit: a backend without the column does not know the field and
/// would otherwise answer with `400`, even for everyone who has not set a start
/// path.
fn non_empty(value: &str) -> Option<String> {
    (!value.is_empty()).then(|| value.to_string())
}

fn put_provider(body: &mut Value, provider: Option<VaultProvider>) {
    if let (Some(object), Some(provider)) = (body.as_object_mut(), provider) {
        let name = match provider {
            VaultProvider::OnePassword => "onePassword",
            VaultProvider::Bitwarden => "bitwarden",
        };
        object.insert("vaultProvider".to_string(), Value::String(name.to_string()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ssh_row(auth_source: &str) -> ApiConnection {
        ApiConnection {
            id: "conn-1".into(),
            project_id: "proj-1".into(),
            name: "web01".into(),
            kind: "ssh".into(),
            bookmarked: false,
            position: 0,
            system: None,
            revision: "7".into(),
            deleted_at: None,
            ssh: Some(SshBody {
                host: "web01.example".into(),
                port: 22,
                user: "root".into(),
                auth_source: auth_source.into(),
                key_file_path: Some("C:/keys/id_ed25519".into()),
                vault_provider: Some(VaultProvider::Bitwarden),
                vault_reference: Some("bw://v/i/f".into()),
                start_path: String::new(),
                jump_connection_id: None,
                agent_forwarding: false,
                forwards: None,
                proxy: None,
                startup_snippet_id: None,
            }),
            ftp: None,
            s3: None,
        }
    }

    /// A custom proxy makes the round trip; without one the field is not sent
    /// at all — a backend from before the column would not accept it otherwise.
    #[test]
    fn a_connections_proxy_makes_the_round_trip() {
        let without = to_settings(&ssh_row("agent"), None).expect("builds");
        assert!(settings_body(&without)["ssh"].get("proxy").is_none());

        let mut row = ssh_row("agent");
        let proxy = crate::proxy::ProxySetting::Custom(crate::proxy::Proxy {
            kind: crate::proxy::ProxyKind::Http,
            host: "proxy.intern".into(),
            port: 3128,
        });
        row.ssh.as_mut().expect("ssh").proxy = Some(proxy.clone());
        let settings = to_settings(&row, None).expect("builds");
        let body = settings_body(&settings);
        assert_eq!(
            body["ssh"]["proxy"],
            json!({ "mode": "custom", "kind": "http", "host": "proxy.intern", "port": 3128 })
        );
        let (back, _, _) = bodies_of(&settings);
        assert_eq!(back.expect("ssh").proxy, Some(proxy));
    }

    /// The difference that carries this module: the server only records *where*
    /// the secret comes from, the client has it **inside**.
    #[test]
    fn an_entered_key_comes_from_the_second_row() {
        let settings = to_settings(&ssh_row("inlineKey"), Some("PRIVATE KEY".into()))
            .expect("builds the settings");
        let ConnectionSettings::Ssh(ssh) = settings else {
            panic!("an SSH row yields SSH settings");
        };
        assert!(matches!(ssh.auth, SshAuth::InlineKey { key } if key == "PRIVATE KEY"));
    }

    /// Loaded locked means: the row is there, the secret is not.
    #[test]
    fn without_a_key_the_field_stays_empty_instead_of_failing() {
        let settings = to_settings(&ssh_row("inlineKey"), None).expect("builds the settings");
        assert_eq!(secret_of(&settings), None);
        assert!(has_secret_source(&settings));
    }

    /// And that is exactly why an empty value does not count as a secret:
    /// otherwise saving after a locked load would replace the ciphertext on the
    /// server with nothing.
    #[test]
    fn an_empty_field_overwrites_no_ciphertext() {
        let settings =
            to_settings(&ssh_row("inlineKey"), Some(String::new())).expect("builds the settings");
        assert_eq!(secret_of(&settings), None);
    }

    #[test]
    fn a_file_and_a_vault_have_no_secret_at_all() {
        let file = to_settings(&ssh_row("keyFile"), None).expect("builds");
        assert!(!has_secret_source(&file));
        assert!(matches!(
            file,
            ConnectionSettings::Ssh(SshSettings {
                auth: SshAuth::KeyFile { .. },
                ..
            })
        ));

        let vault = to_settings(&ssh_row("vault"), None).expect("builds");
        assert!(!has_secret_source(&vault));
    }

    /// A fixed SSH password goes as ciphertext, like an entered key, not in the
    /// body.
    #[test]
    fn a_fixed_ssh_password_is_a_secret() {
        let settings = to_settings(&ssh_row("password"), Some("hunter2".into())).expect("builds");
        assert_eq!(secret_of(&settings), Some("hunter2"));
        assert!(has_secret_source(&settings));
        let body = settings_body(&settings);
        assert_eq!(body["ssh"]["authSource"].as_str(), Some("password"));
        assert!(!body.to_string().contains("hunter2"));
    }

    /// Password instead of key: the same source there and back, and neither of
    /// the two has a ciphertext on the server.
    #[test]
    fn an_ssh_password_makes_the_round_trip() {
        for source in ["vaultPassword", "prompt"] {
            let settings = to_settings(&ssh_row(source), None).expect("builds");
            assert!(!has_secret_source(&settings));
            let body = settings_body(&settings);
            let ssh = &body["ssh"];
            assert_eq!(ssh["authSource"].as_str(), Some(source));
            assert!(ssh.get("keyFilePath").is_none());
            assert_eq!(
                ssh.get("vaultReference").is_some(),
                source == "vaultPassword"
            );
        }
    }

    /// Jump host and agent go to the server and come back — and where none is
    /// set, nothing is in the body either: a backend from before the two
    /// fields would not accept the connection otherwise.
    #[test]
    fn jump_host_and_agent_make_the_round_trip() {
        let mut row = ssh_row("agent");
        if let Some(ssh) = row.ssh.as_mut() {
            ssh.jump_connection_id = Some("bastion".into());
            ssh.agent_forwarding = true;
        }
        let settings = to_settings(&row, None).expect("builds");
        let ConnectionSettings::Ssh(ssh) = &settings else {
            panic!("SSH");
        };
        assert_eq!(ssh.jump.as_deref(), Some("bastion"));
        assert!(ssh.agent_forwarding);
        let body = settings_body(&settings);
        assert_eq!(body["ssh"]["jumpConnectionId"].as_str(), Some("bastion"));
        assert_eq!(body["ssh"]["agentForwarding"].as_bool(), Some(true));

        let without = settings_body(&to_settings(&ssh_row("agent"), None).expect("builds"));
        assert!(without["ssh"].get("jumpConnectionId").is_none());
        assert!(without["ssh"].get("agentForwarding").is_none());
    }

    /// The SSH agent stores nothing: no secret, no path, no vault. Whatever
    /// else the row from the server brings along is dropped.
    #[test]
    fn the_ssh_agent_makes_the_round_trip_without_extra_fields() {
        let settings = to_settings(&ssh_row("agent"), None).expect("builds");
        assert!(matches!(
            settings,
            ConnectionSettings::Ssh(SshSettings {
                auth: SshAuth::Agent,
                ..
            })
        ));
        assert!(!has_secret_source(&settings));
        let body = settings_body(&settings);
        let ssh = &body["ssh"];
        assert_eq!(ssh["authSource"].as_str(), Some("agent"));
        assert!(ssh.get("keyFilePath").is_none());
        assert!(ssh.get("vaultProvider").is_none());
        assert!(ssh.get("vaultReference").is_none());
    }

    /// The route's schema allows no additional properties and knows no `null`.
    /// A `"keyFilePath": null` sent along would be a 400.
    #[test]
    fn what_is_not_needed_is_not_in_the_body() {
        let settings = to_settings(&ssh_row("inlineKey"), None).expect("builds");
        let body = settings_body(&settings);
        let ssh = body.get("ssh").expect("the group is named like the type");
        assert_eq!(
            ssh.get("authSource").and_then(Value::as_str),
            Some("inlineKey")
        );
        assert!(ssh.get("keyFilePath").is_none());
        assert!(ssh.get("vaultProvider").is_none());
        assert!(ssh.get("vaultReference").is_none());
    }

    /// The same again for the detour through the structs — and this is not a
    /// duplicate test but the one that is needed: [`settings_body`] omits the
    /// fields by hand, [`connection_body`] serializes the struct, and that is
    /// where `"vaultProvider": null` came out. The route's schema allows two
    /// values for the field, and `null` is not one of them — the connection
    /// could not be created with it.
    #[test]
    fn the_way_through_the_struct_writes_no_null_either() {
        let (ssh, _, _) = bodies_of(&to_settings(&ssh_row("inlineKey"), None).expect("builds"));
        let written = serde_json::to_string(&ssh.expect("an SSH group")).expect("writes");
        assert!(!written.contains("null"), "{written}");

        let connection = ApiConnection {
            ssh: serde_json::from_str(&written).ok(),
            ..ssh_row("inlineKey")
        };
        let body = connection_body(&connection, true);
        let inner = body.get("ssh").expect("the group").to_string();
        assert!(!inner.contains("null"), "{inner}");
        // `system`, on the other hand, may be `null`: there it means "never
        // reached yet", and the schema explicitly allows it.
        assert!(body.get("system").expect("system").is_null());
    }

    #[test]
    fn a_vault_takes_provider_and_reference_along() {
        let settings = to_settings(&ssh_row("vault"), None).expect("builds");
        let body = settings_body(&settings);
        let ssh = body.get("ssh").expect("the group");
        assert_eq!(
            ssh.get("vaultProvider").and_then(Value::as_str),
            Some("bitwarden")
        );
        assert_eq!(
            ssh.get("vaultReference").and_then(Value::as_str),
            Some("bw://v/i/f")
        );
    }

    /// As a string, `"9"` is greater than `"10"`. That is why the comparison is
    /// numeric, even though the revision travels as a string.
    #[test]
    fn revisions_are_compared_as_numbers() {
        assert_eq!(newer("9", "10"), "10");
        assert_eq!(newer("42", "7"), "42");
    }
}

// ---- The notation on the wire ------------------------------------------------

/// A connection the way the route accepts it.
///
/// Not simply [`ApiConnection`] serialized: its `projectId`, `revision` and
/// `deletedAt` come from the server and do not belong back. The schemas are
/// set to `additionalProperties: false`, so one field too many is not an
/// overlooked detail but a `400`.
pub fn connection_body(connection: &ApiConnection, with_id: bool) -> Value {
    let mut body = json!({
        "name": connection.name,
        "type": connection.kind,
        "bookmarked": connection.bookmarked,
        "position": connection.position,
        // `null` is allowed here and means "never reached yet" — unlike the
        // fields in `settings_body`, where it would be a 400.
        "system": connection.system,
    });

    if let Some(object) = body.as_object_mut() {
        if with_id {
            object.insert("id".to_string(), Value::String(connection.id.clone()));
        } else {
            // Always sent when updating: this is how a connection that has
            // wandered into another project moves. If it is already there, the
            // server does nothing with it.
            object.insert(
                "projectId".to_string(),
                Value::String(connection.project_id.clone()),
            );
        }
        if let Some(ssh) = &connection.ssh {
            object.insert("ssh".to_string(), json!(ssh));
        }
        if let Some(ftp) = &connection.ftp {
            object.insert("ftp".to_string(), json!(ftp));
        }
        if let Some(s3) = &connection.s3 {
            object.insert("s3".to_string(), json!(s3));
        }
    }
    body
}

/// Distributes the settings across the three groups — exactly one is filled,
/// namely the one that matches `type`. The server rejects anything else with
/// `C-SM`.
pub fn bodies_of(
    settings: &ConnectionSettings,
) -> (Option<SshBody>, Option<FtpBody>, Option<S3Body>) {
    let body = settings_body(settings);
    let take = |name: &str| body.get(name).cloned().unwrap_or(Value::Null);
    match settings {
        ConnectionSettings::Ssh(_) => (serde_json::from_value(take("ssh")).ok(), None, None),
        ConnectionSettings::Ftp(_) => (None, serde_json::from_value(take("ftp")).ok(), None),
        ConnectionSettings::S3(_) => (None, None, serde_json::from_value(take("s3")).ok()),
    }
}
