//! The local copy of a workspace — and what still has to go up.
//!
//! Without it there would be no offline mode: the tree would come fresh over
//! the wire on every start, and without a connection the workspace would be
//! empty. With it, the workspace is visible and usable, and changes wait in
//! [`Pending`] until the server is back.
//!
//! What lies on disk here lies on the server just the same: names, hosts,
//! ports, user names in plaintext, secrets **only as ciphertext**. The key to
//! them is nowhere in this file — it comes from the master password and lives
//! exclusively in memory.
//!
//! Two things from `CLIENT.md` determine the shape:
//!
//! - **Tombstones.** The server deletes nothing; it sets `deletedAt`. Here the
//!   row is then actually removed — a tombstone is a message, not an entry.
//! - **`projectKeys` and `shares` are not a delta.** They always arrive in
//!   full and are therefore replaced instead of merged.

use std::collections::HashMap;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use serde::{Deserialize, Serialize};

use super::crypto::{self, Secret32};
use super::model::{
    newer, ApiConnection, ApiKnownHost, ApiProject, ApiProjectKey, ApiSecret, ApiShare, ApiSnippet,
    ApiVaultAccount, Role, SyncResponse, WorkspaceKind,
};
use crate::bitwarden;
use crate::storage::{Connection, Project};
use crate::vault::VaultProvider;
use rust_i18n::t;

/// Everything this client knows about a workspace.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Cached {
    /// The `organizationId` — also the workspace ID in the tree.
    pub id: String,
    /// Which account this workspace belongs to.
    pub account_id: String,
    pub name: String,
    #[serde(default)]
    pub slug: String,
    #[serde(default)]
    pub kind: WorkspaceKind,
    #[serde(default)]
    pub role: Role,
    /// Where the next sync continues. `"0"` means: fetch everything.
    #[serde(default = "zero")]
    pub revision: String,
    #[serde(default)]
    pub projects: Vec<ApiProject>,
    #[serde(default)]
    pub connections: Vec<ApiConnection>,
    #[serde(default)]
    pub secrets: Vec<ApiSecret>,
    #[serde(default)]
    pub project_keys: Vec<ApiProjectKey>,
    #[serde(default)]
    pub shares: Vec<ApiShare>,
    #[serde(default)]
    pub vault_accounts: Vec<ApiVaultAccount>,
    #[serde(default)]
    pub known_hosts: Vec<ApiKnownHost>,
    #[serde(default)]
    pub snippets: Vec<ApiSnippet>,
    /// What still has to go up, in the order in which it was created.
    #[serde(default)]
    pub pending: Vec<Pending>,
    /// What the last sync failed on, for the banner above the overview. Empty
    /// again after a successful sync.
    #[serde(default)]
    pub last_error: Option<String>,
    /// Changes that a conflict discarded. Unlike [`Cached::last_error`] they
    /// stay until someone acknowledges them — otherwise they would be gone
    /// after the next sync a minute later, and anyone who was not looking
    /// would never find out.
    #[serde(default)]
    pub conflicts: Vec<String>,
}

fn zero() -> String {
    "0".to_string()
}

impl Cached {
    pub fn new(id: String, account_id: String, name: String) -> Self {
        Self {
            id,
            account_id,
            name,
            slug: String::new(),
            kind: WorkspaceKind::Organization,
            role: Role::Member,
            revision: zero(),
            projects: Vec::new(),
            connections: Vec::new(),
            secrets: Vec::new(),
            project_keys: Vec::new(),
            shares: Vec::new(),
            vault_accounts: Vec::new(),
            known_hosts: Vec::new(),
            pending: Vec::new(),
            last_error: None,
            conflicts: Vec::new(),
            snippets: Vec::new(),
        }
    }

    /// Takes in what has happened since `revision`.
    pub fn apply(&mut self, delta: SyncResponse) {
        self.name = delta.workspace.name;
        self.slug = delta.workspace.slug;
        self.kind = delta.workspace.kind;
        self.role = delta.workspace.role;
        self.revision = newer(&self.revision, &delta.revision);

        merge(
            &mut self.projects,
            delta.projects,
            |row| row.id.clone(),
            |row| row.deleted_at.is_some(),
        );
        merge(
            &mut self.connections,
            delta.connections,
            |row| row.id.clone(),
            |row| row.deleted_at.is_some(),
        );
        merge(
            &mut self.secrets,
            delta.secrets,
            |row| row.connection_id.clone(),
            |row| row.deleted_at.is_some(),
        );
        merge(
            &mut self.vault_accounts,
            delta.vault_accounts,
            |row| format!("{:?}", row.provider),
            |row| row.deleted_at.is_some(),
        );
        merge(
            &mut self.known_hosts,
            delta.known_hosts,
            |row| row.id.clone(),
            |row| row.deleted_at.is_some(),
        );
        merge(
            &mut self.snippets,
            delta.snippets,
            |row| row.id.clone(),
            |row| row.deleted_at.is_some(),
        );

        // Not a delta: both always arrive in full. Merging would mean never
        // getting rid of a revoked share again.
        //
        // The exception are project keys that this client generated itself and
        // has not uploaded yet — the server does not know them yet, and without
        // them the secrets in the queue would be unreadable.
        let unsent = self.unsent_key_ids();
        let mut keys: Vec<ApiProjectKey> = self
            .project_keys
            .drain(..)
            .filter(|key| unsent.contains(&(key.project_id.clone(), key.key_id.clone())))
            .collect();
        for key in delta.project_keys {
            if !keys
                .iter()
                .any(|own| own.project_id == key.project_id && own.key_id == key.key_id)
            {
                keys.push(key);
            }
        }
        self.project_keys = keys;
        self.shares = delta.shares;

        // A connection whose project is gone is gone too. The server does set
        // its own tombstone for it, but only for whoever was still allowed to
        // see the project — whoever lost the share gets nothing at all anymore
        // and would otherwise keep it forever.
        let projects: Vec<String> = self.projects.iter().map(|p| p.id.clone()).collect();
        self.connections
            .retain(|connection| projects.contains(&connection.project_id));
        let connections: Vec<String> = self.connections.iter().map(|c| c.id.clone()).collect();
        self.secrets
            .retain(|secret| connections.contains(&secret.connection_id));
    }

    /// The key versions this client generated that are not on the server yet.
    fn unsent_key_ids(&self) -> Vec<(String, String)> {
        self.pending
            .iter()
            .filter_map(|op| match op {
                Pending::GrantKeys {
                    project_id, key_id, ..
                } => Some((project_id.clone(), key_id.clone())),
                _ => None,
            })
            .collect()
    }

    /// Appends new changes to the queue.
    ///
    /// A second change to the same project or the same connection, while the
    /// first is still waiting, replaces it in place — and keeps its
    /// `expected_revision`. Sent one after the other, the second would
    /// otherwise arrive with a revision that the first has just moved on, and
    /// fail as a conflict with itself.
    pub fn enqueue(&mut self, ops: Vec<Pending>) {
        for op in ops {
            let earlier = self
                .pending
                .iter_mut()
                .find(|queued| match (&**queued, &op) {
                    (
                        Pending::UpdateProject { id: a, .. },
                        Pending::UpdateProject { id: b, .. },
                    ) => a == b,
                    (
                        Pending::UpdateConnection { id: a, .. },
                        Pending::UpdateConnection { id: b, .. },
                    ) => a == b,
                    _ => false,
                });
            match earlier {
                Some(queued) => {
                    let kept = match &*queued {
                        Pending::UpdateProject {
                            expected_revision, ..
                        }
                        | Pending::UpdateConnection {
                            expected_revision, ..
                        } => expected_revision.clone(),
                        _ => None,
                    };
                    *queued = op;
                    if let Pending::UpdateProject {
                        expected_revision, ..
                    }
                    | Pending::UpdateConnection {
                        expected_revision, ..
                    } = queued
                    {
                        *expected_revision = kept;
                    }
                }
                None => self.pending.push(op),
            }
        }
    }

    /// Whether the creation of this project or connection is still waiting. If
    /// so, the row in the copy has no revision from the server yet, only a
    /// placeholder.
    pub fn creation_pending(&self, id: &str) -> bool {
        self.pending.iter().any(|op| match op {
            Pending::CreateProject { id: created, .. } => created == id,
            Pending::CreateConnection { connection, .. } => connection.id == id,
            Pending::CreateSnippet { snippet } => snippet.id == id,
            _ => false,
        })
    }

    pub fn project(&self, id: &str) -> Option<&ApiProject> {
        self.projects.iter().find(|project| project.id == id)
    }

    pub fn connection(&self, id: &str) -> Option<&ApiConnection> {
        self.connections
            .iter()
            .find(|connection| connection.id == id)
    }

    pub fn secret(&self, connection_id: &str) -> Option<&ApiSecret> {
        self.secrets
            .iter()
            .find(|secret| secret.connection_id == connection_id)
    }

    /// The key version under which new secrets of this project are stored.
    ///
    /// The newest one this user owns themselves — one they do not have, they
    /// could neither use nor open again.
    pub fn current_key_id(&self, project_id: &str) -> Option<String> {
        self.project_keys
            .iter()
            .filter(|key| key.project_id == project_id)
            .map(|key| key.key_id.clone())
            .next_back()
    }

    /// Unwraps a project key, provided there is one and the vault is open.
    pub fn unwrap_key(
        &self,
        private: &[u8; 32],
        project_id: &str,
        key_id: &str,
    ) -> Option<Secret32> {
        let row = self
            .project_keys
            .iter()
            .find(|key| key.project_id == project_id && key.key_id == key_id)?;
        let epk = BASE64.decode(&row.ephemeral_public_key).ok()?;
        let nonce = BASE64.decode(&row.nonce).ok()?;
        let wrapped = BASE64.decode(&row.wrapped_key).ok()?;
        crypto::unwrap_project_key(private, &epk, &nonce, &wrapped).ok()
    }

    /// This workspace's vault account, in the form the tree knows.
    pub fn one_password_account(&self) -> String {
        self.vault_accounts
            .iter()
            .find(|row| row.provider == VaultProvider::OnePassword)
            .map(|row| row.account.clone())
            .unwrap_or_default()
    }

    pub fn bitwarden_account(&self) -> Option<bitwarden::Account> {
        self.vault_accounts
            .iter()
            .find(|row| row.provider == VaultProvider::Bitwarden)
            .filter(|row| !row.account.trim().is_empty())
            .map(|row| bitwarden::Account {
                server: row.server.clone(),
                email: row.account.clone(),
                accept_invalid_cert: row.accept_invalid_cert,
            })
    }

    /// The snippets in their order, as the tree knows them — only those of
    /// a project (and connection) that is in the tree. One without a project
    /// is from before snippets belonged to one; the next save deletes it on
    /// the server, where it is long gone anyway.
    pub fn snippet_list(&self) -> Vec<crate::storage::Snippet> {
        let live = |id: &str| {
            self.projects
                .iter()
                .any(|row| row.id == id && row.deleted_at.is_none())
        };
        let connection = |id: &str| {
            self.connections
                .iter()
                .any(|row| row.id == id && row.deleted_at.is_none())
        };
        let mut rows: Vec<&ApiSnippet> = self
            .snippets
            .iter()
            .filter(|row| live(&row.project_id))
            .filter(|row| row.connection_id.as_deref().is_none_or(connection))
            .collect();
        rows.sort_by_key(|row| (row.position, row.name.to_lowercase()));
        rows.into_iter()
            .map(|row| crate::storage::Snippet {
                id: row.id.clone(),
                project_id: row.project_id.clone(),
                connection_id: row.connection_id.clone(),
                locked: row.locked,
                name: row.name.clone(),
                folder: row.folder.clone(),
                command: row.command.clone(),
            })
            .collect()
    }

    /// Builds the tree the way the rest of the app expects it.
    ///
    /// `private` is one's own private key, provided the vault is open. Without
    /// it the connections still come — just without their secrets, and the
    /// second return value says that some are missing.
    pub fn tree(&self, private: Option<&[u8; 32]>) -> (Vec<Project>, bool) {
        // Unwrap once instead of once per connection: a project has one key,
        // but possibly thirty connections.
        let mut keys: HashMap<(String, String), Secret32> = HashMap::new();
        if let Some(private) = private {
            for row in &self.project_keys {
                let id = (row.project_id.clone(), row.key_id.clone());
                if keys.contains_key(&id) {
                    continue;
                }
                if let Some(key) = self.unwrap_key(private, &row.project_id, &row.key_id) {
                    keys.insert(id, key);
                }
            }
        }

        let mut locked = false;
        let mut projects: Vec<&ApiProject> = self.projects.iter().collect();
        projects.sort_by_key(|project| (project.position, project.name.to_lowercase()));

        let tree = projects
            .into_iter()
            .map(|project| {
                let mut rows: Vec<&ApiConnection> = self
                    .connections
                    .iter()
                    .filter(|connection| connection.project_id == project.id)
                    .collect();
                rows.sort_by_key(|connection| {
                    (connection.position, connection.name.to_lowercase())
                });

                let connections = rows
                    .into_iter()
                    .filter_map(|row| {
                        let secret = self.secret(&row.id).filter(|s| s.deleted_at.is_none());
                        let plaintext = match secret {
                            None => None,
                            Some(secret) => {
                                let opened = keys
                                    .get(&(project.id.clone(), secret.key_id.clone()))
                                    .and_then(|key| open_secret(key, secret, &row.id));
                                if opened.is_none() {
                                    // Either the vault is closed, or a key
                                    // for this version was never wrapped
                                    // for us. The UI says both.
                                    locked = true;
                                }
                                opened
                            }
                        };

                        let settings = super::model::to_settings(row, plaintext).ok()?;
                        Some(Connection {
                            id: row.id.clone(),
                            name: row.name.clone(),
                            settings,
                            system: row.system.clone(),
                            bookmarked: row.bookmarked,
                            secret_unreadable: false,
                        })
                    })
                    .collect();

                Project {
                    id: project.id.clone(),
                    name: project.name.clone(),
                    connections,
                }
            })
            .collect();

        (tree, locked)
    }
}

fn open_secret(key: &Secret32, secret: &ApiSecret, connection_id: &str) -> Option<String> {
    let nonce = BASE64.decode(&secret.nonce).ok()?;
    let ciphertext = BASE64.decode(&secret.ciphertext).ok()?;
    // The `aad` is the `connectionId`: a ciphertext that a tampered server
    // moved from one connection to another does not open here.
    let plaintext = crypto::open(key, &nonce, &ciphertext, connection_id.as_bytes()).ok()?;
    String::from_utf8(plaintext).ok()
}

/// Merges a delta into a list: replace, append, or — for a tombstone —
/// remove.
fn merge<T, Id, Dead>(into: &mut Vec<T>, delta: Vec<T>, id: Id, dead: Dead)
where
    Id: Fn(&T) -> String,
    Dead: Fn(&T) -> bool,
{
    for row in delta {
        let key = id(&row);
        let at = into.iter().position(|existing| id(existing) == key);
        if dead(&row) {
            if let Some(at) = at {
                into.remove(at);
            }
            continue;
        }
        match at {
            Some(at) => into[at] = row,
            None => into.push(row),
        }
    }
}

// ---- The queue ---------------------------------------------------------------

/// A change that still has to go up.
///
/// It carries everything needed for uploading — in particular **finished
/// ciphertexts**, never plaintext. Otherwise the secret would lie in this file,
/// and all the effort around it would be for nothing. Encryption therefore
/// happens when enqueuing, not when sending.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "op", rename_all = "camelCase")]
pub enum Pending {
    /// The organization's name. Goes through better-auth, not through the tree.
    RenameWorkspace {
        name: String,
    },
    CreateProject {
        id: String,
        name: String,
        position: i64,
    },
    UpdateProject {
        id: String,
        name: String,
        position: i64,
        /// The revision the change builds on. If someone else has moved it on in
        /// the meantime, the server answers `409 R-CF`. `None` for a project
        /// whose creation is itself still in the queue, and for entries from
        /// before this check existed.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        expected_revision: Option<String>,
    },
    DeleteProject {
        id: String,
    },
    /// Wrapped versions of the project key. Comes **before** every secret of
    /// this project in the queue: the server rejects a `secret` with an unknown
    /// `keyId`, because a ciphertext nobody can open would be silent data
    /// loss.
    GrantKeys {
        project_id: String,
        key_id: String,
        grants: Vec<Grant>,
    },
    CreateConnection {
        project_id: String,
        connection: ApiConnection,
    },
    UpdateConnection {
        id: String,
        connection: ApiConnection,
        /// Wie bei [`Pending::UpdateProject`].
        #[serde(default, skip_serializing_if = "Option::is_none")]
        expected_revision: Option<String>,
    },
    DeleteConnection {
        id: String,
    },
    PutSecret {
        connection_id: String,
        key_id: String,
        /// base64.
        nonce: String,
        /// base64.
        ciphertext: String,
    },
    DeleteSecret {
        connection_id: String,
    },
    /// The workspace's vault account — 1Password or Bitwarden.
    PutVaultAccount {
        provider: VaultProvider,
        account: String,
        server: String,
        accept_invalid_cert: bool,
    },
    DeleteVaultAccount {
        provider: VaultProvider,
    },
    CreateSnippet {
        snippet: ApiSnippet,
    },
    UpdateSnippet {
        snippet: ApiSnippet,
        /// Wie bei [`Pending::UpdateProject`].
        #[serde(default, skip_serializing_if = "Option::is_none")]
        expected_revision: Option<String>,
    },
    DeleteSnippet {
        id: String,
    },
}

impl Pending {
    /// What the change is called in an error message.
    pub fn label(&self) -> String {
        let label = match self {
            Self::RenameWorkspace { name } => t!("cloud_sync.op_rename_workspace", name = name),
            Self::CreateProject { name, .. } => t!("cloud_sync.op_create_project", name = name),
            Self::UpdateProject { name, .. } => t!("cloud_sync.op_update_project", name = name),
            Self::DeleteProject { .. } => t!("cloud_sync.op_delete_project"),
            Self::GrantKeys { .. } => t!("cloud_sync.op_grant_keys"),
            Self::CreateConnection { connection, .. } => {
                t!("cloud_sync.op_create_connection", name = connection.name)
            }
            Self::UpdateConnection { connection, .. } => {
                t!("cloud_sync.op_update_connection", name = connection.name)
            }
            Self::DeleteConnection { .. } => t!("cloud_sync.op_delete_connection"),
            Self::PutSecret { .. } => t!("cloud_sync.op_put_secret"),
            Self::DeleteSecret { .. } => t!("cloud_sync.op_delete_secret"),
            Self::PutVaultAccount { .. } => t!("cloud_sync.op_put_vault_account"),
            Self::DeleteVaultAccount { .. } => t!("cloud_sync.op_delete_vault_account"),
            Self::CreateSnippet { snippet } => {
                t!("cloud_sync.op_create_snippet", name = snippet.name)
            }
            Self::UpdateSnippet { snippet, .. } => {
                t!("cloud_sync.op_update_snippet", name = snippet.name)
            }
            Self::DeleteSnippet { .. } => t!("cloud_sync.op_delete_snippet"),
        };
        label.into_owned()
    }
}

/// A wrapped project key for exactly one recipient, ready for upload.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Grant {
    pub user_id: String,
    pub ephemeral_public_key: String,
    pub nonce: String,
    pub wrapped_key: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cloud::model::{SshBody, WorkspaceRow};

    fn empty_workspace() -> Cached {
        Cached::new("org-1".into(), "acc-1".into(), "Company".into())
    }

    fn project(id: &str, revision: &str) -> ApiProject {
        ApiProject {
            id: id.into(),
            name: format!("Project {id}"),
            position: 0,
            created_by_id: None,
            revision: revision.into(),
            deleted_at: None,
        }
    }

    fn connection(id: &str, project_id: &str) -> ApiConnection {
        ApiConnection {
            id: id.into(),
            project_id: project_id.into(),
            name: id.into(),
            kind: "ssh".into(),
            bookmarked: false,
            position: 0,
            system: None,
            revision: "1".into(),
            deleted_at: None,
            ssh: Some(SshBody {
                host: "example".into(),
                port: 22,
                user: "root".into(),
                auth_source: "inlineKey".into(),
                key_file_path: None,
                vault_provider: None,
                vault_reference: None,
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

    fn delta(cached: &Cached, projects: Vec<ApiProject>, revision: &str) -> SyncResponse {
        SyncResponse {
            workspace: WorkspaceRow {
                id: cached.id.clone(),
                name: cached.name.clone(),
                slug: String::new(),
                kind: WorkspaceKind::Organization,
                role: Role::Owner,
                wirecloud_company: None,
            },
            revision: revision.into(),
            projects,
            connections: Vec::new(),
            secrets: Vec::new(),
            vault_accounts: Vec::new(),
            known_hosts: Vec::new(),
            project_keys: Vec::new(),
            shares: Vec::new(),
            snippets: Vec::new(),
        }
    }

    /// A tombstone is a message, not an entry. Whoever takes it in as a row
    /// keeps showing deleted projects forever.
    #[test]
    fn a_tombstone_removes_the_row() {
        let mut cached = empty_workspace();
        cached.apply(delta(&cached.clone(), vec![project("p1", "1")], "1"));
        assert_eq!(cached.projects.len(), 1);

        let mut dead = project("p1", "2");
        dead.deleted_at = Some("2026-09-20T00:00:00.000Z".into());
        cached.apply(delta(&cached.clone(), vec![dead], "2"));
        assert!(cached.projects.is_empty());
        assert_eq!(cached.revision, "2");
    }

    /// Whoever loses the share gets nothing at all for the project anymore —
    /// not even a tombstone for the connections under it. They would otherwise
    /// stay in the copy forever.
    #[test]
    fn connections_without_a_project_go_with_it() {
        let mut cached = empty_workspace();
        cached.projects.push(project("p1", "1"));
        cached.connections.push(connection("c1", "p1"));

        let mut dead = project("p1", "2");
        dead.deleted_at = Some("2026-09-20T00:00:00.000Z".into());
        cached.apply(delta(&cached.clone(), vec![dead], "2"));

        assert!(cached.connections.is_empty());
    }

    /// Shares always arrive in full. If they were merged, a revoked one could
    /// never be gotten rid of again.
    #[test]
    fn shares_are_replaced_instead_of_merged() {
        let mut cached = empty_workspace();
        cached.shares.push(ApiShare {
            id: "s1".into(),
            project_id: "p1".into(),
            team_id: Some("t1".into()),
            team_name: None,
            role: super::super::model::ShareRole::Editor,
        });

        cached.apply(delta(&cached.clone(), Vec::new(), "3"));
        assert!(cached.shares.is_empty());
    }

    /// A key that this client generated and has not uploaded yet is unknown to
    /// the server — and a sync must not clear it away, otherwise the secrets
    /// in the queue would be unreadable.
    #[test]
    fn a_key_not_yet_sent_survives_the_sync() {
        let mut cached = empty_workspace();
        cached.project_keys.push(ApiProjectKey {
            project_id: "p1".into(),
            user_id: "u1".into(),
            key_id: "k1".into(),
            algorithm: crypto::GRANT_ALGORITHM.into(),
            ephemeral_public_key: String::new(),
            nonce: String::new(),
            wrapped_key: String::new(),
        });
        cached.pending.push(Pending::GrantKeys {
            project_id: "p1".into(),
            key_id: "k1".into(),
            grants: Vec::new(),
        });

        cached.apply(delta(&cached.clone(), Vec::new(), "4"));
        assert_eq!(cached.project_keys.len(), 1);
    }

    /// And one that was deleted on the server disappears — that is the
    /// revocation, and it has to arrive.
    #[test]
    fn a_revoked_key_disappears() {
        let mut cached = empty_workspace();
        cached.project_keys.push(ApiProjectKey {
            project_id: "p1".into(),
            user_id: "u1".into(),
            key_id: "k1".into(),
            algorithm: crypto::GRANT_ALGORITHM.into(),
            ephemeral_public_key: String::new(),
            nonce: String::new(),
            wrapped_key: String::new(),
        });

        cached.apply(delta(&cached.clone(), Vec::new(), "4"));
        assert!(cached.project_keys.is_empty());
    }

    /// The whole way: encrypt, store, open.
    #[test]
    fn a_secret_comes_back_out_in_the_tree() {
        let pair = crypto::new_key_pair().expect("creates a pair");
        let pk = crypto::new_project_key().expect("creates a project key");
        let wrapped = crypto::wrap_project_key(&pk, &pair.public).expect("wraps");

        let mut cached = empty_workspace();
        cached.projects.push(project("p1", "1"));
        cached.connections.push(connection("c1", "p1"));
        cached.project_keys.push(ApiProjectKey {
            project_id: "p1".into(),
            user_id: "u1".into(),
            key_id: "k1".into(),
            algorithm: crypto::GRANT_ALGORITHM.into(),
            ephemeral_public_key: BASE64.encode(wrapped.ephemeral_public_key),
            nonce: BASE64.encode(&wrapped.nonce),
            wrapped_key: BASE64.encode(&wrapped.wrapped_key),
        });

        let nonce = crypto::new_nonce().expect("nonce");
        let ciphertext = crypto::seal(&pk, &nonce, b"PRIVATE KEY", b"c1").expect("seal");
        cached.secrets.push(ApiSecret {
            connection_id: "c1".into(),
            algorithm: crypto::SECRET_ALGORITHM.into(),
            key_id: "k1".into(),
            nonce: BASE64.encode(&nonce),
            ciphertext: BASE64.encode(&ciphertext),
            revision: "1".into(),
            deleted_at: None,
        });

        let (tree, missing) = cached.tree(Some(&pair.private));
        assert!(!missing);
        let settings = &tree[0].connections[0].settings;
        assert_eq!(
            super::super::model::secret_of(settings),
            Some("PRIVATE KEY")
        );

        // And locked: the row is there, the secret is not.
        let (tree, missing) = cached.tree(None);
        assert!(missing);
        assert_eq!(tree[0].connections.len(), 1);
        assert_eq!(
            super::super::model::secret_of(&tree[0].connections[0].settings),
            None
        );
    }

    /// New secrets go under the newest version this user owns themselves — one
    /// they do not have, they could never open again.
    #[test]
    fn the_current_version_is_the_last_own_one() {
        let mut cached = empty_workspace();
        assert_eq!(cached.current_key_id("p1"), None);

        for key_id in ["k1", "k2"] {
            cached.project_keys.push(ApiProjectKey {
                project_id: "p1".into(),
                user_id: "u1".into(),
                key_id: key_id.into(),
                algorithm: crypto::GRANT_ALGORITHM.into(),
                ephemeral_public_key: String::new(),
                nonce: String::new(),
                wrapped_key: String::new(),
            });
        }
        assert_eq!(cached.current_key_id("p1").as_deref(), Some("k2"));
    }

    /// The same connection changed twice before the first change is up: one
    /// entry, with the revision the first one built on. The second would
    /// otherwise have reported a conflict against the first.
    #[test]
    fn a_second_change_replaces_the_waiting_one() {
        let mut cached = empty_workspace();
        let mut first = connection("c1", "p1");
        first.name = "web02".into();
        cached.enqueue(vec![Pending::UpdateConnection {
            id: "c1".into(),
            connection: first,
            expected_revision: Some("7".into()),
        }]);

        let mut second = connection("c1", "p1");
        second.name = "web03".into();
        cached.enqueue(vec![Pending::UpdateConnection {
            id: "c1".into(),
            connection: second,
            expected_revision: Some("7".into()),
        }]);
        cached.enqueue(vec![Pending::UpdateConnection {
            id: "c2".into(),
            connection: connection("c2", "p1"),
            expected_revision: Some("9".into()),
        }]);

        assert_eq!(cached.pending.len(), 2);
        let Pending::UpdateConnection {
            connection,
            expected_revision,
            ..
        } = &cached.pending[0]
        else {
            panic!("the change to c1 is at the front");
        };
        assert_eq!(connection.name, "web03");
        assert_eq!(expected_revision.as_deref(), Some("7"));
    }

    /// A queue from before this check still reads — without a revision, so
    /// without a check, as before.
    #[test]
    fn an_old_queue_reads_without_a_revision() {
        let old = serde_json::json!({
            "op": "updateProject",
            "id": "p1",
            "name": "Production",
            "position": 0
        });
        let op: Pending = serde_json::from_value(old).expect("reads");
        assert!(matches!(
            op,
            Pending::UpdateProject {
                expected_revision: None,
                ..
            }
        ));
    }
}
