//! Turns "this is what the tree looks like now" into "this is what to do".
//!
//! The rest of the app only knows `workspaces_save` and sends the whole tree
//! every time. For a file that is right; for a backend someone else is also
//! working on, it would be an overwrite. So this compares what comes in with
//! what was last known — and turns that into the individual calls.
//!
//! This module has a say in two things, and both have to do with data loss:
//!
//! - **An empty secret is not a secret.** Whoever opens a locked workspace and
//!   changes something about a name would otherwise have replaced every
//!   ciphertext on the server with an empty string. See
//!   [`model::secret_of`] versus [`model::has_secret_source`].
//! - **Encryption happens when enqueuing, not when sending.** There is never
//!   plaintext in the queue — it is stored on disk.

use std::collections::HashSet;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use rust_i18n::t;

use super::account::Unlocked;
use super::cache::{Cached, Grant, Pending};
use super::crypto;
use super::model::{
    self, ApiConnection, ApiProject, ApiProjectKey, ApiSecret, ApiSnippet, ApiVaultAccount,
};
use crate::storage::{Connection, ConnectionSettings, Project, Workspace};
use crate::vault::VaultProvider;

/// Compares and enters the result into the copy right away.
///
/// So the copy is treated as if everything were already up — otherwise the
/// next load would show the old state again while the queue is still working.
/// What the server makes of it comes back with the next sync and then has the
/// last word.
pub fn plan(
    cached: &mut Cached,
    incoming: &Workspace,
    user_id: &str,
    unlocked: Option<&Unlocked>,
) -> Result<Vec<Pending>, String> {
    let mut ops = Vec::new();

    if cached.name != incoming.name {
        cached.name = incoming.name.clone();
        ops.push(Pending::RenameWorkspace {
            name: incoming.name.clone(),
        });
    }

    vault_accounts(cached, incoming, &mut ops);

    let private = unlocked.map(|open| &*open.private);
    let (current, _) = cached.tree(private);

    // After the projects: a new snippet needs its project and connection on
    // the server, and a deleted one should go only after the connections that
    // started with it have let go of it — otherwise the server takes it out
    // of them first, and their change would meet a newer revision.
    //
    // A startup command the server would not take yet — its snippet is new,
    // or becomes locked or this connection's only in this same go — waits for
    // a second pass after the snippets.
    let later = startups_for_later(cached, &current, incoming);
    projects(
        cached,
        &current,
        later.as_ref().unwrap_or(incoming),
        user_id,
        private,
        &mut ops,
    )?;
    snippets(cached, incoming, &mut ops);
    if later.is_some() {
        let (current, _) = cached.tree(private);
        projects(cached, &current, incoming, user_id, private, &mut ops)?;
    }

    Ok(ops)
}

/// The tree with the startup commands the server would refuse right now put
/// back to what they were — `None` if there are none. The server only takes
/// a locked snippet of the connection's project that is for all of its
/// connections or for this one; what the copy knows is what it has (or will
/// have, from the queue).
fn startups_for_later(
    cached: &Cached,
    current: &[Project],
    incoming: &Workspace,
) -> Option<Workspace> {
    let startup = |connection: &Connection| match &connection.settings {
        ConnectionSettings::Ssh(ssh) => ssh.startup_snippet.clone(),
        _ => None,
    };
    let before = |id: &str| {
        current
            .iter()
            .flat_map(|project| project.connections.iter())
            .find(|connection| connection.id == id)
            .and_then(startup)
    };
    let fits = |project_id: &str, connection_id: &str, snippet_id: &str| {
        cached.snippets.iter().any(|row| {
            row.id == snippet_id
                && row.deleted_at.is_none()
                && row.locked
                && match &row.connection_id {
                    Some(id) => id == connection_id,
                    None => row.project_id == project_id,
                }
        })
    };

    let mut later = incoming.clone();
    let mut any = false;
    for project in &mut later.projects {
        for connection in &mut project.connections {
            let was = before(&connection.id);
            if let ConnectionSettings::Ssh(ssh) = &mut connection.settings {
                if let Some(id) = &ssh.startup_snippet {
                    if was.as_deref() != Some(id.as_str()) && !fits(&project.id, &connection.id, id)
                    {
                        ssh.startup_snippet = was;
                        any = true;
                    }
                }
            }
        }
    }
    any.then_some(later)
}

// ---- Snippets ----------------------------------------------------------------

/// The order in the tree is the position. A snippet that is no longer in it is
/// deleted.
///
/// The project is not compared: a snippet does not change projects on its
/// own, only along with its connection — and that the server does itself.
fn snippets(cached: &mut Cached, incoming: &Workspace, ops: &mut Vec<Pending>) {
    let wanted: HashSet<&str> = incoming.snippets.iter().map(|s| s.id.as_str()).collect();
    let gone: Vec<String> = cached
        .snippets
        .iter()
        .filter(|row| !wanted.contains(row.id.as_str()))
        .map(|row| row.id.clone())
        .collect();
    for id in gone {
        cached.snippets.retain(|row| row.id != id);
        ops.push(Pending::DeleteSnippet { id });
    }

    for (position, snippet) in incoming.snippets.iter().enumerate() {
        let row = ApiSnippet {
            id: snippet.id.clone(),
            project_id: snippet.project_id.clone(),
            connection_id: snippet.connection_id.clone(),
            locked: snippet.locked,
            name: snippet.name.clone(),
            folder: snippet.folder.clone(),
            command: snippet.command.clone(),
            position: position as i64,
            revision: String::new(),
            deleted_at: None,
        };
        let existing = cached.snippets.iter().position(|r| r.id == snippet.id);
        match existing {
            None => {
                cached.snippets.push(row.clone());
                ops.push(Pending::CreateSnippet { snippet: row });
            }
            Some(at) => {
                let known = &cached.snippets[at];
                let changed = known.name != row.name
                    || known.connection_id != row.connection_id
                    || known.locked != row.locked
                    || known.folder != row.folder
                    || known.command != row.command
                    || known.position != row.position;
                if !changed {
                    continue;
                }
                let expected_revision = expected(cached, &row.id, &known.revision);
                let revision = known.revision.clone();
                cached.snippets[at] = ApiSnippet {
                    revision,
                    project_id: known.project_id.clone(),
                    ..row.clone()
                };
                ops.push(Pending::UpdateSnippet {
                    snippet: row,
                    expected_revision,
                });
            }
        }
    }
}

// ---- Vault accounts ----------------------------------------------------------

fn vault_accounts(cached: &mut Cached, incoming: &Workspace, ops: &mut Vec<Pending>) {
    let one_password = incoming.one_password_account.trim().to_string();
    if cached.one_password_account() != one_password {
        set_vault_account(
            cached,
            ops,
            VaultProvider::OnePassword,
            &one_password,
            "",
            false,
        );
    }

    let bitwarden = incoming
        .bitwarden
        .clone()
        .filter(|account| !account.is_empty());
    let current = cached.bitwarden_account();
    let same = match (&current, &bitwarden) {
        (Some(a), Some(b)) => {
            a.email == b.email
                && a.server == b.server
                && a.accept_invalid_cert == b.accept_invalid_cert
        }
        (None, None) => true,
        _ => false,
    };
    if !same {
        let account = bitwarden.unwrap_or_default();
        set_vault_account(
            cached,
            ops,
            VaultProvider::Bitwarden,
            &account.email,
            &account.server,
            account.accept_invalid_cert,
        );
    }
}

fn set_vault_account(
    cached: &mut Cached,
    ops: &mut Vec<Pending>,
    provider: VaultProvider,
    account: &str,
    server: &str,
    accept_invalid_cert: bool,
) {
    cached.vault_accounts.retain(|row| row.provider != provider);

    // "No account" and "an account without a name" are the same, and only one
    // of them belongs in the database.
    if account.trim().is_empty() {
        ops.push(Pending::DeleteVaultAccount { provider });
        return;
    }

    cached.vault_accounts.push(ApiVaultAccount {
        id: String::new(),
        provider,
        account: account.to_string(),
        server: server.to_string(),
        accept_invalid_cert,
        revision: cached.revision.clone(),
        deleted_at: None,
    });
    ops.push(Pending::PutVaultAccount {
        provider,
        account: account.to_string(),
        server: server.to_string(),
        accept_invalid_cert,
    });
}

// ---- Projects ----------------------------------------------------------------

fn projects(
    cached: &mut Cached,
    current: &[Project],
    incoming: &Workspace,
    user_id: &str,
    private: Option<&[u8; 32]>,
    ops: &mut Vec<Pending>,
) -> Result<(), String> {
    // Where each connection is now, and where it was before: one that
    // disappears from one project and shows up in another has been moved —
    // not deleted and created anew.
    let incoming_ids: HashSet<&str> = incoming
        .projects
        .iter()
        .flat_map(|project| project.connections.iter())
        .map(|connection| connection.id.as_str())
        .collect();
    let everywhere: Vec<&Connection> = current
        .iter()
        .flat_map(|project| project.connections.iter())
        .collect();

    // A deleted project takes its connections with it. The deletion therefore
    // goes up **last**: a connection that was pulled out beforehand has to
    // have moved first.
    let mut deleted = Vec::new();
    for project in current {
        if !incoming.projects.iter().any(|row| row.id == project.id) {
            cached.projects.retain(|row| row.id != project.id);
            cached
                .connections
                .retain(|row| row.project_id != project.id);
            cached.secrets.retain(|row| {
                project
                    .connections
                    .iter()
                    .all(|c| c.id != row.connection_id)
            });
            deleted.push(Pending::DeleteProject {
                id: project.id.clone(),
            });
        }
    }

    for (position, project) in incoming.projects.iter().enumerate() {
        let position = position as i64;
        let known = current.iter().find(|row| row.id == project.id);

        match known {
            None => {
                cached.projects.push(ApiProject {
                    id: project.id.clone(),
                    name: project.name.clone(),
                    position,
                    created_by_id: Some(user_id.to_string()),
                    revision: cached.revision.clone(),
                    deleted_at: None,
                });
                ops.push(Pending::CreateProject {
                    id: project.id.clone(),
                    name: project.name.clone(),
                    position,
                });

                // A new project needs a project key before the first secret can
                // be stored under it — and that key is created here, not on the
                // server.
                new_project_key(cached, &project.id, user_id, private, ops)?;
            }
            Some(_) => {
                let row = cached
                    .project(&project.id)
                    .cloned()
                    .ok_or_else(|| t!("cloud_sync.project_missing_from_cache").into_owned())?;
                if row.name != project.name || row.position != position {
                    if let Some(entry) = cached.projects.iter_mut().find(|p| p.id == project.id) {
                        entry.name = project.name.clone();
                        entry.position = position;
                    }
                    ops.push(Pending::UpdateProject {
                        id: project.id.clone(),
                        name: project.name.clone(),
                        position,
                        expected_revision: expected(cached, &project.id, &row.revision),
                    });
                }
            }
        }

        let empty = Vec::new();
        let was = known.map(|row| &row.connections).unwrap_or(&empty);
        connections(
            cached,
            was,
            &everywhere,
            &incoming_ids,
            project,
            private,
            ops,
        )?;
    }

    ops.extend(deleted);
    Ok(())
}

/// Generates a project key and wraps it for oneself.
///
/// For oneself first and for others later: whoever has a share but no key yet
/// is listed in `…/key-requests` — and that list is caught up on every sync.
/// Waiting for all members here would mean not being able to create any
/// project at all while offline.
fn new_project_key(
    cached: &mut Cached,
    project_id: &str,
    user_id: &str,
    private: Option<&[u8; 32]>,
    ops: &mut Vec<Pending>,
) -> Result<(), String> {
    let Some(private) = private else {
        return Err(locked());
    };
    let public = crypto::public_key_of(private);

    let key_id = uuid::Uuid::new_v4().to_string();
    let key = crypto::new_project_key()?;
    let wrapped = crypto::wrap_project_key(&key, &public)?;

    let grant = Grant {
        user_id: user_id.to_string(),
        ephemeral_public_key: BASE64.encode(wrapped.ephemeral_public_key),
        nonce: BASE64.encode(&wrapped.nonce),
        wrapped_key: BASE64.encode(&wrapped.wrapped_key),
    };

    // Into the copy as well, not only into the queue: otherwise the secrets
    // enqueued right behind it would be unreadable after a restart before the
    // upload.
    cached.project_keys.push(ApiProjectKey {
        project_id: project_id.to_string(),
        user_id: user_id.to_string(),
        key_id: key_id.clone(),
        algorithm: crypto::GRANT_ALGORITHM.to_string(),
        ephemeral_public_key: grant.ephemeral_public_key.clone(),
        nonce: grant.nonce.clone(),
        wrapped_key: grant.wrapped_key.clone(),
    });

    ops.push(Pending::GrantKeys {
        project_id: project_id.to_string(),
        key_id,
        grants: vec![grant],
    });
    Ok(())
}

// ---- Connections -------------------------------------------------------------

fn connections(
    cached: &mut Cached,
    was: &[Connection],
    everywhere: &[&Connection],
    incoming_ids: &HashSet<&str>,
    project: &Project,
    private: Option<&[u8; 32]>,
    ops: &mut Vec<Pending>,
) -> Result<(), String> {
    for connection in was {
        // If it is in another project, it has moved — the project it is in now
        // takes care of that.
        if !incoming_ids.contains(connection.id.as_str()) {
            cached.connections.retain(|row| row.id != connection.id);
            cached
                .secrets
                .retain(|row| row.connection_id != connection.id);
            ops.push(Pending::DeleteConnection {
                id: connection.id.clone(),
            });
        }
    }

    for (position, connection) in project.connections.iter().enumerate() {
        let position = position as i64;
        let here = was.iter().find(|row| row.id == connection.id);
        // Moved here from another project.
        let moved_from = match here {
            Some(_) => None,
            None => everywhere
                .iter()
                .copied()
                .find(|row| row.id == connection.id),
        };
        let known = here.or(moved_from);
        let moved = moved_from.is_some();
        let row = api_connection(connection, &project.id, position)?;

        match known {
            None => {
                cached.connections.push(row.clone());
                ops.push(Pending::CreateConnection {
                    project_id: project.id.clone(),
                    connection: row.clone(),
                });
            }
            Some(known) => {
                let before = cached
                    .connection(&connection.id)
                    .map(|entry| entry.position)
                    .unwrap_or(position);
                // The tree is compared, not the server row: the secret is in
                // the settings, and that is exactly what matters.
                let same = !moved && same_connection(known, connection) && before == position;
                if !same {
                    let mut revision = String::new();
                    match cached
                        .connections
                        .iter_mut()
                        .find(|c| c.id == connection.id)
                    {
                        Some(entry) => {
                            revision = entry.revision.clone();
                            *entry = row.clone();
                            entry.revision = revision.clone();
                        }
                        // Its old project was deleted in the same go and took
                        // it out of the copy along with it.
                        None => cached.connections.push(row.clone()),
                    }
                    ops.push(Pending::UpdateConnection {
                        id: connection.id.clone(),
                        connection: row.clone(),
                        expected_revision: expected(cached, &connection.id, &revision),
                    });
                }
            }
        }

        secret(cached, known, connection, &project.id, private, ops, moved)?;
    }

    Ok(())
}

/// The revision a change builds on — provided the copy has one from the
/// server. A row whose creation is still waiting carries only a placeholder;
/// the server would not know it and would report a conflict that does not
/// exist.
fn expected(cached: &Cached, id: &str, revision: &str) -> Option<String> {
    if revision.is_empty() || cached.creation_pending(id) {
        return None;
    }
    Some(revision.to_string())
}

/// Whether two connections are the same.
///
/// Via the serialized form instead of field by field: the settings are a
/// tagged enum with three variants, each with its own authentication, and a
/// new connection type should not require any change here.
fn same_connection(a: &Connection, b: &Connection) -> bool {
    serde_json::to_value(a).ok() == serde_json::to_value(b).ok()
}

fn api_connection(
    connection: &Connection,
    project_id: &str,
    position: i64,
) -> Result<ApiConnection, String> {
    let (ssh, ftp, s3) = model::bodies_of(&connection.settings);
    Ok(ApiConnection {
        id: connection.id.clone(),
        project_id: project_id.to_string(),
        name: connection.name.clone(),
        kind: model::type_of(&connection.settings).to_string(),
        bookmarked: connection.bookmarked,
        position,
        system: connection.system.clone(),
        revision: String::new(),
        deleted_at: None,
        ssh,
        ftp,
        s3,
    })
}

// ---- Secrets -----------------------------------------------------------------

/// Decides whether the ciphertext on the server is to be renewed, deleted or
/// left alone.
///
/// The third case is the most important one and the only one that is not
/// obvious: a field that is empty *because the vault was closed* looks exactly
/// like one that someone has cleared. That is why the source decides, not the
/// value — an `inlineKey` without content leaves it in place, a switch to
/// `keyFile` clears it away.
fn secret(
    cached: &mut Cached,
    known: Option<&Connection>,
    connection: &Connection,
    project_id: &str,
    private: Option<&[u8; 32]>,
    ops: &mut Vec<Pending>,
    moved: bool,
) -> Result<(), String> {
    let has_source = model::has_secret_source(&connection.settings);
    let stored = cached
        .secret(&connection.id)
        .filter(|row| row.deleted_at.is_none())
        .is_some();

    if !has_source {
        if stored {
            cached
                .secrets
                .retain(|row| row.connection_id != connection.id);
            ops.push(Pending::DeleteSecret {
                connection_id: connection.id.clone(),
            });
        }
        return Ok(());
    }

    let Some(plaintext) = model::secret_of(&connection.settings) else {
        // Moved, but locked: the ciphertext is under the old project's key,
        // and nobody in the new one can open it. Better not to move at all
        // than like that.
        if moved && stored {
            return Err(locked());
        }
        // A source with a secret, but none at hand: loaded locked. The
        // ciphertext stays where it is.
        return Ok(());
    };

    let before = known.and_then(|row| model::secret_of(&row.settings));
    // Unchanged and already up — only the rest of the connection has changed.
    // Uploading again would be a new nonce for the same bytes and good for
    // nothing. Except after a move: then it belongs under the new project's
    // key.
    if before == Some(plaintext) && stored && !moved {
        return Ok(());
    }

    let Some(private) = private else {
        return Err(locked());
    };
    let key_id = cached
        .current_key_id(project_id)
        .ok_or_else(|| t!("cloud_sync.no_project_key").into_owned())?;
    let key = cached
        .unwrap_key(private, project_id, &key_id)
        .ok_or_else(|| t!("cloud_sync.project_key_unwrap_failed").into_owned())?;

    let nonce = crypto::new_nonce()?;
    // The `aad` is the `connectionId`. It has to be fixed from the start —
    // introducing it later would mean re-encrypting everything.
    let ciphertext = crypto::seal(&key, &nonce, plaintext.as_bytes(), connection.id.as_bytes())?;

    let nonce = BASE64.encode(&nonce);
    let ciphertext = BASE64.encode(&ciphertext);

    cached
        .secrets
        .retain(|row| row.connection_id != connection.id);
    cached.secrets.push(ApiSecret {
        connection_id: connection.id.clone(),
        algorithm: crypto::SECRET_ALGORITHM.to_string(),
        key_id: key_id.clone(),
        nonce: nonce.clone(),
        ciphertext: ciphertext.clone(),
        revision: cached.revision.clone(),
        deleted_at: None,
    });
    ops.push(Pending::PutSecret {
        connection_id: connection.id.clone(),
        key_id,
        nonce,
        ciphertext,
    });
    Ok(())
}

fn locked() -> String {
    t!("cloud_sync.vault_locked").into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cloud::model::{ShareRole, WorkspaceKind};
    use crate::storage::{ConnectionSettings, SshAuth, SshSettings, StorageKind};

    fn vault() -> (Unlocked, [u8; 32]) {
        let pair = crypto::new_key_pair().expect("creates a pair");
        let public = pair.public;
        (Unlocked::new(pair.private, public), public)
    }

    fn copy() -> Cached {
        Cached::new("org-1".into(), "acc-1".into(), "Company".into())
    }

    fn ssh(key: &str) -> ConnectionSettings {
        ConnectionSettings::Ssh(SshSettings {
            host: "web01.example".into(),
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
        })
    }

    fn tree_of(projects: Vec<Project>) -> Workspace {
        Workspace {
            id: "org-1".into(),
            name: "Company".into(),
            storage: StorageKind::Cloud,
            one_password_account: String::new(),
            bitwarden: None,
            remote: None,
            projects,
            snippets: Vec::new(),
        }
    }

    fn connection(id: &str, name: &str, settings: ConnectionSettings) -> Connection {
        Connection {
            id: id.into(),
            name: name.into(),
            settings,
            system: None,
            bookmarked: false,
            secret_unreadable: false,
        }
    }

    /// A new project brings its key along — and that key comes **before** the
    /// secret in the queue, because the server rejects a `secret` with an
    /// unknown `keyId`.
    #[test]
    fn a_new_project_brings_its_key_along() {
        let (open, _) = vault();
        let mut cached = copy();

        let tree = tree_of(vec![Project {
            id: "p1".into(),
            name: "Production".into(),
            connections: vec![connection("c1", "web01", ssh("PRIVATE KEY"))],
        }]);

        let ops = plan(&mut cached, &tree, "u1", Some(&open)).expect("plans");

        let names: Vec<&str> = ops
            .iter()
            .map(|op| match op {
                Pending::CreateProject { .. } => "project",
                Pending::GrantKeys { .. } => "key",
                Pending::CreateConnection { .. } => "connection",
                Pending::PutSecret { .. } => "secret",
                _ => "other",
            })
            .collect();
        assert_eq!(names, vec!["project", "key", "connection", "secret"]);
    }

    fn snippet(id: &str, command: &str) -> crate::storage::Snippet {
        crate::storage::Snippet {
            id: id.into(),
            project_id: "p1".into(),
            connection_id: None,
            locked: true,
            name: id.into(),
            folder: String::new(),
            command: command.into(),
        }
    }

    /// Only the snippet operations, in their order.
    fn snippet_ops(ops: &[Pending]) -> Vec<&Pending> {
        ops.iter()
            .filter(|op| {
                matches!(
                    op,
                    Pending::CreateSnippet { .. }
                        | Pending::UpdateSnippet { .. }
                        | Pending::DeleteSnippet { .. }
                )
            })
            .collect()
    }

    /// Create, update with the revision the change builds on, and delete — and
    /// a mere reordering is a change.
    #[test]
    fn snippets_are_created_updated_and_deleted() {
        let (open, _) = vault();
        let mut cached = copy();

        let mut tree = tree_of(vec![Project {
            id: "p1".into(),
            name: "Production".into(),
            connections: Vec::new(),
        }]);
        tree.snippets = vec![snippet("s1", "uptime"), snippet("s2", "df -h")];
        let ops = plan(&mut cached, &tree, "u1", Some(&open)).expect("plans");
        assert!(matches!(
            snippet_ops(&ops).as_slice(),
            [Pending::CreateSnippet { .. }, Pending::CreateSnippet { .. }]
        ));

        // As after the sync: the server has assigned revisions.
        cached.pending.clear();
        for row in &mut cached.snippets {
            row.revision = "7".into();
        }
        for row in &mut cached.projects {
            row.revision = "7".into();
        }

        tree.snippets = vec![snippet("s2", "df -h"), snippet("s1", "uptime -p")];
        let ops = plan(&mut cached, &tree, "u1", Some(&open)).expect("plans");
        let seen: Vec<_> = snippet_ops(&ops)
            .into_iter()
            .map(|op| match op {
                Pending::UpdateSnippet {
                    snippet,
                    expected_revision,
                } => (
                    snippet.id.as_str(),
                    snippet.position,
                    expected_revision.as_deref(),
                ),
                _ => ("other", -1, None),
            })
            .collect();
        assert_eq!(seen, [("s2", 0, Some("7")), ("s1", 1, Some("7"))]);

        tree.snippets = vec![snippet("s1", "uptime -p")];
        let ops = plan(&mut cached, &tree, "u1", Some(&open)).expect("plans");
        assert!(matches!(
            snippet_ops(&ops).as_slice(),
            [Pending::DeleteSnippet { id }, Pending::UpdateSnippet { .. }] if id == "s2"
        ));
        assert_eq!(cached.snippet_list().len(), 1);
    }

    /// Locking and binding to a connection are changes; the project is not —
    /// it only changes along with the connection, on the server.
    #[test]
    fn a_snippet_is_changed_by_lock_and_connection_but_not_by_project() {
        let (open, _) = vault();
        let mut cached = copy();
        let mut tree = tree_of(vec![Project {
            id: "p1".into(),
            name: "Production".into(),
            connections: vec![connection("c1", "web01", ssh("KEY"))],
        }]);
        tree.snippets = vec![snippet("s1", "uptime")];
        plan(&mut cached, &tree, "u1", Some(&open)).expect("plans");
        cached.pending.clear();

        tree.snippets[0].project_id = "p2".into();
        let ops = plan(&mut cached, &tree, "u1", Some(&open)).expect("plans");
        assert!(snippet_ops(&ops).is_empty());

        tree.snippets[0].locked = false;
        tree.snippets[0].connection_id = Some("c1".into());
        let ops = plan(&mut cached, &tree, "u1", Some(&open)).expect("plans");
        assert!(matches!(
            snippet_ops(&ops).as_slice(),
            [Pending::UpdateSnippet { snippet, .. }]
                if !snippet.locked && snippet.connection_id.as_deref() == Some("c1")
        ));
    }

    fn startup_of(connection: &model::ApiConnection) -> Option<String> {
        serde_json::to_value(connection).ok()?["ssh"]["startupSnippetId"]
            .as_str()
            .map(str::to_string)
    }

    /// The snippets come after the connections: a new one needs its
    /// connection on the server. A startup command that points at it waits
    /// for it — the connection goes up without, and gets it afterwards.
    #[test]
    fn snippets_follow_the_connections_and_a_startup_command_follows_its_snippet() {
        let (open, _) = vault();
        let mut cached = copy();
        let mut settings = ssh("KEY");
        if let ConnectionSettings::Ssh(ssh) = &mut settings {
            ssh.startup_snippet = Some("s1".into());
        }
        let mut tree = tree_of(vec![Project {
            id: "p1".into(),
            name: "Production".into(),
            connections: vec![connection("c1", "web01", settings)],
        }]);
        tree.snippets = vec![crate::storage::Snippet {
            connection_id: Some("c1".into()),
            ..snippet("s1", "uptime")
        }];
        let ops = plan(&mut cached, &tree, "u1", Some(&open)).expect("plans");
        let order: Vec<_> = ops
            .iter()
            .filter_map(|op| match op {
                Pending::CreateConnection { connection, .. } => {
                    Some(("create connection", startup_of(connection)))
                }
                Pending::CreateSnippet { .. } => Some(("create snippet", None)),
                Pending::UpdateConnection { connection, .. } => {
                    Some(("update connection", startup_of(connection)))
                }
                _ => None,
            })
            .collect();
        assert_eq!(
            order,
            [
                ("create connection", None),
                ("create snippet", None),
                ("update connection", Some("s1".to_string())),
            ]
        );
    }

    /// Deleting a startup snippet: the connection lets go of it first.
    #[test]
    fn a_deleted_startup_snippet_goes_after_the_connection_let_go() {
        let (open, _) = vault();
        let mut cached = copy();
        let mut settings = ssh("KEY");
        if let ConnectionSettings::Ssh(ssh) = &mut settings {
            ssh.startup_snippet = Some("s1".into());
        }
        let mut tree = tree_of(vec![Project {
            id: "p1".into(),
            name: "Production".into(),
            connections: vec![connection("c1", "web01", settings)],
        }]);
        tree.snippets = vec![snippet("s1", "uptime")];
        plan(&mut cached, &tree, "u1", Some(&open)).expect("plans");
        cached.pending.clear();

        if let ConnectionSettings::Ssh(ssh) = &mut tree.projects[0].connections[0].settings {
            ssh.startup_snippet = None;
        }
        tree.snippets.clear();
        let ops = plan(&mut cached, &tree, "u1", Some(&open)).expect("plans");
        let update = ops
            .iter()
            .position(|op| matches!(op, Pending::UpdateConnection { .. }))
            .expect("updates the connection");
        let delete = ops
            .iter()
            .position(|op| matches!(op, Pending::DeleteSnippet { .. }))
            .expect("deletes the snippet");
        assert!(update < delete);
    }

    /// And afterwards it comes back out when loading — the copy has been kept
    /// as if everything were already up.
    #[test]
    fn after_planning_everything_is_already_in_the_copy() {
        let (open, _) = vault();
        let mut cached = copy();

        let tree = tree_of(vec![Project {
            id: "p1".into(),
            name: "Production".into(),
            connections: vec![connection("c1", "web01", ssh("PRIVATE KEY"))],
        }]);
        plan(&mut cached, &tree, "u1", Some(&open)).expect("plans");

        let (projects, missing) = cached.tree(Some(&open.private));
        assert!(!missing);
        assert_eq!(
            model::secret_of(&projects[0].connections[0].settings),
            Some("PRIVATE KEY")
        );
    }

    /// The case that would have deleted every ciphertext on the server without
    /// this distinction: loaded locked, something changed in a name, saved.
    #[test]
    fn a_tree_loaded_locked_deletes_no_secret() {
        let (open, _) = vault();
        let mut cached = copy();

        let tree = tree_of(vec![Project {
            id: "p1".into(),
            name: "Production".into(),
            connections: vec![connection("c1", "web01", ssh("PRIVATE KEY"))],
        }]);
        plan(&mut cached, &tree, "u1", Some(&open)).expect("plans");
        cached.pending.clear();

        // This is what the tree looks like when it was loaded locked: the row
        // is there, the field empty.
        let (locked, missing) = cached.tree(None);
        assert!(missing);
        let mut changed = tree_of(locked);
        changed.projects[0].connections[0].name = "web02".into();

        let ops = plan(&mut cached, &changed, "u1", None).expect("plans even when locked");

        assert!(ops
            .iter()
            .any(|op| matches!(op, Pending::UpdateConnection { .. })));
        assert!(!ops
            .iter()
            .any(|op| matches!(op, Pending::DeleteSecret { .. } | Pending::PutSecret { .. })));
        assert!(cached.secret("c1").is_some());
    }

    /// A change names the revision it builds on. If someone else has changed
    /// the connection in the meantime, the server rejects it instead of
    /// silently overwriting their version.
    #[test]
    fn a_change_builds_on_the_servers_revision() {
        let (open, _) = vault();
        let mut cached = copy();

        let tree = tree_of(vec![Project {
            id: "p1".into(),
            name: "Production".into(),
            connections: vec![connection("c1", "web01", ssh("PRIVATE KEY"))],
        }]);
        plan(&mut cached, &tree, "u1", Some(&open)).expect("plans");
        cached.pending.clear();
        // This is how it stands after the sync.
        cached.connections[0].revision = "41".into();
        cached.projects[0].revision = "40".into();

        let mut changed = tree.clone();
        changed.projects[0].name = "Production old".into();
        changed.projects[0].connections[0].name = "web02".into();

        let ops = plan(&mut cached, &changed, "u1", Some(&open)).expect("plans");
        assert!(ops.iter().any(|op| matches!(
            op,
            Pending::UpdateConnection { expected_revision: Some(r), .. } if r == "41"
        )));
        assert!(ops.iter().any(|op| matches!(
            op,
            Pending::UpdateProject { expected_revision: Some(r), .. } if r == "40"
        )));
    }

    /// As long as the creation is still in the queue, the row has no revision
    /// from the server — and a change on top of it must not invent one.
    #[test]
    fn while_the_creation_is_waiting_there_is_no_revision() {
        let (open, _) = vault();
        let mut cached = copy();

        let tree = tree_of(vec![Project {
            id: "p1".into(),
            name: "Production".into(),
            connections: vec![connection("c1", "web01", ssh("PRIVATE KEY"))],
        }]);
        let ops = plan(&mut cached, &tree, "u1", Some(&open)).expect("plans");
        cached.enqueue(ops);

        let mut changed = tree.clone();
        changed.projects[0].name = "Production old".into();
        changed.projects[0].connections[0].name = "web02".into();

        let ops = plan(&mut cached, &changed, "u1", Some(&open)).expect("plans");
        assert!(ops.iter().any(|op| matches!(
            op,
            Pending::UpdateConnection {
                expected_revision: None,
                ..
            }
        )));
        assert!(ops.iter().any(|op| matches!(
            op,
            Pending::UpdateProject {
                expected_revision: None,
                ..
            }
        )));
    }

    /// A change of source, on the other hand, clears the ciphertext away — there
    /// the empty field is meant and not merely unavailable.
    #[test]
    fn switching_to_a_file_clears_the_ciphertext() {
        let (open, _) = vault();
        let mut cached = copy();

        let tree = tree_of(vec![Project {
            id: "p1".into(),
            name: "Production".into(),
            connections: vec![connection("c1", "web01", ssh("PRIVATE KEY"))],
        }]);
        plan(&mut cached, &tree, "u1", Some(&open)).expect("plans");
        cached.pending.clear();

        let mut changed = tree.clone();
        changed.projects[0].connections[0].settings = ConnectionSettings::Ssh(SshSettings {
            host: "web01.example".into(),
            port: 22,
            user: "root".into(),
            auth: SshAuth::KeyFile {
                path: "C:/keys/id_ed25519".into(),
            },
            start_path: String::new(),
            jump: None,
            agent_forwarding: false,
            via: Vec::new(),
            forwards: Vec::new(),
            proxy: None,
            startup_snippet: None,
        });

        let ops = plan(&mut cached, &changed, "u1", Some(&open)).expect("plans");
        assert!(ops
            .iter()
            .any(|op| matches!(op, Pending::DeleteSecret { .. })));
        assert!(cached.secret("c1").is_none());
    }

    /// A connection that is dragged into another project is updated there — not
    /// deleted and created anew — and its secret goes under the new project's
    /// key.
    #[test]
    fn a_moved_connection_takes_its_secret_along() {
        let (open, _) = vault();
        let mut cached = copy();

        let tree = tree_of(vec![
            Project {
                id: "p1".into(),
                name: "Old".into(),
                connections: vec![connection("c1", "web01", ssh("PRIVATE KEY"))],
            },
            Project {
                id: "p2".into(),
                name: "New".into(),
                connections: vec![],
            },
        ]);
        plan(&mut cached, &tree, "u1", Some(&open)).expect("plans");
        cached.pending.clear();

        let mut changed = tree.clone();
        let moving = changed.projects[0].connections.remove(0);
        changed.projects[1].connections.push(moving);

        let ops = plan(&mut cached, &changed, "u1", Some(&open)).expect("plans");
        assert!(
            !ops.iter().any(|op| matches!(
                op,
                Pending::DeleteConnection { .. } | Pending::CreateConnection { .. }
            )),
            "{ops:?}"
        );
        assert!(ops.iter().any(|op| matches!(
            op,
            Pending::UpdateConnection { connection, .. } if connection.project_id == "p2"
        )));
        let new_key = cached.current_key_id("p2").expect("p2 has a key");
        assert!(ops.iter().any(|op| matches!(
            op,
            Pending::PutSecret { key_id, .. } if *key_id == new_key
        )));
    }

    /// While locked, a connection with a secret cannot be moved: the secret
    /// would then lie under a key that nobody in the new project has.
    #[test]
    fn nothing_is_moved_while_locked() {
        let (open, _) = vault();
        let mut cached = copy();
        let tree = tree_of(vec![
            Project {
                id: "p1".into(),
                name: "Old".into(),
                connections: vec![connection("c1", "web01", ssh("PRIVATE KEY"))],
            },
            Project {
                id: "p2".into(),
                name: "New".into(),
                connections: vec![],
            },
        ]);
        plan(&mut cached, &tree, "u1", Some(&open)).expect("plans");
        cached.pending.clear();

        let (locked, _) = cached.tree(None);
        let mut changed = tree_of(locked);
        let moving = changed.projects[0].connections.remove(0);
        changed.projects[1].connections.push(moving);

        assert!(plan(&mut cached, &changed, "u1", None).is_err());
    }

    /// The SSH agent has no more of a secret than a file does — the ciphertext
    /// goes just the same.
    #[test]
    fn switching_to_the_agent_clears_the_ciphertext() {
        let (open, _) = vault();
        let mut cached = copy();

        let tree = tree_of(vec![Project {
            id: "p1".into(),
            name: "Production".into(),
            connections: vec![connection("c1", "web01", ssh("PRIVATE KEY"))],
        }]);
        plan(&mut cached, &tree, "u1", Some(&open)).expect("plans");
        cached.pending.clear();

        let mut changed = tree.clone();
        changed.projects[0].connections[0].settings = ConnectionSettings::Ssh(SshSettings {
            host: "web01.example".into(),
            port: 22,
            user: "root".into(),
            auth: SshAuth::Agent,
            start_path: String::new(),
            jump: None,
            agent_forwarding: false,
            via: Vec::new(),
            forwards: Vec::new(),
            proxy: None,
            startup_snippet: None,
        });

        let ops = plan(&mut cached, &changed, "u1", Some(&open)).expect("plans");
        assert!(ops
            .iter()
            .any(|op| matches!(op, Pending::DeleteSecret { .. })));
        assert!(cached.secret("c1").is_none());
    }

    /// A second save without changes must yield nothing — otherwise every time
    /// a form is opened, one more revision would be written.
    #[test]
    fn without_changes_there_is_nothing_to_do() {
        let (open, _) = vault();
        let mut cached = copy();

        let tree = tree_of(vec![Project {
            id: "p1".into(),
            name: "Production".into(),
            connections: vec![connection("c1", "web01", ssh("PRIVATE KEY"))],
        }]);
        plan(&mut cached, &tree, "u1", Some(&open)).expect("plans");

        let ops = plan(&mut cached, &tree, "u1", Some(&open)).expect("plans again");
        assert!(ops.is_empty(), "{ops:?}");
    }

    /// A changed secret goes up with a new nonce, and the plaintext stays
    /// invisible in the queue while doing so.
    #[test]
    fn a_changed_secret_goes_into_the_queue_encrypted() {
        let (open, _) = vault();
        let mut cached = copy();

        let tree = tree_of(vec![Project {
            id: "p1".into(),
            name: "Production".into(),
            connections: vec![connection("c1", "web01", ssh("OLD"))],
        }]);
        plan(&mut cached, &tree, "u1", Some(&open)).expect("plans");

        let mut changed = tree.clone();
        changed.projects[0].connections[0].settings = ssh("NEW");
        let ops = plan(&mut cached, &changed, "u1", Some(&open)).expect("plans");

        let written = serde_json::to_string(&ops).expect("serializes");
        assert!(written.contains("putSecret"));
        assert!(
            !written.contains("NEW"),
            "plaintext in the queue: {written}"
        );
    }

    /// A deleted project takes its connections with it — their individual
    /// calls would all be in vain afterwards.
    #[test]
    fn a_deleted_project_takes_its_connections_with_it() {
        let (open, _) = vault();
        let mut cached = copy();

        let tree = tree_of(vec![Project {
            id: "p1".into(),
            name: "Production".into(),
            connections: vec![connection("c1", "web01", ssh("X"))],
        }]);
        plan(&mut cached, &tree, "u1", Some(&open)).expect("plans");

        let ops = plan(&mut cached, &tree_of(Vec::new()), "u1", Some(&open)).expect("plans");
        assert_eq!(ops.len(), 1);
        assert!(matches!(ops[0], Pending::DeleteProject { .. }));
        assert!(cached.connections.is_empty());
        assert!(cached.secrets.is_empty());
    }

    /// "No account" and "an account without a name" are the same, and only one
    /// of them belongs in the database.
    #[test]
    fn a_cleared_vault_account_is_removed() {
        let (open, _) = vault();
        let mut cached = copy();

        let mut tree = tree_of(Vec::new());
        tree.one_password_account = "my-company".into();
        plan(&mut cached, &tree, "u1", Some(&open)).expect("plans");
        assert_eq!(cached.one_password_account(), "my-company");

        tree.one_password_account = "  ".into();
        let ops = plan(&mut cached, &tree, "u1", Some(&open)).expect("plans");
        assert!(matches!(
            ops.as_slice(),
            [Pending::DeleteVaultAccount {
                provider: VaultProvider::OnePassword
            }]
        ));
    }

    /// Without the master password nothing that needs a secret can be created —
    /// and the error says so, instead of silently storing an empty ciphertext.
    #[test]
    fn no_new_project_can_be_created_while_locked() {
        let mut cached = copy();
        let tree = tree_of(vec![Project {
            id: "p1".into(),
            name: "Production".into(),
            connections: Vec::new(),
        }]);

        let error = plan(&mut cached, &tree, "u1", None).expect_err("must fail");
        assert!(error.contains("master password"), "{error}");
    }

    #[test]
    fn the_diff_does_not_touch_shares() {
        let (open, _) = vault();
        let mut cached = copy();
        cached.shares.push(super::super::model::ApiShare {
            id: "s1".into(),
            project_id: "p1".into(),
            team_id: None,
            team_name: None,
            role: ShareRole::Editor,
        });

        plan(&mut cached, &tree_of(Vec::new()), "u1", Some(&open)).expect("plans");
        assert_eq!(cached.shares.len(), 1);
        assert_eq!(cached.kind, WorkspaceKind::Organization);
    }
}
