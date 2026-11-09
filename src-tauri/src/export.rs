//! Taking workspaces along as a file — secrets included, under a password.
//!
//! Since the secrets in `workspaces.json` are encrypted with the device key,
//! the file can no longer simply be copied to another computer. This is the
//! way to do that, and at the same time the backup in case the device key is
//! lost.
//!
//! The **whole** file is encrypted, not just the secrets: whoever finds it
//! should not learn which hosts are in it either. The key comes from the
//! export password via Argon2id, with the same parameters as the master
//! password; they travel along in the file.

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use rust_i18n::t;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::cloud::crypto::{self, KdfParams};
use crate::storage::{ConnectionSettings, StorageKind, Workspace};

const FORMAT: &str = "wireterm-export";
const VERSION: u32 = 1;
const AAD: &[u8] = b"wireterm/export/v1";

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExportFile {
    format: String,
    version: u32,
    kdf_params: KdfParams,
    /// base64.
    salt: String,
    /// base64.
    nonce: String,
    /// base64.
    ciphertext: String,
}

#[derive(Serialize, Deserialize)]
struct Payload {
    workspaces: Vec<Workspace>,
}

/// The workspaces as a file. What only holds at runtime — where a workspace
/// came from, whether a secret was unreadable just now — is left out.
fn pack(mut workspaces: Vec<Workspace>, password: &str) -> Result<String, String> {
    for workspace in &mut workspaces {
        workspace.remote = None;
        workspace.storage = StorageKind::Local;
        for project in &mut workspace.projects {
            for connection in &mut project.connections {
                connection.secret_unreadable = false;
            }
        }
    }
    let payload =
        Zeroizing::new(serde_json::to_vec(&Payload { workspaces }).map_err(|e| e.to_string())?);

    let params = KdfParams::default();
    let salt = crypto::new_salt()?;
    let nonce = crypto::new_nonce()?;
    let key = crypto::derive_key(password.as_bytes(), &salt, params)?;
    let ciphertext = crypto::seal(&key, &nonce, &payload, AAD)?;

    serde_json::to_string_pretty(&ExportFile {
        format: FORMAT.to_string(),
        version: VERSION,
        kdf_params: params,
        salt: BASE64.encode(salt),
        nonce: BASE64.encode(nonce),
        ciphertext: BASE64.encode(ciphertext),
    })
    .map_err(|e| e.to_string())
}

/// The workspaces from the file, with new IDs: an import is a copy, and the
/// rest of the app would take a second connection under the same ID for the
/// same one.
fn unpack(raw: &str, password: &str) -> Result<Vec<Workspace>, String> {
    let file: ExportFile =
        serde_json::from_str(raw).map_err(|_| t!("secrets.export_not_wireterm").into_owned())?;
    if file.format != FORMAT {
        return Err(t!("secrets.export_not_wireterm").into_owned());
    }
    if file.version != VERSION {
        return Err(t!(
            "secrets.export_unknown_version",
            version = file.version,
            supported = VERSION
        )
        .into_owned());
    }
    let decode = |value: &str| {
        BASE64
            .decode(value)
            .map_err(|_| t!("secrets.export_damaged").into_owned())
    };
    let key = crypto::derive_key(password.as_bytes(), &decode(&file.salt)?, file.kdf_params)?;
    let payload = Zeroizing::new(
        crypto::open(&key, &decode(&file.nonce)?, &decode(&file.ciphertext)?, AAD)
            .map_err(|_| t!("secrets.export_wrong_password").into_owned())?,
    );
    let Payload { mut workspaces } = serde_json::from_slice(&payload)
        .map_err(|e| t!("secrets.export_damaged_detail", error = e).into_owned())?;

    // A jump host points at a connection, and that one gets a new ID — even if
    // it is in another workspace of the same file.
    let mut connections = std::collections::HashMap::new();
    for workspace in &mut workspaces {
        workspace.id = new_id();
        workspace.storage = StorageKind::Local;
        workspace.remote = None;
        // A startup command points at a snippet of the same workspace; it moves
        // along to the snippet's new ID.
        let mut snippets = std::collections::HashMap::new();
        for snippet in &mut workspace.snippets {
            let id = new_id();
            snippets.insert(std::mem::replace(&mut snippet.id, id.clone()), id);
        }
        let mut projects = std::collections::HashMap::new();
        for project in &mut workspace.projects {
            let id = new_id();
            projects.insert(std::mem::replace(&mut project.id, id.clone()), id);
            for connection in &mut project.connections {
                let id = new_id();
                connections.insert(std::mem::replace(&mut connection.id, id.clone()), id);
                connection.secret_unreadable = false;
                if let ConnectionSettings::Ssh(ssh) = &mut connection.settings {
                    ssh.startup_snippet = ssh
                        .startup_snippet
                        .as_ref()
                        .and_then(|old| snippets.get(old).cloned());
                }
            }
        }
        // The snippets go along to the new IDs of their project and
        // connection. Here on the device they are all locked: there is nobody
        // whose rights would differ.
        for snippet in &mut workspace.snippets {
            snippet.project_id = projects
                .get(&snippet.project_id)
                .cloned()
                .unwrap_or_default();
            snippet.connection_id = snippet
                .connection_id
                .as_ref()
                .map(|old| connections.get(old).cloned().unwrap_or_default());
            snippet.locked = true;
        }
        workspace.prune_snippets();
    }
    for workspace in &mut workspaces {
        for project in &mut workspace.projects {
            for connection in &mut project.connections {
                if let ConnectionSettings::Ssh(ssh) = &mut connection.settings {
                    ssh.jump = ssh
                        .jump
                        .as_ref()
                        .and_then(|old| connections.get(old).cloned());
                }
            }
        }
    }
    Ok(workspaces)
}

fn new_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

fn check_password(password: &str) -> Result<(), String> {
    if password.chars().count() < 8 {
        return Err(t!("secrets.export_password_too_short").into_owned());
    }
    Ok(())
}

/// Writes the given workspaces to `path`. Which ones is up to the UI; it has
/// the tree with decrypted secrets anyway.
#[tauri::command]
pub async fn workspaces_export(
    path: String,
    password: String,
    workspaces: Vec<Workspace>,
) -> Result<(), String> {
    let password = Zeroizing::new(password);
    check_password(&password)?;
    // Argon2id with 64 MiB: not on the UI thread.
    let json = tauri::async_runtime::spawn_blocking(move || pack(workspaces, &password))
        .await
        .map_err(|e| e.to_string())??;
    let path = std::path::PathBuf::from(path);
    let tmp = path.with_extension("wireterm.tmp");
    std::fs::write(&tmp, json).map_err(|e| {
        t!("secrets.export_write_failed", path = tmp : {:?}, error = e).into_owned()
    })?;
    std::fs::rename(&tmp, &path)
        .map_err(|e| t!("secrets.export_write_failed", path = path : {:?}, error = e).into_owned())
}

/// Reads an export file. The workspaces go back to the UI, which files and
/// saves them — and in doing so [`crate::storage`] encrypts their secrets with
/// this device's key.
#[tauri::command]
pub async fn workspaces_import(path: String, password: String) -> Result<Vec<Workspace>, String> {
    let password = Zeroizing::new(password);
    let raw = std::fs::read_to_string(&path)
        .map_err(|e| t!("secrets.export_read_failed", path = path, error = e).into_owned())?;
    tauri::async_runtime::spawn_blocking(move || unpack(&raw, &password))
        .await
        .map_err(|e| e.to_string())?
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{Connection, Project, Snippet, SshAuth, SshSettings};

    fn tree() -> Vec<Workspace> {
        vec![Workspace {
            id: "ws-1".into(),
            name: "Company".into(),
            storage: StorageKind::Local,
            one_password_account: String::new(),
            bitwarden: None,
            remote: None,
            projects: vec![Project {
                id: "p1".into(),
                name: "Production".into(),
                connections: vec![Connection {
                    id: "c1".into(),
                    name: "web01".into(),
                    settings: ConnectionSettings::Ssh(SshSettings {
                        host: "web01.example".into(),
                        port: 22,
                        user: "root".into(),
                        auth: SshAuth::InlineKey {
                            key: "PRIVATE KEY".into(),
                        },
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

    #[test]
    fn an_export_comes_back_out_with_the_password() {
        let file = pack(tree(), "a long password").expect("packs");
        assert!(
            !file.contains("PRIVATE"),
            "the secret is not in it in readable form"
        );
        assert!(!file.contains("web01"), "nor are the hosts");

        let back = unpack(&file, "a long password").expect("unpacks");
        let connection = &back[0].projects[0].connections[0];
        assert!(matches!(
            &connection.settings,
            ConnectionSettings::Ssh(SshSettings { auth: SshAuth::InlineKey { key }, .. })
                if key == "PRIVATE KEY"
        ));
        assert_eq!(connection.name, "web01");
    }

    #[test]
    fn an_import_gets_new_ids() {
        let file = pack(tree(), "a long password").expect("packs");
        let back = unpack(&file, "a long password").expect("unpacks");
        assert_ne!(back[0].id, "ws-1");
        assert_ne!(back[0].projects[0].id, "p1");
        assert_ne!(back[0].projects[0].connections[0].id, "c1");
    }

    #[test]
    fn a_startup_command_moves_along_with_its_snippet() {
        let mut workspaces = tree();
        workspaces[0].snippets = vec![Snippet {
            id: "s1".into(),
            project_id: "p1".into(),
            connection_id: Some("c1".into()),
            locked: false,
            name: "Logs".into(),
            folder: String::new(),
            command: "tail -f /var/log/syslog".into(),
        }];
        if let ConnectionSettings::Ssh(ssh) = &mut workspaces[0].projects[0].connections[0].settings
        {
            ssh.startup_snippet = Some("s1".into());
        }
        let file = pack(workspaces, "a long password").expect("packs");
        let back = unpack(&file, "a long password").expect("unpacks");
        let new = &back[0].snippets[0].id;
        assert_ne!(new, "s1");
        // Along to the new IDs of project and connection, and locked on the
        // device.
        let project = &back[0].projects[0];
        assert_eq!(back[0].snippets[0].project_id, project.id);
        assert_eq!(
            back[0].snippets[0].connection_id.as_deref(),
            Some(project.connections[0].id.as_str())
        );
        assert!(back[0].snippets[0].locked);
        assert!(matches!(
            &back[0].projects[0].connections[0].settings,
            ConnectionSettings::Ssh(SshSettings { startup_snippet: Some(id), .. }) if id == new
        ));
    }

    #[test]
    fn a_jump_host_moves_along_with_its_connection() {
        let mut workspaces = tree();
        let mut target = workspaces[0].projects[0].connections[0].clone();
        target.id = "c2".into();
        if let ConnectionSettings::Ssh(ssh) = &mut target.settings {
            ssh.jump = Some("c1".into());
        }
        workspaces[0].projects[0].connections.push(target);
        let file = pack(workspaces, "a long password").expect("packs");
        let back = unpack(&file, "a long password").expect("unpacks");
        let connections = &back[0].projects[0].connections;
        assert!(matches!(
            &connections[1].settings,
            ConnectionSettings::Ssh(SshSettings { jump: Some(id), .. }) if *id == connections[0].id
        ));
    }

    #[test]
    fn a_wrong_password_opens_nothing() {
        let file = pack(tree(), "a long password").expect("packs");
        let error = unpack(&file, "another password").expect_err("stays closed");
        assert!(error.contains("password"), "{error}");
    }

    #[test]
    fn a_foreign_file_is_recognised() {
        assert!(unpack("{\"hello\":1}", "whatever whatever").is_err());
        assert!(unpack("not json", "whatever whatever").is_err());
    }

    #[test]
    fn a_short_password_is_refused() {
        assert!(check_password("short").is_err());
        assert!(check_password("long enough").is_ok());
    }
}
