//! The sync: up with what is waiting — down with what has changed.
//!
//! Always in this order. The other way round, the delta would arrive and
//! overwrite the copy with a state that does not know about our own changes
//! yet; the queue would send them up right afterwards, but in between the UI
//! would have jumped back once.
//!
//! The third step is the one only a client can do: look up who is still
//! missing the key for a project, and wrap it for them. The server can record
//! a share, but not grant one — whoever gets stuck after a share stays stuck
//! until a client with the project key comes along. That is why this happens
//! on every sync and not only when sharing.

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;

use super::account::Unlocked;
use super::api;
use super::cache::{Cached, Grant, Pending};
use super::crypto;
use super::http::{Api, ApiError, Jar};
use super::model::{self};
use rust_i18n::t;

/// How a pass ended.
#[derive(Default, Debug)]
pub struct Outcome {
    /// The server could not be reached. The copy stays valid, and so does the
    /// queue.
    pub offline: bool,
    /// The sign-in is no longer valid.
    pub signed_out: bool,
    /// What did not go through and will not go through either.
    pub error: Option<String>,
}

/// A full pass for one workspace.
pub async fn run(
    api: &Api,
    jar: &mut Jar,
    cached: &mut Cached,
    unlocked: Option<&Unlocked>,
    user_id: &str,
) -> Outcome {
    let mut outcome = Outcome::default();

    if let Err(error) = flush(api, jar, cached, &mut outcome).await {
        note(&mut outcome, error);
        if outcome.offline || outcome.signed_out {
            cached.last_error = outcome.error.clone();
            return outcome;
        }
    }

    match api::sync(api, jar, &cached.id, &cached.revision.clone()).await {
        Ok(delta) => cached.apply(delta),
        Err(error) => {
            note(&mut outcome, error);
            cached.last_error = outcome.error.clone();
            return outcome;
        }
    }

    if let Some(unlocked) = unlocked {
        if let Err(error) = hand_out_keys(api, jar, cached, unlocked, user_id).await {
            note(&mut outcome, error);
        }
    }

    cached.last_error = outcome.error.clone();
    outcome
}

/// Records what went wrong — namely the first thing, for the same reason as in
/// [`flush`]: a later error is usually a consequence of the first.
fn note(outcome: &mut Outcome, error: ApiError) {
    match &error {
        ApiError::Offline(_) => outcome.offline = true,
        ApiError::Unauthorized => outcome.signed_out = true,
        ApiError::Api { .. } => {}
    }
    outcome.error.get_or_insert_with(|| error.to_string());
}

// ---- Up ----------------------------------------------------------------------

/// Works through the queue, from the front.
///
/// It was built in the order in which it has to be processed — a project
/// before its connections, a project key before the first secret under it.
/// That is why it stops at the first hold-up instead of skipping: whatever
/// comes after builds on what is not up yet at the front.
///
/// What is rejected permanently, on the other hand, is dropped. Keeping it in
/// the queue would mean nothing behind it ever goes up again — and the next
/// sync fetches the state that actually applies anyway.
async fn flush(
    api: &Api,
    jar: &mut Jar,
    cached: &mut Cached,
    outcome: &mut Outcome,
) -> Result<(), ApiError> {
    while let Some(op) = cached.pending.first().cloned() {
        match apply(api, jar, &cached.id, &op).await {
            Ok(()) => {
                cached.pending.remove(0);
            }
            Err(error) if error.is_temporary() => return Err(error),
            Err(ApiError::Unauthorized) => return Err(ApiError::Unauthorized),
            Err(ApiError::Api { ref code, .. }) if code == "R-CF" => {
                cached.pending.remove(0);
                discard_follow_ups(cached, &op);
                // Not a sync error but a piece of information: someone was
                // faster. Their version comes in right afterwards; the message
                // stays until someone dismisses it.
                cached
                    .conflicts
                    .push(t!("cloud_sync.conflict", label = op.label()).into_owned());
            }
            Err(error) => {
                cached.pending.remove(0);
                // The **first** rejection, not the last: whatever comes after
                // builds on what did not go through at the front, and therefore
                // fails as a consequence. A project that could not be created
                // would otherwise report itself as "Upload secret: connection
                // not found" — correct and useless.
                outcome
                    .error
                    .get_or_insert_with(|| format!("{}: {error}", op.label()));
            }
        }
    }
    Ok(())
}

/// After a conflict on a connection, its secret from the same change has to be
/// discarded as well. Otherwise, say, an entered key would end up on the
/// server while a key file has been configured there in the meantime.
fn discard_follow_ups(cached: &mut Cached, op: &Pending) {
    let Pending::UpdateConnection { id, .. } = op else {
        return;
    };
    cached.pending.retain(|queued| match queued {
        Pending::PutSecret { connection_id, .. } | Pending::DeleteSecret { connection_id } => {
            connection_id != id
        }
        _ => true,
    });
}

async fn apply(api: &Api, jar: &mut Jar, org: &str, op: &Pending) -> Result<(), ApiError> {
    match op {
        Pending::RenameWorkspace { name } => super::org::rename(api, jar, org, name).await,
        Pending::CreateProject { id, name, position } => {
            match api::create_project(api, jar, org, id, name, *position).await {
                // Already there — for instance because the response got lost on
                // the way back. The goal of the call is reached all the same.
                Err(ApiError::Api { ref code, .. }) if code == "P-EX" => Ok(()),
                other => other,
            }
        }
        Pending::UpdateProject {
            id,
            name,
            position,
            expected_revision,
        } => {
            api::update_project(
                api,
                jar,
                org,
                id,
                name,
                *position,
                expected_revision.as_deref(),
            )
            .await
        }
        Pending::DeleteProject { id } => match api::delete_project(api, jar, org, id).await {
            Err(ApiError::Api { ref code, .. }) if code == "P-NF" => Ok(()),
            other => other,
        },
        Pending::GrantKeys {
            project_id,
            key_id,
            grants,
        } => api::grant_keys(api, jar, org, project_id, key_id, grants).await,
        Pending::CreateConnection {
            project_id,
            connection,
        } => {
            let body = model::connection_body(connection, true);
            match api::create_connection(api, jar, org, project_id, body).await {
                Err(ApiError::Api { ref code, .. }) if code == "C-EX" => {
                    // Already created: then the change is a PATCH.
                    let body = model::connection_body(connection, false);
                    api::update_connection(api, jar, org, &connection.id, body).await
                }
                other => other,
            }
        }
        Pending::UpdateConnection {
            id,
            connection,
            expected_revision,
        } => {
            let mut body = model::connection_body(connection, false);
            if let Some(revision) = expected_revision {
                body["expectedRevision"] = serde_json::json!(revision);
            }
            api::update_connection(api, jar, org, id, body).await
        }
        Pending::DeleteConnection { id } => match api::delete_connection(api, jar, org, id).await {
            Err(ApiError::Api { ref code, .. }) if code == "C-NF" => Ok(()),
            other => other,
        },
        Pending::PutSecret {
            connection_id,
            key_id,
            nonce,
            ciphertext,
        } => api::put_secret(api, jar, org, connection_id, key_id, nonce, ciphertext).await,
        Pending::DeleteSecret { connection_id } => {
            api::delete_secret(api, jar, org, connection_id).await
        }
        Pending::PutVaultAccount {
            provider,
            account,
            server,
            accept_invalid_cert,
        } => {
            api::put_vault_account(
                api,
                jar,
                org,
                provider_name(*provider),
                account,
                server,
                *accept_invalid_cert,
            )
            .await
        }
        Pending::DeleteVaultAccount { provider } => {
            api::delete_vault_account(api, jar, org, provider_name(*provider)).await
        }
        Pending::CreateSnippet { snippet } => {
            match api::create_snippet(api, jar, org, snippet).await {
                Err(ApiError::Api { ref code, .. }) if code == "SN-EX" => {
                    api::update_snippet(api, jar, org, snippet, None).await
                }
                other => other,
            }
        }
        Pending::UpdateSnippet {
            snippet,
            expected_revision,
        } => api::update_snippet(api, jar, org, snippet, expected_revision.as_deref()).await,
        Pending::DeleteSnippet { id } => match api::delete_snippet(api, jar, org, id).await {
            Err(ApiError::Api { ref code, .. }) if code == "SN-NF" => Ok(()),
            other => other,
        },
    }
}

fn provider_name(provider: crate::vault::VaultProvider) -> &'static str {
    match provider {
        crate::vault::VaultProvider::OnePassword => "onePassword",
        crate::vault::VaultProvider::Bitwarden => "bitwarden",
    }
}

// ---- Pending keys ------------------------------------------------------------

/// Wraps the project keys for everyone who is still missing them.
///
/// Only for the projects whose key this client has itself — for the others it
/// can do nothing, and the server would reject it too. Anyone who has not
/// stored a public key anywhere is skipped: they have not set up a master
/// password yet, and that is not an error but information for the UI.
pub async fn hand_out_keys(
    api: &Api,
    jar: &mut Jar,
    cached: &mut Cached,
    unlocked: &Unlocked,
    user_id: &str,
) -> Result<(), ApiError> {
    let projects: Vec<String> = cached
        .projects
        .iter()
        .map(|project| project.id.clone())
        .collect();

    for project_id in projects {
        let Some(key_id) = cached.current_key_id(&project_id) else {
            continue;
        };
        let Some(key) = cached.unwrap_key(&unlocked.private, &project_id, &key_id) else {
            continue;
        };

        let entitled = match api::key_requests(api, jar, &cached.id, &project_id).await {
            Ok(list) => list,
            // Whoever may only view a project but not edit it gets turned away
            // here. That is as it should be and no reason to abort the whole
            // sync.
            Err(ApiError::Api { status, .. }) if status == 403 || status == 404 => continue,
            Err(error) if error.is_temporary() => return Err(error),
            Err(_) => continue,
        };

        let mut grants = Vec::new();
        for member in entitled {
            if member.user_id == user_id || member.key_ids.contains(&key_id) {
                continue;
            }
            let Some(public) = member.key.as_ref() else {
                // Waiting for their setup.
                continue;
            };
            let Ok(bytes) = BASE64.decode(&public.public_key) else {
                continue;
            };
            let Ok(wrapped) = crypto::wrap_project_key(&key, &bytes) else {
                continue;
            };
            grants.push(Grant {
                user_id: member.user_id,
                ephemeral_public_key: BASE64.encode(wrapped.ephemeral_public_key),
                nonce: BASE64.encode(&wrapped.nonce),
                wrapped_key: BASE64.encode(&wrapped.wrapped_key),
            });
        }

        if grants.is_empty() {
            continue;
        }
        match api::grant_keys(api, jar, &cached.id, &project_id, &key_id, &grants).await {
            Ok(()) => {}
            Err(error) if error.is_temporary() => return Err(error),
            Err(_) => continue,
        }
    }

    Ok(())
}

// ---- Host-Keys ---------------------------------------------------------------

/// Writes the workspace's trusted host keys into this device's `known_hosts`.
///
/// Only in this direction. Keeping them on the workspace means not every team
/// member answers the same question individually — and what arrives here was
/// confirmed by someone in the client, not claimed by the server.
///
/// A line that cannot be read is skipped instead of reported: it leads to a
/// prompt, and that is the safe direction.
///
/// A TLS certificate is in the same list, with the type
/// [`crate::certificates::ALGORITHM`] and the fingerprint in place of the key;
/// it goes into the separate file for certificates.
pub fn write_known_hosts(app: &tauri::AppHandle, cached: &Cached) {
    for host in &cached.known_hosts {
        if host.deleted_at.is_some() || host.public_key.trim().is_empty() {
            continue;
        }
        let _ = if host.algorithm == crate::certificates::ALGORITHM {
            crate::certificates::trust_hex(app, &host.host, host.port, &host.public_key)
        } else {
            crate::known_hosts::trust_openssh(app, &host.host, host.port, &host.public_key)
        };
    }
}
