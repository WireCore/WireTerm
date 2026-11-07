//! A new version of the project key — so that a revocation actually holds.
//!
//! Someone removed from a project loses their wrapped copy of the project key.
//! But whatever they opened until then they still know, and possibly the key
//! itself as well. It only holds once the secrets lie under a **new** key that
//! they never received.
//!
//! Only a client that has the old version can do that:
//!
//! 1. create a new version (`keyId` = UUID),
//! 2. wrap it for everyone who is entitled now and already has a public
//!    key — oneself included,
//! 3. open every secret of the project with the old version and upload it
//!    again under the new one.
//!
//! Whoever has not set up a master password yet gets the new version later on
//! their own: [`super::sync::hand_out_keys`] always hands out the current one.
//! Whatever cannot be opened here stays under the old version and is
//! reported — nothing breaks in the process.

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use rust_i18n::t;
use serde::Serialize;

use super::account::Unlocked;
use super::api;
use super::cache::{Cached, Grant};
use super::crypto;
use super::http::{Api, Jar};

/// What the rotation achieved.
#[derive(Serialize, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct Rotated {
    pub key_id: String,
    /// Secrets that now lie under the new version.
    pub secrets: usize,
    /// Secrets that could not be opened here and stay under the old
    /// version.
    pub skipped: usize,
    /// For how many the new version has now been wrapped.
    pub granted: usize,
    /// Entitled members without a public key — they get the version as soon
    /// as they have set up their master password.
    pub waiting: usize,
}

/// A secret, opened and ready for the new version.
struct Open {
    connection_id: String,
    plaintext: zeroize::Zeroizing<Vec<u8>>,
}

/// Opens every secret of the project with the version it lies under.
fn open_all(cached: &Cached, private: &[u8; 32], project_id: &str) -> (Vec<Open>, usize) {
    let mut opened = Vec::new();
    let mut skipped = 0;
    let connections = cached.connections.iter().filter(|connection| {
        connection.project_id == project_id && connection.deleted_at.is_none()
    });
    for connection in connections {
        let Some(secret) = cached
            .secret(&connection.id)
            .filter(|secret| secret.deleted_at.is_none() && !secret.ciphertext.is_empty())
        else {
            continue;
        };
        let plaintext = cached
            .unwrap_key(private, project_id, &secret.key_id)
            .and_then(|key| {
                let nonce = BASE64.decode(&secret.nonce).ok()?;
                let ciphertext = BASE64.decode(&secret.ciphertext).ok()?;
                crypto::open(&key, &nonce, &ciphertext, connection.id.as_bytes()).ok()
            });
        match plaintext {
            Some(plaintext) => opened.push(Open {
                connection_id: connection.id.clone(),
                plaintext: zeroize::Zeroizing::new(plaintext),
            }),
            None => skipped += 1,
        }
    }
    (opened, skipped)
}

pub async fn rotate(
    api: &Api,
    jar: &mut Jar,
    cached: &Cached,
    unlocked: &Unlocked,
    user_id: &str,
    project_id: &str,
) -> Result<Rotated, String> {
    let org = cached.id.as_str();
    let (opened, skipped) = open_all(cached, &unlocked.private, project_id);

    let key = crypto::new_project_key()?;
    let key_id = uuid::Uuid::new_v4().to_string();

    // Wrap first, then re-encrypt: the server does not accept a secret under
    // a `keyId` that nobody holds.
    let entitled = api::key_requests(api, jar, org, project_id)
        .await
        .map_err(String::from)?;
    let mut grants = Vec::new();
    let mut waiting = 0;
    let mut own = false;
    for member in entitled {
        let Some(public) = member.key.as_ref() else {
            waiting += 1;
            continue;
        };
        let Ok(bytes) = BASE64.decode(&public.public_key) else {
            waiting += 1;
            continue;
        };
        let wrapped = crypto::wrap_project_key(&key, &bytes)?;
        own |= member.user_id == user_id;
        grants.push(Grant {
            user_id: member.user_id,
            ephemeral_public_key: BASE64.encode(wrapped.ephemeral_public_key),
            nonce: BASE64.encode(&wrapped.nonce),
            wrapped_key: BASE64.encode(&wrapped.wrapped_key),
        });
    }
    // Without an own copy, everything after this would be mere bytes to oneself.
    if !own {
        return Err(t!("cloud.rotate_not_entitled").to_string());
    }
    api::grant_keys(api, jar, org, project_id, &key_id, &grants)
        .await
        .map_err(String::from)?;

    let mut secrets = 0;
    for open in &opened {
        let nonce = crypto::new_nonce()?;
        let ciphertext =
            crypto::seal(&key, &nonce, &open.plaintext, open.connection_id.as_bytes())?;
        api::put_secret(
            api,
            jar,
            org,
            &open.connection_id,
            &key_id,
            &BASE64.encode(&nonce),
            &BASE64.encode(&ciphertext),
        )
        .await
        .map_err(String::from)?;
        secrets += 1;
    }

    Ok(Rotated {
        key_id,
        secrets,
        skipped,
        granted: grants.len(),
        waiting,
    })
}
