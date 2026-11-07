//! The one door to all password managers.
//!
//! There are two so far — 1Password in [`crate::op`], Bitwarden and
//! Vaultwarden in [`crate::bitwarden`] — and from the outside they look alike:
//! a list of vaults, entries in them, fields in those, and a reference that
//! points at exactly one of them. That one runs through a sidecar and the
//! other over HTTP is a question of how they are connected, and not one the
//! form or a connection type should have to answer.
//!
//! That is why a connection does not say "1Password" but "vault" plus
//! [`VaultProvider`]. A third provider is one more value in this enum and one
//! more branch in [`resolve`] — and nothing else.

use rust_i18n::t;
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager};

use crate::bitwarden::{self, BwState};
use crate::op::{self, OpState};

/// Which password manager is meant.
///
/// [`VaultProvider::OnePassword`] is the default because that provider came
/// first: a connection from an older `workspaces.json` names none, and this
/// one was meant back then.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum VaultProvider {
    #[default]
    OnePassword,
    /// Bitwarden itself and Vaultwarden — the same API, the same path.
    Bitwarden,
}

impl VaultProvider {
    /// What the provider is called in an error message.
    pub fn label(self) -> &'static str {
        match self {
            Self::OnePassword => "1Password",
            Self::Bitwarden => "Bitwarden",
        }
    }
}

/// A vault: a collection of entries. 1Password calls it that, in Bitwarden it
/// is the own vault or an organization.
#[derive(Serialize, Deserialize, Clone)]
pub struct Vault {
    pub id: String,
    pub title: String,
    #[serde(rename = "itemCount")]
    pub item_count: u32,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Item {
    pub id: String,
    pub title: String,
    /// `Login`, `SshKey`, … Both providers report the same names, so the form
    /// can put SSH keys at the top without knowing where the list comes from.
    pub category: String,
}

/// A field of an entry.
///
/// The value is deliberately not in it, only its length: this list is meant
/// to show what an entry looks like, not to carry secrets into the UI. A value
/// is read through [`resolve`], and that in the backend.
#[derive(Serialize, Deserialize, Clone)]
pub struct Field {
    pub id: String,
    pub title: String,
    #[serde(rename = "fieldType")]
    pub field_type: String,
    #[serde(rename = "valueLength")]
    pub value_length: u32,
}

/// What a workspace knows about its vaults.
///
/// Both belong to the workspace and not to the device: which account a
/// collection of connections is read with belongs to the connections.
#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct VaultConfig {
    #[serde(default)]
    pub one_password_account: String,
    #[serde(default)]
    pub bitwarden: Option<bitwarden::Account>,
}

/// Tells the backend which accounts the open workspace works with.
///
/// Sent on every workspace change and once more when one of the accounts was
/// edited.
#[tauri::command]
pub async fn vault_configure(app: AppHandle, config: VaultConfig) -> Result<(), String> {
    op::set_account(&app.state::<OpState>(), config.one_password_account).await;
    bitwarden::set_account(
        &app.state::<BwState>(),
        config.bitwarden.unwrap_or_default(),
    )
    .await;
    Ok(())
}

#[tauri::command]
pub async fn vault_vaults(app: AppHandle, provider: VaultProvider) -> Result<Vec<Vault>, String> {
    match provider {
        VaultProvider::OnePassword => op::vaults(&app, &app.state::<OpState>()).await,
        VaultProvider::Bitwarden => bitwarden::vaults(&app.state::<BwState>()).await,
    }
}

#[tauri::command]
pub async fn vault_items(
    app: AppHandle,
    provider: VaultProvider,
    vault_id: String,
) -> Result<Vec<Item>, String> {
    match provider {
        VaultProvider::OnePassword => op::items(&app, &app.state::<OpState>(), &vault_id).await,
        VaultProvider::Bitwarden => bitwarden::items(&app.state::<BwState>(), &vault_id).await,
    }
}

#[tauri::command]
pub async fn vault_fields(
    app: AppHandle,
    provider: VaultProvider,
    vault_id: String,
    item_id: String,
) -> Result<Vec<Field>, String> {
    match provider {
        VaultProvider::OnePassword => {
            op::fields(&app, &app.state::<OpState>(), &vault_id, &item_id).await
        }
        VaultProvider::Bitwarden => {
            bitwarden::fields(&app.state::<BwState>(), &vault_id, &item_id).await
        }
    }
}

/// Resolves a reference to its secret.
///
/// The return value is logged nowhere. The connection types call this
/// directly, without the detour through the command layer — a secret does not
/// have to pass through the webview just because it was requested from there.
///
/// The providers' states hang on the `AppHandle` instead of being passed
/// along: otherwise every function on the way from `ssh_connect` to here would
/// carry one more argument per provider.
pub async fn resolve(
    app: &AppHandle,
    provider: VaultProvider,
    reference: &str,
) -> Result<String, String> {
    match provider {
        VaultProvider::OnePassword => op::resolve(app, &app.state::<OpState>(), reference).await,
        VaultProvider::Bitwarden => bitwarden::resolve(&app.state::<BwState>(), reference).await,
    }
}

/// Which provider is behind a reference — or none, if it is not one at all.
fn provider_of(reference: &str) -> Option<VaultProvider> {
    if reference.starts_with("op://") {
        Some(VaultProvider::OnePassword)
    } else if reference.starts_with("bw://") {
        Some(VaultProvider::Bitwarden)
    } else {
        None
    }
}

/// A connection's user name.
///
/// The field holds either the name itself or a reference to it, in the same
/// form as for a secret. A name starting with `op://` or `bw://` is not one
/// that exists — so the prefix is enough, and nothing has to change on the
/// server.
pub async fn resolve_user(app: &AppHandle, user: &str) -> Result<String, String> {
    let Some(provider) = provider_of(user) else {
        return Ok(user.to_string());
    };
    resolve(app, provider, user)
        .await
        .map(|name| name.trim().to_string())
        .map_err(|e| {
            t!(
                "vault.user_name_unreadable",
                provider = provider.label(),
                error = e
            )
            .into_owned()
        })
}

#[tauri::command]
pub async fn vault_resolve(
    app: AppHandle,
    provider: VaultProvider,
    reference: String,
) -> Result<String, String> {
    resolve(&app, provider, &reference).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_reference_is_looked_up_in_the_vault() {
        assert_eq!(
            provider_of("op://v/i/username"),
            Some(VaultProvider::OnePassword)
        );
        assert_eq!(
            provider_of("bw://v/i/username"),
            Some(VaultProvider::Bitwarden)
        );
        assert_eq!(provider_of("root"), None);
        assert_eq!(provider_of("u123456"), None);
    }
}
