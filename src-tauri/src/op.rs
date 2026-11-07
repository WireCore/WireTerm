//! Access to 1Password via the `op-sidecar` child process.
//!
//! 1Password ships no Rust SDK, so the Go sidecar holds the SDK client and we
//! talk to it over newline-delimited JSON on stdin/stdout. The process is kept
//! alive between requests: building its client costs about 5s, individual
//! calls 200-400ms.
//!
//! The sidecar is spawned from Rust rather than from the webview, so the
//! frontend needs no shell permission and cannot start arbitrary processes.
//!
//! Which 1Password account to authenticate with is not compiled in: the
//! desktop-app integration signs every user in with their *own* account, so
//! the name belongs to the workspace and is handed down with
//! [`set_account`].
//!
//! Nothing here is a Tauri command any more: the frontend asks
//! [`crate::vault`] for a vault, an item or a field and names the provider it
//! means. What is left here is the 1Password half of that answer.

use rust_i18n::t;
use serde_json::{json, Value};
use tauri::AppHandle;
use tauri_plugin_shell::process::{CommandChild, CommandEvent};
use tauri_plugin_shell::ShellExt;
use tokio::sync::mpsc::Receiver;
use tokio::sync::Mutex;

use crate::vault::{Field, Item, Vault};

/// Returned in place of a 1Password error when there is no account to try
/// with. The frontend matches on the marker and asks for one instead of
/// showing this text.
const NO_ACCOUNT: &str = "op:no-account";

/// Returned when 1Password does not know the account that was configured —
/// the usual outcome of a typo, or of a workspace set up by someone else.
const UNKNOWN_ACCOUNT: &str = "op:unknown-account";

/// What 1Password says when the account name is not one of the signed-in ones.
const ACCOUNT_NOT_FOUND: &str = "account not found";

/// A running sidecar plus the channel its output arrives on.
struct Sidecar {
    child: CommandChild,
    events: Receiver<CommandEvent>,
    next_id: u64,
}

#[derive(Default)]
struct Inner {
    /// The account the open workspace names. Empty until one is opened that
    /// has an account, which is what [`NO_ACCOUNT`] reports.
    account: String,
    /// The running sidecar and the account it was started with. The SDK client
    /// inside it is built once and bound to that account for life, so a
    /// different account means a new process, not a new request.
    sidecar: Option<(String, Sidecar)>,
}

/// Holds the configured account and the sidecar serving it.
#[derive(Default)]
pub struct OpState(Mutex<Inner>);

impl Sidecar {
    fn spawn(app: &AppHandle, account: &str) -> Result<Self, String> {
        let (events, child) = app
            .shell()
            .sidecar("op-sidecar")
            .map_err(|e| t!("vault.op_sidecar_missing", error = e).into_owned())?
            .env("OP_ACCOUNT", account)
            .spawn()
            .map_err(|e| t!("vault.op_sidecar_start_failed", error = e).into_owned())?;

        Ok(Self {
            child,
            events,
            next_id: 0,
        })
    }
}

/// Ends the sidecar, if one is running, so the next request starts a fresh
/// one. Dropping the handle alone would leave the process behind.
fn stop(inner: &mut Inner) {
    if let Some((_, sidecar)) = inner.sidecar.take() {
        let _ = sidecar.child.kill();
    }
}

/// Tells the backend which 1Password account to authenticate with. Sent when a
/// workspace is opened and whenever its account is edited; an empty name means
/// the workspace has none yet.
///
/// A running sidecar is deliberately left alone. The next request notices that
/// it belongs to another account and replaces it, so switching between
/// workspaces costs nothing until 1Password is actually used.
pub async fn set_account(state: &OpState, account: String) {
    state.0.lock().await.account = account.trim().to_string();
}

/// Sends one request and waits for the response carrying the same id.
///
/// Requests are serialized by the mutex, so at most one is in flight and the
/// id only has to guard against a stale response from a previous, timed-out
/// exchange.
async fn request(app: &AppHandle, state: &OpState, mut body: Value) -> Result<Value, String> {
    let mut guard = state.0.lock().await;
    if guard.account.is_empty() {
        return Err(NO_ACCOUNT.to_string());
    }

    // A sidecar left over from a workspace with a different account cannot be
    // reused, because the account it authenticated with is baked in.
    let wrong_account = guard
        .sidecar
        .as_ref()
        .is_some_and(|(started_with, _)| *started_with != guard.account);
    if wrong_account {
        stop(&mut guard);
    }
    if guard.sidecar.is_none() {
        let account = guard.account.clone();
        let sidecar = Sidecar::spawn(app, &account)?;
        guard.sidecar = Some((account, sidecar));
    }
    let (_, sidecar) = guard.sidecar.as_mut().expect("just ensured");

    sidecar.next_id += 1;
    let id = sidecar.next_id;
    body["id"] = json!(id);

    let mut line = serde_json::to_vec(&body).map_err(|e| e.to_string())?;
    line.push(b'\n');
    if let Err(e) = sidecar.child.write(&line) {
        stop(&mut guard);
        return Err(t!("vault.op_sidecar_unreachable", error = e).into_owned());
    }

    loop {
        match sidecar.events.recv().await {
            Some(CommandEvent::Stdout(bytes)) => {
                let Ok(response) = serde_json::from_slice::<Value>(&bytes) else {
                    // Not a response line; the sidecar writes nothing else to
                    // stdout, so this only happens on a truncated read.
                    continue;
                };
                if response.get("id").and_then(Value::as_u64) != Some(id) {
                    continue;
                }
                if response.get("ok").and_then(Value::as_bool) == Some(true) {
                    return Ok(response.get("data").cloned().unwrap_or(Value::Null));
                }
                let message = response
                    .get("error")
                    .and_then(Value::as_str)
                    .map(str::to_string)
                    .unwrap_or_else(|| t!("vault.op_sidecar_unknown_error").into_owned());

                // A rejected account cannot be corrected in place — the
                // sidecar took it from its environment at startup — so the
                // process goes, and the next attempt starts one with whatever
                // the user supplies in its place.
                if message.to_lowercase().contains(ACCOUNT_NOT_FOUND) {
                    let marked = format!("{UNKNOWN_ACCOUNT}: {message}");
                    stop(&mut guard);
                    return Err(marked);
                }
                return Err(message);
            }
            Some(CommandEvent::Stderr(bytes)) => {
                // Passed through as-is; the sidecar already prefixes its own
                // diagnostics with "op-sidecar:".
                eprintln!("{}", String::from_utf8_lossy(&bytes).trim_end());
            }
            Some(CommandEvent::Error(e)) => {
                stop(&mut guard);
                return Err(t!("vault.op_sidecar_error", error = e).into_owned());
            }
            Some(CommandEvent::Terminated(_)) | None => {
                // Let go of the dead process so the next call starts a fresh
                // one.
                stop(&mut guard);
                return Err(t!("vault.op_sidecar_stopped").into_owned());
            }
            _ => {}
        }
    }
}

/// The sidecar deliberately reports only the length of each field's value, so
/// listing an item never moves a secret into the frontend — the same rule
/// [`crate::vault::Field`] states for every provider.
pub async fn vaults(app: &AppHandle, state: &OpState) -> Result<Vec<Vault>, String> {
    let data = request(app, state, json!({ "cmd": "vaults" })).await?;
    serde_json::from_value(data).map_err(|e| e.to_string())
}

pub async fn items(app: &AppHandle, state: &OpState, vault_id: &str) -> Result<Vec<Item>, String> {
    let data = request(app, state, json!({ "cmd": "items", "vault": vault_id })).await?;
    serde_json::from_value(data).map_err(|e| e.to_string())
}

pub async fn fields(
    app: &AppHandle,
    state: &OpState,
    vault_id: &str,
    item_id: &str,
) -> Result<Vec<Field>, String> {
    let data = request(
        app,
        state,
        json!({ "cmd": "fields", "vault": vault_id, "item": item_id }),
    )
    .await?;
    serde_json::from_value(data).map_err(|e| e.to_string())
}

/// Resolves a secret reference of the form `op://vault/item/field`.
///
/// The value is returned to the caller but never logged. [`crate::vault`]
/// reaches this directly rather than through the command layer, so a secret
/// asked for by a connection never passes through the webview.
pub async fn resolve(app: &AppHandle, state: &OpState, reference: &str) -> Result<String, String> {
    let data = request(app, state, json!({ "cmd": "resolve", "ref": reference })).await?;
    data.as_str()
        .map(str::to_string)
        .ok_or_else(|| t!("vault.op_no_secret").into_owned())
}
