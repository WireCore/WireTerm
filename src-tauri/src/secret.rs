//! Secrets that have to be asked for — the same for every protocol.
//!
//! Two of the three connection types offer a credential source that stores
//! nothing anywhere: FTP's "ask for the password when connecting" and S3's
//! "ask for the secret access key when connecting". Both need the same three
//! things, and none of them has anything to do with the protocol underneath:
//! a question put to the window, an answer that may never come, and somewhere
//! to keep what was typed for as long as the tab lives — otherwise every
//! parallel transfer would ask again.
//!
//! What differs is only what the secret is *called*, which is [`Kind`] and
//! reaches the dialog as a word rather than as a second event.
//!
//! Nothing here is ever written to disk. That is the entire point of the
//! option: a connection that should remember its secret has the vault
//! source, which is the better answer to the same wish.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use rust_i18n::t;
use serde::Serialize;
use tauri::{AppHandle, Emitter, State};
use tokio::sync::{oneshot, Mutex};
use tokio::time::timeout;

/// Where the question goes. One event for both kinds: the dialog is the same
/// dialog, and which word it uses is in the payload.
pub const EVENT: &str = "secret:ask";

/// How long an unanswered question is waited on.
///
/// The same reasoning as the host-key question in [`crate::ssh`]: the dialog
/// always answers, so this only catches the case where nothing is listening
/// at all — a window that closed while the question was in the air.
const ANSWER_TIMEOUT: Duration = Duration::from_secs(300);

/// What is being asked for, in the words the user knows it by.
#[derive(Clone, Copy)]
pub enum Kind {
    /// A question the SSH server asks during a keyboard-interactive login —
    /// a one-time code, typically. The words come from the server, see
    /// [`ask_challenge`].
    Challenge,
    /// An FTP or SSH password.
    Password,
    /// An S3 secret access key.
    SecretKey,
    /// What opens an encrypted SSH private key.
    Passphrase,
}

impl Kind {
    fn tag(self) -> &'static str {
        match self {
            Kind::Challenge => "challenge",
            Kind::Password => "password",
            Kind::SecretKey => "secretKey",
            Kind::Passphrase => "passphrase",
        }
    }
}

/// What the dialog is asked.
///
/// Carries no session id, for the same reason the host-key question does not:
/// "Test connection" raises it too, and that has no session.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct Question {
    id: String,
    kind: &'static str,
    host: String,
    port: u16,
    user: String,
    /// Only for [`Kind::Challenge`]: the server's own question, the
    /// instructions it sent along, and whether the answer may be shown while
    /// typing.
    #[serde(skip_serializing_if = "Option::is_none")]
    challenge: Option<Challenge>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct Challenge {
    text: String,
    instructions: String,
    echo: bool,
}

/// The questions waiting for an answer, by id.
#[derive(Clone, Default)]
pub struct Prompts(Arc<Mutex<HashMap<String, oneshot::Sender<Option<String>>>>>);

/// Secrets that were typed into the dialog, by session.
///
/// In memory and nowhere else. Kept per tab rather than per connection so
/// further connections for parallel transfers do not ask again, and dropped
/// when the tab closes. One map for both protocols: a tab is one connection,
/// so the two can never disagree about what belongs to a session id.
#[derive(Default)]
pub struct Cache(Mutex<HashMap<String, String>>);

impl Cache {
    pub async fn get(&self, session_id: &str) -> Option<String> {
        self.0.lock().await.get(session_id).cloned()
    }

    pub async fn put(&self, session_id: &str, secret: &str) {
        self.0
            .lock()
            .await
            .insert(session_id.to_string(), secret.to_string());
    }

    pub async fn forget(&self, session_id: &str) {
        self.0.lock().await.remove(session_id);
    }
}

/// Only has to tell concurrent questions apart.
fn next_question_id() -> String {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    format!("secret{}", NEXT.fetch_add(1, Ordering::Relaxed))
}

/// Puts the question to the frontend and waits for the answer.
pub async fn ask(
    app: &AppHandle,
    prompts: &Prompts,
    kind: Kind,
    host: &str,
    port: u16,
    user: &str,
) -> Result<String, String> {
    put(
        app,
        prompts,
        Question {
            id: next_question_id(),
            kind: kind.tag(),
            host: host.to_string(),
            port,
            user: user.to_string(),
            challenge: None,
        },
    )
    .await
}

/// Puts one of the server's keyboard-interactive questions to the frontend.
///
/// Nothing of it is cached: a one-time code is good for exactly one login.
#[allow(clippy::too_many_arguments)]
pub async fn ask_challenge(
    app: &AppHandle,
    prompts: &Prompts,
    host: &str,
    port: u16,
    user: &str,
    text: &str,
    instructions: &str,
    echo: bool,
) -> Result<String, String> {
    put(
        app,
        prompts,
        Question {
            id: next_question_id(),
            kind: Kind::Challenge.tag(),
            host: host.to_string(),
            port,
            user: user.to_string(),
            challenge: Some(Challenge {
                text: text.to_string(),
                instructions: instructions.to_string(),
                echo,
            }),
        },
    )
    .await
}

async fn put(app: &AppHandle, prompts: &Prompts, question: Question) -> Result<String, String> {
    let (sender, answer) = oneshot::channel();
    prompts.0.lock().await.insert(question.id.clone(), sender);

    if app.emit(EVENT, &question).is_err() {
        prompts.0.lock().await.remove(&question.id);
        return Err(t!("secrets.no_window").into_owned());
    }

    match timeout(ANSWER_TIMEOUT, answer).await {
        Ok(Ok(Some(secret))) => Ok(secret),
        // Cancelled, timed out, or the sender was dropped. None of the three
        // is a secret, and there is nothing to log in with.
        _ => {
            prompts.0.lock().await.remove(&question.id);
            Err(t!("secrets.nothing_given").into_owned())
        }
    }
}

/// The dialog's answer. `None` is "Cancel", which fails the connection.
///
/// An id that is no longer waiting is ignored rather than reported: the
/// question may have timed out while the dialog was still on screen.
#[tauri::command]
pub async fn secret_answer(
    prompts: State<'_, Prompts>,
    id: String,
    secret: Option<String>,
) -> Result<(), String> {
    if let Some(sender) = prompts.0.lock().await.remove(&id) {
        let _ = sender.send(secret);
    }
    Ok(())
}
