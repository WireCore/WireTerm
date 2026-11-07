//! "Edit on server", for whichever protocol the file came over.
//!
//! The gesture downloads a working copy, opens it with whatever the system
//! would otherwise open it with, and watches that copy: a change is uploaded
//! back automatically, the way editing over sshfs or rmate feels. Polled
//! rather than event-driven, because a watcher tied to one path misses the
//! common way editors save — write a new file, then rename it into place —
//! and a second's delay before an upload starts is nothing anyone editing a
//! config file will notice.
//!
//! None of that depends on how the bytes travel. The one protocol-specific
//! part is the upload itself, which each module hands in as a closure to
//! [`watch`]: SFTP sends it down the channel it already has, FTP takes a
//! connection out of its pool. Everything else — the polling, the settling,
//! the editor process, what the row on screen is told — is the same either
//! way and is decided here, once.

use std::collections::HashMap;
use std::future::Future;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use rust_i18n::t;
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager, State};
use tokio::fs;
use tokio::sync::Mutex;

/// How often an open edit is checked for a change.
const POLL: Duration = Duration::from_millis(1000);

/// How long a change has to sit still before it is trusted.
///
/// Some editors write a file in more than one step; catching it mid-write
/// would upload a half-saved file. Two polls agreeing on both the size and the
/// modification time is treated as settled.
const SETTLE: Duration = Duration::from_millis(350);

/// How long a started editor has to stay alive for its exit to mean anything.
///
/// Most editors are single-instance: started a second time they hand the file
/// to the window that is already open and quit immediately. Their exit then
/// says nothing about whether anyone is still editing, and treating it as
/// "done" would close the watch while the file is on screen. Anything that
/// short is therefore taken as a hand-off, not as an ending — and said so,
/// because the cure is a flag the user has to add themselves (`-multiInst`
/// for Notepad++, `--wait` for VS Code and most others).
const HANDOFF: Duration = Duration::from_secs(3);

/// Where an open edit reports what its last sync attempt did.
///
/// Per edit rather than per session: a row in "Edited on server" is one
/// file, and it is the only thing that cares.
pub fn status_event(edit_id: &str) -> String {
    format!("edit:status:{edit_id}")
}

/// What an edit reports about itself, sent on every change of state.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EditStatus {
    pub state: &'static str,
    /// Set for `error`, and for `detached` — where it is not a failure but an
    /// explanation of what will not happen.
    pub message: Option<String>,
}

impl EditStatus {
    fn plain(state: &'static str) -> Self {
        Self {
            state,
            message: None,
        }
    }
}

/// Which program "Edit" hands the working copy to.
///
/// Absent, or with an empty path, means the system's own choice — which is
/// also the only case where nothing can be waited for: the shell opens the
/// file and tells no-one when it is done with it.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EditorCommand {
    pub path: String,
    /// Extra arguments, as typed. `%f` stands for the file; without it the
    /// file is appended, which is what every editor here expects anyway.
    #[serde(default)]
    pub args: String,
}

/// What "Edit" hands back: where the copy landed, so the frontend can
/// open it, and the id its status updates arrive under.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EditSession {
    pub id: String,
    pub local_path: String,
    pub name: String,
    /// Whether an editor was started here. False means the frontend still has
    /// to hand the file to the system, and that nothing is waiting for it.
    pub opened: bool,
}

/// One file open for editing.
struct Edit {
    session_id: String,
    /// Told to stop by [`EditWatchers::stop_for_session`] and [`edit_close`];
    /// checked by the poll loop between rounds.
    stop: Arc<AtomicBool>,
}

/// Every edit currently open, whatever protocol it came over.
///
/// One map for both: an edit belongs to a tab, and a tab closing has to end
/// its edits without first asking what it was connected with.
#[derive(Default)]
pub struct EditWatchers(Mutex<HashMap<String, Edit>>);

impl EditWatchers {
    /// Stops every edit belonging to a tab — called when its file browser
    /// closes, since an edit is only as good as the connection under it and
    /// that connection is what just went away.
    pub async fn stop_for_session(&self, session_id: &str) {
        let mut guard = self.0.lock().await;
        guard.retain(|_, edit| {
            if edit.session_id == session_id {
                edit.stop.store(true, Ordering::Relaxed);
                false
            } else {
                true
            }
        });
    }

    /// Registers a new edit and hands back the flag its watch should check.
    pub async fn register(&self, id: &str, session_id: &str) -> Arc<AtomicBool> {
        let stop = Arc::new(AtomicBool::new(false));
        self.0.lock().await.insert(
            id.to_string(),
            Edit {
                session_id: session_id.to_string(),
                stop: Arc::clone(&stop),
            },
        );
        stop
    }
}

/// Only has to tell edits apart, the same as the host-key questions do.
pub fn next_id() -> String {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    format!("ed{}", NEXT.fetch_add(1, Ordering::Relaxed))
}

/// The last segment of a remote path — what the working copy is called.
pub fn file_name(remote: &str) -> String {
    remote
        .rsplit('/')
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or("file")
        .to_string()
}

/// Where the working copy for one edit goes.
///
/// Its own directory per edit: two files of the same name from different
/// remote folders must not collide, and keeping the real name is what lets the
/// editor still recognise the extension.
///
/// Through Tauri's resolver rather than `std::env::temp_dir()`, even though
/// the two normally agree: the opener's scope in the capability file is
/// written as `$TEMP/wireterm-edit/*/*`, and `$TEMP` is *this* function.
/// Reading the directory from anywhere else would leave the working copy one
/// environment variable away from a path the scope does not cover, and the
/// only sign of it would be "Not allowed to open path" at the very end.
pub async fn working_copy(app: &AppHandle, id: &str, name: &str) -> Result<PathBuf, String> {
    let dir = app
        .path()
        .temp_dir()
        .map_err(|e| t!("files.working_copy_failed", error = e).into_owned())?
        .join("wireterm-edit")
        .join(id);
    fs::create_dir_all(&dir)
        .await
        .map_err(|e| t!("files.working_copy_failed", error = e).into_owned())?;
    Ok(dir.join(name))
}

/// Splits an argument line the way a shell would, minus the parts an editor
/// flag never needs: no variables, no escapes, only double quotes holding a
/// value with spaces in it together.
fn split_args(line: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    let mut started = false;

    for c in line.chars() {
        match c {
            '"' => {
                quoted = !quoted;
                // An empty `""` is still an argument, which is why this is
                // tracked apart from whether anything was written.
                started = true;
            }
            c if c.is_whitespace() && !quoted => {
                if started {
                    args.push(std::mem::take(&mut current));
                    started = false;
                }
            }
            c => {
                current.push(c);
                started = true;
            }
        }
    }
    if started {
        args.push(current);
    }
    args
}

/// Starts the configured editor on the working copy.
///
/// Returns the running process, which is what makes "the editor is closed"
/// something this app can ever know. A failure to start is reported to the
/// caller rather than swallowed: a mistyped path would otherwise look like an
/// editor that opens nothing.
fn start_editor(editor: &EditorCommand, file: &str) -> Result<tokio::process::Child, String> {
    let mut command = tokio::process::Command::new(&editor.path);

    let mut placed = false;
    for arg in split_args(&editor.args) {
        if arg.contains("%f") {
            command.arg(arg.replace("%f", file));
            placed = true;
        } else {
            command.arg(arg);
        }
    }
    if !placed {
        command.arg(file);
    }

    // Nothing here reads or writes the editor's streams, and leaving them
    // attached to this process would keep a console editor waiting on input
    // that never comes.
    command
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());

    command
        .spawn()
        .map_err(|e| t!("files.editor_start_failed", path = editor.path, error = e).into_owned())
}

/// Starts the editor, if one is configured, and arranges for its exit to end
/// the edit.
///
/// Returns whether anything was started — false means the frontend still has
/// to hand the file to the system and that nothing is waiting for it. The
/// editor is started before the watch is spawned by the caller, so a mistyped
/// path is an error on "Edit" rather than a watch quietly running on a
/// file no editor ever received.
pub fn open_editor(
    app: &AppHandle,
    editor: Option<EditorCommand>,
    local: &str,
    id: &str,
    stop: &Arc<AtomicBool>,
) -> Result<bool, String> {
    let Some(editor) = editor.filter(|e| !e.path.trim().is_empty()) else {
        return Ok(false);
    };
    let child = start_editor(&editor, local)?;
    tauri::async_runtime::spawn(await_editor(
        app.clone(),
        child,
        id.to_string(),
        Arc::clone(stop),
    ));
    Ok(true)
}

/// Waits for a started editor and ends the edit when it closes.
///
/// The watch is stopped rather than the working copy deleted: the poll loop
/// has one last look before it goes, so a save made a moment before the editor
/// was closed still goes across. See [`HANDOFF`] for the case where waiting
/// says nothing.
async fn await_editor(
    app: AppHandle,
    mut child: tokio::process::Child,
    id: String,
    stop: Arc<AtomicBool>,
) {
    let started = Instant::now();
    let _ = child.wait().await;

    if started.elapsed() < HANDOFF {
        let _ = app.emit(
            &status_event(&id),
            EditStatus {
                state: "detached",
                message: Some(t!("files.editor_handed_off").into_owned()),
            },
        );
        return;
    }

    stop.store(true, Ordering::Relaxed);
}

/// Size and modification time together — what one look at the working copy
/// says, and `None` where there is nothing to look at.
async fn stamp(local: &str) -> Option<(u64, Option<SystemTime>)> {
    let meta = fs::metadata(local).await.ok()?;
    Some((meta.len(), meta.modified().ok()))
}

/// Polls the working copy and sends it back whenever it settles on a new
/// state. Runs until told to stop, which is the only way it ends — a poll loop
/// has no natural end of its own.
///
/// `push` is the one protocol-specific part: it uploads the working copy as it
/// stands and says how that went. It is called only when the file has settled,
/// never concurrently with itself.
pub async fn watch<F, Fut>(
    app: AppHandle,
    stop: Arc<AtomicBool>,
    id: String,
    local: String,
    push: F,
) where
    F: Fn() -> Fut + Send,
    Fut: Future<Output = Result<(), String>> + Send,
{
    let event = status_event(&id);
    let mut baseline = stamp(&local).await;

    let send = |app: &AppHandle, status: EditStatus| {
        let _ = app.emit(&event, status);
    };

    loop {
        tokio::time::sleep(POLL).await;
        if stop.load(Ordering::Relaxed) {
            break;
        }

        let Some(current) = stamp(&local).await else {
            // The working copy is gone — deleted by hand, or the editor moved
            // it away instead of saving in place. Nothing left to watch, and
            // nothing left to send either.
            send(&app, EditStatus::plain("closed"));
            return;
        };
        if Some(current) == baseline {
            continue;
        }

        // Settling: wait and check again before trusting a change that may
        // still be mid-write. Deliberately not checking `stop` in between —
        // a save that is still landing while the editor closes is exactly
        // what the next line is for.
        tokio::time::sleep(SETTLE).await;
        let Some(settled) = stamp(&local).await else {
            send(&app, EditStatus::plain("closed"));
            return;
        };
        if settled != current {
            // Still moving; the next poll picks it up from here.
            continue;
        }

        baseline = Some(settled);
        send(&app, EditStatus::plain("uploading"));
        send(
            &app,
            match push().await {
                Ok(()) => EditStatus::plain("synced"),
                Err(message) => EditStatus {
                    state: "error",
                    message: Some(message),
                },
            },
        );
    }

    // Stopped — by the editor closing, by "Stop watching", or by the
    // browser going away. Whatever was saved in the last second has not been
    // through a poll yet, so it goes now: losing the edit that prompted
    // closing the editor would be the worst moment to lose one.
    if let Some(current) = stamp(&local).await {
        if Some(current) != baseline {
            send(&app, EditStatus::plain("uploading"));
            send(
                &app,
                match push().await {
                    Ok(()) => EditStatus::plain("synced"),
                    Err(message) => EditStatus {
                        state: "error",
                        message: Some(message),
                    },
                },
            );
        }
    }

    // Last, so the frontend takes the row away only once nothing more is
    // coming for it.
    send(&app, EditStatus::plain("closed"));
}

/// Stops watching an open edit, whichever protocol it belongs to.
///
/// The working copy is left in place rather than deleted: it costs nothing
/// sitting in the temp directory, and removing it out from under an editor
/// that still has it open would be its own kind of surprise.
#[tauri::command]
pub async fn edit_close(watchers: State<'_, EditWatchers>, edit_id: String) -> Result<(), String> {
    if let Some(edit) = watchers.0.lock().await.remove(&edit_id) {
        edit.stop.store(true, Ordering::Relaxed);
    }
    Ok(())
}
