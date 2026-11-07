//! SFTP — the file browser that sits beside each terminal.
//!
//! SFTP is a subsystem of SSH, not a protocol of its own: it runs over the
//! same connection, behind the same host-key check and the same login. So a
//! tab opens one connection ([`crate::ssh::Transports`]) and this takes
//! another channel on it. Opening the file browser on a tab whose terminal is
//! already up costs one channel and no authentication at all.
//!
//! Transfers report progress as `transfer:progress:<session_id>` and behave
//! the same way they do over FTP — the queue, the cancelling and the
//! `.wtpart` file are all decided in [`crate::transfer`], and what is here is
//! only how SFTP moves the bytes.
//!
//! Directories are not transferred here. The frontend walks them and queues
//! one transfer per file, which is what lets the queue show what is actually
//! happening rather than one row that sits at 0% for a minute. The frontend
//! also runs several of these at once: [`SftpSession`] pipelines its requests
//! over the one channel by request id (see its `DashMap` of in-flight
//! requests), so concurrent transfers on the same session are the library's
//! own intended use, not something worked around here.

use std::collections::HashMap;
use std::io::SeekFrom;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use russh_sftp::client::SftpSession;
use russh_sftp::protocol::{FileAttributes, OpenFlags};
use rust_i18n::t;
use serde::Serialize;
use tauri::{AppHandle, Manager, State};
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::sync::Mutex;

use crate::edit::{self, EditSession, EditWatchers, EditorCommand};
use crate::files::{self, Entry, Listing};
use crate::resume::{Partial, Partials};
use crate::ssh::{Transport, Transports};
use crate::storage::SshSettings;
use crate::transfer::{Job, Reporter, Transfers, CANCELLED, CHUNK, WORKING_SUFFIX};

/// Per request, not per transfer. The default of ten seconds is tight on a
/// slow link, and a timed-out request fails the whole transfer.
const REQUEST_TIMEOUT: u64 = 30;

/// How many symlinks in one directory are resolved.
///
/// Whether a link can be entered takes a round trip each, and a directory of
/// thousands of them would turn one listing into thousands of requests. Past
/// the cap they are listed as what they are and simply cannot be opened.
const LINK_LIMIT: usize = 128;

// ---- Sessions ---------------------------------------------------------------

/// An open file browser: the SFTP channel, and the connection under it.
struct Browser {
    sftp: Arc<SftpSession>,
    /// Where the pane starts, remembered so reconnecting lands in the same
    /// place rather than asking the server again.
    home: String,
    /// Holds the tab's connection up for as long as the browser is open, so
    /// closing the terminal beside it does not pull it away.
    _transport: Transport,
}

#[derive(Default)]
pub struct SftpState(Mutex<HashMap<String, Browser>>);

impl SftpState {
    async fn session(&self, session_id: &str) -> Result<Arc<SftpSession>, String> {
        self.0
            .lock()
            .await
            .get(session_id)
            .map(|browser| Arc::clone(&browser.sftp))
            .ok_or_else(|| t!("sftp.not_connected").into_owned())
    }

    /// Closes the browser on a tab, if one was ever opened.
    pub(crate) async fn close(&self, session_id: &str) {
        let Some(browser) = self.0.lock().await.remove(session_id) else {
            return;
        };
        let _ = browser.sftp.close().await;
    }
}

/// Opens the file browser on a tab and reports where it starts.
///
/// Called again after an error, and safe to: a browser that is still answering
/// is kept, and one that is not is replaced.
#[tauri::command]
pub async fn sftp_connect(
    app: AppHandle,
    transports: State<'_, Transports>,
    state: State<'_, SftpState>,
    session_id: String,
    settings: SshSettings,
) -> Result<String, String> {
    // Asking the server where "." is doubles as the liveness check: an answer
    // means the channel is still good, and it is the same request the first
    // connect makes anyway. Taken out of the map before asking, so a slow
    // server does not hold every other browser up behind the lock.
    let existing = state
        .0
        .lock()
        .await
        .get(&session_id)
        .map(|browser| (Arc::clone(&browser.sftp), browser.home.clone()));
    if let Some((sftp, home)) = existing {
        if sftp.canonicalize(".").await.is_ok() {
            return Ok(home);
        }
    }

    // Without the map locked: logging in can take seconds if the terminal has
    // not already done it.
    let transport = transports.get(&app, &session_id, &settings).await?;

    let channel = transport
        .channel_open_session()
        .await
        .map_err(|e| t!("sftp.channel_failed", error = e).into_owned())?;
    channel
        .request_subsystem(true, "sftp")
        .await
        .map_err(|e| t!("sftp.subsystem_refused", error = e).into_owned())?;

    let sftp = SftpSession::new(channel.into_stream())
        .await
        .map_err(|e| t!("sftp.start_failed", error = e).into_owned())?;
    sftp.set_timeout(REQUEST_TIMEOUT);

    // The login directory. Servers differ on what a bare relative path means
    // later on, so the pane works in absolute paths from here.
    let home = sftp
        .canonicalize(".")
        .await
        .map_err(|e| t!("sftp.home_not_found", error = e).into_owned())?;

    state.0.lock().await.insert(
        session_id,
        Browser {
            sftp: Arc::new(sftp),
            home: home.clone(),
            _transport: transport,
        },
    );
    Ok(home)
}

/// Closes the file browser, leaving the terminal beside it connected.
///
/// Also the end of every edit open on this tab: an edit's upload runs over
/// this same kind of session, and one belonging to a browser that just closed
/// has nothing left under it worth watching.
#[tauri::command]
pub async fn sftp_disconnect(
    state: State<'_, SftpState>,
    edits: State<'_, EditWatchers>,
    session_id: String,
) -> Result<(), String> {
    edits.stop_for_session(&session_id).await;
    state.close(&session_id).await;
    Ok(())
}

// ---- Directories -----------------------------------------------------------

#[tauri::command]
pub async fn sftp_list(
    state: State<'_, SftpState>,
    session_id: String,
    path: String,
) -> Result<Listing, String> {
    let sftp = state.session(&session_id).await?;

    // Resolved first, so the path bar shows where the pane really is after a
    // `..` or a symlinked directory.
    let dir = sftp
        .canonicalize(path.as_str())
        .await
        .unwrap_or_else(|_| path.clone());

    let read = sftp
        .read_dir(dir.as_str())
        .await
        .map_err(|e| t!("sftp.read_failed", path = dir, error = e).into_owned())?;

    let mut entries = Vec::new();
    let mut resolved = 0usize;
    for item in read {
        let name = item.file_name();
        if name == "." || name == ".." {
            continue;
        }
        let meta = item.metadata();
        let full = item.path();
        let is_symlink = meta.is_symlink();

        // `read_dir` reports the link itself, so following it is the only way
        // to know whether it opens into a directory.
        let mut is_dir = meta.is_dir();
        if is_symlink && resolved < LINK_LIMIT {
            resolved += 1;
            if let Ok(target) = sftp.metadata(full.as_str()).await {
                is_dir = target.is_dir();
            }
        }

        entries.push(Entry {
            name,
            path: full,
            is_dir,
            is_symlink,
            size: meta.len(),
            modified: meta.mtime.map(|t| t as i64),
            // The method answers for absent permissions too, with a string of
            // dashes that reads like a real answer. The field says whether
            // there was one.
            permissions: meta.permissions.map(|_| meta.permissions().to_string()),
            // The low 12 bits only — see the field's own doc comment. The raw
            // value also carries the file-type bits, which a chmod dialog has
            // no business seeing or sending back.
            mode: meta.permissions.map(|p| p & 0o7777),
        });
    }
    files::sort(&mut entries);

    Ok(Listing {
        parent: files::remote_parent(&dir),
        path: dir,
        entries,
        truncated: false,
    })
}

#[tauri::command]
pub async fn sftp_mkdir(
    state: State<'_, SftpState>,
    session_id: String,
    path: String,
) -> Result<(), String> {
    let sftp = state.session(&session_id).await?;
    // An upload into a tree creates the same directories over and over; one
    // that is already there is what was wanted, not a failure.
    if sftp.try_exists(path.as_str()).await.unwrap_or(false) {
        return Ok(());
    }
    sftp.create_dir(path.as_str())
        .await
        .map_err(|e| t!("sftp.create_failed", path = path, error = e).into_owned())
}

/// Creates an empty file, and fails if something is already there.
///
/// "New file" beside "New folder", and the refusal is the point: this is
/// reached from a dialog that just asked for a name, where silently emptying
/// an existing file would be the one outcome nobody meant.
#[tauri::command]
pub async fn sftp_create_file(
    state: State<'_, SftpState>,
    session_id: String,
    path: String,
) -> Result<(), String> {
    let sftp = state.session(&session_id).await?;
    if sftp.try_exists(path.as_str()).await.unwrap_or(false) {
        return Err(t!("sftp.already_exists", path = path).into_owned());
    }
    // EXCLUDE rather than a check alone: the test above races anything else
    // writing to the same directory, and the server settles it for good.
    let file = sftp
        .open_with_flags(
            path.as_str(),
            OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::EXCLUDE,
        )
        .await
        .map_err(|e| t!("sftp.create_failed", path = path, error = e).into_owned())?;
    file.close()
        .await
        .map_err(|e| t!("sftp.create_failed", path = path, error = e).into_owned())
}

/// How full the file system under a path is, in bytes.
#[derive(Serialize)]
pub struct Space {
    used: u64,
    total: u64,
}

impl Space {
    fn of(fs: &russh_sftp::extensions::Statvfs) -> Space {
        Space {
            used: fs.blocks.saturating_sub(fs.blocks_free) * fs.fragment_size,
            total: fs.blocks * fs.fragment_size,
        }
    }
}

/// `None` where the server does not offer `statvfs@openssh.com`, or reports
/// nothing usable. OpenSSH offers it, so most servers answer.
#[tauri::command]
pub async fn sftp_space(
    state: State<'_, SftpState>,
    session_id: String,
    path: String,
) -> Result<Option<Space>, String> {
    let sftp = state.session(&session_id).await?;
    let fs = sftp.fs_info(path.as_str()).await.ok().flatten();
    Ok(fs.map(|fs| Space::of(&fs)).filter(|space| space.total > 0))
}

/// Whether a remote path exists — file, directory, either.
///
/// What the overwrite question is built on, the same as [`files::local_exists`]
/// is for the other side.
#[tauri::command]
pub async fn sftp_exists(
    state: State<'_, SftpState>,
    session_id: String,
    path: String,
) -> Result<bool, String> {
    let sftp = state.session(&session_id).await?;
    Ok(sftp.try_exists(path.as_str()).await.unwrap_or(false))
}

#[tauri::command]
pub async fn sftp_rename(
    state: State<'_, SftpState>,
    session_id: String,
    from: String,
    to: String,
) -> Result<(), String> {
    let sftp = state.session(&session_id).await?;
    sftp.rename(from.as_str(), to.as_str())
        .await
        .map_err(|e| t!("sftp.rename_failed", path = from, error = e).into_owned())
}

/// Changes a remote entry's permission bits.
///
/// `mode` is the low 12 bits `chmod` would take — owner, group and other
/// read/write/execute, plus setuid, setgid and the sticky bit — masked here
/// again in case the frontend ever sent more. The file-type bits are never
/// touched: the server does not need them to carry out a chmod, and a wrong
/// one could reclassify what the entry is instead of merely its permissions.
///
/// A server that refuses — no rights to, a read-only mount, a chroot that does
/// not allow setuid — reports why in its own words, which is what reaches the
/// caller unchanged; there is nothing to paper over here.
/// What one recursive run did.
///
/// Counted rather than failed on the first refusal: one directory inside a
/// tree that the login may not touch must not stop the other nine hundred, and
/// afterwards the dialog can say plainly how many were left as they were.
#[derive(Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ChmodResult {
    pub changed: u32,
    pub failed: u32,
    /// The first refusal, in the server's own words. What the UI shows — the
    /// rest are nearly always the same sentence about the same mount.
    pub error: Option<String>,
    /// Stopped by the user before the tree was done; what was counted so far
    /// is still true.
    pub cancelled: bool,
}

/// What a file gets when a directory's mode is applied to a whole tree.
///
/// Not the mode itself: `755` on a source tree would make every `.php` in it
/// executable, which is the classic way `chmod -R` ruins a deployment. The
/// execute bits are therefore dropped for files that do not already carry one
/// — `chmod`'s own `a+X` rule, and what anyone setting `rwxr-xr-x` on a folder
/// actually means. A file that *is* a program keeps being one.
fn tree_file_mode(mode: u32, current: Option<u32>) -> u32 {
    let executable = current.is_some_and(|bits| bits & 0o111 != 0);
    if executable {
        mode
    } else {
        mode & !0o111
    }
}

async fn set_mode(sftp: &SftpSession, path: &str, mode: u32) -> Result<(), String> {
    let mut attrs = FileAttributes::empty();
    attrs.permissions = Some(mode & 0o7777);
    sftp.set_metadata(path, attrs)
        .await
        .map_err(|e| t!("sftp.chmod_failed", path = path, error = e).into_owned())
}

/// Applies `mode` to everything under `root`, `root` itself included.
///
/// Walked iteratively for the same reason [`remove_tree`] is: an async
/// function that calls itself has to box its own future, and a stack says the
/// same thing without that. Symlinks are not followed — changing the
/// permissions of whatever one happens to point at, possibly nowhere near this
/// tree, is never what "Also apply to contents" meant.
async fn chmod_tree(sftp: &SftpSession, root: &str, mode: u32, cancel: &AtomicBool) -> ChmodResult {
    let mut result = ChmodResult::default();
    let mut pending = vec![root.to_string()];

    let note = |outcome: Result<(), String>, result: &mut ChmodResult| match outcome {
        Ok(()) => result.changed += 1,
        Err(message) => {
            result.failed += 1;
            result.error.get_or_insert(message);
        }
    };

    note(set_mode(sftp, root, mode).await, &mut result);

    'walk: while let Some(dir) = pending.pop() {
        if cancel.load(Ordering::Relaxed) {
            result.cancelled = true;
            break;
        }
        let Ok(read) = sftp.read_dir(dir.as_str()).await else {
            // Unreadable, so there is nothing below it to reach. Counted once
            // rather than silently: the total the dialog reports has to add up.
            result.failed += 1;
            result
                .error
                .get_or_insert_with(|| t!("sftp.read_failed_bare", path = dir).into_owned());
            continue;
        };

        for item in read {
            if cancel.load(Ordering::Relaxed) {
                result.cancelled = true;
                break 'walk;
            }
            let name = item.file_name();
            if name == "." || name == ".." {
                continue;
            }
            let path = item.path();
            let metadata = item.metadata();
            // The entry's own kind, not what a link points at — see above.
            if metadata.is_dir() {
                pending.push(path.clone());
                note(set_mode(sftp, &path, mode).await, &mut result);
            } else {
                let file_mode = tree_file_mode(mode, metadata.permissions);
                note(set_mode(sftp, &path, file_mode).await, &mut result);
            }
        }
    }

    result
}

#[tauri::command]
pub async fn sftp_chmod(
    state: State<'_, SftpState>,
    transfers: State<'_, Transfers>,
    session_id: String,
    path: String,
    mode: u32,
    recursive: bool,
    operation_id: Option<String>,
) -> Result<ChmodResult, String> {
    let sftp = state.session(&session_id).await?;
    if !recursive {
        set_mode(&sftp, &path, mode).await?;
        return Ok(ChmodResult {
            changed: 1,
            ..Default::default()
        });
    }
    let cancel = transfers.begin(&operation_id).await;
    let result = chmod_tree(&sftp, &path, mode, &cancel).await;
    transfers.end(&operation_id).await;
    Ok(result)
}

#[tauri::command]
pub async fn sftp_remove(
    state: State<'_, SftpState>,
    session_id: String,
    path: String,
    is_dir: bool,
) -> Result<(), String> {
    let sftp = state.session(&session_id).await?;
    if is_dir {
        remove_tree(&sftp, &path).await
    } else {
        sftp.remove_file(path.as_str())
            .await
            .map_err(|e| t!("sftp.delete_failed", path = path, error = e).into_owned())
    }
}

/// Deletes a directory and everything under it.
///
/// SFTP has no recursive remove, so the tree is walked here. Iteratively
/// rather than recursively: an async function that calls itself has to box its
/// own future, and a stack says the same thing without that.
async fn remove_tree(sftp: &SftpSession, root: &str) -> Result<(), String> {
    let mut pending = vec![root.to_string()];
    // Depth-first order, in which a directory always comes before everything
    // inside it — so deleting in reverse empties each one before removing it.
    let mut dirs = Vec::new();

    while let Some(dir) = pending.pop() {
        let read = sftp
            .read_dir(dir.as_str())
            .await
            .map_err(|e| t!("sftp.read_failed", path = dir, error = e).into_owned())?;
        for item in read {
            let name = item.file_name();
            if name == "." || name == ".." {
                continue;
            }
            let path = item.path();
            // Deliberately not resolved: a symlink pointing at a directory is
            // unlinked, never followed. Following one would delete whatever it
            // happens to point at, which may be nowhere near this tree.
            if item.metadata().is_dir() {
                pending.push(path);
            } else {
                sftp.remove_file(path.as_str())
                    .await
                    .map_err(|e| t!("sftp.delete_failed", path = path, error = e).into_owned())?;
            }
        }
        dirs.push(dir);
    }

    for dir in dirs.into_iter().rev() {
        sftp.remove_dir(dir.as_str())
            .await
            .map_err(|e| t!("sftp.delete_failed", path = dir, error = e).into_owned())?;
    }
    Ok(())
}

// ---- Transfers -------------------------------------------------------------
//
// What a transfer looks like from the outside — progress, cancelling, the
// `.wtpart` file — is the same over either protocol and lives in
// [`crate::transfer`]. What is here is how SFTP moves the bytes.

/// Fetches one file, reporting as it goes. Returns the number of bytes moved.
///
/// Writes to `{local}.wtpart` and only renames it onto `local` once every byte
/// has arrived — a reader of `local` therefore only ever sees nothing or the
/// whole file, never a part of one sitting there under its real name. A
/// partial file left behind by a stopped attempt is not deleted, since that
/// same naming is what makes it safe to pick back up: this finds it and
/// carries on from where it stopped.
///
/// What makes that safe is [`crate::resume`], not the fragment's length: a
/// source replaced since by a different file of the same size would otherwise
/// be resumed into, and the result would be neither file. The fragment is only
/// trusted when the source still matches what it was written from, down to its
/// modification time.
async fn download(
    app: &AppHandle,
    sftp: &SftpSession,
    partials: &Partials,
    cancel: &AtomicBool,
    job: &Job<'_>,
) -> Result<u64, String> {
    let Job { local, remote, .. } = *job;
    let meta = sftp
        .metadata(remote)
        .await
        .map_err(|e| t!("sftp.read_failed", path = remote, error = e).into_owned())?;
    let source = Partial {
        source: remote.to_string(),
        size: meta.len(),
        modified: meta.mtime.unwrap_or(0) as i64,
    };
    let resumable = partials.resumable(app, local, &source).await;

    let result = fetch(app, sftp, cancel, job, meta.len(), resumable).await;

    match &result {
        // Renamed into place, so there is no fragment left to describe.
        Ok(_) => partials.forget(app, local).await,
        // Only where something is actually lying there: a transfer that failed
        // before writing a byte has nothing for a later attempt to continue.
        Err(_) => {
            let working = format!("{local}{WORKING_SUFFIX}");
            if fs::metadata(&working).await.map(|m| m.len()).unwrap_or(0) > 0 {
                partials.remember(app, local, source).await;
            }
        }
    }
    result
}

/// The bytes of a download, once [`download`] has settled whether the fragment
/// already on disk may be continued from.
async fn fetch(
    app: &AppHandle,
    sftp: &SftpSession,
    cancel: &AtomicBool,
    job: &Job<'_>,
    total: u64,
    resumable: bool,
) -> Result<u64, String> {
    // Destructured rather than reached through: everything below reads the
    // same four names it always did.
    let Job {
        session_id,
        transfer_id,
        local,
        remote,
    } = *job;
    let working = format!("{local}{WORKING_SUFFIX}");
    // Longer than the source it is meant to be a prefix of, and it cannot be
    // one whatever the notes say.
    let existing = fs::metadata(&working).await.map(|m| m.len()).unwrap_or(0);
    let start = if resumable && existing <= total {
        existing
    } else {
        0
    };

    let mut reporter = Reporter::new(app, session_id, transfer_id, total);
    reporter.report(start, true);

    // The queue creates the directories it needs before enqueuing, but a
    // single file dropped into a fresh target is the common case and this
    // costs nothing. Needed either way below, so it happens before the branch
    // rather than inside just one side of it.
    if let Some(parent) = Path::new(&working).parent() {
        let _ = fs::create_dir_all(parent).await;
    }

    if start < total {
        let mut source = sftp
            .open(remote)
            .await
            .map_err(|e| t!("sftp.open_failed", path = remote, error = e).into_owned())?;
        if start > 0 {
            source
                .seek(SeekFrom::Start(start))
                .await
                .map_err(|e| t!("sftp.resume_failed", path = remote, error = e).into_owned())?;
        }

        let mut target = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .append(start > 0)
            .truncate(start == 0)
            .open(&working)
            .await
            .map_err(|e| t!("sftp.write_failed", path = local, error = e).into_owned())?;

        let mut buffer = vec![0u8; CHUNK];
        let mut moved = start;

        loop {
            if cancel.load(Ordering::Relaxed) {
                return Err(CANCELLED.to_string());
            }
            let read = source
                .read(&mut buffer)
                .await
                .map_err(|e| t!("sftp.read_failed", path = remote, error = e).into_owned())?;
            if read == 0 {
                break;
            }
            target
                .write_all(&buffer[..read])
                .await
                .map_err(|e| t!("sftp.write_failed", path = local, error = e).into_owned())?;
            moved += read as u64;
            reporter.report(moved, false);
        }

        target
            .flush()
            .await
            .map_err(|e| t!("sftp.write_failed", path = local, error = e).into_owned())?;
    } else if start == 0 {
        // `start == total` and nothing was resumed, so the source is empty.
        // `create` truncates, which is what a fragment left by some earlier,
        // longer file needs: it is not a prefix of an empty file either, and
        // the rename below would otherwise put its tail in place.
        fs::File::create(&working)
            .await
            .map_err(|e| t!("sftp.write_failed", path = local, error = e).into_owned())?;
    }

    fs::rename(&working, local)
        .await
        .map_err(|e| t!("sftp.finish_failed", path = local, error = e).into_owned())?;
    reporter.report(total, true);
    Ok(total)
}

/// Fetches one file. Cleanup happens inside [`download`] on success; a stopped
/// attempt leaves its `.wtpart` file in place, on purpose — see there.
// Every parameter here is either state Tauri injects or an argument the
// frontend sends; there is nothing to group that would not also have to be
// grouped on the other side of the IPC boundary.
#[allow(clippy::too_many_arguments)]
#[tauri::command]
pub async fn sftp_download(
    app: AppHandle,
    state: State<'_, SftpState>,
    transfers: State<'_, Transfers>,
    partials: State<'_, Partials>,
    session_id: String,
    transfer_id: String,
    remote: String,
    local: String,
) -> Result<u64, String> {
    let sftp = state.session(&session_id).await?;
    let cancel = transfers.start(&transfer_id).await;
    let job = Job {
        session_id: &session_id,
        transfer_id: &transfer_id,
        local: &local,
        remote: &remote,
    };
    let result = download(&app, &sftp, &partials, &cancel, &job).await;
    transfers.finish(&transfer_id).await;
    result
}

/// Sends one file, reporting as it goes.
///
/// The mirror of [`download`]: written to `{remote}.wtpart` and only put in
/// place under its real name once it is whole. SFTP's own rename refuses a
/// destination that already exists, so the old one is removed first — safe
/// here specifically, because upstream only ever calls this once the
/// overwrite question has already been agreed to.
async fn upload(
    app: &AppHandle,
    sftp: &SftpSession,
    partials: &Partials,
    cancel: &AtomicBool,
    job: &Job<'_>,
) -> Result<u64, String> {
    let Job { local, remote, .. } = *job;
    let meta = fs::metadata(local)
        .await
        .map_err(|e| t!("sftp.read_failed", path = local, error = e).into_owned())?;
    let source = Partial {
        source: local.to_string(),
        size: meta.len(),
        modified: meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0),
    };
    let resumable = partials.resumable(app, remote, &source).await;

    let result = send(app, sftp, cancel, job, meta.len(), resumable).await;

    match &result {
        Ok(_) => partials.forget(app, remote).await,
        Err(_) => {
            let working = format!("{remote}{WORKING_SUFFIX}");
            let left = sftp
                .metadata(working.as_str())
                .await
                .map(|m| m.len())
                .unwrap_or(0);
            if left > 0 {
                partials.remember(app, remote, source).await;
            }
        }
    }
    result
}

/// The bytes of an upload, the mirror of [`fetch`].
async fn send(
    app: &AppHandle,
    sftp: &SftpSession,
    cancel: &AtomicBool,
    job: &Job<'_>,
    total: u64,
    resumable: bool,
) -> Result<u64, String> {
    let Job {
        session_id,
        transfer_id,
        local,
        remote,
    } = *job;
    let mut source = fs::File::open(local)
        .await
        .map_err(|e| t!("sftp.read_failed", path = local, error = e).into_owned())?;

    let working = format!("{remote}{WORKING_SUFFIX}");
    // Same check as the download side: a fragment longer than the source it is
    // meant to be a prefix of cannot be one.
    let existing = sftp
        .metadata(working.as_str())
        .await
        .map(|m| m.len())
        .unwrap_or(0);
    let start = if resumable && existing <= total {
        existing
    } else {
        0
    };

    let mut reporter = Reporter::new(app, session_id, transfer_id, total);
    reporter.report(start, true);

    if start < total {
        if start > 0 {
            source
                .seek(SeekFrom::Start(start))
                .await
                .map_err(|e| t!("sftp.resume_failed", path = local, error = e).into_owned())?;
        }

        // Truncated whenever this is not a continuation. Without that, a
        // fragment left by an earlier, longer file would keep its tail past
        // the end of what is written now, and the rename below would put a
        // file on the server that is longer than the one it came from.
        let mut flags = OpenFlags::WRITE | OpenFlags::CREATE;
        if start == 0 {
            flags |= OpenFlags::TRUNCATE;
        }

        let mut target = sftp
            .open_with_flags(working.as_str(), flags)
            .await
            .map_err(|e| t!("sftp.write_failed", path = remote, error = e).into_owned())?;
        if start > 0 {
            target
                .seek(SeekFrom::Start(start))
                .await
                .map_err(|e| t!("sftp.resume_failed", path = remote, error = e).into_owned())?;
        }

        let mut buffer = vec![0u8; CHUNK];
        let mut moved = start;

        loop {
            if cancel.load(Ordering::Relaxed) {
                return Err(CANCELLED.to_string());
            }
            let read = source
                .read(&mut buffer)
                .await
                .map_err(|e| t!("sftp.read_failed", path = local, error = e).into_owned())?;
            if read == 0 {
                break;
            }
            target
                .write_all(&buffer[..read])
                .await
                .map_err(|e| t!("sftp.write_failed", path = remote, error = e).into_owned())?;
            moved += read as u64;
            reporter.report(moved, false);
        }

        // Not just a flush: closing is what waits for the writes still in
        // flight and for the server to confirm them. Dropping the file
        // instead would report success before the last bytes had landed.
        target
            .close()
            .await
            .map_err(|e| t!("sftp.finish_failed", path = remote, error = e).into_owned())?;
    } else if start == 0 {
        // `start == total` and nothing was resumed, so the source is empty.
        // Truncating rather than only creating: whatever may be lying there
        // under the working name is not a prefix of an empty file either.
        let empty = sftp
            .open_with_flags(
                working.as_str(),
                OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::TRUNCATE,
            )
            .await
            .map_err(|e| t!("sftp.write_failed", path = remote, error = e).into_owned())?;
        empty
            .close()
            .await
            .map_err(|e| t!("sftp.write_failed", path = remote, error = e).into_owned())?;
    }

    let _ = sftp.remove_file(remote).await;
    sftp.rename(working.as_str(), remote)
        .await
        .map_err(|e| t!("sftp.finish_failed", path = remote, error = e).into_owned())?;
    reporter.report(total, true);
    Ok(total)
}

/// Sends one file. Cleanup happens inside [`upload`] on success; a stopped
/// attempt leaves its `.wtpart` file in place, on purpose — see there.
// Every parameter here is either state Tauri injects or an argument the
// frontend sends; there is nothing to group that would not also have to be
// grouped on the other side of the IPC boundary.
#[allow(clippy::too_many_arguments)]
#[tauri::command]
pub async fn sftp_upload(
    app: AppHandle,
    state: State<'_, SftpState>,
    transfers: State<'_, Transfers>,
    partials: State<'_, Partials>,
    session_id: String,
    transfer_id: String,
    local: String,
    remote: String,
) -> Result<u64, String> {
    let sftp = state.session(&session_id).await?;
    let cancel = transfers.start(&transfer_id).await;
    let job = Job {
        session_id: &session_id,
        transfer_id: &transfer_id,
        local: &local,
        remote: &remote,
    };
    let result = upload(&app, &sftp, &partials, &cancel, &job).await;
    transfers.finish(&transfer_id).await;
    result
}

/// Throws away what a stopped transfer left behind.
///
/// Reached from "Discard" in the queue, which is the one gesture that says
/// the transfer is not wanted after all — "Cancel" only stops it, and the
/// fragment stays so it can be picked up again. Failing is not worth
/// reporting: a fragment that is already gone is exactly the state being asked
/// for, and a server that refuses to delete it would also have refused to
/// write it.
#[tauri::command]
pub async fn sftp_discard(
    app: AppHandle,
    state: State<'_, SftpState>,
    partials: State<'_, Partials>,
    session_id: String,
    direction: String,
    local: String,
    remote: String,
) -> Result<(), String> {
    let target = if direction == "download" {
        &local
    } else {
        &remote
    };
    let working = format!("{target}{WORKING_SUFFIX}");

    if direction == "download" {
        let _ = fs::remove_file(&working).await;
    } else if let Ok(sftp) = state.session(&session_id).await {
        let _ = sftp.remove_file(working.as_str()).await;
    }

    partials.forget(&app, target).await;
    Ok(())
}
// ---- Editing on the server --------------------------------------------------
//
// How an edit works — the working copy, the editor, the polling — is the same
// over either protocol and lives in [`crate::edit`]. What is here is only the
// SFTP half: fetching the copy, and sending it back when it settles.

/// Downloads a copy to edit and starts watching it.
///
/// Kept apart from a normal transfer: this is expected to sit open for a
/// minute or an hour, not run once to completion, and it keeps its own clone
/// of the session for as long as the watch runs rather than reaching for the
/// browser's — which may by then have been asked for another directory
/// listing, or have closed.
#[tauri::command]
pub async fn sftp_edit_open(
    app: AppHandle,
    state: State<'_, SftpState>,
    watchers: State<'_, EditWatchers>,
    partials: State<'_, Partials>,
    session_id: String,
    remote: String,
    editor: Option<EditorCommand>,
) -> Result<EditSession, String> {
    let sftp = state.session(&session_id).await?;

    let id = edit::next_id();
    let name = edit::file_name(&remote);
    let local = edit::working_copy(&app, &id, &name)
        .await?
        .to_string_lossy()
        .into_owned();

    let cancel = AtomicBool::new(false);
    let job = Job {
        session_id: &session_id,
        transfer_id: &id,
        local: &local,
        remote: &remote,
    };
    download(&app, &sftp, &partials, &cancel, &job).await?;

    // Registered before the editor starts, so the flag exists for the process
    // watcher to set the moment it does.
    let stop = watchers.register(&id, &session_id).await;
    let opened = edit::open_editor(&app, editor, &local, &id, &stop)?;

    tauri::async_runtime::spawn(edit::watch(app.clone(), stop, id.clone(), local.clone(), {
        let app = app.clone();
        let sftp = Arc::clone(&sftp);
        let session_id = session_id.clone();
        let id = id.clone();
        let local = local.clone();
        let remote = remote.clone();
        move || {
            // Cloned again per call: the closure is a `Fn`, so it may be
            // called more than once and must not give its contents away.
            let (app, sftp) = (app.clone(), Arc::clone(&sftp));
            let (session_id, id) = (session_id.clone(), id.clone());
            let (local, remote) = (local.clone(), remote.clone());
            async move {
                let cancel = AtomicBool::new(false);
                let partials = app.state::<Partials>();
                let job = Job {
                    session_id: &session_id,
                    transfer_id: &id,
                    local: &local,
                    remote: &remote,
                };
                upload(&app, &sftp, &partials, &cancel, &job)
                    .await
                    .map(|_| ())
            }
        }
    }));

    Ok(EditSession {
        id,
        local_path: local,
        name,
        opened,
    })
}
