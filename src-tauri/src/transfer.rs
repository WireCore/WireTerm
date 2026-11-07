//! What every transfer has in common, whichever protocol carries it.
//!
//! SFTP and FTP move bytes over entirely different machinery, but they answer
//! the same questions on the way: how often to tell the queue about progress,
//! what a cancelled transfer looks like, and where the half-written file lives
//! until it is whole. Those answers belong in one place — the alternative is
//! two copies that drift, and a user who finds `.wtpart` files behaving one
//! way over SSH and another over FTP.
//!
//! What is *not* here is the moving of the bytes. [`crate::sftp`] pipelines
//! sixteen requests down one channel; [`crate::ftp`] opens a data connection
//! per file and has to be told where to resume by a separate command. There is
//! nothing shared in that beyond the loop shape, and pretending otherwise
//! would cost more than it saves.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::Serialize;
use tauri::{AppHandle, Emitter, State};
use tokio::sync::Mutex;

/// What a cancelled transfer fails with.
///
/// A marker rather than a sentence: the frontend tells "cancelled" from
/// "failed" by it, and only the latter is worth showing an error for.
pub const CANCELLED: &str = "transfer:cancelled";

/// How much is moved between progress reports.
///
/// Not how much is read or written at once — both protocols move far larger
/// pieces than this underneath. It only decides how often the queue redraws.
pub const CHUNK: usize = 64 * 1024;

/// The shortest gap between two progress events for the same transfer.
///
/// A fast local transfer would otherwise emit thousands a second, and the
/// queue cannot draw anywhere near that often.
pub const PROGRESS_INTERVAL: Duration = Duration::from_millis(120);

/// What a transfer writes to while it runs.
///
/// Only ever renamed to the name it was asked for once every byte has arrived
/// and been confirmed. Until then it sits under this name, which is also what
/// lets a later attempt pick a stalled one back up: both protocols look for it
/// before starting from nothing.
pub const WORKING_SUFFIX: &str = ".wtpart";

/// Named per session, for the same reason terminal output is: only the tab
/// that started a transfer is woken by it. Not named per protocol — the queue
/// under the file browser draws the same rows either way.
pub fn progress_event(session_id: &str) -> String {
    format!("transfer:progress:{session_id}")
}

/// One transfer's whole state, sent on every report.
///
/// The whole state rather than a delta, so a dropped event costs nothing —
/// the next one is complete again.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct Progress {
    id: String,
    transferred: u64,
    /// 0 where the size is not known in advance — a remote file whose server
    /// did not report one.
    total: u64,
}

/// The flags cancellable transfers watch, by transfer id.
///
/// One map for both protocols: a transfer id is unique across the app, and
/// "stop" means the same thing to either side.
#[derive(Default)]
pub struct Transfers(Mutex<HashMap<String, Arc<AtomicBool>>>);

impl Transfers {
    pub async fn start(&self, id: &str) -> Arc<AtomicBool> {
        let flag = Arc::new(AtomicBool::new(false));
        self.0
            .lock()
            .await
            .insert(id.to_string(), Arc::clone(&flag));
        flag
    }

    pub async fn finish(&self, id: &str) {
        self.0.lock().await.remove(id);
    }

    /// For an operation that may or may not be cancellable: the frontend names
    /// it when it offers a stop button, and says nothing otherwise.
    pub async fn begin(&self, id: &Option<String>) -> Arc<AtomicBool> {
        match id {
            Some(id) => self.start(id).await,
            None => Arc::new(AtomicBool::new(false)),
        }
    }

    pub async fn end(&self, id: &Option<String>) {
        if let Some(id) = id {
            self.finish(id).await;
        }
    }
}

/// Asks a running transfer to stop.
///
/// An id that is not running is ignored rather than reported: the transfer may
/// have finished in the moment between the click and this arriving.
#[tauri::command]
pub async fn transfer_cancel(
    transfers: State<'_, Transfers>,
    transfer_id: String,
) -> Result<(), String> {
    if let Some(flag) = transfers.0.lock().await.get(&transfer_id) {
        flag.store(true, Ordering::Relaxed);
    }
    Ok(())
}

/// Reports progress, but not more often than [`PROGRESS_INTERVAL`].
///
/// Holds the time of the last report so the caller does not have to; `force`
/// is what the final one passes, which must never be dropped.
pub struct Reporter {
    /// `None` only in the live tests, which move real bytes against a real
    /// server with no window behind them to report to.
    app: Option<AppHandle>,
    event: String,
    id: String,
    total: u64,
    last: Instant,
}

impl Reporter {
    pub fn new(app: &AppHandle, session_id: &str, id: &str, total: u64) -> Self {
        Self {
            app: Some(app.clone()),
            event: progress_event(session_id),
            id: id.to_string(),
            total,
            // Far enough back that the first chunk reports straight away: a
            // transfer that starts silently looks like one that is stuck.
            // `checked_sub` because the clock has a floor and may be younger
            // than the interval shortly after a boot.
            last: Instant::now()
                .checked_sub(PROGRESS_INTERVAL)
                .unwrap_or_else(Instant::now),
        }
    }

    pub fn report(&mut self, transferred: u64, force: bool) {
        if !force && self.last.elapsed() < PROGRESS_INTERVAL {
            return;
        }
        self.last = Instant::now();
        let Some(app) = &self.app else {
            return;
        };
        let _ = app.emit(
            &self.event,
            Progress {
                id: self.id.clone(),
                transferred,
                total: self.total,
            },
        );
    }
}

/// A reporter with nowhere to report to.
///
/// For the tests that move real bytes against a real server: they exercise
/// the transfer itself, which is the part worth testing, and there is no
/// window behind them for a progress event to reach.
#[cfg(test)]
impl Reporter {
    pub fn silent(total: u64) -> Self {
        Self {
            app: None,
            event: String::new(),
            id: String::new(),
            total,
            last: Instant::now(),
        }
    }
}

/// One transfer: the two paths it is between, and who to report about it as.
///
/// Together rather than as four parameters, because they travel together
/// through every layer below — the wrapper, the resume check and the bytes
/// themselves — and none of them means anything without the others.
#[derive(Clone, Copy)]
pub struct Job<'a> {
    /// Names the tab, which is what the progress events are addressed to.
    pub session_id: &'a str,
    pub transfer_id: &'a str,
    pub local: &'a str,
    pub remote: &'a str,
}
