//! What a stopped transfer left behind, and whether it still fits.
//!
//! A transfer that stops leaves its `.wtpart` file in place on purpose, so the
//! next attempt can carry on from where it got to. Its length alone does not
//! say whether that is safe: a source replaced since by a different file of
//! the same length — or a shorter one — would be resumed into, and the result
//! would be neither file. So what was known about the source at the moment the
//! fragment was written is kept here, and a fragment is only trusted when the
//! source still matches it.
//!
//! Written only when a transfer ends badly. One that succeeds has nothing to
//! remember, and writing on every start would mean one file write per queued
//! file — for a dragged folder of two hundred, two hundred writes of a map
//! that grows as it goes. The price is a fragment left behind by a killed
//! process: it has no entry here, so it is not resumed and is written over
//! from the beginning. Safe, just not clever.

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager};
use tokio::sync::Mutex;

use crate::transfer::WORKING_SUFFIX;

const FILE_NAME: &str = "partials.json";

/// How long a note and its fragment are kept. After that nobody is coming
/// back for it, and a half-written copy of a file only takes up room.
const MAX_AGE: Duration = Duration::from_secs(30 * 24 * 60 * 60);

/// What the source of a fragment looked like when the fragment was written.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Partial {
    /// Where it was coming from.
    ///
    /// Checked as well as the key, because the key is the target path on its
    /// own: two servers can offer the same path, and this is what tells their
    /// fragments apart. A mismatch is not resumed, which is the safe answer
    /// for a collision this unlikely.
    pub source: String,
    pub size: u64,
    /// Unix seconds, or 0 where the side it came from would not say — in
    /// which case the size carries the check by itself, as it did before.
    pub modified: i64,
}

/// The fragments worth remembering, by the path they are on their way to.
///
/// Read from disk once per run and written back on every change. Both are
/// cheap: the map only ever holds transfers that stopped and have not been
/// picked up again.
#[derive(Default)]
pub struct Partials(Mutex<Loaded>);

#[derive(Default)]
struct Loaded {
    read: bool,
    entries: HashMap<String, Stored>,
}

/// A [`Partial`] with the day it was noted, so old ones can be cleared out.
///
/// Kept beside it rather than inside: whether a fragment fits its source is a
/// question about the source, and the day has no say in it. `noted` is 0 in a
/// file written before it existed — those start counting at the next start.
#[derive(Serialize, Deserialize, Clone, Debug)]
struct Stored {
    #[serde(flatten)]
    partial: Partial,
    #[serde(default)]
    noted: i64,
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

/// `partials.json` in the app's data directory — beside the workspaces, for
/// the same reasons; see [`crate::paths`].
fn file_path(app: &AppHandle) -> Result<PathBuf, String> {
    let dir = crate::paths::app_data_dir(app)?;
    Ok(dir.join(FILE_NAME))
}

fn read(app: &AppHandle) -> HashMap<String, Stored> {
    // A damaged or missing file is not an error worth surfacing: the worst it
    // costs is a transfer that starts over.
    let Ok(path) = file_path(app) else {
        return HashMap::new();
    };
    let Ok(raw) = fs::read_to_string(&path) else {
        return HashMap::new();
    };
    serde_json::from_str(&raw).unwrap_or_default()
}

fn write(app: &AppHandle, entries: &HashMap<String, Stored>) {
    let Ok(path) = file_path(app) else {
        return;
    };
    if let Some(dir) = path.parent() {
        let _ = fs::create_dir_all(dir);
    }
    let Ok(json) = serde_json::to_string_pretty(entries) else {
        return;
    };
    // Beside the target and renamed, the same as the workspaces: an
    // interrupted write must not leave a half-written file where the list was.
    let tmp = path.with_extension("json.tmp");
    if fs::write(&tmp, json).is_ok() {
        let _ = fs::rename(&tmp, &path);
    }
}

impl Partials {
    async fn loaded(&self) -> tokio::sync::MutexGuard<'_, Loaded> {
        self.0.lock().await
    }

    fn fill(app: &AppHandle, state: &mut Loaded) {
        if !state.read {
            state.entries = read(app);
            state.read = true;
        }
    }

    /// Whether the fragment on `target` may be carried on from.
    ///
    /// True only when a stored entry describes exactly the source given —
    /// same path, same length, same modification time.
    pub async fn resumable(&self, app: &AppHandle, target: &str, source: &Partial) -> bool {
        let mut state = self.loaded().await;
        Self::fill(app, &mut state);
        state.entries.get(target).map(|stored| &stored.partial) == Some(source)
    }

    /// Notes that `target` has a fragment on it, and what it came from.
    pub async fn remember(&self, app: &AppHandle, target: &str, source: Partial) {
        let mut state = self.loaded().await;
        Self::fill(app, &mut state);
        if state.entries.get(target).map(|stored| &stored.partial) == Some(&source) {
            return;
        }
        let stored = Stored {
            partial: source,
            noted: now(),
        };
        state.entries.insert(target.to_string(), stored);
        write(app, &state.entries);
    }

    /// Drops the note for `target`, if there was one. The fragment itself is
    /// the caller's business — it may have been renamed into place, deleted,
    /// or never have existed.
    pub async fn forget(&self, app: &AppHandle, target: &str) {
        let mut state = self.loaded().await;
        Self::fill(app, &mut state);
        if state.entries.remove(target).is_some() {
            write(app, &state.entries);
        }
    }
}

/// Which notes are older than `max_age` — the targets to drop. Notes from
/// before the day was recorded are stamped with `now` instead and kept, so
/// they get their own full span rather than going on the first start.
fn expired(entries: &mut HashMap<String, Stored>, now: i64, max_age: i64) -> Vec<String> {
    let mut old = Vec::new();
    for (target, stored) in entries.iter_mut() {
        if stored.noted == 0 {
            stored.noted = now;
        } else if now - stored.noted > max_age {
            old.push(target.clone());
        }
    }
    old
}

/// Clears out what has been lying around for [`MAX_AGE`]: the note, and the
/// fragment where it is on this machine.
///
/// A fragment is only removed if it carries the working suffix *and* has not
/// been touched for as long itself. The note's key is a path on whichever side
/// the transfer was writing to, so it can name a file on a server — which this
/// does not reach, and which therefore stays. That is what is left of the
/// problem in TODO.md.
async fn sweep(app: &AppHandle) {
    let partials = app.state::<Partials>();
    let mut state = partials.loaded().await;
    Partials::fill(app, &mut state);

    let max_age = MAX_AGE.as_secs() as i64;
    let old = expired(&mut state.entries, now(), max_age);
    for target in &old {
        state.entries.remove(target);
        let working = format!("{target}{WORKING_SUFFIX}");
        let untouched = fs::metadata(&working)
            .and_then(|meta| meta.modified())
            .is_ok_and(|time| time.elapsed().is_ok_and(|age| age > MAX_AGE));
        if untouched {
            let _ = fs::remove_file(&working);
        }
    }
    // Also writes back the stamps given to notes that had none.
    write(app, &state.entries);
}

/// Runs [`sweep`] once at start, off the thread that builds the window.
pub fn sweep_on_start(app: &AppHandle) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move { sweep(&app).await });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stored(noted: i64) -> Stored {
        Stored {
            partial: Partial {
                source: "s".into(),
                size: 1,
                modified: 0,
            },
            noted,
        }
    }

    #[test]
    fn only_old_notes_expire() {
        let mut entries = HashMap::from([
            ("old".to_string(), stored(100)),
            ("new".to_string(), stored(950)),
            ("undated".to_string(), stored(0)),
        ]);
        let old = expired(&mut entries, 1000, 500);
        assert_eq!(old, vec!["old".to_string()]);
        assert_eq!(entries["undated"].noted, 1000, "counts from now on");
    }

    #[test]
    fn an_old_file_without_a_date_is_read() {
        let old = r#"{"a":{"source":"s","size":1,"modified":0}}"#;
        let entries: HashMap<String, Stored> = serde_json::from_str(old).expect("reads");
        assert_eq!(entries["a"].noted, 0);
        let new = serde_json::to_string(&entries).expect("writes");
        assert!(new.contains("\"noted\":0"), "{new}");
    }
}
