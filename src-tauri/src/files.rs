//! The local half of the file browser, and the shapes both halves share.
//!
//! The browser puts the local machine next to the remote one, so both sides
//! have to describe a directory the same way — that is what [`Entry`] and
//! [`Listing`] are for; [`crate::sftp`] fills in the same shapes from the
//! other end.
//!
//! Path arithmetic lives here rather than in the frontend, because the two
//! sides do not agree on it: the remote side is always POSIX, the local one is
//! whatever this machine runs. Every listing therefore reports the directory
//! it actually read and what sits above it, instead of leaving the frontend to
//! work that out from a string.

use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use rust_i18n::t;
use serde::Serialize;
use tauri::{AppHandle, Manager};
use tokio::fs;

/// One file or directory, on either side.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Entry {
    pub name: String,
    /// Absolute, and in the form its own side expects it back in.
    pub path: String,
    /// A symlink pointing at a directory is one too: it can be entered, which
    /// is what this decides.
    pub is_dir: bool,
    pub is_symlink: bool,
    /// Meaningless for directories, which report whatever the filesystem uses
    /// for the entry itself.
    pub size: u64,
    /// Unix seconds, `None` where the filesystem or the server did not say.
    pub modified: Option<i64>,
    /// `rwxr-xr-x`, the way `ls` prints it. Remote only — Windows has nothing
    /// to put here.
    pub permissions: Option<String>,
    /// The same permissions as the raw bits `chmod` takes — owner, group and
    /// other read/write/execute, plus setuid, setgid and sticky. Remote only,
    /// masked to the low 12 bits: the file-type bits above them are none of a
    /// chmod dialog's business.
    pub mode: Option<u32>,
}

/// What one directory read gives back.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Listing {
    /// The directory that was read, resolved. What was asked for may have been
    /// relative, or have had a `..` in it.
    pub path: String,
    /// `None` at the top of the tree, which is what disables "Up".
    pub parent: Option<String>,
    pub entries: Vec<Entry>,
    /// The server had more than was read — only S3 cuts a listing short, at
    /// [`crate::s3`]'s limit. The pane says so instead of showing a part as if
    /// it were the whole.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub truncated: bool,
}

/// Directories first, then by name, case ignored — the order every file
/// manager uses, and applied on this side so both panes match.
pub fn sort(entries: &mut [Entry]) {
    entries.sort_by(|a, b| {
        b.is_dir
            .cmp(&a.is_dir)
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });
}

/// The parent of a path on the remote side, which is always POSIX whatever
/// this machine uses.
///
/// Here rather than in one of the two remote modules because both of them need
/// it and neither owns it: SFTP and FTP disagree about almost everything and
/// agree about this.
pub fn remote_parent(path: &str) -> Option<String> {
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        return None;
    }
    match trimmed.rfind('/') {
        Some(0) => Some("/".to_string()),
        Some(cut) => Some(trimmed[..cut].to_string()),
        None => None,
    }
}

fn to_string(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

/// Where a local pane starts.
///
/// Through Tauri rather than the environment directly, so this keeps working
/// on the platforms that do not set `HOME`.
#[tauri::command]
pub fn local_home(app: AppHandle) -> Result<String, String> {
    app.path()
        .home_dir()
        .map(|path| to_string(&path))
        .map_err(|e| t!("files.home_not_found", error = e).into_owned())
}

/// The drives to offer above the local pane.
///
/// Windows has no single root, so the pane would otherwise be stuck on
/// whichever drive it started on. Everywhere else the one root is the answer.
#[tauri::command]
pub fn local_roots() -> Vec<String> {
    if !cfg!(windows) {
        return vec!["/".to_string()];
    }
    (b'A'..=b'Z')
        .map(|letter| format!("{}:\\", letter as char))
        .filter(|root| std::fs::metadata(root).is_ok())
        .collect()
}

#[tauri::command]
pub async fn local_list(path: String) -> Result<Listing, String> {
    // Resolves `..` and any symlinks on the way, so the pane's path bar says
    // where it really is. A directory that cannot be canonicalised — a
    // permission problem, or a path that is simply gone — is reported as
    // given, and the read below then says what is actually wrong.
    let dir = fs::canonicalize(&path)
        .await
        .map(|resolved| strip_verbatim(&resolved))
        .unwrap_or_else(|_| PathBuf::from(&path));

    let mut read = fs::read_dir(&dir)
        .await
        .map_err(|e| t!("files.read_failed", path = dir.display(), error = e).into_owned())?;

    let mut entries = Vec::new();
    while let Some(item) = read
        .next_entry()
        .await
        .map_err(|e| t!("files.read_failed", path = dir.display(), error = e).into_owned())?
    {
        // Anything unreadable is skipped rather than failing the listing: one
        // entry the user has no rights to must not hide the rest of the
        // directory.
        let Ok(kind) = item.file_type().await else {
            continue;
        };
        let full = item.path();
        let is_symlink = kind.is_symlink();

        // `metadata` follows symlinks where `file_type` above does not, which
        // is what decides whether a link can be entered and gives the size of
        // what it points at rather than of the link itself. A broken link
        // falls back on what is already known about it.
        let (is_dir, size, modified) = match fs::metadata(&full).await {
            Ok(meta) => (
                meta.is_dir(),
                meta.len(),
                meta.modified()
                    .ok()
                    .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                    .map(|d| d.as_secs() as i64),
            ),
            Err(_) => (kind.is_dir(), 0, None),
        };

        entries.push(Entry {
            name: item.file_name().to_string_lossy().into_owned(),
            path: to_string(&full),
            is_dir,
            is_symlink,
            size,
            modified,
            permissions: None,
            mode: None,
        });
    }
    sort(&mut entries);

    Ok(Listing {
        path: to_string(&dir),
        parent: dir.parent().map(to_string),
        entries,
        truncated: false,
    })
}

/// Windows canonicalisation returns `\\?\C:\…`, which is correct and which no
/// user wants to read. The prefix is only needed past the old path limit, and
/// nothing here goes near it.
fn strip_verbatim(path: &Path) -> PathBuf {
    let text = path.to_string_lossy();
    match text.strip_prefix(r"\\?\") {
        Some(rest) => PathBuf::from(rest),
        None => path.to_path_buf(),
    }
}

/// Describes one path the way a listing describes its entries.
///
/// A drop from the file manager arrives as a list of paths and nothing else;
/// this is what turns them back into something the transfer queue can carry.
#[tauri::command]
pub async fn local_stat(path: String) -> Result<Entry, String> {
    let full = PathBuf::from(&path);
    let meta = fs::metadata(&full)
        .await
        .map_err(|e| t!("files.read_failed", path = path, error = e).into_owned())?;
    // Follows nothing, unlike the line above: whether this *is* a link is a
    // different question from what it points at.
    let is_symlink = fs::symlink_metadata(&full)
        .await
        .map(|link| link.is_symlink())
        .unwrap_or(false);

    Ok(Entry {
        // A drive root has no file name of its own, so it stands in for one.
        name: full
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.clone()),
        path: to_string(&full),
        is_dir: meta.is_dir(),
        is_symlink,
        size: meta.len(),
        modified: meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs() as i64),
        permissions: None,
        mode: None,
    })
}

/// Whether a local path exists at all — file, directory, either.
///
/// What the overwrite question is built on: it has to know before a transfer
/// starts, not find out from the failure of one that clobbered something.
#[tauri::command]
pub async fn local_exists(path: String) -> bool {
    fs::metadata(&path).await.is_ok()
}

/// Creates the directory and every missing one above it — what a download into
/// a nested target needs.
#[tauri::command]
pub async fn local_mkdir(path: String) -> Result<(), String> {
    fs::create_dir_all(&path)
        .await
        .map_err(|e| t!("files.create_failed", path = path, error = e).into_owned())
}

#[tauri::command]
pub async fn local_remove(path: String, is_dir: bool) -> Result<(), String> {
    let result = if is_dir {
        fs::remove_dir_all(&path).await
    } else {
        fs::remove_file(&path).await
    };
    result.map_err(|e| t!("files.delete_failed", path = path, error = e).into_owned())
}

#[tauri::command]
pub async fn local_rename(from: String, to: String) -> Result<(), String> {
    fs::rename(&from, &to)
        .await
        .map_err(|e| t!("files.rename_failed", path = from, error = e).into_owned())
}

/// Creates an empty file, and fails if something is already there.
///
/// "New file" beside "New folder". `create_new` rather than a check
/// followed by a create: the check would race anything else writing to the
/// same directory, and emptying a file that was already there is the one
/// outcome nobody picking a name in a dialog meant.
#[tauri::command]
pub async fn local_create_file(path: String) -> Result<(), String> {
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .await
        .map(|_| ())
        .map_err(|e| t!("files.create_failed", path = path, error = e).into_owned())
}
