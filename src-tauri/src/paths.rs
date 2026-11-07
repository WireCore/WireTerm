//! Where the app keeps its own files.
//!
//! In one place, because a build run from source and an installed build must
//! not write into the same folder: the workspaces used for testing would
//! otherwise be the workspaces used for work, and a half-finished feature
//! could damage the file the user actually depends on.
//!
//! The installed app uses the platform's usual directory, unchanged. Only a
//! development build steps aside, into the sibling folder with `-dev`
//! appended. `tauri dev` compiles with debug assertions on and `tauri build`
//! without, so nothing has to be configured or remembered for this — it
//! follows from how the binary was built.

use std::path::PathBuf;

use rust_i18n::t;
use tauri::{AppHandle, Manager};

/// `%APPDATA%\<bundle identifier>` on Windows, the platform equivalent
/// elsewhere — and in a development build `%APPDATA%\<bundle identifier>-dev`
/// instead.
///
/// Not created here: whoever writes creates it, and whoever reads treats a
/// missing folder as nothing stored yet.
pub fn app_data_dir(app: &AppHandle) -> Result<PathBuf, String> {
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|e| t!("core.no_app_data_dir", error = e).to_string())?;
    Ok(stepped_aside(dir))
}

#[cfg(debug_assertions)]
fn stepped_aside(dir: PathBuf) -> PathBuf {
    // A resolver that handed back a path without a last component would leave
    // nothing to rename; that the installed app's folder is then used is the
    // lesser of the two problems, and cannot happen on any platform Tauri
    // supports.
    match dir.file_name() {
        Some(name) => {
            let dev = format!("{}-dev", name.to_string_lossy());
            dir.with_file_name(dev)
        }
        None => dir,
    }
}

#[cfg(not(debug_assertions))]
fn stepped_aside(dir: PathBuf) -> PathBuf {
    dir
}
