//! The local terminal: a shell on this machine, in a tab like an SSH
//! session.
//!
//! Runs over a pseudo terminal ([`portable_pty`]) — ConPTY on Windows,
//! openpty elsewhere. The UI addresses it like the SSH terminal, only under
//! its own name: `local:data:<session_id>` for the output,
//! `local:closed:<session_id>` for the end, `local_send`, `local_resize` and
//! `local_close` in the other direction.
//!
//! Nothing is saved. Which shells exist is looked up anew every time the menu
//! opens ([`local_shells`]).

use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use portable_pty::{native_pty_system, Child, CommandBuilder, MasterPty, PtySize};
use rust_i18n::t;
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager, State};

/// A shell that can be opened.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Shell {
    /// Stable across restarts, e.g. `pwsh` or `wsl:Ubuntu`.
    pub id: String,
    /// What appears in the menu and in the tab.
    pub name: String,
    pub program: String,
    #[serde(default)]
    pub args: Vec<String>,
}

impl Shell {
    fn new(id: &str, name: &str, program: impl Into<String>, args: &[&str]) -> Self {
        Self {
            id: id.to_string(),
            name: name.to_string(),
            program: program.into(),
            args: args.iter().map(|arg| arg.to_string()).collect(),
        }
    }
}

struct Session {
    writer: Box<dyn Write + Send>,
    master: Box<dyn MasterPty + Send>,
    child: Box<dyn Child + Send + Sync>,
}

/// The open local terminals, by session.
#[derive(Default)]
pub struct LocalTerminals(Mutex<HashMap<String, Session>>);

fn data_event(session_id: &str) -> String {
    format!("local:data:{session_id}")
}

fn closed_event(session_id: &str) -> String {
    format!("local:closed:{session_id}")
}

// ---- Finding shells --------------------------------------------------------------

/// The first `name` on the `PATH`, with the extensions Windows tries for it.
fn on_path(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    let suffixes: &[&str] = if cfg!(windows) { &["", ".exe"] } else { &[""] };
    std::env::split_paths(&path).find_map(|dir| {
        suffixes
            .iter()
            .map(|suffix| dir.join(format!("{name}{suffix}")))
            .find(|candidate| candidate.is_file())
    })
}

#[cfg(windows)]
fn first_existing(candidates: &[PathBuf]) -> Option<PathBuf> {
    candidates.iter().find(|path| path.is_file()).cloned()
}

/// What `wsl.exe -l -q` prints: UTF-16 LE, one name per line — sometimes with
/// a BOM, and in older versions with nulls between the lines. Without the
/// distributions Docker Desktop creates for itself: nobody works in those.
#[cfg(any(windows, test))]
fn wsl_distributions(raw: &[u8]) -> Vec<String> {
    let units: Vec<u16> = raw
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_le_bytes(*pair))
        .collect();
    String::from_utf16_lossy(&units)
        .replace(['\u{feff}', '\0'], "")
        .lines()
        .map(str::trim)
        .filter(|name| !name.is_empty() && !name.starts_with("docker-desktop"))
        .map(str::to_string)
        .collect()
}

#[cfg(windows)]
fn windows_shells() -> Vec<Shell> {
    use std::os::windows::process::CommandExt;
    /// No console window flashing up briefly while looking.
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    let mut shells = Vec::new();
    let env_dir = |name: &str| std::env::var_os(name).map(PathBuf::from);
    let program_files =
        env_dir("ProgramFiles").unwrap_or_else(|| PathBuf::from(r"C:\Program Files"));
    let system_root = env_dir("SystemRoot").unwrap_or_else(|| PathBuf::from(r"C:\Windows"));

    let pwsh = on_path("pwsh")
        .or_else(|| first_existing(&[program_files.join("PowerShell").join("7").join("pwsh.exe")]));
    if let Some(pwsh) = pwsh {
        shells.push(Shell::new(
            "pwsh",
            "PowerShell 7",
            pwsh.to_string_lossy(),
            &["-NoLogo"],
        ));
    }
    let powershell = system_root
        .join("System32")
        .join("WindowsPowerShell")
        .join("v1.0")
        .join("powershell.exe");
    if powershell.is_file() {
        shells.push(Shell::new(
            "powershell",
            "Windows PowerShell",
            powershell.to_string_lossy(),
            &["-NoLogo"],
        ));
    }
    let cmd = env_dir("ComSpec").unwrap_or_else(|| system_root.join("System32").join("cmd.exe"));
    if cmd.is_file() {
        shells.push(Shell::new(
            "cmd",
            &t!("core.shell_cmd"),
            cmd.to_string_lossy(),
            &[],
        ));
    }

    let wsl = system_root.join("System32").join("wsl.exe");
    if wsl.is_file() {
        let listed = std::process::Command::new(&wsl)
            .args(["-l", "-q"])
            .creation_flags(CREATE_NO_WINDOW)
            .output();
        if let Ok(output) = listed {
            if output.status.success() {
                for name in wsl_distributions(&output.stdout) {
                    shells.push(Shell::new(
                        &format!("wsl:{name}"),
                        &format!("WSL: {name}"),
                        wsl.to_string_lossy(),
                        &["-d", &name, "--cd", "~"],
                    ));
                }
            }
        }
    }

    let git_bash = first_existing(&[
        program_files.join("Git").join("bin").join("bash.exe"),
        env_dir("LOCALAPPDATA")
            .unwrap_or_default()
            .join("Programs")
            .join("Git")
            .join("bin")
            .join("bash.exe"),
    ]);
    if let Some(bash) = git_bash {
        shells.push(Shell::new(
            "git-bash",
            "Git Bash",
            bash.to_string_lossy(),
            &["--login", "-i"],
        ));
    }
    shells
}

#[cfg(not(windows))]
fn unix_shells() -> Vec<Shell> {
    let mut shells = Vec::new();
    if let Some(shell) = std::env::var_os("SHELL") {
        let path = PathBuf::from(shell);
        if path.is_file() {
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            shells.push(Shell::new(
                "login",
                &t!("core.shell_default", name = name),
                path.to_string_lossy(),
                &["-l"],
            ));
        }
    }
    for name in ["bash", "zsh", "fish", "sh"] {
        if let Some(path) = on_path(name) {
            if !shells.iter().any(|s| Path::new(&s.program) == path) {
                shells.push(Shell::new(name, name, path.to_string_lossy(), &[]));
            }
        }
    }
    shells
}

/// The shells present on this machine, the usual one first.
#[tauri::command]
pub async fn local_shells() -> Vec<Shell> {
    tauri::async_runtime::spawn_blocking(|| {
        #[cfg(windows)]
        return windows_shells();
        #[cfg(not(windows))]
        return unix_shells();
    })
    .await
    .unwrap_or_default()
}

/// Splits a freely entered command into program and arguments. Spaces
/// separate, double quotes hold together — no more is needed for
/// `"C:\Program Files\…\bash.exe" --login`, and backslashes stay as they are,
/// because on Windows they are paths.
fn split_command(command: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    let mut started = false;
    for ch in command.chars() {
        match ch {
            '"' => {
                quoted = !quoted;
                started = true;
            }
            c if c.is_whitespace() && !quoted => {
                if started {
                    parts.push(std::mem::take(&mut current));
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
        parts.push(current);
    }
    parts
}

/// A shell from a freely entered command.
#[tauri::command]
pub fn local_custom_shell(command: String) -> Result<Shell, String> {
    let mut parts = split_command(&command);
    if parts.is_empty() {
        return Err(t!("core.command_missing").to_string());
    }
    let program = parts.remove(0);
    let resolved = if Path::new(&program).is_absolute() {
        PathBuf::from(&program)
    } else {
        on_path(&program)
            .ok_or_else(|| t!("core.program_not_found", program = program).to_string())?
    };
    Ok(Shell {
        id: format!("custom:{}", command.trim()),
        name: command.trim().to_string(),
        program: resolved.to_string_lossy().into_owned(),
        args: parts,
    })
}

// ---- Session ----------------------------------------------------------------------

fn spawn(
    app: &AppHandle,
    session_id: &str,
    shell: &Shell,
    cols: u16,
    rows: u16,
) -> Result<Session, String> {
    let pair = native_pty_system()
        .openpty(PtySize {
            rows: rows.max(1),
            cols: cols.max(1),
            pixel_width: 0,
            pixel_height: 0,
        })
        .map_err(|e| t!("core.terminal_create_failed", error = e).to_string())?;

    let mut command = CommandBuilder::new(&shell.program);
    command.args(&shell.args);
    command.env("TERM", "xterm-256color");
    command.env("COLORTERM", "truecolor");
    if let Ok(home) = app.path().home_dir() {
        command.cwd(home);
    }
    let child = pair
        .slave
        .spawn_command(command)
        .map_err(|e| t!("core.shell_start_failed", name = shell.name, error = e).to_string())?;
    // Without this the reader never gets an end: the other side would stay open.
    drop(pair.slave);

    let mut reader = pair.master.try_clone_reader().map_err(|e| e.to_string())?;
    let writer = pair.master.take_writer().map_err(|e| e.to_string())?;

    let app = app.clone();
    let id = session_id.to_string();
    std::thread::spawn(move || {
        let mut buffer = [0u8; 8192];
        loop {
            match reader.read(&mut buffer) {
                Ok(0) | Err(_) => break,
                Ok(read) => {
                    if app.emit(&data_event(&id), &buffer[..read]).is_err() {
                        break;
                    }
                }
            }
        }
        let _ = app.emit(&closed_event(&id), ());
        // The shell has ended — nobody needs its entry any more. First out of
        // the list, then release: releasing can wait, and nobody should be
        // stuck on the lock meanwhile.
        let gone = app
            .state::<LocalTerminals>()
            .0
            .lock()
            .ok()
            .and_then(|mut sessions| sessions.remove(&id));
        drop(gone);
    });

    Ok(Session {
        writer,
        master: pair.master,
        child,
    })
}

/// Starts a shell for a tab. A tab that already has one gets a new one.
#[tauri::command]
pub async fn local_open(
    app: AppHandle,
    state: State<'_, LocalTerminals>,
    session_id: String,
    shell: Shell,
    cols: u16,
    rows: u16,
) -> Result<(), String> {
    close(&state, &session_id);
    let session = spawn(&app, &session_id, &shell, cols, rows)?;
    state
        .0
        .lock()
        .map_err(|e| e.to_string())?
        .insert(session_id, session);
    Ok(())
}

#[tauri::command]
pub async fn local_send(
    state: State<'_, LocalTerminals>,
    session_id: String,
    data: String,
) -> Result<(), String> {
    let mut sessions = state.0.lock().map_err(|e| e.to_string())?;
    let session = sessions
        .get_mut(&session_id)
        .ok_or_else(|| t!("core.terminal_not_open").to_string())?;
    session
        .writer
        .write_all(data.as_bytes())
        .and_then(|()| session.writer.flush())
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn local_resize(
    state: State<'_, LocalTerminals>,
    session_id: String,
    cols: u16,
    rows: u16,
) -> Result<(), String> {
    let sessions = state.0.lock().map_err(|e| e.to_string())?;
    if let Some(session) = sessions.get(&session_id) {
        session
            .master
            .resize(PtySize {
                rows: rows.max(1),
                cols: cols.max(1),
                pixel_width: 0,
                pixel_height: 0,
            })
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn close(state: &LocalTerminals, session_id: &str) {
    let session = state.0.lock().ok().and_then(|mut s| s.remove(session_id));
    if let Some(mut session) = session {
        let _ = session.child.kill();
        // On Windows, closing the pseudo terminal waits until conhost is done
        // — that must not hold up any command or worker.
        std::thread::spawn(move || drop(session));
    }
}

/// Ends the shell. A tab that no longer has one is not an error.
#[tauri::command]
pub async fn local_close(
    state: State<'_, LocalTerminals>,
    session_id: String,
) -> Result<(), String> {
    close(&state, &session_id);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_command_is_split() {
        assert_eq!(split_command("bash --login -i"), ["bash", "--login", "-i"]);
        assert_eq!(
            split_command(r#""C:\Program Files\Git\bin\bash.exe"  --login"#),
            [r"C:\Program Files\Git\bin\bash.exe", "--login"]
        );
        assert_eq!(split_command(r#"echo "" x"#), ["echo", "", "x"]);
        assert!(split_command("   ").is_empty());
    }

    #[test]
    fn the_wsl_list_comes_as_utf16() {
        let text = "\u{feff}Ubuntu\r\nDebian\r\ndocker-desktop\r\n\0\r\n";
        let raw: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
        assert_eq!(wsl_distributions(&raw), ["Ubuntu", "Debian"]);
        assert!(wsl_distributions(&[]).is_empty());
    }

    /// What is found on this machine — for looking at, not for checking.
    #[test]
    #[ignore = "depends on what is installed"]
    fn shells_on_this_machine() {
        let shells = tauri::async_runtime::block_on(local_shells());
        for shell in &shells {
            println!("{} = {} {:?}", shell.name, shell.program, shell.args);
        }
        assert!(!shells.is_empty());
    }

    /// A real pseudo terminal: a command in, its output out.
    #[test]
    fn a_pty_returns_the_output() {
        let pair = native_pty_system()
            .openpty(PtySize {
                rows: 24,
                cols: 80,
                pixel_width: 0,
                pixel_height: 0,
            })
            .expect("pty");
        let mut command = if cfg!(windows) {
            let mut command = CommandBuilder::new("cmd.exe");
            command.args(["/c", "echo wireterm-local"]);
            command
        } else {
            let mut command = CommandBuilder::new("sh");
            command.args(["-c", "echo wireterm-local"]);
            command
        };
        command.env("TERM", "xterm-256color");
        let mut child = pair.slave.spawn_command(command).expect("starts");
        drop(pair.slave);
        // In a thread of its own: ConPTY holds the process until someone
        // reads, and a blocking `read` knows no deadline.
        let mut reader = pair.master.try_clone_reader().expect("reader");
        let mut writer = pair.master.take_writer().expect("writer");
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut buffer = [0u8; 4096];
            while let Ok(read) = reader.read(&mut buffer) {
                if read == 0 || tx.send(buffer[..read].to_vec()).is_err() {
                    break;
                }
            }
        });
        let mut seen = String::new();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        while !seen.contains("wireterm-local") {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            match rx.recv_timeout(left) {
                Ok(bytes) => {
                    let text = String::from_utf8_lossy(&bytes);
                    // ConPTY first asks for the cursor position and waits for
                    // the answer. In the app, xterm.js gives it.
                    if text.contains("\x1b[6n") {
                        let _ = writer.write_all(b"\x1b[1;1R");
                    }
                    seen.push_str(&text);
                }
                Err(_) => break,
            }
        }
        let _ = child.kill();
        // As in [`close`]: closing can wait on Windows.
        std::thread::spawn(move || drop((writer, pair.master)));
        assert!(seen.contains("wireterm-local"), "{seen:?}");
    }
}
