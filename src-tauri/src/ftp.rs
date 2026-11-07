//! FTP and FTPS — the second kind of connection a tab can be.
//!
//! Unlike SFTP this is a protocol of its own rather than a subsystem, so an
//! FTP tab has no terminal beside it: the file browser *is* the connection.
//!
//! # One connection cannot do two things at once
//!
//! This is the difference that shapes everything here. SFTP multiplexes — one
//! channel carries sixteen requests at a time, and several transfers share it
//! happily ([`crate::sftp`]). FTP has a control connection that handles one
//! command at a time and a data connection that carries one transfer at a
//! time. Running three transfers at once therefore means three logins, not one
//! connection used harder.
//!
//! So a tab owns a [`Pool`] rather than a connection. Listing a directory
//! borrows a connection, uses it and hands it back; a transfer holds one for
//! as long as it runs. The pool grows to whatever the queue asks of it and
//! keeps what it has opened, because a login costs a round trip or four and a
//! folder of small files would otherwise pay it over and over. It never has to
//! be capped here: the frontend already decides how many transfers run at
//! once, and that number is the pool's real ceiling.
//!
//! A connection handed back is only reused after a `NOOP` says it is still
//! there — an FTP server hangs up on an idle client faster than anything else
//! in this app, and finding that out from a failed listing would be worse than
//! one extra round trip. One that errors is not handed back at all: it is
//! dropped, and the next caller gets a fresh login.
//!
//! # What the server will and will not say
//!
//! FTP predates every convention this app relies on elsewhere. There is no
//! `stat`, so a listing is parsed out of text a server was never obliged to
//! format any particular way; `MLSD` fixed that in 2007 and is used where it
//! is offered. There is no `chmod` either — `SITE CHMOD` is a local extension
//! that most Unix servers happen to implement and IIS does not. Where the
//! answer is simply not available the field stays empty rather than being
//! guessed at: a listing that claims `rwxrwxrwx` because the server said
//! nothing is worse than one that admits it does not know.

use std::collections::HashMap;
use std::io::SeekFrom;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rust_i18n::t;
use serde::Serialize;
use suppaftp::list::{File, ListParser, PosixPexQuery};
use suppaftp::tokio::{AsyncRustlsConnector, AsyncRustlsFtpStream};
use suppaftp::types::FileType as TransferType;
use suppaftp::{FtpError, Status};
use tauri::{AppHandle, Manager, State};
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::sync::Mutex;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

use crate::edit::{self, EditSession, EditWatchers, EditorCommand};
use crate::files::{self, Entry, Listing};
use crate::proxy::Route;
use crate::resume::{Partial, Partials};
use crate::secret::{self, Cache, Prompts};
use crate::storage::{FtpAuth, FtpSecurity, FtpSettings, Probe, RemoteSystem};
use crate::tls::{self, Pinning};
use crate::transfer::{Job, Reporter, Transfers, CANCELLED, CHUNK, WORKING_SUFFIX};
use crate::vault;

/// The one client type used for every connection, secured or not.
///
/// A plain FTP connection never reaches for the TLS half of it — but typing it
/// as the rustls flavour anyway is what lets plain and encrypted connections
/// live in the same pool and be passed to the same functions. The alternative
/// is two of everything below, differing in a type parameter and nothing else.
type Client = AsyncRustlsFtpStream;

/// How long a login is given before it is called unreachable.
///
/// FTP's own timeouts are generous and a wrong port simply hangs. This is what
/// makes "Test connection" answer in a reasonable time rather than looking
/// frozen.
const LOGIN_TIMEOUT: Duration = Duration::from_secs(20);

/// How long to wait for the data connection in active mode.
///
/// Only reached where the user asked for active mode; passive needs nothing of
/// the sort, which is why it is the default.
const ACTIVE_TIMEOUT: Duration = Duration::from_secs(30);

/// How many symlinks in one directory are resolved — see [`enters`], which
/// costs two round trips each. Lower than SFTP's limit, and for the same
/// reason it exists there at all: a directory full of links must not turn one
/// listing into a minute of waiting.
const LINK_LIMIT: usize = 32;

// ---- TLS -------------------------------------------------------------------

/// Wraps the shared configuration in the connector suppaftp wants.
///
/// What is trusted and what "Don't verify certificate" gives up is decided in
/// [`crate::tls`]. Unchecked is unchecked; otherwise the system's roots, and
/// after them whatever certificate the user accepted for this server.
fn tls_connector(
    settings: &FtpSettings,
    pinning: &Pinning,
) -> Result<AsyncRustlsConnector, String> {
    let config = if settings.accept_invalid_cert {
        tls::config(true)?
    } else {
        tls::pinned(pinning)?
    };
    Ok(AsyncRustlsConnector::from(TlsConnector::from(Arc::new(
        config,
    ))))
}

/// Logs in, and where the server shows a certificate neither the system nor
/// this app trusts, asks whether to — the same dialog as for an unknown SSH
/// host key. On a yes the certificate is remembered and the login tried once
/// more; it failed the first time, since the handshake cannot wait for an
/// answer.
///
/// Returns the pins the pool goes on with, and how long the login that
/// worked took: the time the dialog was open is the user's, not the server's.
async fn login_asking(
    app: &AppHandle,
    settings: &FtpSettings,
    proxy: Option<&Route>,
    user: &str,
    password: &str,
) -> Result<(Client, Pinning, Duration), String> {
    let pinning = Pinning::new(crate::certificates::pins(
        app,
        &settings.host,
        settings.port,
    )?);
    let started = Instant::now();
    let message = match login(settings, proxy, user, password, &pinning).await {
        Ok(client) => return Ok((client, pinning, started.elapsed())),
        Err(message) => message,
    };
    let Some(refused) = pinning.take_refused() else {
        return Err(message);
    };

    let pinning =
        crate::certificates::ask_and_trust(app, &settings.host, settings.port, &refused, &pinning)
            .await?;
    let started = Instant::now();
    let client = login(settings, proxy, user, password, &pinning).await?;
    Ok((client, pinning, started.elapsed()))
}

// ---- Passwords ---------------------------------------------------------------
//
// The question, the waiting and the per-tab memory are not FTP's own — S3 asks
// for its secret access key exactly the same way — and live in
// [`crate::secret`]. What is left here is which of the four sources needs
// asking at all.

/// The name and password one login uses.
///
/// [`FtpAuth::Anonymous`] ignores the user field entirely: the convention is a
/// fixed name and an e-mail address as the password, and letting a stored user
/// name override half of that would only produce logins that fail for a reason
/// nobody could see.
async fn credentials(
    app: &AppHandle,
    cache: &Cache,
    prompts: &Prompts,
    session_id: Option<&str>,
    settings: &FtpSettings,
) -> Result<(String, String), String> {
    // The user may be a vault reference. An anonymous login ignores the field,
    // so it is not looked up there.
    let user = match settings.auth {
        FtpAuth::Anonymous => String::new(),
        _ => vault::resolve_user(app, &settings.user).await?,
    };
    let password = match &settings.auth {
        FtpAuth::Anonymous => return Ok(("anonymous".to_string(), "anonymous@".to_string())),
        FtpAuth::Password { password } => password.clone(),
        FtpAuth::Vault {
            provider,
            reference,
        } => vault::resolve(app, *provider, reference)
            .await
            .map_err(|e| {
                t!(
                    "ftp.vault_password_read_failed",
                    name = provider.label(),
                    error = e
                )
                .into_owned()
            })?,
        FtpAuth::Prompt => {
            let cached = match session_id {
                Some(id) => cache.get(id).await,
                // "Test connection" has no session to remember anything
                // for, so it asks every time — which is the honest thing for
                // a test to do anyway.
                None => None,
            };
            match cached {
                Some(password) => password,
                None => {
                    let password = secret::ask(
                        app,
                        prompts,
                        secret::Kind::Password,
                        &settings.host,
                        settings.port,
                        &user,
                    )
                    .await?;
                    if let Some(id) = session_id {
                        cache.put(id, &password).await;
                    }
                    password
                }
            }
        }
    };
    Ok((user, password))
}

// ---- Login ------------------------------------------------------------------

/// Opens one connection and logs it in.
///
/// Everything a connection needs to be usable happens here, transfer mode
/// included: FTP defaults to ASCII, which rewrites line endings as it goes and
/// would quietly corrupt every file that is not text. Nothing above this point
/// ever has to think about it again.
async fn login(
    settings: &FtpSettings,
    proxy: Option<&Route>,
    user: &str,
    password: &str,
    pinning: &Pinning,
) -> Result<Client, String> {
    let address = (settings.host.as_str(), settings.port);

    let opening = async {
        let client = match settings.security {
            // TLS from the first byte. Nothing is exchanged in the clear, but
            // there is also no way to tell a server that speaks plain FTP on
            // this port from one that is not there at all.
            // suppaftp sets up the connection for that itself and takes
            // none that already goes through a proxy.
            FtpSecurity::Implicit if proxy.is_some() => {
                return Err(t!("ftp.implicit_over_proxy").into_owned())
            }
            FtpSecurity::Implicit => Client::connect_secure_implicit(
                address,
                tls_connector(settings, pinning)?,
                &settings.host,
            )
            .await
            .map_err(|e| t!("ftp.unreachable", host = settings.host, error = e).into_owned())?,
            _ => {
                let plain = match proxy {
                    Some(route) => {
                        let stream =
                            crate::proxy::connect(route, &settings.host, settings.port).await?;
                        Client::connect_with_stream(stream).await
                    }
                    None => Client::connect(address).await,
                }
                .map_err(|e| t!("ftp.unreachable", host = settings.host, error = e).into_owned())?;
                match settings.security {
                    // `AUTH TLS` on the connection that is already open. The
                    // greeting arrived in the clear; the login does not.
                    // The wording stays neutral about whose refusal it was:
                    // the server may not offer `AUTH TLS` at all, or its
                    // certificate may be one this machine does not trust, and
                    // both arrive here as the same kind of failure.
                    FtpSecurity::Explicit => plain
                        .into_secure(tls_connector(settings, pinning)?, &settings.host)
                        .await
                        .map_err(|e| {
                            t!("ftp.tls_failed", host = settings.host, error = e).into_owned()
                        })?,
                    _ => plain,
                }
            }
        };
        Ok::<Client, String>(client)
    };

    let mut client = timeout(LOGIN_TIMEOUT, opening)
        .await
        .map_err(|_| t!("ftp.timeout", host = settings.host).into_owned())??;

    if settings.passive {
        match proxy {
            // The data connection goes the same way, and to the connection's
            // host rather than to the address from the `PASV` reply — for the
            // same reason as below, except that the other end of the control
            // connection is the proxy here and not the server.
            Some(route) => {
                let (route, host) = (route.clone(), settings.host.clone());
                client = client.passive_stream_builder(move |address| {
                    let (route, host) = (route.clone(), host.clone());
                    Box::pin(async move {
                        // In a task of its own: suppaftp demands a `Sync`
                        // future, and a `JoinHandle` is one.
                        tokio::spawn(async move {
                            crate::proxy::connect(&route, &host, address.port()).await
                        })
                        .await
                        .map_err(|e| e.to_string())
                        .and_then(|stream| stream)
                        .map_err(|e| FtpError::ConnectionError(std::io::Error::other(e)))
                    })
                });
            }
            // The address a server names in its `PASV` reply is often the
            // private one it sees of itself, which is unreachable from here.
            // Answering instead on the address the control connection
            // already reached is what every other client does, and it is
            // right in every case where the two disagree for that reason.
            None => client.set_passive_nat_workaround(true),
        }
    } else if proxy.is_some() {
        return Err(t!("ftp.active_over_proxy").into_owned());
    } else {
        client = client.active_mode(ACTIVE_TIMEOUT);
    }

    client
        .login(user, password)
        .await
        .map_err(|e| t!("ftp.login_failed", user = user, error = e).into_owned())?;

    client
        .transfer_type(TransferType::Binary)
        .await
        .map_err(|e| t!("ftp.binary_refused", error = e).into_owned())?;

    Ok(client)
}

// ---- Pool -------------------------------------------------------------------

/// The logged-in connections one tab has, and what it takes to open another.
struct Pool {
    settings: FtpSettings,
    /// Resolved on opening, like the password.
    proxy: Option<Route>,
    user: String,
    /// Resolved once when the browser is opened. For [`FtpAuth::Prompt`] this
    /// is what keeps the dialog from coming back for every parallel transfer.
    password: String,
    /// Whether the server offered `MLSD` in its `FEAT` reply — asked once,
    /// because it is a property of the server and not of the connection.
    mlsd: bool,
    /// The certificate accepted when the browser was opened, so the next
    /// connection in the pool does not ask again.
    pinning: Pinning,
    idle: Mutex<Vec<Client>>,
}

impl Pool {
    /// A connection to work on, opened if none is free.
    ///
    /// Idle connections are checked before being handed out: an FTP server
    /// drops a client that has said nothing for a few minutes, and a listing
    /// that fails for that reason would look like an error on the directory.
    async fn acquire(&self) -> Result<Lease<'_>, String> {
        while let Some(mut client) = self.idle.lock().await.pop() {
            if client.noop().await.is_ok() {
                return Ok(Lease {
                    pool: self,
                    client: Some(client),
                });
            }
            // Dropped: the socket closes, and the next round either finds
            // another idle connection or opens one.
        }

        let client = login(
            &self.settings,
            self.proxy.as_ref(),
            &self.user,
            &self.password,
            &self.pinning,
        )
        .await?;
        Ok(Lease {
            pool: self,
            client: Some(client),
        })
    }

    /// Hangs up on everything still open.
    async fn close(&self) {
        for mut client in self.idle.lock().await.drain(..) {
            let _ = client.quit().await;
        }
    }
}

/// A connection borrowed from a [`Pool`].
///
/// Handed back with [`Lease::release`], and only ever on the way out of an
/// operation that worked. One that failed is simply dropped, which closes it:
/// after a failed command an FTP connection may have a reply still queued on
/// it that nobody read, and guessing at that is how a client ends up answering
/// the wrong question. A fresh login costs a round trip and is certain.
struct Lease<'a> {
    pool: &'a Pool,
    client: Option<Client>,
}

impl Lease<'_> {
    /// The connection itself. Always `Some` until [`Lease::release`].
    fn client(&mut self) -> &mut Client {
        self.client
            .as_mut()
            .expect("a lease holds its connection until it is released")
    }

    async fn release(mut self) {
        if let Some(client) = self.client.take() {
            self.pool.idle.lock().await.push(client);
        }
    }
}

// ---- Sessions ----------------------------------------------------------------

/// An open file browser on a tab.
struct Browser {
    pool: Pool,
    /// Where the pane starts, remembered so reconnecting lands in the same
    /// place rather than asking the server again.
    home: String,
}

#[derive(Default)]
pub struct FtpState(Mutex<HashMap<String, Arc<Browser>>>);

impl FtpState {
    async fn browser(&self, session_id: &str) -> Result<Arc<Browser>, String> {
        self.0
            .lock()
            .await
            .get(session_id)
            .cloned()
            .ok_or_else(|| t!("ftp.not_connected").into_owned())
    }

    /// Closes the browser on a tab, if one was ever opened.
    pub(crate) async fn close(&self, session_id: &str) {
        let Some(browser) = self.0.lock().await.remove(session_id) else {
            return;
        };
        browser.pool.close().await;
    }
}

/// Opens the file browser on a tab and reports where it starts.
///
/// Called again after an error, and safe to: a pool that still answers is
/// kept, and one that does not is replaced.
#[tauri::command]
pub async fn ftp_connect(
    app: AppHandle,
    state: State<'_, FtpState>,
    cache: State<'_, Cache>,
    prompts: State<'_, Prompts>,
    session_id: String,
    settings: FtpSettings,
) -> Result<String, String> {
    // Taken out of the map before being asked anything, so a slow server does
    // not hold every other browser up behind the lock.
    let existing = state.0.lock().await.get(&session_id).cloned();
    if let Some(browser) = existing {
        if let Ok(lease) = browser.pool.acquire().await {
            lease.release().await;
            return Ok(browser.home.clone());
        }
        // Past reviving. Closed here rather than left to be overwritten, so
        // whatever is still open in it actually goes away.
        state.close(&session_id).await;
    }

    let (user, password) =
        credentials(&app, &cache, &prompts, Some(&session_id), &settings).await?;

    let proxy = crate::proxy::route(&app, settings.proxy.as_ref())?;
    let (mut client, pinning, _) =
        login_asking(&app, &settings, proxy.as_ref(), &user, &password).await?;

    // The login directory. Servers differ on what a bare relative path means
    // later on, so the pane works in absolute paths from here.
    let home = client
        .pwd()
        .await
        .map_err(|e| t!("ftp.home_not_found", error = e).into_owned())?;

    // A server that will not answer `FEAT` at all is an old one, and an old
    // one does not have `MLSD` either — so the failure and the absence mean
    // the same thing here.
    let mlsd = client
        .feat()
        .await
        .map(|features| {
            features
                .keys()
                .any(|name| name.eq_ignore_ascii_case("MLSD"))
        })
        .unwrap_or(false);

    state.0.lock().await.insert(
        session_id,
        Arc::new(Browser {
            pool: Pool {
                settings,
                proxy,
                user,
                password,
                mlsd,
                pinning,
                idle: Mutex::new(vec![client]),
            },
            home: home.clone(),
        }),
    );
    Ok(home)
}

/// Closes the file browser and everything it had open.
#[tauri::command]
pub async fn ftp_disconnect(
    state: State<'_, FtpState>,
    edits: State<'_, EditWatchers>,
    cache: State<'_, Cache>,
    session_id: String,
) -> Result<(), String> {
    edits.stop_for_session(&session_id).await;
    state.close(&session_id).await;
    // A typed-in password lives exactly as long as the tab it was typed for.
    cache.forget(&session_id).await;
    Ok(())
}

/// Logs in with the given settings, asks what the system is, and hangs up.
///
/// Opens no browser and touches no stored session, so it is safe to run
/// against settings that are still being edited while other tabs are open.
#[tauri::command]
pub async fn ftp_probe(
    app: AppHandle,
    cache: State<'_, Cache>,
    prompts: State<'_, Prompts>,
    settings: FtpSettings,
) -> Result<Probe, String> {
    // Resolved before the clock starts: a password typed into a dialog is not
    // something the server should be timed on.
    let (user, password) = credentials(&app, &cache, &prompts, None, &settings).await?;

    let proxy = crate::proxy::route(&app, settings.proxy.as_ref())?;
    let (mut client, _, took) =
        login_asking(&app, &settings, proxy.as_ref(), &user, &password).await?;
    let millis = took.as_millis() as u64;

    let system = read_system(&mut client).await;
    let _ = client.quit().await;
    Ok(Probe { millis, system })
}

/// What `SYST` says the server is.
///
/// Far less than `/etc/os-release` gives over SSH — "UNIX Type: L8" names a
/// family and not a distribution — but it is everything FTP has to offer, and
/// it still tells a Unix server from a Windows one. Best effort throughout: a
/// server that refuses the command is perfectly usable.
async fn read_system(client: &mut Client) -> Option<RemoteSystem> {
    let response = client.custom_command("SYST", &[Status::Name]).await.ok()?;
    let line = response.as_string().ok()?;
    let line = line.trim();
    if line.is_empty() {
        return None;
    }

    let family = line.split_whitespace().next().unwrap_or(line);
    Some(RemoteSystem {
        // Lowercased and cut at the first underscore, so `Windows_NT` lands on
        // the same id as any other Windows and can be given one icon.
        id: family
            .to_lowercase()
            .split('_')
            .next()
            .unwrap_or_default()
            .to_string(),
        name: family.to_string(),
        // FTP has no version to give. Left empty rather than filled with the
        // rest of the line, which is `Type: L8` and means nothing to a reader.
        version: String::new(),
        pretty: line.to_string(),
    })
}

// ---- Directories -------------------------------------------------------------

/// Joins a remote directory and a name. Always POSIX, whatever this machine
/// uses.
fn join(dir: &str, name: &str) -> String {
    if dir.ends_with('/') {
        format!("{dir}{name}")
    } else {
        format!("{dir}/{name}")
    }
}

/// One line of a listing, and whether its permissions are real.
///
/// The second half is the reason this is not one call to the parser. `MLSD`
/// only carries permissions when the server chose to send `UNIX.mode`, and
/// suppaftp fills in `rwxrwxrwx` where it did not — a default that reads
/// exactly like an answer. A DOS-format `LIST` has no permissions at all and
/// the same thing happens. So the raw line is asked whether it really said
/// anything, and where it did not the fields are left empty and the pane shows
/// a dash, the way it does for the local side.
fn parse_line(line: &str, mlsd: bool) -> Option<(File, bool)> {
    if mlsd {
        let file = ListParser::parse_mlsd(line).ok()?;
        let stated = line.to_ascii_lowercase().contains("unix.mode=");
        return Some((file, stated));
    }
    if let Ok(file) = ListParser::parse_posix(line) {
        return Some((file, true));
    }
    ListParser::parse_dos(line).ok().map(|file| (file, false))
}

/// The nine permission bits as `chmod` would take them.
fn mode_of(file: &File) -> u32 {
    use PosixPexQuery::{Group, Others, Owner};
    let bit = |set: bool, value: u32| if set { value } else { 0 };
    bit(file.can_read(Owner), 0o400)
        | bit(file.can_write(Owner), 0o200)
        | bit(file.can_execute(Owner), 0o100)
        | bit(file.can_read(Group), 0o040)
        | bit(file.can_write(Group), 0o020)
        | bit(file.can_execute(Group), 0o010)
        | bit(file.can_read(Others), 0o004)
        | bit(file.can_write(Others), 0o002)
        | bit(file.can_execute(Others), 0o001)
}

/// `rwxr-xr-x`, the way `ls` prints it and the way the SFTP side reports it.
fn permission_string(mode: u32) -> String {
    let mut text = String::with_capacity(9);
    for shift in [6, 3, 0] {
        let bits = (mode >> shift) & 0o7;
        text.push(if bits & 0o4 != 0 { 'r' } else { '-' });
        text.push(if bits & 0o2 != 0 { 'w' } else { '-' });
        text.push(if bits & 0o1 != 0 { 'x' } else { '-' });
    }
    text
}

/// Unix seconds, or `None` where the listing carried no time.
///
/// The epoch itself is what suppaftp leaves behind when a line said nothing,
/// and a file dated 1970 is so much more likely to be that than a real
/// timestamp that it is treated as "did not say".
fn modified_of(file: &File) -> Option<i64> {
    let seconds = file.modified().duration_since(UNIX_EPOCH).ok()?.as_secs() as i64;
    (seconds > 0).then_some(seconds)
}

/// Whether a path can be entered — the only way FTP has of asking.
///
/// There is no `stat`, so the question "is this link a directory" can only be
/// answered by trying to walk into it. Two round trips, which is why
/// [`LINK_LIMIT`] exists; the walk back is what keeps the working directory
/// where the caller left it.
async fn enters(client: &mut Client, path: &str, back_to: &str) -> bool {
    if client.cwd(path).await.is_err() {
        return false;
    }
    let _ = client.cwd(back_to).await;
    true
}

/// Reads one directory.
///
/// `CWD` first and then a bare `LIST`, rather than `LIST <path>`: a path
/// handed to `LIST` is taken by many servers as a set of flags if it starts
/// with a dash, and by others as something to split on spaces. Walking there
/// first has neither problem and works everywhere.
///
/// `resolve_links` is off for the tree walks. They want the entry itself and
/// not what it points at — deleting the contents of whatever a link happens to
/// aim at would be the one outcome nobody meant — and it saves the round trips
/// as well.
async fn read_entries(
    client: &mut Client,
    mlsd: bool,
    path: &str,
    resolve_links: bool,
) -> Result<(String, Vec<Entry>), String> {
    client
        .cwd(path)
        .await
        .map_err(|e| t!("ftp.open_failed", path = path, error = e).into_owned())?;
    let dir = client
        .pwd()
        .await
        .map_err(|e| t!("ftp.read_failed", path = path, error = e).into_owned())?;

    let lines = if mlsd {
        client.mlsd(None).await
    } else {
        client.list(None).await
    }
    .map_err(|e| t!("ftp.read_failed", path = dir, error = e).into_owned())?;

    let mut entries = Vec::new();
    let mut probed = 0usize;

    for line in lines {
        // A line the parser cannot make sense of is skipped rather than
        // failing the listing: servers put banners and totals in there, and
        // one odd line must not cost the user the whole directory.
        let Some((file, permissions_stated)) = parse_line(&line, mlsd) else {
            continue;
        };
        let name = file.name().to_string();
        if name.is_empty() || name == "." || name == ".." {
            continue;
        }

        let full = join(&dir, &name);
        let is_symlink = file.is_symlink();
        let mut is_dir = file.is_directory();
        if resolve_links && is_symlink && !is_dir && probed < LINK_LIMIT {
            probed += 1;
            is_dir = enters(client, &full, &dir).await;
        }

        let mode = permissions_stated.then(|| mode_of(&file));
        entries.push(Entry {
            name,
            path: full,
            is_dir,
            is_symlink,
            size: file.size() as u64,
            modified: modified_of(&file),
            permissions: mode.map(permission_string),
            mode,
        });
    }

    files::sort(&mut entries);
    Ok((dir, entries))
}

#[tauri::command]
pub async fn ftp_list(
    state: State<'_, FtpState>,
    session_id: String,
    path: String,
) -> Result<Listing, String> {
    let browser = state.browser(&session_id).await?;
    let mut lease = browser.pool.acquire().await?;
    let (dir, entries) = read_entries(lease.client(), browser.pool.mlsd, &path, true).await?;
    lease.release().await;

    Ok(Listing {
        parent: files::remote_parent(&dir),
        path: dir,
        entries,
        truncated: false,
    })
}

/// Whether a remote path exists — file, directory, either.
///
/// Two questions because FTP has no one command that answers for both: `SIZE`
/// is refused for a directory on most servers, and walking into a file fails
/// on all of them. Between them they cover everything.
async fn exists(client: &mut Client, path: &str) -> bool {
    if client.size(path).await.is_ok() {
        return true;
    }
    client.cwd(path).await.is_ok()
}

#[tauri::command]
pub async fn ftp_exists(
    state: State<'_, FtpState>,
    session_id: String,
    path: String,
) -> Result<bool, String> {
    let browser = state.browser(&session_id).await?;
    let mut lease = browser.pool.acquire().await?;
    let found = exists(lease.client(), &path).await;
    lease.release().await;
    Ok(found)
}

#[tauri::command]
pub async fn ftp_mkdir(
    state: State<'_, FtpState>,
    session_id: String,
    path: String,
) -> Result<(), String> {
    let browser = state.browser(&session_id).await?;
    let mut lease = browser.pool.acquire().await?;

    // An upload into a tree creates the same directories over and over; one
    // that is already there is what was wanted, not a failure.
    if exists(lease.client(), &path).await {
        lease.release().await;
        return Ok(());
    }

    lease
        .client()
        .mkdir(&path)
        .await
        .map_err(|e| t!("ftp.create_failed", path = path, error = e).into_owned())?;
    lease.release().await;
    Ok(())
}

/// Creates an empty file, and fails if something is already there.
///
/// "New file" beside "New folder", and the refusal is the point: this is
/// reached from a dialog that just asked for a name, where silently emptying
/// an existing file would be the one outcome nobody meant.
///
/// Unlike SFTP there is no exclusive-create flag to settle the race with
/// anything else writing to the same directory — `STOR` simply overwrites. The
/// check is therefore all there is, and the window between it and the write is
/// the honest limit of what FTP can promise.
#[tauri::command]
pub async fn ftp_create_file(
    state: State<'_, FtpState>,
    session_id: String,
    path: String,
) -> Result<(), String> {
    let browser = state.browser(&session_id).await?;
    let mut lease = browser.pool.acquire().await?;

    if exists(lease.client(), &path).await {
        lease.release().await;
        return Err(t!("ftp.already_exists", path = path).into_owned());
    }

    let stream = lease
        .client()
        .put_with_stream(&path)
        .await
        .map_err(|e| t!("ftp.create_failed", path = path, error = e).into_owned())?;
    stream
        .finish()
        .await
        .map_err(|e| t!("ftp.create_failed", path = path, error = e).into_owned())?;

    lease.release().await;
    Ok(())
}

#[tauri::command]
pub async fn ftp_rename(
    state: State<'_, FtpState>,
    session_id: String,
    from: String,
    to: String,
) -> Result<(), String> {
    let browser = state.browser(&session_id).await?;
    let mut lease = browser.pool.acquire().await?;
    lease
        .client()
        .rename(from.as_str(), to.as_str())
        .await
        .map_err(|e| t!("ftp.rename_failed", path = from, error = e).into_owned())?;
    lease.release().await;
    Ok(())
}

// ---- Deleting ------------------------------------------------------------------

/// Deletes a directory and everything under it.
///
/// Walked iteratively rather than recursively, for the same reason the SFTP
/// side is: an async function that calls itself has to box its own future, and
/// a stack says the same thing without that.
async fn remove_tree(client: &mut Client, mlsd: bool, root: &str) -> Result<(), String> {
    let mut pending = vec![root.to_string()];
    // Depth-first order, in which a directory always comes before everything
    // inside it — so deleting in reverse empties each one before removing it.
    let mut dirs = Vec::new();

    while let Some(dir) = pending.pop() {
        let (resolved, entries) = read_entries(client, mlsd, &dir, false).await?;
        for entry in entries {
            // Links are unlinked, never followed: whatever one points at may
            // be nowhere near this tree.
            if entry.is_dir && !entry.is_symlink {
                pending.push(entry.path);
            } else {
                client.rm(entry.path.as_str()).await.map_err(|e| {
                    t!("ftp.delete_failed", path = entry.path, error = e).into_owned()
                })?;
            }
        }
        dirs.push(resolved);
    }

    // Out of the tree before pulling it down. Reading a directory walks into
    // it, so the connection is currently standing inside what is about to be
    // deleted — and a server asked to remove the directory its client is in
    // is within its rights to refuse.
    let _ = client
        .cwd(files::remote_parent(root).unwrap_or_else(|| "/".to_string()))
        .await;

    for dir in dirs.into_iter().rev() {
        client
            .rmdir(dir.as_str())
            .await
            .map_err(|e| t!("ftp.delete_failed", path = dir, error = e).into_owned())?;
    }
    Ok(())
}

#[tauri::command]
pub async fn ftp_remove(
    state: State<'_, FtpState>,
    session_id: String,
    path: String,
    is_dir: bool,
) -> Result<(), String> {
    let browser = state.browser(&session_id).await?;
    let mut lease = browser.pool.acquire().await?;

    if is_dir {
        remove_tree(lease.client(), browser.pool.mlsd, &path).await?;
    } else {
        lease
            .client()
            .rm(path.as_str())
            .await
            .map_err(|e| t!("ftp.delete_failed", path = path, error = e).into_owned())?;
    }

    lease.release().await;
    Ok(())
}

// ---- Permissions -----------------------------------------------------------------

/// What one recursive run did. The same shape the SFTP side reports, because
/// the dialog above it is the same one.
#[derive(Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ChmodResult {
    pub changed: u32,
    pub failed: u32,
    /// The first refusal, in the server's own words.
    pub error: Option<String>,
    /// Stopped by the user before the tree was done.
    pub cancelled: bool,
}

/// What a file gets when a directory's mode is applied to a whole tree.
///
/// Not the mode itself: `755` on a source tree would make every `.php` in it
/// executable, which is the classic way `chmod -R` ruins a deployment. The
/// execute bits are therefore dropped for files that do not already carry one
/// — `chmod`'s own `a+X` rule. A file that *is* a program keeps being one.
fn tree_file_mode(mode: u32, current: Option<u32>) -> u32 {
    if current.is_some_and(|bits| bits & 0o111 != 0) {
        mode
    } else {
        mode & !0o111
    }
}

/// `SITE CHMOD`, which is not part of FTP.
///
/// It is a local extension — widely implemented on Unix servers, absent on
/// IIS and on anything not backed by a POSIX filesystem. There is nothing to
/// fall back to, so a server that says no says no, and its own words are what
/// reaches the dialog.
async fn set_mode(client: &mut Client, path: &str, mode: u32) -> Result<(), String> {
    client
        .site(format!("CHMOD {:03o} {}", mode & 0o777, path))
        .await
        .map(|_| ())
        .map_err(|e| t!("ftp.chmod_failed", path = path, error = e).into_owned())
}

/// Applies `mode` to everything under `root`, `root` itself included.
///
/// Counted rather than failed on the first refusal: one directory inside a
/// tree that the login may not touch must not stop the other nine hundred, and
/// afterwards the dialog can say plainly how many were left as they were.
async fn chmod_tree(
    client: &mut Client,
    mlsd: bool,
    root: &str,
    mode: u32,
    cancel: &AtomicBool,
) -> ChmodResult {
    let mut result = ChmodResult::default();
    let mut pending = vec![root.to_string()];

    fn note(outcome: Result<(), String>, result: &mut ChmodResult) {
        match outcome {
            Ok(()) => result.changed += 1,
            Err(message) => {
                result.failed += 1;
                result.error.get_or_insert(message);
            }
        }
    }

    note(set_mode(client, root, mode).await, &mut result);

    'walk: while let Some(dir) = pending.pop() {
        if cancel.load(Ordering::Relaxed) {
            result.cancelled = true;
            break;
        }
        let entries = match read_entries(client, mlsd, &dir, false).await {
            Ok((_, entries)) => entries,
            Err(message) => {
                // Unreadable, so there is nothing below it to reach. Counted
                // once rather than silently: the total the dialog reports has
                // to add up.
                result.failed += 1;
                result.error.get_or_insert(message);
                continue;
            }
        };

        for entry in entries {
            if cancel.load(Ordering::Relaxed) {
                result.cancelled = true;
                break 'walk;
            }
            // Symlinks are left alone — changing the permissions of whatever
            // one happens to point at is never what "Also apply to contents"
            // meant.
            if entry.is_symlink {
                continue;
            }
            if entry.is_dir {
                pending.push(entry.path.clone());
                note(set_mode(client, &entry.path, mode).await, &mut result);
            } else {
                let file_mode = tree_file_mode(mode, entry.mode);
                note(set_mode(client, &entry.path, file_mode).await, &mut result);
            }
        }
    }

    result
}

#[tauri::command]
pub async fn ftp_chmod(
    state: State<'_, FtpState>,
    transfers: State<'_, Transfers>,
    session_id: String,
    path: String,
    mode: u32,
    recursive: bool,
    operation_id: Option<String>,
) -> Result<ChmodResult, String> {
    let browser = state.browser(&session_id).await?;
    let mut lease = browser.pool.acquire().await?;

    let result = if recursive {
        let cancel = transfers.begin(&operation_id).await;
        let result = chmod_tree(lease.client(), browser.pool.mlsd, &path, mode, &cancel).await;
        transfers.end(&operation_id).await;
        result
    } else {
        set_mode(lease.client(), &path, mode).await?;
        ChmodResult {
            changed: 1,
            ..Default::default()
        }
    };

    lease.release().await;
    Ok(result)
}

// ---- Transfers ---------------------------------------------------------------------
//
// The shape of a transfer — the `.wtpart` file, the progress events, what
// "cancel" means — is decided in [`crate::transfer`] and is the same over
// either protocol. What differs is how the bytes are asked for: FTP opens a
// data connection per file and is told where to resume by a separate `REST`
// command beforehand, rather than seeking inside an open handle.

/// Fetches one file, reporting as it goes. Returns the number of bytes moved.
///
/// Writes to `{local}.wtpart` and only renames it onto `local` once every byte
/// has arrived, so a reader of `local` only ever sees nothing or the whole
/// file. A fragment left by a stopped attempt is kept on purpose: that is what
/// lets a later attempt carry on from it.
///
/// Whether it may be carried on from is [`crate::resume`]'s question, not a
/// matter of its length — a source replaced since by a different file of the
/// same size would otherwise be resumed into, and the result would be neither
/// file. `MDTM` is what the check has to go on; a server that does not offer
/// it leaves the modification time at zero, and the size carries the check
/// alone.
async fn download(
    app: &AppHandle,
    client: &mut Client,
    partials: &Partials,
    cancel: &AtomicBool,
    job: &Job<'_>,
) -> Result<u64, String> {
    let Job { local, remote, .. } = *job;

    // `SIZE` is not guaranteed — an old server may not have it, and one in
    // ASCII mode is allowed to refuse. Its absence costs the progress bar its
    // total and the transfer its ability to resume, and nothing else: the
    // download itself reads to the end of the stream either way.
    let total = client.size(remote).await.ok().map(|size| size as u64);
    let modified = client
        .mdtm(remote)
        .await
        .map(|stamp| stamp.and_utc().timestamp())
        .unwrap_or(0);

    let source = total.map(|size| Partial {
        source: remote.to_string(),
        size,
        modified,
    });
    let resumable = match &source {
        Some(source) => partials.resumable(app, local, source).await,
        None => false,
    };

    let result = fetch(app, client, cancel, job, total, resumable).await;

    match &result {
        // Renamed into place, so there is no fragment left to describe.
        Ok(_) => partials.forget(app, local).await,
        // Only where something is actually lying there, and only where the
        // source could be described in the first place: a fragment whose size
        // the server would not state is one a later attempt cannot check, so
        // there is nothing worth noting about it.
        Err(_) => {
            let working = format!("{local}{WORKING_SUFFIX}");
            if let Some(source) = source {
                if fs::metadata(&working).await.map(|m| m.len()).unwrap_or(0) > 0 {
                    partials.remember(app, local, source).await;
                }
            }
        }
    }
    result
}

/// The bytes of a download, once [`download`] has settled whether the fragment
/// already on disk may be continued from.
///
/// `total` is `None` where the server would not say how large the file is. The
/// bytes still arrive — `RETR` ends when the data connection closes — but the
/// queue shows no percentage and nothing can be resumed, because there is
/// nothing to check a fragment against.
async fn fetch(
    app: &AppHandle,
    client: &mut Client,
    cancel: &AtomicBool,
    job: &Job<'_>,
    total: Option<u64>,
    resumable: bool,
) -> Result<u64, String> {
    let Job {
        session_id,
        transfer_id,
        local,
        remote,
    } = *job;

    let working = format!("{local}{WORKING_SUFFIX}");
    // A fragment longer than the source it is meant to be a prefix of cannot
    // be one, whatever the notes say.
    let existing = fs::metadata(&working).await.map(|m| m.len()).unwrap_or(0);
    let start = match total {
        Some(size) if resumable && existing <= size => existing,
        _ => 0,
    };

    // 0 is what the queue reads as "size unknown", which is the truth here.
    let mut reporter = Reporter::new(app, session_id, transfer_id, total.unwrap_or(0));
    reporter.report(start, true);

    // The queue creates the directories it needs before enqueuing, but a
    // single file dropped into a fresh target is the common case and this
    // costs nothing.
    if let Some(parent) = Path::new(&working).parent() {
        let _ = fs::create_dir_all(parent).await;
    }

    // Nothing left to fetch: the fragment already holds the whole file, and
    // all that is missing is the rename. Only ever true where the size is
    // known, since that is the only way to tell.
    let complete = total.is_some_and(|size| start >= size);
    let mut moved = start;

    if !complete {
        if start > 0 {
            // `REST` on its own transfers nothing; it sets where the `RETR`
            // that follows begins. A server that refuses it fails the transfer
            // rather than silently sending the file from the top, which would
            // land its first bytes after the fragment's last.
            client
                .resume_transfer(start as usize)
                .await
                .map_err(|e| t!("ftp.resume_failed", path = remote, error = e).into_owned())?;
        }

        let mut source = client
            .retr_as_stream(remote)
            .await
            .map_err(|e| t!("ftp.open_failed", path = remote, error = e).into_owned())?;

        let mut target = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .append(start > 0)
            .truncate(start == 0)
            .open(&working)
            .await
            .map_err(|e| t!("ftp.write_failed", path = local, error = e).into_owned())?;

        let mut buffer = vec![0u8; CHUNK];

        loop {
            if cancel.load(Ordering::Relaxed) {
                // Returned without finishing the stream: dropping it closes
                // the data connection, and the connection this ran on is
                // dropped with the lease rather than handed back — see
                // [`Lease`].
                return Err(CANCELLED.to_string());
            }
            let read = source
                .read(&mut buffer)
                .await
                .map_err(|e| t!("ftp.read_failed", path = remote, error = e).into_owned())?;
            if read == 0 {
                break;
            }
            target
                .write_all(&buffer[..read])
                .await
                .map_err(|e| t!("ftp.write_failed", path = local, error = e).into_owned())?;
            moved += read as u64;
            reporter.report(moved, false);
        }

        target
            .flush()
            .await
            .map_err(|e| t!("ftp.write_failed", path = local, error = e).into_owned())?;

        // Not a formality: this closes the data connection and reads the
        // server's verdict on the transfer, which is the only place a
        // truncated download is reported at all.
        source
            .finish()
            .await
            .map_err(|e| t!("ftp.incomplete", path = remote, error = e).into_owned())?;
    } else if start == 0 {
        // Complete from a standing start, so the source is empty. `create`
        // truncates, which is what a fragment left by some earlier, longer
        // file needs: it is not a prefix of an empty file either, and the
        // rename below would otherwise put its tail in place.
        fs::File::create(&working)
            .await
            .map_err(|e| t!("ftp.write_failed", path = local, error = e).into_owned())?;
    }

    fs::rename(&working, local)
        .await
        .map_err(|e| t!("ftp.finish_failed", path = local, error = e).into_owned())?;
    reporter.report(moved, true);
    Ok(moved)
}

/// Sends one file, reporting as it goes.
///
/// The mirror of [`download`]: written to `{remote}.wtpart` and only put in
/// place under its real name once it is whole.
async fn upload(
    app: &AppHandle,
    client: &mut Client,
    partials: &Partials,
    cancel: &AtomicBool,
    job: &Job<'_>,
) -> Result<u64, String> {
    let Job { local, remote, .. } = *job;

    let meta = fs::metadata(local)
        .await
        .map_err(|e| t!("ftp.read_failed", path = local, error = e).into_owned())?;
    let source = Partial {
        source: local.to_string(),
        size: meta.len(),
        modified: meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0),
    };
    let resumable = partials.resumable(app, remote, &source).await;

    let result = send(app, client, cancel, job, meta.len(), resumable).await;

    match &result {
        Ok(_) => partials.forget(app, remote).await,
        Err(_) => {
            // Asked of the server rather than assumed: what actually landed is
            // the only thing a later attempt can build on, and it is rarely
            // exactly what was written before the connection went.
            let working = format!("{remote}{WORKING_SUFFIX}");
            if client.size(working.as_str()).await.unwrap_or(0) > 0 {
                partials.remember(app, remote, source).await;
            }
        }
    }
    result
}

/// The bytes of an upload, the mirror of [`fetch`].
async fn send(
    app: &AppHandle,
    client: &mut Client,
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

    let working = format!("{remote}{WORKING_SUFFIX}");
    let existing = client.size(working.as_str()).await.unwrap_or(0) as u64;
    let start = if resumable && existing <= total {
        existing
    } else {
        0
    };

    let mut reporter = Reporter::new(app, session_id, transfer_id, total);
    reporter.report(start, true);

    if start < total {
        let mut source = fs::File::open(local)
            .await
            .map_err(|e| t!("ftp.read_failed", path = local, error = e).into_owned())?;
        if start > 0 {
            source
                .seek(SeekFrom::Start(start))
                .await
                .map_err(|e| t!("ftp.resume_failed", path = local, error = e).into_owned())?;
        }

        // `APPE` rather than `REST` plus `STOR`: both are meant to resume, but
        // servers disagree about whether `REST` applies to an upload at all,
        // and appending is exactly what is wanted here — the fragment ends
        // where the next byte belongs. `STOR` where there is nothing to
        // continue, because it replaces whatever is lying there, and a
        // fragment from some earlier, longer file must not keep its tail.
        let mut target = if start > 0 {
            client.append_with_stream(working.as_str()).await
        } else {
            client.put_with_stream(working.as_str()).await
        }
        .map_err(|e| t!("ftp.write_failed", path = remote, error = e).into_owned())?;

        let mut buffer = vec![0u8; CHUNK];
        let mut moved = start;

        loop {
            if cancel.load(Ordering::Relaxed) {
                return Err(CANCELLED.to_string());
            }
            let read = source
                .read(&mut buffer)
                .await
                .map_err(|e| t!("ftp.read_failed", path = local, error = e).into_owned())?;
            if read == 0 {
                break;
            }
            target
                .write_all(&buffer[..read])
                .await
                .map_err(|e| t!("ftp.write_failed", path = remote, error = e).into_owned())?;
            moved += read as u64;
            reporter.report(moved, false);
        }

        // Not just a flush: finishing is what shuts the data connection down
        // and waits for the server to say it has the file. Dropping the
        // stream instead would report success before the last bytes had
        // landed.
        target
            .finish()
            .await
            .map_err(|e| t!("ftp.finish_failed", path = remote, error = e).into_owned())?;
    } else if start == 0 {
        let empty = client
            .put_with_stream(working.as_str())
            .await
            .map_err(|e| t!("ftp.write_failed", path = remote, error = e).into_owned())?;
        empty
            .finish()
            .await
            .map_err(|e| t!("ftp.write_failed", path = remote, error = e).into_owned())?;
    }

    // Removed first because a rename onto an existing name is refused by some
    // servers and silently accepted by others — and "silently accepted" is
    // not something to rely on. Safe here specifically, because upstream only
    // calls this once the overwrite question has been agreed to.
    let _ = client.rm(remote).await;
    client
        .rename(working.as_str(), remote)
        .await
        .map_err(|e| t!("ftp.finish_failed", path = remote, error = e).into_owned())?;

    reporter.report(total, true);
    Ok(total)
}

/// Fetches one file. Holds a connection of its own for as long as it runs —
/// that is what "simultaneous" costs over FTP.
#[allow(clippy::too_many_arguments)]
#[tauri::command]
pub async fn ftp_download(
    app: AppHandle,
    state: State<'_, FtpState>,
    transfers: State<'_, Transfers>,
    partials: State<'_, Partials>,
    session_id: String,
    transfer_id: String,
    remote: String,
    local: String,
) -> Result<u64, String> {
    let browser = state.browser(&session_id).await?;
    let mut lease = browser.pool.acquire().await?;
    let cancel = transfers.start(&transfer_id).await;

    let job = Job {
        session_id: &session_id,
        transfer_id: &transfer_id,
        local: &local,
        remote: &remote,
    };
    let result = download(&app, lease.client(), &partials, &cancel, &job).await;

    transfers.finish(&transfer_id).await;
    if result.is_ok() {
        lease.release().await;
    }
    result
}

/// Sends one file. The mirror of [`ftp_download`], down to the lease.
#[allow(clippy::too_many_arguments)]
#[tauri::command]
pub async fn ftp_upload(
    app: AppHandle,
    state: State<'_, FtpState>,
    transfers: State<'_, Transfers>,
    partials: State<'_, Partials>,
    session_id: String,
    transfer_id: String,
    local: String,
    remote: String,
) -> Result<u64, String> {
    let browser = state.browser(&session_id).await?;
    let mut lease = browser.pool.acquire().await?;
    let cancel = transfers.start(&transfer_id).await;

    let job = Job {
        session_id: &session_id,
        transfer_id: &transfer_id,
        local: &local,
        remote: &remote,
    };
    let result = upload(&app, lease.client(), &partials, &cancel, &job).await;

    transfers.finish(&transfer_id).await;
    if result.is_ok() {
        lease.release().await;
    }
    result
}

/// Throws away what a stopped transfer left behind.
///
/// Reached from "Discard" in the queue, which is the one gesture that says
/// the transfer is not wanted after all — "Cancel" only stops it, and the
/// fragment stays so it can be picked up again.
#[tauri::command]
pub async fn ftp_discard(
    app: AppHandle,
    state: State<'_, FtpState>,
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
    } else if let Ok(browser) = state.browser(&session_id).await {
        if let Ok(mut lease) = browser.pool.acquire().await {
            // Failing is not worth reporting: a fragment that is already gone
            // is exactly the state being asked for.
            if lease.client().rm(working.as_str()).await.is_ok() {
                lease.release().await;
            }
        }
    }

    partials.forget(&app, target).await;
    Ok(())
}

// ---- Editing on the server ----------------------------------------------------
//
// How an edit works lives in [`crate::edit`]; what is here is the FTP half of
// it. The one difference from SFTP is the connection: each sync takes one out
// of the pool for as long as it runs, rather than sharing a channel that is
// already open.

/// Downloads a copy to edit and starts watching it.
#[tauri::command]
pub async fn ftp_edit_open(
    app: AppHandle,
    state: State<'_, FtpState>,
    watchers: State<'_, EditWatchers>,
    partials: State<'_, Partials>,
    session_id: String,
    remote: String,
    editor: Option<EditorCommand>,
) -> Result<EditSession, String> {
    let browser = state.browser(&session_id).await?;

    let id = edit::next_id();
    let name = edit::file_name(&remote);
    let local = edit::working_copy(&app, &id, &name)
        .await?
        .to_string_lossy()
        .into_owned();

    let mut lease = browser.pool.acquire().await?;
    let cancel = AtomicBool::new(false);
    let job = Job {
        session_id: &session_id,
        transfer_id: &id,
        local: &local,
        remote: &remote,
    };
    download(&app, lease.client(), &partials, &cancel, &job).await?;
    lease.release().await;

    // Registered before the editor starts, so the flag exists for the process
    // watcher to set the moment it does.
    let stop = watchers.register(&id, &session_id).await;
    let opened = edit::open_editor(&app, editor, &local, &id, &stop)?;

    tauri::async_runtime::spawn(edit::watch(app.clone(), stop, id.clone(), local.clone(), {
        // The browser is held by the closure rather than looked up again: an
        // edit outlives any one listing, and what it needs is the pool, which
        // this keeps alive for as long as the watch runs.
        let app = app.clone();
        let browser = Arc::clone(&browser);
        let session_id = session_id.clone();
        let (id, local, remote) = (id.clone(), local.clone(), remote.clone());
        move || {
            // Cloned again per call: the closure is a `Fn` and may be called
            // many times, so it must not give its contents away.
            let (app, browser) = (app.clone(), Arc::clone(&browser));
            let session_id = session_id.clone();
            let (id, local, remote) = (id.clone(), local.clone(), remote.clone());
            async move {
                let mut lease = browser.pool.acquire().await?;
                let cancel = AtomicBool::new(false);
                let partials = app.state::<Partials>();
                let job = Job {
                    session_id: &session_id,
                    transfer_id: &id,
                    local: &local,
                    remote: &remote,
                };
                let result = upload(&app, lease.client(), &partials, &cancel, &job).await;
                if result.is_ok() {
                    lease.release().await;
                }
                result.map(|_| ())
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

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Reading listings ----------------------------------------------------
    //
    // The parsing is where a silent wrong answer is most likely, because every
    // server words its listing differently and nothing complains about a line
    // read the wrong way — it just shows the wrong size, or a file where a
    // directory was. These run without a server.

    fn parsed(line: &str, mlsd: bool) -> (File, bool) {
        parse_line(line, mlsd).expect("line should parse")
    }

    #[test]
    fn posix_listing_states_its_permissions() {
        let (file, stated) = parsed("-rw-r--r-- 1 user group 1234 Nov 5 13:46 note.txt", false);
        assert_eq!(file.name(), "note.txt");
        assert_eq!(file.size(), 1234);
        assert!(!file.is_directory());
        assert!(stated);
        assert_eq!(mode_of(&file), 0o644);
        assert_eq!(permission_string(0o644), "rw-r--r--");
    }

    #[test]
    fn posix_listing_reports_directories_and_links() {
        let (dir, _) = parsed("drwxr-xr-x 2 user group 4096 Nov 5 13:46 folder", false);
        assert!(dir.is_directory());
        assert_eq!(mode_of(&dir), 0o755);

        let (link, _) = parsed(
            "lrwxrwxrwx 1 user group 7 Nov 5 13:46 short -> target",
            false,
        );
        assert!(link.is_symlink());
        assert_eq!(link.name(), "short");
    }

    /// The case the honesty of the permission column rests on: `MLSD` carries
    /// rights only when it sends `UNIX.mode`, and the parser fills in 0777
    /// where it did not. Reporting that as an answer would have the pane claim
    /// `rwxrwxrwx` for every entry on a server that simply says nothing.
    #[test]
    fn mlsd_without_unix_mode_states_no_permissions() {
        let (file, stated) = parsed("type=file;size=88;modify=20240105120000; report.pdf", true);
        assert_eq!(file.name(), "report.pdf");
        assert_eq!(file.size(), 88);
        assert!(!stated, "no UNIX.mode was sent, so nothing may be claimed");
    }

    #[test]
    fn mlsd_with_unix_mode_states_them() {
        let (file, stated) = parsed(
            "type=file;size=88;modify=20240105120000;UNIX.mode=0640; report.pdf",
            true,
        );
        assert!(stated);
        assert_eq!(mode_of(&file), 0o640);
    }

    /// A DOS listing has no permissions at all, and the parser's default would
    /// otherwise read as `rwxrwxrwx` here too.
    #[test]
    fn dos_listing_states_no_permissions() {
        let (file, stated) = parsed("01-05-24  12:00PM                  888 report.pdf", false);
        assert_eq!(file.name(), "report.pdf");
        assert!(!stated);
    }

    /// Servers put banners, totals and blank lines in a `LIST`. One of them
    /// must not cost the user the whole directory.
    #[test]
    fn unreadable_lines_are_skipped() {
        assert!(parse_line("total 48", false).is_none());
        assert!(parse_line("", false).is_none());
    }

    #[test]
    fn a_listing_without_a_time_says_so() {
        let (file, _) = parsed("type=file;size=1; notime", true);
        assert_eq!(modified_of(&file), None, "the epoch means \"did not say\"");
    }

    // ---- Permissions on a tree ------------------------------------------------

    /// `chmod -R 755` on a source tree must not make every file in it
    /// executable — the classic way a deployment is ruined.
    #[test]
    fn a_tree_does_not_make_plain_files_executable() {
        assert_eq!(tree_file_mode(0o755, Some(0o644)), 0o644);
        assert_eq!(
            tree_file_mode(0o755, Some(0o755)),
            0o755,
            "a program stays one"
        );
        assert_eq!(tree_file_mode(0o755, None), 0o644);
    }

    // ---- Paths -----------------------------------------------------------------

    #[test]
    fn remote_paths_are_joined_posix_style() {
        assert_eq!(join("/var/www", "index.html"), "/var/www/index.html");
        assert_eq!(join("/", "index.html"), "/index.html");
    }
}

/// Against a real server, and therefore not run by default.
///
/// FTP is a protocol of assumptions: whether `MLSD` is offered, whether `SITE
/// CHMOD` is understood, whether `REST` applies to an upload. None of that can
/// be settled by reading the RFC, so it is settled here — against vsftpd,
/// which is what most of the Unix world actually runs.
///
/// Three servers, because they disagree in exactly the places that matter.
/// vsftpd offers no `MLSD` at all and so exercises the `LIST` parser; pure-ftpd
/// offers `MLSD` and, run with `-R` as its image does, refuses `SITE CHMOD`;
/// the third adds a self-signed certificate for the FTPS pair.
///
/// ```text
/// docker run -d --name wireterm-ftptest -p 2121:21 -p 30010-30019:30010-30019 \
///   -e FTP_USER=tester -e FTP_PASS=geheim -e PASV_ADDRESS=127.0.0.1 \
///   -e PASV_MIN_PORT=30010 -e PASV_MAX_PORT=30019 fauria/vsftpd
///
/// docker run -d --name wireterm-ftptest2 -p 2122:21 -p 30000-30009:30000-30009 \
///   -e PUBLICHOST=127.0.0.1 -e FTP_USER_NAME=tester -e FTP_USER_PASS=geheim \
///   -e FTP_USER_HOME=/home/tester stilliard/pure-ftpd
///
/// docker run -d --name wireterm-ftps -p 2123:21 -p 30020-30029:30020-30029 \
///   -e PUBLICHOST=127.0.0.1 -e FTP_USER_NAME=tester -e FTP_USER_PASS=geheim \
///   -e FTP_USER_HOME=/home/tester -e TLS_CN=localhost -e TLS_ORG=WireTerm \
///   -e TLS_C=DE -e ADDED_FLAGS=--tls=1 -e FTP_PASSIVE_PORTS=30020:30029 \
///   stilliard/pure-ftpd
///
/// cargo test --lib ftp::live -- --ignored --nocapture
/// WIRETERM_FTP_PORT=2122 cargo test --lib ftp::live -- --ignored --nocapture
/// ```
///
/// `WIRETERM_FTP_PORT` picks which plain server to run against (2121 by
/// default), `WIRETERM_FTPS_PORT` which TLS one (2123).
#[cfg(test)]
mod live {
    use super::*;

    fn settings() -> FtpSettings {
        FtpSettings {
            host: "127.0.0.1".to_string(),
            port: std::env::var("WIRETERM_FTP_PORT")
                .ok()
                .and_then(|p| p.parse().ok())
                .unwrap_or(2121),
            user: "tester".to_string(),
            auth: FtpAuth::Password {
                password: "geheim".to_string(),
            },
            security: FtpSecurity::Plain,
            passive: true,
            accept_invalid_cert: false,
            start_path: String::new(),
            proxy: None,
        }
    }

    /// Where the TLS-enabled server listens; see the module's doc comment.
    fn tls_port() -> u16 {
        std::env::var("WIRETERM_FTPS_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(2123)
    }

    fn run<F: std::future::Future<Output = ()>>(test: F) {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(test);
    }

    async fn connect() -> (Client, bool) {
        let settings = settings();
        let mut client = login(
            &settings,
            None,
            &settings.user,
            "geheim",
            &Pinning::default(),
        )
        .await
        .expect("login");
        let mlsd = client
            .feat()
            .await
            .map(|f| f.keys().any(|k| k.eq_ignore_ascii_case("MLSD")))
            .unwrap_or(false);
        (client, mlsd)
    }

    /// Everything the file browser does that does not move bytes: log in, walk
    /// a tree into being, read it back, change its permissions and take it
    /// down again.
    #[test]
    #[ignore = "needs the vsftpd container named in the module's doc comment"]
    fn a_tree_can_be_built_read_and_removed() {
        run(async {
            let (mut client, mlsd) = connect().await;
            println!("MLSD offered: {mlsd}");

            let home = client.pwd().await.expect("pwd");
            let root = join(&home, "wireterm-test");
            let _ = remove_tree(&mut client, mlsd, &root).await;

            client.mkdir(&root).await.expect("mkdir");
            let inner = join(&root, "subfolder");
            client.mkdir(&inner).await.expect("mkdir inner");

            let file = join(&root, "note.txt");
            let mut stream = client.put_with_stream(&file).await.expect("stor");
            stream.write_all(b"hi, world!").await.expect("write");
            stream.finish().await.expect("finish");

            // The listing, which is the part with the most ways to go wrong.
            let (dir, entries) = read_entries(&mut client, mlsd, &root, true)
                .await
                .expect("list");
            assert_eq!(dir, root);
            let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
            assert!(names.contains(&"note.txt"), "got {names:?}");
            assert!(names.contains(&"subfolder"), "got {names:?}");

            let note = entries.iter().find(|e| e.name == "note.txt").unwrap();
            assert!(!note.is_dir);
            assert_eq!(note.size, 10, "\"hi, world!\" is ten bytes");
            assert!(note.modified.is_some(), "both servers state a time");
            let folder = entries.iter().find(|e| e.name == "subfolder").unwrap();
            assert!(folder.is_dir);

            // The honesty invariant, which holds whatever the server says: the
            // two permission fields are filled in together or not at all.
            // Never one without the other, and never a made-up 0777.
            assert_eq!(
                note.mode.is_some(),
                note.permissions.is_some(),
                "permissions and mode agree about whether anything was said"
            );

            // `SITE CHMOD` is not part of FTP. vsftpd has it; pure-ftpd run
            // with `-R` refuses it, and so does anything not on a POSIX
            // filesystem. Both outcomes are correct behaviour — what is being
            // checked is that a refusal arrives as the server's own words and
            // a success actually takes effect.
            match set_mode(&mut client, &file, 0o640).await {
                Err(refusal) => {
                    assert!(refusal.contains(&file), "the refusal names the file");
                    println!("SITE CHMOD refused (to be expected): {refusal}");
                }
                Ok(()) => {
                    let (_, entries) = read_entries(&mut client, mlsd, &root, false)
                        .await
                        .expect("list again");
                    let note = entries.iter().find(|e| e.name == "note.txt").unwrap();
                    assert_eq!(note.mode, Some(0o640), "permissions were read back");
                    assert_eq!(note.permissions.as_deref(), Some("rw-r-----"));
                }
            }

            client
                .rename(file.as_str(), join(&root, "new.txt").as_str())
                .await
                .expect("rename");
            assert!(exists(&mut client, &join(&root, "new.txt")).await);
            assert!(!exists(&mut client, &file).await);

            // Removing a tree the connection is standing inside of.
            remove_tree(&mut client, mlsd, &root).await.expect("remove");
            assert!(!exists(&mut client, &root).await);

            let _ = client.quit().await;
        });
    }

    /// Both halves of the certificate checkbox, against a self-signed one.
    ///
    /// The point of the pair is that they disagree: if the checked connection
    /// also got through, the check would be doing nothing and nobody would
    /// notice until it mattered.
    #[test]
    #[ignore = "needs the TLS container named in the module's doc comment"]
    fn a_self_signed_certificate_is_refused_unless_it_is_waived() {
        run(async {
            let mut strict = settings();
            strict.port = tls_port();
            strict.security = FtpSecurity::Explicit;

            // `expect_err` is not available: a client has no `Debug`, so the
            // error has to be taken out by hand.
            let pinning = Pinning::default();
            let refusal = match login(&strict, None, &strict.user, "geheim", &pinning).await {
                Err(refusal) => refusal,
                Ok(_) => panic!("a self-signed certificate must not pass the check"),
            };
            assert!(
                refusal.contains("TLS") && refusal.contains("certificate"),
                "the refusal says it was the certificate: {refusal}"
            );
            println!("Checked, refused: {refusal}");

            // What was turned down is left for the question — and once that
            // exact certificate is pinned, the checked connection gets through.
            let refused = pinning
                .take_refused()
                .expect("the certificate is left to ask about");
            println!(
                "Fingerprint {} ({})",
                tls::fingerprint_text(&refused.fingerprint),
                refused.reason
            );
            let pinned = Pinning::new(vec![refused.fingerprint]);
            let mut client = login(&strict, None, &strict.user, "geheim", &pinned)
                .await
                .expect("the pinned certificate gets through");
            let _ = client.quit().await;

            // A pin for some other certificate is no pin for this one.
            let other = Pinning::new(vec![[0u8; 32]]);
            assert!(login(&strict, None, &strict.user, "geheim", &other)
                .await
                .is_err());

            let mut waived = strict.clone();
            waived.accept_invalid_cert = true;
            let mut client = login(&waived, None, &waived.user, "geheim", &Pinning::default())
                .await
                .expect("waiving the check gets through");

            // And it is a working connection, not merely a handshake: the
            // login and a command ran over it.
            let home = client.pwd().await.expect("pwd over TLS");
            assert!(home.starts_with('/'), "got {home}");
            println!("Connected unchecked, pwd = {home}");
            let _ = client.quit().await;
        });
    }

    /// The two assumptions the resume path rests on: that `SIZE` answers, and
    /// that `APPE` continues a file rather than replacing it.
    #[test]
    #[ignore = "needs the vsftpd container named in the module's doc comment"]
    fn an_upload_can_be_continued_with_appe() {
        run(async {
            let (mut client, mlsd) = connect().await;
            let home = client.pwd().await.expect("pwd");
            let root = join(&home, "wireterm-resume");
            let _ = remove_tree(&mut client, mlsd, &root).await;
            client.mkdir(&root).await.expect("mkdir");

            let file = join(&root, "split.bin");
            let mut first = client.put_with_stream(&file).await.expect("stor");
            first.write_all(b"the first one").await.expect("write");
            first.finish().await.expect("finish");

            let after_first = client.size(file.as_str()).await.expect("size") as u64;
            assert_eq!(after_first, 13, "SIZE reports what actually landed");

            let mut second = client.append_with_stream(&file).await.expect("appe");
            second.write_all(b" the second one").await.expect("write");
            second.finish().await.expect("finish");

            assert_eq!(
                client.size(file.as_str()).await.expect("size") as u64,
                28,
                "APPE continued the file instead of replacing it"
            );

            // And `REST` before a `RETR`, which is the download half.
            client.resume_transfer(13).await.expect("rest");
            let mut rest = client.retr_as_stream(file.as_str()).await.expect("retr");
            let mut tail = Vec::new();
            rest.read_to_end(&mut tail).await.expect("read");
            rest.finish().await.expect("finish");
            assert_eq!(
                String::from_utf8_lossy(&tail),
                " the second one",
                "REST began the transfer where it was told to"
            );

            remove_tree(&mut client, mlsd, &root).await.expect("remove");
            let _ = client.quit().await;
        });
    }

    /// Through the proxies from `scripts/proxy` to a pure-ftpd that lives only
    /// inside the Docker network — the data connection has to go through
    /// them too:
    ///
    /// ```text
    /// docker run -d --rm --name wireterm-ftp-intern --network wireterm-jump --network-alias ftp \
    ///   -e PUBLICHOST=ftp -e FTP_USER_NAME=tester -e FTP_USER_PASS=geheim \
    ///   -e FTP_USER_HOME=/home/tester stilliard/pure-ftpd
    /// cargo test --lib ftp::live::through_a_proxy -- --ignored
    /// ```
    #[test]
    #[ignore]
    fn through_a_proxy() {
        run(async {
            for (kind, port) in [
                (crate::proxy::ProxyKind::Socks5, 21080),
                (crate::proxy::ProxyKind::Http, 23128),
            ] {
                let route = Route {
                    kind,
                    host: "127.0.0.1".into(),
                    port,
                    user: "anna".into(),
                    password: "geheim".into(),
                };
                let internal = FtpSettings {
                    host: "ftp".to_string(),
                    port: 21,
                    ..settings()
                };
                let mut client = login(
                    &internal,
                    Some(&route),
                    "tester",
                    "geheim",
                    &Pinning::default(),
                )
                .await
                .expect("logged in through the proxy");

                let file = format!("proxy-{kind:?}.txt");
                let mut upload = client.put_with_stream(&file).await.expect("stor");
                upload.write_all(b"through the proxy").await.expect("write");
                upload.finish().await.expect("finish");
                let names = client.nlst(None).await.expect("nlst");
                assert!(
                    names.iter().any(|name| name.ends_with(&file)),
                    "{kind:?}: {names:?}"
                );
                client.rm(&file).await.expect("dele");

                let active = FtpSettings {
                    passive: false,
                    ..internal.clone()
                };
                assert!(login(
                    &active,
                    Some(&route),
                    "tester",
                    "geheim",
                    &Pinning::default()
                )
                .await
                .is_err());
                let _ = client.quit().await;
            }
        });
    }
}
