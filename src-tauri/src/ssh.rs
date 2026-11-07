//! Interactive SSH sessions for the terminal tabs.
//!
//! Several sessions run at once, one per open tab, each identified by a
//! `session_id` the frontend makes up. Keystrokes go in through `ssh_send`;
//! everything the server sends back is emitted as `ssh:data:<session_id>`
//! carrying raw bytes, so multi-byte characters split across reads stay
//! intact. `ssh:closed:<session_id>` marks the end of a session.
//!
//! Events are named per session rather than carrying the id in the payload, so
//! a terminal is only woken by its own output.
//!
//! The connection itself belongs to the tab, not to the terminal. SFTP
//! ([`crate::sftp`]) is a subsystem of SSH and runs over the same one, so the
//! key, the host-key question and the login happen once per tab however many
//! of its views are open. [`Transports`] holds them; [`session_close`] is the
//! only thing that hangs one up, and `ssh_disconnect` merely ends the shell.
//!
//! Which host to reach and where its key comes from is part of the stored
//! connection ([`SshSettings`]), not compiled in.
//!
//! The server's own key is checked against [`crate::known_hosts`] before the
//! login, and anything not on file is put to the user as a question.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use russh::client::{self, AuthResult, Handle, KeyboardInteractiveAuthResponse, Msg};
use russh::keys::agent::client::{AgentClient, AgentStream};
use russh::keys::{
    decode_secret_key, Error as KeyError, HashAlg, PrivateKey, PrivateKeyWithHashAlg, PublicKey,
    PublicKeyOrCertificate,
};
use russh::{Channel, ChannelId, ChannelMsg, ChannelWriteHalf, Disconnect, MethodKind};
use rust_i18n::t;
use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager, State};
use tokio::sync::{oneshot, Mutex};
use tokio::time::timeout;

use crate::known_hosts::{self, Verdict};
use crate::secret::{self, Cache, Prompts};
use crate::storage::{Probe, RemoteSystem, SshAuth, SshSettings};
use crate::vault;

fn data_event(session_id: &str) -> String {
    format!("ssh:data:{session_id}")
}

/// `cd` to `path`, single-quoted so spaces and `$` stay literal. A leading `~`
/// stays outside the quotes, since that is the only way it still expands.
fn cd_command(path: &str) -> String {
    let (home, rest) = match path.strip_prefix("~/") {
        Some(rest) => ("~/", rest),
        None if path == "~" => ("~/", ""),
        None => ("", path),
    };
    format!("cd {home}'{}'\n", rest.replace('\'', r"'\''"))
}

fn closed_event(session_id: &str) -> String {
    format!("ssh:closed:{session_id}")
}

fn system_event(session_id: &str) -> String {
    format!("ssh:system:{session_id}")
}

// ---- Host key --------------------------------------------------------------

/// Where the question about an unknown host key goes.
const HOST_KEY_EVENT: &str = "ssh:host-key";

/// How long an unanswered question is waited on.
///
/// The dialog is modal and always answers, so this only catches the case where
/// nothing is listening at all — a window closed mid-handshake, say. Without
/// it the connecting task would sit there for the rest of the run.
const ANSWER_TIMEOUT: Duration = Duration::from_secs(300);

/// The questions waiting for an answer, by id.
///
/// Verification happens inside the handshake, on whichever task is connecting,
/// while the answer arrives later on another one through
/// [`ssh_host_key_answer`]. The channel in here is what joins the two.
#[derive(Clone, Default)]
pub struct HostKeyPrompts(Arc<Mutex<HashMap<String, oneshot::Sender<bool>>>>);

/// What the dialog is asked.
///
/// Carries no session id: the same question comes up while *testing* a
/// connection, which has no session, and the id in the payload is what the
/// answer comes back with anyway.
///
/// FTPS asks about a certificate in the same dialog — see [`crate::ftp`] —
/// which is what `kind` and `reason` are for.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct HostKeyQuestion {
    pub(crate) id: String,
    /// `ssh` for a host key, `tls` for a server certificate.
    pub(crate) kind: &'static str,
    pub(crate) host: String,
    pub(crate) port: u16,
    /// `ssh-ed25519`, `ecdsa-sha2-nistp256`, …; for a certificate
    /// [`crate::certificates::ALGORITHM`].
    pub(crate) algorithm: String,
    /// `SHA256:…`, the same form OpenSSH prints, so the two can be compared.
    /// For a certificate the `AB:CD:…` that `openssl` prints.
    pub(crate) fingerprint: String,
    /// A different key of this type is already on file — the serious case.
    pub(crate) changed: bool,
    /// Why the system does not trust a certificate. Empty for a host key,
    /// which has no one but the user to vouch for it.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) reason: String,
    /// The key itself, as an `authorized_keys` line.
    ///
    /// Not for the dialog to show — nobody reads a base64 blob — but for what
    /// happens after "Trust": in a workspace on a backend, the answer
    /// belongs to the workspace rather than to this device, so the frontend
    /// hands it on. See [`crate::cloud`]. For a certificate its SHA-256
    /// fingerprint in hex, which is all a workspace needs to pin it.
    pub(crate) public_key: String,
}

/// Only has to tell concurrent questions apart: two tabs can be reaching two
/// unknown hosts at the same moment.
pub(crate) fn next_question_id() -> String {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    format!("hk{}", NEXT.fetch_add(1, Ordering::Relaxed))
}

/// Puts the question to the frontend and waits for the answer. Anything that
/// is not a yes — a timeout, a closed window — is a no.
pub(crate) async fn ask_host_key(
    app: &AppHandle,
    prompts: &HostKeyPrompts,
    question: &HostKeyQuestion,
) -> bool {
    let (sender, answer) = oneshot::channel();
    prompts.0.lock().await.insert(question.id.clone(), sender);

    if app.emit(HOST_KEY_EVENT, question).is_err() {
        prompts.0.lock().await.remove(&question.id);
        return false;
    }

    match timeout(ANSWER_TIMEOUT, answer).await {
        Ok(Ok(trusted)) => trusted,
        // Timed out, or the sender was dropped. Neither is an answer.
        _ => {
            prompts.0.lock().await.remove(&question.id);
            false
        }
    }
}

/// What the check leaves behind for whoever started the connection.
#[derive(Default)]
struct CheckOutcome {
    /// Why the key was refused. `client::connect` reports nothing but "unknown
    /// key", so the reason is left here for [`authenticate`] to pick up.
    refusal: Option<String>,
    /// How long the question was on screen. Not something the server is
    /// responsible for, so "Test connection" takes it back off its timing.
    waited: Duration,
    /// The line the server introduced itself with, `SSH-2.0-OpenSSH_9.6p1 …`.
    /// The fallback for a target that answers no questions about its system.
    software: Option<String>,
}

/// Checks the server's key against the known hosts and, where they say
/// nothing, asks the user.
pub(crate) struct HostKeyCheck {
    app: AppHandle,
    prompts: HostKeyPrompts,
    host: String,
    port: u16,
    outcome: Arc<Mutex<CheckOutcome>>,
    /// Whether the server may open channels to the local SSH agent. Only for
    /// the target, and only if the connection is set up that way — never for a
    /// jump host.
    forward_agent: bool,
    /// For remote port forwardings: which port on the server leads to which
    /// target here — see [`crate::forward`].
    remote_targets: crate::forward::RemoteTargets,
}

impl HostKeyCheck {
    /// Turns down the key and records why. Every failure ends up here,
    /// including one reading the store: a check that cannot be carried out has
    /// not passed.
    async fn refuse(&self, reason: String) -> Result<bool, russh::Error> {
        self.outcome.lock().await.refusal = Some(reason);
        Ok(false)
    }

    /// Puts the question to the frontend and waits for the answer.
    async fn ask(&self, question: &HostKeyQuestion) -> bool {
        let asked = Instant::now();
        let trusted = ask_host_key(&self.app, &self.prompts, question).await;
        self.outcome.lock().await.waited += asked.elapsed();
        trusted
    }
}

impl client::Handler for HostKeyCheck {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        let key = match server_public_key {
            PublicKeyOrCertificate::PublicKey { key, .. } => key.clone(),
            // A host certificate would have to be checked against the CA that
            // signed it, and there is nowhere in this app to configure one.
            // The certified key is pinned instead, exactly like a bare host
            // key: it does not give the certificate its meaning back, but it
            // still catches a stranger answering on the same address.
            PublicKeyOrCertificate::Certificate(cert) => {
                PublicKey::new(cert.public_key().clone(), "")
            }
        };

        let verdict = match known_hosts::lookup(&self.app, &self.host, self.port, &key) {
            Ok(verdict) => verdict,
            Err(e) => {
                return self
                    .refuse(t!("ssh.known_hosts_read_failed", error = e).into_owned())
                    .await
            }
        };
        if verdict == Verdict::Known {
            return Ok(true);
        }

        let changed = verdict == Verdict::Changed;
        let question = HostKeyQuestion {
            id: next_question_id(),
            kind: "ssh",
            host: self.host.clone(),
            port: self.port,
            algorithm: key.algorithm().to_string(),
            fingerprint: key.fingerprint(HashAlg::Sha256).to_string(),
            changed,
            reason: String::new(),
            // A key that cannot be written would not have made it this far;
            // an empty field would only mean it does not go into the
            // workspace.
            public_key: known_hosts::to_openssh(&key).unwrap_or_default(),
        };

        if !self.ask(&question).await {
            return self
                .refuse(if changed {
                    t!("ssh.host_key_changed_rejected", host = self.host).into_owned()
                } else {
                    t!("ssh.host_key_rejected", host = self.host).into_owned()
                })
                .await;
        }

        // Written before the login, so the answer holds for the next
        // connection even if this one goes on to fail on the user's key.
        if let Err(e) = known_hosts::trust(&self.app, &self.host, self.port, &key) {
            return self
                .refuse(t!("ssh.host_key_record_failed", error = e).into_owned())
                .await;
        }
        Ok(true)
    }

    /// The first callback that sees the session, and every view opens a
    /// channel — so this is where the server's identification is picked up.
    async fn channel_open_confirmation(
        &mut self,
        _id: ChannelId,
        _max_packet_size: u32,
        _window_size: u32,
        session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        let mut outcome = self.outcome.lock().await;
        if outcome.software.is_none() {
            outcome.software = Some(String::from_utf8_lossy(session.remote_sshid()).into_owned());
        }
        Ok(())
    }

    /// The server wants to reach the local agent — because someone on it runs
    /// `ssh` onwards. Refused if the connection did not allow that; otherwise
    /// the channel is connected to this machine's agent.
    async fn server_channel_open_agent_forward(
        &mut self,
        channel: Channel<Msg>,
        reply: client::ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        if !self.forward_agent {
            reply
                .reject(russh::ChannelOpenFailure::AdministrativelyProhibited)
                .await;
            return Ok(());
        }
        reply.accept().await;
        tauri::async_runtime::spawn(async move {
            if let Ok(agent) = connect_agent().await {
                let _ = bridge(channel, agent.into_inner()).await;
            }
        });
        Ok(())
    }

    /// A connection on a port the server forwards for us. Refused if there is
    /// no such forwarding.
    async fn server_channel_open_forwarded_tcpip(
        &mut self,
        channel: Channel<Msg>,
        _connected_address: &str,
        connected_port: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: client::ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        if !crate::forward::expects(&self.remote_targets, connected_port) {
            reply
                .reject(russh::ChannelOpenFailure::AdministrativelyProhibited)
                .await;
            return Ok(());
        }
        reply.accept().await;
        let targets = Arc::clone(&self.remote_targets);
        tauri::async_runtime::spawn(async move {
            crate::forward::serve_forwarded(&targets, channel, connected_port).await;
        });
        Ok(())
    }
}

/// Connects a forwarded agent channel to the local agent until either side
/// stops. Nobody here has to understand the protocol in between — it is the
/// same bytes as over a local socket.
pub(crate) async fn bridge<S>(channel: Channel<Msg>, mut agent: S) -> std::io::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut stream = channel.into_stream();
    tokio::io::copy_bidirectional(&mut stream, &mut agent).await?;
    Ok(())
}

/// The dialog's answer.
///
/// An id that is no longer waiting is ignored rather than reported: the
/// question may have timed out, or its tab been closed, while the dialog was
/// still on screen.
#[tauri::command]
pub async fn ssh_host_key_answer(
    prompts: State<'_, HostKeyPrompts>,
    id: String,
    trust: bool,
) -> Result<(), String> {
    if let Some(sender) = prompts.0.lock().await.remove(&id) {
        let _ = sender.send(trust);
    }
    Ok(())
}

/// The write side of the channel. Splitting it off lets the reader task own
/// the read side while commands keep writing and resizing.
///
/// Holds no handle: the transport belongs to the tab, not to the shell — see
/// [`Transports`].
struct Session {
    channel: ChannelWriteHalf<Msg>,
}

#[derive(Default)]
pub struct SshState(Mutex<HashMap<String, Session>>);

// ---- Transport per tab ---------------------------------------------------------

/// A logged-in connection, shared by everything one tab does over it.
///
/// Dropping the last one tears the connection down, which is why it is an
/// `Arc` rather than something a single view owns.
pub(crate) type Transport = Arc<Handle<HostKeyCheck>>;

/// The slot a tab's transport lives in.
///
/// The `Option` is what makes a slot reusable: a connection that turned out to
/// be dead is taken out and a new one put in its place, without the map itself
/// having to be touched again.
/// Beside the transport: what its login left behind, which the handler goes on
/// filling in — the server's identification arrives with the first channel.
type Slot = Arc<Mutex<Option<Login>>>;

/// A login together with everything that keeps it alive.
pub(crate) struct Login {
    pub transport: Transport,
    outcome: Arc<Mutex<CheckOutcome>>,
    /// The connections to the jump hosts, first hop first. They carry the
    /// tunnel `transport` runs through — if they go away, so does the target.
    /// That is why they are here and nowhere else.
    jumps: Vec<Transport>,
    /// This login's remote port forwardings, shared with its handler.
    remote_targets: crate::forward::RemoteTargets,
}

impl Login {
    async fn hang_up(&self) {
        let _ = self
            .transport
            .disconnect(Disconnect::ByApplication, "", "en")
            .await;
        for jump in self.jumps.iter().rev() {
            let _ = jump.disconnect(Disconnect::ByApplication, "", "en").await;
        }
    }
}

/// One logged-in connection per tab, opened on demand.
///
/// Terminal and file browser are two channels on the same connection, so the
/// key, the host-key question and the login happen once per tab rather than
/// once per view. Whichever of the two is opened first pays for it.
#[derive(Default)]
pub struct Transports(Mutex<HashMap<String, Slot>>);

impl Transports {
    /// The tab's connection, logged in if it is not up yet.
    ///
    /// The login runs under the tab's own lock, not the map's: it can take
    /// seconds — a vault, a host-key question — and no other tab may be held
    /// up by that. The same tab asking twice at once does wait, which is the
    /// point: otherwise the terminal and the file browser opening together
    /// would log in twice.
    pub(crate) async fn get(
        &self,
        app: &AppHandle,
        session_id: &str,
        settings: &SshSettings,
    ) -> Result<Transport, String> {
        let slot: Slot = self
            .0
            .lock()
            .await
            .entry(session_id.to_string())
            .or_default()
            .clone();
        let mut held = slot.lock().await;

        // A connection that is merely stored says nothing about whether it is
        // still up — the network may have gone away under it. The keepalive
        // fails as soon as the transport task has ended, which is the case
        // that matters here.
        if let Some(login) = held.as_ref() {
            if login.transport.send_keepalive(false).await.is_ok() {
                return Ok(Arc::clone(&login.transport));
            }
            if let Some(dead) = held.take() {
                dead.hang_up().await;
            }
        }

        let login = login(app, settings, Some(session_id)).await?;
        let transport = Arc::clone(&login.transport);
        *held = Some(login);
        Ok(transport)
    }

    /// The tab's connection, if it is logged in — without logging in.
    pub(crate) async fn current(&self, session_id: &str) -> Option<Transport> {
        let slot = self.0.lock().await.get(session_id)?.clone();
        let held = slot.lock().await;
        held.as_ref().map(|login| Arc::clone(&login.transport))
    }

    /// This tab's mapping of remote forwardings.
    pub(crate) async fn remote_targets(
        &self,
        session_id: &str,
    ) -> Option<crate::forward::RemoteTargets> {
        let slot = self.0.lock().await.get(session_id)?.clone();
        let held = slot.lock().await;
        held.as_ref().map(|login| Arc::clone(&login.remote_targets))
    }

    /// How the tab's server introduced itself — once a channel is open.
    async fn software(&self, session_id: &str) -> Option<String> {
        let slot = self.0.lock().await.get(session_id)?.clone();
        let held = slot.lock().await;
        let software = held.as_ref()?.outcome.lock().await.software.clone();
        software
    }

    /// Hangs up, if the tab ever got as far as logging in.
    async fn close(&self, session_id: &str) {
        let Some(slot) = self.0.lock().await.remove(session_id) else {
            return;
        };
        let Some(login) = slot.lock().await.take() else {
            return;
        };
        login.hang_up().await;
    }
}

/// What the login is proved with.
enum Credential {
    Key(PrivateKey),
    Password(String),
    Agent(AgentClient<Box<dyn AgentStream + Send + Unpin>>),
}

/// Whether decoding failed only for want of a passphrase. russh says so for
/// the OpenSSH and the old PEM format; encrypted PKCS#8 and PuTTY files fail
/// with an error that does not, so those are recognised by their text.
fn needs_passphrase(pem: &str, error: &KeyError) -> bool {
    let ppk_encrypted = pem.trim_start().starts_with("PuTTY-User-Key-File-")
        && pem.lines().any(|l| {
            l.strip_prefix("Encryption:")
                .is_some_and(|v| v.trim() != "none")
        });
    matches!(error, KeyError::KeyIsEncrypted)
        || pem.contains("-----BEGIN ENCRYPTED PRIVATE KEY-----")
        || ppk_encrypted
}

/// Decodes a private key, asking for its passphrase if it has one.
///
/// The passphrase is kept per tab in [`Cache`] like a typed-in password — the
/// key and the password sources exclude each other, so the slot is free. A
/// passphrase that does not open the key is forgotten, so the next attempt
/// asks again.
async fn decode_key(
    app: &AppHandle,
    settings: &SshSettings,
    session_id: Option<&str>,
    pem: &str,
    unusable: &str,
) -> Result<PrivateKey, String> {
    match decode_secret_key(pem, None) {
        Ok(key) => return Ok(key),
        Err(e) if !needs_passphrase(pem, &e) => return Err(format!("{unusable}: {e}")),
        Err(_) => {}
    }

    let cache = app.state::<Cache>();
    let cached = match session_id {
        Some(id) => cache.get(id).await,
        None => None,
    };
    let passphrase = match cached {
        Some(passphrase) => passphrase,
        None => {
            secret::ask(
                app,
                app.state::<Prompts>().inner(),
                secret::Kind::Passphrase,
                &settings.host,
                settings.port,
                &settings.user,
            )
            .await?
        }
    };
    match decode_secret_key(pem, Some(&passphrase)) {
        Ok(key) => {
            if let Some(id) = session_id {
                cache.put(id, &passphrase).await;
            }
            Ok(key)
        }
        Err(_) => {
            if let Some(id) = session_id {
                cache.forget(id).await;
            }
            Err(t!("ssh.passphrase_wrong").into_owned())
        }
    }
}

/// The OpenSSH agent that ships with Windows first — 1Password's agent sits
/// on the same pipe — then Pageant.
#[cfg(windows)]
async fn connect_agent() -> Result<AgentClient<Box<dyn AgentStream + Send + Unpin>>, String> {
    if let Ok(agent) = AgentClient::connect_named_pipe(r"\\.\pipe\openssh-ssh-agent").await {
        return Ok(agent.dynamic());
    }
    AgentClient::connect_pageant()
        .await
        .map(AgentClient::dynamic)
        .map_err(|_| t!("ssh.no_agent").into_owned())
}

/// The agent behind `SSH_AUTH_SOCK` — ssh-agent, gpg-agent, the macOS
/// keychain agent or 1Password's, whichever the session points to.
#[cfg(unix)]
async fn connect_agent() -> Result<AgentClient<Box<dyn AgentStream + Send + Unpin>>, String> {
    AgentClient::connect_env()
        .await
        .map(AgentClient::dynamic)
        .map_err(|_| t!("ssh.no_agent").into_owned())
}

/// Loads the key or password from whichever source the connection names.
///
/// For the vault sources the secret is fetched here and dropped once the
/// session is up; it is never written to disk. A typed-in password is kept
/// per tab in [`Cache`], so a reconnect does not ask again — "Test
/// connection" has no tab and asks every time, as FTP does.
async fn credential(
    app: &AppHandle,
    settings: &SshSettings,
    session_id: Option<&str>,
) -> Result<Credential, String> {
    match &settings.auth {
        SshAuth::InlineKey { key } => {
            let unusable = t!("ssh.stored_key_unusable");
            decode_key(app, settings, session_id, key, &unusable)
                .await
                .map(Credential::Key)
        }
        SshAuth::KeyFile { path } => {
            let unusable = t!("ssh.key_file_read_failed", path = path).into_owned();
            let pem = std::fs::read_to_string(path).map_err(|e| format!("{unusable}: {e}"))?;
            decode_key(app, settings, session_id, &pem, &unusable)
                .await
                .map(Credential::Key)
        }
        SshAuth::Vault {
            provider,
            reference,
        } => {
            let name = provider.label();
            let pem = vault::resolve(app, *provider, reference)
                .await
                .map_err(|e| {
                    t!("ssh.vault_key_read_failed", name = name, error = e).into_owned()
                })?;
            let unusable = t!("ssh.vault_key_unusable", name = name).into_owned();
            decode_key(app, settings, session_id, &pem, &unusable)
                .await
                .map(Credential::Key)
        }
        SshAuth::Agent => connect_agent().await.map(Credential::Agent),
        SshAuth::Password { password } => Ok(Credential::Password(password.clone())),
        SshAuth::VaultPassword {
            provider,
            reference,
        } => vault::resolve(app, *provider, reference)
            .await
            .map(Credential::Password)
            .map_err(|e| {
                t!(
                    "ssh.vault_password_read_failed",
                    name = provider.label(),
                    error = e
                )
                .into_owned()
            }),
        SshAuth::Prompt => {
            let cache = app.state::<Cache>();
            if let Some(password) = match session_id {
                Some(id) => cache.get(id).await,
                None => None,
            } {
                return Ok(Credential::Password(password));
            }
            let password = secret::ask(
                app,
                app.state::<Prompts>().inner(),
                secret::Kind::Password,
                &settings.host,
                settings.port,
                &settings.user,
            )
            .await?;
            if let Some(id) = session_id {
                cache.put(id, &password).await;
            }
            Ok(Credential::Password(password))
        }
    }
}

/// Key, TCP, host key, login — the part that opening a terminal and testing a
/// connection have in common.
/// At most this many jump hosts in a row. More is no longer a setup but a
/// loop the UI did not detect.
const MAX_JUMPS: usize = 8;

/// Logs in to the target — through the jump hosts in [`SshSettings::via`], if
/// there are any. Each hop is a login of its own with its own host-key check
/// and its own credentials; through it a `direct-tcpip` channel goes to the
/// next.
async fn login(
    app: &AppHandle,
    settings: &SshSettings,
    session_id: Option<&str>,
) -> Result<Login, String> {
    if settings.jump.is_some() && settings.via.is_empty() {
        return Err(t!("ssh.jump_host_gone").into_owned());
    }
    if settings.via.len() > MAX_JUMPS {
        return Err(t!("ssh.too_many_jumps", max = MAX_JUMPS).into_owned());
    }

    let mut jumps: Vec<Transport> = Vec::new();
    for (index, hop) in settings.via.iter().enumerate() {
        // A password asked for holds per hop, not for the target as well.
        let hop_session = session_id.map(|id| format!("{id}#jump{index}"));
        let outcome = Arc::new(Mutex::new(CheckOutcome::default()));
        let handle = authenticate(
            app,
            hop,
            hop_session.as_deref(),
            &outcome,
            jumps.last(),
            false,
            crate::forward::RemoteTargets::default(),
        )
        .await
        .map_err(|e| t!("ssh.jump_host_failed", host = hop.host, error = e).into_owned())?;
        jumps.push(Arc::new(handle));
    }

    let outcome = Arc::new(Mutex::new(CheckOutcome::default()));
    let remote_targets = crate::forward::RemoteTargets::default();
    let handle = authenticate(
        app,
        settings,
        session_id,
        &outcome,
        jumps.last(),
        settings.agent_forwarding,
        Arc::clone(&remote_targets),
    )
    .await;
    match handle {
        Ok(handle) => Ok(Login {
            transport: Arc::new(handle),
            outcome,
            jumps,
            remote_targets,
        }),
        Err(e) => {
            for jump in jumps.iter().rev() {
                let _ = jump.disconnect(Disconnect::ByApplication, "", "en").await;
            }
            Err(e)
        }
    }
}

/// A channel through `jump` to `host:port`: the jump host sets up the TCP
/// connection, and an ordinary SSH session runs over it.
async fn open_tunnel<H: client::Handler>(
    jump: &Handle<H>,
    host: &str,
    port: u16,
) -> Result<impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static, String> {
    let channel = jump
        .channel_open_direct_tcpip(host.to_string(), u32::from(port), "127.0.0.1", 0)
        .await
        .map_err(|e| t!("ssh.tunnel_failed", host = host, port = port, error = e).into_owned())?;
    Ok(channel.into_stream())
}

async fn authenticate(
    app: &AppHandle,
    settings: &SshSettings,
    session_id: Option<&str>,
    outcome: &Arc<Mutex<CheckOutcome>>,
    through: Option<&Transport>,
    forward_agent: bool,
    remote_targets: crate::forward::RemoteTargets,
) -> Result<Handle<HostKeyCheck>, String> {
    // The user may be a vault reference; from here on it is the name.
    let settings = &SshSettings {
        user: vault::resolve_user(app, &settings.user).await?,
        ..settings.clone()
    };
    let credential = credential(app, settings, session_id).await?;

    let check = HostKeyCheck {
        app: app.clone(),
        // Taken off the app rather than handed down from the command: the
        // waiting questions are needed here and nowhere on the way.
        prompts: app.state::<HostKeyPrompts>().inner().clone(),
        host: settings.host.clone(),
        port: settings.port,
        outcome: Arc::clone(outcome),
        forward_agent,
        remote_targets,
    };

    let config = Arc::new(client::Config::default());
    let connected = match through {
        // A proxy only counts for the first hop: everything after that is set
        // up by the jump host.
        None => match crate::proxy::route(app, settings.proxy.as_ref())? {
            Some(route) => {
                let stream = crate::proxy::connect(&route, &settings.host, settings.port).await?;
                client::connect_stream(config, stream, check).await
            }
            None => client::connect(config, (settings.host.as_str(), settings.port), check).await,
        },
        // Through the jump host: it sets up the TCP connection to the target,
        // and a perfectly ordinary SSH session runs over that channel — with
        // its own encryption, which the jump host cannot read.
        Some(jump) => {
            let tunnel = open_tunnel(jump, &settings.host, settings.port).await?;
            client::connect_stream(config, tunnel, check).await
        }
    };
    let mut handle = match connected {
        Ok(handle) => handle,
        // A refused host key arrives here as a bare "unknown key", which
        // says nothing about what went wrong. The check left the real
        // reason behind; it takes precedence.
        Err(e) => {
            return Err(match outcome.lock().await.refusal.take() {
                Some(reason) => reason,
                None => t!("ssh.unreachable", host = settings.host, error = e).into_owned(),
            })
        }
    };

    // `None` would sign RSA keys with SHA-1 (`ssh-rsa`), which OpenSSH
    // refuses since 8.8. A server that does not announce its algorithms gets
    // SHA-256; other key types ignore the hash.
    let hash = match handle.best_supported_rsa_hash().await {
        Ok(Some(hash)) => hash,
        _ => Some(HashAlg::Sha256),
    };
    let failed = |e: &dyn std::fmt::Display| t!("ssh.auth_failed", error = e).into_owned();
    // Kept for keyboard-interactive: a server that turned plain password logins
    // off asks for the same password there.
    let password = match &credential {
        Credential::Password(password) => Some(password.clone()),
        _ => None,
    };
    let (auth, what) = match credential {
        Credential::Key(key) => (
            handle
                .authenticate_publickey(
                    &settings.user,
                    PrivateKeyWithHashAlg::new(Arc::new(key), hash),
                )
                .await
                .map_err(|e| failed(&e))?,
            "key",
        ),
        Credential::Password(password) => (
            handle
                .authenticate_password(&settings.user, password)
                .await
                .map_err(|e| failed(&e))?,
            "password",
        ),
        // Every key the agent holds, in its order, as `ssh` does. A server
        // with a low `MaxAuthTries` may hang up before the right one comes.
        Credential::Agent(mut agent) => {
            let identities = agent
                .request_identities()
                .await
                .map_err(|e| t!("ssh.agent_identities_failed", error = e).into_owned())?;
            if identities.is_empty() {
                return Err(t!("ssh.agent_empty").into_owned());
            }
            let mut auth = None;
            for identity in identities {
                let result = handle
                    .authenticate_publickey_with(
                        &settings.user,
                        identity.public_key().into_owned(),
                        hash,
                        &mut agent,
                    )
                    .await
                    .map_err(|e| failed(&e))?;
                // Partial success is a key that was accepted, with a second
                // factor still to come — not a reason to try the next key.
                let done = !matches!(
                    result,
                    AuthResult::Failure {
                        partial_success: false,
                        ..
                    }
                );
                auth = Some(result);
                if done {
                    break;
                }
            }
            (auth.expect("at least one identity was tried"), "agent")
        }
    };
    let (success, what) = if auth.success() {
        (true, what)
    } else if offers_keyboard_interactive(&auth) {
        let ask = |prompt: String, instructions: String, echo: bool| {
            let app = app.clone();
            let settings = settings.clone();
            async move {
                secret::ask_challenge(
                    &app,
                    app.state::<Prompts>().inner(),
                    &settings.host,
                    settings.port,
                    &settings.user,
                    &prompt,
                    &instructions,
                    echo,
                )
                .await
            }
        };
        let done = keyboard_interactive(&mut handle, &settings.user, password.as_deref(), ask)
            .await
            .map_err(|e| failed(&e))?;
        (done, "login")
    } else {
        (false, what)
    };
    if !success {
        // A mistyped password must not stick to the tab: the next attempt asks
        // again instead of failing the same way for as long as it is open.
        if let (SshAuth::Prompt, Some(id)) = (&settings.auth, session_id) {
            app.state::<Cache>().forget(id).await;
        }
        let user = &settings.user;
        return Err(match what {
            "key" => t!("ssh.rejected_key", user = user),
            "password" => t!("ssh.rejected_password", user = user),
            "agent" => t!("ssh.rejected_agent_keys", user = user),
            _ => t!("ssh.rejected_login", user = user),
        }
        .into_owned());
    }
    Ok(handle)
}

/// Whether the server would go on with keyboard-interactive — after a
/// rejected password on a server that only takes it that way, or after an
/// accepted key with a one-time code still to come.
fn offers_keyboard_interactive(auth: &AuthResult) -> bool {
    matches!(
        auth,
        AuthResult::Failure { remaining_methods, .. }
            if remaining_methods.contains(&MethodKind::KeyboardInteractive)
    )
}

/// Whether one of the server's questions is the password. Asked in whatever
/// language PAM speaks on that machine — and not when it is a one-time
/// password, which some OTP modules call exactly that.
fn asks_for_password(prompt: &str) -> bool {
    let prompt = prompt.to_lowercase();
    let one_time = ["one-time", "one time", "einmal", "otp", "code", "token"]
        .iter()
        .any(|word| prompt.contains(word));
    !one_time
        && [
            "password",
            "passwort",
            "kennwort",
            "mot de passe",
            "contraseña",
        ]
        .iter()
        .any(|word| prompt.contains(word))
}

/// The keyboard-interactive exchange: the server asks, we answer, until it
/// says yes or no.
///
/// The connection's password answers the first question that asks for one,
/// without a dialog — that is the server that has `PasswordAuthentication no`
/// and `KbdInteractiveAuthentication yes`, which is most of them. Everything
/// else, a one-time code above all, goes to `ask` — the dialog, with the
/// server's own words: the question, its instructions, and whether the answer
/// may be shown.
async fn keyboard_interactive<H, A, F>(
    handle: &mut Handle<H>,
    user: &str,
    password: Option<&str>,
    mut ask: A,
) -> Result<bool, String>
where
    H: client::Handler,
    A: FnMut(String, String, bool) -> F,
    F: std::future::Future<Output = Result<String, String>>,
{
    let mut password = password;
    let mut reply = handle
        .authenticate_keyboard_interactive_start(user, None)
        .await
        .map_err(|e| e.to_string())?;

    // A server that asks forever is broken; ten rounds cover a password, a
    // code and a changed-password dance with room to spare.
    for _ in 0..10 {
        let (instructions, questions) = match reply {
            KeyboardInteractiveAuthResponse::Success => return Ok(true),
            KeyboardInteractiveAuthResponse::Failure { .. } => return Ok(false),
            KeyboardInteractiveAuthResponse::InfoRequest {
                instructions,
                prompts,
                ..
            } => (instructions, prompts),
        };

        let mut answers = Vec::with_capacity(questions.len());
        for question in questions {
            let answer = match password {
                Some(known) if !question.echo && asks_for_password(&question.prompt) => {
                    password = None;
                    known.to_string()
                }
                _ => ask(question.prompt, instructions.clone(), question.echo).await?,
            };
            answers.push(answer);
        }

        reply = handle
            .authenticate_keyboard_interactive_respond(answers)
            .await
            .map_err(|e| e.to_string())?;
    }
    Err(t!("ssh.kept_asking").into_owned())
}

// ---- What the target is ----------------------------------------------------

/// `os-release` is the standard on every Linux distribution; `uname` covers
/// the BSDs and macOS, which do not have the file. Asked on a channel of its
/// own, so none of it lands in the user's terminal.
const SYSTEM_COMMAND: &str = "cat /etc/os-release 2>/dev/null || uname -sr";

/// Best effort throughout: the badge on the card is a nicety, and a target
/// that answers none of this is still perfectly usable.
async fn read_system(mut channel: Channel<Msg>) -> Option<RemoteSystem> {
    channel.exec(true, SYSTEM_COMMAND).await.ok()?;

    let mut out = Vec::new();
    while let Some(msg) = channel.wait().await {
        match msg {
            ChannelMsg::Data { data } => out.extend_from_slice(&data),
            ChannelMsg::Eof | ChannelMsg::Close => break,
            _ => {}
        }
    }

    let text = String::from_utf8_lossy(&out);
    parse_os_release(&text).or_else(|| parse_uname(&text))
}

/// `KEY=value` lines, values optionally quoted. Anything else is ignored.
fn parse_os_release(text: &str) -> Option<RemoteSystem> {
    let fields: HashMap<&str, &str> = text
        .lines()
        .filter_map(|line| line.split_once('='))
        .map(|(key, value)| {
            (
                key.trim(),
                value.trim().trim_matches(|c| c == '"' || c == '\''),
            )
        })
        .collect();

    // No ID at all means this was not an os-release file.
    let id = fields.get("ID")?.to_lowercase();
    let name = fields.get("NAME").copied().unwrap_or_default().to_string();
    let version = fields
        .get("VERSION_ID")
        .copied()
        .unwrap_or_default()
        .to_string();
    let pretty = fields
        .get("PRETTY_NAME")
        .copied()
        .unwrap_or_default()
        .to_string();

    Some(RemoteSystem {
        name: if name.is_empty() { id.clone() } else { name },
        pretty: if pretty.is_empty() {
            format!("{id} {version}").trim().to_string()
        } else {
            pretty
        },
        id,
        version,
    })
}

/// `uname -sr` prints one line: `Darwin 23.5.0`, `FreeBSD 14.0-RELEASE`.
fn parse_uname(text: &str) -> Option<RemoteSystem> {
    let line = text.lines().map(str::trim).find(|l| !l.is_empty())?;
    let (name, version) = line.split_once(char::is_whitespace).unwrap_or((line, ""));
    Some(RemoteSystem {
        id: name.to_lowercase(),
        name: name.to_string(),
        version: version.trim().to_string(),
        pretty: line.to_string(),
    })
}

/// Hosting products that answer neither `os-release` nor `uname`, told apart by
/// their host name. The restricted shell of a storage box has neither command.
const PROVIDERS: &[(&str, &str, &str)] =
    &[(".your-storagebox.de", "hetzner", "Hetzner Storage Box")];

/// What the card shows, best answer first.
///
/// A known hosting product wins over what its shell says: a restricted shell
/// may answer the question with an error line that reads like a system name.
/// After that the target's own answer, and last the server software it
/// introduced itself with.
fn pick_system(
    host: &str,
    detected: Option<RemoteSystem>,
    software: Option<&str>,
) -> Option<RemoteSystem> {
    let host = host.to_lowercase();
    let provider = PROVIDERS.iter().find(|(suffix, ..)| host.ends_with(suffix));
    if let Some((_, id, name)) = provider {
        return Some(RemoteSystem {
            id: id.to_string(),
            name: name.to_string(),
            version: String::new(),
            pretty: name.to_string(),
        });
    }
    detected.or_else(|| parse_software(software?))
}

/// `SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13` → OpenSSH 9.6p1.
///
/// The comment after the version is free-form, but Debian, Ubuntu and FreeBSD
/// put their own name first; that picks the logo. Without one the id is `ssh`,
/// which draws nothing rather than a penguin for what may not be Linux.
fn parse_software(line: &str) -> Option<RemoteSystem> {
    let rest = line.trim().strip_prefix("SSH-")?;
    let (_protocol, rest) = rest.split_once('-')?;
    let (software, comment) = rest.split_once(' ').unwrap_or((rest, ""));
    let (name, version) = software.split_once('_').unwrap_or((software, ""));
    if name.is_empty() {
        return None;
    }
    let distribution = comment
        .split(['-', ' '])
        .next()
        .unwrap_or("")
        .to_lowercase();
    Some(RemoteSystem {
        id: if distribution.is_empty() {
            "ssh".to_string()
        } else {
            distribution
        },
        name: name.to_string(),
        version: version.to_string(),
        pretty: line.trim().to_string(),
    })
}

/// Logs in with the given settings, asks what the system is, and hangs up.
///
/// Opens no terminal and touches no stored session, so it is safe to run
/// against settings that are still being edited while other tabs are open.
#[tauri::command]
pub async fn ssh_probe(app: AppHandle, settings: SshSettings) -> Result<Probe, String> {
    let started = Instant::now();
    let login = login(&app, &settings, None).await?;
    // Minus whatever the user spent on the host-key question: what is being
    // reported is how quickly the target answers, not how quickly they read.
    let millis = started
        .elapsed()
        .saturating_sub(login.outcome.lock().await.waited)
        .as_millis() as u64;

    let detected = match login.transport.channel_open_session().await {
        Ok(channel) => read_system(channel).await,
        Err(_) => None,
    };
    let software = login.outcome.lock().await.software.clone();
    let system = pick_system(&settings.host, detected, software.as_deref());

    login.hang_up().await;
    Ok(Probe { millis, system })
}

/// Adds a public key to `~/.ssh/authorized_keys` — logged in with
/// `settings`, that is with whatever works so far. Returns whether it is new
/// (`true`) or was already in there.
#[tauri::command]
pub async fn ssh_install_key(
    app: AppHandle,
    settings: SshSettings,
    public_key: String,
) -> Result<bool, String> {
    let command = crate::keys::install_command(&public_key)?;
    let login = login(&app, &settings, None).await?;
    let result = async {
        let mut channel = login
            .transport
            .channel_open_session()
            .await
            .map_err(|e| t!("ssh.no_channel", error = e).into_owned())?;
        channel
            .exec(true, command.as_str())
            .await
            .map_err(|e| t!("ssh.command_not_sent", error = e).into_owned())?;
        let mut out = Vec::new();
        let mut status = None;
        while let Some(msg) = channel.wait().await {
            match msg {
                ChannelMsg::Data { data } | ChannelMsg::ExtendedData { data, .. } => {
                    out.extend_from_slice(&data)
                }
                ChannelMsg::ExitStatus { exit_status } => status = Some(exit_status),
                ChannelMsg::Eof | ChannelMsg::Close => break,
                _ => {}
            }
        }
        let out = String::from_utf8_lossy(&out);
        if out.contains("WIRETERM:ADDED") {
            Ok(true)
        } else if out.contains("WIRETERM:PRESENT") {
            Ok(false)
        } else {
            Err(t!(
                "ssh.key_not_installed",
                status = status.map_or("?".to_string(), |s| s.to_string()),
                output = out.trim()
            )
            .into_owned())
        }
    }
    .await;
    login.hang_up().await;
    result
}

/// What one command left behind — see [`ssh_exec`].
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ExecResult {
    pub stdout: String,
    pub stderr: String,
    /// `None` where the server never said — after a timeout, or when the
    /// command was ended by a signal.
    pub exit_code: Option<u32>,
    pub timed_out: bool,
    /// More came than [`EXEC_LIMIT`]; the rest was dropped.
    pub truncated: bool,
}

/// How much of a command's output is kept, per stream.
const EXEC_LIMIT: usize = 1024 * 1024;

/// Runs one command over its own login, without a terminal, and hands back
/// what it printed. For the MCP server: an agent wants the output as text,
/// not a screen, and a command of its own must not land in somebody's shell.
pub async fn exec(
    app: &AppHandle,
    settings: &SshSettings,
    command: &str,
    timeout: Duration,
) -> Result<ExecResult, String> {
    let login = login(app, settings, None).await?;
    let result = run(&login.transport, command, timeout).await;
    login.hang_up().await;
    result
}

/// The part of [`exec`] after the login — kept apart so a test can run it
/// against a real server, with no window behind it.
async fn run<H: client::Handler>(
    transport: &client::Handle<H>,
    command: &str,
    timeout: Duration,
) -> Result<ExecResult, String> {
    let mut channel = transport
        .channel_open_session()
        .await
        .map_err(|e| t!("ssh.no_channel", error = e).into_owned())?;
    channel
        .exec(true, command)
        .await
        .map_err(|e| t!("ssh.command_not_sent", error = e).into_owned())?;
    let mut result = ExecResult {
        stdout: String::new(),
        stderr: String::new(),
        exit_code: None,
        timed_out: false,
        truncated: false,
    };
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let collect = async {
        while let Some(msg) = channel.wait().await {
            match msg {
                ChannelMsg::Data { data } => keep(&mut out, &data, &mut result.truncated),
                ChannelMsg::ExtendedData { data, .. } => {
                    keep(&mut err, &data, &mut result.truncated)
                }
                ChannelMsg::ExitStatus { exit_status } => result.exit_code = Some(exit_status),
                ChannelMsg::Close => break,
                _ => {}
            }
        }
    };
    if tokio::time::timeout(timeout, collect).await.is_err() {
        result.timed_out = true;
    }
    result.stdout = String::from_utf8_lossy(&out).into_owned();
    result.stderr = String::from_utf8_lossy(&err).into_owned();
    Ok(result)
}

fn keep(into: &mut Vec<u8>, data: &[u8], truncated: &mut bool) {
    let room = EXEC_LIMIT.saturating_sub(into.len());
    if data.len() > room {
        *truncated = true;
    }
    into.extend_from_slice(&data[..data.len().min(room)]);
}

/// [`exec`] for the frontend, which runs it on behalf of an agent once the
/// user has said yes.
#[tauri::command]
pub async fn ssh_exec(
    app: AppHandle,
    settings: SshSettings,
    command: String,
    timeout_seconds: u64,
) -> Result<ExecResult, String> {
    let timeout = Duration::from_secs(timeout_seconds.clamp(1, 3600));
    exec(&app, &settings, &command, timeout).await
}

/// Opens a session and starts streaming its output.
///
/// `cols` and `rows` size the remote pty at start; `ssh_resize` keeps it in
/// step afterwards.
#[tauri::command]
pub async fn ssh_connect(
    app: AppHandle,
    state: State<'_, SshState>,
    transports: State<'_, Transports>,
    session_id: String,
    settings: SshSettings,
    cols: u32,
    rows: u32,
) -> Result<(), String> {
    if state.0.lock().await.contains_key(&session_id) {
        return Err(t!("ssh.already_connected").into_owned());
    }

    // Without the session lock held: the login can take seconds — a vault, a
    // host-key question — and other tabs must stay responsive meanwhile.
    // Already logged in if the file browser got there first, in which case
    // this is only another channel on the connection it opened.
    let handle = transports.get(&app, &session_id, &settings).await?;

    let channel = handle
        .channel_open_session()
        .await
        .map_err(|e| t!("ssh.session_open_failed", error = e).into_owned())?;
    channel
        .request_pty(true, "xterm-256color", cols, rows, 0, 0, &[])
        .await
        .map_err(|e| t!("ssh.pty_failed", error = e).into_owned())?;
    // Before the shell, so it finds `SSH_AUTH_SOCK` already set. A server
    // that forbids it is no reason to be left without a terminal.
    if settings.agent_forwarding {
        let _ = channel.agent_forward(false).await;
    }
    channel
        .request_shell(true)
        .await
        .map_err(|e| t!("ssh.shell_failed", error = e).into_owned())?;

    let (mut read, write) = channel.split();

    // Typed into the shell rather than baked into an exec: a restricted shell
    // like a Storage Box's takes `cd`, but not `cd …; exec $SHELL`.
    if !settings.start_path.is_empty() {
        write
            .data_bytes(cd_command(&settings.start_path).into_bytes())
            .await
            .map_err(|e| t!("ssh.start_path_failed", error = e).into_owned())?;
    }

    let reader_app = app.clone();
    let reader_id = session_id.clone();
    tauri::async_runtime::spawn(async move {
        let data = data_event(&reader_id);
        while let Some(msg) = read.wait().await {
            match msg {
                // Extended data is the remote stderr; a terminal shows both.
                ChannelMsg::Data { data: bytes } | ChannelMsg::ExtendedData { data: bytes, .. } => {
                    if reader_app.emit(&data, &bytes[..]).is_err() {
                        break;
                    }
                }
                ChannelMsg::Eof | ChannelMsg::Close => break,
                _ => {}
            }
        }
        let _ = reader_app.emit(&closed_event(&reader_id), ());
    });

    // Asked on a second channel and off the critical path: the shell is
    // already usable while this runs. See [`pick_system`] for what wins; the
    // shell channel above has already brought the server's identification.
    let software = transports.software(&session_id).await;
    let probe = handle.channel_open_session().await.ok();
    let probe_app = app.clone();
    let probe_id = session_id.clone();
    let host = settings.host.clone();
    tauri::async_runtime::spawn(async move {
        let detected = match probe {
            Some(channel) => read_system(channel).await,
            None => None,
        };
        if let Some(system) = pick_system(&host, detected, software.as_deref()) {
            let _ = probe_app.emit(&system_event(&probe_id), system);
        }
    });

    state
        .0
        .lock()
        .await
        .insert(session_id, Session { channel: write });
    Ok(())
}

/// Forwards keystrokes to the remote shell.
#[tauri::command]
pub async fn ssh_send(
    state: State<'_, SshState>,
    session_id: String,
    data: String,
) -> Result<(), String> {
    let guard = state.0.lock().await;
    let session = guard
        .get(&session_id)
        .ok_or_else(|| t!("ssh.not_connected").into_owned())?;
    session
        .channel
        .data_bytes(data.into_bytes())
        .await
        .map_err(|e| t!("ssh.send_failed", error = e).into_owned())
}

/// Tells the remote pty about a new window size, so line wrapping and
/// full-screen programs keep matching what the user sees.
#[tauri::command]
pub async fn ssh_resize(
    state: State<'_, SshState>,
    session_id: String,
    cols: u32,
    rows: u32,
) -> Result<(), String> {
    let guard = state.0.lock().await;
    // Resizing a tab that is not connected is not worth an error: the terminal
    // is resized by the window, not by the user asking for it.
    let Some(session) = guard.get(&session_id) else {
        return Ok(());
    };
    session
        .channel
        .window_change(cols, rows, 0, 0)
        .await
        .map_err(|e| t!("ssh.resize_failed", error = e).into_owned())
}

/// Ends the shell, leaving the connection itself up.
///
/// The file browser in the same tab may still be using it, and "Reconnect"
/// gets a new shell on the connection that is already there rather
/// than logging in again.
#[tauri::command]
pub async fn ssh_disconnect(state: State<'_, SshState>, session_id: String) -> Result<(), String> {
    let Some(session) = state.0.lock().await.remove(&session_id) else {
        return Ok(());
    };
    let _ = session.channel.eof().await;
    let _ = session.channel.close().await;
    Ok(())
}

/// Closes a tab: shell, file browser and the connection under both.
///
/// The views disconnect themselves as they unmount; this is what actually
/// hangs up, and it is the only place that does.
#[tauri::command]
pub async fn session_close(
    state: State<'_, SshState>,
    sftp_state: State<'_, crate::sftp::SftpState>,
    edits: State<'_, crate::edit::EditWatchers>,
    transports: State<'_, Transports>,
    forwards: State<'_, crate::forward::Forwards>,
    cache: State<'_, Cache>,
    session_id: String,
) -> Result<(), String> {
    if let Some(session) = state.0.lock().await.remove(&session_id) {
        let _ = session.channel.eof().await;
        let _ = session.channel.close().await;
    }
    // Belt and braces alongside `sftp_disconnect`, which the file browser's
    // own teardown already calls as it unmounts: both run on a tab close, and
    // an edit is stopped by whichever gets to it first.
    edits.stop_for_session(&session_id).await;
    sftp_state.close(&session_id).await;
    forwards.stop(&transports, &session_id).await;
    transports.close(&session_id).await;
    // A typed-in password lives exactly as long as the tab it was typed for —
    // and so do those typed for its jump hosts.
    cache.forget(&session_id).await;
    for index in 0..MAX_JUMPS {
        cache.forget(&format!("{session_id}#jump{index}")).await;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Ed25519, passphrase "geheim" — generated for this test only.
    const ENCRYPTED_KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABAmZ23t65
ywIoK9rnVW+uoeAAAAGAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIO6tjHaMd4brL94Y
6vbLHVTQxKTP028pbhwsdXhcNqXdAAAAkMD150gr0gaAMF20qEp3QtLKXMLGwSFaCT3/kS
+4crHhUuPTWJNf4NYtAx5TaFh5jN8NUgxNl2wsKvJFY2t2RsqyXJjqD7jm1IZy//gdayhK
J42lWaWzpu1qWxw4cwNMbWwyiJ11gAizTR8Ypl3g0OzS1SSeLkxAkMS9KDl7mutq8rHJvt
rQJg0mWLjEkHy+xw==
-----END OPENSSH PRIVATE KEY-----
";

    #[test]
    fn an_encrypted_key_requires_the_passphrase() {
        let e = decode_secret_key(ENCRYPTED_KEY, None).expect_err("without passphrase");
        assert!(needs_passphrase(ENCRYPTED_KEY, &e));
        assert!(decode_secret_key(ENCRYPTED_KEY, Some("geheim")).is_ok());
        assert!(decode_secret_key(ENCRYPTED_KEY, Some("falsch")).is_err());

        let ppk = "PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: aes256-cbc\n";
        assert!(needs_passphrase(ppk, &KeyError::CouldNotReadKey));
        let ppk = "PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\n";
        assert!(!needs_passphrase(ppk, &KeyError::CouldNotReadKey));
    }

    #[test]
    fn the_start_path_is_quoted_and_the_tilde_stays_outside() {
        assert_eq!(cd_command("/var/www"), "cd '/var/www'\n");
        assert_eq!(cd_command("~/it's here"), "cd ~/'it'\\''s here'\n");
        assert_eq!(cd_command("~"), "cd ~/''\n");
    }

    #[test]
    fn openssh_names_itself_and_its_distribution() {
        let system = parse_software("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13").expect("recognised");
        assert_eq!(system.id, "ubuntu");
        assert_eq!(system.name, "OpenSSH");
        assert_eq!(system.version, "9.6p1");
    }

    #[test]
    fn without_a_comment_there_is_no_logo() {
        let system = parse_software("SSH-2.0-dropbear_2022.83").expect("recognised");
        assert_eq!(system.id, "ssh");
        assert_eq!(system.name, "dropbear");
        assert!(parse_software("not SSH").is_none());
    }

    /// The Storage Box wins even over what its shell answers.
    #[test]
    fn a_known_provider_comes_first() {
        let shell = parse_uname("Command not found");
        let system = pick_system(
            "U123.your-storagebox.de",
            shell,
            Some("SSH-2.0-OpenSSH_9.6"),
        )
        .expect("recognised");
        assert_eq!(system.id, "hetzner");
        assert_eq!(system.name, "Hetzner Storage Box");

        let fallback = pick_system("web01", None, Some("SSH-2.0-OpenSSH_9.6")).expect("recognised");
        assert_eq!(fallback.name, "OpenSSH");
        assert!(pick_system("web01", None, None).is_none());
    }

    /// PAM asks in the server's language. A one-time code is not a password
    /// and must not be answered with one silently.
    #[test]
    fn the_password_is_recognised_in_every_language_the_code_is_not() {
        assert!(asks_for_password("Password: "));
        assert!(asks_for_password("root@web01's password:"));
        assert!(asks_for_password("Passwort: "));
        assert!(!asks_for_password("Verification code: "));
        assert!(!asks_for_password("One-time password (OATH) for `root':"));
        assert!(!asks_for_password("Einmalpasswort: "));
    }

    /// Go on with keyboard-interactive only if the server offers it.
    #[test]
    fn keyboard_interactive_only_if_the_server_offers_it() {
        let offered = AuthResult::Failure {
            remaining_methods: (&[MethodKind::PublicKey, MethodKind::KeyboardInteractive][..])
                .into(),
            partial_success: true,
        };
        assert!(offers_keyboard_interactive(&offered));

        let key_only = AuthResult::Failure {
            remaining_methods: (&[MethodKind::PublicKey][..]).into(),
            partial_success: false,
        };
        assert!(!offers_keyboard_interactive(&key_only));
        assert!(!offers_keyboard_interactive(&AuthResult::Success));
    }

    // ---- Against a server with a second factor ------------------------------
    //
    // The container from `scripts/ssh-2fa`: passwords only through
    // keyboard-interactive, then a TOTP code from Google Authenticator.
    //
    //   docker build -t wireterm-ssh-2fa scripts/ssh-2fa
    //   docker run -d --rm --name wireterm-ssh-2fa -p 2222:22 wireterm-ssh-2fa
    //   docker cp wireterm-ssh-2fa:/home/anna/.ssh/id_ed25519 <file>
    //   WIRETERM_SSH_2FA_KEY=<file> cargo test --lib ssh::tests::two_factor -- --ignored
    //
    // `WIRETERM_SSH_2FA` points at a `host:port` other than `localhost:2222`.

    /// Does not ask about the host key — the container is a different one on
    /// every build, and the check is not what this is about.
    struct Blind;

    impl client::Handler for Blind {
        type Error = russh::Error;

        async fn check_server_key(
            &mut self,
            _: &PublicKeyOrCertificate,
        ) -> Result<bool, Self::Error> {
            Ok(true)
        }
    }

    fn two_factor(test: impl std::future::Future<Output = ()>) {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(test);
    }

    async fn to_server() -> Handle<Blind> {
        let target =
            std::env::var("WIRETERM_SSH_2FA").unwrap_or_else(|_| "localhost:2222".to_string());
        let (host, port) = target.rsplit_once(':').expect("host:port");
        let port: u16 = port.parse().expect("a port");
        client::connect(Arc::new(client::Config::default()), (host, port), Blind)
            .await
            .expect("the container from scripts/ssh-2fa is running")
    }

    /// The code Google Authenticator is showing right now — RFC 6238 with the
    /// secret `JBSWY3DPEHPK3PXP` from the Dockerfile.
    fn totp() -> String {
        use ring::hmac;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("after 1970")
            .as_secs();
        let key = hmac::Key::new(
            hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
            b"Hello!\xde\xad\xbe\xef",
        );
        let tag = hmac::sign(&key, &(now / 30).to_be_bytes());
        let h = tag.as_ref();
        let at = (h[19] & 0x0f) as usize;
        let code = u32::from_be_bytes([h[at] & 0x7f, h[at + 1], h[at + 2], h[at + 3]]) % 1_000_000;
        format!("{code:06}")
    }

    /// The server takes no password directly, only through
    /// keyboard-interactive — and wants a code after that. The password goes
    /// without asking, the code is asked for, and exactly once.
    #[test]
    #[ignore]
    fn two_factor_password_then_code() {
        two_factor(async {
            let mut handle = to_server().await;
            let direct = handle
                .authenticate_password("anna", "geheim")
                .await
                .expect("answers");
            assert!(!direct.success(), "direct passwords are switched off");
            assert!(offers_keyboard_interactive(&direct));

            let mut asked = Vec::new();
            let ok = keyboard_interactive(&mut handle, "anna", Some("geheim"), |question, _, _| {
                asked.push(question);
                async { Ok(totp()) }
            })
            .await
            .expect("the exchange runs through");

            assert!(ok, "password and code open the door");
            assert_eq!(asked.len(), 1, "only the code is asked for: {asked:?}");
            assert!(asked[0].to_lowercase().contains("code"), "{asked:?}");
        });
    }

    /// Key first: the server accepts it as a partial success and then still
    /// wants keyboard-interactive. With no password in the connection, both
    /// questions go to the dialog.
    #[test]
    #[ignore]
    fn two_factor_key_then_code() {
        two_factor(async {
            let file = std::env::var("WIRETERM_SSH_2FA_KEY")
                .expect("WIRETERM_SSH_2FA_KEY points at the key from the container");
            let pem = std::fs::read_to_string(&file).expect("read the key");
            let key = decode_secret_key(&pem, None).expect("key without passphrase");

            let mut handle = to_server().await;
            let first = handle
                .authenticate_publickey("anna", PrivateKeyWithHashAlg::new(Arc::new(key), None))
                .await
                .expect("answers");
            assert!(
                matches!(
                    first,
                    AuthResult::Failure {
                        partial_success: true,
                        ..
                    }
                ),
                "the key is accepted, something is still missing: {first:?}"
            );
            assert!(offers_keyboard_interactive(&first));

            let mut asked = Vec::new();
            let ok = keyboard_interactive(&mut handle, "anna", None, |question: String, _, _| {
                let answer = if asks_for_password(&question) {
                    "geheim".to_string()
                } else {
                    totp()
                };
                asked.push(question);
                async move { Ok(answer) }
            })
            .await
            .expect("the exchange runs through");

            assert!(ok, "key, password and code open the door");
            assert_eq!(asked.len(), 2, "password and code: {asked:?}");
        });
    }

    /// A wrong code is a no, not an error — and not a hang.
    #[test]
    #[ignore]
    fn two_factor_wrong_code() {
        two_factor(async {
            let mut handle = to_server().await;
            let direct = handle
                .authenticate_password("anna", "geheim")
                .await
                .expect("answers");
            assert!(offers_keyboard_interactive(&direct));

            let real = totp();
            let wrong = if real == "123456" { "654321" } else { "123456" };
            let ok = keyboard_interactive(&mut handle, "anna", Some("geheim"), |_, _, _| async {
                Ok(wrong.to_string())
            })
            .await
            .expect("the exchange runs through");

            assert!(!ok, "with a wrong code the door stays shut");
        });
    }

    // ---- Through a jump host -------------------------------------------------
    //
    // The containers from `scripts/ssh-jump`: `bastion` on port 2223, `ziel`
    // reachable only inside the Docker network — so only through `bastion`.
    // The setup is in the Dockerfile. `WIRETERM_SSH_JUMP` points at another
    // `host:port`.

    fn run_async(test: impl std::future::Future<Output = ()>) {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(test);
    }

    async fn to_bastion<H: client::Handler + Send + 'static>(handler: H) -> Handle<H> {
        let target =
            std::env::var("WIRETERM_SSH_JUMP").unwrap_or_else(|_| "localhost:2223".to_string());
        let (host, port) = target.rsplit_once(':').expect("host:port");
        let port: u16 = port.parse().expect("a port");
        let mut handle =
            client::connect(Arc::new(client::Config::default()), (host, port), handler)
                .await
                .expect("the jump host from scripts/ssh-jump is running");
        let ok = handle
            .authenticate_password("anna", "geheim")
            .await
            .expect("answers");
        assert!(ok.success(), "logged in to the jump host");
        handle
    }

    /// Runs `command` and returns what came of it.
    async fn execute<H: client::Handler>(handle: &Handle<H>, command: &str, agent: bool) -> String {
        let mut channel = handle.channel_open_session().await.expect("channel");
        if agent {
            channel
                .agent_forward(true)
                .await
                .expect("forward the agent");
        }
        channel.exec(true, command).await.expect("execute");
        let mut out = Vec::new();
        while let Some(msg) = channel.wait().await {
            match msg {
                ChannelMsg::Data { data } | ChannelMsg::ExtendedData { data, .. } => {
                    out.extend_from_slice(&data)
                }
                ChannelMsg::Eof | ChannelMsg::Close => break,
                _ => {}
            }
        }
        String::from_utf8_lossy(&out).into_owned()
    }

    /// A new key is added, recognised the second time — and then logs in
    /// with it.
    #[test]
    #[ignore]
    fn jump_a_key_is_installed() {
        run_async(async {
            let new = crate::keys::generate("ed25519", "wireterm-test").expect("generated");
            let command = crate::keys::install_command(&new.public).expect("builds");
            let handle = to_bastion(Blind).await;
            assert!(execute(&handle, &command, false)
                .await
                .contains("WIRETERM:ADDED"));
            assert!(execute(&handle, &command, false)
                .await
                .contains("WIRETERM:PRESENT"));
            let lines = execute(&handle, "grep -c . ~/.ssh/authorized_keys", false).await;
            let _ = handle.disconnect(Disconnect::ByApplication, "", "en").await;

            let target =
                std::env::var("WIRETERM_SSH_JUMP").unwrap_or_else(|_| "localhost:2223".to_string());
            let (host, port) = target.rsplit_once(':').expect("host:port");
            let mut handle = client::connect(
                Arc::new(client::Config::default()),
                (host, port.parse::<u16>().expect("port")),
                Blind,
            )
            .await
            .expect("connects");
            let key = decode_secret_key(&new.private, None).expect("key");
            let ok = handle
                .authenticate_publickey("anna", PrivateKeyWithHashAlg::new(Arc::new(key), None))
                .await
                .expect("answers");
            assert!(ok.success(), "logged in with the new key ({lines} lines)");
        });
    }

    /// What `run_command` gets over MCP: output, error output, status — and
    /// for a command that does not end, the deadline.
    #[test]
    #[ignore]
    fn jump_a_command_returns_output_and_status() {
        run_async(async {
            let handle = to_bastion(Blind).await;
            let done = run(
                &handle,
                "echo hello; echo broken >&2; exit 3",
                Duration::from_secs(20),
            )
            .await
            .expect("runs");
            assert_eq!(done.stdout.trim(), "hello");
            assert_eq!(done.stderr.trim(), "broken");
            assert_eq!(done.exit_code, Some(3));
            assert!(!done.timed_out && !done.truncated);

            let hangs = run(&handle, "sleep 30", Duration::from_secs(2))
                .await
                .expect("runs");
            assert!(hangs.timed_out);
            assert_eq!(hangs.exit_code, None);
            let _ = handle.disconnect(Disconnect::ByApplication, "", "en").await;
        });
    }

    /// The target cannot be reached from here at all — only through the
    /// tunnel.
    #[test]
    #[ignore]
    fn jump_host_reaches_the_target() {
        run_async(async {
            let bastion = to_bastion(Blind).await;
            let tunnel = open_tunnel(&bastion, "ziel", 22).await.expect("tunnel");
            let mut target =
                client::connect_stream(Arc::new(client::Config::default()), tunnel, Blind)
                    .await
                    .expect("SSH through the tunnel");
            let ok = target
                .authenticate_password("anna", "geheim")
                .await
                .expect("answers");
            assert!(ok.success(), "logged in to the target");
            assert_eq!(execute(&target, "hostname", false).await.trim(), "ziel");
        });
    }

    /// Accepts forwarded agent channels and connects them — through
    /// [`bridge`], as in the app — to an agent without keys.
    struct WithAgent;

    impl client::Handler for WithAgent {
        type Error = russh::Error;

        async fn check_server_key(
            &mut self,
            _: &PublicKeyOrCertificate,
        ) -> Result<bool, Self::Error> {
            Ok(true)
        }

        async fn server_channel_open_agent_forward(
            &mut self,
            channel: Channel<Msg>,
            reply: client::ChannelOpenHandle,
            _session: &mut client::Session,
        ) -> Result<(), Self::Error> {
            reply.accept().await;
            let (here, there) = tokio::io::duplex(1024);
            tokio::spawn(empty_agent(there));
            tokio::spawn(async move {
                let _ = bridge(channel, here).await;
            });
            Ok(())
        }
    }

    /// An agent without keys: "which keys?" — "none". It refuses everything
    /// else. Enough to see whether the server reaches it.
    async fn empty_agent(mut stream: tokio::io::DuplexStream) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        loop {
            let mut len = [0u8; 4];
            if stream.read_exact(&mut len).await.is_err() {
                return;
            }
            let mut msg = vec![0u8; u32::from_be_bytes(len) as usize];
            if stream.read_exact(&mut msg).await.is_err() {
                return;
            }
            // 11 = REQUEST_IDENTITIES → 12 = IDENTITIES_ANSWER with zero
            // keys; otherwise 5 = FAILURE.
            let answer: &[u8] = if msg.first() == Some(&11) {
                &[0, 0, 0, 5, 12, 0, 0, 0, 0]
            } else {
                &[0, 0, 0, 1, 5]
            };
            if stream.write_all(answer).await.is_err() {
                return;
            }
        }
    }

    /// `ssh-add -l` on the server: 1 means "agent there, but empty" — that
    /// is, our agent —, 2 means "no agent".
    #[test]
    #[ignore]
    fn jump_agent_forwarding_arrives_on_the_server() {
        run_async(async {
            let with_agent = to_bastion(WithAgent).await;
            let with = execute(&with_agent, "ssh-add -l; echo rc=$?", true).await;
            assert!(with.contains("rc=1"), "the forwarded agent answers: {with}");
            // A connection of its own: sshd makes an agent forwarded once
            // available to the whole connection, not just the one channel.
            let without_agent = to_bastion(Blind).await;
            let without = execute(&without_agent, "ssh-add -l; echo rc=$?", false).await;
            assert!(
                without.contains("rc=2"),
                "without forwarding there is none: {without}"
            );
        });
    }
}
