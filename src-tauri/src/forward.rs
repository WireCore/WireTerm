//! Port forwardings over a tab's SSH connection — `ssh -L`, `-R`, `-D`.
//!
//! The rules belong to the connection ([`Forward`]) and start once the tab's
//! terminal is connected; they end with the tab. All three run over the same
//! logged-in connection that terminal and file browser already share — and
//! therefore through its jump hosts as well.
//!
//! - **local**: listening happens here, and each connection goes to the
//!   target as `direct-tcpip`, the way the server sees it.
//! - **dynamic**: a SOCKS5 proxy listens here; each connection names its
//!   target itself.
//! - **remote**: the server listens (`tcpip-forward`) and opens a channel
//!   back for each connection, which is connected to the target here — see
//!   [`serve_forwarded`].
//!
//! Without an address given, listening happens on `127.0.0.1` only. A port
//! open to the whole network should be a decision, not an accident.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex as SyncMutex};

use russh::client::{self, Handle, Msg};
use russh::Channel;
use rust_i18n::t;
use serde::Serialize;
use tauri::{AppHandle, State};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

use crate::ssh::{bridge, Transports};
use crate::storage::{Forward, ForwardKind, SshSettings};

/// For remote forwardings: which port on the server leads to which target
/// here. The connection's handler looks it up when the server opens a
/// channel.
pub type RemoteTargets = Arc<SyncMutex<HashMap<u32, (String, u16)>>>;

/// What the UI needs to know about a rule.
#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    pub kind: ForwardKind,
    /// `L 127.0.0.1:8080 → db:5432` — the way `ssh` would write it.
    pub label: String,
    pub active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// The port actually being listened on — for 0, the one the system
    /// picked.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// How many connections are running through right now.
    pub connections: usize,
}

pub struct Running {
    status: Arc<SyncMutex<Status>>,
    task: Option<JoinHandle<()>>,
    /// For a remote one: address and port on the server, for cancelling it.
    remote: Option<(String, u32)>,
}

impl Running {
    fn status(&self) -> Status {
        self.status
            .lock()
            .map(|s| s.clone())
            .unwrap_or_else(|e| e.into_inner().clone())
    }
}

fn bind_host(forward: &Forward) -> &str {
    if forward.bind_host.trim().is_empty() {
        "127.0.0.1"
    } else {
        forward.bind_host.trim()
    }
}

pub fn label(forward: &Forward) -> String {
    match forward.kind {
        ForwardKind::Local => format!(
            "L {}:{} → {}:{}",
            bind_host(forward),
            forward.bind_port,
            forward.target_host,
            forward.target_port
        ),
        ForwardKind::Remote => format!(
            "R {}:{} → {}:{}",
            bind_host(forward),
            forward.bind_port,
            forward.target_host,
            forward.target_port
        ),
        ForwardKind::Dynamic => format!("D {}:{} (SOCKS5)", bind_host(forward), forward.bind_port),
    }
}

fn status_of(forward: &Forward) -> Arc<SyncMutex<Status>> {
    Arc::new(SyncMutex::new(Status {
        kind: forward.kind,
        label: label(forward),
        active: false,
        error: None,
        port: None,
        connections: 0,
    }))
}

fn set(status: &Arc<SyncMutex<Status>>, change: impl FnOnce(&mut Status)) {
    if let Ok(mut status) = status.lock() {
        change(&mut status);
    }
}

/// Counts a connection for as long as it runs.
struct Counted(Arc<SyncMutex<Status>>);

impl Counted {
    fn new(status: &Arc<SyncMutex<Status>>) -> Self {
        set(status, |s| s.connections += 1);
        Self(Arc::clone(status))
    }
}

impl Drop for Counted {
    fn drop(&mut self) {
        set(&self.0, |s| s.connections = s.connections.saturating_sub(1));
    }
}

/// Starts a rule. Whatever goes wrong — a port in use, a server that allows
/// no forwarding — ends up in the status afterwards, not as an error: the
/// other rules run regardless.
pub async fn start<H>(handle: Arc<Handle<H>>, targets: &RemoteTargets, forward: &Forward) -> Running
where
    H: client::Handler + Send + 'static,
{
    let status = status_of(forward);
    match forward.kind {
        ForwardKind::Local | ForwardKind::Dynamic => {
            let listener = match TcpListener::bind((bind_host(forward), forward.bind_port)).await {
                Ok(listener) => listener,
                Err(e) => {
                    set(&status, |s| {
                        s.error = Some(t!("ssh.forward_port_busy", error = e).into_owned())
                    });
                    return Running {
                        status,
                        task: None,
                        remote: None,
                    };
                }
            };
            let port = listener.local_addr().map(|a| a.port()).ok();
            set(&status, |s| {
                s.active = true;
                s.port = port;
            });
            let task = tokio::spawn(accept(
                listener,
                handle,
                forward.clone(),
                Arc::clone(&status),
            ));
            Running {
                status,
                task: Some(task),
                remote: None,
            }
        }
        ForwardKind::Remote => {
            let address = bind_host(forward).to_string();
            match handle
                .tcpip_forward(address.clone(), u32::from(forward.bind_port))
                .await
            {
                Ok(allocated) => {
                    // The server only names the port if it picked it
                    // itself.
                    let bound = if forward.bind_port == 0 {
                        allocated
                    } else {
                        u32::from(forward.bind_port)
                    };
                    if let Ok(mut map) = targets.lock() {
                        map.insert(bound, (forward.target_host.clone(), forward.target_port));
                    }
                    set(&status, |s| {
                        s.active = true;
                        s.port = u16::try_from(bound).ok();
                    });
                    Running {
                        status,
                        task: None,
                        remote: Some((address, bound)),
                    }
                }
                Err(e) => {
                    set(&status, |s| {
                        s.error = Some(t!("ssh.forward_refused", error = e).into_owned())
                    });
                    Running {
                        status,
                        task: None,
                        remote: None,
                    }
                }
            }
        }
    }
}

async fn accept<H>(
    listener: TcpListener,
    handle: Arc<Handle<H>>,
    forward: Forward,
    status: Arc<SyncMutex<Status>>,
) where
    H: client::Handler + Send + 'static,
{
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(e) => {
                set(&status, |s| {
                    s.active = false;
                    s.error = Some(e.to_string());
                });
                return;
            }
        };
        let handle = Arc::clone(&handle);
        let forward = forward.clone();
        let counted = Counted::new(&status);
        tokio::spawn(async move {
            let _counted = counted;
            let _ = match forward.kind {
                ForwardKind::Dynamic => socks(stream, peer, &handle).await,
                _ => {
                    tunnel(
                        stream,
                        peer,
                        &handle,
                        &forward.target_host,
                        forward.target_port,
                    )
                    .await
                }
            };
        });
    }
}

async fn tunnel<H: client::Handler>(
    stream: TcpStream,
    peer: SocketAddr,
    handle: &Handle<H>,
    host: &str,
    port: u16,
) -> Result<(), String> {
    let channel = handle
        .channel_open_direct_tcpip(
            host.to_string(),
            u32::from(port),
            peer.ip().to_string(),
            u32::from(peer.port()),
        )
        .await
        .map_err(|e| e.to_string())?;
    bridge(channel, stream).await.map_err(|e| e.to_string())
}

// ---- SOCKS5 ------------------------------------------------------------------
//
// Only what a browser or `curl --socks5-hostname` needs: no authentication,
// CONNECT only. The name is resolved on the server, not here — that is the
// point of a proxy on the other side.

async fn socks<H: client::Handler>(
    mut stream: TcpStream,
    peer: SocketAddr,
    handle: &Handle<H>,
) -> Result<(), String> {
    let (host, port) = socks_request(&mut stream).await?;
    match handle
        .channel_open_direct_tcpip(
            host,
            u32::from(port),
            peer.ip().to_string(),
            u32::from(peer.port()),
        )
        .await
    {
        Ok(channel) => {
            stream
                .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
                .await
                .map_err(|e| e.to_string())?;
            bridge(channel, stream).await.map_err(|e| e.to_string())
        }
        Err(e) => {
            // 5 = connection refused.
            let _ = stream.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]).await;
            Err(e.to_string())
        }
    }
}

/// Reads the greeting and CONNECT and returns where to go.
async fn socks_request<S>(stream: &mut S) -> Result<(String, u16), String>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let io = |e: std::io::Error| e.to_string();
    let mut head = [0u8; 2];
    stream.read_exact(&mut head).await.map_err(io)?;
    if head[0] != 5 {
        return Err("not SOCKS5".to_string());
    }
    let mut methods = vec![0u8; head[1] as usize];
    stream.read_exact(&mut methods).await.map_err(io)?;
    if !methods.contains(&0) {
        let _ = stream.write_all(&[5, 0xff]).await;
        return Err("the client wants to authenticate; this proxy cannot do that".to_string());
    }
    stream.write_all(&[5, 0]).await.map_err(io)?;

    let mut request = [0u8; 4];
    stream.read_exact(&mut request).await.map_err(io)?;
    if request[1] != 1 {
        // 7 = command not supported.
        let _ = stream.write_all(&[5, 7, 0, 1, 0, 0, 0, 0, 0, 0]).await;
        return Err("CONNECT only".to_string());
    }
    let host = match request[3] {
        1 => {
            let mut ip = [0u8; 4];
            stream.read_exact(&mut ip).await.map_err(io)?;
            std::net::Ipv4Addr::from(ip).to_string()
        }
        3 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await.map_err(io)?;
            let mut name = vec![0u8; len[0] as usize];
            stream.read_exact(&mut name).await.map_err(io)?;
            String::from_utf8(name).map_err(|_| "the name is not text".to_string())?
        }
        4 => {
            let mut ip = [0u8; 16];
            stream.read_exact(&mut ip).await.map_err(io)?;
            std::net::Ipv6Addr::from(ip).to_string()
        }
        _ => return Err("unknown address type".to_string()),
    };
    let mut port = [0u8; 2];
    stream.read_exact(&mut port).await.map_err(io)?;
    Ok((host, u16::from_be_bytes(port)))
}

// ---- Remote ------------------------------------------------------------------

/// A channel the server opened for a remote forwarding: connect it to the
/// target here that belongs to its port.
pub async fn serve_forwarded(targets: &RemoteTargets, channel: Channel<Msg>, connected_port: u32) {
    let target = targets
        .lock()
        .ok()
        .and_then(|map| map.get(&connected_port).cloned());
    let Some((host, port)) = target else {
        return;
    };
    if let Ok(stream) = TcpStream::connect((host.as_str(), port)).await {
        let _ = bridge(channel, stream).await;
    }
}

/// Whether a channel opened by the server belongs to one of our forwardings.
pub fn expects(targets: &RemoteTargets, connected_port: u32) -> bool {
    targets
        .lock()
        .map(|map| map.contains_key(&connected_port))
        .unwrap_or(false)
}

// ---- Per tab -----------------------------------------------------------------

#[derive(Default)]
pub struct Forwards(Mutex<HashMap<String, Vec<Running>>>);

impl Forwards {
    /// Stops all of a tab's forwardings.
    pub async fn stop(&self, transports: &Transports, session_id: &str) {
        let Some(running) = self.0.lock().await.remove(session_id) else {
            return;
        };
        let handle = transports.current(session_id).await;
        let targets = transports.remote_targets(session_id).await;
        for forward in running {
            if let Some(task) = forward.task {
                task.abort();
            }
            if let Some((address, port)) = forward.remote {
                if let Some(targets) = &targets {
                    if let Ok(mut map) = targets.lock() {
                        map.remove(&port);
                    }
                }
                if let Some(handle) = &handle {
                    let _ = handle.cancel_tcpip_forward(address, port).await;
                }
            }
        }
    }
}

/// Starts the connection's forwardings — once the tab's terminal is
/// connected, over the same login. Whatever was already running is stopped
/// first.
#[tauri::command]
pub async fn ssh_forwards_start(
    app: AppHandle,
    transports: State<'_, Transports>,
    forwards: State<'_, Forwards>,
    session_id: String,
    settings: SshSettings,
) -> Result<Vec<Status>, String> {
    forwards.stop(&transports, &session_id).await;
    if settings.forwards.is_empty() {
        return Ok(Vec::new());
    }
    let handle = transports.get(&app, &session_id, &settings).await?;
    let targets = transports
        .remote_targets(&session_id)
        .await
        .ok_or_else(|| t!("ssh.tab_not_connected").into_owned())?;
    let mut running = Vec::new();
    for forward in &settings.forwards {
        running.push(start(Arc::clone(&handle), &targets, forward).await);
    }
    let statuses = running.iter().map(Running::status).collect();
    forwards.0.lock().await.insert(session_id, running);
    Ok(statuses)
}

#[tauri::command]
pub async fn ssh_forwards_status(
    forwards: State<'_, Forwards>,
    session_id: String,
) -> Result<Vec<Status>, String> {
    Ok(forwards
        .0
        .lock()
        .await
        .get(&session_id)
        .map(|running| running.iter().map(Running::status).collect())
        .unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(kind: ForwardKind) -> Forward {
        Forward {
            kind,
            bind_host: String::new(),
            bind_port: 8080,
            target_host: "db".into(),
            target_port: 5432,
        }
    }

    #[test]
    fn the_rule_reads_like_in_ssh() {
        assert_eq!(
            label(&rule(ForwardKind::Local)),
            "L 127.0.0.1:8080 → db:5432"
        );
        assert_eq!(
            label(&rule(ForwardKind::Remote)),
            "R 127.0.0.1:8080 → db:5432"
        );
        assert_eq!(
            label(&rule(ForwardKind::Dynamic)),
            "D 127.0.0.1:8080 (SOCKS5)"
        );
    }

    /// What `curl --socks5-hostname` sends: a greeting without
    /// authentication, then CONNECT with a name.
    #[test]
    fn socks5_understands_a_name() {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(async {
                let (mut client, mut server) = tokio::io::duplex(256);
                let mut request = vec![5, 1, 0, 5, 1, 0, 3, 4];
                request.extend_from_slice(b"ziel");
                request.extend_from_slice(&22u16.to_be_bytes());
                client.write_all(&request).await.expect("write");
                let (host, port) = socks_request(&mut server).await.expect("understood");
                assert_eq!((host.as_str(), port), ("ziel", 22));
                let mut answer = [0u8; 2];
                client.read_exact(&mut answer).await.expect("answer");
                assert_eq!(answer, [5, 0], "accepted without authentication");
            });
    }

    #[test]
    fn socks5_refuses_anything_but_connect() {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(async {
                let (mut client, mut server) = tokio::io::duplex(256);
                // BIND (2) instead of CONNECT.
                client
                    .write_all(&[5, 1, 0, 5, 2, 0, 1, 127, 0, 0, 1, 0, 22])
                    .await
                    .expect("write");
                assert!(socks_request(&mut server).await.is_err());
            });
    }

    // ---- Against the containers from scripts/ssh-jump ------------------------
    //
    // `bastion` on port 2223, `ziel` only inside the Docker network. Setup in
    // the Dockerfile; `cargo test --lib forward::tests::forwarding -- --ignored`.

    use russh::keys::PublicKeyOrCertificate;

    /// Does not ask about the host key and accepts remote forwardings —
    /// through the same functions as the app's handler.
    struct TestCase {
        targets: RemoteTargets,
    }

    impl client::Handler for TestCase {
        type Error = russh::Error;

        async fn check_server_key(
            &mut self,
            _: &PublicKeyOrCertificate,
        ) -> Result<bool, Self::Error> {
            Ok(true)
        }

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
            if !expects(&self.targets, connected_port) {
                reply
                    .reject(russh::ChannelOpenFailure::AdministrativelyProhibited)
                    .await;
                return Ok(());
            }
            reply.accept().await;
            let targets = Arc::clone(&self.targets);
            tokio::spawn(async move { serve_forwarded(&targets, channel, connected_port).await });
            Ok(())
        }
    }

    fn run(test: impl std::future::Future<Output = ()>) {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(test);
    }

    async fn to_bastion(targets: &RemoteTargets) -> Arc<Handle<TestCase>> {
        let target =
            std::env::var("WIRETERM_SSH_JUMP").unwrap_or_else(|_| "localhost:2223".to_string());
        let (host, port) = target.rsplit_once(':').expect("host:port");
        let port: u16 = port.parse().expect("a port");
        let handler = TestCase {
            targets: Arc::clone(targets),
        };
        let mut handle =
            client::connect(Arc::new(client::Config::default()), (host, port), handler)
                .await
                .expect("the jump host from scripts/ssh-jump is running");
        assert!(handle
            .authenticate_password("anna", "geheim")
            .await
            .expect("answers")
            .success());
        Arc::new(handle)
    }

    async fn banner(stream: &mut TcpStream) -> String {
        let mut buffer = [0u8; 64];
        let read =
            tokio::time::timeout(std::time::Duration::from_secs(5), stream.read(&mut buffer))
                .await
                .expect("in time")
                .expect("read");
        String::from_utf8_lossy(&buffer[..read]).into_owned()
    }

    fn target_rule(kind: ForwardKind, target_host: &str, target_port: u16) -> Forward {
        Forward {
            kind,
            bind_host: String::new(),
            bind_port: 0,
            target_host: target_host.into(),
            target_port,
        }
    }

    /// `-L`: a port here, and behind it the SSH service of `ziel` — which
    /// cannot be reached from here at all.
    #[test]
    #[ignore]
    fn forwarding_local() {
        run(async {
            let targets = RemoteTargets::default();
            let bastion = to_bastion(&targets).await;
            let running = start(
                bastion,
                &targets,
                &target_rule(ForwardKind::Local, "ziel", 22),
            )
            .await;
            let status = running.status();
            assert!(status.active, "{status:?}");
            let mut stream = TcpStream::connect(("127.0.0.1", status.port.expect("port")))
                .await
                .expect("connect");
            assert!(banner(&mut stream).await.starts_with("SSH-2.0-OpenSSH"));
        });
    }

    /// `-D`: SOCKS5 with a name only the server can resolve.
    #[test]
    #[ignore]
    fn forwarding_dynamic() {
        run(async {
            let targets = RemoteTargets::default();
            let bastion = to_bastion(&targets).await;
            let running = start(bastion, &targets, &target_rule(ForwardKind::Dynamic, "", 0)).await;
            let port = running.status().port.expect("port");
            let mut stream = TcpStream::connect(("127.0.0.1", port))
                .await
                .expect("connect");
            let mut request = vec![5, 1, 0, 5, 1, 0, 3, 4];
            request.extend_from_slice(b"ziel");
            request.extend_from_slice(&22u16.to_be_bytes());
            stream.write_all(&request).await.expect("write");
            let mut answer = [0u8; 12];
            stream.read_exact(&mut answer).await.expect("answer");
            assert_eq!(&answer[..2], &[5, 0], "greeting accepted");
            assert_eq!(&answer[2..4], &[5, 0], "CONNECT succeeded");
            assert!(banner(&mut stream).await.starts_with("SSH-2.0-OpenSSH"));
        });
    }

    /// `-R`: a port on the server, and behind it an echo service here.
    #[test]
    #[ignore]
    fn forwarding_remote() {
        run(async {
            let echo = TcpListener::bind(("127.0.0.1", 0)).await.expect("echo");
            let echo_port = echo.local_addr().expect("address").port();
            tokio::spawn(async move {
                while let Ok((mut stream, _)) = echo.accept().await {
                    tokio::spawn(async move {
                        let (mut read, mut write) = stream.split();
                        let _ = tokio::io::copy(&mut read, &mut write).await;
                    });
                }
            });

            let targets = RemoteTargets::default();
            let bastion = to_bastion(&targets).await;
            let running = start(
                Arc::clone(&bastion),
                &targets,
                &target_rule(ForwardKind::Remote, "127.0.0.1", echo_port),
            )
            .await;
            let status = running.status();
            assert!(status.active, "{status:?}");
            let port = status.port.expect("port on the server");

            let mut channel = bastion.channel_open_session().await.expect("channel");
            let command = format!(
                "exec 3<>/dev/tcp/127.0.0.1/{port}; echo hello >&3; read -t 5 line <&3; echo \"$line\""
            );
            channel.exec(true, command).await.expect("execute");
            let mut out = Vec::new();
            while let Some(msg) = channel.wait().await {
                match msg {
                    russh::ChannelMsg::Data { data } => out.extend_from_slice(&data),
                    russh::ChannelMsg::Eof | russh::ChannelMsg::Close => break,
                    _ => {}
                }
            }
            assert_eq!(String::from_utf8_lossy(&out).trim(), "hello");
        });
    }
}
