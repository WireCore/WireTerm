//! The MCP server: Claude and other agents talk to WireTerm through the
//! Model Context Protocol.
//!
//! An HTTP endpoint on `127.0.0.1` ("Streamable HTTP", only the POST half:
//! every request gets its answer as JSON, there is no stream from the
//! server). Whoever wants to use it needs the token from the settings as
//! `Authorization: Bearer …` — without it the server answers only with 401,
//! even to another program on this machine.
//!
//! Only the protocol lives here. What a tool *does* is decided by the
//! window: that is where the connections, the open terminals and the dialog
//! that asks before every writing call are. A call therefore goes to the
//! front as `mcp:call` and comes back through [`mcp_answer`].
//!
//! Secrets never leave the app this way: no tool hands out a password, a key
//! or a vault reference.

use std::collections::HashMap;
use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{header, Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use rust_i18n::t;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tauri::{AppHandle, Emitter, Manager, State};
use tokio::net::TcpListener;
use tokio::sync::{oneshot, Mutex};

use crate::local_secrets::{self, LocalVault};

const FILE: &str = "mcp.json";
const AAD: &str = "wireterm/mcp/token";
pub const DEFAULT_PORT: u16 = 47_821;
const CALL_EVENT: &str = "mcp:call";

/// The protocol versions this server speaks, the newest first.
const PROTOCOL_VERSIONS: &[&str] = &["2025-06-18", "2025-03-26"];

/// How long a call waits for the window — the confirmation included, and
/// whoever is not at the machine right now does not answer in seconds.
const CALL_TIMEOUT: Duration = Duration::from_secs(10 * 60);

/// No reasonable request to these tools is larger.
const MAX_BODY: usize = 1024 * 1024;

// ---- Tools ---------------------------------------------------------------------

/// What an agent can call here. `readOnlyHint` is set on everything that runs
/// without asking; the rest waits for a confirmation in the window.
fn tools() -> Value {
    let id = |what: &str| json!({ "type": "string", "description": what });
    json!([
        {
            "name": "list_connections",
            "title": "List connections",
            "description": "Lists the saved connections (SSH, FTP, S3) in all workspaces: id, name, type, host, port, user, workspace and project. Never includes passwords or keys.",
            "inputSchema": { "type": "object", "properties": {} },
            "annotations": { "readOnlyHint": true, "openWorldHint": false }
        },
        {
            "name": "list_snippets",
            "title": "List snippets",
            "description": "Lists the saved command snippets of all workspaces. Placeholders like {{connection.host}} are filled in when a snippet is sent to a terminal.",
            "inputSchema": { "type": "object", "properties": {} },
            "annotations": { "readOnlyHint": true, "openWorldHint": false }
        },
        {
            "name": "list_terminals",
            "title": "List open terminals",
            "description": "Lists the terminals currently open in WireTerm (SSH sessions and local shells) with their sessionId.",
            "inputSchema": { "type": "object", "properties": {} },
            "annotations": { "readOnlyHint": true, "openWorldHint": false }
        },
        {
            "name": "read_terminal",
            "title": "Read terminal",
            "description": "Returns the last lines of an open terminal's screen and scrollback as plain text.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "sessionId": id("From list_terminals."),
                    "lines": { "type": "integer", "minimum": 1, "maximum": 2000, "description": "How many lines from the end (default 100)." }
                },
                "required": ["sessionId"]
            },
            "annotations": { "readOnlyHint": true, "openWorldHint": false }
        },
        {
            "name": "list_files",
            "title": "List files",
            "description": "Lists a directory on a saved connection (SFTP for SSH, FTP, S3). Without a path it lists the connection's start directory.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "connectionId": id("From list_connections."),
                    "path": id("Absolute path on the server; for S3 /bucket/prefix.")
                },
                "required": ["connectionId"]
            },
            "annotations": { "readOnlyHint": true, "openWorldHint": true }
        },
        {
            "name": "run_command",
            "title": "Run command",
            "description": "Runs one shell command on a saved SSH connection, without a terminal, and returns stdout, stderr and the exit code. The user has to confirm every call in WireTerm and sees the exact command.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "connectionId": id("An SSH connection from list_connections."),
                    "command": id("The command line, run by the user's login shell."),
                    "timeoutSeconds": { "type": "integer", "minimum": 1, "maximum": 3600, "description": "Default 60." }
                },
                "required": ["connectionId", "command"]
            },
            "annotations": { "readOnlyHint": false, "destructiveHint": true, "openWorldHint": true }
        },
        {
            "name": "send_to_terminal",
            "title": "Type into a terminal",
            "description": "Types text into an open terminal, as if the user had typed it, and presses Enter unless pressEnter is false. The user has to confirm every call. Use read_terminal afterwards to see the result.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "sessionId": id("From list_terminals."),
                    "text": id("What to type."),
                    "pressEnter": { "type": "boolean", "description": "Default true." }
                },
                "required": ["sessionId", "text"]
            },
            "annotations": { "readOnlyHint": false, "destructiveHint": true, "openWorldHint": true }
        }
    ])
}

fn known_tool(name: &str) -> bool {
    tools()
        .as_array()
        .is_some_and(|all| all.iter().any(|tool| tool["name"] == name))
}

// ---- Protocol ------------------------------------------------------------------

/// A call as it goes to the front.
#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Call {
    pub id: String,
    pub tool: String,
    pub arguments: Value,
    /// What the agent called itself when connecting — for the dialog.
    pub client: String,
}

/// What the window returns.
#[derive(Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct CallResult {
    pub text: String,
    #[serde(default)]
    pub is_error: bool,
}

impl CallResult {
    fn error(text: &str) -> Self {
        Self {
            text: text.to_string(),
            is_error: true,
        }
    }
}

type Forward = Arc<dyn Fn(Call) -> Pin<Box<dyn Future<Output = CallResult> + Send>> + Send + Sync>;

struct Context {
    token: String,
    forward: Forward,
    client: std::sync::Mutex<String>,
}

/// The answer to a JSON-RPC message — `None` for everything that gets no
/// answer: notifications and the client's responses.
async fn answer(context: &Context, message: &Value) -> Option<Value> {
    let id = message.get("id")?.clone();
    let method = message.get("method")?.as_str().unwrap_or_default();
    let params = message.get("params").cloned().unwrap_or_else(|| json!({}));

    let result: Result<Value, (i64, String)> = match method {
        "initialize" => {
            let client = params["clientInfo"]["name"]
                .as_str()
                .map(str::to_string)
                .unwrap_or_else(|| t!("mcp.unknown_client").to_string());
            if let Ok(mut slot) = context.client.lock() {
                *slot = client;
            }
            let asked = params["protocolVersion"].as_str().unwrap_or_default();
            let version = PROTOCOL_VERSIONS
                .iter()
                .find(|v| **v == asked)
                .unwrap_or(&PROTOCOL_VERSIONS[0]);
            Ok(json!({
                "protocolVersion": version,
                "capabilities": { "tools": { "listChanged": false } },
                "serverInfo": {
                    "name": "wireterm",
                    "title": "WireTerm",
                    "version": env!("CARGO_PKG_VERSION")
                },
                "instructions": "WireTerm manages SSH, FTP and S3 connections. Reading (list_*, read_terminal) runs at once. run_command and send_to_terminal wait until the user confirms them in WireTerm and fail if they decline. No tool ever returns passwords or keys."
            }))
        }
        "ping" => Ok(json!({})),
        "tools/list" => Ok(json!({ "tools": tools() })),
        "tools/call" => {
            let name = params["name"].as_str().unwrap_or_default().to_string();
            if !known_tool(&name) {
                Err((-32602, format!("Unknown tool: {name}")))
            } else {
                let client = context.client.lock().map(|c| c.clone()).unwrap_or_default();
                let call = Call {
                    id: uuid::Uuid::new_v4().to_string(),
                    tool: name,
                    arguments: params
                        .get("arguments")
                        .cloned()
                        .unwrap_or_else(|| json!({})),
                    client,
                };
                let outcome = (context.forward)(call).await;
                Ok(json!({
                    "content": [{ "type": "text", "text": outcome.text }],
                    "isError": outcome.is_error
                }))
            }
        }
        other => Err((-32601, format!("Method not found: {other}"))),
    };

    Some(match result {
        Ok(result) => json!({ "jsonrpc": "2.0", "id": id, "result": result }),
        Err((code, message)) => {
            json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
        }
    })
}

// ---- HTTP ------------------------------------------------------------------------

/// A page in the browser must not reach this server — otherwise a DNS
/// rebinding would be enough to get in from outside. Without `Origin` the
/// request does not come from a browser.
fn allowed_origin(origin: Option<&str>) -> bool {
    let Some(origin) = origin else {
        return true;
    };
    let Some(rest) = origin.split_once("://").map(|(_, rest)| rest) else {
        return false;
    };
    let host = if rest.starts_with('[') {
        rest.split_inclusive(']').next().unwrap_or_default()
    } else {
        rest.split([':', '/']).next().unwrap_or_default()
    };
    matches!(host, "localhost" | "127.0.0.1" | "[::1]")
}

/// Without a shortcut at the first wrong character, so the response time
/// reveals nothing about the token.
fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn reply(status: StatusCode, body: Option<Value>) -> Response<Full<Bytes>> {
    let mut response = Response::builder().status(status);
    let body = match body {
        Some(value) => {
            response = response.header(header::CONTENT_TYPE, "application/json");
            Bytes::from(value.to_string())
        }
        None => Bytes::new(),
    };
    response.body(Full::new(body)).unwrap_or_default()
}

async fn handle(
    context: Arc<Context>,
    request: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    if request.uri().path() != "/mcp" {
        return Ok(reply(StatusCode::NOT_FOUND, None));
    }
    let origin = request
        .headers()
        .get(header::ORIGIN)
        .and_then(|v| v.to_str().ok());
    if !allowed_origin(origin) {
        return Ok(reply(StatusCode::FORBIDDEN, None));
    }
    let bearer = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or_default();
    if !same(bearer.trim().as_bytes(), context.token.as_bytes()) {
        return Ok(reply(StatusCode::UNAUTHORIZED, None));
    }
    if request.method() != Method::POST {
        // There is no stream from the server here; the protocol prescribes
        // exactly this answer for that case.
        let mut response = reply(StatusCode::METHOD_NOT_ALLOWED, None);
        response
            .headers_mut()
            .insert(header::ALLOW, header::HeaderValue::from_static("POST"));
        return Ok(response);
    }

    let body = match Limited::new(request.into_body(), MAX_BODY).collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => return Ok(reply(StatusCode::PAYLOAD_TOO_LARGE, None)),
    };
    let message: Value = match serde_json::from_slice(&body) {
        Ok(message) => message,
        Err(_) => {
            return Ok(reply(
                StatusCode::BAD_REQUEST,
                Some(
                    json!({ "jsonrpc": "2.0", "id": null, "error": { "code": -32700, "message": "Parse error" } }),
                ),
            ))
        }
    };
    if !message.is_object() {
        return Ok(reply(
            StatusCode::BAD_REQUEST,
            Some(
                json!({ "jsonrpc": "2.0", "id": null, "error": { "code": -32600, "message": "Batches are not supported" } }),
            ),
        ));
    }
    Ok(match answer(&context, &message).await {
        Some(response) => reply(StatusCode::OK, Some(response)),
        None => reply(StatusCode::ACCEPTED, None),
    })
}

/// Accepts connections until the task is aborted.
async fn serve(listener: TcpListener, context: Arc<Context>) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            continue;
        };
        let context = Arc::clone(&context);
        tokio::spawn(async move {
            let service = service_fn(move |request| handle(Arc::clone(&context), request));
            let _ = http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .await;
        });
    }
}

async fn bind(port: u16) -> Result<(TcpListener, SocketAddr), String> {
    let listener = TcpListener::bind(("127.0.0.1", port))
        .await
        .map_err(|e| t!("mcp.port_in_use", port = port, error = e).to_string())?;
    let address = listener.local_addr().map_err(|e| e.to_string())?;
    Ok((listener, address))
}

// ---- State and settings ----------------------------------------------------------

#[derive(Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct Stored {
    enabled: bool,
    port: u16,
    /// Encrypted with the device key, like every other secret here.
    #[serde(default)]
    token: String,
}

struct Running {
    port: u16,
    task: tauri::async_runtime::JoinHandle<()>,
}

type Pending = Arc<Mutex<HashMap<String, oneshot::Sender<CallResult>>>>;

#[derive(Default)]
pub struct Mcp {
    running: Mutex<Option<Running>>,
    pending: Pending,
    /// Why it is not running although it is switched on.
    error: Mutex<Option<String>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    enabled: bool,
    running: bool,
    port: u16,
    url: String,
    error: Option<String>,
}

fn file(app: &AppHandle) -> Result<std::path::PathBuf, String> {
    Ok(crate::paths::app_data_dir(app)?.join(FILE))
}

fn load(app: &AppHandle) -> Result<Stored, String> {
    let stored = crate::cloud::account::read_json::<Stored>(&file(app)?)?.unwrap_or_default();
    Ok(Stored {
        port: if stored.port == 0 {
            DEFAULT_PORT
        } else {
            stored.port
        },
        ..stored
    })
}

fn save(app: &AppHandle, stored: &Stored) -> Result<(), String> {
    crate::cloud::account::write_json(&file(app)?, stored)
}

fn new_token() -> Result<String, String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|e| e.to_string())?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

/// The token in plain text; the first time, one is created.
fn token(app: &AppHandle, stored: &mut Stored) -> Result<String, String> {
    let key = app
        .state::<LocalVault>()
        .key(app)
        .ok_or_else(|| t!("mcp.device_key_locked").to_string())?;
    if !stored.token.is_empty() {
        return local_secrets::open_text(&key, AAD, &stored.token);
    }
    let token = new_token()?;
    stored.token = local_secrets::seal_text(&key, AAD, &token)?;
    save(app, stored)?;
    Ok(token)
}

/// Sends a call to the window and waits for its answer.
fn forward_to_window(app: AppHandle, pending: Pending) -> Forward {
    Arc::new(move |call: Call| {
        let app = app.clone();
        let pending = Arc::clone(&pending);
        Box::pin(async move {
            let (sender, receiver) = oneshot::channel();
            pending.lock().await.insert(call.id.clone(), sender);
            if app.emit(CALL_EVENT, &call).is_err() {
                pending.lock().await.remove(&call.id);
                return CallResult::error("WireTerm could not show the request.");
            }
            match tokio::time::timeout(CALL_TIMEOUT, receiver).await {
                Ok(Ok(result)) => result,
                _ => {
                    pending.lock().await.remove(&call.id);
                    CallResult::error("WireTerm did not answer in time.")
                }
            }
        })
    })
}

async fn stop(mcp: &Mcp) {
    if let Some(running) = mcp.running.lock().await.take() {
        running.task.abort();
    }
}

async fn start(app: &AppHandle, mcp: &Mcp, stored: &mut Stored) -> Result<(), String> {
    stop(mcp).await;
    let token = token(app, stored)?;
    let (listener, address) = bind(stored.port).await?;
    let context = Arc::new(Context {
        token,
        forward: forward_to_window(app.clone(), Arc::clone(&mcp.pending)),
        client: std::sync::Mutex::new(String::new()),
    });
    let task = tauri::async_runtime::spawn(serve(listener, context));
    *mcp.running.lock().await = Some(Running {
        port: address.port(),
        task,
    });
    Ok(())
}

/// Brings the server into the state the settings say.
async fn apply(app: &AppHandle, mcp: &Mcp) -> Result<(), String> {
    let mut stored = load(app)?;
    let outcome = if stored.enabled {
        start(app, mcp, &mut stored).await
    } else {
        stop(mcp).await;
        Ok(())
    };
    *mcp.error.lock().await = outcome.as_ref().err().cloned();
    outcome
}

async fn status(app: &AppHandle, mcp: &Mcp) -> Result<Status, String> {
    let stored = load(app)?;
    let running = mcp.running.lock().await;
    let port = running.as_ref().map_or(stored.port, |r| r.port);
    Ok(Status {
        enabled: stored.enabled,
        running: running.is_some(),
        port,
        url: format!("http://127.0.0.1:{port}/mcp"),
        error: mcp.error.lock().await.clone(),
    })
}

/// Starts the server when the app starts, if it is switched on.
pub fn start_on_launch(app: &AppHandle) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        let mcp = app.state::<Mcp>();
        let _ = apply(&app, &mcp).await;
    });
}

#[tauri::command]
pub async fn mcp_status(app: AppHandle, mcp: State<'_, Mcp>) -> Result<Status, String> {
    status(&app, &mcp).await
}

/// Switches on or off and sets the port. An error when starting — the port
/// is taken, the device key is locked — shows up in the status afterwards.
#[tauri::command]
pub async fn mcp_configure(
    app: AppHandle,
    mcp: State<'_, Mcp>,
    enabled: bool,
    port: u16,
) -> Result<Status, String> {
    let mut stored = load(&app)?;
    stored.enabled = enabled;
    stored.port = if port == 0 { DEFAULT_PORT } else { port };
    save(&app, &stored)?;
    let _ = apply(&app, &mcp).await;
    status(&app, &mcp).await
}

/// The token, for entering at the agent.
#[tauri::command]
pub async fn mcp_token(app: AppHandle) -> Result<String, String> {
    let mut stored = load(&app)?;
    token(&app, &mut stored)
}

/// A new token. The old one stops being valid at once.
#[tauri::command]
pub async fn mcp_renew_token(app: AppHandle, mcp: State<'_, Mcp>) -> Result<String, String> {
    let mut stored = load(&app)?;
    stored.token.clear();
    let token = token(&app, &mut stored)?;
    let _ = apply(&app, &mcp).await;
    Ok(token)
}

/// The window's answer to a call.
#[tauri::command]
pub async fn mcp_answer(mcp: State<'_, Mcp>, id: String, result: CallResult) -> Result<(), String> {
    if let Some(sender) = mcp.pending.lock().await.remove(&id) {
        let _ = sender.send(result);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context(token: &str) -> Arc<Context> {
        let forward: Forward = Arc::new(|call: Call| {
            Box::pin(async move {
                CallResult {
                    text: format!("{} {} {}", call.client, call.tool, call.arguments),
                    is_error: false,
                }
            })
        });
        Arc::new(Context {
            token: token.to_string(),
            forward,
            client: std::sync::Mutex::new(String::new()),
        })
    }

    fn block<F: Future>(future: F) -> F::Output {
        tauri::async_runtime::block_on(future)
    }

    #[test]
    fn initialize_names_version_and_tools() {
        let context = context("t");
        let reply = block(answer(
            &context,
            &json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize",
                     "params": { "protocolVersion": "2025-03-26", "clientInfo": { "name": "claude-code" } } }),
        ))
        .expect("answers");
        assert_eq!(reply["result"]["protocolVersion"], "2025-03-26");
        assert!(reply["result"]["capabilities"]["tools"].is_object());

        let unknown = block(answer(
            &context,
            &json!({ "jsonrpc": "2.0", "id": 2, "method": "initialize", "params": { "protocolVersion": "1999-01-01" } }),
        ))
        .expect("answers");
        assert_eq!(unknown["result"]["protocolVersion"], PROTOCOL_VERSIONS[0]);

        let list = block(answer(
            &context,
            &json!({ "jsonrpc": "2.0", "id": 3, "method": "tools/list" }),
        ))
        .expect("answers");
        let names: Vec<&str> = list["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        assert!(names.contains(&"run_command") && names.contains(&"list_connections"));
    }

    #[test]
    fn notifications_get_no_answer() {
        let context = context("t");
        assert!(block(answer(
            &context,
            &json!({ "jsonrpc": "2.0", "method": "notifications/initialized" })
        ))
        .is_none());
        let error = block(answer(
            &context,
            &json!({ "jsonrpc": "2.0", "id": 9, "method": "nope" }),
        ))
        .expect("answers");
        assert_eq!(error["error"]["code"], -32601);
        let wrong = block(answer(
            &context,
            &json!({ "jsonrpc": "2.0", "id": 10, "method": "tools/call", "params": { "name": "rm_rf" } }),
        ))
        .expect("answers");
        assert_eq!(wrong["error"]["code"], -32602);
    }

    #[test]
    fn only_local_origins_are_allowed() {
        assert!(allowed_origin(None));
        assert!(allowed_origin(Some("http://localhost:5173")));
        assert!(allowed_origin(Some("http://127.0.0.1")));
        assert!(allowed_origin(Some("http://[::1]:8080")));
        assert!(!allowed_origin(Some("https://evil.example")));
        assert!(!allowed_origin(Some("http://localhost.evil.example")));
        assert!(!allowed_origin(Some("null")));
    }

    /// A request over a raw TCP connection — status and body.
    async fn http(
        address: SocketAddr,
        method: &str,
        headers: &[&str],
        body: &str,
    ) -> (u16, String) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = tokio::net::TcpStream::connect(address)
            .await
            .expect("connects");
        let mut request = format!(
            "{method} /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n",
            body.len()
        );
        for header in headers {
            request.push_str(header);
            request.push_str("\r\n");
        }
        request.push_str("\r\n");
        request.push_str(body);
        stream.write_all(request.as_bytes()).await.expect("writes");
        let mut raw = String::new();
        stream.read_to_string(&mut raw).await.expect("reads");
        let status = raw
            .split(' ')
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let body = raw
            .split_once("\r\n\r\n")
            .map(|(_, b)| b.to_string())
            .unwrap_or_default();
        (status, body)
    }

    /// Through HTTP, against a real port: without a token nothing, with a
    /// token a call to the (here simulated) window and back.
    #[test]
    fn over_http_with_and_without_a_token() {
        block(async {
            let (listener, address) = bind(0).await.expect("binds");
            let task = tokio::spawn(serve(listener, context("secret")));
            let call = json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                               "params": { "name": "list_terminals", "arguments": {} } })
            .to_string();
            let auth = "Authorization: Bearer secret";

            assert_eq!(http(address, "POST", &[], &call).await.0, 401);
            assert_eq!(
                http(address, "POST", &["Authorization: Bearer wrong"], &call)
                    .await
                    .0,
                401
            );
            assert_eq!(
                http(
                    address,
                    "POST",
                    &[auth, "Origin: https://evil.example"],
                    &call
                )
                .await
                .0,
                403
            );
            assert_eq!(http(address, "GET", &[auth], "").await.0, 405);

            let (status, body) = http(address, "POST", &[auth], &call).await;
            assert_eq!(status, 200, "{body}");
            let body: Value = serde_json::from_str(&body).expect("json");
            assert_eq!(body["result"]["isError"], false);
            assert!(body["result"]["content"][0]["text"]
                .as_str()
                .unwrap()
                .contains("list_terminals"));

            let note =
                json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }).to_string();
            assert_eq!(http(address, "POST", &[auth], &note).await.0, 202);
            task.abort();
        });
    }

    #[test]
    fn tokens_are_long_and_distinct() {
        let a = new_token().unwrap();
        assert_eq!(a.len(), 64);
        assert_ne!(a, new_token().unwrap());
        assert!(same(b"abc", b"abc") && !same(b"abc", b"abd") && !same(b"abc", b"ab"));
    }
}
