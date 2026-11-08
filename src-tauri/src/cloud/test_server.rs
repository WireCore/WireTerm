//! A small HTTP server for tests: answers with predefined responses in order
//! and records for each request what was sent. This lets the client's paths
//! be checked without starting a backend.

use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// What arrived with a request.
#[derive(Debug, Clone, Default)]
pub struct Seen {
    pub method: String,
    pub path: String,
    pub authorization: String,
    pub cookie: String,
    pub body: String,
    /// All header lines as they arrived — for headers that have no field of
    /// their own above.
    pub head: String,
}

/// A predefined response: status, extra header lines (each ending in `\r\n`) and body.
pub type Reply = (u16, &'static str, &'static str);

/// Answers with the predefined responses in order and returns the address.
pub async fn server(script: Vec<Reply>) -> (String, Arc<Mutex<Vec<Seen>>>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("binds");
    let url = format!(
        "http://127.0.0.1:{}",
        listener.local_addr().expect("address").port()
    );
    let seen = Arc::new(Mutex::new(Vec::new()));
    let record = seen.clone();
    tokio::spawn(async move {
        for (status, extra, body) in script {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let mut buffer = Vec::new();
            let mut chunk = [0u8; 2048];
            let end = loop {
                if let Some(end) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
                    break end;
                }
                let read = stream.read(&mut chunk).await.unwrap_or(0);
                if read == 0 {
                    return;
                }
                buffer.extend_from_slice(&chunk[..read]);
            };
            let head = String::from_utf8_lossy(&buffer[..end]).to_string();
            let header = |name: &str| {
                head.lines()
                    .find_map(|line| {
                        let (key, value) = line.split_once(':')?;
                        key.trim()
                            .eq_ignore_ascii_case(name)
                            .then(|| value.trim().to_string())
                    })
                    .unwrap_or_default()
            };
            // Read the body to the end according to `Content-Length`.
            let length: usize = header("content-length").parse().unwrap_or(0);
            let mut body_bytes = buffer[end + 4..].to_vec();
            while body_bytes.len() < length {
                let read = stream.read(&mut chunk).await.unwrap_or(0);
                if read == 0 {
                    break;
                }
                body_bytes.extend_from_slice(&chunk[..read]);
            }
            let mut first = head.lines().next().unwrap_or_default().split(' ');
            record.lock().unwrap().push(Seen {
                method: first.next().unwrap_or_default().to_string(),
                path: first.next().unwrap_or_default().to_string(),
                authorization: header("authorization"),
                cookie: header("cookie"),
                body: String::from_utf8_lossy(&body_bytes).to_string(),
                head: head.clone(),
            });
            // JSON unless the reply brings a type of its own (an image, say).
            let content_type = if extra.to_ascii_lowercase().contains("content-type:") {
                ""
            } else {
                "Content-Type: application/json\r\n"
            };
            let response = format!(
                "HTTP/1.1 {status} X\r\n{content_type}Content-Length: {}\r\n{extra}Connection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.shutdown().await;
        }
    });
    (url, seen)
}
