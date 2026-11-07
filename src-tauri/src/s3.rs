//! S3 — object storage as the third connection type.
//!
//! From a distance the file view looks the same here as over SFTP: two panes,
//! one queue, the same gestures. Underneath, almost nothing is the same.
//!
//! # There are no directories
//!
//! That is the difference that shapes this module. A bucket is a flat list of
//! keys, and `photos/2024/holiday.jpg` is a name with slashes in it, not a
//! path. What the file view shows as a folder is what `ListObjectsV2` with
//! `delimiter=/` sums up from that: everything up to the next slash becomes a
//! *common prefix*, and that becomes a row with a folder icon here.
//!
//! The rest follows from that:
//!
//! - **An empty folder does not exist.** So that "New folder" still does
//!   something visible, an empty object with a trailing slash is created —
//!   the same convention the AWS console uses. It is filtered out of the
//!   listing again, because it *is* the folder and does not sit inside it.
//! - **There is no renaming.** It is copied server-side
//!   (`x-amz-copy-source`) and deleted, for a folder once per object in it.
//! - **There are no permissions.** No `chmod`, no owners, no modes. The
//!   listing carries no mode bits, and so "Change permissions" is greyed out
//!   in the pane without it having to know about S3.
//! - **There are no symlinks.** That drops every round trip SFTP and FTP
//!   spend on finding out where one points.
//!
//! # Every request stands on its own
//!
//! S3 is HTTP. There is no session that stays open, and nothing that hangs up
//! after minutes of inactivity — so neither a pool as with FTP nor a channel
//! as with SFTP. A tab holds one `reqwest::Client`, which reuses its
//! connections by itself; how many transfers run at once is decided by the
//! queue alone.
//!
//! The price is the signature: every single request is signed with
//! **AWS Signature Version 4** — build the canonical form, hash it, HMAC it
//! with a key derived from date, region and service. That is further down in
//! [`sign`] and is the reason there is no AWS SDK here: its crypto backend is
//! aws-lc-rs, which needs cmake and NASM to build on Windows — exactly what
//! this project avoids in three places.
//!
//! # Uploading leaves nothing half-done
//!
//! Over SFTP and FTP a transfer writes to `{target}.wtpart` and only renames
//! at the end, because otherwise an abort would leave half a file under the
//! right name. S3 does not need that: a `PUT` creates the object only once
//! the last byte has arrived, and an aborted multipart upload is cleaned up
//! here (`AbortMultipartUpload`). An upload is therefore either wholly there
//! or not at all — in exchange it cannot be resumed either. Downloading, on
//! the other hand, writes to `.wtpart` as everywhere else and picks up again
//! with a `Range` header.

use std::collections::HashMap;
use std::io::SeekFrom;
use std::path::Path;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::Bytes;
use chrono::{DateTime, Utc};
use http_body::{Body as HttpBody, Frame, SizeHint};
use percent_encoding::{utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use quick_xml::events::Event;
use reqwest::{Method, Response, StatusCode};
use ring::{digest, hmac};
use serde::Serialize;
use tauri::{AppHandle, Emitter, State};
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinSet;

use crate::edit::{self, EditSession, EditWatchers, EditorCommand};
use crate::files::{self, Entry, Listing};
use crate::resume::{Partial, Partials};
use crate::secret::{self, Cache, Prompts};
use crate::storage::{Probe, RemoteSystem, S3Auth, S3Settings};
use crate::tls::Pinning;
use crate::transfer::{Job, Reporter, Transfers, CANCELLED, CHUNK, WORKING_SUFFIX};
use crate::vault;
use rust_i18n::t;

/// How long the endpoint is given to answer at all.
///
/// The connection, not the request: a transfer may run for an hour, and a
/// listing of a bucket with a million keys is slow for honest reasons. A wrong
/// host or a closed port is what this catches, and it is what makes
/// "Test connection" answer rather than look frozen.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);

/// From here up, an upload goes as a multipart upload.
///
/// Below it a single `PUT` is one round trip and cannot leave anything behind.
/// Above it the same `PUT` would mean starting from zero again after a dropped
/// connection — and past 5 GiB S3 refuses it outright, which is the hard
/// reason the other path has to exist at all.
const MULTIPART_THRESHOLD: u64 = 64 * 1024 * 1024;

/// How much one part carries.
///
/// S3 wants at least 5 MiB for every part but the last, and no more than
/// 10 000 parts — so this also decides the largest file that can go up.
/// 64 MiB × 10 000 is 640 GiB; [`part_size`] raises it for anything bigger
/// rather than failing.
const PART_SIZE: u64 = 64 * 1024 * 1024;

/// The most parts one upload may be cut into. S3's limit, not a choice.
const MAX_PARTS: u64 = 10_000;

/// The largest object one `CopyObject` copies. S3's limit, not a choice:
/// anything bigger is copied in parts, see [`copy_parts`].
const MAX_COPY_SIZE: u64 = 5 * 1024 * 1024 * 1024;

/// How much one part of a server-side copy carries.
///
/// Larger than [`PART_SIZE`], because no bytes come through here: a part costs
/// one request and the server's time, and a 6 GiB object in 64 MiB pieces
/// would be a hundred requests for what twelve do as well.
const COPY_PART_SIZE: u64 = 512 * 1024 * 1024;

/// From what age an unfinished multipart upload counts as left behind.
///
/// Younger ones may well still be running — in another tab, on another
/// machine, in another program — and aborting one of those breaks somebody's
/// upload. A day is long enough for any upload this app would start.
const STALE_UPLOAD_SECONDS: i64 = 24 * 60 * 60;

/// How many objects one `ListObjectsV2` page asks for. S3's maximum.
const PAGE_SIZE: u32 = 1000;

/// How many entries one directory listing reads before it stops asking for
/// further pages.
///
/// A prefix with a million keys under it would otherwise take minutes and fill
/// a list nobody can read. No ordinary directory comes near this, and what it
/// costs where it is reached — a listing that is not the whole truth — is the
/// honest trade for a pane that answers. See TODO.md.
const LISTING_LIMIT: usize = 20_000;

/// How many deletions run at once when a whole prefix goes.
///
/// There is no "delete this directory" in S3: every object is a request of its
/// own. A tree of ten thousand small files is ten thousand round trips, and
/// doing them one after another is what makes deleting a folder feel broken.
const DELETE_PARALLEL: usize = 16;

/// The longest a shared link may be valid. SigV4's own ceiling, seven days.
const MAX_LINK_SECONDS: u64 = 7 * 24 * 60 * 60;

/// What goes in `x-amz-content-sha256` where the body is not hashed.
///
/// Allowed for every request this module makes: the signature still covers the
/// method, the path and every header, and hashing a 40 GB upload before
/// sending it would mean reading the file twice.
const UNSIGNED: &str = "UNSIGNED-PAYLOAD";

/// `sha256("")`, which is what a request without a body signs.
const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

const ALGORITHM: &str = "AWS4-HMAC-SHA256";

// ---- Paths -------------------------------------------------------------------
//
// The file browser navigates in POSIX paths, because that is what the pane and
// [`crate::files`] speak. Here they read `/bucket/key`, with the bucket as the
// first segment — so the top of the tree is the list of buckets, and a path
// with nothing but a bucket in it is that bucket's root.

/// What a browser path points at.
struct Location<'a> {
    /// `None` only for `/`, the list of buckets.
    bucket: Option<&'a str>,
    /// The key below the bucket, without a leading or trailing slash. Empty at
    /// the bucket's root.
    key: &'a str,
}

fn locate(path: &str) -> Location<'_> {
    let trimmed = path.trim_start_matches('/');
    if trimmed.is_empty() {
        return Location {
            bucket: None,
            key: "",
        };
    }
    match trimmed.split_once('/') {
        Some((bucket, key)) => Location {
            bucket: Some(bucket),
            key: key.trim_end_matches('/'),
        },
        None => Location {
            bucket: Some(trimmed),
            key: "",
        },
    }
}

/// The browser path a bucket and a key are reached under.
fn path_of(bucket: &str, key: &str) -> String {
    let key = key.trim_matches('/');
    if key.is_empty() {
        format!("/{bucket}")
    } else {
        format!("/{bucket}/{key}")
    }
}

/// The key a directory is listed under: with the trailing slash S3 needs to
/// tell `photos/` from `photos.txt`, and empty at the bucket's root.
fn prefix_of(key: &str) -> String {
    let key = key.trim_matches('/');
    if key.is_empty() {
        String::new()
    } else {
        format!("{key}/")
    }
}

/// What a listing asks the server for. A path ending in `*` is a name prefix
/// rather than a folder — `photos/2024*` lists everything that starts with
/// `photos/2024` — which is how a listing cut short at [`LISTING_LIMIT`] is
/// narrowed down. Anything else is the folder, with its slash.
fn listing_prefix(key: &str) -> String {
    match key.strip_suffix('*') {
        Some(partial) => partial.trim_start_matches('/').to_string(),
        None => prefix_of(key),
    }
}

/// The last segment of a key — what the pane shows in the name column.
fn name_of(key: &str) -> String {
    key.trim_end_matches('/')
        .rsplit('/')
        .next()
        .unwrap_or(key)
        .to_string()
}

// ---- Signature -----------------------------------------------------------------
//
// AWS Signature Version 4, as every S3 implementation worth reaching expects
// it. The shape is fixed by the specification and there is nothing to decide
// here — which is why it is worth having in one place with the two traps
// named: the path is encoded once and not twice, and the query string is
// sorted by its *encoded* name.

/// The characters SigV4 leaves alone: `A-Za-z0-9-_.~` and nothing else.
const UNRESERVED: AsciiSet = NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');

/// The same, plus the separator — a key's slashes stay slashes.
const PATH_SET: AsciiSet = UNRESERVED.remove(b'/');

fn encode_path(value: &str) -> String {
    utf8_percent_encode(value, &PATH_SET).to_string()
}

fn encode_query(value: &str) -> String {
    utf8_percent_encode(value, &UNRESERVED).to_string()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn sha256_hex(data: &[u8]) -> String {
    hex(digest::digest(&digest::SHA256, data).as_ref())
}

fn sign_with(key: &[u8], data: &str) -> hmac::Tag {
    hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, key), data.as_bytes())
}

/// The access key id and the secret behind it.
#[derive(Clone)]
struct Keys {
    access: String,
    secret: String,
    /// Temporary credentials from STS come with one, and every request has to
    /// carry it as `x-amz-security-token` — signed along with the rest.
    token: Option<String>,
}

/// A stored secret is the secret key, optionally followed by a newline and the
/// session token. One string, because that is what is sealed, synced and
/// exported everywhere else — and a secret key never contains a newline, so
/// nothing that was stored before reads differently.
fn split_secret(stored: &str) -> (String, Option<String>) {
    match stored.split_once('\n') {
        Some((secret, token)) => {
            let token = token.trim();
            (
                secret.trim().to_string(),
                (!token.is_empty()).then(|| token.to_string()),
            )
        }
        None => (stored.to_string(), None),
    }
}

/// Where one request goes: the URL to send it to, and the `Host` header that
/// belongs to it — which is part of the signature and therefore has to be
/// exactly what the connection will use.
struct Address {
    url: String,
    host: String,
    /// The path as the signature spells it: encoded once, slashes intact.
    canonical: String,
}

fn address(settings: &S3Settings, bucket: Option<&str>, key: &str) -> Address {
    let scheme = if settings.tls { "https" } else { "http" };
    let default_port = if settings.tls { 443 } else { 80 };

    // The bucket belongs either in the host name or in the path, and getting
    // that wrong is the difference between reaching MinIO and reaching a DNS
    // error: `bucket.10.0.0.5` resolves nowhere.
    let in_path = settings.path_style || bucket.is_none();
    let authority = match (in_path, bucket) {
        (false, Some(bucket)) => format!("{bucket}.{}", settings.host),
        _ => settings.host.clone(),
    };
    let host = if settings.port == default_port {
        authority
    } else {
        format!("{authority}:{}", settings.port)
    };

    let canonical = match (in_path, bucket) {
        (true, Some(bucket)) if key.is_empty() => format!("/{}", encode_path(bucket)),
        (true, Some(bucket)) => format!("/{}/{}", encode_path(bucket), encode_path(key)),
        _ => format!("/{}", encode_path(key)),
    };

    Address {
        url: format!("{scheme}://{host}{canonical}"),
        host,
        canonical,
    }
}

/// What one request is, before it is signed.
///
/// A builder rather than eight arguments: every call below differs from the
/// next in one or two of these, and reading `Call::new("PUT", …).header(…)`
/// beats counting positions.
struct Call<'a> {
    method: &'static str,
    bucket: Option<&'a str>,
    key: &'a str,
    /// Unencoded; sorted and encoded when the signature is built.
    query: Vec<(&'static str, String)>,
    /// Lowercase names, all of them signed. Owned, because the metadata a
    /// copy carries over arrives under names only the source knows
    /// (`x-amz-meta-…`).
    headers: Vec<(String, String)>,
    /// The body, where it is small enough to hold and hash. A streamed upload
    /// hands its body to [`send`] separately and signs as `UNSIGNED-PAYLOAD`.
    body: Option<Vec<u8>>,
    streamed: bool,
}

impl<'a> Call<'a> {
    fn new(method: &'static str, bucket: Option<&'a str>, key: &'a str) -> Self {
        Self {
            method,
            bucket,
            key,
            query: Vec::new(),
            headers: Vec::new(),
            body: None,
            streamed: false,
        }
    }

    fn query(mut self, name: &'static str, value: impl Into<String>) -> Self {
        self.query.push((name, value.into()));
        self
    }

    fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    fn body(mut self, body: Vec<u8>) -> Self {
        self.body = Some(body);
        self
    }

    /// Marks the body as one that arrives from somewhere else and is not
    /// hashed beforehand.
    fn streamed(mut self) -> Self {
        self.streamed = true;
        self
    }

    fn payload_hash(&self) -> String {
        if self.streamed {
            return UNSIGNED.to_string();
        }
        match &self.body {
            Some(body) => sha256_hex(body),
            None => EMPTY_SHA256.to_string(),
        }
    }
}

/// The signature's date material: `20240501T123456Z` and `20240501`.
fn stamps(now: DateTime<Utc>) -> (String, String) {
    (
        now.format("%Y%m%dT%H%M%SZ").to_string(),
        now.format("%Y%m%d").to_string(),
    )
}

/// `20240501/eu-central-1/s3/aws4_request`.
fn scope(date: &str, region: &str) -> String {
    format!("{date}/{region}/s3/aws4_request")
}

/// The key one day's requests to one region are signed with.
fn signing_key(secret: &str, date: &str, region: &str) -> Vec<u8> {
    let start = format!("AWS4{secret}");
    let date_key = sign_with(start.as_bytes(), date);
    let region_key = sign_with(date_key.as_ref(), region);
    let service_key = sign_with(region_key.as_ref(), "s3");
    sign_with(service_key.as_ref(), "aws4_request")
        .as_ref()
        .to_vec()
}

/// Sorted, encoded, joined — the form the signature is computed over.
fn canonical_query(query: &[(&str, String)]) -> String {
    let mut pairs: Vec<(String, String)> = query
        .iter()
        .map(|(name, value)| (encode_query(name), encode_query(value)))
        .collect();
    // By the *encoded* name, which is what the specification says and what
    // differs from sorting the readable one as soon as a name carries
    // anything but letters.
    pairs.sort();
    pairs
        .into_iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join("&")
}

/// Signs one call and hands back where it goes and what to send with it.
fn sign(
    settings: &S3Settings,
    keys: &Keys,
    call: &Call<'_>,
    now: DateTime<Utc>,
) -> (String, Vec<(String, String)>) {
    let target = address(settings, call.bucket, call.key);
    let (timestamp, date) = stamps(now);
    let payload = call.payload_hash();

    let mut headers: Vec<(String, String)> = vec![
        ("host".to_string(), target.host.clone()),
        ("x-amz-content-sha256".to_string(), payload.clone()),
        ("x-amz-date".to_string(), timestamp.clone()),
    ];
    if let Some(token) = &keys.token {
        headers.push(("x-amz-security-token".to_string(), token.clone()));
    }
    for (name, value) in &call.headers {
        headers.push((name.clone(), value.clone()));
    }
    headers.sort_by(|a, b| a.0.cmp(&b.0));

    let signed_names = headers
        .iter()
        .map(|(name, _)| name.as_str())
        .collect::<Vec<_>>()
        .join(";");
    let canonical_headers = headers
        .iter()
        .map(|(name, value)| format!("{name}:{}\n", value.trim()))
        .collect::<String>();

    let canonical_request = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        call.method,
        target.canonical,
        canonical_query(&call.query),
        canonical_headers,
        signed_names,
        payload
    );

    let scope = scope(&date, &settings.region);
    let to_sign = format!(
        "{ALGORITHM}\n{timestamp}\n{scope}\n{}",
        sha256_hex(canonical_request.as_bytes())
    );
    let signature = hex(sign_with(
        &signing_key(&keys.secret, &date, &settings.region),
        &to_sign,
    )
    .as_ref());

    headers.push((
        "authorization".to_string(),
        format!(
            "{ALGORITHM} Credential={}/{scope}, SignedHeaders={signed_names}, Signature={signature}",
            keys.access
        ),
    ));

    let query = canonical_query(&call.query);
    let url = if query.is_empty() {
        target.url
    } else {
        format!("{}?{query}", target.url)
    };
    // The host header is left to reqwest, which sets it from the URL to
    // exactly the value signed above; sending it a second time would only risk
    // the two disagreeing.
    headers.retain(|(name, _)| name != "host");
    (url, headers)
}

/// Builds a link that carries its own signature in the query string.
///
/// The one thing in this module that is not about reaching the server: this
/// URL is for someone else, who has no credentials and no client. It is valid
/// for as long as it says and not a second longer, and it grants exactly one
/// thing — reading this one object.
fn presign(
    settings: &S3Settings,
    keys: &Keys,
    bucket: &str,
    key: &str,
    seconds: u64,
    now: DateTime<Utc>,
) -> String {
    let target = address(settings, Some(bucket), key);
    let (timestamp, date) = stamps(now);
    let scope = scope(&date, &settings.region);

    let mut query = vec![
        ("X-Amz-Algorithm", ALGORITHM.to_string()),
        ("X-Amz-Credential", format!("{}/{scope}", keys.access)),
        ("X-Amz-Date", timestamp.clone()),
        ("X-Amz-Expires", seconds.to_string()),
        // Only the host is signed: a browser sends whatever else it likes, and
        // a link a browser cannot open is not a link.
        ("X-Amz-SignedHeaders", "host".to_string()),
    ];
    if let Some(token) = &keys.token {
        query.push(("X-Amz-Security-Token", token.clone()));
    }

    let canonical_request = format!(
        "GET\n{}\n{}\nhost:{}\n\nhost\n{UNSIGNED}",
        target.canonical,
        canonical_query(&query),
        target.host
    );
    let to_sign = format!(
        "{ALGORITHM}\n{timestamp}\n{scope}\n{}",
        sha256_hex(canonical_request.as_bytes())
    );
    let signature = hex(sign_with(
        &signing_key(&keys.secret, &date, &settings.region),
        &to_sign,
    )
    .as_ref());

    format!(
        "{}?{}&X-Amz-Signature={signature}",
        target.url,
        canonical_query(&query)
    )
}

// ---- Answers -------------------------------------------------------------------
//
// S3 answers in XML, and so do its errors — a failed request carries a `Code`
// and a `Message` that say far more than the status line does ("NoSuchBucket"
// against "404"), so they are what the pane gets to show.
//
// Read with one flattening pass rather than with a type per answer: the four
// shapes this module cares about are small, and `Contents/Key` says as much as
// a struct would without a derive for each.

/// Every element that carried text, named by its path below the root, in the
/// order the document had them.
///
/// Text is collected per element rather than per event, which is not a detail:
/// the parser hands an escaped character back as an event of its own, so a key
/// called `invoice&2024.pdf` arrives in three pieces. Reading those as three
/// fields would silently list a file that is not there under a name nobody
/// typed.
fn flatten(xml: &[u8]) -> Vec<(String, String)> {
    let mut reader = quick_xml::Reader::from_reader(xml);

    let mut names: Vec<String> = Vec::new();
    let mut texts: Vec<String> = Vec::new();
    let mut found = Vec::new();
    let mut buffer = Vec::new();

    loop {
        match reader.read_event_into(&mut buffer) {
            Ok(Event::Start(element)) => {
                names.push(element.local_name().as_ref().to_string());
                texts.push(String::new());
            }
            Ok(Event::End(_)) => {
                let Some(text) = texts.pop() else {
                    break;
                };
                let text = text.trim();
                // Below the root: the root element names the answer, not a
                // field in it, and leaving it out is what makes `Contents/Key`
                // read the same whichever answer it came in.
                if !text.is_empty() && names.len() > 1 {
                    found.push((names[1..].join("/"), text.to_string()));
                }
                names.pop();
            }
            Ok(Event::Text(text)) => {
                if let Some(current) = texts.last_mut() {
                    current.push_str(&text.xml10_content());
                }
            }
            Ok(Event::GeneralRef(entity)) => {
                let Some(current) = texts.last_mut() else {
                    continue;
                };
                match entity.resolve_char_ref() {
                    // `&#252;` and the like.
                    Ok(Some(character)) => current.push(character),
                    // The five XML knows by name. Anything else is a document
                    // that defined its own, which S3 does not do — and
                    // dropping it beats guessing at it.
                    _ => current.push_str(match entity.into_inner().as_ref() {
                        "amp" => "&",
                        "lt" => "<",
                        "gt" => ">",
                        "quot" => "\"",
                        "apos" => "'",
                        _ => "",
                    }),
                }
            }
            Ok(Event::Eof) => break,
            // A truncated or unparseable answer gives up what was read so far.
            // Every caller treats a missing field as "did not say", which is
            // the right answer for a half-read document too.
            Err(_) => break,
            _ => {}
        }
        buffer.clear();
    }
    found
}

/// One object in a listing.
struct Object {
    key: String,
    size: u64,
    modified: Option<i64>,
    /// As the server names it. `None` where it said nothing, which a `HEAD`
    /// does for `STANDARD`.
    storage_class: Option<String>,
}

/// What one `ListObjectsV2` page carried.
struct Page {
    /// Common prefixes: everything up to the next slash, which is what the
    /// pane draws as a folder.
    dirs: Vec<String>,
    files: Vec<Object>,
    /// Where to carry on from, where the page was not the whole answer.
    next: Option<String>,
}

/// ISO 8601 as S3 writes it, to Unix seconds.
fn parse_time(value: &str) -> Option<i64> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|stamp| stamp.timestamp())
}

fn parse_listing(xml: &[u8]) -> Page {
    let mut page = Page {
        dirs: Vec::new(),
        files: Vec::new(),
        next: None,
    };
    let mut current: Option<Object> = None;

    for (path, value) in flatten(xml) {
        match path.as_str() {
            // `Key` opens an object: S3 sends it first, and the fields that
            // follow belong to it until the next one starts.
            "Contents/Key" => {
                if let Some(object) = current.take() {
                    page.files.push(object);
                }
                current = Some(Object {
                    key: value,
                    size: 0,
                    modified: None,
                    storage_class: None,
                });
            }
            "Contents/Size" => {
                if let Some(object) = current.as_mut() {
                    object.size = value.parse().unwrap_or(0);
                }
            }
            "Contents/LastModified" => {
                if let Some(object) = current.as_mut() {
                    object.modified = parse_time(&value);
                }
            }
            "Contents/StorageClass" => {
                if let Some(object) = current.as_mut() {
                    object.storage_class = Some(value);
                }
            }
            "CommonPrefixes/Prefix" => page.dirs.push(value),
            "NextContinuationToken" => page.next = Some(value),
            _ => {}
        }
    }
    if let Some(object) = current {
        page.files.push(object);
    }
    page
}

/// The buckets, with when each was created.
fn parse_buckets(xml: &[u8]) -> Vec<(String, Option<i64>)> {
    let mut buckets: Vec<(String, Option<i64>)> = Vec::new();
    for (path, value) in flatten(xml) {
        match path.as_str() {
            "Buckets/Bucket/Name" => buckets.push((value, None)),
            "Buckets/Bucket/CreationDate" => {
                if let Some(last) = buckets.last_mut() {
                    last.1 = parse_time(&value);
                }
            }
            _ => {}
        }
    }
    buckets
}

/// One named field out of an answer — `UploadId`, or the `ETag` of a copied
/// part.
fn parse_field(xml: &[u8], name: &str) -> Option<String> {
    flatten(xml)
        .into_iter()
        .find(|(path, _)| path == name)
        .map(|(_, value)| value)
}

/// One unfinished multipart upload.
struct Upload {
    key: String,
    id: String,
    initiated: Option<i64>,
}

/// What one `ListMultipartUploads` page carried.
struct UploadPage {
    uploads: Vec<Upload>,
    /// The key and upload id to carry on from, where the page was not the
    /// whole answer.
    next: Option<(String, String)>,
}

fn parse_uploads(xml: &[u8]) -> UploadPage {
    let mut uploads: Vec<Upload> = Vec::new();
    let (mut truncated, mut next_key, mut next_id) = (false, None, None);
    for (path, value) in flatten(xml) {
        match path.as_str() {
            // `Key` opens an upload, as it opens an object in a listing.
            "Upload/Key" => uploads.push(Upload {
                key: value,
                id: String::new(),
                initiated: None,
            }),
            "Upload/UploadId" => {
                if let Some(upload) = uploads.last_mut() {
                    upload.id = value;
                }
            }
            "Upload/Initiated" => {
                if let Some(upload) = uploads.last_mut() {
                    upload.initiated = parse_time(&value);
                }
            }
            "IsTruncated" => truncated = value == "true",
            "NextKeyMarker" => next_key = Some(value),
            "NextUploadIdMarker" => next_id = Some(value),
            _ => {}
        }
    }
    // Without an id there is nothing to abort, and nothing to report either.
    uploads.retain(|upload| !upload.id.is_empty());
    UploadPage {
        uploads,
        next: match (truncated, next_key, next_id) {
            (true, Some(key), Some(id)) => Some((key, id)),
            _ => None,
        },
    }
}

/// What the server said went wrong, in its own words.
fn parse_error(xml: &[u8]) -> Option<String> {
    let fields = flatten(xml);
    let field = |name: &str| {
        fields
            .iter()
            .find(|(path, _)| path == name)
            .map(|(_, value)| value.clone())
    };
    let code = field("Code")?;
    match field("Message") {
        Some(message) => Some(format!("{code}: {message}")),
        None => Some(code),
    }
}

// ---- Requests --------------------------------------------------------------------

/// An open file browser on a tab.
///
/// No connection in it, deliberately: S3 has no session to hold open. What is
/// kept is what every request needs — where to go, what to sign with, and a
/// client that reuses its sockets rather than shaking hands per object.
struct Browser {
    http: reqwest::Client,
    settings: S3Settings,
    keys: Keys,
    /// Where the pane starts, worked out once from bucket and prefix.
    home: String,
}

#[derive(Default)]
pub struct S3State(Mutex<HashMap<String, Arc<Browser>>>);

impl S3State {
    async fn browser(&self, session_id: &str) -> Result<Arc<Browser>, String> {
        self.0
            .lock()
            .await
            .get(session_id)
            .cloned()
            .ok_or_else(|| t!("s3.not_connected").into_owned())
    }

    /// Closes the browser on a tab, if one was ever opened.
    pub(crate) async fn close(&self, session_id: &str) {
        self.0.lock().await.remove(session_id);
    }
}

/// The HTTP client one tab uses.
///
/// TLS comes from [`crate::tls`], the same answer FTPS gets, so "Don't verify
/// certificate" means exactly one thing across the app — and so does a
/// certificate the user accepted, which `pinning` carries. The only timeout set
/// here is on reaching the endpoint: a transfer may legitimately run for an
/// hour, and a request timeout would cut it off mid-file.
fn http_client(
    settings: &S3Settings,
    proxy: Option<&crate::proxy::Route>,
    pinning: &Pinning,
) -> Result<reqwest::Client, String> {
    let tls = if settings.accept_invalid_cert {
        crate::tls::config(true)?
    } else {
        crate::tls::pinned(pinning)?
    };
    let mut builder = reqwest::Client::builder()
        // By value and of exactly this type: the configuration is handed over
        // as `Any` and recognised by a downcast, so an `Arc` around it is not
        // a rustls configuration as far as reqwest is concerned — it takes the
        // builder silently and fails when it is built.
        .tls_backend_preconfigured(tls)
        .connect_timeout(CONNECT_TIMEOUT);
    if let Some(route) = proxy {
        builder = builder.proxy(crate::proxy::reqwest_proxy(route)?);
    }
    builder
        .build()
        .map_err(|e| t!("s3.http_client_failed", error = e).into_owned())
}

/// Sends one signed request, or says why it did not work.
///
/// `body` is for an upload, whose bytes arrive from a file rather than from
/// the call itself. Everything else carries its body inside the [`Call`],
/// where it can be hashed into the signature.
async fn send(
    browser: &Browser,
    call: Call<'_>,
    body: Option<reqwest::Body>,
) -> Result<Response, String> {
    let (url, headers) = sign(&browser.settings, &browser.keys, &call, Utc::now());
    let method = Method::from_bytes(call.method.as_bytes())
        .map_err(|_| t!("s3.invalid_method", method = call.method).into_owned())?;

    let mut request = browser.http.request(method, &url);
    for (name, value) in headers {
        request = request.header(name, value);
    }
    request = match (body, call.body) {
        (Some(streamed), _) => request.body(streamed),
        (None, Some(bytes)) => request.body(bytes),
        (None, None) => request,
    };

    let response = request
        .send()
        .await
        .map_err(|e| t!("s3.unreachable", host = browser.settings.host, error = e).into_owned())?;

    if response.status().is_success() {
        return Ok(response);
    }
    Err(failure(response).await)
}

/// Turns a refused request into a sentence.
///
/// The XML body first, because `NoSuchBucket: The specified bucket does not
/// exist` is an answer and `404` is a shrug. A `HEAD` has no body at all,
/// which is the case the status line is left to carry.
async fn failure(response: Response) -> String {
    let status = response.status();
    // AWS answers a bucket in another region with a redirect and names the
    // right one in this header. Worth repeating: the region is a setting in
    // the form, and "move it to eu-central-1" is the whole fix.
    let region = response
        .headers()
        .get("x-amz-bucket-region")
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    let body = response.bytes().await.unwrap_or_default();

    let said = parse_error(&body).unwrap_or_else(|| match status {
        StatusCode::NOT_FOUND => t!("s3.not_found").into_owned(),
        StatusCode::FORBIDDEN => t!("s3.forbidden").into_owned(),
        StatusCode::UNAUTHORIZED => t!("s3.unauthorized").into_owned(),
        other => t!("s3.server_answered", status = other).into_owned(),
    });

    match region {
        Some(region) if !region.is_empty() => {
            t!("s3.bucket_region", message = said, region = region).into_owned()
        }
        _ => said,
    }
}

/// What the endpoint says it is, out of the `Server` header.
///
/// Far less than `/etc/os-release` gives over SSH — "AmazonS3" or "MinIO" and
/// nothing else — but it is everything an S3 endpoint volunteers, and it tells
/// a rented bucket from one in the basement. Best effort throughout: a server
/// that sends no such header is perfectly usable.
fn read_system(host: &str, response: &Response) -> RemoteSystem {
    let server = response
        .headers()
        .get(reqwest::header::SERVER)
        .and_then(|v| v.to_str().ok());
    describe(host, server)
}

/// Hosted object stores told apart by their host name, because not all of them
/// send a `Server` header, and the ones that do name the software underneath
/// ("Ceph") rather than the product that was rented.
const PROVIDERS: &[(&str, &str, &str)] = &[(
    ".your-objectstorage.com",
    "hetzner",
    "Hetzner Object Storage",
)];

/// The known hosting product first, then the `Server` header, and last a plain
/// "S3": the request was answered, so it is an S3 endpoint, whatever else it
/// keeps to itself.
fn describe(host: &str, server: Option<&str>) -> RemoteSystem {
    let host = host.to_lowercase();
    if let Some((_, id, name)) = PROVIDERS.iter().find(|(suffix, ..)| host.ends_with(suffix)) {
        return RemoteSystem {
            id: id.to_string(),
            name: name.to_string(),
            version: String::new(),
            pretty: name.to_string(),
        };
    }
    let value = server.map(str::trim).unwrap_or_default().to_string();
    if value.is_empty() {
        return RemoteSystem {
            id: "objectstore".to_string(),
            name: "S3".to_string(),
            version: String::new(),
            pretty: t!("s3.endpoint_unnamed").into_owned(),
        };
    }

    // Only the implementations there is a mark for get an id that draws one.
    // Anything else is named but not drawn, which says less than a wrong logo
    // and nothing false — see os.ts.
    let token = value.split('/').next().unwrap_or(&value).to_lowercase();
    let id = match token.as_str() {
        "minio" => "minio",
        "ceph" => "ceph",
        _ => "objectstore",
    };

    RemoteSystem {
        id: id.to_string(),
        name: value.split('/').next().unwrap_or(&value).to_string(),
        // Servers that name a version put it after a slash. Rarely more than
        // a build date, but it costs nothing to keep.
        version: value
            .split_once('/')
            .map(|(_, rest)| rest.to_string())
            .unwrap_or_default(),
        pretty: value,
    }
}

// ---- Sessions --------------------------------------------------------------------

/// The access key and the secret behind it.
///
/// The access key id is the `user` field of the connection, because that is
/// what it is: the name every request is made under. Only the secret has a
/// source to choose.
async fn credentials(
    app: &AppHandle,
    cache: &Cache,
    prompts: &Prompts,
    session_id: Option<&str>,
    settings: &S3Settings,
) -> Result<Keys, String> {
    // The access key id may be a vault reference; from here on it is the id.
    let settings = &S3Settings {
        user: vault::resolve_user(app, &settings.user).await?,
        ..settings.clone()
    };
    let secret = match &settings.auth {
        S3Auth::Secret { secret } => secret.clone(),
        S3Auth::Vault {
            provider,
            reference,
        } => vault::resolve(app, *provider, reference)
            .await
            .map_err(|e| {
                t!(
                    "s3.vault_read_failed",
                    provider = provider.label(),
                    error = e
                )
                .into_owned()
            })?,
        S3Auth::Prompt => {
            let cached = match session_id {
                Some(id) => cache.get(id).await,
                None => None,
            };
            match cached {
                Some(secret) => secret,
                None => {
                    let secret = secret::ask(
                        app,
                        prompts,
                        secret::Kind::SecretKey,
                        &settings.host,
                        settings.port,
                        &settings.user,
                    )
                    .await?;
                    if let Some(id) = session_id {
                        cache.put(id, &secret).await;
                    }
                    secret
                }
            }
        }
    };

    let (secret, token) = split_secret(&secret);
    Ok(Keys {
        access: settings.user.clone(),
        secret,
        token,
    })
}

/// One cheap request that proves the endpoint is there and the key is good.
///
/// Which one depends on what the connection is rooted in: a pinned bucket is
/// asked about directly, because a key that may use exactly that bucket is the
/// normal case and listing every bucket would fail for it.
async fn reach(browser: &Browser) -> Result<RemoteSystem, String> {
    let bucket = browser.settings.bucket.trim();
    let call = if bucket.is_empty() {
        Call::new("GET", None, "")
    } else {
        Call::new("HEAD", Some(bucket), "")
    };
    let response = send(browser, call, None).await?;
    Ok(read_system(&browser.settings.host, &response))
}

/// Builds a browser and makes its first request, asking about the endpoint's
/// certificate where the system does not trust it — the same question, and
/// the same second attempt, as over FTPS (see `ftp::login_asking`).
///
/// Returns the browser, what answered, and how long the request that worked
/// took: the time the dialog was open is the user's, not the endpoint's.
async fn open(
    app: &AppHandle,
    settings: S3Settings,
    keys: Keys,
    home: String,
) -> Result<(Browser, RemoteSystem, Duration), String> {
    let proxy = crate::proxy::route(app, settings.proxy.as_ref())?;
    let pinning = Pinning::new(crate::certificates::pins(
        app,
        &settings.host,
        settings.port,
    )?);
    let browser = Browser {
        http: http_client(&settings, proxy.as_ref(), &pinning)?,
        settings,
        keys,
        home,
    };

    let started = Instant::now();
    let message = match reach(&browser).await {
        Ok(system) => return Ok((browser, system, started.elapsed())),
        Err(message) => message,
    };
    let Some(refused) = pinning.take_refused() else {
        return Err(message);
    };
    let pinning = crate::certificates::ask_and_trust(
        app,
        &browser.settings.host,
        browser.settings.port,
        &refused,
        &pinning,
    )
    .await?;
    let browser = Browser {
        http: http_client(&browser.settings, proxy.as_ref(), &pinning)?,
        ..browser
    };

    let started = Instant::now();
    let system = reach(&browser).await?;
    Ok((browser, system, started.elapsed()))
}

/// Opens the file browser on a tab and reports where it starts.
///
/// Called again after an error, and safe to: a browser that still answers is
/// kept, and one that does not is replaced.
#[tauri::command]
pub async fn s3_connect(
    app: AppHandle,
    state: State<'_, S3State>,
    cache: State<'_, Cache>,
    prompts: State<'_, Prompts>,
    session_id: String,
    settings: S3Settings,
) -> Result<String, String> {
    // Taken out of the map before anything is asked, so a slow endpoint does
    // not hold every other browser up behind the lock.
    let existing = state.0.lock().await.get(&session_id).cloned();
    if let Some(browser) = existing {
        if reach(&browser).await.is_ok() {
            return Ok(browser.home.clone());
        }
        state.close(&session_id).await;
    }

    let keys = credentials(&app, &cache, &prompts, Some(&session_id), &settings).await?;

    let bucket = settings.bucket.trim().to_string();
    let prefix = settings.prefix.trim().trim_matches('/').to_string();
    // The list of buckets where none was named. Everything below works in
    // absolute paths from here, the same as the other two protocols.
    let home = if bucket.is_empty() {
        "/".to_string()
    } else {
        path_of(&bucket, &prefix)
    };

    let (browser, system, _) = open(&app, settings, keys, home.clone()).await?;
    // For the card, the same as a test from the dialog would have stored.
    let _ = app.emit(&format!("system:{session_id}"), system);

    state.0.lock().await.insert(session_id, Arc::new(browser));
    Ok(home)
}

/// Closes the file browser and forgets what was typed for it.
#[tauri::command]
pub async fn s3_disconnect(
    state: State<'_, S3State>,
    edits: State<'_, EditWatchers>,
    cache: State<'_, Cache>,
    session_id: String,
) -> Result<(), String> {
    edits.stop_for_session(&session_id).await;
    state.close(&session_id).await;
    // A typed-in secret key lives exactly as long as the tab it was typed for.
    cache.forget(&session_id).await;
    Ok(())
}

/// Signs one request with the given settings, asks what answered, and stops.
///
/// Opens no browser and touches no stored session, so it is safe to run
/// against settings that are still being edited while other tabs are open.
#[tauri::command]
pub async fn s3_probe(
    app: AppHandle,
    cache: State<'_, Cache>,
    prompts: State<'_, Prompts>,
    settings: S3Settings,
) -> Result<Probe, String> {
    // Resolved before the clock starts: a secret typed into a dialog is not
    // something the endpoint should be timed on.
    let keys = credentials(&app, &cache, &prompts, None, &settings).await?;

    let (_, system, took) = open(&app, settings, keys, String::new()).await?;
    Ok(Probe {
        millis: took.as_millis() as u64,
        system: Some(system),
    })
}

// ---- Directories ------------------------------------------------------------------

/// One page of a listing.
///
/// `delimiter` is what makes a flat list of keys look like a tree: with it,
/// everything sharing a prefix up to the next slash comes back as one common
/// prefix instead of as its thousand objects. Without it — which is what the
/// walks below want — every key under the prefix arrives, however deep.
async fn list_page(
    browser: &Browser,
    bucket: &str,
    prefix: &str,
    delimiter: Option<&str>,
    token: Option<&str>,
) -> Result<Page, String> {
    let mut call = Call::new("GET", Some(bucket), "")
        .query("list-type", "2")
        .query("max-keys", PAGE_SIZE.to_string());
    if !prefix.is_empty() {
        call = call.query("prefix", prefix);
    }
    if let Some(delimiter) = delimiter {
        call = call.query("delimiter", delimiter);
    }
    if let Some(token) = token {
        call = call.query("continuation-token", token);
    }

    let body = send(browser, call, None)
        .await?
        .bytes()
        .await
        .map_err(|e| t!("s3.listing_read_failed", bucket = bucket, error = e).into_owned())?;
    Ok(parse_listing(&body))
}

/// Every object under a prefix, however deep — what deleting, moving and
/// copying a folder all need, since none of the three is one request in S3.
async fn collect_objects(
    browser: &Browser,
    bucket: &str,
    prefix: &str,
) -> Result<Vec<Object>, String> {
    let mut objects = Vec::new();
    let mut token: Option<String> = None;
    loop {
        let page = list_page(browser, bucket, prefix, None, token.as_deref()).await?;
        objects.extend(page.files);
        token = page.next;
        if token.is_none() {
            return Ok(objects);
        }
    }
}

/// [`collect_objects`], where only the names are wanted.
async fn collect_keys(
    browser: &Browser,
    bucket: &str,
    prefix: &str,
) -> Result<Vec<String>, String> {
    let objects = collect_objects(browser, bucket, prefix).await?;
    Ok(objects.into_iter().map(|object| object.key).collect())
}

/// The buckets this key may see, as the top of the tree.
///
/// Only reached where the connection names no bucket of its own. A key that is
/// scoped to one bucket may not list them, which is exactly why the setting
/// exists.
async fn bucket_listing(browser: &Browser) -> Result<Listing, String> {
    let body = send(browser, Call::new("GET", None, ""), None)
        .await?
        .bytes()
        .await
        .map_err(|e| t!("s3.buckets_read_failed", error = e).into_owned())?;

    let mut entries: Vec<Entry> = parse_buckets(&body)
        .into_iter()
        .map(|(name, created)| Entry {
            path: format!("/{name}"),
            name,
            is_dir: true,
            is_symlink: false,
            size: 0,
            // What a bucket has instead of a modification time. Better than an
            // empty column, and honest: nothing else about a bucket has a date.
            modified: created,
            permissions: None,
            mode: None,
        })
        .collect();
    files::sort(&mut entries);

    Ok(Listing {
        path: "/".to_string(),
        parent: None,
        entries,
        truncated: false,
    })
}

/// What sits above a directory, or `None` where nothing may.
///
/// A connection with a bucket of its own stops at that bucket's root rather
/// than offering a way up into a list of buckets the key probably may not see.
fn parent_of(browser: &Browser, bucket: &str, key: &str) -> Option<String> {
    if key.is_empty() {
        return browser
            .settings
            .bucket
            .trim()
            .is_empty()
            .then(|| "/".to_string());
    }
    files::remote_parent(&path_of(bucket, key))
}

#[tauri::command]
pub async fn s3_list(
    state: State<'_, S3State>,
    session_id: String,
    path: String,
) -> Result<Listing, String> {
    let browser = state.browser(&session_id).await?;
    listing(&browser, &path).await
}

/// One directory, as the pane draws it.
///
/// Apart from the commands rather than inside one so the live tests can reach
/// it: what a listing does with a folder marker and with a common prefix is
/// exactly the kind of thing that can only be settled against a real server.
async fn listing(browser: &Browser, path: &str) -> Result<Listing, String> {
    let location = locate(path);
    let Some(bucket) = location.bucket else {
        return bucket_listing(browser).await;
    };

    let prefix = listing_prefix(location.key);
    let mut entries: Vec<Entry> = Vec::new();
    let mut token: Option<String> = None;

    loop {
        let page = list_page(browser, bucket, &prefix, Some("/"), token.as_deref()).await?;

        for dir in page.dirs {
            entries.push(Entry {
                name: name_of(&dir),
                path: path_of(bucket, &dir),
                is_dir: true,
                is_symlink: false,
                size: 0,
                // A common prefix is not an object: there is nothing to have a
                // size or a date, and saying so is better than inventing one.
                modified: None,
                permissions: None,
                mode: None,
            });
        }

        for object in page.files {
            // The folder marker: the zero-byte object that *is* this
            // directory. It is not in it.
            if object.key == prefix {
                continue;
            }
            entries.push(Entry {
                name: name_of(&object.key),
                path: path_of(bucket, &object.key),
                is_dir: false,
                is_symlink: false,
                size: object.size,
                modified: object.modified,
                // S3 has no Unix permissions at all, which is what the dash in
                // the column and the greyed-out menu entry come from.
                permissions: None,
                mode: None,
            });
        }

        token = page.next;
        if token.is_none() || entries.len() >= LISTING_LIMIT {
            break;
        }
    }

    // Still a continuation token after the loop means it stopped at the limit
    // rather than at the end.
    let truncated = token.is_some();
    files::sort(&mut entries);
    Ok(Listing {
        parent: parent_of(browser, bucket, location.key),
        path: path_of(bucket, location.key),
        entries,
        truncated,
    })
}

/// Whether one key is there as an object.
async fn head(browser: &Browser, bucket: &str, key: &str) -> Result<Option<Response>, String> {
    match send(browser, Call::new("HEAD", Some(bucket), key), None).await {
        Ok(response) => Ok(Some(response)),
        // "Not there" is an answer, not a failure — but a refused key or an
        // unreachable host is a failure, and telling the two apart is the
        // whole point of not returning a bare bool here.
        // Matched against the same localized text [`failure`] produces.
        Err(message) if message.contains(&*t!("s3.not_found")) || message.contains("NoSuchKey") => {
            Ok(None)
        }
        Err(message) => Err(message),
    }
}

/// Whether a path exists — as an object, as a prefix with anything under it,
/// or as a bucket.
///
/// Three questions because S3 answers about objects only: a "directory" that
/// nothing was ever written into does not exist, and one with files in it
/// exists without any object of its own carrying the name.
#[tauri::command]
pub async fn s3_exists(
    state: State<'_, S3State>,
    session_id: String,
    path: String,
) -> Result<bool, String> {
    let browser = state.browser(&session_id).await?;
    exists(&browser, &path).await
}

async fn exists(browser: &Browser, path: &str) -> Result<bool, String> {
    let location = locate(path);
    let Some(bucket) = location.bucket else {
        return Ok(true);
    };
    if location.key.is_empty() {
        return Ok(send(browser, Call::new("HEAD", Some(bucket), ""), None)
            .await
            .is_ok());
    }

    if head(browser, bucket, location.key).await?.is_some() {
        return Ok(true);
    }
    let prefix = prefix_of(location.key);
    let page = list_page(browser, bucket, &prefix, Some("/"), None).await?;
    Ok(!page.dirs.is_empty() || !page.files.is_empty())
}

/// "New folder" — and at the top of the tree, a new bucket.
///
/// A folder is a zero-byte object whose name ends in a slash: the convention
/// the AWS console writes and every other client reads. It is what keeps an
/// empty folder on screen at all, and it is filtered back out of the listing
/// of the folder it stands for.
///
/// Called again for a directory that is already there — an upload into a tree
/// creates the same ones over and over — and that is fine: writing the marker
/// twice leaves exactly one.
#[tauri::command]
pub async fn s3_mkdir(
    state: State<'_, S3State>,
    session_id: String,
    path: String,
) -> Result<(), String> {
    let browser = state.browser(&session_id).await?;
    make_dir(&browser, &path).await
}

async fn make_dir(browser: &Browser, path: &str) -> Result<(), String> {
    let location = locate(path);
    let Some(bucket) = location.bucket else {
        return Err(t!("s3.name_needed").into_owned());
    };

    if location.key.is_empty() {
        return create_bucket(browser, bucket).await;
    }

    let marker = prefix_of(location.key);
    send(
        browser,
        Call::new("PUT", Some(bucket), &marker).body(Vec::new()),
        None,
    )
    .await
    .map(|_| ())
}

/// Creates a bucket.
///
/// "New folder" at the top of the tree, where a folder can only be a bucket.
/// Every region but `us-east-1` has to be named in the body — and saying it
/// there as well as in the signature is a quirk of the API, not a choice.
async fn create_bucket(browser: &Browser, bucket: &str) -> Result<(), String> {
    let region = browser.settings.region.trim();
    let body = if region.is_empty() || region == "us-east-1" {
        Vec::new()
    } else {
        format!(
            "<CreateBucketConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
             <LocationConstraint>{region}</LocationConstraint></CreateBucketConfiguration>"
        )
        .into_bytes()
    };

    send(browser, Call::new("PUT", Some(bucket), "").body(body), None)
        .await
        .map(|_| ())
}

/// Creates an empty object, and fails if something is already there.
///
/// "New file" beside "New folder", and the refusal is the point: this is
/// reached from a dialog that just asked for a name, where silently emptying
/// an existing object would be the one outcome nobody meant.
///
/// S3 has no exclusive-create flag — a `PUT` replaces whatever is there
/// without a word — so the check is all there is, and the window between it
/// and the write is the honest limit of what can be promised. The same limit
/// FTP has, for a different reason.
#[tauri::command]
pub async fn s3_create_file(
    state: State<'_, S3State>,
    session_id: String,
    path: String,
) -> Result<(), String> {
    let browser = state.browser(&session_id).await?;
    make_file(&browser, &path).await
}

async fn make_file(browser: &Browser, path: &str) -> Result<(), String> {
    let location = locate(path);
    let (Some(bucket), false) = (location.bucket, location.key.is_empty()) else {
        return Err(t!("s3.file_needs_bucket").into_owned());
    };

    if head(browser, bucket, location.key).await?.is_some() {
        return Err(t!("s3.already_exists", path = path).into_owned());
    }
    send(
        browser,
        Call::new("PUT", Some(bucket), location.key).body(Vec::new()),
        None,
    )
    .await
    .map(|_| ())
}

/// `x-amz-copy-source`: where a server-side copy reads from.
fn copy_source(bucket: &str, key: &str) -> String {
    format!("/{bucket}/{}", encode_path(key))
}

/// The storage class a copy has to name to stay where its source is.
///
/// A copy does not inherit the class: without the header it lands in
/// `STANDARD`, so an object in `STANDARD_IA` that was merely renamed would cost
/// differently afterwards. `STANDARD` itself is left unsaid — it is what the
/// copy gets anyway, and a server that is not AWS is spared a header it may
/// not know. The connection's own class is for uploads; a rename is not one.
fn kept_class(object: &Object) -> Option<&str> {
    object
        .storage_class
        .as_deref()
        .map(str::trim)
        .filter(|class| !class.is_empty() && *class != "STANDARD")
}

/// Copies one object, server-side. The bytes never come here.
async fn copy_object(
    browser: &Browser,
    from_bucket: &str,
    source: &Object,
    to_bucket: &str,
    to_key: &str,
) -> Result<(), String> {
    if source.size > MAX_COPY_SIZE {
        return copy_parts(browser, from_bucket, source, to_bucket, to_key).await;
    }

    let mut call = Call::new("PUT", Some(to_bucket), to_key)
        .header("x-amz-copy-source", copy_source(from_bucket, &source.key));
    if let Some(class) = kept_class(source) {
        call = call.header("x-amz-storage-class", class);
    }

    let response = send(browser, call, None).await?;
    // A copy can fail *after* the 200: the status is sent before the copy
    // finishes, and the error then arrives in the body. A client that only
    // looks at the status reports a move that never happened and then deletes
    // the source.
    let body = response
        .bytes()
        .await
        .map_err(|e| t!("s3.copy_failed", key = source.key, error = e).into_owned())?;
    match parse_error(&body) {
        Some(message) => Err(t!("s3.copy_failed", key = source.key, error = message).into_owned()),
        None => Ok(()),
    }
}

/// Whether a header of the source goes along with a copy made in parts.
///
/// `CopyObject` carries all of this over by itself. A multipart upload starts
/// with nothing and has to be told — and what is left out here is gone from
/// the copy, so it is everything a client set when it wrote the object.
fn carried(name: &str) -> bool {
    matches!(
        name,
        "content-type"
            | "content-encoding"
            | "content-disposition"
            | "content-language"
            | "cache-control"
            | "expires"
    ) || name.starts_with("x-amz-meta-")
}

/// A copy past [`MAX_COPY_SIZE`]: a multipart upload whose parts are ranges of
/// the source, each copied on the server (`UploadPartCopy`).
///
/// Every part names the source's `ETag`, so an object that is overwritten
/// while this runs fails the copy instead of producing one assembled from two
/// versions. Tags and ACLs are not carried over, as `CopyObject` would — the
/// first is a request of its own, the second a matter for the bucket.
async fn copy_parts(
    browser: &Browser,
    from_bucket: &str,
    source: &Object,
    to_bucket: &str,
    to_key: &str,
) -> Result<(), String> {
    let head = head(browser, from_bucket, &source.key)
        .await?
        .ok_or_else(|| t!("s3.does_not_exist", key = source.key).into_owned())?;
    let etag = head
        .headers()
        .get(reqwest::header::ETAG)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);

    let mut start = Call::new("POST", Some(to_bucket), to_key).query("uploads", "");
    for (name, value) in head.headers() {
        if !carried(name.as_str()) {
            continue;
        }
        // Metadata outside ASCII arrives encoded (RFC 2047), so this is a
        // header no server sends. Failing beats a copy that quietly lost it.
        let value = value
            .to_str()
            .map_err(|_| t!("s3.metadata_not_carried", key = source.key).into_owned())?;
        start = start.header(name.as_str(), value);
    }
    if let Some(class) = kept_class(source) {
        start = start.header("x-amz-storage-class", class);
    }
    let upload_id = begin_upload(browser, start, to_key).await?;

    let result = copy_ranges(
        browser,
        from_bucket,
        source,
        etag.as_deref(),
        to_bucket,
        to_key,
        &upload_id,
    )
    .await;
    if result.is_err() {
        abort_upload(browser, to_bucket, to_key, &upload_id).await;
    }
    result
}

/// The parts of [`copy_parts`], one range of the source each, and the request
/// that makes an object out of them.
async fn copy_ranges(
    browser: &Browser,
    from_bucket: &str,
    source: &Object,
    etag: Option<&str>,
    to_bucket: &str,
    to_key: &str,
    upload_id: &str,
) -> Result<(), String> {
    let total = source.size;
    let size = COPY_PART_SIZE.max(total.div_ceil(MAX_PARTS));
    let mut tags: Vec<(u64, String)> = Vec::new();
    let mut offset = 0u64;
    let mut number = 1u64;

    while offset < total {
        let end = (offset + size).min(total) - 1;
        let mut call = Call::new("PUT", Some(to_bucket), to_key)
            .query("partNumber", number.to_string())
            .query("uploadId", upload_id)
            .header("x-amz-copy-source", copy_source(from_bucket, &source.key))
            .header("x-amz-copy-source-range", format!("bytes={offset}-{end}"));
        if let Some(etag) = etag {
            call = call.header("x-amz-copy-source-if-match", etag);
        }

        let body = send(browser, call, None)
            .await?
            .bytes()
            .await
            .map_err(|e| {
                t!(
                    "s3.copy_part_failed",
                    number = number,
                    key = source.key,
                    error = e
                )
                .into_owned()
            })?;
        // Like `CopyObject`, a part can fail after the 200. Its receipt is in
        // the body, not in a header as with an uploaded part.
        if let Some(message) = parse_error(&body) {
            return Err(t!(
                "s3.copy_part_failed",
                number = number,
                key = source.key,
                error = message
            )
            .into_owned());
        }
        let tag = parse_field(&body, "ETag").ok_or_else(|| {
            t!(
                "s3.part_not_acknowledged",
                number = number,
                key = source.key
            )
            .into_owned()
        })?;

        tags.push((number, tag));
        offset = end + 1;
        number += 1;
    }

    complete_upload(browser, to_bucket, to_key, upload_id, &tags).await
}

async fn delete_object(browser: &Browser, bucket: &str, key: &str) -> Result<(), String> {
    send(browser, Call::new("DELETE", Some(bucket), key), None)
        .await
        .map(|_| ())
}

/// Deletes many objects, several at a time.
///
/// One request per object: the batch call S3 offers wants a `Content-MD5` of
/// its body, which would mean a second hash function in this app for one
/// call — and it is not implemented everywhere either. Sixteen at once gets a
/// tree of small files down to something that feels like deleting a folder.
async fn delete_keys(
    browser: &Arc<Browser>,
    bucket: &str,
    keys: Vec<String>,
    cancel: Option<&AtomicBool>,
) -> Result<(), String> {
    let mut running: JoinSet<Result<(), String>> = JoinSet::new();
    let mut failure: Option<String> = None;
    let mut stopped = false;

    for key in keys {
        // What is already on the wire finishes; nothing new is started.
        if cancel.is_some_and(|flag| flag.load(Ordering::Relaxed)) {
            stopped = true;
            break;
        }
        while running.len() >= DELETE_PARALLEL {
            if let Some(done) = running.join_next().await {
                note(done, &mut failure);
            }
        }
        let browser = Arc::clone(browser);
        let bucket = bucket.to_string();
        running.spawn(async move { delete_object(&browser, &bucket, &key).await });
    }
    while let Some(done) = running.join_next().await {
        note(done, &mut failure);
    }

    match failure {
        Some(message) => Err(message),
        None if stopped => Err(CANCELLED.to_string()),
        None => Ok(()),
    }
}

/// Keeps the first thing that went wrong and lets the rest finish.
///
/// Stopping at the first refusal would leave a half-deleted tree *and* the
/// objects that were perfectly deletable, which is the worst of both.
fn note(outcome: Result<Result<(), String>, tokio::task::JoinError>, failure: &mut Option<String>) {
    let message = match outcome {
        Ok(Ok(())) => return,
        Ok(Err(message)) => message,
        Err(e) => t!("s3.deletion_unfinished", error = e).into_owned(),
    };
    failure.get_or_insert(message);
}

/// Moves a name, which in S3 means copying and then deleting.
///
/// A folder is every key under its prefix, one copy and one delete each. There
/// is no atomic form of this and no way to make one: a rename of a thousand
/// objects that fails halfway leaves half of them moved, and the pane's error
/// line is where that is said.
#[tauri::command]
pub async fn s3_rename(
    state: State<'_, S3State>,
    session_id: String,
    from: String,
    to: String,
) -> Result<(), String> {
    let browser = state.browser(&session_id).await?;
    move_key(&browser, &from, &to).await
}

async fn move_key(browser: &Arc<Browser>, from: &str, to: &str) -> Result<(), String> {
    let source = locate(from);
    let target = locate(to);

    let (Some(from_bucket), Some(to_bucket)) = (source.bucket, target.bucket) else {
        return Err(t!("s3.bucket_not_renamable").into_owned());
    };
    if source.key.is_empty() || target.key.is_empty() {
        return Err(t!("s3.bucket_not_renamable").into_owned());
    }

    // The object itself, where there is one, plus everything below it as a
    // prefix. Both, because a key and a folder of the same name can exist side
    // by side — `note.txt` and `note.txt/` are two different keys. Size and
    // storage class come along: the first decides how the copy is made, the
    // second where it lands.
    let mut moves: Vec<(Object, String)> = Vec::new();
    if let Some(response) = head(browser, from_bucket, source.key).await? {
        let object = Object {
            key: source.key.to_string(),
            size: header_u64(&response, reqwest::header::CONTENT_LENGTH).unwrap_or(0),
            modified: None,
            storage_class: response
                .headers()
                .get("x-amz-storage-class")
                .and_then(|value| value.to_str().ok())
                .map(str::to_string),
        };
        moves.push((object, target.key.to_string()));
    }
    let prefix = prefix_of(source.key);
    for object in collect_objects(browser, from_bucket, &prefix).await? {
        let rest = object
            .key
            .strip_prefix(&prefix)
            .unwrap_or_default()
            .to_string();
        moves.push((object, format!("{}/{rest}", target.key)));
    }
    if moves.is_empty() {
        return Err(t!("s3.does_not_exist", key = from).into_owned());
    }

    for (object, to_key) in &moves {
        copy_object(browser, from_bucket, object, to_bucket, to_key).await?;
    }
    delete_keys(
        browser,
        from_bucket,
        moves.into_iter().map(|(object, _)| object.key).collect(),
        None,
    )
    .await
}

/// Deletes an object, or everything under a prefix.
///
/// A bucket is the one thing this will not empty first: `DELETE` on a bucket
/// that still holds something is refused by the server, and that refusal is
/// the safety net. Emptying a whole bucket because somebody pressed Delete on
/// the wrong row in a list of buckets is not a thing this app should be able
/// to do.
#[tauri::command]
pub async fn s3_remove(
    state: State<'_, S3State>,
    transfers: State<'_, Transfers>,
    session_id: String,
    path: String,
    is_dir: bool,
    operation_id: Option<String>,
) -> Result<(), String> {
    let browser = state.browser(&session_id).await?;
    let cancel = transfers.begin(&operation_id).await;
    let result = remove_path(&browser, &path, is_dir, Some(&cancel)).await;
    transfers.end(&operation_id).await;
    result
}

async fn remove_path(
    browser: &Arc<Browser>,
    path: &str,
    is_dir: bool,
    cancel: Option<&AtomicBool>,
) -> Result<(), String> {
    let location = locate(path);
    let Some(bucket) = location.bucket else {
        return Err(t!("s3.nothing_above_buckets").into_owned());
    };

    if location.key.is_empty() {
        return send(browser, Call::new("DELETE", Some(bucket), ""), None)
            .await
            .map(|_| ());
    }
    if !is_dir {
        return delete_object(browser, bucket, location.key).await;
    }

    // The marker object is part of what the prefix lists, so it goes with the
    // rest and needs no case of its own.
    let keys = collect_keys(browser, bucket, &prefix_of(location.key)).await?;
    delete_keys(browser, bucket, keys, cancel).await
}

// ---- Left-behind uploads ----------------------------------------------------------
//
// A multipart upload that is neither finished nor aborted keeps its parts in
// the bucket: in no listing, and billed all the same. This app aborts its own
// on every failure, but a process that is killed aborts nothing — and other
// programs leave theirs too. Nobody else will mention them, so the pane does
// when a bucket is opened.

/// What the pane says about a bucket's left-behind uploads.
#[derive(Serialize, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct StaleUploads {
    pub bucket: String,
    pub count: usize,
    /// When the oldest was started, Unix seconds.
    pub oldest: Option<i64>,
}

/// The uploads in a bucket older than [`STALE_UPLOAD_SECONDS`].
///
/// Limited to the connection's prefix where it is rooted in this bucket: a key
/// scoped to that prefix may not list the rest, and what lies outside it is
/// not this connection's business either. One without a start date is left
/// out — its age is unknown, and unknown is not old.
async fn stale_uploads(browser: &Browser, bucket: &str) -> Result<Vec<Upload>, String> {
    let cutoff = Utc::now().timestamp() - STALE_UPLOAD_SECONDS;
    let prefix = browser.settings.prefix.trim().trim_matches('/');
    let rooted = browser.settings.bucket.trim() == bucket && !prefix.is_empty();

    let mut stale = Vec::new();
    let mut marker: Option<(String, String)> = None;
    loop {
        let mut call = Call::new("GET", Some(bucket), "").query("uploads", "");
        if rooted {
            call = call.query("prefix", format!("{prefix}/"));
        }
        if let Some((key, id)) = &marker {
            call = call
                .query("key-marker", key.as_str())
                .query("upload-id-marker", id.as_str());
        }
        let body = send(browser, call, None)
            .await?
            .bytes()
            .await
            .map_err(|e| t!("s3.uploads_read_failed", bucket = bucket, error = e).into_owned())?;

        let page = parse_uploads(&body);
        stale.extend(
            page.uploads
                .into_iter()
                .filter(|upload| upload.initiated.is_some_and(|at| at < cutoff)),
        );
        marker = page.next;
        if marker.is_none() {
            return Ok(stale);
        }
    }
}

/// Whether the bucket a path is in holds left-behind uploads. `None` above the
/// buckets, and where there are none.
#[tauri::command]
pub async fn s3_stale_uploads(
    state: State<'_, S3State>,
    session_id: String,
    path: String,
) -> Result<Option<StaleUploads>, String> {
    let browser = state.browser(&session_id).await?;
    let Some(bucket) = locate(&path).bucket else {
        return Ok(None);
    };
    let uploads = stale_uploads(&browser, bucket).await?;
    if uploads.is_empty() {
        return Ok(None);
    }
    Ok(Some(StaleUploads {
        bucket: bucket.to_string(),
        count: uploads.len(),
        oldest: uploads.iter().filter_map(|upload| upload.initiated).min(),
    }))
}

/// Aborts the left-behind uploads in a bucket and says how many went.
///
/// Asks the server again rather than taking a list from the pane: what is old
/// is decided here, at the moment of deleting, and an upload that finished in
/// the meantime is simply no longer listed. Every one is tried; the first
/// refusal is what is reported.
#[tauri::command]
pub async fn s3_abort_stale_uploads(
    state: State<'_, S3State>,
    session_id: String,
    bucket: String,
) -> Result<usize, String> {
    let browser = state.browser(&session_id).await?;
    let mut aborted = 0;
    let mut failure: Option<String> = None;
    for upload in stale_uploads(&browser, &bucket).await? {
        let call = Call::new("DELETE", Some(&bucket), &upload.key).query("uploadId", upload.id);
        match send(&browser, call, None).await {
            Ok(_) => aborted += 1,
            Err(message) => {
                failure.get_or_insert(
                    t!("s3.abort_upload_failed", key = upload.key, error = message).into_owned(),
                );
            }
        }
    }
    match failure {
        Some(message) => Err(message),
        None => Ok(aborted),
    }
}

// ---- Permissions -----------------------------------------------------------------

/// There are none.
///
/// The command exists because the file browser asks the same questions of
/// every protocol, and it fails plainly rather than being missing: a missing
/// command reaches the pane as "unknown command", which reads like a bug. In
/// practice nothing calls it — a listing with no mode bits greys the menu
/// entry out.
///
/// What S3 has instead is ACLs and bucket policies, which are a different
/// thing with different words and do not belong behind a chmod dialog. See
/// TODO.md.
#[tauri::command]
pub async fn s3_chmod(
    _session_id: String,
    _path: String,
    _mode: u32,
    _recursive: bool,
) -> Result<(), String> {
    Err(t!("s3.no_permissions").into_owned())
}

// ---- Transfers --------------------------------------------------------------------
//
// What a transfer looks like from outside — the queue rows, the progress
// events, what "cancel" means — is decided in [`crate::transfer`] and is
// the same over all three protocols. What differs here is the direction:
//
// - **Downloading** is a `GET`, resumed with a `Range` header, written to
//   `{target}.wtpart` and renamed into place at the end, exactly as elsewhere.
// - **Uploading** is a `PUT`, or a multipart upload for anything large, and
//   has no `.wtpart` at all: S3 publishes an object when it is whole or never,
//   so there is nothing half-written for a fragment to protect against — and
//   nothing to carry on from either.

/// What is in the `x-amz-storage-class` header, if anything.
///
/// Empty for everything that is not AWS, which is what those servers expect
/// to hear: a storage class they do not know is refused outright.
fn storage_class(browser: &Browser) -> Option<String> {
    let class = browser.settings.storage_class.trim();
    (!class.is_empty()).then(|| class.to_string())
}

/// How large one part of a multipart upload is.
///
/// [`PART_SIZE`] unless the file is so large that 10 000 of them would not
/// cover it — S3's limit on parts, and the only reason this is a function.
fn part_size(total: u64) -> u64 {
    PART_SIZE.max(total.div_ceil(MAX_PARTS))
}

fn header_u64(response: &Response, name: reqwest::header::HeaderName) -> Option<u64> {
    response.headers().get(name)?.to_str().ok()?.parse().ok()
}

/// `Wed, 01 May 2024 12:34:56 GMT`, which is what HTTP dates look like.
fn http_date(value: &str) -> Option<i64> {
    DateTime::parse_from_rfc2822(value)
        .ok()
        .map(|stamp| stamp.timestamp())
}

/// The body of one upload: a piece of a local file, read as it is sent.
///
/// Its whole reason for existing is [`HttpBody::size_hint`]. S3 refuses a
/// `PUT` without a `Content-Length`, and a body that is a stream has none —
/// so a plain stream would be sent chunked and rejected. This one knows
/// exactly how many bytes are coming, which is what puts the header there.
struct FileBody {
    chunks: mpsc::Receiver<Result<Bytes, std::io::Error>>,
    remaining: u64,
}

impl HttpBody for FileBody {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        match self.chunks.poll_recv(context) {
            Poll::Ready(Some(Ok(bytes))) => {
                self.remaining = self.remaining.saturating_sub(bytes.len() as u64);
                Poll::Ready(Some(Ok(Frame::data(bytes))))
            }
            Poll::Ready(Some(Err(problem))) => Poll::Ready(Some(Err(problem))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(self.remaining)
    }
}

/// One piece of a file on its way out.
struct Feed {
    local: String,
    offset: u64,
    length: u64,
    /// Bytes sent by this whole transfer, across every part of it. What the
    /// queue's bar is drawn from, so a multipart upload does not restart at
    /// zero for each part.
    moved: Arc<AtomicU64>,
    reporter: Arc<Mutex<Reporter>>,
    cancel: Arc<AtomicBool>,
}

/// Starts reading the file into a request body and hands the body back.
///
/// The reading runs in a task of its own, because a body is pulled by the
/// connection rather than pushed by us. The channel is two chunks deep: that
/// is enough that the socket never waits for the disk, and shallow enough that
/// "this much has been transferred" stays close to the truth — bytes counted here have
/// nowhere left to go but the wire.
fn feed(feed: Feed) -> reqwest::Body {
    let (sender, chunks) = mpsc::channel::<Result<Bytes, std::io::Error>>(2);
    let length = feed.length;

    tauri::async_runtime::spawn(async move {
        let mut file = match fs::File::open(&feed.local).await {
            Ok(file) => file,
            Err(problem) => {
                let _ = sender.send(Err(problem)).await;
                return;
            }
        };
        if feed.offset > 0 {
            if let Err(problem) = file.seek(SeekFrom::Start(feed.offset)).await {
                let _ = sender.send(Err(problem)).await;
                return;
            }
        }

        let mut left = feed.length;
        let mut buffer = vec![0u8; CHUNK];
        while left > 0 {
            if feed.cancel.load(Ordering::Relaxed) {
                // Fails the body, which fails the request. The caller turns
                // that back into "cancelled" by looking at the same flag.
                let _ = sender.send(Err(std::io::Error::other(CANCELLED))).await;
                return;
            }
            let want = left.min(CHUNK as u64) as usize;
            match file.read(&mut buffer[..want]).await {
                // Shorter than the length promised in the header, which is the
                // one thing that must not be sent silently: the server would
                // wait for bytes that are never coming.
                Ok(0) => {
                    let _ = sender
                        .send(Err(std::io::Error::other(
                            t!("s3.file_shortened").into_owned(),
                        )))
                        .await;
                    return;
                }
                Ok(read) => {
                    if sender
                        .send(Ok(Bytes::copy_from_slice(&buffer[..read])))
                        .await
                        .is_err()
                    {
                        // Nobody is reading any more: the request failed or
                        // was dropped, and the error belongs to whoever is
                        // awaiting it.
                        return;
                    }
                    left -= read as u64;
                    let total = feed.moved.fetch_add(read as u64, Ordering::Relaxed) + read as u64;
                    feed.reporter.lock().await.report(total, false);
                }
                Err(problem) => {
                    let _ = sender.send(Err(problem)).await;
                    return;
                }
            }
        }
    });

    reqwest::Body::wrap(FileBody {
        chunks,
        remaining: length,
    })
}

/// Turns a failed request into "cancelled" where that is what it was.
///
/// A cancelled upload fails as a broken request body, and what reqwest says
/// about that describes the plumbing rather than what happened. The flag is
/// the truth.
fn stopped(cancel: &AtomicBool, message: String) -> String {
    if cancel.load(Ordering::Relaxed) {
        CANCELLED.to_string()
    } else {
        message
    }
}

/// Fetches one object, reporting as it goes. Returns the bytes moved.
///
/// Writes to `{local}.wtpart` and only renames it onto `local` once every byte
/// has arrived, so a reader of `local` only ever sees nothing or the whole
/// file. A fragment left by a stopped attempt is kept on purpose: that is what
/// lets a later attempt carry on from it.
///
/// Whether it may be carried on from is [`crate::resume`]'s question. The
/// object's size and its `Last-Modified` are what that check has to go on —
/// both come from one `HEAD`, which is also how the progress bar learns its
/// total.
async fn download(
    app: &AppHandle,
    browser: &Browser,
    partials: &Partials,
    cancel: &AtomicBool,
    job: &Job<'_>,
) -> Result<u64, String> {
    let Job { local, remote, .. } = *job;
    let location = locate(remote);
    let (Some(bucket), false) = (location.bucket, location.key.is_empty()) else {
        return Err(t!("s3.not_an_object", path = remote).into_owned());
    };

    let head = send(browser, Call::new("HEAD", Some(bucket), location.key), None).await?;
    let total = header_u64(&head, reqwest::header::CONTENT_LENGTH).unwrap_or(0);
    let modified = head
        .headers()
        .get(reqwest::header::LAST_MODIFIED)
        .and_then(|value| value.to_str().ok())
        .and_then(http_date)
        .unwrap_or(0);

    let source = Partial {
        source: remote.to_string(),
        size: total,
        modified,
    };
    let resumable = partials.resumable(app, local, &source).await;

    let result = fetch(
        Reporter::new(app, job.session_id, job.transfer_id, total),
        browser,
        cancel,
        job,
        bucket,
        location.key,
        total,
        resumable,
    )
    .await;

    match &result {
        // Renamed into place, so there is no fragment left to describe.
        Ok(_) => partials.forget(app, local).await,
        Err(_) => {
            let working = format!("{local}{WORKING_SUFFIX}");
            if fs::metadata(&working).await.map(|m| m.len()).unwrap_or(0) > 0 {
                partials.remember(app, local, source).await;
            }
        }
    }
    result
}

/// The bytes of a download, once [`download`] has settled whether the fragment
/// already on disk may be continued from.
///
/// Takes the reporter rather than making one, which is what lets the live
/// tests run this against a real endpoint: everything else it needs is a
/// bucket, a key and somewhere to put the bytes.
#[allow(clippy::too_many_arguments)]
async fn fetch(
    mut reporter: Reporter,
    browser: &Browser,
    cancel: &AtomicBool,
    job: &Job<'_>,
    bucket: &str,
    key: &str,
    total: u64,
    resumable: bool,
) -> Result<u64, String> {
    let Job { local, .. } = *job;

    let working = format!("{local}{WORKING_SUFFIX}");
    // A fragment longer than the object it is meant to be a prefix of cannot
    // be one, whatever the notes say.
    let existing = fs::metadata(&working).await.map(|m| m.len()).unwrap_or(0);
    let mut start = match resumable && existing <= total {
        true => existing,
        false => 0,
    };

    reporter.report(start, true);

    // The queue creates the directories it needs before enqueuing, but a
    // single file dropped into a fresh target is the common case and this
    // costs nothing.
    if let Some(parent) = Path::new(&working).parent() {
        let _ = fs::create_dir_all(parent).await;
    }

    let mut moved = start;
    if start < total {
        let mut call = Call::new("GET", Some(bucket), key);
        if start > 0 {
            call = call.header("range", format!("bytes={start}-"));
        }
        let mut response = send(browser, call, None).await?;

        // A range that was asked for and not granted comes back as a whole
        // object with status 200. Writing that onto the fragment would put the
        // file's first bytes after its middle, so the fragment is dropped and
        // the download starts again — which is slower and correct.
        if start > 0 && response.status() != StatusCode::PARTIAL_CONTENT {
            start = 0;
            moved = 0;
            reporter.report(0, true);
        }

        let mut target = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .append(start > 0)
            .truncate(start == 0)
            .open(&working)
            .await
            .map_err(|e| t!("s3.write_failed", path = local, error = e).into_owned())?;

        loop {
            if cancel.load(Ordering::Relaxed) {
                // Returned without reading the rest: dropping the response
                // closes the connection, and reqwest hands the socket back or
                // throws it away as it sees fit.
                return Err(CANCELLED.to_string());
            }
            let chunk = response
                .chunk()
                .await
                .map_err(|e| t!("s3.read_failed", path = key, error = e).into_owned())?;
            let Some(chunk) = chunk else {
                break;
            };
            target
                .write_all(&chunk)
                .await
                .map_err(|e| t!("s3.write_failed", path = local, error = e).into_owned())?;
            moved += chunk.len() as u64;
            reporter.report(moved, false);
        }

        target
            .flush()
            .await
            .map_err(|e| t!("s3.write_failed", path = local, error = e).into_owned())?;
    } else if start == 0 {
        // An empty object. `create` truncates, which is what a fragment left
        // by some earlier, longer file needs: it is not a prefix of an empty
        // file either, and the rename below would otherwise put its tail in
        // place.
        fs::File::create(&working)
            .await
            .map_err(|e| t!("s3.write_failed", path = local, error = e).into_owned())?;
    }

    fs::rename(&working, local)
        .await
        .map_err(|e| t!("s3.finish_failed", path = local, error = e).into_owned())?;
    reporter.report(moved, true);
    Ok(moved)
}

/// Sends one file up, reporting as it goes.
///
/// One `PUT` for anything ordinary. Above [`MULTIPART_THRESHOLD`] it becomes a
/// multipart upload, because a single `PUT` that dies at 90 % has to start
/// over — and past 5 GiB S3 will not take one at all.
///
/// Nothing is written under a working name and nothing is left behind: the
/// object appears when it is complete. A cancelled multipart upload is aborted
/// here, so its parts do not sit in the bucket costing money invisibly.
async fn upload(
    app: &AppHandle,
    browser: &Browser,
    cancel: Arc<AtomicBool>,
    job: &Job<'_>,
) -> Result<u64, String> {
    let Job {
        session_id,
        transfer_id,
        local,
        remote,
    } = *job;
    let location = locate(remote);
    let (Some(bucket), false) = (location.bucket, location.key.is_empty()) else {
        return Err(t!("s3.not_an_upload_target", path = remote).into_owned());
    };

    let total = fs::metadata(local)
        .await
        .map_err(|e| t!("s3.read_failed", path = local, error = e).into_owned())?
        .len();

    let reporter = Arc::new(Mutex::new(Reporter::new(
        app,
        session_id,
        transfer_id,
        total,
    )));
    reporter.lock().await.report(0, true);
    let moved = Arc::new(AtomicU64::new(0));

    if total < MULTIPART_THRESHOLD {
        put_object(
            browser,
            bucket,
            location.key,
            local,
            total,
            &moved,
            &reporter,
            &cancel,
        )
        .await?;
    } else {
        put_parts(
            browser,
            bucket,
            location.key,
            local,
            total,
            &moved,
            &reporter,
            &cancel,
        )
        .await?;
    }

    reporter.lock().await.report(total, true);
    Ok(total)
}

/// One `PUT` with the whole file behind it.
#[allow(clippy::too_many_arguments)]
async fn put_object(
    browser: &Browser,
    bucket: &str,
    key: &str,
    local: &str,
    total: u64,
    moved: &Arc<AtomicU64>,
    reporter: &Arc<Mutex<Reporter>>,
    cancel: &Arc<AtomicBool>,
) -> Result<(), String> {
    let body = feed(Feed {
        local: local.to_string(),
        offset: 0,
        length: total,
        moved: Arc::clone(moved),
        reporter: Arc::clone(reporter),
        cancel: Arc::clone(cancel),
    });

    let mut call = Call::new("PUT", Some(bucket), key).streamed();
    if let Some(class) = storage_class(browser) {
        call = call.header("x-amz-storage-class", class);
    }

    send(browser, call, Some(body))
        .await
        .map(|_| ())
        .map_err(|e| stopped(cancel, e))
}

/// A multipart upload: begin, send the pieces, put them together.
///
/// Every exit but the successful one aborts the upload. An abandoned
/// multipart upload keeps its parts in the bucket, invisible in every listing
/// and billed like anything else — which is the one way this app could quietly
/// cost somebody money.
#[allow(clippy::too_many_arguments)]
async fn put_parts(
    browser: &Browser,
    bucket: &str,
    key: &str,
    local: &str,
    total: u64,
    moved: &Arc<AtomicU64>,
    reporter: &Arc<Mutex<Reporter>>,
    cancel: &Arc<AtomicBool>,
) -> Result<(), String> {
    let mut start = Call::new("POST", Some(bucket), key).query("uploads", "");
    if let Some(class) = storage_class(browser) {
        start = start.header("x-amz-storage-class", class);
    }
    let upload_id = begin_upload(browser, start, key).await?;

    let result = send_parts(
        browser, bucket, key, local, total, &upload_id, moved, reporter, cancel,
    )
    .await;

    if result.is_err() {
        abort_upload(browser, bucket, key, &upload_id).await;
    }
    result
}

/// Starts a multipart upload with the given `POST …?uploads` and returns its id.
async fn begin_upload(browser: &Browser, start: Call<'_>, key: &str) -> Result<String, String> {
    let answer = send(browser, start, None)
        .await?
        .bytes()
        .await
        .map_err(|e| t!("s3.upload_start_failed", key = key, error = e).into_owned())?;
    parse_field(&answer, "UploadId")
        .ok_or_else(|| t!("s3.upload_not_named", key = key).into_owned())
}

/// Throws a multipart upload away, parts and all.
///
/// Best effort: where this is called the upload has already failed, and a
/// failed abort would only replace the message that says why.
async fn abort_upload(browser: &Browser, bucket: &str, key: &str, upload_id: &str) {
    let _ = send(
        browser,
        Call::new("DELETE", Some(bucket), key).query("uploadId", upload_id),
        None,
    )
    .await;
}

/// Puts the parts together into the object.
async fn complete_upload(
    browser: &Browser,
    bucket: &str,
    key: &str,
    upload_id: &str,
    tags: &[(u64, String)],
) -> Result<(), String> {
    let mut xml = String::from("<CompleteMultipartUpload>");
    for (number, tag) in tags {
        xml.push_str(&format!(
            "<Part><PartNumber>{number}</PartNumber><ETag>{tag}</ETag></Part>"
        ));
    }
    xml.push_str("</CompleteMultipartUpload>");

    let answer = send(
        browser,
        Call::new("POST", Some(bucket), key)
            .query("uploadId", upload_id)
            .body(xml.into_bytes()),
        None,
    )
    .await?
    .bytes()
    .await
    .map_err(|e| t!("s3.finish_failed", path = key, error = e).into_owned())?;

    // Putting the parts together can fail after the 200: the status goes out
    // before the work is done, so that a long assembly does not look like a
    // dead connection. A client that only reads the status reports an upload
    // that does not exist.
    match parse_error(&answer) {
        Some(message) => Err(t!("s3.finish_failed", path = key, error = message).into_owned()),
        None => Ok(()),
    }
}

/// The parts themselves, and the request that makes an object out of them.
#[allow(clippy::too_many_arguments)]
async fn send_parts(
    browser: &Browser,
    bucket: &str,
    key: &str,
    local: &str,
    total: u64,
    upload_id: &str,
    moved: &Arc<AtomicU64>,
    reporter: &Arc<Mutex<Reporter>>,
    cancel: &Arc<AtomicBool>,
) -> Result<(), String> {
    let size = part_size(total);
    let mut tags: Vec<(u64, String)> = Vec::new();
    let mut offset = 0u64;
    let mut number = 1u64;

    while offset < total {
        if cancel.load(Ordering::Relaxed) {
            return Err(CANCELLED.to_string());
        }
        let length = size.min(total - offset);
        let body = feed(Feed {
            local: local.to_string(),
            offset,
            length,
            moved: Arc::clone(moved),
            reporter: Arc::clone(reporter),
            cancel: Arc::clone(cancel),
        });

        let response = send(
            browser,
            Call::new("PUT", Some(bucket), key)
                .query("partNumber", number.to_string())
                .query("uploadId", upload_id)
                .streamed(),
            Some(body),
        )
        .await
        .map_err(|e| stopped(cancel, e))?;

        // The part's receipt. Without it the final request cannot name the
        // part, and S3 checks that what is named is what arrived.
        let tag = response
            .headers()
            .get(reqwest::header::ETAG)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string)
            .ok_or_else(|| {
                t!("s3.part_not_acknowledged", number = number, key = key).into_owned()
            })?;

        tags.push((number, tag));
        offset += length;
        number += 1;
    }

    complete_upload(browser, bucket, key, upload_id, &tags).await
}

/// Fetches one object into a local file.
#[allow(clippy::too_many_arguments)]
#[tauri::command]
pub async fn s3_download(
    app: AppHandle,
    state: State<'_, S3State>,
    transfers: State<'_, Transfers>,
    partials: State<'_, Partials>,
    session_id: String,
    transfer_id: String,
    remote: String,
    local: String,
) -> Result<u64, String> {
    let browser = state.browser(&session_id).await?;
    let cancel = transfers.start(&transfer_id).await;

    let job = Job {
        session_id: &session_id,
        transfer_id: &transfer_id,
        local: &local,
        remote: &remote,
    };
    let result = download(&app, &browser, &partials, &cancel, &job).await;

    transfers.finish(&transfer_id).await;
    result
}

/// Sends one local file up as an object. The mirror of [`s3_download`].
#[allow(clippy::too_many_arguments)]
#[tauri::command]
pub async fn s3_upload(
    app: AppHandle,
    state: State<'_, S3State>,
    transfers: State<'_, Transfers>,
    session_id: String,
    transfer_id: String,
    local: String,
    remote: String,
) -> Result<u64, String> {
    let browser = state.browser(&session_id).await?;
    let cancel = transfers.start(&transfer_id).await;

    let job = Job {
        session_id: &session_id,
        transfer_id: &transfer_id,
        local: &local,
        remote: &remote,
    };
    let result = upload(&app, &browser, Arc::clone(&cancel), &job).await;

    transfers.finish(&transfer_id).await;
    result
}

/// Throws away what a stopped transfer left behind.
///
/// Which, upwards, is nothing: an interrupted upload leaves no object and no
/// parts — [`put_parts`] aborts its own upload — so "Discard" on an upload
/// row only has to take the row away. Downwards it is the usual `.wtpart`
/// fragment and the note that describes it.
#[tauri::command]
pub async fn s3_discard(
    app: AppHandle,
    partials: State<'_, Partials>,
    // Taken and ignored, because the file browser asks all three protocols the
    // same question and only some of them have an answer that needs these.
    _session_id: String,
    direction: String,
    local: String,
    _remote: String,
) -> Result<(), String> {
    if direction != "download" {
        return Ok(());
    }
    let _ = fs::remove_file(format!("{local}{WORKING_SUFFIX}")).await;
    partials.forget(&app, &local).await;
    Ok(())
}

// ---- Links ------------------------------------------------------------------------

/// A link to one object that works without an access key.
///
/// The one thing S3 offers that neither SFTP nor FTP has anything like:
/// a URL that carries its own signature, valid for as long as it says, and
/// good for reading exactly this one object. It is how a file in a private
/// bucket gets sent to somebody who has no account — instead of downloading it
/// here and mailing it on.
///
/// The link contains the access key id (not the secret) and the signature, so
/// it is worth saying out loud what it is: anyone who has it can fetch the
/// object until it expires. That is what the dialog says, and it is why the
/// shortest useful validity is the default there rather than the longest.
#[tauri::command]
pub async fn s3_link(
    state: State<'_, S3State>,
    session_id: String,
    path: String,
    seconds: u64,
) -> Result<String, String> {
    let browser = state.browser(&session_id).await?;
    let location = locate(&path);
    let (Some(bucket), false) = (location.bucket, location.key.is_empty()) else {
        return Err(t!("s3.link_file_only").into_owned());
    };

    // SigV4 refuses anything longer, and a link that the server rejects is
    // worse than one that expires.
    let seconds = seconds.clamp(60, MAX_LINK_SECONDS);
    Ok(presign(
        &browser.settings,
        &browser.keys,
        bucket,
        location.key,
        seconds,
        Utc::now(),
    ))
}

// ---- Edit on server -----------------------------------------------------------------
//
// How an edit works lives in [`crate::edit`]; what is here is the S3 half of
// it. Saving replaces the whole object — there is no writing into the middle
// of one — which is exactly what an editor does anyway.

/// Downloads a copy to edit and starts watching it.
#[tauri::command]
pub async fn s3_edit_open(
    app: AppHandle,
    state: State<'_, S3State>,
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

    let cancel = AtomicBool::new(false);
    let job = Job {
        session_id: &session_id,
        transfer_id: &id,
        local: &local,
        remote: &remote,
    };
    download(&app, &browser, &partials, &cancel, &job).await?;

    // Registered before the editor starts, so the flag exists for the process
    // watcher to set the moment it does.
    let stop = watchers.register(&id, &session_id).await;
    let opened = edit::open_editor(&app, editor, &local, &id, &stop)?;

    tauri::async_runtime::spawn(edit::watch(app.clone(), stop, id.clone(), local.clone(), {
        // The browser is held by the closure rather than looked up again: an
        // edit outlives any one listing, and what it needs — the endpoint and
        // the keys — is in there.
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
                let cancel = Arc::new(AtomicBool::new(false));
                let job = Job {
                    session_id: &session_id,
                    transfer_id: &id,
                    local: &local,
                    remote: &remote,
                };
                upload(&app, &browser, cancel, &job).await.map(|_| ())
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

    #[test]
    fn describes_the_endpoint() {
        let hetzner = describe("fsn1.your-objectstorage.com", Some("Ceph"));
        assert_eq!(hetzner.id, "hetzner");
        let minio = describe("s3.example.org", Some("MinIO"));
        assert_eq!((minio.id.as_str(), minio.name.as_str()), ("minio", "MinIO"));
        let silent = describe("s3.example.org", None);
        assert_eq!(
            (silent.id.as_str(), silent.name.as_str()),
            ("objectstore", "S3")
        );
    }

    fn settings() -> S3Settings {
        S3Settings {
            host: "s3.amazonaws.com".to_string(),
            port: 443,
            user: "AKIAIOSFODNN7EXAMPLE".to_string(),
            auth: S3Auth::Prompt,
            region: "us-east-1".to_string(),
            bucket: String::new(),
            prefix: String::new(),
            tls: true,
            path_style: false,
            accept_invalid_cert: false,
            storage_class: String::new(),
            proxy: None,
        }
    }

    fn keys() -> Keys {
        Keys {
            access: "AKIAIOSFODNN7EXAMPLE".to_string(),
            secret: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string(),
            token: None,
        }
    }

    // ---- Settings ----------------------------------------------------------------

    /// What the connection form sends, read the way the backend reads it.
    ///
    /// The two sides describe the same object twice — once in TypeScript and
    /// once here — and nothing checks that they agree until a connection is
    /// opened and fails for a reason that reads like a server problem. This is
    /// that check: the JSON below is what `defaultSettings("s3")` in types.ts
    /// produces, down to the spelling of every key.
    #[test]
    fn the_settings_arrive_the_way_the_form_sends_them() {
        let json = r#"{
            "type": "s3",
            "host": "minio.internal",
            "port": 9000,
            "user": "AKIAIOSFODNN7EXAMPLE",
            "auth": { "source": "secret", "secret": "secret" },
            "region": "eu-central-1",
            "bucket": "my-bucket",
            "prefix": "backups/2024",
            "tls": false,
            "pathStyle": true,
            "acceptInvalidCert": true,
            "storageClass": "GLACIER_IR"
        }"#;

        let settings: crate::storage::ConnectionSettings =
            serde_json::from_str(json).expect("the form's own JSON must deserialize");
        let crate::storage::ConnectionSettings::S3(settings) = settings else {
            panic!("the tag \"s3\" must pick the S3 variant");
        };

        assert_eq!(settings.host, "minio.internal");
        assert_eq!(settings.port, 9000);
        assert_eq!(settings.region, "eu-central-1");
        assert_eq!(settings.bucket, "my-bucket");
        assert_eq!(settings.prefix, "backups/2024");
        assert!(!settings.tls);
        assert!(settings.path_style);
        assert!(settings.accept_invalid_cert);
        assert_eq!(settings.storage_class, "GLACIER_IR");
        assert!(matches!(settings.auth, S3Auth::Secret { .. }));
    }

    /// The fields a connection written before this type existed does not have.
    ///
    /// `workspaces.json` is read as it was last written, so anything added
    /// later has to have a default — otherwise one new field makes every
    /// stored workspace unreadable.
    #[test]
    fn what_is_missing_has_a_default() {
        let json = r#"{
            "type": "s3",
            "host": "s3.amazonaws.com",
            "port": 443,
            "user": "AK",
            "auth": { "source": "prompt" },
            "region": "us-east-1"
        }"#;

        let settings: crate::storage::ConnectionSettings =
            serde_json::from_str(json).expect("a sparse connection must still load");
        let crate::storage::ConnectionSettings::S3(settings) = settings else {
            panic!("the tag \"s3\" must pick the S3 variant");
        };

        assert!(settings.bucket.is_empty());
        assert!(settings.prefix.is_empty());
        // TLS is the one default that is not "off": an endpoint reached
        // without it is the exception, and the safe answer belongs in the
        // default rather than in whoever remembers to tick the box.
        assert!(settings.tls);
        assert!(!settings.path_style);
    }

    // ---- Paths ---------------------------------------------------------------

    #[test]
    fn a_path_is_a_bucket_and_a_key() {
        let root = locate("/");
        assert!(root.bucket.is_none());

        let bucket = locate("/my-bucket");
        assert_eq!(bucket.bucket, Some("my-bucket"));
        assert_eq!(bucket.key, "");

        let deep = locate("/my-bucket/photos/2024/holiday.jpg");
        assert_eq!(deep.bucket, Some("my-bucket"));
        assert_eq!(deep.key, "photos/2024/holiday.jpg");

        // A directory arrives with or without its slash, depending on whether
        // it came from a listing or from a path bar.
        assert_eq!(locate("/my-bucket/photos/").key, "photos");
    }

    #[test]
    fn a_directory_is_a_prefix_with_a_slash() {
        assert_eq!(prefix_of(""), "");
        assert_eq!(prefix_of("photos"), "photos/");
        assert_eq!(prefix_of("photos/2024"), "photos/2024/");
        assert_eq!(name_of("photos/2024/"), "2024");
        assert_eq!(name_of("photos/2024/holiday.jpg"), "holiday.jpg");
        assert_eq!(
            path_of("my-bucket", "photos/2024/"),
            "/my-bucket/photos/2024"
        );
    }

    // ---- Addressing ----------------------------------------------------------
    //
    // Where the bucket goes is the setting that decides whether anything but
    // AWS can be reached at all, and it changes the signature as well as the
    // URL — the host is signed.

    #[test]
    fn a_bucket_goes_in_the_host_by_default() {
        let target = address(&settings(), Some("my-bucket"), "photos/holiday.jpg");
        assert_eq!(target.host, "my-bucket.s3.amazonaws.com");
        assert_eq!(
            target.url,
            "https://my-bucket.s3.amazonaws.com/photos/holiday.jpg"
        );
        assert_eq!(target.canonical, "/photos/holiday.jpg");
    }

    #[test]
    fn path_style_puts_it_in_the_path_and_keeps_the_port() {
        let mut config = settings();
        config.host = "10.0.0.5".to_string();
        config.port = 9000;
        config.tls = false;
        config.path_style = true;

        let target = address(&config, Some("my-bucket"), "photos/holiday.jpg");
        assert_eq!(target.host, "10.0.0.5:9000");
        assert_eq!(
            target.url,
            "http://10.0.0.5:9000/my-bucket/photos/holiday.jpg"
        );
        assert_eq!(target.canonical, "/my-bucket/photos/holiday.jpg");
    }

    #[test]
    fn a_key_is_encoded_once_and_keeps_its_slashes() {
        let target = address(&settings(), Some("my-bucket"), "folder with spaces/ü&+.txt");
        assert_eq!(target.canonical, "/folder%20with%20spaces/%C3%BC%26%2B.txt");
    }

    // ---- Signature -------------------------------------------------------------
    //
    // The example from Amazon's own "Authenticating Requests: Using the
    // Authorization Header", which is the only way to tell a signature that is
    // built correctly from one that merely looks plausible: a wrong one is not
    // wrong in a readable way, it is just refused.

    #[test]
    fn it_signs_amazons_own_example() {
        let mut config = settings();
        config.host = "s3.amazonaws.com".to_string();

        let call = Call::new("GET", Some("examplebucket"), "test.txt").header("range", "bytes=0-9");
        let when = DateTime::parse_from_rfc3339("2013-05-24T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);

        let (url, headers) = sign(&config, &keys(), &call, when);
        assert_eq!(url, "https://examplebucket.s3.amazonaws.com/test.txt");

        let authorization = headers
            .iter()
            .find(|(name, _)| name == "authorization")
            .map(|(_, value)| value.clone())
            .expect("a signed call carries an authorization header");

        assert!(
            authorization.contains("SignedHeaders=host;range;x-amz-content-sha256;x-amz-date"),
            "{authorization}"
        );
        assert!(
            authorization.contains(
                "Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
            ),
            "{authorization}"
        );
    }

    #[test]
    fn the_query_string_is_sorted_by_its_encoded_name() {
        let query = vec![
            ("prefix", "photos/".to_string()),
            ("list-type", "2".to_string()),
            ("delimiter", "/".to_string()),
        ];
        assert_eq!(
            canonical_query(&query),
            "delimiter=%2F&list-type=2&prefix=photos%2F"
        );
    }

    #[test]
    fn a_link_carries_its_own_signature() {
        let when = DateTime::parse_from_rfc3339("2013-05-24T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let link = presign(
            &settings(),
            &keys(),
            "examplebucket",
            "test.txt",
            86400,
            when,
        );

        assert!(link.starts_with("https://examplebucket.s3.amazonaws.com/test.txt?"));
        assert!(link.contains("X-Amz-Expires=86400"));
        assert!(link.contains("X-Amz-SignedHeaders=host"));
        assert!(link.contains("&X-Amz-Signature="));
        // The secret itself never appears in a link — only the key id does.
        assert!(!link.contains("wJalrXUtnFEMI"));
    }

    #[test]
    fn a_trailing_star_narrows_the_listing() {
        assert_eq!(listing_prefix("photos"), "photos/");
        assert_eq!(listing_prefix("photos/2024*"), "photos/2024");
        assert_eq!(listing_prefix("*"), "");
        assert_eq!(listing_prefix(""), "");
    }

    #[test]
    fn a_session_token_is_signed_along() {
        let when = DateTime::parse_from_rfc3339("2013-05-24T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let mut with = keys();
        with.token = Some("TOKEN/with+chars==".to_string());

        let (_, headers) = sign(&settings(), &with, &Call::new("GET", None, ""), when);
        let authorization = &headers
            .iter()
            .find(|(n, _)| n == "authorization")
            .unwrap()
            .1;
        assert!(
            authorization.contains("x-amz-security-token"),
            "{authorization}"
        );
        assert!(headers
            .iter()
            .any(|(n, v)| n == "x-amz-security-token" && v == "TOKEN/with+chars=="));
        let (_, without) = sign(&settings(), &keys(), &Call::new("GET", None, ""), when);
        assert!(!without.iter().any(|(n, _)| n == "x-amz-security-token"));

        let link = presign(&settings(), &with, "my-bucket", "a.txt", 60, when);
        assert!(
            link.contains("X-Amz-Security-Token=TOKEN%2Fwith%2Bchars%3D%3D"),
            "{link}"
        );
    }

    #[test]
    fn the_stored_secret_is_split_into_key_and_token() {
        assert_eq!(split_secret("abc"), ("abc".to_string(), None));
        assert_eq!(
            split_secret("abc\nTOKEN"),
            ("abc".to_string(), Some("TOKEN".to_string()))
        );
        assert_eq!(split_secret("abc\n \n"), ("abc".to_string(), None));
    }

    // ---- Reading answers ---------------------------------------------------------

    #[test]
    fn a_listing_becomes_folders_and_objects() {
        let xml = br#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult>
  <Name>my-bucket</Name>
  <Prefix>photos/</Prefix>
  <IsTruncated>true</IsTruncated>
  <NextContinuationToken>more</NextContinuationToken>
  <Contents>
    <Key>photos/</Key>
    <LastModified>2024-05-01T12:34:56.000Z</LastModified>
    <Size>0</Size>
  </Contents>
  <Contents>
    <Key>photos/holiday.jpg</Key>
    <LastModified>2024-05-02T08:00:00.000Z</LastModified>
    <Size>4096</Size>
  </Contents>
  <CommonPrefixes><Prefix>photos/2024/</Prefix></CommonPrefixes>
</ListBucketResult>"#;

        let page = parse_listing(xml);
        assert_eq!(page.next.as_deref(), Some("more"));
        assert_eq!(page.dirs, vec!["photos/2024/".to_string()]);
        assert_eq!(page.files.len(), 2);
        // The folder marker is in there; filtering it out is the listing's
        // job, not the parser's.
        assert_eq!(page.files[0].key, "photos/");
        assert_eq!(page.files[1].size, 4096);
        assert_eq!(page.files[1].modified, Some(1714636800));
    }

    #[test]
    fn a_listing_names_the_storage_class() {
        let xml = br#"<ListBucketResult>
  <Contents><Key>old.tar</Key><Size>1</Size><StorageClass>STANDARD_IA</StorageClass></Contents>
  <Contents><Key>new.tar</Key><Size>2</Size></Contents>
</ListBucketResult>"#;
        let page = parse_listing(xml);
        assert_eq!(page.files[0].storage_class.as_deref(), Some("STANDARD_IA"));
        assert_eq!(page.files[1].storage_class, None);
    }

    #[test]
    fn a_copy_names_the_class_only_where_it_is_not_standard() {
        let object = |class: Option<&str>| Object {
            key: "a".to_string(),
            size: 1,
            modified: None,
            storage_class: class.map(str::to_string),
        };
        assert_eq!(kept_class(&object(None)), None);
        assert_eq!(kept_class(&object(Some(""))), None);
        assert_eq!(kept_class(&object(Some("STANDARD"))), None);
        assert_eq!(kept_class(&object(Some("GLACIER_IR"))), Some("GLACIER_IR"));
    }

    #[test]
    fn a_copy_in_parts_carries_content_headers_and_metadata() {
        assert!(carried("content-type"));
        assert!(carried("cache-control"));
        assert!(carried("x-amz-meta-owner"));
        // What the server sets itself, or what belongs to this one object.
        assert!(!carried("etag"));
        assert!(!carried("content-length"));
        assert!(!carried("last-modified"));
        assert!(!carried("x-amz-storage-class"));
    }

    #[test]
    fn left_behind_uploads_are_read_with_where_to_go_on() {
        let xml = br#"<ListMultipartUploadsResult>
  <Bucket>my-bucket</Bucket>
  <IsTruncated>true</IsTruncated>
  <NextKeyMarker>b.bin</NextKeyMarker>
  <NextUploadIdMarker>up-2</NextUploadIdMarker>
  <Upload>
    <Key>a.bin</Key><UploadId>up-1</UploadId>
    <Initiator><ID>x</ID></Initiator>
    <StorageClass>STANDARD</StorageClass>
    <Initiated>2024-05-01T00:00:00.000Z</Initiated>
  </Upload>
  <Upload><Key>b.bin</Key><UploadId>up-2</UploadId></Upload>
</ListMultipartUploadsResult>"#;
        let page = parse_uploads(xml);
        assert_eq!(page.uploads.len(), 2);
        assert_eq!(page.uploads[0].key, "a.bin");
        assert_eq!(page.uploads[0].id, "up-1");
        assert_eq!(page.uploads[0].initiated, Some(1714521600));
        assert_eq!(page.uploads[1].initiated, None);
        assert_eq!(page.next, Some(("b.bin".to_string(), "up-2".to_string())));

        // The markers are there on the last page too, but say nothing there.
        let last = parse_uploads(
            b"<R><IsTruncated>false</IsTruncated><NextKeyMarker>b</NextKeyMarker>\
              <NextUploadIdMarker>c</NextUploadIdMarker></R>",
        );
        assert!(last.uploads.is_empty());
        assert_eq!(last.next, None);
    }

    // ---- Requests against a test server -------------------------------------------

    /// A browser on the small server in [`crate::cloud::test_server`], which
    /// answers with what it is given and remembers what it was asked.
    fn served(url: &str, bucket: &str, prefix: &str, storage_class: &str) -> Browser {
        let port = url
            .rsplit(':')
            .next()
            .and_then(|p| p.parse().ok())
            .expect("port");
        let settings = S3Settings {
            host: "127.0.0.1".to_string(),
            port,
            user: "access".to_string(),
            auth: S3Auth::Secret {
                secret: "secret".to_string(),
            },
            region: "us-east-1".to_string(),
            bucket: bucket.to_string(),
            prefix: prefix.to_string(),
            tls: false,
            path_style: true,
            accept_invalid_cert: false,
            storage_class: storage_class.to_string(),
            proxy: None,
        };
        Browser {
            http: http_client(&settings, None, &Pinning::default()).expect("client"),
            keys: Keys {
                access: settings.user.clone(),
                secret: "secret".to_string(),
                token: None,
            },
            home: String::new(),
            settings,
        }
    }

    fn run<F: std::future::Future<Output = ()>>(test: F) {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(test);
    }

    const STARTED: &str =
        "<InitiateMultipartUploadResult><UploadId>up-1</UploadId></InitiateMultipartUploadResult>";

    #[test]
    fn a_rename_keeps_the_class_of_the_object_not_the_connections() {
        run(async {
            let (url, seen) = crate::cloud::test_server::server(vec![
                (200, "", "<CopyObjectResult/>"),
                (200, "", "<CopyObjectResult/>"),
            ])
            .await;
            // The connection uploads into GLACIER; a rename must not move
            // anything there.
            let browser = served(&url, "", "", "GLACIER");
            let mut object = Object {
                key: "old.txt".to_string(),
                size: 10,
                modified: None,
                storage_class: Some("STANDARD_IA".to_string()),
            };
            copy_object(&browser, "my-bucket", &object, "my-bucket", "new.txt")
                .await
                .expect("copied");
            object.storage_class = None;
            copy_object(&browser, "my-bucket", &object, "my-bucket", "new.txt")
                .await
                .expect("copied");

            let seen = seen.lock().unwrap();
            let first = seen[0].head.to_lowercase();
            assert_eq!(seen[0].method, "PUT");
            assert_eq!(seen[0].path, "/my-bucket/new.txt");
            assert!(
                first.contains("x-amz-copy-source: /my-bucket/old.txt"),
                "{first}"
            );
            assert!(
                first.contains("x-amz-storage-class: standard_ia"),
                "{first}"
            );
            let second = seen[1].head.to_lowercase();
            assert!(!second.contains("x-amz-storage-class"), "{second}");
        });
    }

    #[test]
    fn a_copy_past_five_gib_goes_in_parts_of_one_version() {
        run(async {
            let (url, seen) = crate::cloud::test_server::server(vec![
                (
                    200,
                    "ETag: \"v1\"\r\nX-Amz-Meta-Owner: max\r\nCache-Control: no-cache\r\n",
                    "",
                ),
                (200, "", STARTED),
                (
                    200,
                    "",
                    "<CopyPartResult><ETag>&quot;p1&quot;</ETag></CopyPartResult>",
                ),
                (
                    200,
                    "",
                    "<CopyPartResult><ETag>&quot;p2&quot;</ETag></CopyPartResult>",
                ),
                (200, "", "<CompleteMultipartUploadResult/>"),
            ])
            .await;
            let browser = served(&url, "", "", "");
            let source = Object {
                key: "large.iso".to_string(),
                size: COPY_PART_SIZE + 10,
                modified: None,
                storage_class: Some("STANDARD_IA".to_string()),
            };
            copy_parts(&browser, "my-bucket", &source, "target", "large.iso")
                .await
                .expect("copied");

            let seen = seen.lock().unwrap();
            let methods: Vec<&str> = seen.iter().map(|s| s.method.as_str()).collect();
            assert_eq!(methods, ["HEAD", "POST", "PUT", "PUT", "POST"]);

            // The upload starts with what the source carried.
            let start = seen[1].head.to_lowercase();
            assert!(
                seen[1].path.starts_with("/target/large.iso?uploads"),
                "{}",
                seen[1].path
            );
            assert!(start.contains("x-amz-meta-owner: max"), "{start}");
            assert!(start.contains("cache-control: no-cache"), "{start}");
            assert!(
                start.contains("x-amz-storage-class: standard_ia"),
                "{start}"
            );

            // Two ranges that meet, both bound to the version that was asked about.
            let first = seen[2].head.to_lowercase();
            let second = seen[3].head.to_lowercase();
            assert!(
                first.contains(&format!(
                    "x-amz-copy-source-range: bytes=0-{}",
                    COPY_PART_SIZE - 1
                )),
                "{first}"
            );
            assert!(
                second.contains(&format!(
                    "x-amz-copy-source-range: bytes={}-{}",
                    COPY_PART_SIZE,
                    COPY_PART_SIZE + 9
                )),
                "{second}"
            );
            for part in [&first, &second] {
                assert!(
                    part.contains("x-amz-copy-source: /my-bucket/large.iso"),
                    "{part}"
                );
                assert!(
                    part.contains("x-amz-copy-source-if-match: \"v1\""),
                    "{part}"
                );
            }
            assert!(seen[2].path.contains("partNumber=1"), "{}", seen[2].path);
            assert!(seen[3].path.contains("partNumber=2"), "{}", seen[3].path);

            assert!(seen[4]
                .body
                .contains("<PartNumber>1</PartNumber><ETag>\"p1\"</ETag>"));
            assert!(seen[4]
                .body
                .contains("<PartNumber>2</PartNumber><ETag>\"p2\"</ETag>"));
        });
    }

    #[test]
    fn a_part_that_fails_after_the_200_aborts_the_copy() {
        run(async {
            let (url, seen) = crate::cloud::test_server::server(vec![
                (200, "ETag: \"v1\"\r\n", ""),
                (200, "", STARTED),
                (
                    200,
                    "",
                    "<Error><Code>PreconditionFailed</Code><Message>changed</Message></Error>",
                ),
                (204, "", ""),
            ])
            .await;
            let browser = served(&url, "", "", "");
            let source = Object {
                key: "large.iso".to_string(),
                size: COPY_PART_SIZE + 10,
                modified: None,
                storage_class: None,
            };
            let error = copy_parts(&browser, "my-bucket", &source, "my-bucket", "copy.iso")
                .await
                .expect_err("refused");
            assert!(error.contains("PreconditionFailed"), "{error}");

            let seen = seen.lock().unwrap();
            assert_eq!(seen[3].method, "DELETE");
            assert_eq!(seen[3].path, "/my-bucket/copy.iso?uploadId=up-1");
        });
    }

    #[test]
    fn only_old_uploads_count_as_left_behind() {
        run(async {
            let fresh = Utc::now().format("%Y-%m-%dT%H:%M:%S.000Z").to_string();
            let first: &'static str = Box::leak(
                format!(
                    "<R><IsTruncated>true</IsTruncated>\
                     <NextKeyMarker>b.bin</NextKeyMarker><NextUploadIdMarker>up-2</NextUploadIdMarker>\
                     <Upload><Key>customers/a.bin</Key><UploadId>up-1</UploadId>\
                     <Initiated>2024-05-01T00:00:00.000Z</Initiated></Upload>\
                     <Upload><Key>customers/b.bin</Key><UploadId>up-2</UploadId>\
                     <Initiated>{fresh}</Initiated></Upload></R>"
                )
                .into_boxed_str(),
            );
            let (url, seen) = crate::cloud::test_server::server(vec![
                (200, "", first),
                (
                    200,
                    "",
                    "<R><IsTruncated>false</IsTruncated>\
                     <Upload><Key>customers/c.bin</Key><UploadId>up-3</UploadId>\
                     <Initiated>2024-06-01T00:00:00.000Z</Initiated></Upload></R>",
                ),
            ])
            .await;
            let browser = served(&url, "my-bucket", "/customers/", "");
            let stale = stale_uploads(&browser, "my-bucket").await.expect("listed");
            let ids: Vec<&str> = stale.iter().map(|upload| upload.id.as_str()).collect();
            assert_eq!(ids, ["up-1", "up-3"]);

            let seen = seen.lock().unwrap();
            assert!(
                seen[0].path.contains("prefix=customers%2F"),
                "{}",
                seen[0].path
            );
            assert!(
                seen[1].path.contains("key-marker=b.bin"),
                "{}",
                seen[1].path
            );
            assert!(
                seen[1].path.contains("upload-id-marker=up-2"),
                "{}",
                seen[1].path
            );
        });
    }

    #[test]
    fn an_error_says_what_the_server_said() {
        let xml = br#"<?xml version="1.0" encoding="UTF-8"?>
<Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist</Message></Error>"#;
        assert_eq!(
            parse_error(xml).as_deref(),
            Some("NoSuchBucket: The specified bucket does not exist")
        );
        // An answer that is not an error must not be read as one, or every
        // successful listing would come back as a failure.
        assert!(
            parse_error(b"<ListBucketResult><Name>my-bucket</Name></ListBucketResult>").is_none()
        );
    }

    #[test]
    fn the_buckets_come_back_with_their_dates() {
        let xml = br#"<ListAllMyBucketsResult><Buckets>
  <Bucket><Name>one</Name><CreationDate>2024-01-01T00:00:00.000Z</CreationDate></Bucket>
  <Bucket><Name>two</Name><CreationDate>2024-02-01T00:00:00.000Z</CreationDate></Bucket>
</Buckets></ListAllMyBucketsResult>"#;

        let buckets = parse_buckets(xml);
        assert_eq!(buckets.len(), 2);
        assert_eq!(buckets[0].0, "one");
        assert_eq!(buckets[1].0, "two");
        assert_eq!(buckets[1].1, Some(1706745600));
    }

    #[test]
    fn a_multipart_upload_is_cut_to_fit_s3s_limit() {
        // Anything ordinary takes the plain part size.
        assert_eq!(part_size(1024), PART_SIZE);
        assert_eq!(part_size(PART_SIZE * 100), PART_SIZE);
        // A terabyte does not fit into 10 000 parts of 64 MiB, so the parts
        // grow rather than the upload failing.
        let huge = 2 * 1024 * 1024 * 1024 * 1024u64;
        assert!(part_size(huge) > PART_SIZE);
        assert!(huge.div_ceil(part_size(huge)) <= MAX_PARTS);
    }
}

/// Against a real endpoint, and therefore not run by default.
///
/// The signature is the part that cannot be checked by reading it: it is
/// either accepted or refused, and a refusal says nothing about which of the
/// twenty bytes of the canonical request was wrong. The unit tests above
/// settle it against Amazon's own example; these settle the rest — that the
/// listing really does fold keys into folders, that a `Range` really does
/// resume, that a multipart upload really does come back as the file that
/// went up, and that a presigned link really does open without a key.
///
/// MinIO rather than AWS, because it is the case that needs the most care —
/// path-style addressing, a port that is not 443, and no TLS — and because a
/// test that costs money is a test nobody runs.
///
/// ```text
/// docker run -d --name wireterm-s3test -p 9100:9000 \
///   -e MINIO_ROOT_USER=wireterm -e MINIO_ROOT_PASSWORD=secret123 \
///   quay.io/minio/minio server /data
///
/// cargo test --lib s3::live -- --ignored --nocapture --test-threads=1
/// ```
///
/// `WIRETERM_S3_PORT` picks the port (9100 by default). Every test makes its
/// own bucket and takes it away again, so a leftover from a failed run is the
/// only thing ever left behind.
#[cfg(test)]
mod live {
    use std::time::SystemTime;

    use super::*;

    fn settings(bucket: &str) -> S3Settings {
        S3Settings {
            host: "127.0.0.1".to_string(),
            port: std::env::var("WIRETERM_S3_PORT")
                .ok()
                .and_then(|port| port.parse().ok())
                .unwrap_or(9100),
            user: "wireterm".to_string(),
            auth: S3Auth::Secret {
                secret: "secret123".to_string(),
            },
            region: "us-east-1".to_string(),
            bucket: bucket.to_string(),
            prefix: String::new(),
            tls: false,
            // What everything that is not AWS needs, and the reason this test
            // runs against MinIO rather than against a mock.
            path_style: true,
            accept_invalid_cert: false,
            storage_class: String::new(),
            proxy: None,
        }
    }

    fn browser(bucket: &str) -> Arc<Browser> {
        let settings = settings(bucket);
        Arc::new(Browser {
            http: http_client(&settings, None, &Pinning::default()).expect("client"),
            keys: Keys {
                access: settings.user.clone(),
                secret: "secret123".to_string(),
                token: None,
            },
            home: path_of(bucket, ""),
            settings,
        })
    }

    /// A name no other run is using, so two runs cannot tread on each other.
    fn bucket_name() -> String {
        let stamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|since| since.as_millis())
            .unwrap_or(0);
        format!("wireterm-test-{stamp}")
    }

    fn run<F: std::future::Future<Output = ()>>(test: F) {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(test);
    }

    fn job<'a>(local: &'a str, remote: &'a str) -> Job<'a> {
        Job {
            session_id: "live",
            transfer_id: "live",
            local,
            remote,
        }
    }

    fn scratch(name: &str) -> String {
        std::env::temp_dir()
            .join(name)
            .to_string_lossy()
            .into_owned()
    }

    /// Takes the bucket and everything in it away, whatever the test did.
    async fn cleanup(browser: &Arc<Browser>, bucket: &str) {
        if let Ok(keys) = collect_keys(browser, bucket, "").await {
            let _ = delete_keys(browser, bucket, keys, None).await;
        }
        let _ = send(browser, Call::new("DELETE", Some(bucket), ""), None).await;
    }

    /// Everything the file browser does that does not move bytes: make a
    /// bucket, walk a tree into being, read it back, move it and take it down.
    #[test]
    #[ignore = "needs the MinIO container named in the module's doc comment"]
    fn a_bucket_a_tree_and_back_again() {
        run(async {
            let bucket = bucket_name();
            let browser = browser("");

            make_dir(&browser, &format!("/{bucket}"))
                .await
                .expect("bucket");
            let buckets = listing(&browser, "/").await.expect("buckets");
            assert!(
                buckets.entries.iter().any(|entry| entry.name == bucket),
                "the new bucket should be in the list"
            );

            let root = path_of(&bucket, "");
            make_dir(&browser, &format!("{root}/folder"))
                .await
                .expect("mkdir");
            make_dir(&browser, &format!("{root}/folder/deep"))
                .await
                .expect("mkdir");
            make_file(&browser, &format!("{root}/folder/note.txt"))
                .await
                .expect("touch");
            // A key with characters that have to survive being signed, encoded
            // and parsed back out of XML.
            make_file(&browser, &format!("{root}/folder/invoice & co (2024).txt"))
                .await
                .expect("touch");

            let here = listing(&browser, &format!("{root}/folder"))
                .await
                .expect("list");
            let names: Vec<&str> = here.entries.iter().map(|e| e.name.as_str()).collect();
            assert_eq!(
                names,
                vec!["deep", "invoice & co (2024).txt", "note.txt"],
                "folders first, then names — and the marker of this folder itself is not in it"
            );
            assert!(here.entries[0].is_dir, "a common prefix is a folder");
            assert!(
                here.entries[0].mode.is_none() && here.entries[0].permissions.is_none(),
                "S3 states no permissions, so none may be invented"
            );
            assert_eq!(here.parent.as_deref(), Some(root.as_str()));

            assert!(exists(&browser, &format!("{root}/folder")).await.unwrap());
            assert!(exists(&browser, &format!("{root}/folder/note.txt"))
                .await
                .unwrap());
            assert!(!exists(&browser, &format!("{root}/folder/missing.txt"))
                .await
                .unwrap());

            // Renaming a folder is a copy and a delete per key. What must come
            // out of it is the whole subtree under the new name and nothing
            // under the old one.
            move_key(
                &browser,
                &format!("{root}/folder"),
                &format!("{root}/elsewhere"),
            )
            .await
            .expect("rename");
            assert!(!exists(&browser, &format!("{root}/folder")).await.unwrap());
            let moved = listing(&browser, &format!("{root}/elsewhere"))
                .await
                .expect("list");
            assert_eq!(moved.entries.len(), 3, "everything came along");

            remove_path(&browser, &format!("{root}/elsewhere"), true, None)
                .await
                .expect("remove tree");
            let empty = listing(&browser, &root).await.expect("list");
            assert!(empty.entries.is_empty(), "the bucket is empty again");

            remove_path(&browser, &root, true, None)
                .await
                .expect("remove bucket");
            cleanup(&browser, &bucket).await;
        });
    }

    /// A bucket that still holds something is not emptied by "Delete".
    ///
    /// The safety net named in [`remove_path`]: the server refuses, and that
    /// refusal is what stands between a mis-click in a list of buckets and a
    /// bucket that is gone.
    #[test]
    #[ignore = "needs the MinIO container named in the module's doc comment"]
    fn a_bucket_with_something_in_it_is_not_deleted() {
        run(async {
            let bucket = bucket_name();
            let browser = browser("");
            let root = path_of(&bucket, "");

            make_dir(&browser, &root).await.expect("bucket");
            make_file(&browser, &format!("{root}/note.txt"))
                .await
                .expect("touch");

            let refused = remove_path(&browser, &root, true, None).await;
            assert!(refused.is_err(), "a full bucket must not be deletable");
            assert!(
                exists(&browser, &format!("{root}/note.txt")).await.unwrap(),
                "and nothing in it may have been touched"
            );

            cleanup(&browser, &bucket).await;
        });
    }

    /// One file up and back down again, byte for byte.
    #[test]
    #[ignore = "needs the MinIO container named in the module's doc comment"]
    fn bytes_go_up_and_come_back() {
        run(async {
            let bucket = bucket_name();
            let browser = browser(&bucket);
            let root = path_of(&bucket, "");
            make_dir(&browser, &root).await.expect("bucket");

            let source = scratch("wireterm-s3-up.bin");
            let target = scratch("wireterm-s3-down.bin");
            // Not a round number of chunks: the last read is the one that gets
            // a loop's arithmetic wrong.
            let content: Vec<u8> = (0..300_000u32).map(|n| (n % 251) as u8).collect();
            fs::write(&source, &content).await.expect("write");
            let _ = fs::remove_file(&target).await;

            let remote = format!("{root}/folder/data.bin");
            let reporter = Arc::new(Mutex::new(Reporter::silent(content.len() as u64)));
            let moved = Arc::new(AtomicU64::new(0));
            let cancel = Arc::new(AtomicBool::new(false));

            put_object(
                &browser,
                &bucket,
                "folder/data.bin",
                &source,
                content.len() as u64,
                &moved,
                &reporter,
                &cancel,
            )
            .await
            .expect("upload");

            assert_eq!(
                moved.load(Ordering::Relaxed),
                content.len() as u64,
                "the progress counter saw every byte"
            );

            // The object is a file in the listing of the folder it landed in,
            // with the size it went up as.
            let listed = listing(&browser, &format!("{root}/folder"))
                .await
                .expect("list");
            let entry = listed
                .entries
                .iter()
                .find(|entry| entry.name == "data.bin")
                .expect("the object is listed");
            assert!(!entry.is_dir);
            assert_eq!(entry.size, content.len() as u64);
            assert!(
                entry.modified.is_some(),
                "S3 states a date for every object"
            );

            let fetched = fetch(
                Reporter::silent(0),
                &browser,
                &AtomicBool::new(false),
                &job(&target, &remote),
                &bucket,
                "folder/data.bin",
                content.len() as u64,
                false,
            )
            .await
            .expect("download");

            assert_eq!(fetched, content.len() as u64);
            assert_eq!(fs::read(&target).await.expect("read"), content);
            // The working file is renamed away, not left beside the result.
            assert!(fs::metadata(format!("{target}{WORKING_SUFFIX}"))
                .await
                .is_err());

            let _ = fs::remove_file(&source).await;
            let _ = fs::remove_file(&target).await;
            cleanup(&browser, &bucket).await;
        });
    }

    /// A download that stopped carries on from its fragment rather than from
    /// the beginning — which is one `Range` header and the server's answer to
    /// it, and neither can be checked without a server.
    #[test]
    #[ignore = "needs the MinIO container named in the module's doc comment"]
    fn a_stopped_download_carries_on_where_it_stopped() {
        run(async {
            let bucket = bucket_name();
            let browser = browser(&bucket);
            let root = path_of(&bucket, "");
            make_dir(&browser, &root).await.expect("bucket");

            let source = scratch("wireterm-s3-resume-up.bin");
            let target = scratch("wireterm-s3-resume-down.bin");
            let content: Vec<u8> = (0..200_000u32).map(|n| (n % 241) as u8).collect();
            fs::write(&source, &content).await.expect("write");
            let _ = fs::remove_file(&target).await;

            let reporter = Arc::new(Mutex::new(Reporter::silent(content.len() as u64)));
            put_object(
                &browser,
                &bucket,
                "data.bin",
                &source,
                content.len() as u64,
                &Arc::new(AtomicU64::new(0)),
                &reporter,
                &Arc::new(AtomicBool::new(false)),
            )
            .await
            .expect("upload");

            // The fragment a stopped attempt would have left: the first half
            // of the file, under the working name.
            let half = content.len() / 2;
            fs::write(format!("{target}{WORKING_SUFFIX}"), &content[..half])
                .await
                .expect("fragment");

            let moved = fetch(
                Reporter::silent(0),
                &browser,
                &AtomicBool::new(false),
                &job(&target, &format!("{root}/data.bin")),
                &bucket,
                "data.bin",
                content.len() as u64,
                true,
            )
            .await
            .expect("resume");

            assert_eq!(
                moved,
                content.len() as u64,
                "the whole file is there once it is done"
            );
            assert_eq!(
                fs::read(&target).await.expect("read"),
                content,
                "and the halves fit together"
            );

            let _ = fs::remove_file(&source).await;
            let _ = fs::remove_file(&target).await;
            cleanup(&browser, &bucket).await;
        });
    }

    /// A file large enough to go up in parts, which is a different request
    /// three times over — begin, send, put together — and the one path where
    /// a wrong answer looks like success right up until the file is read back.
    #[test]
    #[ignore = "needs the MinIO container named in the module's doc comment"]
    fn a_large_file_goes_up_in_parts() {
        run(async {
            let bucket = bucket_name();
            let browser = browser(&bucket);
            let root = path_of(&bucket, "");
            make_dir(&browser, &root).await.expect("bucket");

            let source = scratch("wireterm-s3-parts-up.bin");
            let target = scratch("wireterm-s3-parts-down.bin");
            // Just over two parts, so there is a first, a middle and a short
            // last one — the arrangement that gets part numbering wrong.
            let total = PART_SIZE * 2 + 1024 * 1024;
            let pattern: Vec<u8> = (0..1024u32).map(|n| (n % 253) as u8).collect();
            {
                let mut file = fs::File::create(&source).await.expect("create");
                let mut written = 0u64;
                while written < total {
                    file.write_all(&pattern).await.expect("write");
                    written += pattern.len() as u64;
                }
                file.flush().await.expect("flush");
            }
            let total = fs::metadata(&source).await.expect("meta").len();
            let _ = fs::remove_file(&target).await;

            let reporter = Arc::new(Mutex::new(Reporter::silent(total)));
            let moved = Arc::new(AtomicU64::new(0));
            put_parts(
                &browser,
                &bucket,
                "large.bin",
                &source,
                total,
                &moved,
                &reporter,
                &Arc::new(AtomicBool::new(false)),
            )
            .await
            .expect("multipart upload");

            assert_eq!(moved.load(Ordering::Relaxed), total, "every part was read");

            let listed = listing(&browser, &root).await.expect("list");
            let entry = listed
                .entries
                .iter()
                .find(|entry| entry.name == "large.bin")
                .expect("the object is listed");
            assert_eq!(
                entry.size, total,
                "the parts were put back together as one object of the right size"
            );

            let fetched = fetch(
                Reporter::silent(0),
                &browser,
                &AtomicBool::new(false),
                &job(&target, &format!("{root}/large.bin")),
                &bucket,
                "large.bin",
                total,
                false,
            )
            .await
            .expect("download");
            assert_eq!(fetched, total);

            // Compared by content rather than only by length: parts sent in
            // the wrong order come back as a file of exactly the right size.
            assert_eq!(
                fs::read(&target).await.expect("read"),
                fs::read(&source).await.expect("read"),
                "byte for byte what went up"
            );

            let _ = fs::remove_file(&source).await;
            let _ = fs::remove_file(&target).await;
            cleanup(&browser, &bucket).await;
        });
    }

    /// The link is the one thing here meant for somebody else, so it is
    /// fetched the way somebody else would: a plain client that has never
    /// heard of an access key.
    #[test]
    #[ignore = "needs the MinIO container named in the module's doc comment"]
    fn a_link_works_without_any_key() {
        run(async {
            let bucket = bucket_name();
            let browser = browser(&bucket);
            let root = path_of(&bucket, "");
            make_dir(&browser, &root).await.expect("bucket");

            let source = scratch("wireterm-s3-link.txt");
            let content = b"Hello from WireTerm";
            fs::write(&source, content).await.expect("write");

            put_object(
                &browser,
                &bucket,
                "folder/hello & world.txt",
                &source,
                content.len() as u64,
                &Arc::new(AtomicU64::new(0)),
                &Arc::new(Mutex::new(Reporter::silent(content.len() as u64))),
                &Arc::new(AtomicBool::new(false)),
            )
            .await
            .expect("upload");

            let link = presign(
                &browser.settings,
                &browser.keys,
                &bucket,
                "folder/hello & world.txt",
                600,
                Utc::now(),
            );

            // Built the way the app builds one — not `Client::new`, whose default TLS
            // path drags in the platform verifier this crate deliberately does not
            // use. What makes it a stranger is that it signs nothing.
            let stranger =
                http_client(&browser.settings, None, &Pinning::default()).expect("client");
            let answer = stranger.get(&link).send().await.expect("fetch the link");
            assert!(
                answer.status().is_success(),
                "a presigned link opens without credentials: {}",
                answer.status()
            );
            assert_eq!(answer.bytes().await.expect("body").as_ref(), content);

            // And without the signature it does not, or the link would be
            // saying nothing about who may read the object.
            let bare = format!("{}/{bucket}/folder/hello%20%26%20world.txt", {
                let settings = &browser.settings;
                format!("http://{}:{}", settings.host, settings.port)
            });
            let refused = stranger.get(&bare).send().await.expect("fetch");
            assert!(
                refused.status().is_client_error(),
                "the same object without a signature must be refused"
            );

            let _ = fs::remove_file(&source).await;
            cleanup(&browser, &bucket).await;
        });
    }
}
