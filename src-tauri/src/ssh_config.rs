//! The hosts from `~/.ssh/config` — for the import.
//!
//! It is read the way OpenSSH reads it: every alias goes through all `Host`
//! blocks from top to bottom, and for every option the **first** value that
//! matches applies. That is why the defaults from a `Host *` at the end also
//! reach the hosts above it, and a `Host *` at the beginning overrides
//! everything below.
//!
//! `Include` is resolved by putting the files in its place — that is how
//! OpenSSH reads them too, with one exception: if an `Include` stands in the
//! middle of a `Host` block and brings `Host` lines of its own, the rest of
//! the block belongs to the last of them here. `Match` blocks are not
//! evaluated: they depend on conditions that are only decided when
//! connecting.
//!
//! A `ProxyJump` is taken over as far as its hops are imported along with it
//! or are already in the project. A `ProxyCommand` only if it is one of the
//! usual ones: `nc -X 5|connect -x proxy:port` becomes the connection's
//! proxy, `ssh -W %h:%p hop` the jump host. An arbitrary command as a tunnel
//! does not exist in WireTerm.

use rust_i18n::t;
use tauri::{AppHandle, Manager};

use crate::import::{bind_host, endpoint, ImportAuth, ImportKind, ImportResult, ImportedHost};
use crate::proxy::{Proxy, ProxyKind, ProxySetting};
use crate::storage::{Forward, ForwardKind};

/// The deepest OpenSSH nests `Include`.
const MAX_INCLUDE_DEPTH: usize = 16;

/// A `Host` block: its patterns and its options in the order of the file.
/// Options before the first `Host` apply to all.
struct Block {
    patterns: Vec<String>,
    options: Vec<(String, String)>,
}

/// Reads the file and returns every host that has a fixed name. Patterns with
/// `*` or `?` are defaults for others, not hosts of their own.
pub fn parse(text: &str, home: &str, local_user: &str) -> Vec<ImportedHost> {
    let blocks = blocks(text);

    let mut aliases: Vec<String> = Vec::new();
    for block in &blocks {
        for pattern in &block.patterns {
            let concrete = !pattern.starts_with('!') && !pattern.contains(['*', '?']);
            if concrete && !aliases.contains(pattern) {
                aliases.push(pattern.clone());
            }
        }
    }

    aliases
        .into_iter()
        .map(|alias| resolve(&blocks, alias, home, local_user))
        .collect()
}

fn blocks(text: &str) -> Vec<Block> {
    let mut blocks = vec![Block {
        patterns: vec!["*".to_string()],
        options: Vec::new(),
    }];
    // Inside a `Match` nothing is taken over until the next block starts.
    let mut in_match = false;

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = split_line(line) else {
            continue;
        };
        match key.as_str() {
            "host" => {
                in_match = false;
                blocks.push(Block {
                    patterns: words(&value),
                    options: Vec::new(),
                });
            }
            "match" => in_match = true,
            _ if in_match => {}
            _ => {
                let block = blocks.last_mut().expect("there is always one block");
                block.options.push((key, unquote(&value)));
            }
        }
    }
    blocks
}

/// `Key Value` or `Key=Value`, the key regardless of upper and lower case.
fn split_line(line: &str) -> Option<(String, String)> {
    let end = line.find(|c: char| c.is_whitespace() || c == '=')?;
    let key = line[..end].to_lowercase();
    let rest = line[end..].trim_start();
    let rest = rest.strip_prefix('=').unwrap_or(rest).trim();
    (!rest.is_empty()).then(|| (key, rest.to_string()))
}

/// The patterns after `Host`, respecting quotes.
fn words(value: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    for c in value.chars() {
        match c {
            '"' => quoted = !quoted,
            c if c.is_whitespace() && !quoted => {
                if !current.is_empty() {
                    out.push(std::mem::take(&mut current));
                }
            }
            c => current.push(c),
        }
    }
    if !current.is_empty() {
        out.push(current);
    }
    out
}

fn unquote(value: &str) -> String {
    value
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .unwrap_or(value)
        .to_string()
}

/// Whether an alias belongs to a block: at least one pattern matches, and no
/// negated one.
fn applies(patterns: &[String], alias: &str) -> bool {
    let mut hit = false;
    for pattern in patterns {
        match pattern.strip_prefix('!') {
            Some(negated) if glob(negated, alias) => return false,
            Some(_) => {}
            None => hit |= glob(pattern, alias),
        }
    }
    hit
}

/// `*` and `?`, nothing else — `ssh_config` knows no more either.
fn glob(pattern: &str, text: &str) -> bool {
    fn go(p: &[char], t: &[char]) -> bool {
        match (p.first(), t.first()) {
            (None, None) => true,
            (Some('*'), _) => go(&p[1..], t) || (!t.is_empty() && go(p, &t[1..])),
            (Some('?'), Some(_)) => go(&p[1..], &t[1..]),
            (Some(a), Some(b)) if a.eq_ignore_ascii_case(b) => go(&p[1..], &t[1..]),
            _ => false,
        }
    }
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    go(&p, &t)
}

/// Puts the files behind `Include` in its place. `read` returns, for a
/// pattern, the contents of the matching files, in the order of their names.
pub fn inline_includes(text: &str, read: &dyn Fn(&str) -> Vec<String>, depth: usize) -> String {
    let mut out = String::new();
    for line in text.lines() {
        match split_line(line.trim()) {
            Some((key, value)) if key == "include" => {
                if depth >= MAX_INCLUDE_DEPTH {
                    continue;
                }
                for pattern in words(&value) {
                    for included in read(&pattern) {
                        out.push_str(&inline_includes(&included, read, depth + 1));
                    }
                }
            }
            _ => {
                out.push_str(line);
                out.push('\n');
            }
        }
    }
    out
}

fn resolve(blocks: &[Block], alias: String, home: &str, local_user: &str) -> ImportedHost {
    let matching = || {
        blocks
            .iter()
            .filter(|block| applies(&block.patterns, &alias))
            .flat_map(|block| block.options.iter())
    };
    let first = |name: &str| -> Option<String> {
        matching()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.clone())
    };
    // Forwardings all apply, not just the first.
    let all = |name: &str| -> Vec<String> {
        matching()
            .filter(|(key, _)| key == name)
            .map(|(_, value)| value.clone())
            .collect()
    };

    let host = first("hostname")
        .map(|name| name.replace("%h", &alias))
        .unwrap_or_else(|| alias.clone());
    let port = first("port").and_then(|p| p.parse().ok()).unwrap_or(22);
    let user = first("user").unwrap_or_else(|| local_user.to_string());
    let identity_file = first("identityfile")
        .filter(|path| !path.eq_ignore_ascii_case("none"))
        .map(|path| expand(&path, home, &alias, &user));
    // Without `IdentityFile` the SSH agent remains, and that is also what
    // `ssh` would do.
    let auth = match identity_file {
        Some(path) => ImportAuth::KeyFile { path },
        None => ImportAuth::Agent,
    };
    let mut imported = ImportedHost::new(ImportKind::Ssh, &alias, &host, port, &user, auth);
    imported.agent_forwarding =
        first("forwardagent").is_some_and(|v| v.eq_ignore_ascii_case("yes"));

    let jump = first("proxyjump").filter(|jump| !jump.eq_ignore_ascii_case("none"));
    let command = first("proxycommand").filter(|cmd| !cmd.eq_ignore_ascii_case("none"));
    match (jump, command) {
        (Some(jump), _) => {
            imported.proxy_jump = jump
                .split(',')
                .map(hop_name)
                .filter(|hop| !hop.is_empty())
                .collect();
            imported.proxy = Some(jump);
        }
        (None, Some(command)) => match proxy_command(&command) {
            Some(Tunnel::Proxy(proxy)) => imported.connection_proxy = Some(proxy),
            Some(Tunnel::Jump(hop)) => {
                imported.proxy_jump = vec![hop];
                imported.proxy = Some(command);
            }
            None => imported
                .notes
                .push(t!("import.named_proxy_command_not_imported", command = command).to_string()),
        },
        (None, None) => {}
    }

    for (key, kind) in [
        ("localforward", ForwardKind::Local),
        ("remoteforward", ForwardKind::Remote),
        ("dynamicforward", ForwardKind::Dynamic),
    ] {
        for value in all(key) {
            match forward(kind, &value) {
                Some(forward) => imported.forwards.push(forward),
                None => imported
                    .notes
                    .push(t!("import.forward_not_imported", entry = value).to_string()),
            }
        }
    }
    imported
}

/// `[address:]port target:targetport`, for `DynamicForward` only the first
/// part. Unix sockets and a `RemoteForward` without a target (the SOCKS proxy
/// on the server) do not exist in WireTerm.
fn forward(kind: ForwardKind, value: &str) -> Option<Forward> {
    let mut parts = value.split_whitespace();
    let (address, bind_port) = endpoint(parts.next()?)?;
    let (target_host, target_port) = match kind {
        ForwardKind::Dynamic => (String::new(), 0),
        _ => endpoint(parts.next()?).filter(|(host, _)| !host.is_empty())?,
    };
    Some(Forward {
        kind,
        bind_host: bind_host(address),
        bind_port,
        target_host,
        target_port,
    })
}

enum Tunnel {
    Proxy(ProxySetting),
    Jump(String),
}

/// The two `ProxyCommand`s almost everyone uses: `nc` with a proxy in front
/// and `ssh -W` through another host.
fn proxy_command(command: &str) -> Option<Tunnel> {
    let words: Vec<&str> = command.split_whitespace().collect();
    let program = words.first()?.rsplit(['/', '\\']).next()?;
    let after = |flag: &str| {
        words
            .iter()
            .position(|word| *word == flag)
            .and_then(|i| words.get(i + 1))
            .copied()
    };
    match program {
        "nc" | "ncat" | "netcat" => {
            let kind = match after("-X").or_else(|| after("--proxy-type"))? {
                "5" | "socks5" => ProxyKind::Socks5,
                "connect" | "http" => ProxyKind::Http,
                _ => return None,
            };
            let (host, port) = endpoint(after("-x").or_else(|| after("--proxy"))?)?;
            (!host.is_empty()).then_some(Tunnel::Proxy(ProxySetting::Custom(Proxy {
                kind,
                host,
                port,
            })))
        }
        "ssh" if words.contains(&"-W") => {
            // Skip options with a value; what is left is the hop.
            const WITH_VALUE: [&str; 9] = ["-W", "-p", "-l", "-i", "-o", "-F", "-J", "-b", "-c"];
            let mut rest = words[1..].iter();
            while let Some(word) = rest.next() {
                if WITH_VALUE.contains(word) {
                    rest.next();
                } else if !word.starts_with('-') {
                    return Some(Tunnel::Jump(hop_name(word)));
                }
            }
            None
        }
        _ => None,
    }
}

/// `user@host:port` → `host`: the name a hop can be found again by.
fn hop_name(hop: &str) -> String {
    let hop = hop.trim();
    let hop = hop.rsplit_once('@').map(|(_, host)| host).unwrap_or(hop);
    let hop = hop
        .strip_prefix('[')
        .and_then(|h| h.split_once(']'))
        .map(|(h, _)| h)
        .unwrap_or(hop);
    let hop = match hop.rsplit_once(':') {
        Some((host, port)) if port.chars().all(|c| c.is_ascii_digit()) => host,
        _ => hop,
    };
    hop.to_string()
}

/// `~` and the placeholders that occur in a path to a key.
fn expand(path: &str, home: &str, alias: &str, user: &str) -> String {
    let path = match path.strip_prefix('~') {
        Some(rest) => format!("{home}{rest}"),
        None => path.to_string(),
    };
    path.replace("%d", home)
        .replace("%h", alias)
        .replace("%r", user)
}

#[tauri::command]
pub fn ssh_config_hosts(app: AppHandle) -> Result<ImportResult, String> {
    let home = app
        .path()
        .home_dir()
        .map_err(|e| t!("import.no_home_dir", error = e).to_string())?;
    let ssh_dir = home.join(".ssh");
    let file = ssh_dir.join("config");
    let text = match std::fs::read_to_string(&file) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(ImportResult::default()),
        Err(e) => {
            return Err(t!("import.read_failed", path = file.display(), error = e).to_string())
        }
    };
    // Relative, for the user's configuration, means: under `~/.ssh`.
    // Wildcards only in the last part of the path, as in `config.d/*`.
    let read = |pattern: &str| -> Vec<String> {
        let path = match pattern.strip_prefix('~') {
            Some(rest) => home.join(rest.trim_start_matches(['/', '\\'])),
            None => ssh_dir.join(pattern),
        };
        let name = path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        if !name.contains(['*', '?']) {
            return std::fs::read_to_string(&path).into_iter().collect();
        }
        let Some(dir) = path.parent() else {
            return Vec::new();
        };
        let mut files: Vec<_> = std::fs::read_dir(dir)
            .into_iter()
            .flatten()
            .flatten()
            .filter(|entry| glob(&name, &entry.file_name().to_string_lossy()))
            .map(|entry| entry.path())
            .collect();
        files.sort();
        files
            .iter()
            .filter_map(|file| std::fs::read_to_string(file).ok())
            .collect()
    };
    let text = inline_includes(&text, &read, 0);
    let local_user = std::env::var("USERNAME")
        .or_else(|_| std::env::var("USER"))
        .unwrap_or_default();
    Ok(ImportResult {
        hosts: parse(&text, &home.to_string_lossy(), &local_user),
        skipped: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOME: &str = "C:\\Users\\anna";

    fn hosts(text: &str) -> Vec<ImportedHost> {
        parse(text, HOME, "anna")
    }

    #[test]
    fn a_host_with_everything_that_belongs_to_it() {
        let list = hosts(
            "Host web01\n  HostName web01.example.com\n  Port 2222\n  User root\n  IdentityFile ~/.ssh/id_ed25519\n",
        );
        assert_eq!(
            list,
            vec![ImportedHost::new(
                ImportKind::Ssh,
                "web01",
                "web01.example.com",
                2222,
                "root",
                ImportAuth::KeyFile {
                    path: "C:\\Users\\anna/.ssh/id_ed25519".into()
                },
            )]
        );
    }

    /// Without `HostName` the alias is the host, without `User` the local
    /// name, without `Port` 22 — as with `ssh`.
    #[test]
    fn what_is_missing_comes_from_ssh_itself() {
        let list = hosts("Host nas.local\n");
        assert_eq!(list[0].host, "nas.local");
        assert_eq!(list[0].user, "anna");
        assert_eq!(list[0].port, 22);
        assert_eq!(list[0].auth, ImportAuth::Agent);
    }

    /// The first value applies: a `Host *` at the end only fills in what is
    /// missing above.
    #[test]
    fn host_star_at_the_end_only_fills_in() {
        let list = hosts("Host a\n  User deploy\nHost b\nHost *\n  User root\n  Port 2200\n");
        assert_eq!(list.len(), 2, "the star is not a host");
        assert_eq!(list[0].user, "deploy");
        assert_eq!(list[0].port, 2200);
        assert_eq!(list[1].user, "root");
    }

    #[test]
    fn several_names_patterns_and_negation() {
        let list = hosts(
            "Host web01 web02\n  User www\nHost web* !web02\n  Port 2222\nHost *.internal\n  User admin\n",
        );
        let names: Vec<&str> = list.iter().map(|h| h.alias.as_str()).collect();
        assert_eq!(names, ["web01", "web02"]);
        assert_eq!(list[0].port, 2222);
        assert_eq!(list[1].port, 22, "web02 is excluded");
    }

    #[test]
    fn equals_sign_quotes_and_upper_case() {
        let list = hosts(
            "HOST \"my server\"\n  hostname=10.0.0.5\n  IdentityFile \"%d/.ssh/key with space\"\n",
        );
        assert_eq!(list[0].alias, "my server");
        assert_eq!(list[0].host, "10.0.0.5");
        assert_eq!(
            list[0].auth,
            ImportAuth::KeyFile {
                path: "C:\\Users\\anna/.ssh/key with space".into()
            }
        );
    }

    #[test]
    fn match_blocks_and_comments_are_left_out() {
        let list = hosts(
            "# Comment\nHost a\n  Port 1\nMatch host a exec \"true\"\n  Port 2\n  User wrong\nHost b\n",
        );
        assert_eq!(list[0].port, 1);
        assert_eq!(list[0].user, "anna");
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn a_jump_host_is_reported() {
        let list = hosts("Host inner\n  ProxyJump bastion\nHost free\n  ProxyJump none\n");
        assert_eq!(list[0].proxy.as_deref(), Some("bastion"));
        assert_eq!(list[0].proxy_jump, ["bastion"]);
        assert_eq!(list[1].proxy, None);
        assert!(list[1].proxy_jump.is_empty());
    }

    /// Several hops, with user and port — found again by the name.
    #[test]
    fn a_chain_of_hops_becomes_names() {
        let list = hosts("Host deep\n  ProxyJump admin@outer:2222,[inner]:22,middle\n");
        assert_eq!(list[0].proxy_jump, ["outer", "inner", "middle"]);
    }

    /// `nc` with a proxy becomes the connection's proxy, `ssh -W` a hop, and
    /// everything else is reported.
    #[test]
    fn the_usual_proxy_commands_are_taken_over() {
        let list = hosts(
            "Host a\n  ProxyCommand nc -X 5 -x proxy:1080 %h %p\nHost b\n  ProxyCommand /usr/bin/ncat --proxy squid:3128 --proxy-type http %h %p\nHost c\n  ProxyCommand ssh -q -p 2222 -W %h:%p admin@bastion\nHost d\n  ProxyCommand socat - PROXY:p:%h:%p\n",
        );
        assert_eq!(
            list[0].connection_proxy,
            Some(ProxySetting::Custom(Proxy {
                kind: ProxyKind::Socks5,
                host: "proxy".into(),
                port: 1080
            }))
        );
        assert!(list[0].proxy_jump.is_empty());
        assert!(matches!(
            &list[1].connection_proxy,
            Some(ProxySetting::Custom(Proxy { kind: ProxyKind::Http, host, port: 3128 })) if host == "squid"
        ));
        assert_eq!(list[2].proxy_jump, ["bastion"]);
        assert_eq!(list[3].connection_proxy, None);
        assert_eq!(list[3].notes.len(), 1, "{:?}", list[3].notes);
    }

    #[test]
    fn all_forwardings_apply_and_agent_forwarding_too() {
        let list = hosts(
            "Host a\n  LocalForward 8080 localhost:80\n  LocalForward *:5433 [db::1]:5432\n  RemoteForward 2222 localhost:22\n  DynamicForward 127.0.0.1:1080\n  RemoteForward 1081\n  ForwardAgent yes\nHost *\n  LocalForward 9000 x:9000\n",
        );
        let seen: Vec<_> = list[0]
            .forwards
            .iter()
            .map(|f| {
                (
                    f.kind,
                    f.bind_host.as_str(),
                    f.bind_port,
                    f.target_host.as_str(),
                    f.target_port,
                )
            })
            .collect();
        assert_eq!(
            seen,
            [
                (ForwardKind::Local, "", 8080, "localhost", 80),
                (ForwardKind::Local, "0.0.0.0", 5433, "db::1", 5432),
                (ForwardKind::Local, "", 9000, "x", 9000),
                (ForwardKind::Remote, "", 2222, "localhost", 22),
                (ForwardKind::Dynamic, "127.0.0.1", 1080, "", 0),
            ]
        );
        assert_eq!(list[0].notes, ["Forwarding \"1081\" not imported"]);
        assert!(list[0].agent_forwarding);
    }

    #[test]
    fn include_puts_files_in_its_place() {
        let read = |pattern: &str| -> Vec<String> {
            match pattern {
                "config.d/*" => vec![
                    "Host one\n  User a\n".to_string(),
                    "Include deeper\nHost two\n".to_string(),
                ],
                "deeper" => vec!["Host three\n  Port 2200\n".to_string()],
                // A cycle ends at the depth limit, not in the stack.
                "cycle" => vec!["Include cycle\n".to_string()],
                _ => Vec::new(),
            }
        };
        let text = inline_includes(
            "Include config.d/*\nInclude cycle\nHost zero\nHost *\n  User b\n",
            &read,
            0,
        );
        let list = hosts(&text);
        let seen: Vec<_> = list
            .iter()
            .map(|h| (h.alias.as_str(), h.user.as_str(), h.port))
            .collect();
        assert_eq!(
            seen,
            [
                ("one", "a", 22),
                ("three", "b", 2200),
                ("two", "b", 22),
                ("zero", "b", 22)
            ]
        );
    }
}
