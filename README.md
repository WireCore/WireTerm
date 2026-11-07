<p align="center">
    <img src="assets/wireterm.svg" alt="" width="160" height="160" />
</p>

<h1 align="center">WireTerm</h1>

<p align="center">
    SSH, SFTP, FTP/FTPS and S3 in one desktop app – with 1Password and Bitwarden built in,<br />
    and workspaces a team shares end-to-end encrypted.<br />
    Tauri 2 · Vue 3 · Rust · English and German
</p>

<p align="center">
    <a href="https://github.com/WireCore/wireterm/releases"><b>Download</b></a> ·
    <a href="#getting-started">Getting started</a> ·
    <a href="#how-it-compares">How it compares</a> ·
    <a href="#development">Development</a> ·
    <a href="#localization">Localization</a> ·
    <a href="TODO.md">Roadmap</a> ·
    <a href="CONTRIBUTING.md">Contributing</a> ·
    <a href="SECURITY.md">Security</a>
</p>

<p align="center">
    <a href="https://github.com/WireCore/wireterm/releases"><img alt="Release" src="https://img.shields.io/github/v/release/WireCore/wireterm?include_prereleases&label=release" /></a>
    <a href="https://github.com/WireCore/wireterm/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/WireCore/wireterm/actions/workflows/ci.yml/badge.svg?branch=main" /></a>
    <img alt="Platforms: Windows, macOS, Linux" src="https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-blue" />
    <a href="LICENSE"><img alt="License: AGPL-3.0" src="https://img.shields.io/badge/license-AGPL--3.0-green" /></a>
</p>

## About

Desktop client for managing and opening server connections. Tauri 2 with Vue 3 in the frontend
and Rust in the backend.

Connections are organized in **workspaces**, and within them in **projects**. Every connection
has a type — **SSH/SFTP**, **FTP/FTPS** or **S3** — and the settings that go with it. Open
connections run side by side as tabs.

An SSH tab shows a terminal and a file view side by side; an FTP or S3 tab only the file view,
because there is no shell at the other end. The file view itself is the same.

Credentials come from a vault — **1Password** or **Bitwarden/Vaultwarden** —, from a file, from
a prompt when connecting, or are typed in directly. With a vault only the reference is stored,
never the secret itself. See [Vaults](#vaults).

A workspace lives in your **WireCloud account** — synced to every device you sign in on and
shareable with your team — or, if you prefer, on a server of your own or **locally** in a file.
On a server the secrets are end-to-end encrypted: it sees hosts and names, but never a password
or a key. See [Cloud and custom backend](#cloud-and-custom-backend).

The UI is available in English and German; see [Localization](#localization).

Installers exist for **Windows, macOS and Linux**, each for x86-64 and ARM64. Windows is where
WireTerm is used every day; on macOS and Linux it is new — see [Development](#development).

Open items are in [TODO.md](TODO.md) — one of them with security impact.

## Why WireTerm

WireTerm exists because we could not find the tool we wanted. We work on more than one machine —
a desktop in the office, a laptop on the road — and every connection set up on one had to be set
up again on the other. The SSH clients that sync do it well, but stop at SSH and SFTP; the file
clients that speak S3 keep their site list on one machine, or offer S3 only in a paid edition.

So WireTerm keeps every connection in sync on its own, the moment you sign in on another device —
SSH and SFTP as much as FTP and S3 buckets. A team shares the same workspaces without handing a
server the passwords, and credentials can come straight from the password manager you already
use.

## How it compares

| | WireTerm | Termius | electerm | Voltius | FileZilla |
|---|:---:|:---:|:---:|:---:|:---:|
| SSH terminal | ✓ | ✓ | ✓ | ✓ | – |
| SFTP file browser | ✓ | ✓ | ✓ | ✓ | ✓ |
| S3 buckets, with shareable presigned links | ✓ | – | – | – | S3 in Pro only |
| Connections sync across devices | ✓ automatic | ✓ real-time | via Gist, WebDAV or S3 | ✓ real-time | – |
| Team workspaces | ✓ end-to-end encrypted | ✓ | – | ✓ | – |
| 1Password and Bitwarden/Vaultwarden built in | ✓ | – | – | – | – |
| Claude and other AI agents can work with your connections | ✓ via MCP, every command confirmed | own built-in AI | own built-in AI, agent mode | – | – |
| Run the sync server yourself | ✓ | – | – | ✓ | – |
| Open source | AGPL-3.0 | – | MIT | AGPL-3.0 | GPL (Pro: commercial) |

As of 6 October 2026 — Termius 10.1.3, electerm 5.5.66, Voltius 0.49, FileZilla 3.71.1 — from
each project's own documentation. If something has changed, a correction is welcome.

Where WireTerm is behind today: it is newest on macOS and Linux, it has no serial, Telnet or Mosh
connections, and it syncs every minute rather than in real time. The full comparison, feature by
feature, is in [TODO.md](TODO.md#feature-gaps-compared-to-electerm-voltius-termius-and-filezilla).

## Getting started

1. Download the installer for your system from the
   [releases](https://github.com/WireCore/wireterm/releases) — the table there lists them by
   system and architecture: EXE or MSI for Windows, DMG for macOS (Apple Silicon or Intel), deb,
   rpm or AppImage for Linux. The builds are not signed yet — Windows SmartScreen
   warns, and macOS only opens the app after allowing it under System Settings → Privacy &
   Security.
2. In WireTerm choose **Add workspace** and, as the place it should live, **In the account at
   WireCloud**. **Sign in with WireCloud** opens your browser; create a WireCloud account there if
   you have none yet.
3. Set your **master password**. It encrypts the credentials in your workspaces before they leave
   the device and is stored nowhere — not on the server, not at WireCloud. Note your recovery
   codes; they are the only way back if you forget it.
4. On every other device: install WireTerm, sign in with WireCloud, unlock with the master
   password — your workspaces are there and stay in sync.

Working as a team: companies and teams are managed in [WireCloud](https://cloud.wirecore.net);
in WireTerm you share a project with a team, and the members get its key from a colleague's
WireTerm the next time it runs.

Without WireCloud, a workspace can also live in a file on this device only, or on a
[WireTerm server](https://github.com/WireCore/wireterm-server) you run yourself.

## Development

```bash
npm install
npm run build:sidecar   # Go binary for 1Password access
npm run tauri dev       # npm run tauri build for the installers
```

Prerequisites: Node and Rust; Go only for the 1Password sidecar. For the 1Password part, also
the steps under [1Password](#1password). Bitwarden needs none of that — it is built into Rust.

**Windows, macOS and Linux.** The CI builds and tests on all three. A tag builds the installers —
Windows x64 and ARM64, macOS Apple Silicon and Intel, Linux x64 and ARM64 — into one draft
release whose description gets a download table (`.github/workflows/release.yml`,
`scripts/release-notes.mjs`). `npm run build:sidecar -- <target>` builds the sidecar for another
target; with CGO that only works across macOS architectures. Where the systems differ, the code
has a branch for each: the SSH agent (named pipe or Pageant on Windows, `SSH_AUTH_SOCK`
elsewhere), the keyring, the local shells, the idle detection and the 1Password library paths.
Windows is used every day; on Linux the unit tests pass and the packages build, macOS has only
been built by the CI so far — see [TODO.md](TODO.md#smaller-open-items).

**Updates** come from the GitHub releases: on start and every six hours the app reads the latest
release's `latest.json` (`plugins.updater` in `src-tauri/tauri.conf.json`); if there is a newer
version, a banner offers to install it and restart ([updates.ts](src/updates.ts)). Every update
is checked against the update key before it is installed — on Windows with the installer, on
macOS by replacing the app, on Linux as AppImage, deb or rpm (the last two with an
administrator prompt). The release workflow builds the signatures and `latest.json` with the
private update key from the `release` environment on GitHub (`TAURI_SIGNING_PRIVATE_KEY` and
`TAURI_SIGNING_PRIVATE_KEY_PASSWORD`).

On Linux, Tauri needs its system packages: `build-essential`, `libwebkit2gtk-4.1-dev`,
`libayatana-appindicator3-dev`, `librsvg2-dev`, `libxdo-dev` and `libssl-dev`; the 1Password
sidecar needs `gcc` (CGO). On macOS the Xcode command line tools are enough.

Recommended setup: [VS Code](https://code.visualstudio.com/) with
[Vue - Official](https://marketplace.visualstudio.com/items?itemName=Vue.volar),
[Tauri](https://marketplace.visualstudio.com/items?itemName=tauri-apps.tauri-vscode) and
[rust-analyzer](https://marketplace.visualstudio.com/items?itemName=rust-lang.rust-analyzer).

## SSH

Implemented with [russh](https://github.com/Eugeny/russh), a pure Rust implementation — the
libssh2 bindings would need a C toolchain and an OpenSSL build on Windows. russh runs on the
`ring` backend instead of the default `aws-lc-rs`, whose `aws-lc-sys` needs cmake and NASM to
build.

Every tab is a session of its own with its own ID. The server's output is sent to the frontend
as `ssh:data:<session-id>` — as raw bytes, so that a character falling on a chunk boundary is not
torn apart.

Authentication is by key (vault, file, SSH agent or typed in) or by password — from the vault or
prompted for when connecting, for example for a Hetzner Storage Box without a stored key. As with
FTP, a prompted password applies to the tab and is stored nowhere.

If a key is protected by a passphrase, it is prompted for when connecting and likewise applies
only to the tab. On Windows the SSH agent is first the OpenSSH agent of Windows
(`\\.\pipe\openssh-ssh-agent`, which is also where 1Password's agent listens), otherwise
Pageant; on macOS and Linux it is the agent in `SSH_AUTH_SOCK`. Every key it holds is tried in
turn.

If the server then offers *keyboard-interactive* — because it only accepts passwords that way, or
because a one-time code follows the key —, the app answers its questions: the one for the
password with the connection's password, everything else (an OTP, say) through the same dialog
as a prompted password, in the server's words. A code applies only to this one sign-in. This is
checked against an sshd with Google Authenticator from
[scripts/ssh-2fa](scripts/ssh-2fa/Dockerfile) — how is described there and in the tests
`ssh::tests::two_factor_*`.

### Importing

"Import" on a project takes over connections from other programs
([import.rs](src-tauri/src/import.rs), [ssh_config.rs](src-tauri/src/ssh_config.rs)). Every
source yields the same list; what cannot be taken over — Telnet, RDP, Serial — is listed below
it with the reason. None of them takes over passwords: where there is no key, the connection
asks when connecting.

- **`~/.ssh/config`**, read the way `ssh` reads it: for every option the first matching value
  wins. `Include` is resolved, relative to `~/.ssh` and with wildcards in the file name
  (`config.d/*`). With `IdentityFile` it becomes a key file, otherwise the SSH agent.
  `LocalForward`, `RemoteForward`, `DynamicForward` and `ForwardAgent` come along. A `ProxyJump`
  becomes the jump host if its hops are imported as well or are already in the project; a
  `ProxyCommand` only if it is one of the usual ones — `nc -X 5|connect -x …` becomes the
  connection's proxy, `ssh -W %h:%p hop` the jump host. `Match` is not evaluated.
- **PuTTY**: the saved sessions from the registry
  (`HKCU\Software\SimonTatham\PuTTY\Sessions`), on Linux from `~/.putty/sessions`. With key file
  (a `.ppk` is read directly by the sign-in), forwards, agent forwarding and a SOCKS5 or HTTP
  proxy; an SSH proxy becomes the jump host.
- **MobaXterm**: the `MobaXterm.ini` or an exported `.mxtsessions`. The format is not
  documented; SSH sessions are taken over with host, port, user, key and gateway, plus their
  folder for display.
- **CSV** with a header row, separated by comma, semicolon or tab, in UTF-8 or Windows-1252:
  `name`, `host`, `port`, `user`, `protocol` (ssh, sftp, ftp, ftps), `key`, `group`. Termius has
  no documented export format; such a table is the way out of it.

### Jump hosts and agent forwarding

An SSH connection can run **through another one** of the same workspace ("Via jump host" in the
form), and that one through yet another. Every hop is a sign-in of its own with its own
credentials and its own host key check; through it runs a `direct-tcpip` channel to the next,
and over that an ordinary SSH session, encrypted in its own right. Only the jump host's ID is
stored; the UI resolves the chain when connecting (`withJumps` in [store.ts](src/store.ts)) and
sends it along as `via`. A vanished hop or a cycle is an error when connecting, not a silent
direct connection. The connections to the hops live as long as the tab.

The jump host may come from **another workspace** if that one belongs to nobody else — a local
or a personal one. In a team workspace it has to come from the workspace itself: colleagues
could not resolve the ID from someone else's workspace. An export moves such references to the
new IDs.

**Agent forwarding** passes the local agent on to the target, so that from there you can connect
onward with the same keys. Only for the target, never for a hop, and only on request: whoever is
root on the server can use the agent while the connection stands.

Both are checked against two containers from [scripts/ssh-jump](scripts/ssh-jump/Dockerfile) —
a target that can only be reached through the jump host, and `ssh-add -l` on the server:
`cargo test --lib ssh::tests::jump -- --ignored`.

### Port forwarding

Like `ssh -L`, `-R` and `-D`, as rules on the connection (Options in the form,
[forward.rs](src-tauri/src/forward.rs)). They start as soon as the tab's terminal is connected,
run over the same sign-in — so also over its jump hosts — and end with the tab. Above the
terminal every rule is shown with the port actually being listened on and the number of
connections currently open; one that could not start is struck through and says why in its
tooltip.

- **Local**: a port here leads via `direct-tcpip` to a target as the server sees it.
- **Remote**: the server listens (`tcpip-forward`), and every connection there is connected to
  the target here. The app refuses channels to ports that were not requested.
- **SOCKS**: a SOCKS5 proxy here, without authentication, CONNECT only; the server resolves
  names.

Without an address only `127.0.0.1` is listened on — a port for the whole network should be a
decision. Checked against the same containers:
`cargo test --lib forward::tests::forwarding -- --ignored`.

### Keys

Under "Enter key" a key can also be generated (Ed25519, or RSA with 4096 bits on request) or
taken from a file — `.ppk` from PuTTY, OpenSSH, PEM, with or without passphrase
([keys.rs](src-tauri/src/keys.rs)). Afterwards the field holds it as OpenSSH without a
passphrase; it is encrypted there anyway, with the device key or the project key.

"Install on the server" appends the public key to `~/.ssh/authorized_keys`, like
`ssh-copy-id` — signed in with whatever applies so far, or with a prompted password if there is
nothing yet or if that already is this key. If the same key is already there, whatever its
comment, it does not go in a second time; the remote command reports `WIRETERM:ADDED` or
`WIRETERM:PRESENT`. Checked against the container from
[scripts/ssh-jump](scripts/ssh-jump/Dockerfile):
`cargo test --lib ssh::tests::jump_a_key_is_installed -- --ignored`.

### Snippets

Saved commands of the workspace, in folders (`Maintenance/Linux`), managed under "Snippets" in
the overview and sent through the snippet menu above the terminal. Several lines go out one
after another, each with Enter. `{{connection.host}}`, `.user`, `.port` and `.name` are replaced
with the connection's values ([terminals.ts](src/terminals.ts)).

An SSH connection can name one as its **startup command** ("Run when connecting" under Options
in the form); it runs as soon as the terminal is up, and again after every reconnect. On a
backend the snippets reach all members through the sync — but only owner and admin may change
them there, because a startup command runs unasked in every colleague's terminal. So passwords
do not belong in them.

### Side by side and broadcast

The columns icon on the right of the tab bar shows up to four tabs at once, starting with the
front one: two or three side by side, four as 2 × 2. The panes stay where they are — only their
position changes —, so that no terminal is rebuilt. Picking a tab outside the group shows only
that one again; going back to one from the group brings the group back.

Next to it, **Broadcast** makes every input in one of the terminals go to all of the group, and
a snippet as well — with the placeholders of the respective connection. The tiles then have a
yellow border; in the snippet menu "only here" still sends to just the one.

### Proxy

SSH, FTP and S3 can go through a SOCKS5 or HTTP CONNECT proxy
([proxy.rs](src-tauri/src/proxy.rs)). Two levels:

- The **default proxy** belongs to this device (overview → "Proxy"), not to the workspace:
  whether a proxy is needed depends on the network the computer is in. It lives in `proxy.json`,
  its password encrypted with the device key.
- A **connection** can deviate from it: directly, or through a proxy of its own. That travels
  with the connection, through the backend too, and therefore without a login.

With SSH the proxy applies to the first hop; everything after it is built by the jump host. With
FTP every data connection goes through the proxy too, and to the connection's host rather than
to the address from the `PASV` reply. Implicit FTPS and active mode do not go through a proxy.
SOCKS5 resolves names at the proxy, just as HTTP CONNECT does. Checked against Dante and
tinyproxy from [scripts/proxy](scripts/proxy/Dockerfile), both with authentication, in front of
hosts that can only be reached behind them:
`cargo test --lib proxy::tests::through_real_proxies ftp::live::through_a_proxy -- --ignored`.

### Host keys

Before signing in, the server's key is checked. Two files are consulted:

- `known_hosts` next to `workspaces.json` — the only one the app writes to.
- `~/.ssh/known_hosts` — read only, so that a host already trusted in a terminal does not have to
  be confirmed a second time. The app never changes this file; other SSH clients on the machine
  depend on it.

If both files say something, the app's own wins: an answer given here should not be overruled by
an old entry somewhere else.

If the host is unknown, the app asks — with the fingerprint in the same `SHA256:…` format that
OpenSSH prints. If instead a *different* key of the same type is stored, this is shown as a
warning and confirmed twice: either the server was set up anew, or someone else is answering
under the same address.

## Local terminal

The "+" in the tab bar offers this computer's shells under **Local**: PowerShell 7, Windows
PowerShell, Command Prompt, every WSL distribution and Git Bash — depending on what is
installed; this is checked every time the menu opens (`local_shells` in
[local.rs](src-tauri/src/local.rs)). Below them a custom command can be entered; the last one
stays. On Linux and macOS the candidates are `$SHELL`, bash, zsh, fish and sh — not tried yet
there.

The shell runs in a pseudo terminal ([portable-pty](https://crates.io/crates/portable-pty),
ConPTY on Windows) and looks like an SSH session in the tab: the same terminal, the same
settings, search, copy, side by side and broadcast. Events and commands are called `local:…` and
`local_…` instead of `ssh:…` and `ssh_…`. Nothing is stored, and a local tab does not come back
after a restart. There are no snippets there, because they belong to a workspace.

ConPTY asks for the cursor position at startup (`ESC[6n`) and waits for the answer — xterm.js
gives it on its own. And closing a pseudo terminal on Windows waits until conhost is done; it
therefore runs in a thread of its own.

## MCP server

So that Claude and other agents can use WireTerm — switched on in the overview under **MCP**. An
HTTP endpoint on `127.0.0.1` (port 47821, configurable) following the
[Model Context Protocol](https://modelcontextprotocol.io), "Streamable HTTP" without a stream
from the server: every request gets its answer as JSON. Whoever wants to talk to it needs the
token from the dialog as `Authorization: Bearer …`; it is stored encrypted with the device key in
`mcp.json`. A request with an `Origin` other than a loopback host (`localhost`, `127.0.0.1`,
`[::1]`) is refused, so that a web page cannot get in through DNS rebinding. For Claude Code the
dialog shows the ready-made `claude mcp add` command.

| Tool | What it does | Confirmation |
|---|---|---|
| `list_connections` | Connections of all workspaces: name, type, host, port, user | no |
| `list_snippets` | The snippets of all workspaces | no |
| `list_terminals` | The open terminals, SSH and local | no |
| `read_terminal` | The last lines of an open terminal | no |
| `list_files` | A directory over SFTP, FTP or S3 | no |
| `run_command` | A command over SSH, without a terminal; output, error output, exit code | **every time** |
| `send_to_terminal` | Types into an open terminal | **every time** |

The protocol is spoken by [mcp.rs](src-tauri/src/mcp.rs); execution happens in the window
([mcp.ts](src/mcp.ts)), because that is where the connections, the terminals and the dialog are.
A call goes to the front as `mcp:call` and comes back through `mcp_answer`. The confirmation
dialog names the agent, the target and the exact command. Enter does not answer it, "Run" only
becomes clickable after a moment, and the focus is on "Decline" — it can pop up while someone is
typing in the terminal. No tool hands out a password, a key or a vault reference.

`run_command` signs in anew for every call (`ssh_exec`), through the same jump hosts and proxies
as a tab, and stops after the time limit (default 60 s) or at 1 MiB of output per stream.
`list_files` opens a session of its own and closes it again; an open tab stays where it is.

Tested: the protocol and the HTTP path (token, origin, methods) in `cargo test --lib mcp`,
`ssh_exec` against the container from [scripts/ssh-jump](scripts/ssh-jump/Dockerfile) with
`cargo test --lib ssh::tests::jump_a_command_returns_output_and_status -- --ignored`.

## SFTP

An SSH tab switches between terminal and file view. These are **not two connections**: SFTP is a
subsystem of SSH and runs as a second channel over the same connection, behind the same host key
check and the same sign-in. Whichever of the two is opened first pays for the login; the second
only costs a channel. The connection therefore belongs to the tab, not to the terminal —
`Transports` in [ssh.rs](src-tauri/src/ssh.rs) holds it, and only `session_close` hangs up.

### Transfers

A folder is not transferred as a folder. The frontend walks it and queues **one transfer per
file** — otherwise one row would sit at 0 % for a minute instead of showing what is happening.
Against symlinks pointing in a circle, the walk remembers the directories it has visited by their
resolved path.

Writing always goes to `<target>.wtpart`, renamed only once all bytes are confirmed. There are two
reasons: there is never half a file under the real name that looks like a finished one — and a
cancelled transfer may keep its fragment instead of throwing it away. Whatever has been lying
around for more than 30 days is cleaned up at startup: the entry in `partials.json` and the
fragment, as far as it is on this computer. Half an upload on a server stays there.

Whether that fragment still fits later is not decided by its length. On cancelling,
`partials.json` next to `workspaces.json` records where it came from, how large the source was
and when it was last modified ([resume.rs](src-tauri/src/resume.rs)); a transfer is only resumed
if all of that still holds. A source replaced with one of the same length since the cancel is
caught that way, instead of being copied into the file. The record is only written on cancel —
a successful transfer has nothing to remember, and an entry written per file would mean two
hundred writes for a folder with two hundred files. The price is a fragment from a killed
process: it has no entry, so it is not resumed but written anew.

A fragment disappears when its row in the queue is **discarded** (✕). "Cancel" alone keeps it —
that is the difference between "continue later" and "don't need it any more".

SFTP's own `rename` refuses to overwrite an existing target. When uploading, the old target is
therefore removed first — allowed only because at this point the overwrite question has already
been answered.

Several transfers run at once — three by default, adjustable between 1 and 10 via the gear at
the top right ("Simultaneous"). They share the one SFTP channel: `SftpSession` matches replies by
request ID and has requests in flight in parallel — that is the intended use, not a workaround.

The gain lies in overlapping the wait for replies, not in more bandwidth. For a single large file
the setting therefore does nothing: russh-sftp keeps sixteen requests in flight for it anyway
and fills a fast connection on its own. Transferring many small files, on the other hand, costs
one round trip per file, and that can only be hidden by several transfers running at once. The
setting takes effect immediately: raising it starts more transfers in the middle of a running
folder.

### Already exists

If a name is already taken at the target, a dialog asks — **one row per name**, each with its
own answer (Replace, Rename, Skip) and a header row that sets all of them at once. "Only if
newer" fills in the rows by modification date.

Two **folders** of the same name are not a conflict but are merged. What collides *inside* them
turns up while walking the folder and is asked about afterwards in a second round, labeled with
the path below the dropped folder. Previously only the top level was checked here: a folder
confirmed once then silently overwrote every file inside it.

This is found out through **one listing per target directory**, not through one existence check
per name. That is not only less traffic, it also yields size and date of what is already there —
and that is exactly what the dialog shows.

### Moving

A drag within the same pane onto a folder **moves**: nothing crosses the connection, so there is
no transfer, but a `rename` on the respective side. The overwrite question is the same, because
the result is the same — something at the target ceases to exist. Only merging is impossible
here: a `rename` cannot put one folder into another, so a folder of the same name is a real
conflict here.

### Permissions

`chmod` can optionally apply to a folder's contents too. Files do **not** get the same mode as
the folders, but the same without the execute bits — unless they already carry one. That is the
rule behind `chmod -R a+X`, and it prevents the classic accident of making every file in a
source tree executable with a `755`.

A recursive run does not stop at the first "permission denied" but keeps count: one directory
without permissions should not hold up the other nine hundred. What did not work is shown
afterwards in the pane's error line.

### Drag and drop

Two mechanisms compete for the same window here, and a window has only **one** OS drop target.
Tauri claims it (`dragDropEnabled`, on by default) so that a file dragged from the file manager
arrives as a real path — the queue needs that, because it moves files by path and a file of
several gigabytes should never pass through the renderer. The price: the WebView sees no drag at
all, and HTML5 drag and drop does not work anywhere in the window.

Dragging between the two panes therefore uses ordinary pointer events. `setPointerCapture` is
deliberately *not* involved: a captured pointer makes the browser redirect `click`, `dblclick`
and their `event.target` to the capturing element — then no row can be told apart any more, and
a click no longer selects anything.

### Editing on the server

"Edit" downloads a working copy to `%TEMP%/wireterm-edit/<id>/`, opens it with the system's
program and watches it.

Opening goes through `tauri-plugin-opener`, and the path has to be within its **scope** —
otherwise all you get is "Not allowed to open path". Allowed in
[capabilities/default.json](src-tauri/capabilities/default.json) is exactly
`$TEMP/wireterm-edit/*/*`, that is one level of ID and the file below it. The working copy is
therefore placed via `app.path().temp_dir()` and not via `std::env::temp_dir()`: `$TEMP` in the
scope *is* that function, and two sources for the same directory would be one environment
variable away from drifting apart. Capabilities are compiled in — a change to them needs a new
Rust build, not a reload of the frontend. A save is detected by **polling** every second, not by
a file system watcher: a watcher on a single path misses the common way of saving "write a new
file, then rename", because the inode changes. A change has to look the same twice in a row
before it is uploaded — otherwise a half-written file would go over the wire.

### Which editor, and when it is done

Without a setting, the system opens the file with whatever program it uses anyway. The app then
never learns when someone is done with the file — the entry in the bar stays until it is closed
by hand.

If an editor is set under the gear, the **backend** starts it itself (`tokio::process`, not the
opener) and waits for the process. When it exits, the watcher does one last comparison — a save
right before it is otherwise exactly what would get lost — and sends `state: "closed"`,
whereupon the row disappears.

The catch is single instance: most editors hand the file to a window that is already open and
exit immediately. Their process ending then says nothing about whether someone is still typing,
and ending the watch would simply be wrong. If the started process therefore ends in under
three seconds (`HANDOFF` in [edit.rs](src-tauri/src/edit.rs)), that counts as a handoff and not
as the end: the row stays, but gets a question mark and explains in its tooltip which argument
fixes it — `-multiInst -nosession` for Notepad++, `--wait` for VS Code.

### Lifetime

The watch runs as long as the tab's file view is open, even while the terminal is in front of
it. Closing the tab ends it — `EditWatchers::stop_for_session` in [edit.rs](src-tauri/src/edit.rs)
sets the stop flag of every edit belonging to that tab. That is how it has to be: an edit is only
worth as much as the connection beneath it, and that has just gone away.

## FTP

FTP is **not** a subsystem of something else but a protocol of its own — and the one difference
that shapes the whole module is this: **an FTP connection cannot do two things at once.** The
control connection takes one command after the other, the data connection one transfer after
the other. Three transfers at once therefore mean three logins, not one connection used harder.

A tab therefore owns a **pool** instead of a connection. A listing borrows one, uses it and
returns it; a transfer holds one for as long as it runs. The pool grows to what the queue asks
for — whose limit is the "Simultaneous" setting — and keeps what it has opened, because a login
costs several round trips and a folder with two hundred small files would otherwise pay for it
two hundred times.

Returned connections are only reused after a `NOOP`: an FTP server hangs up faster than anything
else in this app, and learning that from a failed listing would be worse than one extra round
trip. A connection on which a command failed does not go back at all — an unread reply may be
hanging on it, and after that the client answers the wrong question.

### What the server says and what it doesn't

FTP is older than any convention the rest of the app relies on. There is no `stat`, so a listing
is parsed from text whose format the server was never required to follow. `MLSD` fixed that in
2007 and is used where `FEAT` offers it; otherwise `LIST`.

Listing always uses `CWD` followed by a bare `LIST`, never `LIST <path>`: many servers read a
path argument as a list of flags if it starts with a dash, and others split it at spaces.

What the server does **not** say stays empty instead of being guessed. `MLSD` only carries
permissions if it sends `UNIX.mode`; a DOS listing has none at all. In both cases the parser
fills in `rwxrwxrwx` — a default that reads like an answer. The raw line is therefore asked
whether something really was there, and where it was not, the pane shows a dash, just as for the
local side.

Whether a symlink leads to a directory can only be answered by **going into it**. That costs two
round trips per link, hence the cap at 32 (`LINK_LIMIT`); beyond that, links are listed as what
they are and cannot be opened.

Changing permissions goes through `SITE CHMOD` — not part of FTP but a local extension. Nearly
all Unix servers support it, IIS does not. There is nothing to fall back on: if the server says
no, its wording appears in the dialog.

### Encryption

Three modes: none, **explicit** (`AUTH TLS` on the existing connection — today's way) and
**implicit** (TLS from the first byte, classically on port 990 — outdated, but often the only
option on older servers). TLS runs on rustls with `ring`, for the same reason as russh: no
cmake, no NASM.

Certificates are checked against the root certificates of the **operating system**, not against
a bundled list — a company's own CA is in the Windows certificate store and nowhere else.

If the system does not trust a certificate — usually a self-signed one —, the client asks **in
the same dialog as for an unknown SSH host key** and shows the SHA-256 fingerprint in the
notation of `openssl x509 -fingerprint -sha256`. After "Trust" it remembers exactly this
certificate for host and port ([certificates.rs](src-tauri/src/certificates.rs), file
`trusted_certificates` next to `workspaces.json`) and connects a second time: the handshake
cannot wait for an answer, the check inside it is synchronous. A certificate the system trusts
never reaches the remembered ones; a different one than the remembered one brings up the
question again, as "has changed". In a workspace on a backend the answer goes into the workspace
like an SSH host key — as an entry of type `x509-sha256` with the fingerprint as hex —, and the
sync enters it on the other members' devices. The host key management shows remembered
certificates in both lists and can remove them. S3 over HTTPS asks the same way.

"Don't verify certificate" remains configurable per connection. What it drops is the half of
TLS that tells the intended server apart from anyone who can answer in its place; what remains
is encryption against eavesdropping. The signature checks in the handshake deliberately stay
active — without them someone could sit in between without even owning a key.

### Resuming

The same `.wtpart` mechanism as over SFTP, with two peculiarities:

- **Downloads** resume with `REST` before the `RETR`. Whether the fragment fits is decided, as
  everywhere, by [resume.rs](src-tauri/src/resume.rs) — source, size and modification time must
  still match. The modification time comes from `MDTM`; where the server does not know it, the
  size carries the check alone.
- **Uploads** append with `APPE`, not with `REST` plus `STOR`. Both are meant for resuming, but
  servers disagree on whether `REST` applies to an upload at all — and "append at the end" is
  exactly what is meant here. How far the fragment reaches is asked of the server via `SIZE` and
  not assumed: what actually arrived is rarely exactly what was written before the cancel.

`SIZE` is not guaranteed. Without it, the progress bar loses its total and the transfer its
ability to resume — nothing more, the bytes still arrive.

### Passwords

Four sources: from a [vault](#vaults) (only the reference is stored), a prompt when connecting
(nothing is stored — once per tab, after which the backend keeps the input in memory so that
parallel transfers do not ask again), typed in directly (encrypted in `workspaces.json`, see
[Local secrets](#local-secrets)) and anonymous.

### Testing

The assumptions above — does the server offer `MLSD`, does it understand `SITE CHMOD`, does
`APPE` really resume — cannot be derived from the RFC but only settled against real servers.
[ftp.rs](src-tauri/src/ftp.rs) has two test modules for that:

```bash
cargo test --lib ftp                       # listing parser, without a server
cargo test --lib ftp::live -- --ignored    # against real servers
```

The live tests need Docker containers; the commands for them are in the doc comment of the
`live` module. Three of them, because they differ exactly where it matters: **vsftpd** has no
`MLSD` and so tests the `LIST` parser, **pure-ftpd** has `MLSD` and (with `-R`) refuses
`SITE CHMOD`, and one with a self-signed certificate checks both halves of the "Don't verify
certificate" checkbox — checked, it must fail; unchecked, it must get through.

## S3

Object storage as the third connection type — AWS S3 and everything that speaks its API: MinIO,
Ceph, Wasabi, Backblaze B2, Hetzner, IONOS. That is why the type is called "S3" and not
"Amazon".

The file view looks like it does over SFTP. Underneath, almost nothing is the same, and the one
sentence everything else follows from is: **there are no directories.**

### Folders that don't exist

A bucket is a flat list of keys. `photos/2024/holiday.jpg` is a name with slashes in it, not a
path. What the pane shows as a folder only comes into being when listing: `ListObjectsV2` with
`delimiter=/` folds everything up to the next slash into a *common prefix*, and that becomes a
row with a folder icon.

The rest follows from that:

- **An empty folder does not exist.** So that "New folder" still does something visible,
  WireTerm creates an empty object with a trailing slash — the same convention the AWS console
  uses. When listing, it is filtered out again, because it *is* the folder rather than lying in
  it.
- **There is no rename.** It is copied server-side (`x-amz-copy-source`) and deleted, for a
  folder once per object in it. That is not atomic: if it breaks off halfway, half of it is under
  the new name.
- **Deleting is one request per object.** Sixteen of them run at once, otherwise a folder with a
  thousand small files feels like a hang. "Cancel" in the status line stops what has not started
  yet; what is deleted stays deleted.
- **A listing stops at 20,000 entries** and says so in the status line. A `*` at the end of the
  path narrows it down: `/bucket/photos/2024*` shows what starts with `photos/2024`.
- **Temporary credentials** need a session token. It goes in the form below the secret access
  key, is stored in the same encrypted value (separated by a line break) and is signed along as
  `x-amz-security-token`, in presigned links too.
- **There are no permissions.** No `chmod`, no owners, no modes — the permissions column shows a
  dash, and "Change permissions…" is not in the menu at all. What S3 has instead are policies
  and ACLs; that is a different thing with different words and does not belong behind a chmod
  dialog.
- **There are no symlinks.** That removes all the round trips SFTP and FTP spend on finding out
  where one points.

The top path is the **list of buckets**; below it is `/bucket/key`. If the connection names a
bucket, the view starts inside it and does not lead higher — an access key that may only access
one bucket usually may not see the bucket list either. Without a bucket the list is at the top,
and "New folder" creates a new bucket there. A bucket is only deleted if it is empty — otherwise
the server refuses, and exactly that refusal stands between a misclick and a vanished bucket.

### Signing

Every single request is signed with **AWS Signature Version 4**: build the canonical form, hash
it, HMAC it with a key derived from date, region and service. There is no session that stays
open, so there is no pool as with FTP and no channel as with SFTP either — a tab holds a
`reqwest::Client`, which reuses its connections itself.

**No AWS SDK**, for the same reason that runs through the whole project: its crypto backend is
`aws-lc-rs`, which needs cmake and NASM to build on Windows. The signature is about a hundred
lines in [s3.rs](src-tauri/src/s3.rs); HMAC and SHA-256 come from `ring`, which is in the tree
anyway because of russh and rustls. TLS is the same rustls as for FTPS, including the "Don't
verify certificate" checkbox and the prompt for a certificate the system does not trust — both
read their configuration from [tls.rs](src-tauri/src/tls.rs).

Two things about the signature are easy to get wrong and are therefore named in the code: the
path is encoded **once**, not twice, and the query string is sorted by the **encoded** name.

### Addressing

AWS expects the bucket in the host name (`bucket.s3.region.amazonaws.com`), everything else in
the path (`endpoint/bucket`) — because `bucket.10.0.0.5` resolves nowhere. That is the "Bucket in
path" setting, and it decides whether a connection to anything other than AWS works at all. It
changes not only the URL but also the signature: the Host header is signed along.

The **region** belongs to the signature, not to the address. AWS rejects a wrong one and names
the right one in its reply — which then also appears in the error message. Most other
implementations ignore it, which is why `us-east-1` is a usable default.

### Transfers

A download is a `GET` that, as everywhere, writes to `.wtpart` and only renames at the end; it
resumes with a `Range` header. Whether the fragment fits is decided by the same check as for the
other protocols ([resume.rs](src-tauri/src/resume.rs)) — source, size and modification time must
still match. If the server does not answer the `Range` with `206`, the download starts from the
beginning instead of writing the file over the fragment.

**An upload, on the other hand, leaves nothing half-done behind**, and so there is no `.wtpart`
there: a `PUT` only creates the object once the last byte has arrived. From 64 MiB on it becomes
a **multipart upload** — a single `PUT` that dies at 90 % would otherwise have to start over, and
above 5 GiB S3 does not accept one at all. A cancelled multipart upload is cleaned up
(`AbortMultipartUpload`); leftover parts would otherwise sit invisibly in the bucket and be
billed. The price: an upload cannot be resumed.

Whatever a killed process or another program leaves behind anyway is reported by the pane: the
first time a bucket is opened in a tab, it asks `ListMultipartUploads` (for a connection with a
prefix, only below it) and, if uploads **older than one day** are lying there, shows a notice
with "Clean up". Younger ones are left alone — they might be running somewhere right now. If the
key may not list the uploads, the notice simply does not appear.

**Renaming and moving** are copying and deleting, per object. The copy names the **storage class
of the source** (from the listing or the `HEAD`), because `CopyObject` does not inherit it and
otherwise lands in `STANDARD`; the connection's class only applies to uploads. Above 5 GiB,
where `CopyObject` stops, the copy is made in parts (`UploadPartCopy`, 512 MiB per part).
Content-Type, Cache-Control and `x-amz-meta-*` are taken over from the `HEAD`, and every part
demands the same version of the source via `x-amz-copy-source-if-match`. Tags and ACLs do not
come along in this case.

The request body is a custom `http-body` with a known length. S3 refuses a `PUT` without
`Content-Length`, and a streamed body otherwise has none — so a task reads the file piece by
piece into a channel that is two pieces deep. That keeps "this much has been transferred" close
to the truth: what has been counted has nothing ahead of it but the wire.

### Links

From the context menu in the server pane: **"Create link…"** builds a presigned URL for the file
clicked — valid from one hour up to at most seven days (SigV4 allows no more). Whoever has it can
download the file without an account, without a key and without this app. The link contains the
access key ID and the signature, but not the secret key.

This is the one gesture that exists only here, and it is the reason why the protocol differences
are not hidden in the frontend: [remote.ts](src/remote.ts) says per connection whether there are
permissions and whether there are links, and the pane draws its menu accordingly.

### Credentials

The **access key ID** goes in the user field — it is the name under which every request is
signed. For the **secret access key** there are three sources: from a [vault](#vaults) (only the
reference is stored), a prompt when connecting (nothing is stored, once per tab) and typed in
directly (encrypted in `workspaces.json`, see [Local secrets](#local-secrets)).

There is no "anonymous" as with FTP: an unsigned request only reaches a bucket that is open to the
whole internet, and nobody creates a connection entry for that.

The prompt itself is the same as for FTP — [secret.rs](src-tauri/src/secret.rs) asks the
question, waits for the answer and keeps it in memory as long as the tab lives. Only the word
differs: a secret access key is not a password, and calling it one sends people to the wrong
place in their provider's console.

### Testing

The signature is the part you cannot tell by looking at it: it is accepted or rejected, and a
rejection does not say which of the twenty bytes was wrong. That is why a unit test checks it
against **Amazon's own example** from "Authenticating Requests: Using the Authorization Header";
live tests against MinIO settle the rest:

```bash
cargo test --lib s3          # signature, paths, XML — without a server

docker run -d --name wireterm-s3test -p 9100:9000 \
  -e MINIO_ROOT_USER=wireterm -e MINIO_ROOT_PASSWORD=secret123 \
  quay.io/minio/minio server /data
cargo test --lib s3::live -- --ignored --test-threads=1
```

MinIO rather than AWS, because it is the case that needs the most care — bucket in the path, a
port other than 443, no TLS — and because a test that costs money is a test nobody runs. What is
checked is what can only be settled against a real server: that keys really become folders, that
a `Range` really resumes, that a multipart upload really comes back as the same file, and that a
presigned link really opens without a key.

## Cloud and custom backend

A workspace lives either locally in `workspaces.json` or on a backend. **"Cloud" and "custom
backend" are the same thing** — the same protocol, the same encryption, the same sync. The only
difference is where the address comes from: the cloud brings its own (`CLOUD_URL` in
[cloud/http.rs](src-tauri/src/cloud/http.rs), the hosted service at
`https://api.wireterm.wirecore.net`; the UI fetches it via `cloud_url`), while for a custom
backend someone types it in.

The other side is described in `CLIENT.md` of the WireTerm backend; what is written here is the
client half of it.

### Where the account lives

At the very bottom of the workspace rail, set off by a line and outside the scrolling part: an
account **is** not a workspace, but what workspaces hang off. Clicking it opens signing in and
registering — and, as soon as there are accounts, their list with Lock, Sign out, Change master
password and Remove account.

The tile shows the initials as soon as it is clear whose account is meant, that is with exactly
one; with several it shows a symbol. A dot in the corner reports the most urgent state across all
accounts — signed out weighs more than locked: one is solved with a password, the other stops
the sync entirely.

### Signing in with WireCloud

Whether a backend has a sign-in of its own or hangs off WireCloud, it says itself:
`GET /.well-known/wirecloud-tool.json` names `audience` and `wirecloud_url` (may be `null`, in
which case the local mode with cookie sign-in applies as before). The UI detects this when adding
a backend and in the account dialog (`cloud_wirecloud_detect`) and shows "Sign in with WireCloud"
instead of the password form ([WireCloudLogin.vue](src/components/WireCloudLogin.vue)). The master
password stays separate from that and unchanged.

The flow is in [cloud/wirecloud.rs](src-tauri/src/cloud/wirecloud.rs):

1. Authorization code with PKCE (S256) and `state`; the browser comes back through a one-time
   listener on `127.0.0.1` (only `GET /callback`; host and `state` are checked).
2. Exchange the code for an access token (5 minutes) and a refresh token (30 days, rotating).
3. Per request a tool token (`POST /v1/tool-tokens`) as bearer; on `401` exactly one new token
   and a retry ([cloud/http.rs](src-tauri/src/cloud/http.rs)).

The refresh token is stored on disk only encrypted with the device key (like the cookie
sessions), access and tool tokens only in memory. Refreshing happens strictly one after another
(one refresh at a time, everyone waiting shares the result), because WireCloud revokes the whole
session if a refresh token shows up twice. On `invalid_grant` you have to sign in again.

In WireCloud mode there is no `/api/auth/*`: organizations, teams and invitations are managed by
WireCloud; the client hides them and points there. If the backend already has a local account,
the client asks for the previous password on `409 WC-EC` and links it
(`POST /api/wirecloud/link`); `WC-LD`, `WC-NV`, `WC-NN` and `WC-RL` appear as understandable
texts.

**Tests:** `cargo test --lib cloud::` runs without a network (PKCE against the RFC vector,
`state`, listener, refresh under concurrency, mode). The live tests against a running stack are
`#[ignore]`:

```bash
# Credentials of a throwaway account go into a file (0600), never to the output
WIRECLOUD_ENV_FILE=/path/live.env node scripts/live-wirecloud.mjs
set -a; . /path/live.env; set +a
cargo test --lib cloud::wirecloud::live -- --ignored --test-threads=1
```

They need a running WireCloud and a WireTerm backend with `AUTH_MODE=wirecloud` (default
`http://localhost:18080`, changeable via `WIRETERM_BACKEND`); what exactly is described at the
top of [scripts/live-wirecloud.mjs](scripts/live-wirecloud.mjs).

### Organization, project, connection

There is no workspace model of its own on the server. An **organization is** a workspace. Whoever
registers gets one right away — "Personal" (named in the account's language) —, which can be
renamed but not deleted: otherwise one click would leave someone without any workspace, and a
second one would never come into being.

The client brings it into the rail by itself after signing in, and at startup also for an account
that signed in long ago. Once per account: whoever takes it out of the rail with "Remove only
here" will not find it there again at the next start.

Two levels decide who sees what:

- The **role** (`owner`, `admin`, `member`) decides who may create, delete and share projects —
  and whether someone sees all projects or only the shared ones.
- The **share** points to a team or to the whole organization and grants `editor` or `viewer`.
  For `member` it decides which projects exist at all.

A project without a share answers with 404, not 403. That a project of this name exists is
information in itself.

### Encryption

Two passwords, and the difference is the whole point:

| | Sign-in password | Master password |
|---|---|---|
| for | signing in to the server | opening the secrets |
| where it is stored | as a hash on the server | **nowhere**, not even as a hash |
| resettable | yes, by mail | no — that is what recovery codes are for |

If the two were the same, the server could read along at sign-in what the secrets are sealed
with.

Between a secret and a recipient there are two layers:

```
secret       ──encrypted with──▶  project key PK  (32 bytes, one per project)
project key  ──wrapped with────▶  public key      (one per person)
```

The secret is encrypted **once**, no matter how many people may read it. Only `PK` — 32 bytes —
is wrapped once per person. The most common mistake would be to encrypt it directly with your
own public key: then nobody but yourself could ever read it.

From this follows the sentence that matters: **the server can record a share, but cannot grant
one.** Only someone who already has `PK` can wrap it — that is, a client. That is why someone
newly shared with first sees the connections and not their credentials, and why
[cloud/sync.rs](src-tauri/src/cloud/sync.rs) checks on **every** sync who is still missing
something and hands it over.

The algorithms for "v1", all from the RustCrypto family and thus without a C toolchain:

| for | Algorithm |
|---|---|
| Key pair | X25519 |
| Master password → key | Argon2id, parameters from the database (default 64 MiB, t=3, p=4) |
| Private key, secrets | XChaCha20-Poly1305 |
| Wrapping the project key | X25519 + HKDF-SHA256 + XChaCha20-Poly1305 |

The derivation parameters travel **along** and are never taken from a constant in the client:
otherwise they could not be raised without locking out existing accounts.

A connection's secret is encrypted with the `connectionId` as additional authenticated data.
That costs one line and prevents a manipulated server from moving a ciphertext from one
connection to another.

### Recovery codes

Setup creates eight codes; each one wraps **the same** private key once more, under a salt of its
own. They are shown once — **the server does not know them, not even as a hash**: a hash would be
a point of attack for exactly the database that is supposed to be unable to read anything.

A code is recognized by its first group in plain text, so that the client finds the matching row
instead of trying eight Argon2id runs. That gives away 20 of the 120 bits; the remaining 100
carry it.

A redeemed code immediately sets a new master password **and a new set of codes**: every old one
opened the same door.

### What is stored where

| Where | What |
|---|---|
| `cloud-accounts.json` | Address, email, session (encrypted with the [device key](#local-secrets)) |
| `cloud/<organization>.json` | The copy of the workspace, secrets **only as ciphertext** |
| only in memory | The private key and every project key |

The third row is the one that matters. After a quarter of an hour in which nobody touched the
computer, it is cleared and the master password is asked for again. What counts is input at the
computer, not access by WireTerm: someone working in another window should not come back to a
locked vault. Windows answers that with `GetLastInputInfo`
([cloud/idle.rs](src-tauri/src/cloud/idle.rs)); where the system gives no answer, the last
access to the vault counts instead — the same rule as in the Bitwarden module.

Signing in goes through better-auth's session, that is through a cookie. A desktop client has no
browser that keeps one; [cloud/http.rs](src-tauri/src/cloud/http.rs) therefore remembers name and
value and sends them back. That is why a sign-in survives a restart. On disk the cookie is
encrypted with the device key; if that is not open at the moment, a new session is not written
at all rather than in plain text.

### Sync

Every organization counts a `revision`. `GET …/sync?since=N` returns what came after — so the
first time, with `since=0`, everything.

Three things matter here:

- **Tombstones.** Nothing is deleted on the server; `deletedAt` is set. A device that was offline
  since the deletion would otherwise never learn of it. In the local copy the row is then really
  removed: a tombstone is a message, not an entry.
- **Project keys and shares are not a delta.** They always come in full and are replaced rather
  than merged — otherwise a revoked share could never be got rid of.
- **Revisions are strings**, but are compared numerically: as strings, `"9"` is greater than
  `"10"`.

The rest of the app still only knows `workspaces_load` and `workspaces_save` and sends the whole
tree every time. For a file that is right; for a backend that someone else is working on too, it
would be an overwrite. [cloud/diff.rs](src-tauri/src/cloud/diff.rs) therefore compares what comes
in with the last known copy and turns it into individual calls:

```
storage::workspaces_save  ──▶ diff::plan  ──▶ cache::Pending  ──▶ sync::flush
                                   │                                   │
                             crypto::seal                          api::put_*

storage::workspaces_load  ◀── cache::tree ◀── cache::apply  ◀── sync::run
                                   │
                             crypto::open
```

Encryption happens **when queuing, not when sending**: there is never plain text in the queue,
which is stored on disk.

This is not only checked against itself: `cargo test --lib cloud::live -- --ignored` goes the
whole way against a running backend, up to two people, a share and a revocation. What it needs
is at the top of [cloud/live.rs](src-tauri/src/cloud/live.rs).

Two rules in the comparison concern data loss and are each covered by a test:

- **An empty secret is not a secret.** Otherwise someone opening a locked workspace and changing
  a name would have replaced every ciphertext on the server with an empty string. The decision is
  therefore made not by the value but by the source: an `inlineKey` without content leaves things
  as they are, a switch to `keyFile` clears them.
- **The order of the queue is part of its meaning.** A project comes before its connections, a
  project key before the first secret under it — the server rejects a ciphertext with an unknown
  `keyId`, because one that nobody can open would be silent data loss. At the first snag the
  queue therefore stops instead of skipping.

### Offline

Without a network a remote workspace is visible and usable: it comes from the local copy. Changes
land in the queue and go up at the next connection; the rail shows this as a dot on the tile.
Syncing happens at startup, every minute and after every save — but the result is only applied
when no dialog is open: the tree gets swapped, and a form holds a connection from the old one.

What is rejected permanently — not merely a network error — is dropped from the queue and shows
up as a message on the workspace. Keeping it there would mean that nothing behind it ever goes up
again.

Changes to projects and connections name the state they build on (`expectedRevision`). If someone
else has changed the same connection in the meantime, the server refuses with `409 R-CF`: your own
change is discarded, including a secret from the same change, and the workspace says that someone
was faster — until someone dismisses the message, not just until the next sync. Several changes
to the same connection that are still waiting in the queue are merged into one — otherwise the
second would run into the state the first has just moved on.

### Invitations

Invitations are sent under "Members"; the backend sends the mail. The invitee only sees their
open invitations under "Add workspace" once their email address is verified — better-auth
insists on that. The backend sends the link for it on registration; whoever does not have it
(any more) can request it again in the same dialog. *Accepting* works unverified too, which is
why the dialog still takes the link from the invitation mail.

### Host keys

For a remote workspace, trusted server keys belong to the workspace, not the device: otherwise
every team member answers the same question separately, and the fifth repetition is no longer
read. Whoever presses "Trust" in the dialog therefore also enters the key into the workspace;
conversely, every sync writes what is there into the local `known_hosts`.

A revocation only takes effect on the server: the local file stays as it is. It belongs to this
device, and an entry someone confirmed here themselves must not disappear because someone else
takes it out of the workspace.

Both lists can be viewed and revoked under "Host keys" in the overview, with the fingerprint in
`SHA256:…` format. `~/.ssh/known_hosts` does not appear there — the app only reads it.

### A new version of the project key

Whoever loses a share also loses their copy of the project key — but what they have read until
then, they still know. Under "Shares" → "Renew key" ([cloud/rotate.rs](src-tauri/src/cloud/rotate.rs))
a new version is therefore created: wrapped for everyone who is entitled now, and every secret of
the project re-encrypted under it. Whoever has no master password yet gets it at the next sync of
another client. Secrets that cannot be opened here stay under the old version and are reported.
If a share is being removed in the same dialog, it is saved first and renewed afterwards. Checked
in `cloud::live::a_revocation_is_sealed_with_a_new_version`.

When someone is removed from the workspace or from a team, the members dialog offers to do this
right away — for exactly the projects whose current version the person holds without being
allowed to see them any more. Which ones those are is said by the server
(`GET …/members/:user/stale-keys`); a project they still see is not in the list, because they
would get the new version anyway. Checked in
`cloud::live::snippets_startup_command_proxy_and_stale_keys`.

### Reordering and moving

Cards can be dragged in the overview: within a project to reorder, into another project of the
same workspace to move. Dragging uses pointer events, for the same reason as in the file view
(see [Drag and drop](#drag-and-drop)).

On a backend a move is a `PATCH` with `projectId`, and the secret then goes under the new
project's key — otherwise nobody there could open it. That is why a connection with a secret
cannot be moved while locked. A project deleted in the same go is only uploaded after the move,
so that it does not take the connection with it. Checked in
`cloud::live::a_connection_moves_along_with_its_secret`.

## Vaults

Two password managers, and from the outside they look the same: a list of vaults, items in them,
fields in those, and a reference pointing at exactly one of them. That is why a connection does
not say "1Password" but names the source `vault` plus the provider —
[vault.rs](src-tauri/src/vault.rs) is the one door behind which it is decided who answers.

```
{ "source": "vault", "provider": "onePassword", "reference": "op://vault/item/field" }
{ "source": "vault", "provider": "bitwarden",   "reference": "bw://vault/item/field" }
```

The user name (for S3 the access key ID) can come from a vault too. The `user` field then holds
such a reference instead of the name; `resolve_user` in [vault.rs](src-tauri/src/vault.rs)
recognizes it by the `op://` or `bw://` and reads the name when connecting. The field stays the
same, so the backend does not need to know about it.

What applies to both:

- **Only the reference is stored.** The secret is read when connecting, used and dropped; it
  never lands on disk.
- **A secret does not pass through the frontend.** The connection types call `vault::resolve`
  directly. What the webview gets to see are titles, field names and field lengths — the picker
  list, nothing more.
- **The account belongs to the workspace.** With both, every user signs in with their own
  access, so none can be hard-coded. If the account is missing or wrong, the app asks for it
  instead of passing on the provider's error.
- **Both report the same names** for item kinds (`Login`, `SshKey`, …) and field types
  (`Concealed`, `SshKey`, …). Only because of that can the form sort SSH keys to the top and
  preselect the right field without knowing whom it asked.

A third provider would be one more value in the enum and one more branch in `resolve`.

### Older workspace files

A `workspaces.json` from the time when there was only 1Password names the source `onePassword`
and has no `provider`. It is still read: the old name is a serde alias for `vault`, and the
missing provider falls back to 1Password. The next save writes the new form. Checked in the tests
of [storage.rs](src-tauri/src/storage.rs).

A file from before [encryption](#local-secrets) contains keys and passwords in plain text. It is
read as well and, at the first start with the device key available, immediately rewritten
encrypted — not only at the next save.

## Local secrets

Keys, passwords and secret access keys that were typed in are not stored in `workspaces.json` in
plain text, but as `wtenc:v1:…`: XChaCha20-Poly1305 under a **device key**, with connection and
field as `aad` — a ciphertext that someone copies into another connection does not open there.
The same applies to the session in `cloud-accounts.json`. Decryption happens on load in Rust; the
form gets the plain text as before, and on save it is encrypted again with a new nonce.

The device key itself lives in the system's keyring
([local_secrets/](src-tauri/src/local_secrets/), crate `keyring`):

| System | Storage |
|---|---|
| Windows | Credential Manager |
| macOS | Keychain (with unsigned builds macOS asks again after every rebuild) |
| Linux | Secret Service — GNOME Keyring, KWallet — via zbus, pure Rust |

One key rather than one per secret: Credential Manager holds at most 2560 bytes, and an RSA-4096
key is larger. Where there is no keyring — Linux without Secret Service, that is servers, WSL,
minimal window managers —, the device key is wrapped with an **app password** (Argon2id) in
`local-key.json` and asked for at startup.

`local-key.json` exists in both cases and says where the key is. If a keyring that holds the key
fails to answer once, no new one is created because of that — the app reports it and tries again
on request. If the entry is missing entirely (deleted, or the files have moved to another
computer), the old ciphertexts can no longer be opened: the fields arrive empty, the form says
so, and the ciphertext stays in place on save until someone enters something new.

What this protects: the file in a backup, in a synced folder, in the hands of another user. What
it does not: malware running as the same user — it asks the keyring just like WireTerm does.

### Export and import

"Export" in the overview puts workspaces including credentials into a `.wireterm` file,
encrypted **as a whole** (hosts and names too) with a password of its own, Argon2id with the same
parameters as the master password. That is the way onto another computer and the backup against
a lost device key. Workspaces from a backend can be saved this way too, as far as their vault is
open.

Importing goes through "Add workspace" → "Or take it from an export file …". What is in the file
arrives as **local** workspaces with new IDs — an import is a copy — and is encrypted with this
device's key on save.

### Testing

This computer's keyring: `cargo test --lib local_secrets::store -- --ignored`. A container
checks the Linux branch with and without Secret Service:

```
docker build -f scripts/keyring-linux/Dockerfile -t wireterm-keyring-linux .
docker run --rm wireterm-keyring-linux
```

## 1Password

Secrets are read through the 1Password **SDK**, not through the `op` CLI: the tool is meant to be
usable by others without a CLI installed on every client.

### Why a sidecar

1Password offers SDKs only for Go, JavaScript and Python — there is none for Rust. The Tauri
backend therefore cannot embed the SDK directly. Instead, [sidecar/](sidecar/) holds a small Go
program that holds the SDK; Rust talks to it via line-delimited JSON on stdin/stdout.

The process runs **permanently** instead of starting anew per request: setting up the SDK client
costs about 5 s (the WASM core has to be compiled and the auth handshake gone through), single
queries after that only 200–400 ms.

The sidecar is started from Rust, not from the frontend. That way the webview needs no shell
permission and cannot start arbitrary processes.

### Authentication

The **desktop app integration** is used: every user authorizes with their own 1Password account
by biometrics or password. A service account token would be the alternative but is ruled out
here — it would have to be distributed to all users, all would have identical rights, revoking
would only be possible globally, and private vaults would remain unreadable.

This has a few consequences:

- **The project does not run under WSL.** The integration uses a Windows named pipe and
  `op_sdk_ipc_client.dll` from the desktop app; a WSL process reaches neither.
- **On Linux** the SDK loads `libop_sdk_ipc_client.so` from `/opt/1Password/` (or
  `/usr/bin/1password/`) instead. Only the 1Password build from the official apt repository ships
  it — **the Snap package does not contain the library**, and the integration does not work with
  it. The SDK also needs CGO there: building the sidecar requires `gcc`.
- The authorization expires after **10 minutes of inactivity** and when the app is locked. Calls
  then fail and trigger a new prompt.

### Prerequisites

1. 1Password desktop app installed and signed in.
2. In the app: under **Settings → Developer → Integrate with the 1Password SDKs**, enable
   **Integrate with other apps**, then restart the app. On Windows this places `op_sdk_ipc_client.dll` in `%LOCALAPPDATA%\1Password\` and
   opens the IPC channel; on Linux it opens the channel to the bundled `.so`.
3. Go (for the sidecar build), on Linux also `gcc`.

### Account name

The account name belongs to the workspace and is entered there ("Edit workspace" → "Vaults").
Because the desktop app integration signs in every user with their *own* account, it cannot be
hard-coded: it differs per user.

It is shown at the top left of the desktop app's sidebar; `DesktopAuth` accepts the account UUID
or the sign-in address just as well. If the name is missing or 1Password does not know it, the
app asks for it instead of passing on `Account not found`.

The sidecar gets the name as `OP_ACCOUNT` at startup. The account is thereby bound to the process
— a workspace with a different account replaces it on the next access.

### Building

The sidecar binary is a build artifact and is not in the repository:

```bash
npm run build:sidecar   # -> src-tauri/binaries/op-sidecar-<target-triple>[.exe]
npm run tauri dev
```

Tauri expects the target triple in the file name. The build script
([scripts/build-sidecar.mjs](scripts/build-sidecar.mjs)) reads it from `rustc -vV` and builds
for the machine it runs on.

## Bitwarden and Vaultwarden

The same API, the same path — Vaultwarden is a reimplementation of the Bitwarden server, and for
WireTerm they are not two providers but one with a freely chosen address. Both are in
[src-tauri/src/bitwarden/](src-tauri/src/bitwarden/).

### Why no SDK and no CLI

Bitwarden's official SDKs (Go, Rust, Python, …) cover the **Secrets Manager** — a different
product that Vaultwarden does not know at all. For the password vault there is none.

That leaves the `bw` CLI. It would be the official way and would need no crypto of our own, but
it requires an installation of about 150 MB on every client and costs one to two seconds of Node
startup per call. Exactly the requirement that spoke against the `op` CLI for 1Password.

So WireTerm talks to the HTTP API directly and decrypts itself. That is not invented crypto but a
documented format made of standard primitives — but it is crypto in our own tree, and that is the
price of this decision.

### The key chain

```
master password ──PBKDF2/Argon2id(salt = sign-in address)──▶ master key (32 B)
                                                               │
        ┌──────────────────────────────────────────────────────┴─────────┐
        │                                                                │
  PBKDF2(1 round, salt = password)                            HKDF-Expand("enc"/"mac")
        │                                                                │
        ▼                                                                ▼
  master password hash ──▶ to the server                           stretched key
                                                                         │
                                                             decrypts ▼
                                                              user key (64 B)
                                                                    │
                                     ┌──────────────────────────────┴──────────┐
                                     ▼                                         ▼
                        private RSA key ──RSA-OAEP──▶ org key            own items
```

The server only sees the master password hash. The password itself never leaves the device, and
decryption happens only here.

Ciphertexts are stored as text: `2.<iv>|<ct>|<mac>` is AES-256-CBC with HMAC-SHA-256 over it, and
the **MAC is checked before decrypting** — the other way round, the padding error would be an
oracle. `4.<ct>` is RSA-2048-OAEP and only occurs for organization keys. The `1.` format (AES-128,
before 2016) is rejected rather than supported untested.

In the tree for this: `aes`, `cbc`, `rsa`, `argon2`, `sha1`, `sha2`, `base64` — all pure Rust, no
cmake and no NASM, the same requirement as with rustls. PBKDF2, HKDF, HMAC and SHA-256 come from
`ring`, which sits under russh and rustls anyway.

### What is held in memory, and for how long

After unlocking, the backend holds the access tokens, the user key, the private key and the
organization keys — **none of it on disk**. A restart means: unlock again. The same after **15
minutes** without access; the same reasoning by which 1Password lets its authorization expire
after ten minutes.

The sync (`GET /sync`) returns the whole vault at once — there is no endpoint that returns only
titles. What is kept of it is a snapshot in which **every item stays encrypted**: only its title
is decrypted, so that it can be picked, and its field list only once it has been clicked. The
*value* of a field is only read when a connection needs it, and then individually via
`GET /ciphers/<id>`.

### References

```
bw://<vault>/<item>/<field>
```

`<vault>` is `personal` for your own vault or the UUID of an organization. `<item>` is the item's
UUID. `<field>` is one of the built-in names — `username`, `password`, `notes`,
`sshKey.privateKey`, `sshKey.publicKey` — or `custom.<name>` for a custom field.

This is the one point where Bitwarden is weaker than 1Password: there every field has a UUID,
here the built-in ones have fixed names and the custom ones only their title. A renamed custom
field therefore leaves the reference pointing into nothing, and two fields of the same name
cannot be told apart. Bitwarden offers nothing more stable.

A `?ssh-format=openssh` as with 1Password does not exist and is not needed: Bitwarden returns an
SSH key in the form in which it was put in.

### Account and unlocking

Sign-in address and server are set in the workspace ("Edit workspace" → "Vaults"). Empty means
Bitwarden itself; `bitwarden.eu` is recognized. Anything else is your own instance, including a
subpath — `https://vault.example.com/vaultwarden` becomes `…/identity` and `…/api`. HTTPS only;
for a self-signed certificate there is the same checkbox as for FTPS and S3.

The master password is asked for on first access and **stored nowhere**. If the server demands a
second factor, a field for it appears and says which one: authenticator app, YubiKey or email —
with email the code is already on its way. Duo and WebAuthn are missing, they would need a
browser window; see [TODO.md](TODO.md).

### Testing

```bash
cargo test --lib bitwarden
```

Without a server and without an account. What is checked is what can be checked without them and
where a mistake would stay silent: that PBKDF2 takes the password as the secret and the address
as the salt (against a published vector — swapped, it yields 32 equally plausible bytes), that a
tampered ciphertext is rejected rather than decrypted, that every spelling of the API leads to
the same structure, and that a server address turns into the right endpoints.

What this does **not** cover is the path as a whole — sign-in, sync, unwrapping the key chain.
That needs a real account; it is still to be checked against Bitwarden itself and against a
Vaultwarden instance, see [TODO.md](TODO.md).

## Localization

The UI speaks English and German. It starts in the system language — German if the operating
system says German, English otherwise — unless someone picks one under **Language** in the
workspace overview's toolbar. The choice belongs to this person on this device and is kept in
the webview's `localStorage`, like the terminal settings ([i18n.ts](src/i18n.ts)).

Texts live in two places, with English as the source and the fallback for a missing key:

- **Frontend:** `src/locales/<Area>/{en,de}.json`, one area per component or module, loaded by
  vue-i18n and addressed as `t("<Area>.<key>")`; `common` holds what many share. Separate areas
  keep translators and parallel changes out of each other's way. WireLayer's built-in texts come
  with the library and are registered in [main.ts](src/main.ts).
- **Rust:** `src-tauri/locales/*.yml` (rust-i18n), every key with all languages next to each
  other. Every message Rust builds for the UI — errors, prompts, shell names — goes through `t!`.

The Rust side does not guess the language: the UI tells it through the `set_locale` command at
startup and on every change ([locale.rs](src-tauri/src/locale.rs)). Mails are written by the
backend, so it needs the language too: every backend request carries `Accept-Language` (that is
the language of an invitation to someone without an account), and signed-in accounts get theirs
stored on the backend — on sign-in and, after a change, through `cloud_push_locale` — so that
password resets and the like follow it. That push is best effort: a backend in WireCloud mode
does not have the endpoint, and an account that is offline keeps its old language until the next
sign-in.

### Adding a language

1. **Frontend:** add `<code>.json` next to `en.json` in every folder under
   [src/locales/](src/locales/). In [i18n.ts](src/i18n.ts) add the code to `Locale`, `LOCALES`,
   `LOCALE_NAMES` (the name in its own language), the `messages` object and the file pattern,
   map it in `intlLocale` (number and date formats), and let `systemLocale` — and the copy of
   that check in [LanguageDialog.vue](src/components/LanguageDialog.vue) — recognize it. If
   WireLayer ships a translation, register it in [main.ts](src/main.ts).
2. **Rust:** add a line for the code to every key in `src-tauri/locales/*.yml` and the code to
   `LOCALES` in [locale.rs](src-tauri/src/locale.rs); its test checks which locales are
   available.
3. **Backend:** mails are translated there; it has to know the language as well.

## Contributing

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). Please report security
issues privately as described in [SECURITY.md](SECURITY.md), not in a public issue.

## License

WireTerm is licensed under the GNU Affero General Public License, version 3 only
(`AGPL-3.0-only`); see [LICENSE](LICENSE).
