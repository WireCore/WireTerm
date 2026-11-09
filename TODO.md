# TODO

Open items, most important first:

- [ ] **[Code signing for macOS and Windows](#code-signing-for-macos-and-windows)**
- [ ] **[Bitwarden: the path as a whole is untested](#bitwarden-the-path-as-a-whole-is-untested)**
- [ ] [Signing in with WireCloud: the UI in a real window](#signing-in-with-wirecloud-the-ui-in-a-real-window)
- [ ] [Localization: click through the UI in both languages](#localization-click-through-the-ui-in-both-languages)
- [ ] [Workspace storage: open items on the backend](#workspace-storage-open-items-on-the-backend)
- [ ] [Feature gaps compared to electerm, Voltius, Termius and FileZilla](#feature-gaps-compared-to-electerm-voltius-termius-and-filezilla)
- [ ] [More connection types](#more-connection-types)
- [ ] [Bitwarden: other open items](#bitwarden-other-open-items)
- [ ] [SFTP: open items](#sftp-open-items)
- [ ] [FTP: open items](#ftp-open-items)
- [ ] [S3: open items](#s3-open-items)
- [ ] [Smaller open items](#smaller-open-items)

The first item makes the first start warn on macOS and Windows, the second blocks handing
Bitwarden to anyone at all.

## Code signing for macOS and Windows

The update key is in place: its public half is `plugins.updater.pubkey` in
`src-tauri/tauri.conf.json` (minisign key ID `25DAE148DE6F6732`), the private key and its password
are `TAURI_SIGNING_PRIVATE_KEY` and `TAURI_SIGNING_PRIVATE_KEY_PASSWORD` in the `release`
environment on GitHub. Losing the private key means no installed app can update itself anymore —
everyone would have to reinstall once.

**macOS signing and notarization — planned.** Without them Gatekeeper refuses the first start
until it is allowed in the system settings. A Developer ID exists; what the release workflow
needs from it, as secrets in the `release` environment:

- `APPLE_CERTIFICATE` (the "Developer ID Application" certificate as base64-encoded `.p12`) and
  `APPLE_CERTIFICATE_PASSWORD`
- `APPLE_SIGNING_IDENTITY` (e.g. `Developer ID Application: WireCore GmbH (TEAMID)`)
- for notarization an App Store Connect API key: `APPLE_API_ISSUER`, `APPLE_API_KEY` and the
  key file (`APPLE_API_KEY_PATH`)

`tauri-action` signs and notarizes with these on its own; the workflow only has to pass them to
the build step.

**Windows signing — later.** Without a code signing certificate SmartScreen warns. The likely way
is Azure Artifact Signing (formerly Trusted Signing) with a `signCommand` in `tauri.conf.json`.

## Bitwarden: the path as a whole is untested

Access to Bitwarden and Vaultwarden is built into Rust instead of going through an SDK
([README](README.md#bitwarden-and-vaultwarden)) — which makes the whole chain our own code:
prelogin, sign-in, sync, unwrapping the user key, the private key and the organization keys.

What can be tested without a server is tested, in `cargo test --lib bitwarden`: the key
derivation against a published vector, the cipher format including the MAC check, the API's
spellings, the endpoints. What is **not** tested is whether a secret comes out at the end,
because that needs an account.

**To check, once against Bitwarden itself and once against a Vaultwarden instance:**

1. Sign in with a PBKDF2 account and with an Argon2id account (the KDF can be switched in
   Bitwarden's account security settings).
2. Go through the second factor: authenticator app and email.
3. Resolve one secret from the personal vault and one from an organization — the organization
   path goes through RSA and is the part an account without an organization never touches.
4. Use an SSH key item (Bitwarden's own item type) as the key source and actually connect with
   it.
5. Resolve a custom field with umlauts and spaces in its name.
6. Wait a quarter of an hour and check that the lock kicks in and the dialog comes back.
7. Let the access token expire (one hour) and check that it renews without asking for the
   password.

Until that is done, the Bitwarden option is nothing to hand to anyone.

## Signing in with WireCloud: the UI in a real window

The path is implemented ([README](README.md#signing-in-with-wirecloud)), and the Rust side is
verified: the live tests (`cargo test --lib cloud::wirecloud::live -- --ignored --test-threads=1`
— the whole way including renewal, signing out, a denial, cancelling) pass against a local
WireCloud stack, with the account set up by `scripts/live-wirecloud.mjs`. What is still open:

- **The UI is only type-checked** (`vue-tsc`), not clicked through in a real window: signing in,
  linking on `WC-EC`, the hidden management — and that in English and German.

## Localization: click through the UI in both languages

Every visible text goes through vue-i18n or rust-i18n, in English and German. Checked so far
only by the type checker and the tests, not by eye. Once through the whole UI in each language,
looking for:

- **Long texts in narrow places** — German runs longer than English, but not everywhere: buttons,
  tabs, the status bar, the rail, menus, dialog titles.
- **Plurals** — counts of 0, 1 and many in the transfer queue, the file pane, conflicts, members.
- **Text from Rust in the active language** — errors, the codes from the backend and WireCloud,
  the page the browser shows after signing in with WireCloud, and whether switching the language
  reaches all of them without a restart.

## Workspace storage: open items on the backend

`CustomBackend` is implemented — how is in the [README](README.md#cloud-and-custom-backend).
`Cloud` is the same thing with a fixed address (`CLOUD_URL` in
[cloud/http.rs](src-tauri/src/cloud/http.rs)). The live tests (`cargo test --lib cloud::live --
--ignored`) pass against the backend, including its rate limiting. What is open:

- **Sync fetches a delta per workspace every minute.** Normally that is an empty response, but it
  is one request per workspace and minute. A push from the server — WebSocket or SSE — would be
  the next step.
- **The metadata is readable by the server.** Host, port, user name and names are in plain text
  in its database; only the secrets are encrypted. A deliberate decision, so the server can sort
  and merge field by field — but it is worth knowing.

## More connection types

`ConnectionSettings` is a tagged enum with three variants (`Ssh`, `Ftp`, `S3`). A new type means
a new variant there, a matching section in
[ConnectionForm.vue](src/components/ConnectionForm.vue), a backend module with the same command
set and an entry in [remote.ts](src/remote.ts) — the adapter through which the file view
addresses every protocol the same way.

What a protocol **cannot** do is answered there as well instead of hidden: `permissions` and
`links` say per connection whether “Change permissions…” and “Create link…” appear in the menu
at all.

**SFTP is not one** — it is an SSH subsystem and therefore needs no variant of its own, only a
toggle per tab ([README](README.md#sftp)). FTP/FTPS ([README](README.md#ftp)) and S3
([README](README.md#s3)), on the other hand, are types of their own and implemented.

That leaves mainly **WebDAV**, which would share the same command set, and **SMB**, which does
not: there, shares, not paths, belong at the top level — the same question the bucket list
answers for S3.

## Bitwarden: other open items

How access works is in the [README](README.md#bitwarden-and-vaultwarden). What is open:

- **Duo and WebAuthn as a second factor are missing.** Both need a browser window: Duo sends you
  to someone else's UI, WebAuthn wants a device on the USB port. What works is authenticator app,
  YubiKey code and email — everything that comes down to “enter a code”. Anyone with only Duo or
  WebAuthn cannot get in, and the message says so.
- **A reference to a custom field depends on its name.** Bitwarden assigns no ID for it — the
  built-in fields have fixed names, the custom ones only their title. If that changes, the
  reference points nowhere; two fields with the same name cannot be told apart, and the first one
  wins. There is nothing more stable there, but a hint in the form at exactly this spot would be
  more honest than silence.
- **`rsa` 0.9 does not decrypt in constant time** (RUSTSEC-2023-0071). Here it unwraps one key
  per organization locally — the attack would need an oracle that can be fed arbitrary
  ciphertexts any number of times, and whoever can do that is already inside the process. There
  is no pure-Rust alternative at the moment; once `rsa` 0.10 is stable, this should follow.
- **Sync always fetches the whole vault.** There is no endpoint that returns only titles. Only
  what stays encrypted is kept (see README), but with a vault of thousands of items that is still
  a response of several megabytes every five minutes while the form is open. There is no
  `GET /sync` with `lastSync` — what would work is a longer interval or syncing only on demand.
- **No TOTP.** An item's `totp` field contains the *secret*, not the code derived from it. The
  picker therefore does not offer it at all. None of the three connection types here needs it —
  but as soon as one of them asks for a one-time password, this is the place.
- **Sign-in only with the master password.** An API key (`client_id`/`client_secret`) would be
  the way around a second factor and the usual one for automation — it would have to live in the
  workspace, encrypted with the device key like the other secrets.

## SFTP: open items

How the file view works is in the [README](README.md#sftp). What is open:

- **No local copying.** From the file manager, things only go towards the server; dropped on the
  local pane it would be a plain file operation unrelated to the connection, for which the
  backend has nothing. The pane therefore does not light up at all. Within one side you can at
  least *move* — that is a `rename` and needs nothing more.
- **One channel for all transfers.** They share one SFTP channel; how many run at once is
  configurable (1–10). A subsystem channel of its own per transfer would be the next step, but
  probably brings little: russh-sftp already keeps sixteen requests per file in flight, so the
  bottleneck is neither the channel nor the pipelining. This needs measuring before any rework.
- **Leftover `.wtpart` files are only partly cleaned up.** Startup removes what is older than 30
  days — but only what `partials.json` knows about and what lies on this machine. Half an upload
  on a server stays there, and a killed process leaves a fragment without an entry that nobody
  finds.
- **A cancelled folder leaves empty directories behind.** The target tree is created while walking
  the source, so that empty folders come along too — that is, before the question about conflicts
  *inside* merged folders is answered. Whoever presses “Cancel” there finds the created
  directories, just without content.
- **Changing permissions covers only the mode, not owner or group.** SFTP does have `chown`, but
  a dialog for it would need the server's user and group list, and SFTP does not provide that.

## FTP: open items

How the FTP side works is in the [README](README.md#ftp). What is open:

- **The certificate is pinned, not its key.** A renewed self-signed certificate therefore leads
  to the “has changed” question even if the key stayed the same. Pinning the public key (SPKI)
  would avoid that — for that, the whole certificate would have to go into the workspace, not
  just its fingerprint.
- **Active mode is untested.** It is built in (`PORT` instead of `PASV`, 30 s for the incoming
  connection), but behind NAT it cannot be checked sensibly. Anyone who needs it also needs an
  open port on this machine — there is no setting for that.
- **No resuming a dropped connection in the middle of a listing.** If the control connection
  breaks, the pane reports the error; “Reconnect” opens a new one. A running transfer is then lost
  and starts from the fragment on the next attempt.
- **The pool does not shrink.** Connections opened for parallel transfers stay open until the tab
  is closed. They cost nothing but an entry in the server's session list, but a server with a
  tight per-account limit sees that differently. A timeout on idle connections would be the next
  step.
- **`SITE CHMOD` is not available everywhere.** On IIS and anything not on a POSIX file system,
  “Change permissions…” fails. The dialog can still be opened, because there is no way to tell
  beforehand whether the server supports it.

## S3: open items

How the S3 side works is in the [README](README.md#s3). What is open:

- **The session token exists only with a stored secret.** From the vault or a prompt, only the
  secret access key comes; temporary credentials from STS expire and therefore belong in a field
  that can be filled in again anyway.
- **No anonymous access.** A public bucket could be read without a signature; the connection
  still demands a key.
- **Renaming a folder is not atomic.** It is a copy and delete per object. If it breaks off in
  the middle, part of it is under the new name and the rest under the old one. The error line in
  the pane says so; cleaning up is up to you.
- **Multipart copying (over 5 GiB) does not carry tags and ACLs.** Content-Type and
  `x-amz-meta-*` it does; tags would be another request per object.
- **Uploads cannot be resumed.** An aborted multipart upload is cleaned up instead of remembering
  its upload ID. That is the deliberate half of the trade: nothing is left behind that costs
  money, but also nothing to resume from.
- **Leftover uploads only count after a day.** Younger ones could still be running and are
  neither reported nor cleaned up. The question comes once per bucket and tab; whoever leaves
  something lying around afterwards only sees it in the next tab.
- **A listing stops at 20,000 entries.** A prefix with millions of keys would otherwise fill the
  pane for minutes. The status line says “list truncated”, and a `*` at the end of the path
  (`/bucket/photos/2024*`) lists only what starts that way.
- **No ACLs and no policies.** There is no “Change permissions…”, and rightly so — but a dialog
  for “publicly readable” would be a separate, more honest thing. The only thing visible so far
  is the storage class, and only when uploading.
- **Server-side encryption is not configurable.** Whatever the bucket specifies applies;
  `x-amz-server-side-encryption` per connection would be another field in the form.

## Smaller open items

- **The macOS branch of the device key is untested.** Windows and Linux (with and without Secret
  Service) are verified, see [README](README.md#local-secrets). On a Mac, a run of
  `cargo test --lib local_secrets::store -- --ignored` is missing, and with it the question of
  how the keychain prompt behaves with a signed build.
- **Old plain-text copies stay where they are.** The migration encrypts the current
  `workspaces.json`; whatever ended up in backups, versions of a sync folder or free disk space
  before is out of its reach. Anyone who had keys in plain text there should consider them burned.
- **Proxy: what is missing.** No system proxy (Windows setting, PAC); proxy authentication only
  on the default proxy, not on the connection; no SOCKS4. Implicit FTPS and active FTP do not go
  through a proxy. Backend and Bitwarden do not use the default proxy, only what reqwest reads
  from `HTTPS_PROXY`.
- **Import: what is missing.** MobaXterm is checked against a reconstructed file, not against a
  real installation — the format is undocumented, and only SSH sessions are read. From Termius
  there is only the CSV route. `Match` in `~/.ssh/config` is not evaluated, and an `Include` in
  the middle of a `Host` block with its own `Host` lines ends up differently than with OpenSSH.
- **Snippets: what is missing.** Custom variables with a prompt (`{{ask:path}}`), snippets on
  hosts that are not currently open, a confirmation before the startup command, a personal
  snippet folder across projects. The client does not know a member's role in a shared project:
  it offers creating and changing open snippets to every member, and the backend refuses a
  viewer.
- **Side by side: a fixed four tiles.** No freely split areas, no dragging a tab into a tile;
  broadcast only applies within the split view.
- **Local terminal: what is missing.** No saved profile (start directory, environment), no
  restoring after a restart, no snippets. Not tried on Linux and macOS.
- **MCP: what is missing.** Reading, writing and transferring files; `run_command` only over SSH,
  not in a local shell; no stdio transport for clients that only speak that (Claude Desktop
  without a bridge); no log of the calls. The server does not start while the device key is
  locked at startup — only after unlocking and switching it on again.
- **Keys: what is missing.** No ECDSA when generating, no export as `.ppk`, no passphrase for a
  generated key; “Install on the server” exists only in the form, not on the card.
- **macOS and Linux: not clicked through on a real machine yet.** They build and the unit tests
  pass (Linux locally, all three in the CI), but the app itself has only been used on Windows:
  local shells, the agent in `SSH_AUTH_SOCK` (also for agent forwarding), the keyring prompt,
  1Password's desktop integration and the installers want a run on each system — Windows on ARM
  and the Linux ARM64 packages included. The release workflow builds all of them since 0.1.0.
- **A jump host from another workspace only works for private workspaces.** A connection in a
  team workspace can only jump through hosts of the same workspace, because colleagues could not
  resolve the ID otherwise. A locked workspace appears in the list with “(locked)”; connecting
  through it only works after unlocking.

## Feature gaps compared to electerm, Voltius, Termius and FileZilla

Comparison of 6 October 2026 with [electerm](https://github.com/electerm/electerm) (v5.5.66,
MIT, Electron), [Voltius](https://github.com/VoltiusApp/voltius) (v0.49, AGPLv3, Tauri 2 +
russh + xterm.js — that is, our stack), [Termius](https://termius.com) (v10.1.3, commercial) and
[FileZilla](https://filezilla-project.org) (3.71.1, GPL; Pro commercial). Letters in parentheses:
E, V, T, F = which tool has it, F-Pro = only in FileZilla Pro. What is already listed above as an
item of its own (WebDAV/SMB, local copying, `chown`, sorting) is not repeated here.

Voltius works as a technical reference because it uses the same crates. Since WireTerm is
AGPL-3.0-only itself, Voltius code can be reused under the AGPL with attribution; electerm (MIT)
is unproblematic anyway.

### Must-have — all three have it; without it WireTerm is out for admins

- [ ] **Detect the system proxy** (V). SOCKS5 and HTTP CONNECT, global and per connection, exist
      by now.
- [ ] **Import from SecureCRT** (V, T). PuTTY, MobaXterm, CSV and `~/.ssh/config` work.

### Standard — expected from an SSH client

- [ ] **More than four terminals side by side**, freely split (Termius up to 16). Up to four with
      broadcast exists.
- [x] **Auto-update** via `tauri-plugin-updater` from the GitHub releases.
- [ ] **winget and Scoop** packages, for installing and updating from the package managers.
- [ ] **Generate ECDSA** (V, T). Ed25519 and RSA, importing `.ppk` and installing into
      `authorized_keys` exist.
- [ ] **Identities**: create user + key/password once, use it on many hosts (V, T).
- [ ] **Tags** with a filter (V, T); **groups that inherit settings** — credentials, proxy, jump
      host, theme (T).
- [ ] **Quick connect** `user@host` without saving, and `ssh://` deep links (E, T).
- [ ] **Server-to-server transfer** between two connections (E, V, T).
- [ ] **Custom themes** (theme editor) and **configurable shortcuts** (E, V).
- [ ] **Environment variables, pre-/post-connect commands and encoding per host** (E, V, T).
- [ ] **App lock** with password, Windows Hello or PIN (E, T).

### File transfer — mainly FileZilla

FileZilla is a pure file client, so the comparison only concerns the file view. Proxy,
keyboard-interactive, encrypting stored passwords, S3 session token, WebDAV and local copying it
has as well — those are already listed above or in the protocol sections.

- [ ] **Directory comparison**: highlight differences in color (different size, newer, only on
      one side), hide identical files (F).
- [ ] **Synchronized browsing**: local and remote change directory together, can be switched on
      automatically per connection (F).
- [ ] **Synchronize folders** local→remote, remote→local or both ways, with a filter (F-Pro).
- [ ] **Queue survives a restart.** Today [resume.rs](src-tauri/src/resume.rs) only remembers the
      fragments of aborted files; whatever was still in the queue is gone. FileZilla keeps the
      whole queue in SQLite and can also save and load it.
- [ ] **Reorder the queue** by drag and drop, pause it (F).
- [ ] **Speed limits** for upload and download (F).
- [ ] **Automatic retry** with backoff on connection errors (F-Pro).
- [ ] **File filters**, also by regex, for view and transfer — e.g. skipping `node_modules` or
      `.git` (F).
- [ ] **Search on the server**, recursive, also by regex (F).
- [ ] **Bookmarks per connection**, optionally with a matching local directory (F).
- [ ] **Directory tree** next to the file list (F).
- [ ] **Rename multiple files**: replace text, regex, numbering (F-Pro).
- [ ] **Character set per connection** (automatic, UTF-8, custom) and the server's **time zone
      offset** for correct modification times (F) — relevant with old FTP servers.
- [ ] **ASCII/binary mode** for FTP (F).
- [ ] **Transfer log** to a file, with a level of detail (F).
- [ ] **More cloud storage**: Azure Blob/File, Google Cloud Storage, Google Drive, Dropbox,
      OneDrive/SharePoint, Box, OpenStack Swift (F-Pro). B2 and R2 already work through S3.
- [ ] **Command line**: open a connection from the site manager by parameter; scriptable
      transfers (F, F-Pro).

### More protocols

- [ ] **Serial** with baud rate, parity, flow control, DTR/RTS (E, V, T).
- [ ] **Telnet** (E, T).
- [ ] **Mosh** (T).
- [ ] **RDP, VNC** (E) — a big chunk, only on concrete demand.

### Standing out — where WireTerm can pull ahead

- [ ] **AI in the terminal**: generate a command from text, explain errors (E, T); agent mode
      with tool calls (E).
- [ ] **Audit log** for team workspaces: who opened or changed which connection when (V, T).
- [ ] **Real-time sync** instead of polling — see the backend item above; Voltius and Termius have
      it.
- [ ] **SSO (SAML/OIDC)** and **enforcing 2FA in a team** (T); **device management with remote
      sign-out** (T).
- [ ] **Self-hosting via Docker Compose** with an admin dashboard (V).
- [x] **macOS and Linux.** Builds and installers for both; what is still open is listed under
      [Smaller open items](#smaller-open-items).

### Nice to have

- [ ] **Persistent sessions via tmux/screen** that survive network drops and restarts (V).
- [ ] **Session logs / recording** (T).
- [ ] **Autocomplete** from history, paths and commands (T).
- [ ] **Terminal sharing** live, view/control (V, T).
- [ ] **Server monitor** CPU/RAM/disk in the status bar (E, V).
- [ ] **Command palette** Ctrl+K (V).
- [ ] **Triggers and regex highlighting** (E).
- [ ] **Docker management** over SSH (V).
- [ ] **Import servers from AWS, Azure, DigitalOcean automatically** (T).
- [ ] **SFTP path follows the terminal path**, drag a file into the terminal (E).
- [ ] **Tar acceleration** for many small files (V).
- [ ] **Zmodem / Trzsz** (E).
- [ ] **Sync without a backend of our own** — Gist, WebDAV, S3 (E, V).
- [ ] **More UI languages** (E: 14+ languages); English and German exist.
- [ ] **FIDO2 hardware keys, OpenSSH certificates** (T; certificates also E).
- [ ] **Export** of the connections as JSON/CSV (E, V).

**Where WireTerm is already ahead:** None of the four tools has a direct integration with
1Password and Bitwarden/Vaultwarden. Nobody else has S3 with presigned links; FileZilla can do S3
only in the Pro edition. Compared to FileZilla, there is also the terminal, team workspaces with
E2E encryption and checking partial files before resuming.
