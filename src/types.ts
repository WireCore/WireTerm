/** Mirrors the serde representation in src-tauri/src/storage.rs. */

import { t } from "./i18n";

/**
 * Where a workspace lives.
 *
 * "Cloud" and "custom backend" are the same thing: the same protocol, the same
 * encryption, the same sync. The only difference is where the address comes
 * from: the cloud's is `CLOUD_URL` in `src-tauri/src/cloud/http.rs`.
 */
export type StorageKind = "local" | "customBackend" | "cloud";

/** Getters, so each read is in the current language. */
export const STORAGE_LABELS: Record<StorageKind, string> = {
  get local() {
    return t("common.local");
  },
  get customBackend() {
    return t("types.storage.customBackend");
  },
  get cloud() {
    return t("types.storage.cloud");
  },
};

/** How a workspace came into being on the backend. */
export type WorkspaceKind = "personal" | "organization";

/**
 * The role in the organization.
 *
 * It decides which *rows* someone gets. Even an `owner` only gets at the
 * secrets once someone has wrapped the project key for them — the server
 * cannot do that, and so it is not in this list.
 */
export type Role = "owner" | "admin" | "member";

export const ROLE_LABELS: Record<Role, string> = {
  get owner() {
    return t("types.role.owner");
  },
  get admin() {
    return t("types.role.admin");
  },
  get member() {
    return t("types.role.member");
  },
};

/** What a share grants. */
export type ShareRole = "editor" | "viewer";

export const SHARE_ROLE_LABELS: Record<ShareRole, string> = {
  get editor() {
    return t("types.shareRole.editor");
  },
  get viewer() {
    return t("types.shareRole.viewer");
  },
};

/**
 * What a remote workspace brings along besides its tree — mirrors `Remote` in
 * `src-tauri/src/storage.rs`.
 *
 * Pure runtime knowledge: none of it is written. `locked`, for instance, would
 * not just be superfluous in a file but wrong at the next start.
 */
export type Remote = {
  accountId: string;
  /** The backend's address, without scheme. */
  server: string;
  email: string;
  kind: WorkspaceKind;
  role: Role;
  /** Whether this role may create, delete and share projects. */
  admin: boolean;
  /** The vault is locked: the rows are there, the secrets are not. */
  locked: boolean;
  /**
   * There are ciphertexts that could not be opened. With the vault open that
   * means: nobody has wrapped a key for this version yet — "waiting for a
   * share" and not "broken".
   */
  secretsMissing: boolean;
  /** How many changes still have to go up. */
  pending: number;
  revision: string;
  /** What the last sync failed on. */
  error?: string | null;
  /** Changes a conflict discarded — until someone dismisses them. */
  conflicts?: string[];
};

/**
 * Which password manager a stored reference points into.
 *
 * Both answer the same three questions — which vaults, which entries, which
 * fields — so they share one source, one picker and one code path; only the
 * name of the provider travels along. "bitwarden" covers Vaultwarden too:
 * it is the same API, reached the same way.
 */
export type VaultProvider = "onePassword" | "bitwarden";

export const VAULT_PROVIDERS: { value: VaultProvider; label: string }[] = [
  { value: "onePassword", label: "1Password" },
  { value: "bitwarden", label: "Bitwarden" },
];

export const VAULT_LABELS: Record<VaultProvider, string> = {
  onePassword: "1Password",
  bitwarden: "Bitwarden",
};

/** What a reference into each provider looks like, for the placeholder. */
export const VAULT_REFERENCE_HINTS: Record<VaultProvider, string> = {
  onePassword: "op://vault/item/field",
  bitwarden: "bw://vault/item/field",
};

/**
 * Read from a password manager at connect time. Only the reference is stored,
 * never the secret — the one thing every provider here has in common, and the
 * reason this is one source rather than one per provider.
 */
export type VaultAuth = { source: "vault"; provider: VaultProvider; reference: string };

/**
 * `vault` is a private key, `vaultPassword` a password from the same managers,
 * `password` one stored with the connection, and `prompt` a password asked for
 * when the tab connects. `agent` uses whatever keys the running SSH agent holds.
 */
export type SshAuth =
  | { source: "inlineKey"; key: string }
  | { source: "keyFile"; path: string }
  | { source: "agent" }
  | VaultAuth
  | { source: "password"; password: string }
  | { source: "vaultPassword"; provider: VaultProvider; reference: string }
  | { source: "prompt" };

export type SshSettings = {
  host: string;
  port: number;
  user: string;
  auth: SshAuth;
  /** Where the terminal and the file browser go after connecting. Empty is home. */
  startPath: string;
  /** The ID of another SSH connection through which the target is reached. */
  jump?: string;
  /** Forward the local SSH agent to the server. */
  agentForwarding?: boolean;
  /**
   * The resolved chain of jump hosts, first hop first — only set when
   * connecting, by [`withJumps`] in `store.ts`. Never stored.
   */
  via?: SshSettings[];
  /** Port forwards that start with the tab's terminal. */
  forwards?: Forward[];
  /** When absent, this device's default proxy applies. */
  proxy?: ProxySetting;
  /** The ID of a snippet that is sent after connecting. */
  startupSnippet?: string;
};

export type ProxyKind = "socks5" | "http";

/**
 * How a connection departs from the device's default proxy — mirror of
 * `proxy::ProxySetting`. A custom proxy has no login: it travels with the
 * connection, and a connection has exactly one secret.
 */
export type ProxySetting =
  | { mode: "direct" }
  | { mode: "custom"; kind: ProxyKind; host: string; port: number };

/** This device's default proxy — mirror of `proxy::Route`. */
export type DefaultProxy = {
  kind: ProxyKind;
  host: string;
  port: number;
  /** Empty means without login. */
  user: string;
  password: string;
};

/** Protocol names, the same in every language. */
export const PROXY_KIND_LABELS: Record<ProxyKind, string> = {
  socks5: "SOCKS5",
  http: "HTTP (CONNECT)",
};

/**
 * A port forward like `ssh -L` (`local`), `-R` (`remote`) and `-D`
 * (`dynamic`, SOCKS5). Without `bindHost` it only listens on `127.0.0.1`.
 */
export type Forward = {
  kind: "local" | "remote" | "dynamic";
  bindHost?: string;
  /** 0 lets the system pick a free port. */
  bindPort: number;
  targetHost?: string;
  targetPort?: number;
};

/** How a forward is doing right now — mirror of `forward::Status`. */
export type ForwardStatus = {
  kind: Forward["kind"];
  label: string;
  active: boolean;
  error?: string;
  /** The port that is actually being listened on. */
  port?: number;
  connections: number;
};

/**
 * Where an FTP login's password comes from.
 *
 * `anonymous` ignores the user field: the convention is a fixed name and an
 * e-mail address, and half-overriding it only produces logins that fail for a
 * reason nobody can see.
 */
export type FtpAuth =
  | { source: "anonymous" }
  | { source: "password"; password: string }
  | VaultAuth
  | { source: "prompt" };

/** What, if anything, encrypts the connection. */
export type FtpSecurity = "plain" | "explicit" | "implicit";

export type FtpSettings = {
  host: string;
  port: number;
  user: string;
  auth: FtpAuth;
  security: FtpSecurity;
  /** The client opens the data connection. What works from behind NAT. */
  passive: boolean;
  /** Accept a server certificate the system does not vouch for. */
  acceptInvalidCert: boolean;
  /** Where the file browser goes after connecting. Empty is home. */
  startPath: string;
  /** When absent, this device's default proxy applies. */
  proxy?: ProxySetting;
};

/**
 * Where the secret access key of an S3 connection comes from.
 *
 * No "anonymous" here, unlike FTP: an unsigned request only ever reaches a
 * bucket that is open to the whole internet, and nobody sets up a connection
 * entry for one.
 */
export type S3Auth =
  | { source: "secret"; secret: string }
  | VaultAuth
  | { source: "prompt" };

/**
 * An S3 endpoint, mirroring `S3Settings` in the backend.
 *
 * The three fields every type shares mean what they say here too: `host` is
 * the endpoint, `port` its port, and `user` the access key id — which really
 * is the name every request is made under.
 */
export type S3Settings = {
  host: string;
  port: number;
  /** The access key id. */
  user: string;
  auth: S3Auth;
  /** Part of the signature rather than of the address. */
  region: string;
  /** Where the browser starts. Empty means the list of buckets. */
  bucket: string;
  /** A prefix inside the bucket to start in, without a leading slash. */
  prefix: string;
  tls: boolean;
  /** `https://host/bucket/key` instead of `https://bucket.host/key`. */
  pathStyle: boolean;
  /** Accept a server certificate the system does not vouch for. */
  acceptInvalidCert: boolean;
  /** `STANDARD`, `GLACIER_IR`, … Empty leaves it to the server. */
  storageClass: string;
  /** When absent, this device's default proxy applies. */
  proxy?: ProxySetting;
};

/** The tag doubles as the connection type; further types get further variants. */
export type ConnectionSettings =
  | ({ type: "ssh" } & SshSettings)
  | ({ type: "ftp" } & FtpSettings)
  | ({ type: "s3" } & S3Settings);

export type ConnectionType = ConnectionSettings["type"];

/**
 * What a connection type is called on screen.
 *
 * SSH and SFTP are one type, not two: SFTP is a subsystem of SSH, reached over
 * the same connection behind the same host key and the same login. Every SSH
 * connection therefore offers both, and the label says so rather than making
 * the user set the same host up twice.
 *
 * FTP and FTPS are one type for a different reason: they are the same protocol
 * with TLS switched on, which is a setting inside the connection rather than a
 * different kind of it.
 *
 * "S3" names the protocol rather than Amazon, because that is what it is: the
 * same requests reach MinIO, Ceph, Wasabi and half a dozen others, and a label
 * naming one provider would read as if the rest were not supported.
 *
 * Protocol names, the same in every language.
 */
export const TYPE_LABELS: Record<ConnectionType, string> = {
  ssh: "SSH/SFTP",
  ftp: "FTP/FTPS",
  s3: "S3",
};

/** The type picker in the connection form. */
export const CONNECTION_TYPES: { value: ConnectionType; label: string }[] = [
  { value: "ssh", label: TYPE_LABELS.ssh },
  { value: "ftp", label: TYPE_LABELS.ftp },
  { value: "s3", label: TYPE_LABELS.s3 },
];

/**
 * Which half of a connection a tab is showing.
 *
 * An FTP tab only ever shows "files" — there is no shell at the other end to
 * show instead.
 */
export type ConnectionView = "terminal" | "files";

/** Whether a connection has a terminal beside its file browser. */
export function hasTerminal(settings: ConnectionSettings): boolean {
  return settings.type === "ssh";
}

/**
 * The target's own description of itself, read from `/etc/os-release` (or
 * `uname` where that file does not exist). There is no way to know this
 * without logging in, so a connection carries none until it has been reached
 * once.
 */
export type RemoteSystem = {
  /** The os-release `ID`, lowercased: `ubuntu`, `debian`, … Picks the logo. */
  id: string;
  /** `NAME`, e.g. `Ubuntu`. */
  name: string;
  /** `VERSION_ID`, e.g. `24.04`. Empty on rolling releases. */
  version: string;
  /** `PRETTY_NAME`, the whole line, for the tooltip. */
  pretty: string;
};

export type Connection = {
  id: string;
  name: string;
  settings: ConnectionSettings;
  /** Filled in on the first successful login, refreshed on every one after. */
  system?: RemoteSystem;
  /** Lifts the connection to the top of the tab menu. */
  bookmarked?: boolean;
  /**
   * The secret is there encrypted but could not be opened on this device — a
   * different or missing device key. The field is then empty; if it stays
   * empty, the old ciphertext stays. Runtime only.
   */
  secretUnreadable?: boolean;
};

/** What "Test connection" reports back, whichever protocol answered. */
export type ConnectionProbe = {
  /** How long reaching the target and logging in took together. */
  millis: number;
  /** null when the target said nothing about itself. */
  system: RemoteSystem | null;
};

export type Project = {
  id: string;
  name: string;
  connections: Connection[];
};

/**
 * The Bitwarden or Vaultwarden account a workspace reads its secrets with.
 *
 * The master password is deliberately not in here: it is asked for once per
 * app run and kept in the backend's memory, never written to the workspace
 * file. What is stored is only where the vault is and who opens it.
 */
export type BitwardenAccount = {
  /** Empty means Bitwarden's own service. A self-hosted URL otherwise. */
  server: string;
  email: string;
  /** For a self-signed certificate in front of one's own instance. */
  acceptInvalidCert: boolean;
};

export function defaultBitwardenAccount(): BitwardenAccount {
  return { server: "", email: "", acceptInvalidCert: false };
}

export type Workspace = {
  id: string;
  name: string;
  storage: StorageKind;
  /**
   * Which 1Password account the connections in here are read with. Per user
   * and per workspace: the desktop-app integration signs everyone in with
   * their own account. Absent until one has been given.
   */
  onePasswordAccount?: string;
  /** The same question for Bitwarden, and per workspace for the same reason. */
  bitwarden?: BitwardenAccount;
  /**
   * Filled for everything that does not come from this disk. To the rest of
   * the app a remote workspace looks like any other — by this, and only by
   * this, can it be told apart.
   */
  remote?: Remote | null;
  projects: Project[];
  /** Saved commands for the terminal, in their order — each of a project. */
  snippets?: Snippet[];
};

/**
 * A saved command. `{{connection.host}}`, `.user`, `.port` and `.name` are
 * replaced by the connection's values when it is sent.
 *
 * It belongs to a project and is offered for all of its connections — or,
 * with `connectionId`, for just that one.
 */
export type Snippet = {
  id: string;
  projectId: string;
  connectionId?: string;
  /**
   * Locked, only owner and admin change it — and only a locked one can be a
   * startup command, because that runs unasked in other people's terminals.
   * On this device always locked.
   */
  locked: boolean;
  name: string;
  /** `/`-separated; empty means top level. */
  folder: string;
  command: string;
};

/** The snippets offered for a connection: its project's, and its own. */
export function snippetsFor(
  workspace: Workspace | null | undefined,
  projectId: string,
  connectionId: string,
): Snippet[] {
  return (workspace?.snippets ?? []).filter(
    (snippet) =>
      snippet.projectId === projectId && (!snippet.connectionId || snippet.connectionId === connectionId),
  );
}

/** Whether this workspace lives on a backend. */
export function isRemote(workspace: Workspace | null | undefined): boolean {
  return !!workspace?.remote;
}

/**
 * Whether anything about this workspace can be changed right now.
 *
 * With a locked vault a name could be changed, but no secret encrypted — and
 * the half answer would be worse than the whole one: a form that opens and
 * fails on saving.
 */
export function isEditable(workspace: Workspace | null | undefined): boolean {
  if (!workspace) return false;
  if (!workspace.remote) return true;
  return !workspace.remote.locked;
}

/** The editable part of a workspace, as the dialog hands it back. */
export type WorkspaceValues = Pick<
  Workspace,
  "name" | "storage" | "onePasswordAccount" | "bitwarden"
>;

/**
 * What the backend asks before it trusts a server key, sent as `ssh:host-key`.
 * The answer goes back with `ssh_host_key_answer`, carrying the same `id`.
 */
export type HostKeyPrompt = {
  id: string;
  /**
   * `ssh` for a host key; `tls` for the certificate of an FTPS server that the
   * system does not trust, asked about in the same dialog.
   */
  kind: "ssh" | "tls";
  host: string;
  port: number;
  /** `ssh-ed25519`, `ecdsa-sha2-nistp256`, …; `x509-sha256` for a certificate. */
  algorithm: string;
  /** `SHA256:…`, the same form OpenSSH prints; `AB:CD:…` for a certificate, as openssl prints it. */
  fingerprint: string;
  /** A different key of this type is already on file — the serious case. */
  changed: boolean;
  /** Why the system does not trust the certificate. TLS only. */
  reason?: string;
  /**
   * The key itself, as an `authorized_keys` line.
   *
   * Not for the dialog — nobody reads a base64 block — but for what happens
   * after "Trust": in a workspace on a backend the answer belongs to the
   * workspace and not to this device, so that not every team member answers
   * the same question on their own. For a certificate, the SHA-256
   * fingerprint as hex.
   */
  publicKey: string;
};

/** One open terminal tab. */
/** A shell on this machine, as `local_shells` reports it. */
export type LocalShell = {
  id: string;
  name: string;
  program: string;
  args: string[];
};

export type Tab = {
  /** Session id: also identifies the SSH session in the backend. */
  id: string;
  /** Empty for a local terminal. */
  connectionId: string;
  /** Set for a local terminal: which shell runs in it. */
  local?: LocalShell;
  /**
   * Restored after a restart and not shown yet. It only connects when first
   * shown — otherwise at startup every tab would ask its password and
   * host-key questions at once.
   */
  waiting?: boolean;
};

export type TabStatus = "connecting" | "connected" | "closed" | "error";

/** What the tab bar needs to draw one tab; assembled in App.vue. */
export type TabView = {
  id: string;
  name: string;
  /** user@host:port */
  target: string;
  status: TabStatus;
};

/** Shown next to the connection name in its tab. */
export function targetLabel(settings: ConnectionSettings): string {
  // An S3 connection's "user" is a twenty-character access key id, which says
  // nothing to anyone reading a tab. What one wants to see there is which
  // bucket it lands in.
  if (settings.type === "s3") {
    return `${settings.bucket || "Buckets"}@${settings.host}`;
  }
  // An anonymous login does not use the stored user name, so showing it would
  // name someone the connection never logs in as. A user read from a vault is
  // a long reference, so the vault's name stands in for it.
  const user =
    settings.auth.source === "anonymous"
      ? "anonymous"
      : settings.user.startsWith("op://")
        ? `(${VAULT_LABELS.onePassword})`
        : settings.user.startsWith("bw://")
          ? `(${VAULT_LABELS.bitwarden})`
          : settings.user;
  return `${user}@${settings.host}:${settings.port}`;
}

/**
 * "Key: 1Password" and the like, for the card in the overview.
 *
 * A vault is named rather than called "vault": which one a connection reads
 * from is exactly what someone scanning the overview wants to know, and the
 * two are not interchangeable.
 */
export function credentialLabel(settings: ConnectionSettings): string {
  const vault =
    settings.auth.source === "vault" || settings.auth.source === "vaultPassword"
      ? VAULT_LABELS[settings.auth.provider]
      : "";

  if (settings.type === "ssh") {
    const sources: Record<SshAuth["source"], string> = {
      vault: "keyVault",
      keyFile: "keyFile",
      inlineKey: "keyInline",
      agent: "keyAgent",
      password: "passwordStored",
      vaultPassword: "passwordVault",
      prompt: "passwordPrompt",
    };
    return t(`types.credential.${sources[settings.auth.source]}`, { vault });
  }
  if (settings.type === "s3") {
    const sources: Record<S3Auth["source"], string> = {
      vault: "secretKeyVault",
      secret: "secretKeyStored",
      prompt: "secretKeyPrompt",
    };
    return t(`types.credential.${sources[settings.auth.source]}`, { vault });
  }
  const sources: Record<FtpAuth["source"], string> = {
    vault: "passwordVault",
    password: "passwordStored",
    prompt: "passwordPrompt",
    anonymous: "anonymous",
  };
  return t(`types.credential.${sources[settings.auth.source]}`, { vault });
}

/**
 * What the backend asks before it can log in with a secret that is not stored
 * anywhere, sent as `secret:ask`. The answer goes back with `secret_answer`,
 * carrying the same `id`.
 *
 * One question for two protocols — an FTP password and an S3 secret access key
 * are asked for, kept and forgotten in exactly the same way. `kind` is the one
 * difference: it decides what the dialog calls the thing it is asking for. An
 * SSH key's passphrase is asked for the same way.
 */
export type SecretPrompt = {
  id: string;
  kind: "password" | "secretKey" | "passphrase" | "challenge";
  host: string;
  port: number;
  user: string;
  /**
   * Only for `challenge`: a question the SSH server asks during a
   * keyboard-interactive login, in its own words — a one-time code, usually.
   */
  challenge?: { text: string; instructions: string; echo: boolean };
};

/**
 * What the picker shows, whichever provider filled it — mirrors
 * `src-tauri/src/vault.rs`.
 *
 * `category` and `fieldType` use 1Password's names on purpose: the Bitwarden
 * side translates into them, so the picker can put SSH keys first and
 * preselect the likely field without knowing where the list came from.
 */
export type OpVault = { id: string; title: string; itemCount: number };
export type OpItem = { id: string; title: string; category: string };
export type OpField = {
  id: string;
  title: string;
  fieldType: string;
  valueLength: number;
};

export const newId = () => crypto.randomUUID();

/**
 * What a connection of each type starts out as.
 *
 * Also what switching the type in the form replaces the settings with: the two
 * variants share three field names and disagree about everything else, so
 * carrying the old object across would leave fields behind that no longer mean
 * anything. Host, port and user are carried over by the form itself, which is
 * the part a user would be annoyed to retype.
 */
export function defaultSettings(type: ConnectionType): ConnectionSettings {
  if (type === "ftp") {
    return {
      type: "ftp",
      host: "",
      port: 21,
      user: "",
      auth: { source: "prompt" },
      security: "explicit",
      passive: true,
      acceptInvalidCert: false,
      startPath: "",
    };
  }
  if (type === "s3") {
    return {
      type: "s3",
      host: "",
      port: 443,
      user: "",
      auth: { source: "vault", provider: "onePassword", reference: "" },
      // What AWS signs with where nothing else was agreed, and what every
      // other implementation accepts because it ignores the region entirely.
      region: "us-east-1",
      bucket: "",
      prefix: "",
      tls: true,
      pathStyle: false,
      acceptInvalidCert: false,
      storageClass: "",
    };
  }
  return {
    type: "ssh",
    host: "",
    port: 22,
    user: "root",
    auth: { source: "vault", provider: "onePassword", reference: "" },
    startPath: "",
  };
}

/**
 * The port a type expects, so switching type or TLS mode moves it along.
 *
 * Implicit FTPS is the odd one: it was given a port of its own back when it
 * was the only way to encrypt FTP, and servers that still offer it still
 * listen there.
 *
 * S3 is plain HTTP underneath and has no port of its own at all — 443 or 80,
 * depending on the one checkbox. A MinIO on 9000 is therefore typed in, and
 * kept: it is no longer the port the setting suggests.
 */
export function defaultPort(settings: ConnectionSettings): number {
  if (settings.type === "ssh") return 22;
  if (settings.type === "s3") return settings.tls ? 443 : 80;
  return settings.security === "implicit" ? 990 : 21;
}

/**
 * Switches the whole settings object, carrying the three fields that mean the
 * same thing on either side.
 *
 * Wholesale rather than field by field, because the variants agree on nothing
 * else: an FTP connection has no key source and an SSH one has no TLS mode,
 * and leaving either behind would put a field in the stored file that nothing
 * reads and nothing maintains.
 */
export function switchType(connection: Connection, type: ConnectionType) {
  const current = connection.settings;
  if (current.type === type) return;

  const next = defaultSettings(type);
  next.host = current.host;
  next.user = current.user;
  // Only where the port is still the one the old type suggested. A port that
  // was typed deliberately is kept — it is the likelier thing to have meant.
  next.port = current.port === defaultPort(current) ? defaultPort(next) : current.port;

  connection.settings = next;
}

export function defaultConnection(name: string): Connection {
  return { id: newId(), name, settings: defaultSettings("ssh") };
}

// ---- Files -----------------------------------------------------------------
//
// Mirrors `files::Entry` and `files::Listing` in the backend. Both sides of the
// file browser are described the same way, so one pane component draws either.

export type FileEntry = {
  name: string;
  /** Absolute, in the form its own side expects it back in. */
  path: string;
  /** A symlink into a directory counts: this is what decides "can be entered". */
  isDir: boolean;
  isSymlink: boolean;
  size: number;
  /** Unix seconds, or null where nothing said. */
  modified: number | null;
  /** `rwxr-xr-x`. Remote only — the local side has nothing to put here. */
  permissions: string | null;
  /**
   * The same permissions as the raw bits `chmod` takes: owner, group and
   * other read/write/execute, plus setuid, setgid and sticky. Remote only.
   */
  mode: number | null;
};

export type Listing = {
  /** The directory that was read, resolved. */
  path: string;
  /** null at the top of the tree, which disables "up". */
  parent: string | null;
  entries: FileEntry[];
  /** More existed than was read — only an S3 listing is ever cut short. */
  truncated?: boolean;
};

/**
 * Multipart uploads in a bucket that were never finished nor aborted, older
 * than a day. S3 only: they are in no listing and billed all the same.
 */
export type StaleUploads = {
  bucket: string;
  count: number;
  /** When the oldest was started, Unix seconds. */
  oldest: number | null;
};

export type TransferDirection = "download" | "upload";

/**
 * "cancelled" is deliberately not "error": the user asked for it, so it is
 * reported without an error message and without drawing attention.
 *
 * "done" is a moment rather than a state anything rests in — a transfer that
 * succeeds leaves the queue at once and lives on only as the count in its
 * header.
 */
export type TransferStatus = "queued" | "running" | "done" | "error" | "cancelled";

/** One file on its way in or out. Directories become one of these per file. */
export type Transfer = {
  id: string;
  direction: TransferDirection;
  name: string;
  local: string;
  remote: string;
  /** What the source said before the transfer started; 0 if it would not say. */
  size: number;
  transferred: number;
  status: TransferStatus;
  error?: string;
  /** `performance.now()` when it started running, for the elapsed time. */
  startedAt?: number;
  /** How long it ran, in milliseconds. Set once it has ended. */
  elapsed?: number;
};

// ---- Permissions ------------------------------------------------------------

/** The nine ordinary permission bits, split the way a chmod dialog shows them. */
export type PermissionBits = {
  ownerRead: boolean;
  ownerWrite: boolean;
  ownerExec: boolean;
  groupRead: boolean;
  groupWrite: boolean;
  groupExec: boolean;
  otherRead: boolean;
  otherWrite: boolean;
  otherExec: boolean;
  /** Runs as the file's owner rather than the user who started it. */
  setuid: boolean;
  /** Runs as the file's group, or: new files in the directory inherit it. */
  setgid: boolean;
  /** On a directory, only the owner may delete or rename what is inside. */
  sticky: boolean;
};

const BIT_ORDER: (keyof PermissionBits)[] = [
  "setuid",
  "setgid",
  "sticky",
  "ownerRead",
  "ownerWrite",
  "ownerExec",
  "groupRead",
  "groupWrite",
  "groupExec",
  "otherRead",
  "otherWrite",
  "otherExec",
];

/** Bit `n` in `BIT_ORDER`, most significant first — the order `chmod` uses. */
export function bitsFromMode(mode: number): PermissionBits {
  const get = (index: number) => (mode & (1 << (11 - index))) !== 0;
  const result = {} as PermissionBits;
  BIT_ORDER.forEach((key, index) => (result[key] = get(index)));
  return result;
}

export function modeFromBits(bits: PermissionBits): number {
  return BIT_ORDER.reduce(
    (mode, key, index) => (bits[key] ? mode | (1 << (11 - index)) : mode),
    0,
  );
}

// ---- Editing on the server ---------------------------------------------------

/** What `sftp_edit_open` hands back. */
export type EditSession = {
  id: string;
  localPath: string;
  name: string;
  /**
   * Whether the backend started an editor itself. False means the file still
   * has to be handed to the system — and that nothing is waiting for it, so
   * the edit can only be ended by hand.
   */
  opened: boolean;
};

/**
 * "closed" is the end of an edit: the editor was closed, or the working copy
 * went away. The row goes with it.
 *
 * "detached" is the editor that quit at once because a window of its own was
 * already open. Not an error — the file is being edited and every save still
 * goes across — but its exit can no longer mean anything, and the message
 * says what to do about it.
 */
export type EditState = "uploading" | "synced" | "error" | "closed" | "detached";

/** One file currently open for editing, and what its last sync attempt did. */
export type RemoteEdit = {
  id: string;
  name: string;
  remote: string;
  state: EditState;
  message?: string;
};

// ---- Overwriting -------------------------------------------------------------

/**
 * What to do about one destination that already has something at that name.
 *
 * Decided per conflict rather than per batch: a handful of names is worth
 * reviewing one by one, and a dragged folder of a hundred is not. One dialog
 * offers both — a row each, and a header that sets them all at once.
 *
 * "Merge" is what "overwrite" means for a directory: its contents are
 * put alongside what is already there, and whatever collides inside it becomes
 * a conflict of its own rather than being decided here.
 */
export type OverwriteAction = "overwrite" | "rename" | "skip";

/** One name at the target that is already taken, and by what. */
export type OverwriteConflict = {
  /** The source path. Identifies the conflict and nothing else. */
  key: string;
  /** What is shown: a name, or a path below the folder that was dragged in. */
  label: string;
  isDir: boolean;
  /** What is coming. `size` is meaningless for a directory. */
  size: number;
  modified: number | null;
  /** What is already there. A directory meeting a directory is a merge. */
  targetIsDir: boolean;
  targetSize: number;
  targetModified: number | null;
};

/**
 * The dialog's answer: one action per conflict key, or null for "Cancel",
 * which drops the whole transfer rather than any part of it.
 */
export type OverwriteAnswer = Record<string, OverwriteAction> | null;

// ---- Permissions, recursively ------------------------------------------------

/** What one run of `sftp_chmod` did. */
export type ChmodResult = {
  changed: number;
  /** Entries the server would not change — no rights, a read-only mount. */
  failed: number;
  /** The first refusal, in the server's own words. */
  error: string | null;
  /** Stopped by the user before the tree was done. */
  cancelled: boolean;
};
