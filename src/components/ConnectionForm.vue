<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { invoke } from "@tauri-apps/api/core";
import { useI18n } from "vue-i18n";
import {
  Alert,
  Button,
  Checkbox,
  Field,
  Input,
  NativeSelect,
  NumberInput,
  PasswordInput,
  RadioGroup,
  RadioGroupItem,
  Textarea,
} from "@wirecore/wirelayer-vue";
import VaultPicker from "./VaultPicker.vue";
import { pickFile } from "../pick-file";
import { defaultProxy, PROXY_PORTS, proxyLabel } from "../proxy";
import { findConnection, jumpsThrough, projectOf, withJumps, workspaces } from "../store";
import {
  CONNECTION_TYPES,
  defaultPort,
  PROXY_KIND_LABELS,
  snippetsFor,
  switchType,
  VAULT_LABELS,
  VAULT_PROVIDERS,
  VAULT_REFERENCE_HINTS,
  type Connection,
  type FtpAuth,
  type FtpSecurity,
  type OpField,
  type ProxyKind,
  type ProxySetting,
  type S3Auth,
  type Forward,
  type SshAuth,
  type VaultProvider,
} from "../types";

/**
 * A pure input mask: it edits whatever object it is handed and never saves.
 * The dialog around it owns the draft and decides when the change reaches the
 * workspace tree.
 *
 * Three types, and they share three fields — host, port, user — and nothing
 * else. So the top of the form is common and everything below the type picker
 * belongs to one variant or another. Even the three shared fields are not
 * called the same thing everywhere: an S3 endpoint has no "User", it has
 * an access key id, and naming it after the field it is stored in would send
 * people looking for the wrong thing.
 *
 * Shown one section at a time: the wizard walks through them as steps, the
 * edit dialog puts them in side tabs. Each instance edits the same object.
 */
const props = defineProps<{
  connection: Connection;
  section: "general" | "server" | "login" | "options";
  /** Where the connection lives — for picking a jump host from the same workspace. */
  workspaceId?: string;
  /** Its project, for a connection that is not in one yet — for the startup command. */
  projectId?: string;
}>();

const { t } = useI18n();

const settings = computed(() => props.connection.settings);

// ---- Credential sources -------------------------------------------------------
//
// "vault" is one source with several providers behind it, and the radio group
// shows one row per provider rather than a source plus a dropdown: "From
// 1Password" and "From Bitwarden" are two answers to the same question, and the
// list is where the answers already are. The rows are generated from
// VAULT_PROVIDERS, so a third manager adds its own row.

type CredentialSource<S extends string> = {
  value: S;
  /** Only on the vault rows: which manager this one stands for. */
  provider?: VaultProvider;
  label: string;
  hint: string;
};

/**
 * The vault rows for one type, phrased in that type's word for its secret.
 * SSH asks for a key and a password from the same managers, so which of the
 * two is passed in.
 */
function vaultSources<S extends string>(
  secret: "key" | "password",
  value: S,
): CredentialSource<S>[] {
  return VAULT_PROVIDERS.map(({ value: provider, label }) => ({
    value,
    provider,
    label: t("ConnectionForm.sources.vault", { provider: label }),
    hint: t(`ConnectionForm.sources.vaultHint.${secret}`, { provider: label }),
  }));
}

// The lists below are computed so their texts follow the language.

// ---- SSH: first key or password, then where from -------------------------------

type SshMethod = "key" | "password";

const SSH_METHODS = computed<{ value: SshMethod; label: string }[]>(() => [
  { value: "key", label: t("ConnectionForm.sshMethods.key") },
  { value: "password", label: t("ConnectionForm.sshMethods.password") },
]);

const KEY_SOURCES = computed<CredentialSource<SshAuth["source"]>[]>(() => [
  ...vaultSources("key", "vault"),
  {
    value: "keyFile",
    label: t("ConnectionForm.sources.keyFile"),
    hint: t("ConnectionForm.sources.keyFileHint"),
  },
  {
    value: "agent",
    label: t("ConnectionForm.sources.agent"),
    hint: t("ConnectionForm.sources.agentHint"),
  },
  {
    value: "inlineKey",
    label: t("ConnectionForm.sources.inlineKey"),
    hint: t("ConnectionForm.sources.inlineKeyHint"),
  },
]);

const SSH_PASSWORD_SOURCES = computed<CredentialSource<SshAuth["source"]>[]>(() => [
  ...vaultSources("password", "vaultPassword"),
  {
    value: "prompt",
    label: t("ConnectionForm.sources.prompt"),
    hint: t("ConnectionForm.sources.promptHintSsh"),
  },
  {
    value: "password",
    label: t("ConnectionForm.sources.password"),
    hint: t("ConnectionForm.sources.passwordHint"),
  },
]);

const sshMethod = computed<SshMethod>(() =>
  SSH_PASSWORD_SOURCES.value.some((s) => s.value === settings.value.auth.source)
    ? "password"
    : "key",
);

/** Switching the method starts at its first source — the vault, as for a new connection. */
// ---- Jump host ---------------------------------------------------------------
//
// A jump host is another SSH connection — with its own credentials and its own
// host key check. Left out is whatever itself jumps through this connection:
// that would be a circle.
//
// From the same workspace always. From another one only if this workspace
// belongs to nobody else — local or personal: in a team workspace colleagues
// could not resolve the ID, and the connection would break for them.

const jumpCandidates = computed(() => {
  const own = workspaces.find((w) => w.id === props.workspaceId);
  if (!own) return [];
  const private_ = !own.remote || own.remote.kind === "personal";
  return workspaces
    .filter((workspace) => workspace.id === own.id || private_)
    .flatMap((workspace) =>
      workspace.projects.flatMap((project) =>
        project.connections
          .filter(
            (candidate) =>
              candidate.id !== props.connection.id &&
              candidate.settings.type === "ssh" &&
              !jumpsThrough(candidate, props.connection.id),
          )
          .map((candidate) => ({
            value: candidate.id,
            label:
              workspace.id === own.id
                ? `${project.name} / ${candidate.name}`
                : `${workspace.name}${workspace.remote?.locked ? ` ${t("ConnectionForm.jump.locked")}` : ""} / ${project.name} / ${candidate.name}`,
          })),
      ),
    );
});

const jumpItems = computed(() => [
  { value: "", label: t("ConnectionForm.jump.none") },
  ...jumpCandidates.value,
]);

const jump = computed({
  get: () => (settings.value.type === "ssh" ? (settings.value.jump ?? "") : ""),
  set: (value: string) => {
    if (settings.value.type === "ssh") settings.value.jump = value || undefined;
  },
});

const agentForwarding = computed({
  get: () => settings.value.type === "ssh" && !!settings.value.agentForwarding,
  set: (on: boolean) => {
    if (settings.value.type === "ssh") settings.value.agentForwarding = on || undefined;
  },
});

// ---- Port forwards --------------------------------------------------------------

const FORWARD_KINDS = computed<{ value: Forward["kind"]; label: string }[]>(() => [
  { value: "local", label: t("ConnectionForm.forwards.kinds.local") },
  { value: "remote", label: t("ConnectionForm.forwards.kinds.remote") },
  { value: "dynamic", label: t("ConnectionForm.forwards.kinds.dynamic") },
]);

const forwards = computed<Forward[]>(() =>
  settings.value.type === "ssh" ? (settings.value.forwards ?? []) : [],
);

function addForward() {
  if (settings.value.type !== "ssh") return;
  settings.value.forwards = [
    ...(settings.value.forwards ?? []),
    { kind: "local", bindHost: "", bindPort: 8080, targetHost: "localhost", targetPort: 80 },
  ];
}

function removeForward(index: number) {
  if (settings.value.type !== "ssh") return;
  const next = [...(settings.value.forwards ?? [])];
  next.splice(index, 1);
  settings.value.forwards = next.length ? next : undefined;
}

// ---- Startup command -----------------------------------------------------------------

/**
 * Only a locked snippet that applies to this connection: the backend accepts
 * nothing else, because a startup command runs unasked in colleagues' terminals.
 */
const startupItems = computed(() => {
  const workspace = workspaces.find((w) => w.id === props.workspaceId);
  const projectId = props.projectId ?? projectOf(props.connection.id)?.id ?? "";
  return [
    { value: "", label: t("ConnectionForm.startup.none") },
    ...snippetsFor(workspace, projectId, props.connection.id)
      .filter((snippet) => snippet.locked)
      .map((snippet) => ({
      value: snippet.id,
      label: snippet.folder ? `${snippet.folder} / ${snippet.name}` : snippet.name,
    })),
  ];
});

const startupSnippet = computed({
  get: () => (settings.value.type === "ssh" ? (settings.value.startupSnippet ?? "") : ""),
  set: (id: string) => {
    if (settings.value.type === "ssh") settings.value.startupSnippet = id || undefined;
  },
});

// ---- Proxy ------------------------------------------------------------------------

type ProxyMode = "default" | "direct" | "custom";

const PROXY_MODES = computed<{ value: ProxyMode; label: string }[]>(() => [
  { value: "default", label: t("ConnectionForm.proxy.modes.default") },
  { value: "direct", label: t("ConnectionForm.proxy.modes.direct") },
  { value: "custom", label: t("ConnectionForm.proxy.modes.custom") },
]);

const PROXY_KINDS = (Object.keys(PROXY_KIND_LABELS) as ProxyKind[]).map((kind) => ({
  value: kind,
  label: PROXY_KIND_LABELS[kind],
}));

const proxyMode = computed<ProxyMode>({
  get: () => settings.value.proxy?.mode ?? "default",
  set: (mode) => {
    const next: ProxySetting | undefined =
      mode === "default"
        ? undefined
        : mode === "direct"
          ? { mode: "direct" }
          : { mode: "custom", kind: "socks5", host: "", port: PROXY_PORTS.socks5 };
    settings.value.proxy = next;
  },
});

function setProxyKind(kind: ProxyKind) {
  const proxy = settings.value.proxy;
  if (proxy?.mode !== "custom") return;
  // Only carry the port along while it was the usual one of the other kind.
  if (proxy.port === PROXY_PORTS[proxy.kind]) proxy.port = PROXY_PORTS[kind];
  proxy.kind = kind;
}

/** What "default" currently means — for display only. */
const deviceProxy = ref("");
onMounted(async () => {
  try {
    const proxy = await defaultProxy();
    deviceProxy.value = proxy ? proxyLabel(proxy) : t("ConnectionForm.proxy.noDefault");
  } catch (e) {
    deviceProxy.value = String(e);
  }
});

// ---- Generate, import, install a key -------------------------------------------------
//
// Everything lands in the "Private key" field, as OpenSSH without a passphrase —
// it is stored there encrypted anyway. It is installed on the server with the
// login that applies so far; if that already is this key, or there is none yet,
// the password is asked for.

/** Mirrors `keys::KeyPair`. */
type KeyPair = { private: string; public: string; fingerprint: string };

const keyInfo = ref<KeyPair | null>(null);
const keyBusy = ref("");
const keyError = ref("");
const keyNote = ref("");
/** The file that asked for a passphrase, and the passphrase for it. */
const keyFileWaiting = ref("");
const keyPassphrase = ref("");

function setKey(pair: KeyPair) {
  if (settings.value.auth.source !== "inlineKey") return;
  settings.value.auth.key = pair.private;
  keyInfo.value = pair;
  keyError.value = "";
  keyNote.value = "";
}

async function keyAction(label: string, action: () => Promise<void>) {
  keyBusy.value = label;
  keyError.value = "";
  try {
    await action();
  } catch (e) {
    keyError.value = String(e);
  } finally {
    keyBusy.value = "";
  }
}

function generateKey(kind: "ed25519" | "rsa") {
  const comment = settings.value.user && settings.value.host ? `${settings.value.user}@${settings.value.host}` : "";
  return keyAction(kind === "rsa" ? t("ConnectionForm.key.generatingRsa") : t("ConnectionForm.key.generating"), async () =>
    setKey(await invoke<KeyPair>("key_generate", { kind, comment })),
  );
}

async function importKey(path?: string) {
  const file = path ?? (await pickFile(t("ConnectionForm.key.importTitle"), ""));
  if (!file) return;
  await keyAction(t("ConnectionForm.key.reading"), async () => {
    try {
      setKey(
        await invoke<KeyPair>("key_import", { path: file, passphrase: keyPassphrase.value || null }),
      );
      keyFileWaiting.value = "";
      keyPassphrase.value = "";
    } catch (e) {
      if (/passphrase/i.test(String(e))) keyFileWaiting.value = file;
      throw e;
    }
  });
}

function describeKey() {
  if (settings.value.auth.source !== "inlineKey") return;
  const key = settings.value.auth.key;
  return keyAction(t("ConnectionForm.key.reading"), async () => {
    keyInfo.value = await invoke<KeyPair>("key_describe", { private: key, passphrase: null });
  });
}

async function copyPublicKey() {
  if (!keyInfo.value) return;
  await navigator.clipboard.writeText(keyInfo.value.public);
  keyNote.value = t("ConnectionForm.key.copied");
}

function installKey() {
  const pair = keyInfo.value;
  if (!pair || settings.value.type !== "ssh") return;
  const saved = findConnection(props.connection.id)?.settings;
  const usable =
    saved?.type === "ssh" &&
    !(saved.auth.source === "inlineKey" && saved.auth.key.trim() === pair.private.trim());
  const login = usable ? saved : { ...settings.value, auth: { source: "prompt" as const } };
  return keyAction(t("ConnectionForm.key.installing"), async () => {
    const fresh = await invoke<boolean>("ssh_install_key", {
      settings: JSON.parse(JSON.stringify(withJumps(login))),
      publicKey: pair.public,
    });
    keyNote.value = fresh
      ? t("ConnectionForm.key.installed")
      : t("ConnectionForm.key.alreadyInstalled");
  });
}

async function browseKeyFile() {
  const auth = settings.value.auth;
  if (auth.source !== "keyFile") return;
  const path = await pickFile(t("ConnectionForm.key.chooseTitle"), auth.path);
  if (path) auth.path = path;
}

function selectSshMethod(method: SshMethod) {
  if (sshMethod.value === method) return;
  const first = (method === "key" ? KEY_SOURCES : SSH_PASSWORD_SOURCES).value[0];
  selectKeySource(first.value, first.provider);
}

/** Replaces the auth object wholesale — the variants share no fields. */
function selectKeySource(source: SshAuth["source"], provider?: VaultProvider) {
  if (settings.value.type !== "ssh") return;
  settings.value.auth =
    source === "inlineKey"
      ? { source, key: "" }
      : source === "keyFile"
        ? { source, path: "" }
        : source === "password"
          ? { source, password: "" }
          : source === "prompt" || source === "agent"
            ? { source }
            : { source, provider: provider ?? "onePassword", reference: "" };
}

// ---- FTP: password source -----------------------------------------------------

const PASSWORD_SOURCES = computed<CredentialSource<FtpAuth["source"]>[]>(() => [
  ...vaultSources("password", "vault"),
  {
    value: "prompt",
    label: t("ConnectionForm.sources.prompt"),
    hint: t("ConnectionForm.sources.promptHintTransfers"),
  },
  {
    value: "password",
    label: t("ConnectionForm.sources.password"),
    hint: t("ConnectionForm.sources.passwordHint"),
  },
  {
    value: "anonymous",
    label: t("ConnectionForm.sources.anonymous"),
    hint: t("ConnectionForm.sources.anonymousHint"),
  },
]);

function selectPasswordSource(source: FtpAuth["source"], provider?: VaultProvider) {
  if (settings.value.type !== "ftp") return;
  settings.value.auth =
    source === "password"
      ? { source, password: "" }
      : source === "vault"
        ? { source, provider: provider ?? "onePassword", reference: "" }
        : { source };
}

// ---- S3: source of the Secret Access Key --------------------------------------
//
// Three rather than four: there is no anonymous S3. An unsigned request only
// ever reaches a bucket that is open to the whole internet, and a stored
// connection to one is not a thing anybody sets up.

const SECRET_SOURCES = computed<CredentialSource<S3Auth["source"]>[]>(() => [
  ...vaultSources("key", "vault"),
  {
    value: "prompt",
    label: t("ConnectionForm.sources.prompt"),
    hint: t("ConnectionForm.sources.promptHintTransfers"),
  },
  {
    value: "secret",
    label: t("ConnectionForm.sources.inlineKey"),
    hint: t("ConnectionForm.sources.secretHint"),
  },
]);

function selectSecretSource(source: S3Auth["source"], provider?: VaultProvider) {
  if (settings.value.type !== "s3") return;
  settings.value.auth =
    source === "secret"
      ? { source, secret: "" }
      : source === "vault"
        ? { source, provider: provider ?? "onePassword", reference: "" }
        : { source };
}

// ---- S3: endpoint ---------------------------------------------------------------

/**
 * Switching HTTPS off moves the port along, the same way the FTPS mode does —
 * but only while it is still the one the previous setting suggested. A MinIO
 * on 9000 was typed in deliberately and stays where it is.
 */
function selectTls(on: boolean) {
  if (settings.value.type !== "s3" || settings.value.tls === on) return;
  const wasDefault = settings.value.port === defaultPort(settings.value);
  settings.value.tls = on;
  if (wasDefault) settings.value.port = defaultPort(settings.value);
}

// ---- FTP: transport security --------------------------------------------------

const SECURITY_MODES = computed<{ value: FtpSecurity; label: string; hint: string }[]>(() =>
  (["explicit", "implicit", "plain"] as const).map((value) => ({
    value,
    label: t(`ConnectionForm.security.${value}`),
    hint: t(`ConnectionForm.security.${value}Hint`),
  })),
);

/**
 * Changing the mode moves the port along, but only while it is still the one
 * the previous mode suggested — implicit FTPS has a port of its own, and
 * having to know that is exactly the kind of thing a form should take care of.
 */
function selectSecurity(security: FtpSecurity) {
  if (settings.value.type !== "ftp" || settings.value.security === security) return;
  const wasDefault = settings.value.port === defaultPort(settings.value);
  settings.value.security = security;
  if (wasDefault) settings.value.port = defaultPort(settings.value);
}

const encrypted = computed(
  () => settings.value.type === "ftp" && settings.value.security !== "plain",
);

// ---- Hints ---------------------------------------------------------------------

/**
 * What the three shared fields are called, which is not the same everywhere —
 * under `ConnectionForm.fields.<type>`.
 */
const labels = computed(() => {
  const type = settings.value.type;
  return {
    host: t(`ConnectionForm.fields.${type}.host`),
    user: t(`ConnectionForm.fields.${type}.user`),
    credentials: t(`ConnectionForm.fields.${type}.credentials`),
  };
});

const hostPlaceholder = computed(() =>
  settings.value.type === "s3"
    ? t("ConnectionForm.hostPlaceholderS3")
    : t("ConnectionForm.hostPlaceholder"),
);

const credentialSources = computed(() => {
  if (settings.value.type === "ssh") {
    return sshMethod.value === "key" ? KEY_SOURCES.value : SSH_PASSWORD_SOURCES.value;
  }
  if (settings.value.type === "s3") return SECRET_SOURCES.value;
  return PASSWORD_SOURCES.value;
});

type AnySource = SshAuth["source"] | FtpAuth["source"] | S3Auth["source"];

/**
 * The radio group above is drawn from whichever list belongs to the type, so
 * the three lists' source names meet here as one. Which of the three setters
 * it is follows from the type, exactly as the list did.
 */
function selectCredentialSource(source: CredentialSource<AnySource>) {
  if (isActive(source)) return;
  if (settings.value.type === "ssh") {
    selectKeySource(source.value as SshAuth["source"], source.provider);
  } else if (settings.value.type === "s3") {
    selectSecretSource(source.value as S3Auth["source"], source.provider);
  } else {
    selectPasswordSource(source.value as FtpAuth["source"], source.provider);
  }
}

/**
 * Whether a row is the one in effect. A vault row has to agree on the provider
 * as well — "vault" alone would light up both of them.
 */
function isActive(source: CredentialSource<AnySource>): boolean {
  const auth = settings.value.auth;
  if (auth.source !== source.value) return false;
  return !("provider" in auth) || auth.provider === source.provider;
}

/** Either vault source — a key, or for SSH also a password. */
const fromVault = computed(
  () => settings.value.auth.source === "vault" || settings.value.auth.source === "vaultPassword",
);

/**
 * Whether the vault is asked for an SSH key. Everything else it hands out — an
 * FTP or SSH password, an S3 secret — is a plain field.
 */
const wantsKey = computed(
  () => settings.value.type === "ssh" && settings.value.auth.source === "vault",
);

/** Distinct per row, which "vault" alone would not be. */
function sourceKey(source: CredentialSource<AnySource>): string {
  return source.provider ? `${source.value}:${source.provider}` : source.value;
}

const activeHint = computed(() => credentialSources.value.find(isActive)?.hint ?? "");

/** The radio group speaks in row keys; this is the one in effect, and back again. */
const activeSourceKey = computed(() => {
  const active = credentialSources.value.find(isActive);
  return active ? sourceKey(active) : null;
});

function selectCredentialSourceKey(key: string | null) {
  const source = credentialSources.value.find((s) => sourceKey(s) === key);
  if (source) selectCredentialSource(source);
}

/**
 * The Secret Access Key and an optional session token live in one stored
 * secret, separated by a line break — a key never contains one. That way it
 * stays one value that everything else encrypts and syncs as before.
 */
function secretPart(index: 0 | 1) {
  return computed({
    get: () => {
      const auth = settings.value.auth;
      if (auth.source !== "secret") return "";
      const [key, ...token] = auth.secret.split("\n");
      return index === 0 ? key : token.join("\n");
    },
    set: (value: string) => {
      const auth = settings.value.auth;
      if (auth.source !== "secret") return;
      const [key, ...token] = auth.secret.split("\n");
      const next = index === 0 ? [value, token.join("\n")] : [key, value.trim()];
      auth.secret = next[1] ? `${next[0]}\n${next[1]}` : next[0];
    },
  });
}
const secretKey = secretPart(0);
const sessionToken = secretPart(1);

/** The one source per type whose secret is stored with the connection. */
const storedSecret = computed(() =>
  ["inlineKey", "password", "secret"].includes(settings.value.auth.source),
);

const securityHint = computed(
  () =>
    SECURITY_MODES.value.find(
      (m) => settings.value.type === "ftp" && m.value === settings.value.security,
    )?.hint ?? "",
);

// ---- Vault picker ----------------------------------------------------------
//
// The picker itself is [VaultPicker]; it is mounted only while its <details>
// is open, so opening it is what loads the vaults.

/** Which manager the credential source points at. */
const provider = computed<VaultProvider>(() =>
  "provider" in settings.value.auth ? settings.value.auth.provider : "onePassword",
);

const providerLabel = computed(() => VAULT_LABELS[provider.value]);

const credentialPickerOpen = ref(false);

function isOpen(event: Event): boolean {
  return (event.target as HTMLDetailsElement).open;
}

/** Both providers report the same field-type names. */
function preferCredential(field: OpField): boolean {
  return field.fieldType === (wantsKey.value ? "SshKey" : "Concealed");
}

/** The placeholder for the reference field, which differs per manager. */
const referenceHint = computed(() => {
  const base = VAULT_REFERENCE_HINTS[provider.value];
  return wantsKey.value && provider.value === "onePassword"
    ? `${base}?ssh-format=openssh`
    : base;
});

function applyReference(reference: string) {
  const auth = settings.value.auth;
  if ("reference" in auth) auth.reference = reference;
}

// ---- User from the vault ----------------------------------------------------
//
// The user field holds either the name itself or a reference to it — the same
// op:// or bw:// form a secret has, resolved by the backend at connect time
// (see `resolve_user` in src-tauri/src/vault.rs). Nothing on the server has to
// know the difference.

/** The manager a user reference points at, or null for a plain name. */
const userProvider = computed<VaultProvider | null>(() => {
  const user = settings.value.user;
  if (user.startsWith("op://")) return "onePassword";
  if (user.startsWith("bw://")) return "bitwarden";
  return null;
});

/** Typed in, or from one of the managers — the same rows as the credentials. */
type UserSource = "typed" | VaultProvider;

const USER_SOURCES = computed<{ value: UserSource; label: string; hint: string }[]>(() => [
  { value: "typed", label: t("ConnectionForm.user.typed"), hint: "" },
  ...VAULT_PROVIDERS.map(({ value, label }) => ({
    value,
    label: t("ConnectionForm.sources.vault", { provider: label }),
    hint: t("ConnectionForm.user.vaultHint", { provider: label }),
  })),
]);

/**
 * Held as its own state rather than read off the field: a vault row that was
 * just chosen has no reference yet, and an empty field would otherwise put
 * the choice straight back on "Enter".
 */
const userSource = ref<UserSource>(userProvider.value ?? "typed");

const userHint = computed(() => USER_SOURCES.value.find((s) => s.value === userSource.value)?.hint ?? "");

/** A name and a reference mean nothing to each other, so switching clears the field. */
function selectUserSource(source: UserSource) {
  if (userSource.value === source) return;
  userSource.value = source;
  settings.value.user = "";
  userPickerOpen.value = false;
}

const userPickerOpen = ref(false);

/** Both providers name the user name field of a login `username`. */
function preferUser(field: OpField): boolean {
  return field.id === "username";
}

function applyUser(reference: string) {
  settings.value.user = reference;
  userPickerOpen.value = false;
}
</script>

<template>
  <form class="form" @submit.prevent>
    <template v-if="section === 'general'">
    <!-- `data-autoselect`: focused and selected on open, not the close button. -->
    <Field :label="t('common.name')">
      <Input v-model="connection.name" data-autoselect />
    </Field>

    <Field :label="t('ConnectionForm.type')">
      <NativeSelect
        :items="CONNECTION_TYPES"
        :model-value="settings.type"
        @update:model-value="switchType(connection, $event)"
      />
    </Field>
    </template>

    <template v-if="section === 'server'">
    <div class="row">
      <Field :label="labels.host" class="grow">
        <Input v-model="settings.host" :placeholder="hostPlaceholder" data-autofocus />
      </Field>
      <!--
        No grouping: a port is not an amount, and "65.535" would read as one.
        An emptied field gets the last port back when it is left.
      -->
      <Field label="Port" class="port">
        <NumberInput
          v-model="settings.port"
          empty-fallback="previous"
          :min="1"
          :max="65535"
          :allow-decimal="false"
          :allow-negative="false"
          :format-options="{ useGrouping: false }"
          :stepper="false"
        />
      </Field>
    </div>
    <Field
      v-if="settings.type === 'ssh' && (jumpCandidates.length || settings.jump)"
      :label="t('ConnectionForm.jump.label')"
      :helper-text="t('ConnectionForm.jump.hint')"
    >
      <NativeSelect v-model="jump" :items="jumpItems" />
    </Field>
    </template>

    <!-- ---- User ---------------------------------------------------------- -->

    <fieldset v-if="section === 'login'" class="sources">
      <legend>{{ labels.user }}</legend>

      <!--
        Left on screen but disabled for an anonymous login rather than removed:
        what is stored stays visible, and the reason it does not apply is
        easier to see next to the option that switched it off.
      -->
      <Input
        v-if="settings.auth.source === 'anonymous'"
        :model-value="settings.user"
        disabled
        placeholder="anonymous"
      />

      <template v-else>
        <RadioGroup
          required
          :model-value="userSource"
          :aria-label="labels.user"
          @update:model-value="selectUserSource"
        >
          <RadioGroupItem v-for="source in USER_SOURCES" :key="source.value" :value="source.value">
            {{ source.label }}
          </RadioGroupItem>
        </RadioGroup>

        <p v-if="userHint" class="hint">{{ userHint }}</p>

        <Input v-if="userSource === 'typed'" v-model="settings.user" />

        <div v-else class="op">
          <Field :label="t('ConnectionForm.reference')">
            <Input v-model="settings.user" :placeholder="VAULT_REFERENCE_HINTS[userSource]" />
          </Field>

          <details :open="userPickerOpen" @toggle="userPickerOpen = isOpen($event)">
            <summary>{{ t("ConnectionForm.pickIn", { provider: VAULT_LABELS[userSource] }) }}</summary>
            <VaultPicker
              v-if="userPickerOpen"
              :provider="userSource"
              :prefer="preferUser"
              @pick="applyUser"
            />
          </details>
        </div>
      </template>
    </fieldset>

    <!-- ---- FTP: Transport ---------------------------------------------- -->

    <fieldset v-if="section === 'server' && settings.type === 'ftp'" class="sources">
      <legend>{{ t("ConnectionForm.encryption") }}</legend>

      <RadioGroup
        required
        :model-value="settings.security"
        :aria-label="t('ConnectionForm.encryption')"
        @update:model-value="selectSecurity"
      >
        <RadioGroupItem v-for="mode in SECURITY_MODES" :key="mode.value" :value="mode.value">
          {{ mode.label }}
        </RadioGroupItem>
      </RadioGroup>

      <p class="hint" :class="{ warn: settings.security === 'plain' }">{{ securityHint }}</p>

      <Checkbox v-if="encrypted" v-model:checked="settings.acceptInvalidCert">
        {{ t("ConnectionForm.acceptInvalidCert") }}
      </Checkbox>

      <p v-if="encrypted && settings.acceptInvalidCert" class="hint warn">
        {{ t("ConnectionForm.acceptInvalidCertHint") }}
      </p>
    </fieldset>

    <!-- ---- S3: endpoint --------------------------------------------------- -->

    <fieldset v-if="section === 'server' && settings.type === 's3'" class="sources">
      <legend>{{ t("ConnectionForm.fields.s3.host") }}</legend>

      <Checkbox :checked="settings.tls" @update:checked="selectTls">
        HTTPS
      </Checkbox>

      <p class="hint" :class="{ warn: !settings.tls }">
        {{
          settings.tls
            ? t("ConnectionForm.s3.tlsHint")
            : t("ConnectionForm.s3.noTlsHint")
        }}
      </p>

      <Checkbox v-if="settings.tls" v-model:checked="settings.acceptInvalidCert">
        {{ t("ConnectionForm.acceptInvalidCert") }}
      </Checkbox>

      <p v-if="settings.tls && settings.acceptInvalidCert" class="hint warn">
        {{ t("ConnectionForm.acceptInvalidCertHint") }}
      </p>

      <Checkbox v-model:checked="settings.pathStyle">
        {{ t("ConnectionForm.s3.pathStyle") }}
      </Checkbox>

      <i18n-t keypath="ConnectionForm.s3.pathStyleHint" tag="p" class="hint">
        <template #virtualHost><code>{{ t("ConnectionForm.s3.virtualHostExample") }}</code></template>
        <template #pathStyle><code>{{ t("ConnectionForm.s3.pathStyleExample") }}</code></template>
        <template #ip><code>bucket.10.0.0.5</code></template>
      </i18n-t>
    </fieldset>

    <!-- ---- Options -------------------------------------------------------- -->

    <!-- S3 has its own, as bucket and prefix. -->
    <Field v-if="section === 'options' && settings.type !== 's3'" :label="t('ConnectionForm.startPath')">
      <Input v-model.trim="settings.startPath" :placeholder="t('ConnectionForm.startPathPlaceholder')" />
    </Field>

    <fieldset v-if="section === 'options' && settings.type === 'ssh'" class="sources forwards">
      <legend>{{ t("ConnectionForm.forwards.title") }}</legend>
      <i18n-t keypath="ConnectionForm.forwards.hint" tag="p" class="hint">
        <template #local><strong>{{ t("ConnectionForm.forwards.local") }}</strong></template>
        <template #remote><strong>{{ t("ConnectionForm.forwards.remote") }}</strong></template>
        <template #socks><strong>SOCKS</strong></template>
      </i18n-t>
      <div v-for="(forward, index) in forwards" :key="index" class="forward-row">
        <NativeSelect v-model="forward.kind" :items="FORWARD_KINDS" size="sm" :aria-label="t('ConnectionForm.forwards.kind')" />
        <Input v-model.trim="forward.bindHost" size="sm" placeholder="127.0.0.1" :aria-label="t('ConnectionForm.forwards.address')" />
        <NumberInput
          v-model="forward.bindPort"
          size="sm"
          :min="0"
          :max="65535"
          :allow-decimal="false"
          :allow-negative="false"
          :format-options="{ useGrouping: false }"
          :stepper="false"
          aria-label="Port"
        />
        <template v-if="forward.kind !== 'dynamic'">
          <span class="arrow">→</span>
          <Input v-model.trim="forward.targetHost" size="sm" :placeholder="t('ConnectionForm.forwards.target')" :aria-label="t('ConnectionForm.forwards.target')" />
          <NumberInput
            v-model="forward.targetPort"
            size="sm"
            :min="1"
            :max="65535"
            :allow-decimal="false"
            :allow-negative="false"
            :format-options="{ useGrouping: false }"
            :stepper="false"
            :aria-label="t('ConnectionForm.forwards.targetPort')"
          />
        </template>
        <Button variant="text" size="sm" @click="removeForward(index)">{{ t("common.remove") }}</Button>
      </div>
      <Button variant="outline" size="sm" @click="addForward">{{ t("ConnectionForm.forwards.add") }}</Button>
    </fieldset>

    <Field
      v-if="section === 'options' && settings.type === 'ssh' && startupItems.length > 1"
      :label="t('ConnectionForm.startup.label')"
      :helper-text="t('ConnectionForm.startup.hint')"
    >
      <NativeSelect v-model="startupSnippet" :items="startupItems" />
    </Field>

    <template v-if="section === 'options' && settings.type === 'ssh'">
      <Checkbox v-model:checked="agentForwarding">{{ t("ConnectionForm.agentForwarding") }}</Checkbox>
      <p class="hint" :class="{ warn: agentForwarding }">
        {{ t("ConnectionForm.agentForwardingHint") }}
      </p>
    </template>

    <fieldset v-if="section === 'options' && settings.type === 's3'" class="sources">
      <legend>Bucket</legend>

      <div class="row">
        <Field label="Bucket" class="grow">
          <Input v-model="settings.bucket" :placeholder="t('ConnectionForm.s3.bucketPlaceholder')" />
        </Field>
        <Field :label="t('ConnectionForm.s3.region')" class="grow">
          <Input v-model="settings.region" placeholder="us-east-1" />
        </Field>
      </div>

      <Field :label="t('ConnectionForm.s3.prefix')">
        <Input v-model="settings.prefix" :placeholder="t('ConnectionForm.s3.prefixPlaceholder')" />
      </Field>

      <p class="hint">{{ t("ConnectionForm.s3.bucketHint") }}</p>

      <p class="hint">{{ t("ConnectionForm.s3.regionHint") }}</p>

      <Field :label="t('ConnectionForm.s3.storageClass')">
        <Input v-model="settings.storageClass" :placeholder="t('ConnectionForm.s3.storageClassPlaceholder')" />
      </Field>

      <i18n-t keypath="ConnectionForm.s3.storageClassHint" tag="p" class="hint">
        <template #standard><code>STANDARD</code></template>
        <template #standardIa><code>STANDARD_IA</code></template>
        <template #glacierIr><code>GLACIER_IR</code></template>
      </i18n-t>
    </fieldset>

    <!-- ---- Credentials -------------------------------------------------- -->

    <fieldset v-if="section === 'login'" class="sources">
      <legend>{{ labels.credentials }}</legend>

      <RadioGroup
        v-if="settings.type === 'ssh'"
        class="methods"
        orientation="horizontal"
        required
        :model-value="sshMethod"
        :aria-label="t('ConnectionForm.method')"
        @update:model-value="selectSshMethod"
      >
        <RadioGroupItem v-for="method in SSH_METHODS" :key="method.value" :value="method.value">
          {{ method.label }}
        </RadioGroupItem>
      </RadioGroup>

      <RadioGroup
        :model-value="activeSourceKey"
        :aria-label="labels.credentials"
        @update:model-value="selectCredentialSourceKey"
      >
        <RadioGroupItem
          v-for="source in credentialSources"
          :key="sourceKey(source)"
          :value="sourceKey(source)"
        >
          {{ source.label }}
        </RadioGroupItem>
      </RadioGroup>

      <p class="hint">{{ activeHint }}</p>

      <Alert v-if="storedSecret && connection.secretUnreadable" status="warn" size="sm">
        {{ t("ConnectionForm.secretUnreadable") }}
      </Alert>

      <Field v-if="settings.auth.source === 'keyFile'" :label="t('ConnectionForm.path')">
        <div class="path-row">
          <Input v-model="settings.auth.path" placeholder="C:\Users\...\id_ed25519" />
          <Button variant="outline" @click="browseKeyFile">{{ t("ConnectionForm.browse") }}</Button>
        </div>
      </Field>

      <Field v-else-if="settings.auth.source === 'inlineKey'" :label="t('ConnectionForm.privateKey')" class="key">
        <Textarea
          v-model="settings.auth.key"
          mono
          rows="6"
          spellcheck="false"
          placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"
          @update:model-value="keyInfo = null"
        />
      </Field>

      <Field v-else-if="settings.auth.source === 'password'" :label="t('common.password')">
        <PasswordInput v-model="settings.auth.password" autocomplete="off" />
      </Field>

      <template v-else-if="settings.auth.source === 'secret'">
        <Field label="Secret Access Key">
          <PasswordInput v-model="secretKey" autocomplete="off" />
        </Field>
        <Field
          :label="t('ConnectionForm.sessionToken')"
          :helper-text="t('ConnectionForm.sessionTokenHint')"
        >
          <PasswordInput v-model="sessionToken" autocomplete="off" />
        </Field>
      </template>

      <div v-else-if="fromVault && 'reference' in settings.auth" class="op">
        <Field :label="t('ConnectionForm.reference')">
          <Input v-model="settings.auth.reference" :placeholder="referenceHint" />
        </Field>

        <details @toggle="credentialPickerOpen = isOpen($event)">
          <summary>{{ t("ConnectionForm.pickIn", { provider: providerLabel }) }}</summary>
          <VaultPicker
            v-if="credentialPickerOpen"
            :provider="provider"
            :wants-key="wantsKey"
            :prefer="preferCredential"
            @pick="applyReference"
          />
        </details>
      </div>

      <div v-if="settings.type === 'ssh' && settings.auth.source === 'inlineKey'" class="key-tools">
        <div class="key-buttons">
          <Button variant="outline" size="sm" :disabled="!!keyBusy" @click="generateKey('ed25519')">
            {{ t("ConnectionForm.key.generate") }}
          </Button>
          <Button
            variant="text"
            size="sm"
            :disabled="!!keyBusy"
            :title="t('ConnectionForm.key.rsaHint')"
            @click="generateKey('rsa')"
          >
            {{ t("ConnectionForm.key.rsa") }}
          </Button>
          <Button variant="outline" size="sm" :disabled="!!keyBusy" @click="importKey()">
            {{ t("ConnectionForm.key.fromFile") }}
          </Button>
          <Button
            v-if="!keyInfo && settings.auth.key.trim()"
            variant="text"
            size="sm"
            :disabled="!!keyBusy"
            @click="describeKey"
          >
            {{ t("ConnectionForm.key.showPublic") }}
          </Button>
        </div>

        <div v-if="keyFileWaiting" class="row">
          <Field :label="t('ConnectionForm.key.passphrase')" class="grow">
            <PasswordInput v-model="keyPassphrase" autocomplete="off" @keydown.enter.prevent="importKey(keyFileWaiting)" />
          </Field>
          <Button size="sm" :disabled="!keyPassphrase" @click="importKey(keyFileWaiting)">{{ t("ConnectionForm.key.unlock") }}</Button>
        </div>

        <template v-if="keyInfo">
          <code class="public" :title="keyInfo.public">{{ keyInfo.public }}</code>
          <p class="hint">{{ keyInfo.fingerprint }}</p>
          <div class="key-buttons">
            <Button variant="text" size="sm" @click="copyPublicKey">{{ t("ConnectionForm.key.copyPublic") }}</Button>
            <Button
              variant="outline"
              size="sm"
              :disabled="!!keyBusy || !settings.host || !settings.user"
              :title="t('ConnectionForm.key.installHint')"
              @click="installKey"
            >
              {{ t("ConnectionForm.key.install") }}
            </Button>
          </div>
        </template>

        <p v-if="keyBusy" class="hint">{{ keyBusy }}</p>
        <p v-if="keyNote" class="hint">{{ keyNote }}</p>
        <Alert v-if="keyError" status="danger" size="sm">{{ keyError }}</Alert>
      </div>
    </fieldset>

    <!-- ---- FTP: data connection ----------------------------------------- -->

    <fieldset v-if="section === 'options' && settings.type === 'ftp'" class="sources">
      <legend>{{ t("ConnectionForm.ftp.dataConnection") }}</legend>

      <Checkbox v-model:checked="settings.passive">
        {{ t("ConnectionForm.ftp.passive") }}
      </Checkbox>

      <p class="hint">{{ t("ConnectionForm.ftp.passiveHint") }}</p>
    </fieldset>

    <!-- ---- Proxy ---------------------------------------------------------- -->

    <fieldset v-if="section === 'options'" class="sources">
      <legend>Proxy</legend>

      <NativeSelect v-model="proxyMode" :items="PROXY_MODES" aria-label="Proxy" />
      <p v-if="proxyMode === 'default'" class="hint">
        {{ t("ConnectionForm.proxy.defaultHint", { proxy: deviceProxy }) }}
      </p>

      <div v-if="settings.proxy?.mode === 'custom'" class="row">
        <Field :label="t('ConnectionForm.proxy.kind')" class="proxy-kind">
          <NativeSelect
            :model-value="settings.proxy.kind"
            :items="PROXY_KINDS"
            @update:model-value="setProxyKind($event as ProxyKind)"
          />
        </Field>
        <Field label="Host" class="grow">
          <Input
            v-model.trim="settings.proxy.host"
            :placeholder="t('ConnectionForm.proxy.hostPlaceholder')"
            autocapitalize="off"
            spellcheck="false"
          />
        </Field>
        <Field label="Port" class="proxy-port">
          <NumberInput
            v-model="settings.proxy.port"
            :min="1"
            :max="65535"
            :allow-decimal="false"
            :allow-negative="false"
            :format-options="{ useGrouping: false }"
            :stepper="false"
          />
        </Field>
      </div>
      <p v-if="settings.proxy?.mode === 'custom'" class="hint">
        {{ t("ConnectionForm.proxy.customHint") }}
      </p>
      <p v-if="settings.type === 'ssh' && proxyMode !== 'direct'" class="hint">
        {{ t("ConnectionForm.proxy.jumpHint") }}
      </p>
      <p v-if="settings.type === 'ftp' && proxyMode !== 'direct'" class="hint">
        {{ t("ConnectionForm.proxy.ftpHint") }}
      </p>
    </fieldset>
  </form>
</template>

<style scoped>
.forward-row {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 0.4rem;
  margin-bottom: 0.4rem;
}

.forward-row > :nth-child(2),
.forward-row > :nth-child(5) {
  flex: 1;
  min-width: 7rem;
}

.forward-row > :nth-child(3),
.forward-row > :nth-child(6) {
  width: 5.5rem;
}

.proxy-kind {
  width: 11rem;
}

.key-tools {
  display: flex;
  flex-direction: column;
  gap: 0.4rem;
  margin-top: 0.4rem;
}

.key-buttons {
  display: flex;
  flex-wrap: wrap;
  gap: 0.4rem;
}

.public {
  display: block;
  font-family: Consolas, Menlo, monospace;
  font-size: 0.78rem;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  color: var(--muted);
}

.proxy-port {
  width: 6.5rem;
}

.forward-row .arrow {
  color: var(--muted);
}

.path-row {
  display: flex;
  gap: 0.5rem;
}

.path-row > :first-child {
  flex: 1;
  min-width: 0;
}

.form {
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
}

.row {
  display: flex;
  gap: 0.75rem;
}

.grow {
  flex: 1;
}

.port {
  width: 7rem;
  flex: 0 0 7rem;
}

.sources {
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 0.75rem 1rem 1rem;
  margin: 0;
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.sources legend {
  font-size: 0.8rem;
  color: var(--muted);
  padding: 0 0.35rem;
}

.hint {
  margin: 0.25rem 0 0.5rem;
  font-size: 0.85rem;
  color: var(--muted);
  line-height: 1.4;
}

.hint.warn {
  color: var(--warn);
}

/* Host names and storage classes are typed exactly as they are written, so a
   hint that shows one says so. */
.hint code {
  font-family: Consolas, Menlo, monospace;
  font-size: 0.9em;
  color: var(--fg);
  word-break: break-all;
}

details summary {
  cursor: pointer;
  font-size: 0.9rem;
  color: var(--accent);
}

/* Key | Password, above the sources that belong to the choice. */
.methods {
  padding-bottom: 0.5rem;
  margin-bottom: 0.25rem;
  border-bottom: 1px dashed var(--border);
}

.key :deep(textarea) {
  font-size: 0.8rem;
  resize: vertical;
}
</style>
