<script setup lang="ts">
import { computed, ref, watch } from "vue";
import { invoke } from "@tauri-apps/api/core";
import { useI18n } from "vue-i18n";
import { Alert, Button, Checkbox, EmptyState, NativeSelect } from "@wirecore/wirelayer-vue";
import EditDialog from "./EditDialog.vue";
import { pickFile } from "../pick-file";
import { proxyLabel } from "../proxy";
import {
  defaultSettings,
  newId,
  type Connection,
  type Forward,
  type FtpSecurity,
  type Project,
  type ProxySetting,
} from "../types";

/**
 * Imports connections from other programs — for everyone who does not want to
 * type in every host once more.
 *
 * Reading happens in the backend (`import.rs`, `ssh_config.rs`); every source
 * delivers the same list. Passwords come along from none of them: where there
 * is no key, the connection asks when connecting — for `~/.ssh/config` it
 * stays the SSH agent, because `ssh` would do the same at this point.
 *
 * A jump host is taken over if its hops are imported along with it or already
 * exist in the project under the same name or host. Otherwise the connection
 * stays direct, and the list says so.
 */
const props = defineProps<{ project: Project }>();

const emit = defineEmits<{ save: [connections: Connection[]]; cancel: [] }>();
const { t } = useI18n();

type Source = "sshConfig" | "putty" | "mobaxterm" | "csv";

const SOURCES = computed<{ value: Source; label: string }[]>(() => [
  { value: "sshConfig", label: "~/.ssh/config" },
  { value: "putty", label: "PuTTY" },
  { value: "mobaxterm", label: "MobaXterm (.mxtsessions, MobaXterm.ini)" },
  { value: "csv", label: t("HostImport.sources.csv") },
]);

/** Mirrors `import::ImportedHost`. */
type ImportedHost = {
  alias: string;
  kind: "ssh" | "ftp";
  host: string;
  port: number;
  user: string;
  auth: { source: "keyFile"; path: string } | { source: "agent" } | { source: "prompt" };
  security?: FtpSecurity;
  group?: string;
  /** The `ProxyJump` or the gateway, as written. */
  proxy: string | null;
  /** The hops, first one first, as names. */
  proxyJump: string[];
  forwards: Forward[];
  agentForwarding: boolean;
  connectionProxy?: ProxySetting;
  notes: string[];
};

type ImportResult = { hosts: ImportedHost[]; skipped: { name: string; reason: string }[] };

const source = ref<Source>("sshConfig");
const file = ref("");
const result = ref<ImportResult | null>(null);
const loading = ref(false);
const error = ref("");
const chosen = ref<Set<string>>(new Set());

const hosts = computed(() => result.value?.hosts ?? []);
const needsFile = computed(() => source.value === "mobaxterm" || source.value === "csv");

/** Already in the project: same host, same port, same user. */
function present(host: ImportedHost): boolean {
  return props.project.connections.some(
    ({ settings }) =>
      settings.type === host.kind &&
      settings.host === host.host &&
      settings.port === host.port &&
      settings.user === host.user,
  );
}

async function load() {
  result.value = null;
  error.value = "";
  if (needsFile.value && !file.value) return;
  loading.value = true;
  try {
    const loaded =
      source.value === "sshConfig"
        ? await invoke<ImportResult>("ssh_config_hosts")
        : source.value === "putty"
          ? await invoke<ImportResult>("import_putty")
          : await invoke<ImportResult>("import_file", { path: file.value, format: source.value });
    result.value = loaded;
    chosen.value = new Set(loaded.hosts.filter((h) => !present(h)).map((h) => h.alias));
  } catch (e) {
    error.value = String(e);
  } finally {
    loading.value = false;
  }
}

watch(
  source,
  () => {
    file.value = "";
    void load();
  },
  { immediate: true },
);

async function chooseFile() {
  const filters =
    source.value === "csv"
      ? [{ name: "CSV", extensions: ["csv", "txt"] }]
      : [{ name: "MobaXterm", extensions: ["mxtsessions", "ini"] }];
  const picked = await pickFile(t("HostImport.chooseFileTitle"), file.value, filters);
  if (!picked) return;
  file.value = picked;
  await load();
}

function toggle(alias: string, on: boolean) {
  const next = new Set(chosen.value);
  if (on) next.add(alias);
  else next.delete(alias);
  chosen.value = next;
}

function authLabel(host: ImportedHost): string {
  if (host.auth.source === "keyFile") return t("HostImport.auth.keyFile", { path: host.auth.path });
  if (host.auth.source === "agent") return t("HostImport.auth.agent");
  return t("HostImport.auth.prompt");
}

const count = computed(() => chosen.value.size);

/** A hop, found again among the chosen hosts or in the project — by name or host. */
function hopKnown(name: string): boolean {
  return (
    hosts.value.some((h) => chosen.value.has(h.alias) && (h.alias === name || h.host === name)) ||
    props.project.connections.some(
      (c) => c.settings.type === "ssh" && (c.name === name || c.settings.host === name),
    )
  );
}

/** Whether this host's jump can be represented completely. */
function jumpResolvable(host: ImportedHost): boolean {
  return host.proxyJump.length > 0 && host.proxyJump.every(hopKnown);
}

function save() {
  const picked = hosts.value.filter((host) => chosen.value.has(host.alias));
  const ids = new Map(picked.map((host) => [host.alias, newId()]));
  const idOf = (name: string) =>
    ids.get(name) ??
    ids.get(picked.find((h) => h.host === name)?.alias ?? "") ??
    props.project.connections.find(
      (c) => c.settings.type === "ssh" && (c.name === name || c.settings.host === name),
    )?.id;

  const connections: Connection[] = picked.map((host): Connection => {
    if (host.kind === "ftp") {
      const base = defaultSettings("ftp");
      if (base.type !== "ftp") throw new Error("defaultSettings");
      return {
        id: ids.get(host.alias)!,
        name: host.alias,
        settings: {
          ...base,
          host: host.host,
          port: host.port,
          user: host.user,
          security: host.security ?? base.security,
          auth: { source: "prompt" },
          ...(host.connectionProxy ? { proxy: host.connectionProxy } : {}),
        },
      };
    }
    return {
      id: ids.get(host.alias)!,
      name: host.alias,
      settings: {
        type: "ssh",
        host: host.host,
        port: host.port,
        user: host.user,
        auth: host.auth,
        startPath: "",
        ...(host.forwards.length ? { forwards: host.forwards } : {}),
        ...(host.agentForwarding ? { agentForwarding: true } : {}),
        ...(host.connectionProxy ? { proxy: host.connectionProxy } : {}),
      },
    };
  });

  // Hops a, b means: first a, then b, then the target. So the target jumps
  // via b, and b via a — unless b already has one of its own.
  const byHop = (name: string) =>
    connections.find(
      (c) => c.name === name || (c.settings.type === "ssh" && c.settings.host === name),
    );
  for (const host of picked) {
    if (host.kind !== "ssh" || !jumpResolvable(host)) continue;
    const hops = host.proxyJump;
    const target = connections.find((c) => c.name === host.alias)!;
    if (target.settings.type === "ssh") target.settings.jump = idOf(hops[hops.length - 1]);
    for (let i = hops.length - 1; i > 0; i--) {
      const hop = byHop(hops[i]);
      if (hop && hop.settings.type === "ssh" && !hop.settings.jump) hop.settings.jump = idOf(hops[i - 1]);
    }
  }
  emit("save", connections);
}
</script>

<template>
  <EditDialog
    :title="t('HostImport.title')"
    mode="create"
    wide
    :can-save="count > 0"
    @save="save"
    @cancel="emit('cancel')"
  >
    <p class="lead">{{ t("HostImport.lead", { project: project.name }) }}</p>

    <div class="source">
      <NativeSelect v-model="source" :items="SOURCES" :aria-label="t('HostImport.source')" />
      <Button v-if="needsFile" variant="outline" size="sm" @click="chooseFile">
        {{ file ? t("HostImport.otherFile") : t("HostImport.chooseFile") }}
      </Button>
    </div>
    <p v-if="needsFile && file" class="muted file">{{ file }}</p>
    <i18n-t v-if="source === 'csv'" keypath="HostImport.csvHint" tag="p" class="hint">
      <template #name><code>name</code></template>
      <template #host><code>host</code></template>
      <template #hostname><code>hostname</code></template>
      <template #address><code>address</code></template>
      <template #port><code>port</code></template>
      <template #user><code>user</code></template>
      <template #protocol><code>protocol</code></template>
      <template #key><code>key</code></template>
      <template #group><code>group</code></template>
    </i18n-t>
    <p v-else-if="source === 'mobaxterm'" class="hint">{{ t("HostImport.mobaxtermHint") }}</p>
    <i18n-t v-else-if="source === 'sshConfig'" keypath="HostImport.sshConfigHint" tag="p" class="hint">
      <template #identityFile><code>IdentityFile</code></template>
      <template #include><code>Include</code></template>
      <template #match><code>Match</code></template>
    </i18n-t>

    <Alert v-if="error" status="danger" size="sm">{{ error }}</Alert>

    <p v-else-if="loading" class="muted">{{ t("HostImport.reading") }}</p>

    <EmptyState
      v-else-if="result && !hosts.length && !result.skipped.length"
      size="sm"
      :title="t('HostImport.emptyTitle')"
      :description="t('HostImport.emptyDescription')"
    />

    <ul v-if="hosts.length" class="hosts">
      <li v-for="host in hosts" :key="host.alias">
        <label class="row">
          <Checkbox
            :checked="chosen.has(host.alias)"
            @update:checked="(on: boolean) => toggle(host.alias, on)"
          />
          <span class="grow">
            <strong>
              {{ host.alias }}
              <span v-if="host.kind === 'ftp'" class="muted">· FTP</span>
              <span v-if="host.group" class="muted">· {{ host.group }}</span>
            </strong>
            <span class="muted">
              {{ host.user ? `${host.user}@` : "" }}{{ host.host
              }}{{ host.port === (host.kind === "ftp" ? 21 : 22) ? "" : `:${host.port}` }} ·
              {{ authLabel(host) }}
            </span>
            <span v-if="present(host)" class="note">{{ t("HostImport.present") }}</span>
            <span v-if="host.proxyJump.length && jumpResolvable(host)" class="note">
              {{ t("HostImport.jumpResolved", { hops: host.proxyJump.join(" → ") }) }}
            </span>
            <span v-else-if="host.proxyJump.length" class="note">
              {{
                t("HostImport.jumpMissing", {
                  proxy: host.proxy,
                  hops: host.proxyJump.filter((hop) => !hopKnown(hop)).join(", "),
                })
              }}
            </span>
            <span v-if="host.connectionProxy?.mode === 'custom'" class="note">
              {{ t("HostImport.viaProxy", { proxy: proxyLabel(host.connectionProxy) }) }}
            </span>
            <span v-if="host.forwards.length" class="note">
              {{ t("HostImport.forwards", host.forwards.length) }}
            </span>
            <span v-for="note in host.notes" :key="note" class="note">{{ note }}</span>
          </span>
        </label>
      </li>
    </ul>

    <details v-if="result?.skipped.length" class="skipped">
      <summary class="muted">
        {{ t("HostImport.skipped", result.skipped.length) }}
      </summary>
      <ul>
        <li v-for="entry in result.skipped" :key="entry.name" class="muted">
          {{ entry.name }}: {{ entry.reason }}
        </li>
      </ul>
    </details>
  </EditDialog>
</template>

<style scoped>
.lead {
  margin: 0 0 1rem;
  font-size: 0.9rem;
  line-height: 1.5;
  color: var(--muted);
}

.source {
  display: flex;
  gap: 0.5rem;
  align-items: center;
}

.source > :first-child {
  flex: 1;
  min-width: 0;
}

.file {
  margin: 0.4rem 0 0;
}

.hint {
  margin: 0.5rem 0 1rem;
  font-size: 0.85rem;
  line-height: 1.4;
  color: var(--muted);
}

code {
  font-family: Consolas, Menlo, monospace;
  font-size: 0.85rem;
}

.hosts {
  list-style: none;
  margin: 0;
  padding: 0;
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
}

.row {
  display: flex;
  align-items: flex-start;
  gap: 0.6rem;
  padding: 0.4rem 0.25rem;
  cursor: pointer;
}

.grow {
  flex: 1;
  display: flex;
  flex-direction: column;
  gap: 0.1rem;
  min-width: 0;
}

.muted {
  color: var(--muted);
  font-size: 0.85rem;
  word-break: break-all;
}

.note {
  font-size: 0.8rem;
  font-style: italic;
  color: var(--muted);
}

.skipped {
  margin-top: 0.75rem;
}

.skipped ul {
  margin: 0.4rem 0 0;
  padding-left: 1.2rem;
}
</style>
