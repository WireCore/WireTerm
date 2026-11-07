<script setup lang="ts">
/**
 * Which server keys count as trusted — and the way to revoke that trust from
 * one again.
 *
 * Two lists, because there are two stores: this device's `known_hosts`, and
 * for a workspace on a backend the workspace's host keys, which every sync
 * writes into the file here. Revoking in the workspace leaves the file here
 * alone — it belongs to this device. `~/.ssh/known_hosts` is only read and
 * therefore not shown here.
 *
 * TLS certificates (FTPS, S3) are in both lists too: on the device from a file
 * of their own, in the workspace as an entry of type `x509-sha256`.
 */
import { onMounted, ref } from "vue";
import { useI18n } from "vue-i18n";
import { invoke } from "@tauri-apps/api/core";
import { Alert, Button, EmptyState } from "@wirecore/wirelayer-vue";
import EditDialog from "./EditDialog.vue";
import { forgetHost, knownHosts, type KnownHost } from "../cloud";
import type { Workspace } from "../types";

const props = defineProps<{ workspace: Workspace }>();
const emit = defineEmits<{ close: [] }>();
const { t } = useI18n();

/** Mirrors `known_hosts::Entry`; a certificate carries `CERTIFICATE` as its algorithm. */
type LocalEntry = { host: string; port: number; algorithm: string; fingerprint: string };

/** How a certificate is called in a workspace, beside the SSH key types. */
const CERTIFICATE = "x509-sha256";

/** `AB:CD:…`, as `openssl` writes a fingerprint, from the hex a workspace stores. */
function certificateFingerprint(hex: string) {
  return (hex.toUpperCase().match(/../g) ?? []).join(":");
}

function label(algorithm: string) {
  return algorithm === CERTIFICATE ? t("HostKeysDialog.tlsCertificate") : algorithm;
}

/** A certificate is pinned to its port, a host key only shown with one when it is not 22. */
function whereEntry(host: string, port: number, algorithm: string) {
  return algorithm === CERTIFICATE ? `${host}:${port}` : where(host, port);
}

const local = ref<LocalEntry[] | null>(null);
const shared = ref<(KnownHost & { fingerprint: string })[] | null>(null);
const error = ref("");

function where(host: string, port: number) {
  return port === 22 ? host : `${host}:${port}`;
}

async function load() {
  error.value = "";
  try {
    const [keys, certificates] = await Promise.all([
      invoke<LocalEntry[]>("known_hosts_list"),
      invoke<Omit<LocalEntry, "algorithm">[]>("certificates_list"),
    ]);
    local.value = [
      ...keys,
      ...certificates.map((entry) => ({ ...entry, algorithm: CERTIFICATE })),
    ];
    if (props.workspace.remote) {
      const rows = await knownHosts(props.workspace.id);
      shared.value = await Promise.all(
        rows.map(async (row) => ({
          ...row,
          fingerprint:
            row.algorithm === CERTIFICATE
              ? certificateFingerprint(row.publicKey)
              : await invoke<string>("host_key_fingerprint", { publicKey: row.publicKey }).catch(
                  () => t("HostKeysDialog.unreadable"),
                ),
        })),
      );
    }
  } catch (e) {
    error.value = String(e);
  }
}

async function forgetLocal(entry: LocalEntry) {
  try {
    if (entry.algorithm === CERTIFICATE) {
      await invoke("certificates_forget", { host: entry.host, port: entry.port });
    } else {
      await invoke("known_hosts_forget", {
        host: entry.host,
        port: entry.port,
        algorithm: entry.algorithm,
      });
    }
    await load();
  } catch (e) {
    error.value = String(e);
  }
}

async function forgetShared(row: KnownHost) {
  try {
    await forgetHost(props.workspace.id, row.id);
    await load();
  } catch (e) {
    error.value = String(e);
  }
}

onMounted(load);
</script>

<template>
  <EditDialog :title="t('HostKeysDialog.title')" wide :footer="false" @cancel="emit('close')">
    <Alert v-if="error" status="danger" size="sm">{{ error }}</Alert>

    <section v-if="workspace.remote" class="block">
      <h4>{{ t("HostKeysDialog.inWorkspace", { name: workspace.name }) }}</h4>
      <p class="hint">{{ t("HostKeysDialog.workspaceHint") }}</p>
      <EmptyState v-if="shared && !shared.length" size="sm" :title="t('HostKeysDialog.workspaceEmpty')" />
      <ul v-else-if="shared" class="keys">
        <li v-for="row in shared" :key="row.id" class="row">
          <span class="grow">
            <strong>{{ whereEntry(row.host, row.port, row.algorithm) }}</strong>
            <code>{{ label(row.algorithm) }} · {{ row.fingerprint }}</code>
          </span>
          <Button variant="text" size="sm" @click="forgetShared(row)">{{ t("HostKeysDialog.revoke") }}</Button>
        </li>
      </ul>
    </section>

    <section class="block">
      <h4>{{ t("HostKeysDialog.onDevice") }}</h4>
      <i18n-t keypath="HostKeysDialog.deviceHint" tag="p" class="hint">
        <template #knownHosts><code>known_hosts</code></template>
        <template #sshKnownHosts><code>~/.ssh/known_hosts</code></template>
      </i18n-t>
      <EmptyState v-if="local && !local.length" size="sm" :title="t('HostKeysDialog.deviceEmpty')" />
      <ul v-else-if="local" class="keys">
        <li v-for="entry in local" :key="`${entry.host}:${entry.port}:${entry.algorithm}`" class="row">
          <span class="grow">
            <strong>{{ whereEntry(entry.host, entry.port, entry.algorithm) }}</strong>
            <code>{{ label(entry.algorithm) }} · {{ entry.fingerprint }}</code>
          </span>
          <Button variant="text" size="sm" @click="forgetLocal(entry)">{{ t("common.remove") }}</Button>
        </li>
      </ul>
    </section>
  </EditDialog>
</template>

<style scoped>
.block + .block {
  margin-top: 1.5rem;
}

h4 {
  margin: 0 0 0.25rem;
}

.hint {
  margin: 0 0 0.75rem;
  font-size: 0.85rem;
  line-height: 1.5;
  color: var(--muted);
}

.keys {
  list-style: none;
  margin: 0;
  padding: 0;
}

.row {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  padding: 0.4rem 0;
  border-bottom: 1px solid var(--border, transparent);
}

.grow {
  flex: 1;
  min-width: 0;
  display: flex;
  flex-direction: column;
  gap: 0.15rem;
}

code {
  font-family: Consolas, Menlo, monospace;
  font-size: 0.8rem;
  color: var(--muted);
  word-break: break-all;
}
</style>
