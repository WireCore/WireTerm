<script setup lang="ts">
/**
 * The MCP server: on, off, port and token.
 *
 * Applies to this device, not to a workspace — an agent on this machine sees
 * every workspace open here. The token lies in `mcp.json`, encrypted with the
 * device key.
 */
import { computed, onMounted, ref } from "vue";
import { useI18n } from "vue-i18n";
import { Alert, Button, Checkbox, Field, NumberInput } from "@wirecore/wirelayer-vue";
import EditDialog from "./EditDialog.vue";
import { configureMcp, mcpStatus, mcpToken, renewMcpToken, type McpStatus } from "../mcp";

const emit = defineEmits<{ close: [] }>();
const { t } = useI18n();

const status = ref<McpStatus | null>(null);
const enabled = ref(false);
const port = ref(47821);
const token = ref("");
const busy = ref(false);
const error = ref("");
const copied = ref("");

onMounted(async () => {
  try {
    status.value = await mcpStatus();
    enabled.value = status.value.enabled;
    port.value = status.value.port;
  } catch (e) {
    error.value = String(e);
  }
});

const url = computed(() => `http://127.0.0.1:${port.value}/mcp`);

/** For Claude Code — one line in the terminal. */
const claudeCommand = computed(
  () =>
    `claude mcp add --transport http wireterm ${url.value} --header "Authorization: Bearer ${token.value || "<TOKEN>"}"`,
);

/** For everything else that reads an `mcpServers` file. */
const jsonConfig = computed(() =>
  JSON.stringify(
    {
      mcpServers: {
        wireterm: {
          type: "http",
          url: url.value,
          headers: { Authorization: `Bearer ${token.value || "<TOKEN>"}` },
        },
      },
    },
    null,
    2,
  ),
);

async function showToken() {
  error.value = "";
  try {
    token.value = await mcpToken();
  } catch (e) {
    error.value = String(e);
  }
}

async function renew() {
  error.value = "";
  try {
    token.value = await renewMcpToken();
  } catch (e) {
    error.value = String(e);
  }
}

async function copy(what: string, value: string) {
  if (!token.value) await showToken();
  try {
    await navigator.clipboard.writeText(
      what === "claude" ? claudeCommand.value : what === "json" ? jsonConfig.value : value,
    );
    copied.value = what;
    setTimeout(() => (copied.value = ""), 2000);
  } catch {
    error.value = t("McpDialog.copyFailed");
  }
}

async function save() {
  busy.value = true;
  error.value = "";
  try {
    status.value = await configureMcp(enabled.value, port.value);
    if (status.value.error) error.value = status.value.error;
    else emit("close");
  } catch (e) {
    error.value = String(e);
  } finally {
    busy.value = false;
  }
}
</script>

<template>
  <EditDialog :title="t('McpDialog.title')" wide :can-save="!busy" @save="save" @cancel="emit('close')">
    <p class="hint">{{ t("McpDialog.intro") }}</p>

    <div class="row">
      <Checkbox v-model:checked="enabled" class="grow">{{ t("McpDialog.enable") }}</Checkbox>
      <Field :label="t('McpDialog.port')" class="port">
        <NumberInput
          v-model="port"
          :min="1024"
          :max="65535"
          :allow-decimal="false"
          :allow-negative="false"
          :format-options="{ useGrouping: false }"
          :stepper="false"
        />
      </Field>
    </div>
    <p v-if="status" class="hint">
      {{ status.running ? t("McpDialog.runningOn", { url: status.url }) : t("McpDialog.notRunning") }}
      {{ t("McpDialog.localOnly") }}
    </p>

    <h4>{{ t("McpDialog.setup") }}</h4>
    <p class="hint">{{ t("McpDialog.claudeCode") }}</p>
    <pre class="snippet">{{ claudeCommand }}</pre>
    <p class="hint">{{ t("McpDialog.otherClients") }}</p>
    <pre class="snippet">{{ jsonConfig }}</pre>

    <div class="actions">
      <Button variant="outline" size="sm" @click="copy('claude', '')">
        {{ copied === "claude" ? t("McpDialog.copied") : t("McpDialog.copyCommand") }}
      </Button>
      <Button variant="outline" size="sm" @click="copy('json', '')">
        {{ copied === "json" ? t("McpDialog.copied") : t("McpDialog.copyJson") }}
      </Button>
      <span class="spacer"></span>
      <Button v-if="!token" variant="text" size="sm" @click="showToken">{{ t("McpDialog.showToken") }}</Button>
      <Button
        variant="text"
        color="danger"
        size="sm"
        :title="t('McpDialog.newTokenTitle')"
        @click="renew"
      >
        {{ t("McpDialog.newToken") }}
      </Button>
    </div>

    <Alert v-if="error" status="danger" size="sm" class="spaced">{{ error }}</Alert>
  </EditDialog>
</template>

<style scoped>
.row {
  display: flex;
  align-items: flex-end;
  gap: 0.75rem;
}

.grow {
  flex: 1;
  min-width: 0;
}

.port {
  width: 6.5rem;
}

h4 {
  margin: 1rem 0 0.4rem;
  font-size: 0.9rem;
}

.snippet {
  margin: 0 0 0.75rem;
  padding: 0.5rem 0.6rem;
  border-radius: 6px;
  background: var(--panel);
  border: 1px solid var(--border);
  font-family: Consolas, Menlo, monospace;
  font-size: 0.78rem;
  white-space: pre-wrap;
  word-break: break-all;
}

.actions {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 0.5rem;
}

.spacer {
  flex: 1;
}

.spaced {
  margin-top: 1rem;
}

.hint {
  color: var(--muted);
  font-size: 0.85rem;
  margin: 0 0 0.75rem;
}
</style>
