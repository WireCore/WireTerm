<script setup lang="ts">
/**
 * The question before every MCP call that changes something.
 *
 * Enter does not answer it: the dialog can open while someone is typing in a
 * terminal, and an Enter meant for the shell must not allow anything here.
 * That is also why "Run" only becomes clickable after a moment, and why the
 * first button — the one that gets focus — declines.
 */
import { onBeforeUnmount, onMounted, ref } from "vue";
import { useI18n } from "vue-i18n";
import { Button } from "@wirecore/wirelayer-vue";
import EditDialog from "./EditDialog.vue";
import type { Confirmation } from "../mcp";

const props = defineProps<{ request: Confirmation }>();
const emit = defineEmits<{ answer: [allowed: boolean] }>();
const { t } = useI18n();

const armed = ref(false);
let timer: ReturnType<typeof setTimeout> | undefined;

onMounted(() => {
  timer = setTimeout(() => (armed.value = true), 800);
});
onBeforeUnmount(() => clearTimeout(timer));
</script>

<template>
  <EditDialog
    :title="
      props.request.client
        ? t('McpConfirmDialog.requestFrom', { client: props.request.client })
        : t('McpConfirmDialog.requestFromAgent')
    "
    wide
    :can-save="false"
    @cancel="emit('answer', false)"
  >
    <p class="what">
      <strong>{{ request.action }}</strong>
      <span class="where">{{ request.target }}</span>
    </p>
    <pre class="detail">{{ request.detail }}</pre>
    <p class="hint">{{ t("McpConfirmDialog.hint") }}</p>

    <template #actions>
      <Button variant="outline" @click="emit('answer', false)">{{ t("McpConfirmDialog.decline") }}</Button>
      <span class="spacer"></span>
      <Button variant="danger" :disabled="!armed" @click="emit('answer', true)">{{ t("McpConfirmDialog.run") }}</Button>
    </template>
  </EditDialog>
</template>

<style scoped>
.what {
  display: flex;
  flex-direction: column;
  gap: 0.2rem;
  margin: 0 0 0.75rem;
}

.where {
  color: var(--muted);
  font-size: 0.85rem;
}

.detail {
  margin: 0 0 0.75rem;
  padding: 0.6rem;
  max-height: 16rem;
  overflow: auto;
  border-radius: 6px;
  background: var(--panel);
  border: 1px solid var(--border);
  font-family: Consolas, Menlo, monospace;
  font-size: 0.85rem;
  white-space: pre-wrap;
  word-break: break-all;
}

.hint {
  color: var(--muted);
  font-size: 0.8rem;
  margin: 0;
}

.spacer {
  flex: 1;
}
</style>
