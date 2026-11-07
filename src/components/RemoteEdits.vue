<script setup lang="ts">
import { IconButton, StatusDot, type StatusDotStatus } from "@wirecore/wirelayer-vue";
import { X } from "@lucide/vue";
import { useI18n } from "vue-i18n";
import type { RemoteEdit } from "../types";

/**
 * Files currently open for editing on the server pane.
 *
 * Only shown once one exists — this is not a permanent fixture of the
 * browser, and most sessions will never need it.
 */
defineProps<{ edits: RemoteEdit[] }>();

const emit = defineEmits<{ close: [id: string] }>();
const { t } = useI18n();

/** Message keys under `RemoteEdits.state`. */
const LABELS: Record<RemoteEdit["state"], string> = {
  uploading: "uploading",
  synced: "synced",
  error: "error",
  // Never drawn: the row goes the moment this arrives. Here so the record is
  // complete and a missing case cannot slip past the compiler.
  closed: "closed",
  detached: "detached",
};

/**
 * "detached" is not a failure — every save still goes across — so it gets the
 * colour of "saved" and the "?" mark instead. The tooltip explains it.
 */
const DOT: Record<RemoteEdit["state"], StatusDotStatus> = {
  uploading: "info",
  synced: "success",
  error: "danger",
  closed: "neutral",
  detached: "success",
};
</script>

<template>
  <div v-if="edits.length" class="bar">
    <span class="label label-mono">{{ t("RemoteEdits.editing") }}</span>
    <StatusDot
      v-for="edit in edits"
      :key="edit.id"
      class="chip"
      :class="edit.state"
      :status="DOT[edit.state]"
      :pulse="edit.state === 'uploading'"
      :title="edit.message"
    >
      <span class="name">{{ edit.name }}</span>
      <span class="state">{{ t(`RemoteEdits.state.${LABELS[edit.state]}`) }}</span>
      <!-- "detached" marks the edit whose editor cannot be waited for, so
           this button is the only way it will ever end. -->
      <span v-if="edit.state === 'detached'" class="mark" aria-hidden="true">?</span>
      <IconButton
        :icon="X"
        :label="t('RemoteEdits.stopWatching')"
        :title="t('RemoteEdits.stopWatching')"
        variant="text"
        size="xs"
        @click="emit('close', edit.id)"
      />
    </StatusDot>
  </div>
</template>

<style scoped>
.bar {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 0.4rem;
  padding: 0.35rem 0.1rem;
}

/* Font and colour from `label-mono`, WireLayer's label style. */
.label {
  flex: 0 0 auto;
}

/* Border, dot and pulse come from StatusDot; only a little taller, so the
   close button fits inside. */
.chip {
  height: 1.75rem;
  gap: 0.4rem;
  padding: 0 0.15rem 0 0.6rem;
}

.mark {
  display: grid;
  place-items: center;
  width: 0.95rem;
  height: 0.95rem;
  border-radius: 50%;
  border: 1px solid var(--color-line-2);
  font-size: 0.65rem;
  color: var(--color-muted);
  cursor: help;
}

.name {
  max-width: 12rem;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.state {
  color: var(--color-muted);
}

.chip.error .state {
  color: var(--color-danger);
}
</style>
