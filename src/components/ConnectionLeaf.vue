<script setup lang="ts">
import { useI18n } from "vue-i18n";
import OsIcon from "./OsIcon.vue";
import { IconButton } from "@wirecore/wirelayer-vue";
import { Pin } from "@lucide/vue";
import type { Connection } from "../types";

/**
 * One row in the tab menu — under the bookmarks and under each project.
 *
 * Opening and bookmarking only: editing belongs to the overview, where there
 * is room for a dialog.
 */
defineProps<{ connection: Connection }>();

const emit = defineEmits<{
  pick: [];
  bookmark: [];
}>();
const { t } = useI18n();
</script>

<template>
  <!--
    The row itself opens the connection. Not a <button>: the pin and the gear
    sit inside it, and a button inside a button is not valid HTML.
  -->
  <div
    class="leaf"
    role="button"
    tabindex="0"
    :title="t('ConnectionLeaf.open', { name: connection.name })"
    @click="emit('pick')"
    @keydown.enter.self.prevent="emit('pick')"
    @keydown.space.self.prevent="emit('pick')"
  >
    <span class="leaf-name">{{ connection.name }}</span>

    <span class="leaf-target">
      <span class="leaf-host">{{ connection.settings.host || "–" }}</span>
      <OsIcon v-if="connection.system" :id="connection.system.id" :size="12" />
    </span>

    <IconButton
      class="leaf-action pin"
      :class="{ on: connection.bookmarked }"
      :icon="Pin"
      :icon-props="{ fill: connection.bookmarked ? 'currentColor' : 'none' }"
      variant="text"
      size="xs"
      :title="connection.bookmarked ? t('ConnectionLeaf.unbookmark') : t('ConnectionLeaf.bookmark')"
      :label="connection.bookmarked ? t('ConnectionLeaf.unbookmark') : t('ConnectionLeaf.bookmark')"
      @click.stop="emit('bookmark')"
    />
  </div>
</template>

<style scoped>
.leaf {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.35em 0.5em;
  border-radius: 6px;
  cursor: pointer;
}

.leaf:hover,
.leaf:focus-visible {
  background: var(--color-line);
  outline: none;
}

.leaf-name {
  flex: 1;
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.leaf-target {
  display: flex;
  align-items: center;
  gap: 0.35rem;
  flex: 0 1 auto;
  min-width: 0;
}

.leaf-host {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  font-size: 0.75rem;
  color: var(--color-muted);
}

.leaf-action {
  flex: 0 0 auto;
  opacity: 0;
  transition: opacity 120ms ease;
}

/* `:has(:focus-visible)`, not `:focus-within`: clicking the pin leaves it
   focused, and the row would keep showing it after the pointer moved on. */
.leaf:hover .leaf-action,
.leaf:focus-visible .leaf-action,
.leaf:has(:focus-visible) .leaf-action {
  opacity: 1;
}

/* A set bookmark stays visible: it is the state, not just a control. */
.leaf-action.pin.on {
  opacity: 1;
  color: var(--color-primary);
}

@media (prefers-reduced-motion: reduce) {
  .leaf-action {
    transition: none;
  }
}
</style>
