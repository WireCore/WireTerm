<script setup lang="ts">
/**
 * The snippet menu above the terminal: search, click, sent.
 *
 * With broadcast on, the snippet goes to all terminals of the split view, with
 * the placeholders of each one's connection. "only here" then explicitly takes
 * it for this one only.
 */
import { computed, nextTick, onMounted, ref } from "vue";
import { useI18n } from "vue-i18n";
import { Button, Input } from "@wirecore/wirelayer-vue";
import { locale } from "../i18n";
import type { Snippet } from "../types";

const props = defineProps<{ snippets: Snippet[]; broadcast: boolean }>();
const emit = defineEmits<{ run: [snippet: Snippet, only: boolean]; close: [] }>();
const { t } = useI18n();

const query = ref("");
const queryInput = ref<InstanceType<typeof Input>>();

onMounted(async () => {
  await nextTick();
  queryInput.value?.focus();
});

const groups = computed(() => {
  const needle = query.value.trim().toLowerCase();
  const byFolder = new Map<string, Snippet[]>();
  for (const snippet of props.snippets) {
    const haystack = `${snippet.folder} ${snippet.name} ${snippet.command}`.toLowerCase();
    if (needle && !haystack.includes(needle)) continue;
    const list = byFolder.get(snippet.folder) ?? [];
    list.push(snippet);
    byFolder.set(snippet.folder, list);
  }
  return [...byFolder.entries()]
    .sort(([a], [b]) => a.localeCompare(b, locale.value))
    .map(([folder, snippets]) => ({ folder, snippets }));
});

function run(snippet: Snippet, only = false) {
  emit("run", snippet, only);
  emit("close");
}

function first() {
  const snippet = groups.value[0]?.snippets[0];
  if (snippet) run(snippet);
}
</script>

<template>
  <!-- Click-away layer, so the menu closes without a global listener. -->
  <div class="away" @click="emit('close')"></div>
  <div class="menu" @keydown.esc="emit('close')">
    <Input
      ref="queryInput"
      v-model="query"
      size="sm"
      type="text"
      :placeholder="t('SnippetMenu.search')"
      :aria-label="t('SnippetMenu.searchLabel')"
      @keydown.enter.prevent="first"
    />
    <p v-if="broadcast" class="note">{{ t("SnippetMenu.broadcast") }}</p>
    <p v-if="!snippets.length" class="empty">{{ t("SnippetMenu.empty") }}</p>
    <p v-else-if="!groups.length" class="empty">{{ t("SnippetMenu.noMatches") }}</p>
    <section v-for="group in groups" :key="group.folder">
      <p v-if="group.folder" class="folder">{{ group.folder }}</p>
      <div v-for="snippet in group.snippets" :key="snippet.id" class="entry">
        <button type="button" class="pick" :title="snippet.command" @click="run(snippet)">
          {{ snippet.name }}
        </button>
        <Button v-if="broadcast" variant="text" size="sm" @click="run(snippet, true)">{{ t("SnippetMenu.onlyHere") }}</Button>
      </div>
    </section>
  </div>
</template>

<style scoped>
.away {
  position: fixed;
  inset: 0;
  z-index: 19;
}

.menu {
  position: absolute;
  top: 2rem;
  right: 0;
  z-index: 20;
  width: 18rem;
  max-height: 60vh;
  overflow-y: auto;
  padding: 0.5rem;
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 6px;
  box-shadow: 0 6px 24px rgb(0 0 0 / 0.35);
}

.folder {
  margin: 0.5rem 0 0.15rem;
  font-size: 0.75rem;
  color: var(--muted);
}

.entry {
  display: flex;
  align-items: center;
}

.pick {
  flex: 1;
  min-width: 0;
  text-align: left;
  padding: 0.3rem 0.4rem;
  border: 0;
  border-radius: 4px;
  background: none;
  color: var(--fg);
  font: inherit;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.pick:hover,
.pick:focus-visible {
  background: var(--accent-dim);
}

.note,
.empty {
  margin: 0.5rem 0 0;
  font-size: 0.8rem;
  color: var(--muted);
}
</style>
