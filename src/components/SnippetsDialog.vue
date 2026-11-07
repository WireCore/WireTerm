<script setup lang="ts">
/**
 * A workspace's snippets — stored commands for the terminal.
 *
 * They belong to the workspace and, with a backend, reach all members through
 * the sync. There only whoever manages the workspace may change them: a
 * connection can name a snippet as its startup command, and that then runs
 * unasked in every colleague's terminal.
 */
import { computed, ref } from "vue";
import { useI18n } from "vue-i18n";
import { Alert, Button, Field, Input, Textarea } from "@wirecore/wirelayer-vue";
import EditDialog from "./EditDialog.vue";
import { locale } from "../i18n";
import { persist } from "../store";
import { newId, type Snippet, type Workspace } from "../types";

const props = defineProps<{ workspace: Workspace }>();
const emit = defineEmits<{ close: [] }>();
const { t } = useI18n();

const editable = computed(() => !props.workspace.remote || props.workspace.remote.admin);

/** By folder, within a folder in their order. */
const groups = computed(() => {
  const byFolder = new Map<string, Snippet[]>();
  for (const snippet of props.workspace.snippets ?? []) {
    const list = byFolder.get(snippet.folder) ?? [];
    list.push(snippet);
    byFolder.set(snippet.folder, list);
  }
  return [...byFolder.entries()]
    .sort(([a], [b]) => a.localeCompare(b, locale.value))
    .map(([folder, snippets]) => ({ folder, snippets }));
});

/** What is being edited right now — a copy until it is saved. */
const draft = ref<Snippet | null>(null);
const usedBy = computed(() => {
  const id = draft.value?.id;
  if (!id) return [];
  return props.workspace.projects.flatMap((project) =>
    project.connections.filter((c) => c.settings.type === "ssh" && c.settings.startupSnippet === id),
  );
});

function startNew() {
  draft.value = { id: newId(), name: "", folder: "", command: "" };
}

function edit(snippet: Snippet) {
  draft.value = { ...snippet };
}

const valid = computed(
  () => !!draft.value && draft.value.name.trim() !== "" && draft.value.command.trim() !== "",
);

function save() {
  const value = draft.value;
  if (!value || !valid.value) return;
  const clean: Snippet = {
    ...value,
    name: value.name.trim(),
    folder: value.folder
      .split("/")
      .map((part) => part.trim())
      .filter(Boolean)
      .join("/"),
  };
  const list = (props.workspace.snippets ??= []);
  const at = list.findIndex((s) => s.id === clean.id);
  if (at >= 0) list[at] = clean;
  else list.push(clean);
  draft.value = null;
  persist();
}

function remove(snippet: Snippet) {
  props.workspace.snippets = (props.workspace.snippets ?? []).filter((s) => s.id !== snippet.id);
  // A startup command pointing into nothing would be silently broken.
  for (const project of props.workspace.projects) {
    for (const connection of project.connections) {
      if (connection.settings.type === "ssh" && connection.settings.startupSnippet === snippet.id) {
        connection.settings.startupSnippet = undefined;
      }
    }
  }
  if (draft.value?.id === snippet.id) draft.value = null;
  persist();
}

function firstLine(command: string): string {
  const lines = command.split("\n");
  return lines.length > 1 ? `${lines[0]} …` : lines[0];
}
</script>

<template>
  <EditDialog :title="t('SnippetsDialog.title', { name: workspace.name })" wide :footer="false" @cancel="emit('close')">
    <i18n-t keypath="SnippetsDialog.hint" tag="p" class="hint">
      <template #host><code v-pre>{{connection.host}}</code></template>
      <template #user><code v-pre>{{connection.user}}</code></template>
      <template #port><code v-pre>{{connection.port}}</code></template>
      <template #name><code v-pre>{{connection.name}}</code></template>
    </i18n-t>
    <Alert v-if="!editable" status="info" size="sm">
      {{ t("SnippetsDialog.readOnly") }}
    </Alert>

    <section v-for="group in groups" :key="group.folder" class="group">
      <h4 v-if="group.folder" class="folder">{{ group.folder }}</h4>
      <ul class="rows">
        <li v-for="snippet in group.snippets" :key="snippet.id" class="row">
          <span class="grow">
            <strong>{{ snippet.name }}</strong>
            <code class="command">{{ firstLine(snippet.command) }}</code>
          </span>
          <template v-if="editable">
            <Button variant="text" size="sm" @click="edit(snippet)">{{ t("common.edit") }}</Button>
            <Button variant="text" color="danger" size="sm" @click="remove(snippet)">{{
              t("common.delete")
            }}</Button>
          </template>
        </li>
      </ul>
    </section>
    <p v-if="!groups.length && !draft" class="hint">{{ t("SnippetsDialog.empty") }}</p>

    <form v-if="draft" class="editor" @submit.prevent="save">
      <div class="row-fields">
        <Field :label="t('common.name')" class="grow">
          <Input v-model="draft.name" :placeholder="t('SnippetsDialog.namePlaceholder')" data-autofocus />
        </Field>
        <Field :label="t('SnippetsDialog.folder')" class="grow" :helper-text="t('SnippetsDialog.folderHint')">
          <Input v-model="draft.folder" :placeholder="t('SnippetsDialog.folderPlaceholder')" />
        </Field>
      </div>
      <Field :label="t('SnippetsDialog.command')" :helper-text="t('SnippetsDialog.commandHint')">
        <Textarea v-model="draft.command" class="mono" rows="5" spellcheck="false" />
      </Field>
      <p v-if="usedBy.length" class="hint">
        {{
          t("SnippetsDialog.usedBy", {
            names: usedBy.map((c) => t("SnippetsDialog.quoted", { name: c.name })).join(", "),
          })
        }}
      </p>
      <div class="actions">
        <Button variant="text" size="sm" @click="draft = null">{{ t("SnippetsDialog.discard") }}</Button>
        <Button size="sm" type="submit" :disabled="!valid">{{ t("common.save") }}</Button>
      </div>
    </form>
    <Button v-else-if="editable" variant="outline" size="sm" class="add" @click="startNew">
      {{ t("SnippetsDialog.add") }}
    </Button>
  </EditDialog>
</template>

<style scoped>
.hint {
  margin: 0 0 0.75rem;
  font-size: 0.85rem;
  line-height: 1.4;
  color: var(--muted);
}

code {
  font-family: Consolas, Menlo, monospace;
  font-size: 0.85em;
}

.group {
  margin-top: 0.75rem;
}

.folder {
  margin: 0 0 0.25rem;
  font-size: 0.8rem;
  color: var(--muted);
}

.rows {
  list-style: none;
  margin: 0;
  padding: 0;
}

.row {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.3rem 0.25rem;
  border-bottom: 1px solid var(--border);
}

.grow {
  flex: 1;
  min-width: 0;
  display: flex;
  flex-direction: column;
  gap: 0.1rem;
}

.command {
  color: var(--muted);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.editor {
  margin-top: 1rem;
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
}

.row-fields {
  display: flex;
  gap: 0.75rem;
}

.mono :deep(textarea) {
  font-family: Consolas, Menlo, monospace;
}

.actions {
  display: flex;
  justify-content: flex-end;
  gap: 0.5rem;
}

.add {
  margin-top: 1rem;
}
</style>
