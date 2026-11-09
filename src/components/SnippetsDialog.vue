<script setup lang="ts">
/**
 * A project's snippets — stored commands for the terminal.
 *
 * Each is offered for all connections of the project or, if it says so, for
 * just one. With a backend they reach everyone who sees the project.
 *
 * "Locked" decides who changes one: locked only owner and admin, otherwise
 * whoever may edit the project. Only a locked snippet can be a startup
 * command — that runs unasked in every colleague's terminal. The backend
 * checks all of that; the dialog only offers what will go through.
 */
import { computed, ref } from "vue";
import { useI18n } from "vue-i18n";
import { Lock } from "@lucide/vue";
import { Alert, Badge, Button, Checkbox, Field, Input, NativeSelect, Textarea } from "@wirecore/wirelayer-vue";
import EditDialog from "./EditDialog.vue";
import { locale } from "../i18n";
import { persist } from "../store";
import { newId, type Connection, type Project, type Snippet, type Workspace } from "../types";

const props = defineProps<{ workspace: Workspace; project: Project }>();
const emit = defineEmits<{ close: [] }>();
const { t } = useI18n();

/** On this device there is nobody with fewer rights — and nothing to lock. */
const local = computed(() => !props.workspace.remote);
const admin = computed(() => local.value || !!props.workspace.remote?.admin);

/** Locked ones only owner and admin; open ones whoever may edit the project. */
function changeable(snippet: Snippet): boolean {
  return admin.value || !snippet.locked;
}

const mine = computed(() => (props.workspace.snippets ?? []).filter((s) => s.projectId === props.project.id));

/** By folder, within a folder in their order. */
const groups = computed(() => {
  const byFolder = new Map<string, Snippet[]>();
  for (const snippet of mine.value) {
    const list = byFolder.get(snippet.folder) ?? [];
    list.push(snippet);
    byFolder.set(snippet.folder, list);
  }
  return [...byFolder.entries()]
    .sort(([a], [b]) => a.localeCompare(b, locale.value))
    .map(([folder, snippets]) => ({ folder, snippets }));
});

function connectionName(id: string | undefined): string {
  return props.project.connections.find((c) => c.id === id)?.name ?? "";
}

const targets = computed(() => [
  { value: "", label: t("SnippetsDialog.forAll") },
  ...props.project.connections.map((c) => ({ value: c.id, label: c.name })),
]);

/** What is being edited right now — a copy until it is saved. */
const draft = ref<Snippet | null>(null);
const usedBy = computed(() => (draft.value ? startupOf(draft.value.id) : []));

/** The connections that send this snippet as their startup command. */
function startupOf(id: string): Connection[] {
  return props.project.connections.filter(
    (c) => c.settings.type === "ssh" && c.settings.startupSnippet === id,
  );
}

function quoted(connections: Connection[]): string {
  return connections.map((c) => t("SnippetsDialog.quoted", { name: c.name })).join(", ");
}

const target = computed({
  get: () => draft.value?.connectionId ?? "",
  set: (id: string) => {
    if (draft.value) draft.value.connectionId = id || undefined;
  },
});

/**
 * What would leave a startup command behind that the backend no longer
 * accepts: unlocked, or bound to another connection than the ones sending it.
 */
const problem = computed(() => {
  const value = draft.value;
  if (!value || !usedBy.value.length) return "";
  if (!value.locked) return t("SnippetsDialog.staysLocked", { names: quoted(usedBy.value) });
  const strangers = usedBy.value.filter((c) => value.connectionId && c.id !== value.connectionId);
  if (strangers.length) return t("SnippetsDialog.staysForThem", { names: quoted(strangers) });
  return "";
});

/** The snippet whose "Delete" waits for the second click. */
const confirming = ref<string | null>(null);

function deleteQuestion(snippet: Snippet): string {
  const users = startupOf(snippet.id);
  const question = t("SnippetsDialog.deleteQuestion", { name: snippet.name });
  if (!users.length) return question;
  return `${question} ${t("SnippetsDialog.deleteUsedBy", { names: quoted(users) })}`;
}

function startNew() {
  draft.value = {
    id: newId(),
    projectId: props.project.id,
    // What an editor creates stays open to the other editors.
    locked: admin.value,
    name: "",
    folder: "",
    command: "",
  };
}

function edit(snippet: Snippet) {
  draft.value = { ...snippet };
}

const valid = computed(
  () =>
    !!draft.value && draft.value.name.trim() !== "" && draft.value.command.trim() !== "" && !problem.value,
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
  confirming.value = null;
  props.workspace.snippets = (props.workspace.snippets ?? []).filter((s) => s.id !== snippet.id);
  // A startup command pointing into nothing would be silently broken.
  for (const connection of startupOf(snippet.id)) {
    if (connection.settings.type === "ssh") connection.settings.startupSnippet = undefined;
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
  <EditDialog :title="t('SnippetsDialog.title', { name: project.name })" wide :footer="false" @cancel="emit('close')">
    <i18n-t keypath="SnippetsDialog.hint" tag="p" class="hint">
      <template #host><code v-pre>{{connection.host}}</code></template>
      <template #user><code v-pre>{{connection.user}}</code></template>
      <template #port><code v-pre>{{connection.port}}</code></template>
      <template #name><code v-pre>{{connection.name}}</code></template>
    </i18n-t>
    <Alert v-if="!admin" status="info" size="sm">
      {{ t("SnippetsDialog.lockedHint") }}
    </Alert>

    <section v-for="group in groups" :key="group.folder" class="group">
      <h4 v-if="group.folder" class="folder">{{ group.folder }}</h4>
      <ul class="rows">
        <li v-for="snippet in group.snippets" :key="snippet.id" class="row">
          <template v-if="confirming === snippet.id">
            <span class="grow warn">{{ deleteQuestion(snippet) }}</span>
            <Button variant="outline" size="sm" @click="confirming = null">{{ t("common.cancel") }}</Button>
            <Button variant="danger" size="sm" @click="remove(snippet)">{{ t("common.delete") }}</Button>
          </template>
          <template v-else>
            <span class="grow">
              <span class="name">
                <strong>{{ snippet.name }}</strong>
                <Lock
                  v-if="!local && snippet.locked"
                  class="lock"
                  :size="13"
                  :aria-label="t('SnippetsDialog.locked')"
                  :title="t('SnippetsDialog.locked')"
                />
                <Badge v-if="snippet.connectionId" variant="outline" size="sm">
                  {{ t("SnippetsDialog.onlyFor", { name: connectionName(snippet.connectionId) }) }}
                </Badge>
              </span>
              <code class="command">{{ firstLine(snippet.command) }}</code>
            </span>
            <template v-if="changeable(snippet)">
              <Button variant="text" size="sm" @click="edit(snippet)">{{ t("common.edit") }}</Button>
              <Button variant="text" color="danger" size="sm" @click="confirming = snippet.id">{{
                t("common.delete")
              }}</Button>
            </template>
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
      <Field :label="t('SnippetsDialog.target')" :helper-text="t('SnippetsDialog.targetHint')">
        <NativeSelect v-model="target" :items="targets" />
      </Field>
      <Field :label="t('SnippetsDialog.command')" :helper-text="t('SnippetsDialog.commandHint')">
        <Textarea v-model="draft.command" class="mono" rows="5" spellcheck="false" />
      </Field>
      <template v-if="!local && admin">
        <Checkbox v-model:checked="draft.locked">{{ t("SnippetsDialog.lock") }}</Checkbox>
        <p class="hint tight">{{ t("SnippetsDialog.lockHint") }}</p>
      </template>
      <p v-if="usedBy.length && !problem" class="hint tight">
        {{ t("SnippetsDialog.usedBy", { names: quoted(usedBy) }) }}
      </p>
      <p v-if="problem" class="warn">{{ problem }}</p>
      <div class="actions">
        <Button variant="text" size="sm" @click="draft = null">{{ t("SnippetsDialog.discard") }}</Button>
        <Button size="sm" type="submit" :disabled="!valid">{{ t("common.save") }}</Button>
      </div>
    </form>
    <Button v-else variant="outline" size="sm" class="add" @click="startNew">
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

.hint.tight {
  margin: 0;
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

.name {
  display: flex;
  align-items: center;
  gap: 0.4rem;
}

.lock {
  color: var(--muted);
  flex-shrink: 0;
}

.warn {
  margin: 0;
  font-size: 0.85rem;
  color: var(--warn);
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
