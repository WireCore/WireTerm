<script setup lang="ts">
/**
 * Workspaces including credentials into a file, under a password of its own.
 *
 * The way onto another machine, since `workspaces.json` encrypts its secrets
 * with this device's key — and the backup in case that key gets lost. The
 * whole file is encrypted, hosts and names too.
 */
import { computed, ref } from "vue";
import { useI18n } from "vue-i18n";
import { Alert, Checkbox, Field, PasswordInput } from "@wirecore/wirelayer-vue";
import EditDialog from "./EditDialog.vue";
import { exportWorkspaces } from "../local-vault";
import { pickSaveFile } from "../pick-file";
import { workspaces } from "../store";
import type { Workspace } from "../types";

const props = defineProps<{ initialId: string }>();
const emit = defineEmits<{ close: [] }>();
const { t } = useI18n();

const chosen = ref<Set<string>>(new Set([props.initialId]));
const password = ref("");
const repeat = ref("");
const busy = ref(false);
const error = ref("");
const done = ref("");

function toggle(id: string, on: boolean) {
  const next = new Set(chosen.value);
  if (on) next.add(id);
  else next.delete(id);
  chosen.value = next;
}

/** What cannot come along, because it is not open here right now. */
function missing(workspace: Workspace): boolean {
  return (
    !!workspace.remote?.locked ||
    !!workspace.remote?.secretsMissing ||
    workspace.projects.some((p) => p.connections.some((c) => c.secretUnreadable))
  );
}

const selected = computed(() => workspaces.filter((w) => chosen.value.has(w.id)));

const valid = computed(
  () =>
    selected.value.length > 0 &&
    password.value.length >= 8 &&
    password.value === repeat.value &&
    !busy.value,
);

async function save() {
  if (!valid.value) return;
  const name = selected.value.length === 1 ? selected.value[0].name : "Workspaces";
  const path = await pickSaveFile(t("ExportDialog.saveTitle"), `${name}.wireterm`, [
    { name: t("ExportDialog.filterName"), extensions: ["wireterm"] },
  ]);
  if (!path) return;
  busy.value = true;
  error.value = "";
  try {
    await exportWorkspaces(path, password.value, selected.value);
    password.value = "";
    repeat.value = "";
    done.value = path;
  } catch (e) {
    error.value = String(e);
  } finally {
    busy.value = false;
  }
}
</script>

<template>
  <EditDialog
    :title="t('ExportDialog.title')"
    mode="create"
    wide
    :can-save="valid"
    @save="done ? emit('close') : save()"
    @cancel="emit('close')"
  >
    <template v-if="done">
      <Alert status="success" size="sm">{{ t("ExportDialog.saved", { path: done }) }}</Alert>
      <p class="lead spaced">{{ t("ExportDialog.importHint") }}</p>
    </template>

    <template v-else>
      <p class="lead">{{ t("ExportDialog.lead") }}</p>

      <ul class="list">
        <li v-for="workspace in workspaces" :key="workspace.id">
          <label class="row">
            <Checkbox
              :checked="chosen.has(workspace.id)"
              @update:checked="(on: boolean) => toggle(workspace.id, on)"
            />
            <span class="grow">
              {{ workspace.name }}
              <span v-if="workspace.remote" class="muted">· {{ workspace.remote.server }}</span>
              <span v-if="missing(workspace)" class="note">
                {{ t("ExportDialog.missing") }}
              </span>
            </span>
          </label>
        </li>
      </ul>

      <Field
        :label="t('ExportDialog.password')"
        :helper-text="t('ExportDialog.passwordHint')"
        class="spaced"
      >
        <PasswordInput v-model="password" autocomplete="new-password" />
      </Field>
      <Field
        :label="t('ExportDialog.repeat')"
        :helper-text="repeat && repeat !== password ? t('ExportDialog.mismatch') : undefined"
      >
        <PasswordInput v-model="repeat" autocomplete="new-password" />
      </Field>

      <Alert v-if="error" status="danger" size="sm" class="spaced">{{ error }}</Alert>
    </template>
  </EditDialog>
</template>

<style scoped>
.lead {
  margin: 0 0 1rem;
  font-size: 0.9rem;
  line-height: 1.5;
  color: var(--muted);
}

.spaced {
  margin-top: 1rem;
}

.list {
  list-style: none;
  margin: 0;
  padding: 0;
}

.row {
  display: flex;
  align-items: flex-start;
  gap: 0.6rem;
  padding: 0.35rem 0.25rem;
  cursor: pointer;
}

.grow {
  flex: 1;
  display: flex;
  flex-direction: column;
  gap: 0.1rem;
}

.muted {
  color: var(--muted);
  font-size: 0.85rem;
}

.note {
  font-size: 0.8rem;
  font-style: italic;
  color: var(--muted);
}
</style>
