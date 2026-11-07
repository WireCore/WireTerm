<script setup lang="ts">
/**
 * Brings back an export file.
 *
 * What it contains arrives as **local** workspaces, with new IDs — an import
 * is a copy, even if the workspace once lived on a backend. When saving, the
 * app encrypts the credentials with this device's key.
 */
import { computed, ref } from "vue";
import { useI18n } from "vue-i18n";
import { Alert, Button, Field, Input, PasswordInput } from "@wirecore/wirelayer-vue";
import EditDialog from "./EditDialog.vue";
import { importWorkspaces } from "../local-vault";
import { pickFile } from "../pick-file";
import { persist, workspaces } from "../store";

const emit = defineEmits<{ imported: [firstId: string]; cancel: [] }>();
const { t } = useI18n();

const path = ref("");
const password = ref("");
const busy = ref(false);
const error = ref("");

const valid = computed(() => path.value.trim().length > 0 && password.value.length > 0 && !busy.value);

async function browse() {
  const picked = await pickFile(t("ImportDialog.chooseTitle"), path.value, [
    { name: t("ImportDialog.filterName"), extensions: ["wireterm"] },
  ]);
  if (picked) path.value = picked;
}

/** A name that already exists here gets a suffix — otherwise there would be two identical ones in the bar. */
function freeName(name: string): string {
  const taken = new Set(workspaces.map((w) => w.name));
  if (!taken.has(name)) return name;
  let candidate = `${name} (Import)`;
  for (let n = 2; taken.has(candidate); n++) candidate = `${name} (Import ${n})`;
  return candidate;
}

async function submit() {
  if (!valid.value) return;
  busy.value = true;
  error.value = "";
  try {
    const imported = await importWorkspaces(path.value.trim(), password.value);
    if (!imported.length) {
      error.value = t("ImportDialog.empty");
      return;
    }
    for (const workspace of imported) {
      workspace.name = freeName(workspace.name);
      workspaces.push(workspace);
    }
    persist();
    password.value = "";
    emit("imported", imported[0].id);
  } catch (e) {
    error.value = String(e);
  } finally {
    busy.value = false;
  }
}
</script>

<template>
  <EditDialog
    :title="t('ImportDialog.title')"
    mode="create"
    :can-save="valid"
    @save="submit"
    @cancel="emit('cancel')"
  >
    <p class="lead">{{ t("ImportDialog.lead") }}</p>

    <Field :label="t('ImportDialog.file')">
      <div class="path-row">
        <Input v-model="path" :placeholder="t('ImportDialog.filePlaceholder')" spellcheck="false" />
        <Button variant="outline" @click="browse">{{ t("ImportDialog.browse") }}</Button>
      </div>
    </Field>

    <Field :label="t('ImportDialog.password')" class="spaced">
      <PasswordInput v-model="password" autocomplete="off" @keydown.enter.prevent="submit" />
    </Field>

    <Alert v-if="error" status="danger" size="sm" class="spaced">{{ error }}</Alert>
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

.path-row {
  display: flex;
  gap: 0.5rem;
}

.path-row > :first-child {
  flex: 1;
  min-width: 0;
}
</style>
