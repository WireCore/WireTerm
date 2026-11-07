<script setup lang="ts">
/**
 * A new app password — only where there is one: on Linux without a keyring.
 * The device key stays the same, only its wrapping in `local-key.json`
 * changes; nothing else is re-encrypted.
 */
import { computed, ref } from "vue";
import { useI18n } from "vue-i18n";
import { Alert, Field, PasswordInput } from "@wirecore/wirelayer-vue";
import EditDialog from "./EditDialog.vue";
import { localVaultChangePassword } from "../local-vault";

const emit = defineEmits<{ close: [] }>();
const { t } = useI18n();

const old = ref("");
const next = ref("");
const repeat = ref("");
const busy = ref(false);
const error = ref("");

const valid = computed(
  () => old.value.length > 0 && next.value.length >= 8 && next.value === repeat.value && !busy.value,
);

async function save() {
  if (!valid.value) return;
  busy.value = true;
  error.value = "";
  try {
    await localVaultChangePassword(old.value, next.value);
    emit("close");
  } catch (e) {
    error.value = String(e);
  } finally {
    busy.value = false;
  }
}
</script>

<template>
  <EditDialog :title="t('AppPasswordDialog.title')" :can-save="valid" @save="save" @cancel="emit('close')">
    <Field :label="t('AppPasswordDialog.current')">
      <PasswordInput v-model="old" autocomplete="current-password" data-autofocus />
    </Field>
    <Field :label="t('AppPasswordDialog.new')" :helper-text="t('AppPasswordDialog.minLength')" class="spaced">
      <PasswordInput v-model="next" autocomplete="new-password" />
    </Field>
    <Field
      :label="t('AppPasswordDialog.repeat')"
      :helper-text="repeat && repeat !== next ? t('AppPasswordDialog.mismatch') : undefined"
    >
      <PasswordInput v-model="repeat" autocomplete="new-password" @keydown.enter.prevent="save" />
    </Field>
    <Alert v-if="error" status="danger" size="sm" class="spaced">{{ error }}</Alert>
  </EditDialog>
</template>

<style scoped>
.spaced {
  margin-top: 1rem;
}
</style>
