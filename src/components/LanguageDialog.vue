<script setup lang="ts">
import { computed, ref } from "vue";
import { useI18n } from "vue-i18n";
import { Field, NativeSelect } from "@wirecore/wirelayer-vue";
import EditDialog from "./EditDialog.vue";
import { LOCALES, LOCALE_NAMES, localeChoice, setLocale, type LocaleChoice } from "../i18n";

/**
 * The UI language of this device. Signed-in backend accounts learn it too, so
 * their mails (password reset, invitations) arrive in the same language.
 */
const emit = defineEmits<{ close: [] }>();
const { t } = useI18n();

const draft = ref<LocaleChoice>(localeChoice.value);

const systemName = LOCALE_NAMES[navigator.language.toLowerCase().startsWith("de") ? "de" : "en"];
const items = computed(() => [
  { value: "system", label: t("common.languageSystem", { language: systemName }) },
  ...LOCALES.map((value) => ({ value, label: LOCALE_NAMES[value] })),
]);

async function save() {
  await setLocale(draft.value);
  emit("close");
}
</script>

<template>
  <EditDialog :title="t('LanguageDialog.title')" :can-delete="false" @save="save" @cancel="emit('close')">
    <Field :label="t('common.language')">
      <NativeSelect v-model="draft" :items="items" data-autofocus />
      <template #helper-text>{{ t("LanguageDialog.hint") }}</template>
    </Field>
  </EditDialog>
</template>
