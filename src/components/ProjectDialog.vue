<script setup lang="ts">
import { computed, ref } from "vue";
import { useI18n } from "vue-i18n";
import { Field, Input } from "@wirecore/wirelayer-vue";
import EditDialog from "./EditDialog.vue";
import type { Project } from "../types";

const props = defineProps<{ project: Project; mode: "create" | "edit" }>();

/** Only the name is editable, so that is all that travels back. */
const emit = defineEmits<{
  save: [name: string];
  remove: [];
  cancel: [];
}>();
const { t } = useI18n();

const name = ref(props.project.name);

const valid = computed(() => name.value.trim().length > 0);


function save() {
  if (!valid.value) return;
  emit("save", name.value.trim());
}
</script>

<template>
  <EditDialog
    :title="mode === 'create' ? t('ProjectDialog.titleCreate') : t('ProjectDialog.titleEdit')"
    :mode="mode"
    :can-save="valid"
    :delete-question="
      t(
        'ProjectDialog.deleteQuestion',
        { name: project.name, n: project.connections.length },
        project.connections.length,
      )
    "
    @save="save"
    @remove="emit('remove')"
    @cancel="emit('cancel')"
  >
    <!-- `data-autoselect`: focused and selected on open, not the close button. -->
    <Field :label="t('common.name')">
      <Input v-model="name" data-autoselect />
    </Field>
  </EditDialog>
</template>
