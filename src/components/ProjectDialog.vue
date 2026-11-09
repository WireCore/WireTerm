<script setup lang="ts">
/**
 * A project's settings. Creating one only asks for the name; editing one has
 * side tabs, and whoever opens it adds the further ones (shares, import) as
 * edit dialogs of their own through the slot of the same name.
 */
import { computed, ref } from "vue";
import { useI18n } from "vue-i18n";
import { Field, Input, Tabs, TabsContent, TabsList, TabsTrigger } from "@wirecore/wirelayer-vue";
import EditDialog from "./EditDialog.vue";
import EmbeddedPanel from "./EmbeddedPanel.vue";
import type { Project } from "../types";

type ExtraTab = { value: string; label: string };

const props = withDefaults(
  defineProps<{
    project: Project;
    mode: "create" | "edit";
    extras?: ExtraTab[];
    /** Name and delete — only for whoever manages the projects. */
    general?: boolean;
  }>(),
  { general: true, extras: () => [] },
);

/** Only the name is editable, so that is all that travels back. */
const emit = defineEmits<{
  save: [name: string];
  remove: [];
  cancel: [];
}>();
const { t } = useI18n();

const name = ref(props.project.name);

const valid = computed(() => name.value.trim().length > 0);

const tabbed = computed(() => props.extras.length > 0);
const tab = ref(props.general ? "general" : (props.extras[0]?.value ?? "general"));

function save() {
  if (!valid.value) return;
  emit("save", name.value.trim());
}
</script>

<template>
  <EditDialog
    :title="mode === 'create' ? t('ProjectDialog.titleCreate') : t('ProjectDialog.titleEdit')"
    :mode="mode"
    :width="tabbed ? '48rem' : undefined"
    :can-save="valid"
    :footer="!tabbed || tab === 'general'"
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
    <Tabs v-if="tabbed" v-model="tab" orientation="vertical" :label="t('ProjectDialog.tabsLabel')">
      <TabsList>
        <TabsTrigger v-if="general" value="general">{{ t("ProjectDialog.general") }}</TabsTrigger>
        <TabsTrigger v-for="extra in extras" :key="extra.value" :value="extra.value">
          {{ extra.label }}
        </TabsTrigger>
      </TabsList>

      <TabsContent v-if="general" value="general" class="panel">
        <Field :label="t('common.name')">
          <Input v-model="name" data-autoselect />
        </Field>
      </TabsContent>

      <!-- Mounted only while in front: the shares load from the server. -->
      <TabsContent v-for="extra in extras" :key="extra.value" :value="extra.value" class="panel">
        <EmbeddedPanel v-if="tab === extra.value">
          <slot :name="extra.value" />
        </EmbeddedPanel>
      </TabsContent>
    </Tabs>

    <!-- `data-autoselect`: focused and selected on open, not the close button. -->
    <Field v-else :label="t('common.name')">
      <Input v-model="name" data-autoselect />
    </Field>
  </EditDialog>
</template>

<style scoped>
/* Beside the tab list, at a height that keeps the dialog from jumping. */
.panel {
  flex: 1;
  min-width: 0;
  min-height: 22rem;
  display: flex;
  flex-direction: column;
  gap: 1rem;
}
</style>
