<script setup lang="ts">
/**
 * Edits an existing connection, with side tabs per section. Creating one goes
 * through [ConnectionWizard]: there the steps lead the way, here you want to
 * get straight to a field.
 */
import { computed, ref } from "vue";
import { useI18n } from "vue-i18n";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@wirecore/wirelayer-vue";
import EditDialog from "./EditDialog.vue";
import ConnectionForm from "./ConnectionForm.vue";
import ConnectionTest from "./ConnectionTest.vue";
import type { Connection } from "../types";

const props = defineProps<{ connection: Connection; workspaceId?: string }>();

const emit = defineEmits<{
  save: [connection: Connection];
  remove: [];
  cancel: [];
}>();
const { t } = useI18n();

/** Labels under `ConnectionDialog.sections.<value>`. */
const SECTIONS = [
  { value: "general" },
  { value: "server" },
  { value: "login" },
  { value: "options" },
] as const;

/**
 * Edited on a copy, so nothing reaches the workspace tree until "Save"
 * and "Cancel" really does leave the connection as it was. The round trip
 * through JSON also strips Vue's proxies, which is what the store wants to
 * write anyway.
 */
const draft = ref<Connection>(JSON.parse(JSON.stringify(props.connection)));

const tab = ref("general");

const valid = computed(() => draft.value.name.trim().length > 0);

function save() {
  if (!valid.value) {
    tab.value = "general";
    return;
  }
  draft.value.name = draft.value.name.trim();
  emit("save", draft.value);
}
</script>

<template>
  <EditDialog
    width="48rem"
    :title="t('ConnectionDialog.title')"
    mode="edit"
    :can-save="valid"
    :delete-question="t('ConnectionDialog.deleteQuestion', { name: connection.name })"
    @save="save"
    @remove="emit('remove')"
    @cancel="emit('cancel')"
  >
    <Tabs v-model="tab" orientation="vertical" :label="t('ConnectionDialog.sectionsLabel')">
      <TabsList>
        <TabsTrigger v-for="s in SECTIONS" :key="s.value" :value="s.value">
          {{ t(`ConnectionDialog.sections.${s.value}`) }}
        </TabsTrigger>
      </TabsList>
      <TabsContent v-for="s in SECTIONS" :key="s.value" :value="s.value" class="panel">
        <ConnectionForm :connection="draft" :section="s.value" :workspace-id="workspaceId" />
      </TabsContent>
    </Tabs>

    <ConnectionTest class="test" :connection="draft" />
  </EditDialog>
</template>

<style scoped>
/* Fills the space beside the tab list; the height of the longest section
   (Login) keeps the dialog from jumping between tabs. */
.panel {
  flex: 1;
  min-width: 0;
  min-height: 26rem;
}

.test {
  margin-top: 0.75rem;
  padding-top: 0.75rem;
  border-top: 1px dashed var(--border);
}
</style>
