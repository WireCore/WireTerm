<script setup lang="ts">
import { useI18n } from "vue-i18n";
import { Button, Field, Input, Slider } from "@wirecore/wirelayer-vue";
import EditDialog from "./EditDialog.vue";
import { pickFile } from "../pick-file";
import { MAX_PARALLEL_LIMIT, resetTransferSettings, transferSettings } from "../transfer-settings";

/**
 * Edits the live settings object rather than a copy, the same as the terminal
 * settings: a queue running behind the dialog picks the new number up as it is
 * moved. There is nothing to confirm, so the footer offers "Reset" and
 * "Done".
 */
const emit = defineEmits<{ close: [] }>();
const { t } = useI18n();

async function browseEditor() {
  const path = await pickFile(t("TransferSettingsDialog.chooseEditor"), transferSettings.editorPath);
  if (path) transferSettings.editorPath = path;
}
</script>

<template>
  <EditDialog :title="t('TransferSettingsDialog.title')" @save="emit('close')" @cancel="emit('close')">
    <section class="block">
      <h4>{{ t("TransferSettingsDialog.transfers") }}</h4>

      <Slider
        class="field"
        :label="t('TransferSettingsDialog.parallel')"
        show-value
        :model-value="[transferSettings.maxParallel]"
        :min="1"
        :max="MAX_PARALLEL_LIMIT"
        :step="1"
        @update:model-value="transferSettings.maxParallel = $event[0]"
      />

      <p class="hint">{{ t("TransferSettingsDialog.parallelHint") }}</p>
    </section>

    <section class="block">
      <h4>{{ t("TransferSettingsDialog.remoteEditing") }}</h4>

      <Field class="field" :label="t('TransferSettingsDialog.editor')">
        <div class="path-row">
          <Input
            v-model="transferSettings.editorPath"
            type="text"
            spellcheck="false"
            :placeholder="t('TransferSettingsDialog.editorPlaceholder')"
          />
          <Button variant="outline" @click="browseEditor">{{
            t("TransferSettingsDialog.browse")
          }}</Button>
        </div>
      </Field>

      <Field class="field" :label="t('TransferSettingsDialog.arguments')" :disabled="!transferSettings.editorPath.trim()">
        <Input
          v-model="transferSettings.editorArgs"
          type="text"
          spellcheck="false"
          placeholder="-multiInst -nosession"
        />
      </Field>

      <p class="hint">{{ t("TransferSettingsDialog.editorHint") }}</p>
      <i18n-t keypath="TransferSettingsDialog.argumentsHint" tag="p" class="hint">
        <template #notepad>
          <span class="mono">-multiInst -nosession</span>
        </template>
        <template #vscode>
          <span class="mono">--wait</span>
        </template>
        <template #file>
          <span class="mono">%f</span>
        </template>
      </i18n-t>
    </section>

    <template #actions>
      <Button variant="outline" @click="resetTransferSettings">{{ t("common.reset") }}</Button>
      <span class="spacer"></span>
      <Button @click="emit('close')">{{ t("common.done") }}</Button>
    </template>
  </EditDialog>
</template>

<style scoped>
.path-row {
  display: flex;
  gap: 0.5rem;
}

.path-row > :first-child {
  flex: 1;
  min-width: 0;
}

.block h4 {
  margin: 0 0 0.2rem;
  font-size: 0.85rem;
}

.field {
  margin: 0.5rem 0;
}

.block + .block {
  margin-top: 1rem;
  padding-top: 0.9rem;
  border-top: 1px solid var(--border);
}

.hint + .hint {
  margin-top: 0.45rem;
}

.mono {
  font-family: ui-monospace, "Cascadia Mono", Consolas, monospace;
  color: var(--fg);
}

.hint {
  margin: 0;
  font-size: 0.8rem;
  line-height: 1.45;
  color: var(--muted);
}

.spacer {
  flex: 1;
}
</style>
