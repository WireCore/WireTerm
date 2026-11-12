<script setup lang="ts">
import { computed, ref } from "vue";
import { useI18n } from "vue-i18n";
import { getVersion } from "@tauri-apps/api/app";
import { Alert, Button, Descriptions } from "@wirecore/wirelayer-vue";
import EditDialog from "./EditDialog.vue";
import { intlLocale } from "../i18n";
import { availableUpdate, checkForUpdates, checkState } from "../updates";

/**
 * Which WireTerm runs on this device, and whether there is a newer one. The
 * same check as a click on the version at the bottom right — here with the
 * time of the last check, for whoever looks on purpose.
 */
const emit = defineEmits<{ close: [] }>();
const { t } = useI18n();

const version = ref("");
getVersion().then((v) => (version.value = v), () => undefined);

const lastChecked = computed(() =>
  checkState.at
    ? t("Updates.lastChecked", {
        time: checkState.at.toLocaleString(intlLocale.value, {
          dateStyle: "short",
          timeStyle: "short",
        }),
      })
    : t("Updates.neverChecked"),
);

const outcome = computed(() => {
  if (checkState.checking || !checkState.result) return null;
  if (checkState.result === "failed") {
    return { status: "danger" as const, text: t("Updates.failedLong", { error: checkState.error ?? "" }) };
  }
  if (checkState.result === "available") {
    return {
      status: "info" as const,
      text: t("Updates.availableLong", { version: availableUpdate.value?.version ?? "" }),
    };
  }
  return { status: "success" as const, text: t("Updates.currentLong") };
});
</script>

<template>
  <EditDialog :title="t('AboutDialog.title')" @cancel="emit('close')">
    <Descriptions
      orientation="horizontal"
      :columns="1"
      :items="[{ label: t('AboutDialog.version'), value: version ? `WireTerm ${version}` : '—' }]"
    />
    <p class="hint">{{ lastChecked }}</p>
    <Alert v-if="outcome" :status="outcome.status" size="sm">{{ outcome.text }}</Alert>

    <template #actions>
      <Button variant="text" :loading="checkState.checking" @click="checkForUpdates">
        {{ checkState.checking ? t("Updates.checking") : t("Updates.check") }}
      </Button>
      <span class="spacer"></span>
      <Button variant="outline" @click="emit('close')">{{ t("common.close") }}</Button>
    </template>
  </EditDialog>
</template>

<style scoped>
.hint {
  margin: 0.6rem 0 0.75rem;
  font-size: 0.8rem;
  line-height: 1.5;
  color: var(--muted);
}

.spacer {
  flex: 1;
}
</style>
