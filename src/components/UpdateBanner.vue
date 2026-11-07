<script setup lang="ts">
import { computed } from "vue";
import { useI18n } from "vue-i18n";
import { Banner, Button } from "@wirecore/wirelayer-vue";
import {
  availableUpdate,
  dismissUpdate,
  installUpdate,
  updateState,
} from "../updates";

/** A newer WireTerm on GitHub: say so, and install it when asked. */
const { t } = useI18n();

const open = computed(() => availableUpdate.value !== null && !updateState.dismissed);

const message = computed(() => {
  if (updateState.error) return t("UpdateBanner.failed", { error: updateState.error });
  if (!updateState.installing) return t("UpdateBanner.hint");
  if (updateState.progress === null) return t("UpdateBanner.downloading");
  if (updateState.progress >= 100) return t("UpdateBanner.installing");
  return t("UpdateBanner.downloadingPercent", { percent: updateState.progress });
});
</script>

<template>
  <Banner
    v-if="open"
    :variant="updateState.error ? 'danger' : 'info'"
    :title="t('UpdateBanner.title', { version: availableUpdate?.version ?? '' })"
    :dismissible="!updateState.installing"
    :dismiss-label="t('UpdateBanner.later')"
    @dismiss="dismissUpdate"
  >
    {{ message }}
    <template #actions>
      <Button size="sm" :disabled="updateState.installing" @click="installUpdate">
        {{ t("UpdateBanner.install") }}
      </Button>
    </template>
  </Banner>
</template>
