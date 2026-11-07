<script setup lang="ts">
/**
 * The device key, when it does not open by itself.
 *
 * On Windows and macOS this dialog does not come up: there the key lives in
 * the system keyring. It comes up on Linux without a Secret Service — then the
 * key lies under an app password and is asked for at startup — and where a
 * keyring has the key but is not answering right now.
 *
 * The app password is neither the sign-in password nor a backend's master
 * password. It only protects what lives on this device.
 */
import { computed, ref } from "vue";
import { useI18n } from "vue-i18n";
import { Alert, Button, Field, PasswordInput } from "@wirecore/wirelayer-vue";
import EditDialog from "./EditDialog.vue";
import {
  localVaultRetry,
  localVaultSetup,
  localVaultUnlock,
  type LocalVaultStatus,
} from "../local-vault";

const props = defineProps<{ status: LocalVaultStatus }>();

/** `done`: the key is open. `skip`: carry on without — secrets stay locked. */
const emit = defineEmits<{ done: []; skip: [] }>();
const { t } = useI18n();

const current = ref<LocalVaultStatus>(props.status);
const password = ref("");
const repeat = ref("");
const busy = ref(false);
const error = ref("");

const title = computed(
  () =>
    ({
      locked: t("LocalVaultDialog.appPassword"),
      setup: t("LocalVaultDialog.setupTitle"),
      unavailable: t("LocalVaultDialog.unavailableTitle"),
      ready: t("LocalVaultDialog.appPassword"),
    })[current.value.state],
);

/** The system's reason in parentheses, or nothing. */
const reason = computed(() => (current.value.reason ? ` (${current.value.reason})` : ""));

const valid = computed(() => {
  if (current.value.state === "locked") return password.value.length > 0;
  if (current.value.state === "setup")
    return password.value.length >= 8 && password.value === repeat.value;
  return false;
});

async function submit() {
  if (!valid.value || busy.value) return;
  busy.value = true;
  error.value = "";
  try {
    if (current.value.state === "locked") await localVaultUnlock(password.value);
    else await localVaultSetup(password.value);
    password.value = "";
    repeat.value = "";
    emit("done");
  } catch (e) {
    error.value = String(e);
  } finally {
    busy.value = false;
  }
}

async function retry() {
  busy.value = true;
  error.value = "";
  try {
    current.value = await localVaultRetry();
    if (current.value.state === "ready") emit("done");
  } catch (e) {
    error.value = String(e);
  } finally {
    busy.value = false;
  }
}
</script>

<template>
  <EditDialog :title="title" :can-save="valid && !busy" @save="submit" @cancel="emit('skip')">
    <template v-if="current.state === 'locked'">
      <p class="lead">{{ t("LocalVaultDialog.lockedLead") }}</p>
      <Field :label="t('LocalVaultDialog.appPassword')">
        <PasswordInput
          v-model="password"
          autocomplete="current-password"
          data-autofocus
          @keydown.enter.prevent="submit"
        />
      </Field>
    </template>

    <template v-else-if="current.state === 'setup'">
      <p class="lead">{{ t("LocalVaultDialog.setupLead", { reason }) }}</p>
      <Alert status="warn" size="sm">{{ t("LocalVaultDialog.setupWarning") }}</Alert>
      <Field
        :label="t('LocalVaultDialog.appPassword')"
        :helper-text="t('LocalVaultDialog.minLength')"
        class="spaced"
      >
        <PasswordInput v-model="password" autocomplete="new-password" data-autofocus />
      </Field>
      <Field
        :label="t('LocalVaultDialog.repeat')"
        :helper-text="repeat && repeat !== password ? t('LocalVaultDialog.mismatch') : undefined"
      >
        <PasswordInput v-model="repeat" autocomplete="new-password" @keydown.enter.prevent="submit" />
      </Field>
    </template>

    <template v-else-if="current.state === 'unavailable'">
      <p class="lead">{{ t("LocalVaultDialog.unavailableLead", { reason }) }}</p>
      <p class="lead">{{ t("LocalVaultDialog.unavailableHint") }}</p>
    </template>

    <Alert v-if="error" status="danger" size="sm" class="spaced">{{ error }}</Alert>

    <template #actions>
      <span class="spacer"></span>
      <Button variant="outline" :disabled="busy" @click="emit('skip')">
        {{ t("LocalVaultDialog.skip") }}
      </Button>
      <Button v-if="current.state === 'unavailable'" :disabled="busy" @click="retry">
        {{ t("common.retry") }}
      </Button>
      <Button v-else :disabled="!valid || busy" @click="submit">
        {{ current.state === "setup" ? t("LocalVaultDialog.set") : t("LocalVaultDialog.unlock") }}
      </Button>
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

.spacer {
  flex: 1;
}
</style>
