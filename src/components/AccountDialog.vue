<script setup lang="ts">
/**
 * Signing in again to an account that already exists here — at the cloud or at
 * a custom backend. A new account comes through [AccountWizard].
 *
 * The two differ in one field: the cloud brings its address along, for a
 * custom backend it is typed in. Everything else is the same, and that is why
 * it is one dialog and not two.
 *
 * Only the **sign-in password** is asked for here. The master password comes
 * afterwards and from a different dialog — if the two were the same, the
 * server could read along at sign-in what the secrets are packed with.
 */
import { computed, onMounted, ref } from "vue";
import { useI18n } from "vue-i18n";
import { Alert, Button, Checkbox, Field, Input, PasswordInput } from "@wirecore/wirelayer-vue";
import EditDialog from "./EditDialog.vue";
import WireCloudLogin from "./WireCloudLogin.vue";
import {
  cloudUrl,
  detectWireCloud,
  requestPasswordReset,
  signIn,
  type CloudAccount,
  type WireCloudInfo,
} from "../cloud";
import { STORAGE_LABELS, type StorageKind } from "../types";

const props = defineProps<{
  /** `cloud` hides the address field — it brings its own. */
  storage: StorageKind;
  /**
   * Prefilled for signing in again to an account that already exists here.
   * Whoever signs in again after an expired session should not have to type
   * address and email a second time — they would be wrong anyway.
   */
  initialServer?: string;
  initialEmail?: string;
}>();

const emit = defineEmits<{ done: [account: CloudAccount]; cancel: [] }>();
const { t } = useI18n();

const kind = ref(props.storage);
const typedServer = ref(props.initialServer ?? "");
/** From the backend, see `onMounted`. */
const cloudServer = ref("");
const acceptInvalidCert = ref(false);
const email = ref(props.initialEmail ?? "");
const password = ref("");

const busy = ref(false);
const error = ref("");
const notice = ref("");

/**
 * Focus should land where typing starts — and for the cloud that is the email,
 * because its address is fixed and the field is not there at all. The first
 * field that is still empty — not blindly the first one. It gets
 * `data-autofocus`, which the dialog's focus trap follows.
 */
const firstEmpty =
  kind.value !== "cloud" && !typedServer.value.trim()
    ? "server"
    : !email.value.trim()
      ? "email"
      : "password";

const isCloud = computed(() => kind.value === "cloud");
const server = computed(() => (isCloud.value ? cloudServer.value : typedServer.value));

const valid = computed(
  () =>
    server.value.trim().length > 0 &&
    email.value.trim().length > 0 &&
    password.value.length > 0,
);

/** Set when the backend runs in WireCloud mode: then there is only the browser. */
const wireCloud = ref<WireCloudInfo | null>(null);

onMounted(async () => {
  cloudServer.value = await cloudUrl();
  // Signing in again to a cloud account: show it as cloud then, too.
  if (props.initialServer === cloudServer.value) kind.value = "cloud";
  // The backend's mode of operation decides what is asked. If it does not
  // answer, the form stays, and an error shows up at sign-in.
  if (server.value.trim()) {
    wireCloud.value = await detectWireCloud(
      server.value.trim(),
      !isCloud.value && acceptInvalidCert.value,
    ).catch(() => null);
  }
});

function values() {
  return {
    server: server.value.trim(),
    acceptInvalidCert: !isCloud.value && acceptInvalidCert.value,
    email: email.value.trim(),
    password: password.value,
  };
}

async function submit() {
  if (!valid.value || busy.value) return;
  busy.value = true;
  error.value = "";
  notice.value = "";
  try {
    emit("done", await signIn(values()));
  } catch (e) {
    error.value = String(e);
  } finally {
    busy.value = false;
  }
}

/**
 * Sends the mail for resetting the sign-in password.
 *
 * The answer deliberately does not say whether the address exists: that would
 * be information for anyone who types it in.
 */
async function resetPassword() {
  if (!email.value.trim() || busy.value) return;
  busy.value = true;
  error.value = "";
  try {
    const v = values();
    await requestPasswordReset(v.server, v.acceptInvalidCert, v.email);
    notice.value = t("AccountDialog.resetSent");
  } catch (e) {
    error.value = String(e);
  } finally {
    busy.value = false;
  }
}
</script>

<template>
  <EditDialog :title="t('AccountDialog.title', { storage: STORAGE_LABELS[kind] })" @cancel="emit('cancel')">
    <WireCloudLogin
      v-if="wireCloud"
      :server="server.trim()"
      :accept-invalid-cert="!isCloud && acceptInvalidCert"
      :wirecloud-url="wireCloud.wirecloudUrl"
      @done="emit('done', $event)"
      @cancel="emit('cancel')"
    />
    <template v-else>
      <Field v-if="!isCloud" :label="t('AccountDialog.server')">
        <Input
          v-model="typedServer"
          :data-autofocus="firstEmpty === 'server' ? '' : undefined"
          :placeholder="t('AccountDialog.serverPlaceholder')"
          autocapitalize="off"
          spellcheck="false"
        />
      </Field>
      <i18n-t v-if="!isCloud" keypath="AccountDialog.serverHint" tag="p" class="hint">
        <template #https><code>https://</code></template>
        <template #example><code>http://localhost:3000</code></template>
      </i18n-t>

      <Checkbox v-if="!isCloud" v-model:checked="acceptInvalidCert" class="choice">
        {{ t("AccountDialog.acceptInvalidCert") }}
      </Checkbox>
      <Alert v-if="!isCloud && acceptInvalidCert" status="warn" size="sm" class="note">
        {{ t("AccountDialog.acceptInvalidCertWarning") }}
      </Alert>

      <Field :label="t('AccountDialog.email')" class="spaced">
        <Input
          v-model="email"
          :data-autofocus="firstEmpty === 'email' ? '' : undefined"
          type="email"
          autocapitalize="off"
          spellcheck="false"
          :placeholder="t('AccountDialog.emailPlaceholder')"
        />
      </Field>

      <Field :label="t('AccountDialog.password')" class="spaced">
        <PasswordInput
          v-model="password"
          :data-autofocus="firstEmpty === 'password' ? '' : undefined"
          @keydown.enter.prevent="submit"
        />
      </Field>
      <p class="hint">{{ t("AccountDialog.passwordHint") }}</p>

      <Alert v-if="error" status="danger" size="sm" class="note">{{ error }}</Alert>
      <Alert v-if="notice" status="success" size="sm" class="note">{{ notice }}</Alert>

      <!--
        The side path sits in the text and not in the footer: read as a
        sentence it belongs here — a question to whoever is looking at the
        empty field right now.
      -->
      <p class="switch">
        <Button
          variant="link"
          size="sm"
          :disabled="busy || !email.trim()"
          :title="email.trim() ? '' : t('AccountDialog.forgotNeedsEmail')"
          @click="resetPassword"
        >
          {{ t("AccountDialog.forgot") }}
        </Button>
      </p>

    </template>

    <template v-if="!wireCloud" #actions>
      <span class="spacer"></span>
      <Button variant="outline" :disabled="busy" @click="emit('cancel')">{{ t("common.cancel") }}</Button>
      <Button :disabled="!valid || busy" @click="submit">
        {{ busy ? "…" : t("AccountDialog.signIn") }}
      </Button>
    </template>
  </EditDialog>
</template>

<style scoped>
.spaced {
  margin-top: 0.75rem;
}

.hint {
  margin: 0.4rem 0 0;
  font-size: 0.8rem;
  line-height: 1.5;
  color: var(--muted);
}

.hint code {
  font-family: Consolas, Menlo, monospace;
  font-size: 0.9em;
  color: var(--fg);
  word-break: break-all;
}

.note {
  margin-top: 0.6rem;
}

.choice {
  margin-top: 0.6rem;
}

.switch {
  margin: 0.75rem 0 0;
}

.spacer {
  flex: 1;
}
</style>
