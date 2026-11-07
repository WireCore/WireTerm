<script setup lang="ts">
/**
 * Signing in to a backend in WireCloud mode.
 *
 * There is no password and no registration here: signing in happens in the
 * system browser at WireCloud, with everything that belongs to it there
 * (second factor, forgotten password, new account). This program only waits
 * until the browser reports back, and then gets short-lived tokens, no
 * password.
 *
 * There is one case after all: whoever used the backend before WireCloud has
 * an account there with the same address. It is never taken over on its own
 * (the same address at a foreign service does not prove it is the same
 * person), but only once the person enters the **previous sign-in password**
 * of that account. The master password is not affected and comes afterwards
 * as always.
 */
import { ref } from "vue";
import { useI18n } from "vue-i18n";
import { Alert, Button, Field, PasswordInput, Spinner } from "@wirecore/wirelayer-vue";
import { cancelWireCloud, linkWireCloud, signInWireCloud, type CloudAccount } from "../cloud";

const props = defineProps<{
  server: string;
  acceptInvalidCert: boolean;
  /** Where WireCloud lives, for display. */
  wirecloudUrl: string;
}>();

const emit = defineEmits<{ done: [account: CloudAccount]; cancel: [] }>();
const { t } = useI18n();

const phase = ref<"idle" | "waiting" | "link">("idle");
const error = ref("");
const pendingId = ref("");
const email = ref("");
const password = ref("");
const busy = ref(false);
/** So that a cancel by the person does not show up as an error. */
let aborted = false;

async function start() {
  error.value = "";
  aborted = false;
  phase.value = "waiting";
  try {
    const result = await signInWireCloud(props.server, props.acceptInvalidCert);
    if (result.status === "signedIn") {
      emit("done", result.account);
      return;
    }
    pendingId.value = result.pendingId;
    email.value = result.email;
    phase.value = "link";
  } catch (e) {
    if (!aborted) error.value = String(e);
    phase.value = "idle";
  }
}


async function link() {
  if (!password.value || busy.value) return;
  busy.value = true;
  error.value = "";
  try {
    const result = await linkWireCloud(pendingId.value, password.value);
    if (result.status === "signedIn") {
      emit("done", result.account);
      return;
    }
    // A wrong password: another attempt is possible.
    error.value = result.message ?? "";
  } catch (e) {
    // Anything else ends the sign-in, it starts over.
    error.value = String(e);
    phase.value = "idle";
  } finally {
    password.value = "";
    busy.value = false;
  }
}

async function abort() {
  aborted = true;
  await cancelWireCloud(pendingId.value || undefined).catch(() => {});
  emit("cancel");
}
</script>

<template>
  <div class="stack">
    <template v-if="phase === 'idle'">
      <i18n-t keypath="WireCloudLogin.intro" tag="p" class="text">
        <template #wirecloud><strong>WireCloud</strong></template>
        <template #url><code>{{ wirecloudUrl }}</code></template>
      </i18n-t>
      <Alert v-if="error" status="danger" size="sm">{{ error }}</Alert>
      <div class="row">
        <span class="spacer"></span>
        <Button variant="outline" @click="abort">{{ t("common.cancel") }}</Button>
        <Button data-autofocus @click="start">{{ t("WireCloudLogin.signIn") }}</Button>
      </div>
    </template>

    <template v-else-if="phase === 'waiting'">
      <div class="center">
        <Spinner :label="t('WireCloudLogin.waiting')" />
      </div>
      <p class="text">{{ t("WireCloudLogin.waitingHint") }}</p>
      <div class="row">
        <span class="spacer"></span>
        <Button variant="outline" @click="abort">{{ t("common.cancel") }}</Button>
      </div>
    </template>

    <template v-else>
      <Alert status="info" size="sm">
        <i18n-t keypath="WireCloudLogin.linkIntro" tag="span">
          <template #email><strong>{{ email }}</strong></template>
          <template #password>
            <strong>{{ t("WireCloudLogin.linkIntroPassword") }}</strong>
          </template>
        </i18n-t>
      </Alert>
      <Field :label="t('WireCloudLogin.previousPassword')">
        <PasswordInput
          v-model="password"
          autocomplete="current-password"
          data-autofocus
          @keydown.enter.prevent="link"
        />
        <template #helper-text>{{ t("WireCloudLogin.previousPasswordHint") }}</template>
      </Field>
      <Alert v-if="error" status="danger" size="sm">{{ error }}</Alert>
      <div class="row">
        <span class="spacer"></span>
        <Button variant="outline" :disabled="busy" @click="abort">{{ t("common.cancel") }}</Button>
        <Button :disabled="!password || busy" @click="link">
          {{ busy ? "…" : t("WireCloudLogin.link") }}
        </Button>
      </div>
    </template>
  </div>
</template>

<style scoped>
.stack {
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

.text {
  margin: 0;
  line-height: 1.5;
}

code {
  font-family: var(--font-mono);
  font-size: 0.9em;
  color: var(--color-fg);
  word-break: break-all;
}

.row {
  display: flex;
  gap: 0.5rem;
  align-items: center;
}

.spacer {
  flex: 1;
}

.center {
  display: flex;
  justify-content: center;
  padding: 1rem 0;
}
</style>
