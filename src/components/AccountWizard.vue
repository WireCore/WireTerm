<script setup lang="ts">
/**
 * Adding a new account, as a wizard with a summary at the end.
 *
 * First the backend and — for a custom one — its address, then whether the
 * account already exists, then the credentials. Signing in or registering only
 * happens after the summary.
 *
 * Only the **sign-in password** is asked for. The master password comes
 * afterwards and from a dialog of its own — if the two were the same, the
 * server could read along at sign-in what the secrets are packed with.
 *
 * Signing in again to a known account is [AccountDialog]: only the password
 * is missing there, and five steps would be too many for that.
 */
import { computed, onMounted, ref } from "vue";
import { useI18n } from "vue-i18n";
import { Cloud, LogIn, Server, UserPlus } from "@lucide/vue";
import {
  Alert,
  Button,
  Checkbox,
  Descriptions,
  Field,
  Input,
  PasswordInput,
  RadioCard,
  RadioGroup,
  Spinner,
  Wizard,
  type WizardStep,
} from "@wirecore/wirelayer-vue";
import EditDialog from "./EditDialog.vue";
import WireCloudLogin from "./WireCloudLogin.vue";
import {
  cloudUrl,
  detectWireCloud,
  requestPasswordReset,
  signIn,
  signUp,
  type CloudAccount,
  type WireCloudInfo,
} from "../cloud";
import type { StorageKind } from "../types";

const props = defineProps<{
  /** Preselected backend, for instance from the workspace wizard. */
  storage?: StorageKind;
}>();

const emit = defineEmits<{ done: [account: CloudAccount]; cancel: [] }>();
const { t } = useI18n();

const backends = computed(() => [
  {
    value: "cloud",
    title: "WireCloud",
    description: t("AccountWizard.backends.cloud"),
    icon: Cloud,
  },
  {
    value: "customBackend",
    title: t("AccountWizard.backends.customTitle"),
    description: t("AccountWizard.backends.custom"),
    icon: Server,
  },
]);

const modes = computed(() => [
  {
    value: "signIn",
    title: t("AccountWizard.modes.signInTitle"),
    description: t("AccountWizard.modes.signIn"),
    icon: LogIn,
  },
  {
    value: "signUp",
    title: t("AccountWizard.modes.signUpTitle"),
    description: t("AccountWizard.modes.signUp"),
    icon: UserPlus,
  },
]);

const step = ref(0);
const kind = ref<StorageKind>(props.storage === "customBackend" ? "customBackend" : "cloud");
const mode = ref<"signIn" | "signUp">("signIn");

const typedServer = ref("");
/** From the backend, see `onMounted`. */
const cloudServer = ref("");
const acceptInvalidCert = ref(false);
const name = ref("");
const email = ref("");
const password = ref("");

const busy = ref(false);
const error = ref("");
const notice = ref("");

const isCloud = computed(() => kind.value === "cloud");
const server = computed(() => (isCloud.value ? cloudServer.value : typedServer.value).trim());

/**
 * Set when the backend runs in WireCloud mode: then signing in through the
 * browser replaces the rest of the wizard. Email, sign-in password and
 * registration do not exist there.
 */
const wireCloud = ref<WireCloudInfo | null>(null);

/**
 * Asks the backend for its mode of operation. If it does not answer, the usual
 * path applies; an error there only shows up at sign-in, with the text that
 * sign-in returns. Stays on the step if it is WireCloud.
 */
async function detect(): Promise<boolean> {
  if (!server.value) return false;
  try {
    wireCloud.value = await detectWireCloud(server.value, !isCloud.value && acceptInvalidCert.value);
  } catch {
    wireCloud.value = null;
  }
  return wireCloud.value === null;
}

onMounted(async () => {
  cloudServer.value = await cloudUrl();
});

/**
 * The steps' labels, which the template also tells the steps apart by — the
 * slot hands back nothing else.
 */
const stepLabels = computed(() => ({
  backend: t("AccountWizard.steps.backend"),
  server: t("AccountWizard.steps.server"),
  account: t("AccountWizard.steps.account"),
  credentials: t("AccountWizard.steps.credentials"),
}));

const steps = computed<WizardStep[]>(() => [
  { label: stepLabels.value.backend, validate: isCloud.value ? detect : undefined },
  ...(isCloud.value
    ? []
    : [
        {
          label: stepLabels.value.server,
          validate: async () => server.value.length > 0 && (await detect()),
        },
      ]),
  { label: stepLabels.value.account },
  {
    label: stepLabels.value.credentials,
    validate: () =>
      email.value.trim().length > 0 &&
      password.value.length > 0 &&
      (mode.value === "signIn" || name.value.trim().length > 0),
  },
]);

const summary = computed(() => [
  {
    label: t("AccountWizard.summary.backend"),
    value: isCloud.value ? "WireCloud" : t("AccountWizard.backends.customTitle"),
  },
  { label: t("AccountWizard.summary.address"), value: server.value },
  ...(isCloud.value
    ? []
    : [
        {
          label: t("AccountWizard.summary.certificate"),
          value: acceptInvalidCert.value
            ? t("AccountWizard.summary.certificateUnchecked")
            : t("AccountWizard.summary.certificateChecked"),
        },
      ]),
  ...(mode.value === "signUp" ? [{ label: t("common.name"), value: name.value.trim() }] : []),
  { label: t("AccountWizard.email"), value: email.value.trim() },
  {
    label: t("AccountWizard.summary.action"),
    value: mode.value === "signIn" ? t("AccountWizard.signIn") : t("AccountWizard.signUp"),
  },
]);

function values() {
  return {
    server: server.value,
    acceptInvalidCert: !isCloud.value && acceptInvalidCert.value,
    email: email.value.trim(),
    password: password.value,
  };
}

async function finish() {
  busy.value = true;
  error.value = "";
  try {
    const account =
      mode.value === "signIn"
        ? await signIn(values())
        : await signUp({ ...values(), name: name.value.trim() });
    emit("done", account);
  } catch (e) {
    error.value = String(e);
    // Back to the summary: it shows what was attempted, and "Back" leads to the
    // field that was wrong.
    step.value = steps.value.length;
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
  notice.value = "";
  try {
    const v = values();
    await requestPasswordReset(v.server, v.acceptInvalidCert, v.email);
    notice.value = t("AccountWizard.resetSent");
  } catch (e) {
    error.value = String(e);
  } finally {
    busy.value = false;
  }
}
</script>

<template>
  <EditDialog :title="t('AccountWizard.title')" width="48rem" :footer="false" @cancel="emit('cancel')">
    <WireCloudLogin
      v-if="wireCloud"
      :server="server"
      :accept-invalid-cert="!isCloud && acceptInvalidCert"
      :wirecloud-url="wireCloud.wirecloudUrl"
      @done="emit('done', $event)"
      @cancel="emit('cancel')"
    />
    <Wizard
      v-else
      v-model:step="step"
      :steps="steps"
      :summary-label="t('AccountWizard.summary.title')"
      :finish-label="mode === 'signIn' ? t('AccountWizard.signIn') : t('AccountWizard.signUp')"
      focus-on-step-change
      @complete="finish"
    >
      <template #step="{ step: current }">
        <!-- Backend -->
        <RadioGroup
          v-if="current.label === stepLabels.backend"
          v-model="kind"
          :label="t('AccountWizard.backendQuestion')"
          :columns="1"
        >
          <RadioCard
            v-for="option in backends"
            :key="option.value"
            :value="option.value"
            :title="option.title"
            :description="option.description"
            :icon="option.icon"
          />
        </RadioGroup>

        <!-- Server, only for a custom backend -->
        <div v-else-if="current.label === stepLabels.server" class="stack">
          <Field :label="t('AccountWizard.server')">
            <Input
              v-model="typedServer"
              data-autofocus
              :placeholder="t('AccountWizard.serverPlaceholder')"
              autocapitalize="off"
              spellcheck="false"
            />
            <template #helper-text>
              <i18n-t keypath="AccountWizard.serverHint" tag="span">
                <template #https><code>https://</code></template>
                <template #example><code>http://localhost:3000</code></template>
              </i18n-t>
            </template>
          </Field>
          <Checkbox v-model:checked="acceptInvalidCert">
            {{ t("AccountWizard.acceptInvalidCert") }}
          </Checkbox>
          <Alert v-if="acceptInvalidCert" status="warn" size="sm">
            {{ t("AccountWizard.acceptInvalidCertWarning") }}
          </Alert>
        </div>

        <!-- Account: sign in or register -->
        <RadioGroup
          v-else-if="current.label === stepLabels.account"
          v-model="mode"
          :label="t('AccountWizard.modeQuestion')"
          :columns="1"
        >
          <RadioCard
            v-for="option in modes"
            :key="option.value"
            :value="option.value"
            :title="option.title"
            :description="option.description"
            :icon="option.icon"
          />
        </RadioGroup>

        <!-- Credentials -->
        <div v-else-if="current.label === stepLabels.credentials" class="stack">
          <Field v-if="mode === 'signUp'" :label="t('common.name')">
            <Input v-model="name" data-autofocus :placeholder="t('AccountWizard.namePlaceholder')" />
          </Field>
          <Field :label="t('AccountWizard.email')">
            <Input
              v-model="email"
              :data-autofocus="mode === 'signIn' ? '' : undefined"
              type="email"
              autocapitalize="off"
              spellcheck="false"
              :placeholder="t('AccountWizard.emailPlaceholder')"
            />
          </Field>
          <Field :label="t('AccountWizard.password')">
            <PasswordInput
              v-model="password"
              :autocomplete="mode === 'signUp' ? 'new-password' : 'current-password'"
            />
            <template #helper-text>{{ t("AccountWizard.passwordHint") }}</template>
          </Field>
          <Button
            v-if="mode === 'signIn'"
            class="self-start"
            variant="link"
            size="sm"
            :disabled="busy || !email.trim()"
            :title="email.trim() ? '' : t('AccountWizard.forgotNeedsEmail')"
            @click="resetPassword"
          >
            {{ t("AccountWizard.forgot") }}
          </Button>
          <Alert v-if="notice" status="success" size="sm">{{ notice }}</Alert>
          <Alert v-if="error" status="danger" size="sm">{{ error }}</Alert>
        </div>
      </template>

      <template #summary>
        <Descriptions
          orientation="horizontal"
          :columns="1"
          :classes="{ list: 'gap-y-2', item: 'grid-cols-[7rem_minmax(0,1fr)]' }"
          :items="summary"
        />
        <Alert v-if="error" class="error" status="danger" size="sm">{{ error }}</Alert>
      </template>

      <template #completed>
        <div class="done">
          <Spinner
            :label="mode === 'signIn' ? t('AccountWizard.signingIn') : t('AccountWizard.signingUp')"
          />
        </div>
      </template>
    </Wizard>
  </EditDialog>
</template>

<style scoped>
.stack {
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

code {
  font-family: var(--font-mono);
  font-size: 0.9em;
  color: var(--color-fg);
}

.error {
  margin-top: 0.75rem;
}

.done {
  display: flex;
  justify-content: center;
  padding: 1.5rem 0;
}
</style>
