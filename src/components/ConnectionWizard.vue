<script setup lang="ts">
/**
 * Creates a new connection, as a wizard with a summary at the end.
 *
 * The steps are the sections of [ConnectionForm]; the name only comes in the
 * summary, prefilled from user and host — before that you do not yet know what
 * you are creating. Editing goes through [ConnectionDialog].
 */
import { computed, ref } from "vue";
import { useI18n } from "vue-i18n";
import { Database, FolderUp, Terminal } from "@lucide/vue";
import {
  Descriptions,
  Field,
  Input,
  RadioCard,
  RadioGroup,
  Wizard,
  type WizardStep,
} from "@wirecore/wirelayer-vue";
import EditDialog from "./EditDialog.vue";
import ConnectionForm from "./ConnectionForm.vue";
import ConnectionTest from "./ConnectionTest.vue";
import {
  defaultConnection,
  switchType,
  TYPE_LABELS,
  VAULT_LABELS,
  type Connection,
  type ConnectionSettings,
  type ConnectionType,
} from "../types";

defineProps<{ workspaceId?: string }>();

const emit = defineEmits<{ save: [connection: Connection]; cancel: [] }>();
const { t } = useI18n();

/** Descriptions under `ConnectionWizard.types.<value>`. */
const TYPES = [
  { value: "ssh", icon: Terminal },
  { value: "ftp", icon: FolderUp },
  { value: "s3", icon: Database },
] as const;

const draft = ref<Connection>(defaultConnection(""));
const settings = computed(() => draft.value.settings);
const step = ref(0);
const name = ref("");

const type = computed({
  get: () => settings.value.type,
  set: (value: ConnectionType) => switchType(draft.value, value),
});

/** A user and everything the chosen source needs are filled in. */
function loginComplete(s: ConnectionSettings): boolean {
  const auth = s.auth;
  if (auth.source !== "anonymous" && !s.user.trim()) return false;
  if ("reference" in auth) return auth.reference.trim() !== "";
  if (auth.source === "keyFile") return auth.path.trim() !== "";
  if (auth.source === "inlineKey") return auth.key.trim() !== "";
  if (auth.source === "password") return auth.password !== "";
  if (auth.source === "secret") return auth.secret !== "";
  return true;
}

/** A wizard step plus which section it is, since the label depends on the language. */
type Step = WizardStep & { id: "type" | "server" | "login" | "options" };

const steps = computed<Step[]>(() => [
  { id: "type", label: t("ConnectionWizard.steps.type") },
  {
    id: "server",
    label: t("ConnectionWizard.steps.server"),
    validate: () => settings.value.host.trim() !== "" && settings.value.port > 0,
  },
  {
    id: "login",
    label: t("ConnectionWizard.steps.login"),
    validate: () => loginComplete(settings.value),
  },
  { id: "options", label: t("ConnectionWizard.steps.options") },
]);

function stepId(step: WizardStep): Step["id"] {
  return (step as Step).id;
}

/** What the summary shows under "Login". */
function authSummary(s: ConnectionSettings): string {
  const auth = s.auth;
  const what =
    s.type === "s3"
      ? t("ConnectionWizard.auth.secretAccessKey")
      : s.type === "ssh" && ["vault", "keyFile", "inlineKey"].includes(auth.source)
        ? t("ConnectionWizard.auth.key")
        : t("ConnectionWizard.auth.password");
  switch (auth.source) {
    case "anonymous":
      return t("ConnectionWizard.auth.anonymous");
    case "agent":
      return t("ConnectionWizard.auth.agent");
    case "prompt":
      return t("ConnectionWizard.auth.prompt", { what });
    case "keyFile":
      return t("ConnectionWizard.auth.from", { what, source: auth.path });
    case "inlineKey":
    case "password":
    case "secret":
      return t("ConnectionWizard.auth.entered", { what });
    default:
      return t("ConnectionWizard.auth.from", { what, source: VAULT_LABELS[auth.provider] });
  }
}

/** User@host, as long as the user is a name and not a vault reference. */
const suggestedName = computed(() => {
  const s = settings.value;
  const host = s.host.trim();
  const user = s.user.trim();
  const plainUser =
    s.type !== "s3" && s.auth.source !== "anonymous" && user && !/^(op|bw):\/\//.test(user);
  return plainUser ? `${user}@${host}` : host;
});

const summary = computed(() => {
  const s = settings.value;
  return [
    { label: t("ConnectionWizard.summary.type"), value: TYPE_LABELS[s.type] },
    {
      label: s.type === "s3" ? t("ConnectionWizard.summary.endpoint") : t("ConnectionWizard.summary.server"),
      value: `${s.host.trim()}:${s.port}`,
    },
    ...(s.type === "ftp"
      ? [{ label: t("ConnectionWizard.summary.encryption"), value: t(`ConnectionWizard.security.${s.security}`) }]
      : []),
    ...(s.type === "s3"
      ? [{ label: "HTTPS", value: s.tls ? t("ConnectionWizard.summary.yes") : t("ConnectionWizard.summary.no") }]
      : []),
    ...(s.auth.source === "anonymous"
      ? []
      : [{ label: s.type === "s3" ? "Access Key ID" : t("ConnectionWizard.summary.user"), value: s.user.trim() }]),
    { label: t("ConnectionWizard.summary.login"), value: authSummary(s) },
    ...(s.type === "s3"
      ? [{ label: "Bucket", value: s.bucket.trim() || t("ConnectionWizard.summary.allBuckets") }]
      : s.startPath
        ? [{ label: t("ConnectionWizard.summary.startPath"), value: s.startPath }]
        : []),
  ];
});

function finish() {
  draft.value.name = name.value.trim() || suggestedName.value;
  emit("save", draft.value);
}
</script>

<template>
  <EditDialog :title="t('ConnectionWizard.title')" width="48rem" :footer="false" @cancel="emit('cancel')">
    <Wizard
      v-model:step="step"
      :steps="steps"
      :summary-label="t('ConnectionWizard.summaryLabel')"
      :finish-label="t('ConnectionWizard.finish')"
      focus-on-step-change
      @complete="finish"
    >
      <template #step="{ step: current }">
        <RadioGroup
          v-if="stepId(current) === 'type'"
          v-model="type"
          :label="t('ConnectionWizard.typeQuestion')"
          :columns="1"
        >
          <RadioCard
            v-for="option in TYPES"
            :key="option.value"
            :value="option.value"
            :title="TYPE_LABELS[option.value]"
            :description="t(`ConnectionWizard.types.${option.value}`)"
            :icon="option.icon"
          />
        </RadioGroup>

        <ConnectionForm v-else-if="stepId(current) === 'server'" :connection="draft" section="server" :workspace-id="workspaceId" />
        <ConnectionForm v-else-if="stepId(current) === 'login'" :connection="draft" section="login" :workspace-id="workspaceId" />
        <ConnectionForm v-else :connection="draft" section="options" :workspace-id="workspaceId" />
      </template>

      <template #summary>
        <div class="stack">
          <Field :label="t('common.name')">
            <Input v-model="name" data-autofocus :placeholder="suggestedName" />
          </Field>
          <Descriptions
            orientation="horizontal"
            :columns="1"
            :classes="{ list: 'gap-y-2', item: 'grid-cols-[8rem_minmax(0,1fr)]' }"
            :items="summary"
          />
          <ConnectionTest :connection="draft" />
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
</style>
