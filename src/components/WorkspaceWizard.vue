<script setup lang="ts">
/**
 * Creating a workspace, as a wizard with a summary at the end.
 *
 * First the storage, because it decides what is asked afterwards:
 *
 * - **This device:** name, then the vaults (both stored only here).
 * - **On a backend:** the account, then which workspace — an existing one or a
 *   new one. An organization there *is* a workspace.
 *
 * Nothing is carried out until after the summary. Only two things happen along
 * the way, because they are not a choice but a prerequisite: signing in and
 * the master password, if the account needs them — and invitations that one
 * accepts or declines.
 */
import { computed, onMounted, ref } from "vue";
import { useI18n } from "vue-i18n";
import { Cloud, Laptop, Server } from "@lucide/vue";
import {
  Alert,
  Badge,
  Button,
  Card,
  Checkbox,
  Descriptions,
  Field,
  Fieldset,
  Input,
  RadioCard,
  RadioGroup,
  Spinner,
  Wizard,
  type WizardStep,
} from "@wirecore/wirelayer-vue";
import AccountDialog from "./AccountDialog.vue";
import AccountWizard from "./AccountWizard.vue";
import EditDialog from "./EditDialog.vue";
import MasterPasswordDialog from "./MasterPasswordDialog.vue";
import {
  acceptInvitation,
  accounts,
  addWorkspace,
  availableWorkspaces,
  createWorkspace,
  invitationIdFrom,
  keyStatus,
  loadAccounts,
  myInvitations,
  rejectInvitation,
  sendVerificationEmail,
  type CloudAccount,
  type InvitationRow,
  type WorkspaceOption,
} from "../cloud";
import { adoptPersonalWorkspaces } from "../store";
import { defaultBitwardenAccount, type StorageKind, type WorkspaceValues } from "../types";

const emit = defineEmits<{
  /** A workspace on this device: the rail creates it. */
  create: [values: WorkspaceValues];
  /** A workspace on a backend: already created or added there. */
  added: [workspaceId: string];
  /** Instead of creating: take it from an export file. */
  import: [];
  cancel: [];
}>();
const { t } = useI18n();

const storages = computed(() => [
  {
    value: "local",
    title: t("WorkspaceWizard.storages.localTitle"),
    description: t("WorkspaceWizard.storages.local"),
    icon: Laptop,
  },
  {
    value: "cloud",
    title: "WireCloud",
    description: t("WorkspaceWizard.storages.cloud"),
    icon: Cloud,
  },
  {
    value: "customBackend",
    title: t("WorkspaceWizard.storages.customTitle"),
    description: t("WorkspaceWizard.storages.custom"),
    icon: Server,
  },
]);

const step = ref(0);
const storage = ref<StorageKind>("local");
const isLocal = computed(() => storage.value === "local");

const busy = ref(false);
const error = ref("");

// ---- This device ------------------------------------------------------------

const name = ref("");
const onePasswordAccount = ref("");
const bitwarden = ref(defaultBitwardenAccount());

// ---- On a backend -----------------------------------------------------------

const accountId = ref<string | null>(null);
const account = computed(() => accounts.find((entry) => entry.id === accountId.value) ?? null);
/** Signed in through WireCloud: organizations and invitations are then managed by WireCloud. */
const managed = computed(() => !!account.value?.managedBy);

const options = ref<WorkspaceOption[]>([]);
const addable = computed(() => options.value.filter((option) => !option.added));
const invitations = ref<InvitationRow[]>([]);
const invitationInput = ref("");
/** Without a verified address the backend does not hand out the invitations. */
const emailVerified = ref(true);
const verificationSent = ref(false);

/** The choice in the workspace step: the ID of an existing one, or "new". */
const choice = ref<string | null>(null);
const newName = ref("");
const chosen = computed(() => addable.value.find((option) => option.id === choice.value) ?? null);

onMounted(async () => {
  await loadAccounts();
  // One account and nothing to decide: then it is already selected.
  if (accounts.length === 1) accountId.value = accounts[0].id;
});

/**
 * Signing in and master password as a dialog above the wizard.
 *
 * "Next" waits for it: the step checks what is missing, asks for it, and moves
 * on as soon as it is there — or stays put if it was cancelled.
 */
const asking = ref<{ kind: "signIn" | "master"; resolve: (ok: boolean) => void } | null>(null);
/** The account being signed in to; empty means: a new one. */
const signInFor = ref<CloudAccount | null>(null);

function ask(kind: "signIn" | "master"): Promise<boolean> {
  return new Promise((resolve) => (asking.value = { kind, resolve }));
}

function settle(ok: boolean) {
  asking.value?.resolve(ok);
  asking.value = null;
}

async function signedIn(entry: CloudAccount) {
  accountId.value = entry.id;
  await loadAccounts();
  settle(true);
}

/** "Other account …": sign in, and the account is then selected. */
async function addAccount() {
  signInFor.value = null;
  await ask("signIn");
}

/**
 * Checks the account before "Next" and catches up on what it is missing. A
 * text stays on the step as an error.
 */
async function checkAccount(): Promise<boolean | string> {
  error.value = "";
  const entry = account.value;
  if (!entry) return t("WorkspaceWizard.chooseAccount");
  try {
    if (!entry.signedIn) {
      signInFor.value = entry;
      if (!(await ask("signIn"))) return t("WorkspaceWizard.signInCancelled");
    }
    const id = accountId.value!;
    // Is in the rail afterwards and therefore no longer under "Existing".
    const [personal] = await adoptPersonalWorkspaces(id);
    const status = await keyStatus(id);
    if (!status.hasKeys || !status.unlocked) {
      if (!(await ask("master"))) return t("WorkspaceWizard.masterRequired");
    }
    await loadOptions();
    // WireCloud decides the organizations and nothing can be created here: if
    // the personal workspace that just came into the rail was all there is,
    // there is nothing left to choose — that one is what was added.
    if (personal && managed.value && !addable.value.length) emit("added", personal);
    return true;
  } catch (e) {
    return String(e);
  }
}

async function loadOptions() {
  if (!accountId.value) return;
  options.value = await availableWorkspaces(accountId.value);
  // An invitation on the table is the most likely reason to add a workspace
  // at all.
  // In WireCloud mode there are neither invitations nor the address check at
  // the backend: both go through WireCloud.
  const mine = managed.value
    ? { invitations: [], emailVerified: true }
    : await myInvitations(accountId.value).catch(() => ({
        invitations: [],
        emailVerified: true,
      }));
  invitations.value = mine.invitations;
  emailVerified.value = mine.emailVerified;
  if (choice.value !== "new" && !chosen.value) choice.value = null;
}

/** The verification mail once more — it already went out at registration. */
async function requestVerification() {
  if (!accountId.value || busy.value) return;
  busy.value = true;
  error.value = "";
  try {
    await sendVerificationEmail(accountId.value);
    verificationSent.value = true;
  } catch (e) {
    error.value = String(e);
  } finally {
    busy.value = false;
  }
}

/** Invitations take effect immediately: once accepted, the workspace is under "Existing". */
async function acceptById(id: string) {
  if (!accountId.value || busy.value || !id) return;
  busy.value = true;
  error.value = "";
  try {
    await acceptInvitation(accountId.value, id);
    invitationInput.value = "";
    await loadOptions();
  } catch (e) {
    error.value = String(e);
  } finally {
    busy.value = false;
  }
}

async function reject(invitation: InvitationRow) {
  if (!accountId.value || busy.value) return;
  busy.value = true;
  try {
    await rejectInvitation(accountId.value, invitation.id);
    invitations.value = invitations.value.filter((row) => row.id !== invitation.id);
  } catch (e) {
    error.value = String(e);
  } finally {
    busy.value = false;
  }
}

// ---- The wizard -------------------------------------------------------------

/**
 * The steps' labels, which the template also tells the steps apart by — the
 * slot hands back nothing else.
 */
const stepLabels = computed(() => ({
  storage: t("WorkspaceWizard.steps.storage"),
  name: t("WorkspaceWizard.steps.name"),
  vaults: t("WorkspaceWizard.steps.vaults"),
  account: t("WorkspaceWizard.steps.account"),
  workspace: t("WorkspaceWizard.steps.workspace"),
}));

const steps = computed<WizardStep[]>(() => [
  { label: stepLabels.value.storage },
  ...(isLocal.value
    ? [
        { label: stepLabels.value.name, validate: () => name.value.trim().length > 0 },
        { label: stepLabels.value.vaults },
      ]
    : [
        { label: stepLabels.value.account, validate: checkAccount },
        {
          label: stepLabels.value.workspace,
          validate: () =>
            (choice.value === "new" && newName.value.trim().length > 0) || !!chosen.value,
        },
      ]),
]);

const summary = computed(() => {
  if (isLocal.value) {
    const email = bitwarden.value.email.trim();
    return [
      { label: t("WorkspaceWizard.steps.storage"), value: t("WorkspaceWizard.storages.localTitle") },
      { label: t("common.name"), value: name.value.trim() },
      { label: "1Password", value: onePasswordAccount.value.trim() || "—" },
      {
        label: "Bitwarden",
        value: email ? `${email} · ${bitwarden.value.server.trim() || "bitwarden.com"}` : "—",
      },
    ];
  }
  return [
    {
      label: t("WorkspaceWizard.steps.storage"),
      value: storage.value === "cloud" ? "WireCloud" : t("WorkspaceWizard.storages.customTitle"),
    },
    {
      label: t("WorkspaceWizard.steps.account"),
      value: account.value ? `${account.value.email} · ${account.value.server}` : "—",
    },
    {
      label: t("WorkspaceWizard.steps.workspace"),
      value:
        choice.value === "new"
          ? t("WorkspaceWizard.summaryCreate", { name: newName.value.trim() })
          : t("WorkspaceWizard.summaryAdd", { name: chosen.value?.name ?? "" }),
    },
  ];
});

async function finish() {
  if (isLocal.value) {
    const email = bitwarden.value.email.trim();
    emit("create", {
      name: name.value.trim(),
      storage: "local",
      onePasswordAccount: onePasswordAccount.value.trim(),
      bitwarden: email
        ? {
            server: bitwarden.value.server.trim(),
            email,
            acceptInvalidCert: bitwarden.value.acceptInvalidCert,
          }
        : undefined,
    });
    return;
  }

  busy.value = true;
  error.value = "";
  try {
    if (choice.value === "new") {
      emit("added", await createWorkspace(accountId.value!, newName.value.trim()));
    } else if (chosen.value) {
      await addWorkspace(accountId.value!, chosen.value.id, chosen.value.name);
      emit("added", chosen.value.id);
    }
  } catch (e) {
    error.value = String(e);
    // Back to the summary: it shows what was attempted.
    step.value = steps.value.length;
  } finally {
    busy.value = false;
  }
}
</script>

<template>
  <EditDialog :title="t('WorkspaceWizard.title')" width="38rem" :footer="false" @cancel="emit('cancel')">
    <Wizard
      v-model:step="step"
      :steps="steps"
      :summary-label="t('WorkspaceWizard.summary')"
      :finish-label="t('WorkspaceWizard.finish')"
      focus-on-step-change
      @complete="finish"
    >
      <template #step="{ step: current }">
        <!-- Storage -->
        <RadioGroup
          v-if="current.label === stepLabels.storage"
          v-model="storage"
          :columns="1"
          :label="t('WorkspaceWizard.storageQuestion')"
        >
          <RadioCard
            v-for="kind in storages"
            :key="kind.value"
            :value="kind.value"
            :title="kind.title"
            :description="kind.description"
            :icon="kind.icon"
          />
          <Button class="import" variant="text" @click="emit('import')">
            {{ t("WorkspaceWizard.import") }}
          </Button>
        </RadioGroup>

        <!-- This device: name -->
        <Field v-else-if="current.label === stepLabels.name" :label="t('common.name')">
          <Input v-model="name" data-autofocus :placeholder="t('WorkspaceWizard.namePlaceholder')" />
        </Field>

        <!-- This device: vaults -->
        <div v-else-if="current.label === stepLabels.vaults" class="stack">
          <p class="hint">{{ t("WorkspaceWizard.vaultsHint") }}</p>
          <Fieldset legend="1Password">
            <Field :label="t('WorkspaceWizard.onePasswordAccount')">
              <Input
                v-model="onePasswordAccount"
                :placeholder="t('WorkspaceWizard.onePasswordPlaceholder')"
              />
            </Field>
          </Fieldset>
          <Fieldset legend="Bitwarden">
            <Field :label="t('WorkspaceWizard.bitwardenEmail')">
              <Input v-model="bitwarden.email" :placeholder="t('WorkspaceWizard.emailPlaceholder')" />
            </Field>
            <Field :label="t('WorkspaceWizard.server')" :helper-text="t('WorkspaceWizard.serverHelper')">
              <Input v-model="bitwarden.server" :placeholder="t('WorkspaceWizard.serverPlaceholder')" />
            </Field>
            <Checkbox v-model:checked="bitwarden.acceptInvalidCert">
              {{ t("WorkspaceWizard.acceptInvalidCert") }}
            </Checkbox>
          </Fieldset>
        </div>

        <!-- Backend: account -->
        <div v-else-if="current.label === stepLabels.account" class="stack">
          <p class="hint">{{ t("WorkspaceWizard.accountHint") }}</p>
          <RadioGroup
            v-if="accounts.length"
            v-model="accountId"
            :label="t('WorkspaceWizard.steps.account')"
            :columns="1"
          >
            <RadioCard
              v-for="entry in accounts"
              :key="entry.id"
              :value="entry.id"
              :title="entry.email"
              :description="
                !entry.signedIn
                  ? t('WorkspaceWizard.accountSignedOut', { server: entry.server })
                  : !entry.unlocked
                    ? t('WorkspaceWizard.accountLocked', { server: entry.server })
                    : entry.server
              "
            />
          </RadioGroup>
          <Button variant="outline" @click="addAccount">
            {{ accounts.length ? t("WorkspaceWizard.otherAccount") : t("WorkspaceWizard.signInOrCreate") }}
          </Button>
        </div>

        <!-- Backend: workspace -->
        <div v-else-if="current.label === stepLabels.workspace" class="stack">
          <Alert v-if="!emailVerified" status="info" size="sm">
            <p>
              {{
                verificationSent
                  ? t("WorkspaceWizard.verificationSent", { email: account?.email })
                  : t("WorkspaceWizard.notVerified")
              }}
            </p>
            <div class="split">
              <Button variant="outline" :disabled="busy" @click="requestVerification">
                {{ verificationSent ? t("WorkspaceWizard.sendAgain") : t("WorkspaceWizard.sendVerification") }}
              </Button>
              <Button variant="text" :disabled="busy" @click="loadOptions">
                {{ t("WorkspaceWizard.checkAgain") }}
              </Button>
            </div>
          </Alert>

          <template v-if="invitations.length">
            <h4 class="label-mono">{{ t("WorkspaceWizard.invitations") }}</h4>
            <Card v-for="invitation in invitations" :key="invitation.id" size="sm" as-child>
              <div class="split">
                <span class="grow">
                  {{ invitation.organizationName ?? "Workspace" }}
                  <span class="muted">
                    {{ t("WorkspaceWizard.invitedAs", { role: invitation.role ?? t("WorkspaceWizard.member") }) }}
                  </span>
                </span>
                <Button variant="text" :disabled="busy" @click="reject(invitation)">
                  {{ t("WorkspaceWizard.decline") }}
                </Button>
                <Button :disabled="busy" @click="acceptById(invitation.id)">
                  {{ t("WorkspaceWizard.accept") }}
                </Button>
              </div>
            </Card>
          </template>

          <RadioGroup v-model="choice" :label="t('WorkspaceWizard.whichWorkspace')" :columns="1">
            <RadioCard
              v-for="option in addable"
              :key="option.id"
              :value="option.id"
              :title="option.name"
              :description="
                option.kind === 'personal'
                  ? t('WorkspaceWizard.personalRole', { role: option.role })
                  : option.role
              "
            />
            <RadioCard
              v-if="!managed"
              value="new"
              :title="t('WorkspaceWizard.createNew')"
              :description="t('WorkspaceWizard.createNewHint')"
            />
          </RadioGroup>
          <Field v-if="choice === 'new'" :label="t('WorkspaceWizard.newName')">
            <Input v-model="newName" data-autofocus :placeholder="t('WorkspaceWizard.newNamePlaceholder')" />
          </Field>
          <p v-if="!addable.length" class="hint">
            {{
              options.length
                ? t("WorkspaceWizard.allAdded")
                : t("WorkspaceWizard.noneYet")
            }}
          </p>

          <p v-if="managed" class="hint">{{ t("WorkspaceWizard.managedHint") }}</p>

          <details v-else class="invite">
            <summary>{{ t("WorkspaceWizard.pasteInvitation") }}</summary>
            <p class="hint">{{ t("WorkspaceWizard.pasteInvitationHint") }}</p>
            <div class="split">
              <Input
                v-model="invitationInput"
                class="grow"
                :placeholder="t('WorkspaceWizard.invitationPlaceholder')"
                autocapitalize="off"
                spellcheck="false"
              />
              <Button
                :disabled="!invitationIdFrom(invitationInput) || busy"
                @click="acceptById(invitationIdFrom(invitationInput))"
              >
                {{ t("WorkspaceWizard.accept") }}
              </Button>
            </div>
          </details>
        </div>

        <Alert v-if="error" class="error" status="danger" size="sm">{{ error }}</Alert>
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
          <Spinner v-if="busy" :label="t('WorkspaceWizard.creating')" />
          <Badge v-else variant="success">{{ t("common.done") }}</Badge>
        </div>
      </template>
    </Wizard>
  </EditDialog>

  <!-- In front of the wizard, not in its place: cancelling leads back. -->
  <AccountDialog
    v-if="asking?.kind === 'signIn' && signInFor"
    storage="customBackend"
    :initial-server="signInFor.url"
    :initial-email="signInFor.email"
    @done="signedIn"
    @cancel="settle(false)"
  />
  <AccountWizard
    v-else-if="asking?.kind === 'signIn'"
    :storage="storage"
    @done="signedIn"
    @cancel="settle(false)"
  />
  <MasterPasswordDialog
    v-else-if="asking?.kind === 'master' && accountId"
    :account-id="accountId"
    @done="settle(true)"
    @cancel="settle(false)"
  />
</template>

<style scoped>
.stack {
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

.hint {
  margin: 0;
  font-size: 0.8rem;
  line-height: 1.5;
  color: var(--color-muted);
}

h4 {
  margin: 0;
  font-weight: 400;
}

.split {
  flex-direction: row;
  align-items: center;
  gap: 0.5rem;
  padding: 0.55rem 0.75rem;
}

.grow {
  flex: 1;
  min-width: 0;
}

.muted {
  color: var(--color-muted);
  font-size: 0.85em;
}

.invite summary {
  cursor: pointer;
  font-size: 0.85rem;
  color: var(--color-muted);
}

.invite[open] {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
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
