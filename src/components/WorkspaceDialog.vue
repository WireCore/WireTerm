<script setup lang="ts">
import { computed, ref } from "vue";
import { useI18n } from "vue-i18n";
import { si1password, siBitwarden, siVaultwarden } from "simple-icons";
import {
  Accordion,
  AccordionItem,
  Alert,
  Badge,
  Button,
  Checkbox,
  Code,
  Descriptions,
  Field,
  Fieldset,
  Input,
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
} from "@wirecore/wirelayer-vue";
import BrandIcon from "./BrandIcon.vue";
import EditDialog from "./EditDialog.vue";
import EmbeddedPanel from "./EmbeddedPanel.vue";
import OnePasswordAccountHint from "./OnePasswordAccountHint.vue";
import { accountOf } from "../cloud";
import {
  defaultBitwardenAccount,
  ROLE_LABELS,
  type Workspace,
  type WorkspaceValues,
} from "../types";

/**
 * More tabs, filled through the slot of the same name by whoever opens the
 * dialog — each holds an edit dialog of its own, shown as the tab's content.
 * `device` ones are about this device rather than the workspace and come
 * last, under a heading of their own.
 */
type ExtraTab = { value: string; label: string; device?: boolean };

const props = defineProps<{ workspace: Workspace; mode: "create" | "edit"; extras?: ExtraTab[] }>();

/** The settings are the editable part; the projects stay where they are. */
const emit = defineEmits<{
  save: [values: WorkspaceValues];
  remove: [];
  /** Only for a remote workspace: delete or leave, on the server. */
  removeRemote: [leaveOnly: boolean];
  /** Remove from the rail only here, without touching the server. */
  hide: [];
  /** Change this account's master password. */
  changeMaster: [];
  cancel: [];
}>();
const { t } = useI18n();

const name = ref(props.workspace.name);
const account = ref(props.workspace.onePasswordAccount ?? "");
const bitwarden = ref({ ...defaultBitwardenAccount(), ...props.workspace.bitwarden });

const valid = computed(() => name.value.trim().length > 0);

const projectCount = computed(() => props.workspace.projects.length);

const remote = computed(() => props.workspace.remote ?? null);

/**
 * The personal workspace cannot be deleted — the server refuses. Otherwise
 * someone would be left without any workspace after one click, and a second
 * one would never come about: the registration that creates it is long over.
 */
const deletable = computed(() => remote.value?.kind !== "personal" && !managed.value);

/**
 * A workspace whose account is signed in through WireCloud. Companies, members
 * and teams then belong to WireCloud: leaving or deleting is decided there by
 * the administrator, not by this program.
 */
const managed = computed(() => !!accountOf(remote.value?.accountId)?.managedBy);

/** Whoever does not own the organization leaves it instead of deleting it. */
const leaveOnly = computed(() => remote.value?.role !== "owner");

/**
 * Which removal confirmation is showing right now. A local workspace only
 * knows "delete", a remote one two meanings of "gone" — each with its own.
 */
const confirming = ref<"local" | "remote" | "hide" | null>(null);

const tab = ref("general");

const workspaceTabs = computed(() => (props.extras ?? []).filter((extra) => !extra.device));
const deviceTabs = computed(() => (props.extras ?? []).filter((extra) => extra.device));
/** Only name and vaults are saved with the dialog's button; the others bring their own. */
const ownTab = computed(() => tab.value === "general" || tab.value === "vaults");

/**
 * The picture showing where the 1Password account name is: open as long as
 * none was entered yet. After that behind a link — whoever knows it already
 * does not need it every time. Decided once on opening, so that it does not
 * vanish while typing.
 */
const showAccountHint = ref(!props.workspace.onePasswordAccount);

/**
 * Expanded is what is already set up — that is where one wants to look or
 * change something. If nothing is set up yet, 1Password as the usual one.
 */
const openVaults = ref(
  [
    props.workspace.onePasswordAccount ? "onePassword" : null,
    props.workspace.bitwarden?.email ? "bitwarden" : null,
  ].filter((value): value is string => !!value),
);
if (!openVaults.value.length) openVaults.value = ["onePassword"];


function save() {
  if (!valid.value) return;
  const email = bitwarden.value.email.trim();
  emit("save", {
    name: name.value.trim(),
    storage: props.workspace.storage,
    onePasswordAccount: account.value.trim(),
    // Dropped rather than stored empty: "no Bitwarden account" and "a
    // Bitwarden account with no name" are the same thing, and only one of
    // them should end up in the file.
    bitwarden: email
      ? {
          server: bitwarden.value.server.trim(),
          email,
          acceptInvalidCert: bitwarden.value.acceptInvalidCert,
        }
      : undefined,
  });
}
</script>

<template>
  <!--
    Side tabs instead of one long page: what one looks for on every opening
    (name, backend) in front, what one sets up once (vaults) behind, then what
    the overview used to carry as buttons. Removing sits apart at the bottom of
    the first tab, so the footer only carries "Cancel" and "Save" — and only
    for the two tabs it saves.
  -->
  <EditDialog
    :title="mode === 'create' ? t('WorkspaceDialog.titleCreate') : t('WorkspaceDialog.titleEdit')"
    :mode="mode"
    width="56rem"
    :can-save="valid"
    :can-delete="false"
    :footer="ownTab"
    @save="save"
    @cancel="emit('cancel')"
  >
    <Tabs v-model="tab" orientation="vertical" :label="t('WorkspaceDialog.tabsLabel')">
      <TabsList>
        <TabsTrigger value="general">{{ t("WorkspaceDialog.general") }}</TabsTrigger>
        <TabsTrigger value="vaults">{{ t("WorkspaceDialog.vaults") }}</TabsTrigger>
        <TabsTrigger v-for="extra in workspaceTabs" :key="extra.value" :value="extra.value">
          {{ extra.label }}
        </TabsTrigger>
        <p v-if="deviceTabs.length" class="tab-group">{{ t("WorkspaceDialog.device") }}</p>
        <TabsTrigger v-for="extra in deviceTabs" :key="extra.value" :value="extra.value">
          {{ extra.label }}
        </TabsTrigger>
      </TabsList>

      <TabsContent value="general" class="panel">
        <Field :label="t('common.name')">
          <Input v-model="name" data-autoselect />
        </Field>

        <!--
          Where a remote workspace lives is shown as information, not as a
          setting. It cannot be moved — that would be a new workspace and a
          copy, and both are better said than done silently.
        -->
        <Fieldset v-if="remote" :legend="t('WorkspaceDialog.backend')">
          <Descriptions
            class="facts"
            orientation="horizontal"
            :columns="1"
            :classes="{ list: 'gap-y-2', item: 'grid-cols-[6rem_minmax(0,1fr)]' }"
            :items="[
              { label: t('WorkspaceDialog.address'), value: remote.server },
              { label: t('WorkspaceDialog.account'), value: remote.email },
              { label: t('WorkspaceDialog.role'), value: ROLE_LABELS[remote.role] },
              { id: 'state', label: t('WorkspaceDialog.state') },
            ]"
          >
            <template #value-state>
              <template v-if="remote.locked">{{ t("WorkspaceDialog.locked") }}</template>
              <template v-else-if="remote.pending">
                {{ t("WorkspaceDialog.pending", remote.pending) }}
              </template>
              <template v-else>{{ t("WorkspaceDialog.synced") }}</template>
            </template>
          </Descriptions>
          <Alert v-if="remote.error" status="warn" size="sm">{{ remote.error }}</Alert>

          <Button class="start" variant="text" @click="emit('changeMaster')">
            {{ t("WorkspaceDialog.changeMaster") }}
          </Button>
        </Fieldset>

        <!--
          Two meanings of "gone" for a remote workspace, and they differ
          considerably for everyone else. That is why there are two buttons
          instead of one "Delete". A local one only knows the one.
        -->
        <section class="danger-zone">
          <p class="label">{{ t("WorkspaceDialog.removeTitle") }}</p>

          <template v-if="confirming === 'local'">
            <Alert status="warn" size="sm">
              {{
                t("WorkspaceDialog.deleteLocal", { name: workspace.name, n: projectCount }, projectCount)
              }}
            </Alert>
            <div class="row">
              <Button variant="outline" @click="confirming = null">{{ t("common.cancel") }}</Button>
              <Button variant="danger" @click="emit('remove')">{{ t("common.delete") }}</Button>
            </div>
          </template>

          <template v-else-if="confirming === 'hide'">
            <Alert status="warn" size="sm">
              {{ t("WorkspaceDialog.hideWarning", { name: workspace.name }) }}
            </Alert>
            <div class="row">
              <Button variant="outline" @click="confirming = null">{{ t("common.cancel") }}</Button>
              <Button variant="danger" @click="emit('hide')">{{ t("WorkspaceDialog.hide") }}</Button>
            </div>
          </template>

          <template v-else-if="confirming === 'remote'">
            <Alert status="warn" size="sm">
              <template v-if="leaveOnly">
                {{ t("WorkspaceDialog.leaveWarning", { name: workspace.name }) }}
              </template>
              <i18n-t
                v-else
                keypath="WorkspaceDialog.deleteRemote"
                tag="span"
                :plural="projectCount"
              >
                <template #name>{{ workspace.name }}</template>
                <template #n>{{ projectCount }}</template>
                <template #forAll>
                  <strong>{{ t("WorkspaceDialog.deleteRemoteForAll") }}</strong>
                </template>
              </i18n-t>
            </Alert>
            <div class="row">
              <Button variant="outline" @click="confirming = null">{{ t("common.cancel") }}</Button>
              <Button variant="danger" @click="emit('removeRemote', leaveOnly)">
                {{ leaveOnly ? t("WorkspaceDialog.leave") : t("WorkspaceDialog.deleteForAll") }}
              </Button>
            </div>
          </template>

          <div v-else-if="!remote" class="row">
            <Button variant="outline" color="danger" @click="confirming = 'local'">
              {{ t("common.delete") }}
            </Button>
          </div>

          <div v-else class="row">
            <Button variant="outline" color="danger" @click="confirming = 'hide'">{{ t("WorkspaceDialog.hide") }}</Button>
            <Button
              v-if="deletable"
              variant="outline"
              color="danger"
              @click="confirming = 'remote'"
            >
              {{ leaveOnly ? t("WorkspaceDialog.leaveWorkspace") : t("WorkspaceDialog.deleteForAll") }}
            </Button>
          </div>
          <p v-if="remote && managed && remote.kind === 'personal'" class="hint">
            {{ t("WorkspaceDialog.managedPersonalHint") }}
          </p>
          <p v-else-if="remote && managed" class="hint">{{ t("WorkspaceDialog.managedHint") }}</p>
          <p v-else-if="remote && !deletable" class="hint">{{ t("WorkspaceDialog.personalHint") }}</p>
        </section>
      </TabsContent>

      <!--
        Both accounts sit per workspace rather than per device: which account a
        set of connections is read with belongs with the connections. Neither is
        needed unless a connection in here actually points into that vault, so
        both stay empty by default.
      -->
      <!--
        One entry per tool, with logo and state in the header: collapsed, one
        sees which are set up without opening them.
      -->
      <TabsContent value="vaults" class="panel">
        <Accordion v-model="openVaults" multiple>
          <AccordionItem value="onePassword">
            <template #title>
              <span class="vault-title">
                <BrandIcon :icon="si1password" />
                1Password
                <Badge :variant="account.trim() ? 'success' : 'outline'">
                  {{ account.trim() || t("WorkspaceDialog.notSetUp") }}
                </Badge>
              </span>
            </template>

            <div class="vault-body">
              <Field
                :label="t('WorkspaceDialog.account')"
                :helper-text="t('WorkspaceDialog.onePasswordHelper')"
              >
                <Input v-model="account" :placeholder="t('WorkspaceDialog.onePasswordPlaceholder')" />
              </Field>
              <OnePasswordAccountHint v-if="showAccountHint" />
              <Button v-else class="start" variant="link" size="sm" @click="showAccountHint = true">
                {{ t("WorkspaceDialog.whereIsName") }}
              </Button>
            </div>
          </AccordionItem>

          <AccordionItem value="bitwarden">
            <template #title>
              <span class="vault-title">
                <!--
                  Both logos: whether Vaultwarden or a self-hosted Bitwarden
                  runs behind a custom address cannot be told apart from here —
                  they speak the same interface.
                -->
                <BrandIcon :icon="siBitwarden" />
                <BrandIcon :icon="siVaultwarden" />
                Bitwarden / Vaultwarden
                <Badge :variant="bitwarden.email.trim() ? 'success' : 'outline'">
                  {{ bitwarden.email.trim() || t("WorkspaceDialog.notSetUp") }}
                </Badge>
              </span>
            </template>

            <div class="vault-body">
              <Field :label="t('WorkspaceDialog.bitwardenEmail')">
                <Input v-model="bitwarden.email" :placeholder="t('WorkspaceDialog.emailPlaceholder')" />
              </Field>

              <Field :label="t('WorkspaceDialog.server')">
                <Input v-model="bitwarden.server" :placeholder="t('WorkspaceDialog.serverPlaceholder')" />
                <template #helper-text>
                  <i18n-t keypath="WorkspaceDialog.serverHelper" tag="span">
                    <template #example><Code>{{ t("WorkspaceDialog.serverExample") }}</Code></template>
                    <template #eu><Code>bitwarden.eu</Code></template>
                  </i18n-t>
                </template>
              </Field>

              <Checkbox v-model:checked="bitwarden.acceptInvalidCert">
                {{ t("WorkspaceDialog.acceptInvalidCert") }}
              </Checkbox>
              <Alert v-if="bitwarden.acceptInvalidCert" status="warn" size="sm">
                {{ t("WorkspaceDialog.acceptInvalidCertWarning") }}
              </Alert>

              <p class="hint">{{ t("WorkspaceDialog.bitwardenMasterHint") }}</p>
            </div>
          </AccordionItem>
        </Accordion>
      </TabsContent>

      <!-- Mounted only while in front: some of them load from the server. -->
      <TabsContent v-for="extra in extras ?? []" :key="extra.value" :value="extra.value" class="panel">
        <EmbeddedPanel v-if="tab === extra.value">
          <slot :name="extra.value" />
        </EmbeddedPanel>
      </TabsContent>
    </Tabs>
  </EditDialog>
</template>

<style scoped>
/*
  A tab: fields and frames stacked, with room in between. Beside the tab list,
  at a height that keeps the dialog from jumping between tabs.
*/
.panel {
  flex: 1;
  min-width: 0;
  min-height: 28rem;
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

.tab-group {
  margin: 0.75rem 0 0.25rem;
  padding: 0 0.75rem;
  font-size: 0.75rem;
  color: var(--muted);
}

.hint {
  margin: 0;
  font-size: 0.8rem;
  line-height: 1.5;
  color: var(--muted);
}

.vault-title {
  display: inline-flex;
  align-items: center;
  gap: 0.5rem;
}

.vault-body {
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

/* Set apart from the rest: removing is not configuring. */
.danger-zone {
  padding-top: 1rem;
  border-top: 1px solid var(--color-line);
}

.label {
  margin: 0 0 0.5rem;
  font-size: 0.8rem;
  color: var(--muted);
}

/* Long addresses and emails wrap instead of widening the dialog. */
.facts :deep(dd) {
  overflow-wrap: anywhere;
}

/* In the fieldset it would otherwise be stretched to full width. */
.start {
  align-self: flex-start;
}

.row {
  display: flex;
  gap: 0.5rem;
  margin-top: 0.5rem;
  flex-wrap: wrap;
}
</style>
