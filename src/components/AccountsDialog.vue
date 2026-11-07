<script setup lang="ts">
/**
 * The accounts on this computer — behind the tile at the very bottom of the
 * rail.
 *
 * An account is a user on a backend. It does not belong to a workspace, it is
 * the other way round: an account has as many workspaces as the user has
 * organizations there. That is why it lives here and not in the workspace
 * form.
 *
 * As long as there is none yet, this dialog is not shown at all — the sign-in
 * form appears right away. The list would otherwise be an empty list with a
 * button below it, and the button is the whole content.
 */
import { computed, onMounted, ref } from "vue";
import { useI18n } from "vue-i18n";
import { Alert, Badge, Button, Card } from "@wirecore/wirelayer-vue";
import { Plus } from "@lucide/vue";
import AccountDialog from "./AccountDialog.vue";
import AccountWizard from "./AccountWizard.vue";
import EditDialog from "./EditDialog.vue";
import MasterPasswordDialog from "./MasterPasswordDialog.vue";
import {
  accounts,
  forgetAccount,
  keyStatus,
  loadAccounts,
  lock,
  signOut,
  type CloudAccount,
} from "../cloud";
import { adoptPersonalWorkspaces, loadWorkspaces, workspaces } from "../store";

const emit = defineEmits<{ close: [] }>();
const { t } = useI18n();

/** Signing in to an account — new or again. */
const adding = ref<{ server: string; email: string } | null>(null);

/**
 * The account whose master password is asked for. Whether it is set up or
 * entered, the dialog decides itself from the key status.
 */
const masterFor = ref<string | null>(null);
/** "Change" instead of "Unlock" — the same dialog, a different entry. */
const changing = ref(false);

/** Two steps, because the copies of the workspaces depend on it. */
const removing = ref<string | null>(null);

const busy = ref(false);
const error = ref("");

/**
 * Whether a key pair is already stored for an account.
 *
 * Asked over the wire, not guessed: "not set up yet" and "set up, but locked"
 * look the same from here and mean something different. Without a network it
 * stays empty, and then nothing is shown there.
 */
const hasKeys = ref<Record<string, boolean>>({});

onMounted(async () => {
  await loadAccounts();
  if (accounts.length === 0) adding.value = { server: "", email: "" };
  await refreshKeys();
});

async function refreshKeys() {
  for (const account of accounts) {
    if (!account.signedIn) continue;
    try {
      hasKeys.value[account.id] = (await keyStatus(account.id)).hasKeys;
    } catch {
      // No network: then there is simply no information next to the account.
      // An error banner for it would be noise — it is not a failure, but a
      // detail that is not available right now.
      delete hasKeys.value[account.id];
    }
  }
}

/** How many workspaces in the rail belong to this account. */
function workspaceCount(id: string): number {
  return workspaces.filter((workspace) => workspace.remote?.accountId === id).length;
}

function status(account: CloudAccount): { text: string; tone: "ok" | "warn" | "muted" } {
  if (!account.signedIn) return { text: t("AccountsDialog.status.signedOut"), tone: "warn" };
  if (hasKeys.value[account.id] === false) {
    return { text: t("AccountsDialog.status.noMasterPassword"), tone: "warn" };
  }
  if (!account.unlocked) return { text: t("AccountsDialog.status.locked"), tone: "muted" };
  return { text: t("AccountsDialog.status.ready"), tone: "ok" };
}

/** What the status's tone looks like as a badge. */
const TAG_VARIANT = { ok: "success", warn: "warn", muted: "outline" } as const;

async function act(action: () => Promise<unknown>) {
  if (busy.value) return;
  busy.value = true;
  error.value = "";
  try {
    await action();
    await loadAccounts();
    await loadWorkspaces();
    await refreshKeys();
  } catch (e) {
    error.value = String(e);
  } finally {
    busy.value = false;
  }
}

async function afterSignIn() {
  adding.value = null;
  // Whoever just signed in has a workspace there that belongs only to them.
  // It shows up in the rail afterwards without anyone looking for it.
  await act(() => adoptPersonalWorkspaces());
}

async function afterMaster() {
  masterFor.value = null;
  changing.value = false;
  await act(async () => {});
}

const title = computed(() => t("AccountsDialog.title", accounts.length));
</script>

<template>
  <!--
    The sign-in form stands in front of this dialog, not in its place: the way
    back is then "Cancel", and the list behind it stays.
  -->
  <!-- A new account through the wizard, a known one with just the password. -->
  <AccountWizard
    v-if="adding && !adding.server"
    @done="afterSignIn"
    @cancel="accounts.length ? (adding = null) : emit('close')"
  />
  <AccountDialog
    v-else-if="adding"
    storage="customBackend"
    :initial-server="adding.server"
    :initial-email="adding.email"
    @done="afterSignIn"
    @cancel="accounts.length ? (adding = null) : emit('close')"
  />

  <MasterPasswordDialog
    v-else-if="masterFor"
    :key="masterFor"
    :account-id="masterFor"
    :start="changing ? 'change' : 'auto'"
    @done="afterMaster"
    @cancel="
      masterFor = null;
      changing = false;
    "
  />

  <EditDialog v-else :title="title" wide @cancel="emit('close')">
    <p class="hint">{{ t("AccountsDialog.hint") }}</p>

    <ul class="rows">
      <Card v-for="account in accounts" :key="account.id" size="sm" as-child>
        <li class="account">
          <div class="head">
            <span class="grow">
              <span class="name">{{ account.name || account.email }}</span>
              <span v-if="account.name" class="muted">{{ account.email }}</span>
            </span>
            <Badge class="tag" :variant="TAG_VARIANT[status(account).tone]">
              {{ status(account).text }}
            </Badge>
          </div>

          <p class="where">
            {{ account.server }} ·
            {{ t("AccountsDialog.inRail", workspaceCount(account.id)) }}
          </p>

          <Alert v-if="removing === account.id" status="warn" size="sm" class="note">
            {{ t("AccountsDialog.removeWarning", workspaceCount(account.id)) }}
            <template #actions>
              <Button variant="outline" size="sm" :disabled="busy" @click="removing = null">
                {{ t("common.cancel") }}
              </Button>
              <Button
                variant="danger"
                size="sm"
                :disabled="busy"
                @click="
                  act(() => forgetAccount(account.id));
                  removing = null;
                "
              >
                {{ t("AccountsDialog.removeAccount") }}
              </Button>
            </template>
          </Alert>

          <div v-else class="actions">
            <Button
              v-if="!account.signedIn"
              size="sm"
              :disabled="busy"
              @click="adding = { server: account.url, email: account.email }"
            >
              {{ t("AccountsDialog.signIn") }}
            </Button>

            <template v-else>
              <Button
                v-if="!account.unlocked"
                size="sm"
                :disabled="busy"
                @click="
                  masterFor = account.id;
                  changing = false;
                "
              >
                {{
                  hasKeys[account.id] === false
                    ? t("AccountsDialog.setUpMasterPassword")
                    : t("AccountsDialog.unlock")
                }}
              </Button>
              <Button
                v-else
                variant="text"
                size="sm"
                :disabled="busy"
                @click="act(() => lock(account.id))"
              >
                {{ t("AccountsDialog.lock") }}
              </Button>

              <Button
                v-if="hasKeys[account.id] !== false"
                variant="text"
                size="sm"
                :disabled="busy"
                @click="
                  masterFor = account.id;
                  changing = true;
                "
              >
                {{ t("AccountsDialog.changeMasterPassword") }}
              </Button>

              <Button
                variant="text"
                size="sm"
                :disabled="busy"
                @click="act(() => signOut(account.id))"
              >
                {{ t("AccountsDialog.signOut") }}
              </Button>
            </template>

            <span class="spacer"></span>
            <Button
              variant="text"
              color="danger"
              size="sm"
              :disabled="busy"
              @click="removing = account.id"
            >
              {{ t("common.remove") }}
            </Button>
          </div>
        </li>
      </Card>
    </ul>

    <Button
      class="wide-button"
      variant="outline"
      block
      :leading-icon="Plus"
      @click="adding = { server: '', email: '' }"
    >
      {{ t("AccountsDialog.add") }}
    </Button>

    <Alert v-if="error" status="danger" size="sm" class="note">{{ error }}</Alert>

    <template #actions>
      <span class="spacer"></span>
      <Button variant="outline" @click="emit('close')">{{ t("common.close") }}</Button>
    </template>
  </EditDialog>
</template>

<style scoped>
.hint {
  margin: 0.4rem 0 0;
  font-size: 0.8rem;
  line-height: 1.5;
  color: var(--muted);
}

.note {
  margin-top: 0.6rem;
}

.rows {
  list-style: none;
  margin: 0.75rem 0 0;
  padding: 0;
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

/* Border, surface and radius come from the Card (sm); spacing a bit tighter still. */
.account {
  gap: 0;
  padding: 0.65rem 0.75rem;
}

.head {
  display: flex;
  align-items: baseline;
  gap: 0.5rem;
}

.grow {
  flex: 1;
  min-width: 0;
  display: flex;
  align-items: baseline;
  gap: 0.5rem;
  flex-wrap: wrap;
}

.name {
  font-size: 0.95rem;
  font-weight: 500;
}

.muted {
  color: var(--muted);
  font-size: 0.8rem;
}

.where {
  margin: 0.2rem 0 0;
  font-size: 0.78rem;
  color: var(--muted);
  overflow-wrap: anywhere;
}

.tag {
  flex: 0 0 auto;
}

.actions {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 0.4rem;
  margin-top: 0.6rem;
}

.spacer {
  flex: 1;
}

/*
  A dashed border like the "+" in the rail: across the full width a button
  without a visible border looks like a sentence someone centered by accident.
*/
.wide-button {
  margin-top: 0.75rem;
  border-style: dashed;
}
</style>
