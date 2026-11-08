<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { useI18n } from "vue-i18n";
import { Laptop, Plus, Settings, User } from "@lucide/vue";
import {
  Avatar,
  Button,
  IconButton,
  OverlayBadge,
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@wirecore/wirelayer-vue";
import { avatarColor } from "@wirecore/wirelayer-recipes";
import AccountDialog from "./AccountDialog.vue";
import AccountWizard from "./AccountWizard.vue";
import AccountsDialog from "./AccountsDialog.vue";
import WorkspaceWizard from "./WorkspaceWizard.vue";
import ImportDialog from "./ImportDialog.vue";
import {
  accountImages,
  accounts,
  accountOf,
  loadAccounts,
  refreshWorkspaceImages,
  unlockWanted,
  workspaceImages,
  type CloudAccount,
} from "../cloud";
import { adoptPersonalWorkspaces, loadWorkspaces, workspaces, persist } from "../store";
import { newId, STORAGE_LABELS, type Workspace, type WorkspaceValues } from "../types";

const props = defineProps<{ selectedId: string | null }>();
const emit = defineEmits<{ select: [id: string] }>();
const { t } = useI18n();

/** The wizard behind the "+". */
const adding = ref(false);

/** A workspace on this device: one entry in `workspaces.json`. */
function create(values: WorkspaceValues) {
  const workspace: Workspace = { id: newId(), projects: [], ...values };
  workspaces.push(workspace);
  persist();
  emit("select", workspace.id);
  adding.value = false;
}

const importing = ref(false);

function imported(workspaceId: string) {
  importing.value = false;
  emit("select", workspaceId);
}

/** One on a backend: already created there, only reloaded here. */
async function added(workspaceId: string) {
  adding.value = false;
  await loadWorkspaces();
  // Its company's picture right away, not at the next round.
  const accountId = workspaces.find((ws) => ws.id === workspaceId)?.remote?.accountId;
  if (accountId) refreshWorkspaceImages(accountId);
  emit("select", workspaceId);
}

// ---- One's own account -----------------------------------------------------
//
// At the very bottom, set apart from the workspaces: it is not one, but what
// they belong to. An account can have several organizations, and each of them
// is a workspace — signing in happens once per backend.

const showingAccounts = ref(false);

onMounted(loadAccounts);

/**
 * The tile shows initials as soon as it is clear whose account is meant — so
 * with exactly one. With several any choice would be arbitrary, and then the
 * icon is shown.
 */
const single = computed(() => (accounts.length === 1 ? accounts[0] : null));

/**
 * Whose picture and initials the tile at the bottom shows: with one account
 * that one, with several the account of the selected workspace, and with a
 * local workspace none (then the icon is shown).
 */
const shown = computed(() => {
  if (single.value) return single.value;
  const selected = workspaces.find((workspace) => workspace.id === props.selectedId);
  return selected?.remote ? accountOf(selected.remote.accountId) : null;
});

/**
 * The most urgent state across all accounts. A signed-out account weighs more
 * than a locked one: the one is solved with a password, the other stops the
 * sync entirely.
 */
const accountState = computed<"none" | "signedOut" | "locked" | "ready">(() => {
  if (accounts.length === 0) return "none";
  if (accounts.some((account) => !account.signedIn)) return "signedOut";
  if (accounts.some((account) => !account.unlocked)) return "locked";
  return "ready";
});

const accountTitle = computed(() => {
  switch (accountState.value) {
    case "none":
      return t("WorkspaceRail.signInOrCreate");
    case "signedOut":
      return single.value
        ? t("WorkspaceRail.singleSignedOut", { email: single.value.email })
        : t("WorkspaceRail.someSignedOut");
    case "locked":
      return single.value
        ? t("WorkspaceRail.singleLocked", { email: single.value.email })
        : t("WorkspaceRail.someLocked");
    default:
      return single.value
        ? t("WorkspaceRail.singleReady", { email: single.value.email, server: single.value.server })
        : t("WorkspaceRail.accountCount", { n: accounts.length });
  }
});

/**
 * The rail in blocks per account: first "This device" with the local
 * workspaces, then each account with its own — in the order of the accounts.
 *
 * By account and not by storage, because that is the question one has about a
 * tile: whom does it belong to, with which sign-in does it open. Within a
 * block the order from `workspaces.json` stays. A workspace whose account is
 * not loaded (yet) still gets its block — with what it knows about its account
 * itself. Empty blocks are dropped.
 */
type Group = {
  key: string;
  account: CloudAccount | null;
  /** Who and where, for tooltip and screen reader. */
  label: string;
  /** The account's color; header and tiles share it. */
  color?: ReturnType<typeof avatarColor>;
  items: Workspace[];
};

const groups = computed<Group[]>(() => {
  const list: Group[] = [];
  const local = workspaces.filter((workspace) => workspace.storage === "local");
  if (local.length) list.push({ key: "local", account: null, label: t("WorkspaceRail.thisDevice"), items: local });

  const ids = new Set([
    ...accounts.map((account) => account.id),
    ...workspaces.flatMap((workspace) => (workspace.remote ? [workspace.remote.accountId] : [])),
  ]);
  for (const id of ids) {
    const items = workspaces.filter((workspace) => workspace.remote?.accountId === id);
    if (!items.length) continue;
    const account = accountOf(id);
    const email = account?.email ?? items[0].remote!.email;
    const server = account?.server ?? items[0].remote!.server;
    list.push({ key: id, account, label: `${email} · ${server}`, color: avatarColor(email), items });
  }
  return list;
});

/** The dot at the account header and in the menu: signed out weighs more than locked. */
function accountDot(account: CloudAccount | null): { label: string; dot: string } | null {
  if (!account) return null;
  if (!account.signedIn) return { label: t("WorkspaceRail.signedOut"), dot: "bg-danger border-bg" };
  if (!account.unlocked) return { label: t("WorkspaceRail.locked"), dot: "bg-muted border-bg" };
  return null;
}

function accountStateText(account: CloudAccount): string {
  return accountDot(account)?.label ?? t("WorkspaceRail.ready");
}

// ---- The account menu ------------------------------------------------------
//
// At the bottom of the rail, like in Slack: all accounts at a glance, and the
// two actions one really needs — unlocking and signing in again — right next
// to them. Everything else is in the accounts dialog behind it.

const menuOpen = ref(false);

/** Signing in, new or again — the same form as in the accounts dialog. */
const signingIn = ref<{ server: string; email: string } | null>(null);

function unlockAccount(account: CloudAccount) {
  menuOpen.value = false;
  unlockWanted.value = account.id;
}

function startSignIn(account: CloudAccount | null) {
  menuOpen.value = false;
  signingIn.value = account ? { server: account.url, email: account.email } : { server: "", email: "" };
}

function manageAccounts() {
  menuOpen.value = false;
  showingAccounts.value = true;
}

async function signedIn() {
  signingIn.value = null;
  // As in the accounts dialog: the account's personal workspace shows up in
  // the rail afterwards without anyone looking for it.
  await adoptPersonalWorkspaces();
  await loadAccounts();
  await loadWorkspaces();
}

/**
 * Three states that belong visible from outside, without opening the
 * workspace: locked, has something to send, has an error. They exclude each
 * other — the most urgent wins. `dot` colors the dot in the tile's corner.
 */
function status(workspace: Workspace): { label: string; dot: string; detail?: string } | null {
  const remote = workspace.remote;
  if (remote?.error) {
    return { label: t("WorkspaceRail.syncFailed"), dot: "bg-danger border-bg", detail: remote.error };
  }
  if (remote?.conflicts?.length) {
    return {
      label: t("WorkspaceRail.conflict"),
      dot: "bg-warn border-bg",
      detail: remote.conflicts.join("\n"),
    };
  }
  if (remote?.pending) {
    return {
      label: t("WorkspaceRail.pending"),
      dot: "bg-primary border-bg",
      detail: t("WorkspaceRail.pendingDetail", { n: remote.pending }, remote.pending),
    };
  }
  // Locked is the account, not the workspace: the dot for it sits at the
  // account header, once instead of at every tile below. The tooltip still says it.
  return null;
}

/**
 * Two letters per tile: "Production" → "PR", "my-server" → "MS". A single
 * letter tells too little apart when several start with the same one.
 */
function initials(name: string): string {
  const words = name.trim().split(/[\s_-]+/).filter(Boolean);
  if (words.length === 0) return "?";
  if (words.length === 1) return words[0].slice(0, 2).toUpperCase();
  return (words[0][0] + words[1][0]).toUpperCase();
}

/** What a tile says in its tooltip — including "locked". */
function title(workspace: Workspace): string {
  if (!workspace.remote) return workspace.name;
  const where = `${STORAGE_LABELS[workspace.storage]} · ${workspace.remote.server}`;
  if (workspace.remote.locked) {
    return t("WorkspaceRail.titleLocked", { name: workspace.name, where });
  }
  return `${workspace.name} (${where})`;
}
</script>

<template>
  <nav class="rail">
    <!--
      Only the workspaces scroll. The account sits below and stays put: it is
      the one place where one signs in, and that should not depend on how far
      someone has scrolled.
    -->
    <div class="scroll">
      <!--
        One block per account, framed like a folder: at the top, round, the
        account (a person), below it, square, its workspaces, in the same color.
      -->
      <div
        v-for="group in groups"
        :key="group.key"
        class="group"
        role="group"
        :aria-label="group.label"
      >
        <OverlayBadge
          class="shrink-0"
          :label="accountDot(group.account)?.label ?? ''"
          :count="accountDot(group.account) ? undefined : 0"
          :classes="{ dot: accountDot(group.account)?.dot }"
        >
          <Avatar
            v-if="group.account || group.key !== 'local'"
            size="sm"
            :name="group.account?.name || group.label"
            :src="group.account ? accountImages[group.account.id] : undefined"
            :color="group.color"
            :title="group.account ? `${group.label} — ${accountStateText(group.account)}` : group.label"
          />
          <Avatar v-else size="sm" :icon="Laptop" :title="group.label" :aria-label="group.label" />
        </OverlayBadge>

        <!--
          No state, no dot: `count` 0 shows nothing. What used to hang as a
          tooltip on the dot itself is now part of the tile's tooltip — the
          library's dot does not take a pointer.
        -->
        <OverlayBadge
          v-for="ws in group.items"
          :key="ws.id"
          class="shrink-0"
          :label="status(ws)?.label ?? ''"
          :count="status(ws) ? undefined : 0"
          :classes="{ dot: status(ws)?.dot }"
        >
          <Avatar
            as="button"
            class="p-0"
            :name="ws.name"
            :initials="initials(ws.name)"
            :src="workspaceImages[ws.id]"
            shape="square"
            :color="group.color"
            :class="{ 'ring-2 ring-primary ring-inset': ws.id === props.selectedId, remote: !!ws.remote }"
            :title="status(ws)?.detail ? `${title(ws)}\n${status(ws)?.detail}` : title(ws)"
            @click="emit('select', ws.id)"
          />
        </OverlayBadge>
      </div>

      <IconButton
        class="add"
        :icon="Plus"
        :label="t('WorkspaceRail.addWorkspace')"
        variant="outline"
        shape="rounded"
        :title="t('WorkspaceRail.addWorkspace')"
        @click="adding = true"
      />
    </div>

    <!--
      Set apart by a line: the account is not a workspace, but what they
      belong to.
    -->
    <span class="divider"></span>

    <!-- Without an account there is nothing to list: then straight to signing in. -->
    <OverlayBadge
      class="shrink-0"
      :label="
        accountState === 'signedOut'
          ? t('WorkspaceRail.signedOut')
          : accountState === 'locked'
            ? t('WorkspaceRail.locked')
            : ''
      "
      :count="accountState === 'signedOut' || accountState === 'locked' ? undefined : 0"
      :classes="{ dot: accountState === 'locked' ? 'bg-muted border-bg' : 'border-bg' }"
    >
      <Avatar
        v-if="accountState === 'none'"
        as="button"
        class="p-0"
        :icon="User"
        variant="outline"
        :title="accountTitle"
        :aria-label="accountTitle"
        @click="startSignIn(null)"
      />
      <Popover v-else v-model:open="menuOpen" placement="right">
        <PopoverTrigger>
          <!-- Signed in and unlocked: then it is an account and not a prompt. -->
          <Avatar
            as="button"
            class="p-0"
            :name="shown ? shown.name || shown.email : undefined"
            :src="shown ? accountImages[shown.id] : undefined"
            :icon="User"
            :color="shown ? avatarColor(shown.email) : undefined"
            :variant="accountState === 'ready' ? 'soft' : 'outline'"
            :title="accountTitle"
            :aria-label="accountTitle"
          />
        </PopoverTrigger>
        <PopoverContent :title="t('WorkspaceRail.accounts', accounts.length)" class="w-96">
          <ul class="accounts">
            <li v-for="account in accounts" :key="account.id" class="account">
              <OverlayBadge
                class="shrink-0"
                :label="accountDot(account)?.label ?? ''"
                :count="accountDot(account) ? undefined : 0"
                :classes="{ dot: accountDot(account)?.dot }"
              >
                <Avatar
                  size="sm"
                  :name="account.name || account.email"
                  :src="accountImages[account.id]"
                  :color="avatarColor(account.email)"
                />
              </OverlayBadge>
              <span class="who">
                <span class="email">{{ account.email }}</span>
                <span class="where">{{ account.server }} · {{ accountStateText(account) }}</span>
              </span>
              <Button
                v-if="!account.signedIn"
                size="sm"
                variant="outline"
                @click="startSignIn(account)"
              >
                {{ t("WorkspaceRail.signIn") }}
              </Button>
              <Button
                v-else-if="!account.unlocked"
                size="sm"
                variant="outline"
                @click="unlockAccount(account)"
              >
                {{ t("WorkspaceRail.unlock") }}
              </Button>
            </li>
          </ul>
          <div class="menu-actions">
            <Button variant="text" size="sm" :leading-icon="Plus" @click="startSignIn(null)">
              {{ t("WorkspaceRail.addAccount") }}
            </Button>
            <Button variant="text" size="sm" :leading-icon="Settings" @click="manageAccounts">
              {{ t("WorkspaceRail.manageAccounts") }}
            </Button>
          </div>
        </PopoverContent>
      </Popover>
    </OverlayBadge>

    <AccountsDialog v-if="showingAccounts" @close="showingAccounts = false" />

    <!-- A new account through the wizard, a known one with just the password. -->
    <AccountWizard
      v-if="signingIn && !signingIn.server"
      @done="signedIn"
      @cancel="signingIn = null"
    />
    <AccountDialog
      v-else-if="signingIn"
      storage="customBackend"
      :initial-server="signingIn.server"
      :initial-email="signingIn.email"
      @done="signedIn"
      @cancel="signingIn = null"
    />

    <WorkspaceWizard
      v-if="adding"
      @create="create"
      @added="added"
      @import="
        adding = false;
        importing = true;
      "
      @cancel="adding = false"
    />
    <ImportDialog v-if="importing" @imported="imported" @cancel="importing = false" />
  </nav>
</template>

<style scoped>
.rail {
  width: 4rem;
  flex: 0 0 4rem;
  background: var(--rail);
  /* Rail and content share the background in this theme; the line keeps them apart. */
  border-right: 1px solid var(--border);
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 0.5rem;
  padding: 0.75rem 0;
  /* The rail itself no longer scrolls — only its upper half. */
  overflow: hidden;
}

.scroll {
  flex: 1;
  /* Without this a flex item grows past its content instead of scrolling —
     the default minimum size is `auto`. */
  min-height: 0;
  width: 100%;
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 0.5rem;
  overflow-y: auto;
  overflow-x: hidden;
  /* Room for the tiles' focus ring, which `overflow` would otherwise clip. */
  padding: 0.25rem 0;
}

.add {
  flex: 0 0 auto;
}

/* Like a folder: a frame holds account and workspaces together. */
.group {
  flex: 0 0 auto;
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 0.375rem;
  padding: 0.375rem 0.25rem;
  border: 1px solid var(--color-line);
  border-radius: 14px;
}

.accounts {
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
  margin: 0;
  padding: 0;
  list-style: none;
}

.account {
  display: flex;
  align-items: center;
  gap: 0.75rem;
}

.who {
  display: flex;
  flex-direction: column;
  flex: 1;
  min-width: 0;
}

.email {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.where {
  font-size: 0.75rem;
  color: var(--color-muted);
}

.menu-actions {
  display: flex;
  flex-direction: column;
  align-items: flex-start;
  margin-top: 0.75rem;
  padding-top: 0.5rem;
  border-top: 1px solid var(--color-line);
}

.divider {
  flex: 0 0 auto;
  width: 1.75rem;
  height: 1px;
  background: var(--border);
}

</style>
