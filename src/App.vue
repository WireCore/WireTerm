<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from "vue";
import { invoke } from "@tauri-apps/api/core";
import { getVersion } from "@tauri-apps/api/app";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import WorkspaceRail from "./components/WorkspaceRail.vue";
import WorkspaceOverview from "./components/WorkspaceOverview.vue";
import ConnectionPane from "./components/ConnectionPane.vue";
import SshTerminal from "./components/SshTerminal.vue";
import SecretDialog from "./components/SecretDialog.vue";
import HostKeyDialog from "./components/HostKeyDialog.vue";
import McpConfirmDialog from "./components/McpConfirmDialog.vue";
import VaultAccountDialog from "./components/VaultAccountDialog.vue";
import BitwardenUnlockDialog from "./components/BitwardenUnlockDialog.vue";
import MasterPasswordDialog from "./components/MasterPasswordDialog.vue";
import LocalVaultDialog from "./components/LocalVaultDialog.vue";
import TabBar from "./components/TabBar.vue";
import UpdateBanner from "./components/UpdateBanner.vue";
import { availableUpdate, checkForUpdates, checkState } from "./updates";
import { EmptyState, LocaleProvider } from "@wirecore/wirelayer-vue";
import { useVaults, vaultProblem } from "./vault";
import { useI18n } from "vue-i18n";
import { intlLocale } from "./i18n";
import { answerSecret, SECRET_EVENT } from "./remote";
import { checkSessions, trustHost, unlockWanted } from "./cloud";
import { localVaultStatus, type LocalVaultStatus } from "./local-vault";
import { terminals } from "./terminals";
import { answerConfirmation, confirmations, listenForMcp } from "./mcp";
import {
  adoptPersonalWorkspaces,
  findConnection,
  initialWorkspaceId,
  loadWorkspaces,
  persist,
  rememberTabs,
  rememberWorkspace,
  rememberedTabs,
  startSyncing,
  withJumps,
  stopSyncing,
  syncNow,
  workspaces,
} from "./store";
import {
  newId,
  targetLabel,
  type Connection,
  type HostKeyPrompt,
  type LocalShell,
  type RemoteSystem,
  type SecretPrompt,
  type Tab,
  type TabStatus,
  type TabView,
  type Workspace,
} from "./types";

const { t } = useI18n();

/** The installed version, small at the bottom right of the window. */
const version = ref("");
getVersion().then((v) => (version.value = v), () => undefined);

/**
 * A click on the version checks for updates. Its answer stands next to it for
 * a few seconds; an update itself shows as the banner, as always.
 */
const asked = ref(false);
let askedTimer: ReturnType<typeof setTimeout> | undefined;
async function checkFromVersion() {
  clearTimeout(askedTimer);
  asked.value = true;
  await checkForUpdates();
  askedTimer = setTimeout(() => (asked.value = false), 8000);
}
const versionStatus = computed(() => {
  if (!asked.value) return "";
  if (checkState.checking) return t("Updates.checking");
  if (checkState.result === "failed") return t("Updates.failed");
  if (checkState.result === "available") {
    return t("Updates.available", { version: availableUpdate.value?.version ?? "" });
  }
  return t("Updates.current");
});

const workspaceId = ref<string | null>(null);

const tabs = ref<Tab[]>([]);
/** Reported by whichever half of a tab knows, drawn as the dot in its tab. */
const statuses = ref<Record<string, TabStatus>>({});
/** null = the overview tab. */
const activeTabId = ref<string | null>(null);

const workspace = computed(() => workspaces.find((w) => w.id === workspaceId.value) ?? null);

/**
 * Tabs whose connection still exists, paired with it. A local terminal has no
 * connection and stays until it is closed.
 */
const liveTabs = computed(() =>
  tabs.value.flatMap((tab): { tab: Tab; connection: Connection | null }[] => {
    if (tab.local) return [{ tab, connection: null }];
    const connection = findConnection(tab.connectionId);
    return connection ? [{ tab, connection }] : [];
  }),
);

function selectWorkspace(id: string) {
  workspaceId.value = id;
  rememberWorkspace(id);
}

// ---- Vault accounts --------------------------------------------------------
//
// Both accounts belong to the workspace, so the backend has to be told
// whenever a different one comes to the front — and again when either is
// edited, which is why the accounts themselves are watched and not just the
// workspace id.

watch(
  () => [workspace.value?.onePasswordAccount, workspace.value?.bitwarden],
  () => useVaults(workspace.value),
  { immediate: true, deep: true },
);

/** The answer to the account question, saved where it came from. */
function saveVaultAccount(values: Partial<Workspace>) {
  if (!workspace.value) return;
  Object.assign(workspace.value, values);
  persist();
  vaultProblem.value = null;
}

// ---- Host-Key --------------------------------------------------------------

/**
 * Unanswered host-key questions, oldest first. A queue rather than a single
 * slot: two tabs can be opened at once, and each connection waits for its own
 * answer before it goes anywhere.
 */
const hostKeyQueue = ref<HostKeyPrompt[]>([]);
let unlistenHostKey: UnlistenFn | undefined;
let unlistenMcp: UnlistenFn | undefined;

function answerHostKey(trust: boolean) {
  const prompt = hostKeyQueue.value.shift();
  if (!prompt) return;
  // Nothing to do on failure: the connection is waiting on this answer and
  // will time out on its own if it never arrives.
  invoke("ssh_host_key_answer", { id: prompt.id, trust }).catch(() => {});

  // In a workspace on a backend the answer belongs to the workspace and not to
  // this device: otherwise every team member answers the same question on their
  // own, and by the fifth repetition nobody reads it any more.
  const remote = workspace.value?.remote;
  if (trust && remote && prompt.publicKey) {
    void trustHost(
      workspace.value!.id,
      prompt.host,
      prompt.port,
      prompt.algorithm,
      prompt.publicKey,
    );
  }
}

// ---- Master password -------------------------------------------------------
//
// Two paths lead to the same dialog: a locked workspace that someone opens,
// and the quarter of an hour after which the vault closes by itself. That is
// why it is a variable and not an event.

/** The account whose master password is to be changed. */
const changingMaster = ref<string | null>(null);

/**
 * Asks for the master password as soon as a locked workspace comes to the
 * front.
 *
 * Not for all of them at startup: someone with three workspaces on two
 * backends would otherwise get two dialogs in a row before seeing anything.
 */
watch(
  () => [workspaceId.value, workspace.value?.remote?.locked] as const,
  ([, locked]) => {
    const remote = workspace.value?.remote;
    if (locked && remote) unlockWanted.value = remote.accountId;
  },
  { immediate: true },
);

/** Puts the question off. The workspace stays visible, just locked. */
function dismissUnlock() {
  unlockWanted.value = null;
}

async function masterDone() {
  unlockWanted.value = null;
  changingMaster.value = null;
  // Unlocked means: the ciphertexts can be opened now. The tree on the screen
  // does not know that yet.
  await loadWorkspaces();
}

// ---- Secrets ---------------------------------------------------------------

/**
 * Unanswered questions, oldest first — a queue for the same reason the
 * host-key one is: two tabs can be opened at once, and each connection waits
 * on its own answer.
 *
 * Only connections whose credential source is "ask when connecting" ever
 * land here, whether what they need is an FTP password or an S3 secret access
 * key. Every other source is read without asking anyone.
 */
const secretQueue = ref<SecretPrompt[]>([]);
let unlistenSecret: UnlistenFn | undefined;

function answerSecretQuestion(secret: string | null) {
  const prompt = secretQueue.value.shift();
  if (!prompt) return;
  // Nothing to do on failure: the connection is waiting on this answer and
  // will time out on its own if it never arrives.
  answerSecret(prompt.id, secret).catch(() => {});
}

/** Every click opens its own tab: the same host twice is a normal thing to want. */
function openConnection(connection: Connection) {
  const tab: Tab = { id: newId(), connectionId: connection.id };
  tabs.value.push(tab);
  statuses.value[tab.id] = "connecting";
  activeTabId.value = tab.id;
}

/** A local terminal — also its own tab every time. */
function openLocal(shell: LocalShell) {
  const tab: Tab = { id: newId(), connectionId: "", local: shell };
  tabs.value.push(tab);
  statuses.value[tab.id] = "connecting";
  activeTabId.value = tab.id;
}

// ---- Side by side --------------------------------------------------------------
//
// Up to four tabs on screen at once, as tiles. The panes stay where they are —
// only their position changes — so no terminal has to be rebuilt for it.
// Picking a tab outside the group shows only that one again; back to one from
// the group, and the group is back.

const MAX_SPLIT = 4;
const split = ref<string[]>([]);

const splitShown = computed(
  () => split.value.length > 1 && activeTabId.value !== null && split.value.includes(activeTabId.value),
);

function inSplit(id: string): boolean {
  return splitShown.value && split.value.includes(id);
}

function visible(id: string): boolean {
  return activeTabId.value === id || inSplit(id);
}

function toggleSplit() {
  if (split.value.length) {
    split.value = [];
    terminals.broadcast = false;
    return;
  }
  const ids = liveTabs.value.map(({ tab }) => tab.id);
  const start = Math.max(0, ids.indexOf(activeTabId.value ?? ""));
  split.value = [...ids.slice(start), ...ids.slice(0, start)].slice(0, MAX_SPLIT);
  if (!split.value.includes(activeTabId.value ?? "")) activeTabId.value = split.value[0] ?? null;
  // Restored tabs would otherwise only connect once they are in front.
  for (const tab of tabs.value) {
    if (split.value.includes(tab.id) && tab.waiting) {
      tab.waiting = false;
      statuses.value[tab.id] = "connecting";
    }
  }
}

// A closed tab leaves the group; with only one left it is no group.
watch(liveTabs, (live) => {
  const ids = new Set(live.map(({ tab }) => tab.id));
  const left = split.value.filter((id) => ids.has(id));
  if (left.length !== split.value.length) split.value = left.length > 1 ? left : [];
  if (!split.value.length) terminals.broadcast = false;
});

watch(split, (ids) => (terminals.group = [...ids]), { immediate: true });

/** The position of a tile: two or three side by side, four as 2 × 2. */
function tileStyle(id: string) {
  if (!inSplit(id)) return undefined;
  const count = split.value.length;
  const cols = count === 4 ? 2 : count;
  const rows = count === 4 ? 2 : 1;
  const index = split.value.indexOf(id);
  return {
    inset: "auto",
    left: `${((index % cols) * 100) / cols}%`,
    top: `${(Math.floor(index / cols) * 100) / rows}%`,
    width: `${100 / cols}%`,
    height: `${100 / rows}%`,
  };
}

// ---- Tabs across a restart ---------------------------------------------------

watch(
  [tabs, activeTabId],
  () => {
    // Not local terminals: a shell cannot be picked up again, and an empty tab
    // with "Restart" gains nothing.
    const kept = tabs.value.filter((tab) => !tab.local);
    const active = kept.findIndex((tab) => tab.id === activeTabId.value);
    rememberTabs({
      connectionIds: kept.map((tab) => tab.connectionId),
      active: active < 0 ? null : active,
    });
  },
  { deep: true },
);

/** A restored tab connects as soon as it is in front for the first time. */
watch(activeTabId, (id) => {
  const tab = tabs.value.find((entry) => entry.id === id);
  if (tab?.waiting) {
    tab.waiting = false;
    statuses.value[tab.id] = "connecting";
  }
});

function restoreTabs() {
  const open = rememberedTabs();
  for (const connectionId of open.connectionIds) {
    const tab: Tab = { id: newId(), connectionId, waiting: true };
    tabs.value.push(tab);
    statuses.value[tab.id] = "closed";
  }
  if (open.active !== null && open.active >= 0) activeTabId.value = tabs.value[open.active]?.id ?? null;
}

/**
 * Closing a tab ends its session: removing it unmounts the terminal, whose
 * `onBeforeUnmount` disconnects.
 */
function closeTab(id: string) {
  const index = tabs.value.findIndex((t) => t.id === id);
  if (index < 0) return;
  tabs.value.splice(index, 1);
  delete statuses.value[id];
  if (activeTabId.value === id) {
    activeTabId.value = tabs.value[index]?.id ?? tabs.value[index - 1]?.id ?? null;
  }
}

/**
 * Written onto the connection, because the overview shows it on cards whose
 * target is not currently open. Refreshed on every connect: a target that was
 * upgraded meanwhile should not keep advertising its old version.
 */
function rememberSystem(connectionId: string, system: RemoteSystem) {
  const connection = findConnection(connectionId);
  if (!connection) return;
  connection.system = system;
  persist();
}

/**
 * What the tab bar draws. Derived rather than stored, so renaming a connection
 * or changing its host shows up on its tabs straight away.
 */
const tabViews = computed<TabView[]>(() =>
  liveTabs.value.map(({ tab, connection }) => ({
    id: tab.id,
    name: connection ? connection.name : (tab.local?.name ?? ""),
    target: connection ? targetLabel(connection.settings) : t("common.local"),
    status: statuses.value[tab.id] ?? "connecting",
  })),
);

/**
 * The device key, when it does not open by itself — on Linux without a
 * keyring, or when the keyring is not answering right now. Until then
 * everything else runs; only stored credentials arrive empty.
 */
const vaultQuestion = ref<LocalVaultStatus | null>(null);

async function vaultOpened() {
  vaultQuestion.value = null;
  // Now the credentials open — and with them the sessions with a backend that
  // lay locked in the accounts file until now.
  await loadWorkspaces();
  await checkSessions().catch(() => []);
}

onMounted(async () => {
  const vault = await localVaultStatus().catch(() => null);
  if (vault && vault.state !== "ready") vaultQuestion.value = vault;

  unlistenHostKey = await listen<HostKeyPrompt>("ssh:host-key", (event) => {
    hostKeyQueue.value.push(event.payload);
  });
  unlistenSecret = await listen<SecretPrompt>(SECRET_EVENT, (event) => {
    secretQueue.value.push(event.payload);
  });
  unlistenMcp = await listenForMcp();
  await loadWorkspaces();
  workspaceId.value = initialWorkspaceId();
  restoreTabs();

  // Check the sessions first, then sync: a session that is no longer valid
  // should show up as a request to sign in and not as an error banner over
  // every remote workspace.
  await checkSessions().catch(() => []);
  // "Personal" exists on the backend as soon as the account does — also for an
  // account that signed in here long ago.
  await adoptPersonalWorkspaces();
  if (workspaces.some((entry) => entry.remote)) {
    await syncNow();
    workspaceId.value = initialWorkspaceId();
  }
  startSyncing();
});

onUnmounted(() => {
  unlistenHostKey?.();
  unlistenSecret?.();
  unlistenMcp?.();
  stopSyncing();
});
</script>

<template>
  <!-- WireLayer's built-in texts (Close, Show password, Search …) in the UI language. -->
  <LocaleProvider :locale="intlLocale">
    <div class="app">
      <WorkspaceRail :selected-id="workspaceId" @select="selectWorkspace" />

      <div class="main">
        <UpdateBanner />
        <TabBar
          :tabs="tabViews"
          :active-id="activeTabId"
          :workspace="workspace"
          :split="split.length > 1"
          :broadcast="terminals.broadcast"
          @select="activeTabId = $event"
          @close="closeTab"
          @open="openConnection"
          @local="openLocal"
          @split="toggleSplit"
          @broadcast="terminals.broadcast = !terminals.broadcast"
        />

        <div class="content">
          <!--
            Tabs stay mounted while another is in front: unmounting one would
            drop its connection, along with the terminal and any transfer
            running in its file browser.
          -->
          <!-- `pane-…`: what the tab bar's tabs point at (aria-controls). -->
          <div
            v-for="{ tab, connection } in liveTabs"
            v-show="visible(tab.id)"
            :id="`pane-${tab.id}`"
            :key="tab.id"
            class="pane"
            :class="{
              tile: inSplit(tab.id),
              focused: inSplit(tab.id) && activeTabId === tab.id,
              broadcast: inSplit(tab.id) && terminals.broadcast,
            }"
            :style="tileStyle(tab.id)"
            role="tabpanel"
            @pointerdown="inSplit(tab.id) && (activeTabId = tab.id)"
          >
            <!--
              Keyed on the type as well as the tab, so a connection edited from
              one protocol to the other is rebuilt rather than left with a pane
              talking to a session the backend no longer has.
            -->
            <SshTerminal
              v-if="tab.local"
              :session-id="tab.id"
              connection-id=""
              :local="tab.local"
              :active="visible(tab.id)"
              @status="statuses[tab.id] = $event"
            />
            <ConnectionPane
              v-else-if="!tab.waiting && connection"
              :key="connection.settings.type"
              :session-id="tab.id"
              :connection-id="connection.id"
              :settings="withJumps(connection.settings)"
              :active="visible(tab.id)"
              @status="statuses[tab.id] = $event"
              @system="rememberSystem(connection.id, $event)"
            />
          </div>

          <!-- Behind the overview, which scrolls over it. -->
          <div v-show="activeTabId === null" class="honeycomb" aria-hidden="true"></div>

          <div
            v-show="activeTabId === null"
            id="pane-overview"
            class="pane scroll"
            role="tabpanel"
          >
            <WorkspaceOverview
              v-if="workspace"
              :workspace="workspace"
              @open="openConnection"
              @removed="workspaceId = initialWorkspaceId()"
              @change-master="changingMaster = $event"
            />

            <EmptyState
              v-else
              class="placeholder"
              :title="t('App.noWorkspace')"
              :description="t('App.noWorkspaceHint')"
            />
          </div>
        </div>
      </div>

      <button
        v-if="version"
        type="button"
        class="version"
        :title="t('Updates.check')"
        :disabled="checkState.checking"
        @click="checkFromVersion"
      >
        WireTerm {{ version }}<template v-if="versionStatus"> · {{ versionStatus }}</template>
      </button>

      <!--
        Both of these belong to the window rather than to a tab: the question
        comes from the backend and may just as well have been raised by a
        connection test in a dialog as by a terminal.
      -->
      <!-- Keyed, so every question gets its own wait before "Run". -->
      <McpConfirmDialog
        v-if="confirmations[0]"
        :key="confirmations[0].id"
        :request="confirmations[0]"
        @answer="answerConfirmation"
      />

      <HostKeyDialog
        v-if="hostKeyQueue[0]"
        :key="hostKeyQueue[0].id"
        :prompt="hostKeyQueue[0]"
        @answer="answerHostKey"
      />

      <SecretDialog
        v-if="secretQueue[0]"
        :key="secretQueue[0].id"
        :prompt="secretQueue[0]"
        @answer="answerSecretQuestion"
      />

      <LocalVaultDialog
        v-if="vaultQuestion"
        :status="vaultQuestion"
        @done="vaultOpened"
        @skip="vaultQuestion = null"
      />

      <!--
        Two answers to "the vault gives nothing out": a missing account is a
        setting and is saved, a locked vault is a password and is not. Which one
        is on screen follows from what the backend reported.
      -->
      <VaultAccountDialog
        v-if="vaultProblem?.kind === 'account' && workspace"
        :workspace="workspace"
        :provider="vaultProblem.provider"
        :reason="vaultProblem.reason"
        @save="saveVaultAccount"
        @cancel="vaultProblem = null"
      />

      <BitwardenUnlockDialog
        v-if="vaultProblem?.kind === 'unlock' && workspace?.bitwarden"
        :account="workspace.bitwarden"
        :reason="vaultProblem.reason"
        :two-factor="vaultProblem.twoFactor"
        @done="vaultProblem = null"
        @cancel="vaultProblem = null"
      />

      <!--
        The master password of a backend account — not to be confused with the
        one of the Bitwarden vault above. One opens this workspace's
        credentials, the other a third-party vault; they have nothing to do
        with each other except the word.

        "Change" wins when both are pending: whoever is about to change it has
        the old one at hand and does not need to unlock first.
      -->
      <MasterPasswordDialog
        v-if="changingMaster"
        :key="`change-${changingMaster}`"
        :account-id="changingMaster"
        start="change"
        @done="masterDone"
        @cancel="changingMaster = null"
      />

      <MasterPasswordDialog
        v-else-if="unlockWanted"
        :key="`unlock-${unlockWanted}`"
        :account-id="unlockWanted"
        @done="masterDone"
        @cancel="dismissUnlock"
      />
    </div>
  </LocaleProvider>
</template>

<style>
/* In the base layer so WireLayer's component classes win over these element defaults. */
@layer base {
/*
  The app's own names for the WireLayer theme tokens, so the parts built here
  (tab bar, file list, cards, rail) follow the same theme as the components.
*/
:root {
  --bg: var(--color-bg);
  --rail: var(--color-bg);
  --panel: var(--color-bg-2);
  --card: var(--color-card);
  --border: var(--color-line);
  --fg: var(--color-fg);
  --muted: var(--color-muted);
  --accent: var(--color-primary);
  /* Selection and hover: a step above the line, as the components do it. */
  --accent-dim: var(--color-line-2);
  --ok: var(--color-success);
  --warn: var(--color-warn);
  --danger: var(--color-danger);

  font-family: var(--font-sans);
  color: var(--fg);
  background: var(--bg);
  color-scheme: dark;
}

html,
body,
#app {
  height: 100%;
  margin: 0;
}

/*
  The text size of the app; the root stays at 16px, because WireLayer's sizes
  are in rem and would all shrink with it.
*/
body {
  font-size: 14px;
}

h2 {
  margin: 0;
  font-size: 1rem;
}

/*
  The few buttons still built here (tabs, column heads, theme tiles) style
  themselves; this only keeps the pointer Tailwind's reset takes away.
*/
button:not(:disabled) {
  cursor: pointer;
}

/*
  Scrollbars in the theme instead of the system's grey ones: a slim rounded
  thumb on a transparent track, a step brighter under the pointer. The border
  keeps the thumb off the edge. Not `scrollbar-color`/`scrollbar-width`: in
  Chromium (WebView2) they would switch these off.
*/
::-webkit-scrollbar {
  width: 10px;
  height: 10px;
}

::-webkit-scrollbar-track,
::-webkit-scrollbar-corner {
  background: transparent;
}

::-webkit-scrollbar-thumb {
  background-color: var(--color-line-2);
  background-clip: padding-box;
  border: 2px solid transparent;
  border-radius: 999px;
}

::-webkit-scrollbar-thumb:hover {
  background-color: var(--color-muted);
}

::-webkit-scrollbar-button {
  display: none;
}
}
</style>

<style scoped>
.app {
  position: relative;
  display: flex;
  height: 100%;
  overflow: hidden;
}

/* Above the panes; a click on it checks for updates. */
.version {
  position: absolute;
  right: 6px;
  bottom: 2px;
  z-index: 1;
  padding: 0;
  border: 0;
  background: none;
  font: inherit;
  font-size: 10px;
  color: var(--muted);
  opacity: 0.8;
  cursor: pointer;
  user-select: none;
}

.version:hover,
.version:focus-visible {
  opacity: 1;
  text-decoration: underline;
}

.version:disabled {
  cursor: progress;
}

.main {
  flex: 1;
  min-width: 0;
  display: flex;
  flex-direction: column;
}

.content {
  flex: 1;
  min-height: 0;
  position: relative;
}

.pane {
  position: absolute;
  inset: 0;
}

.pane.scroll {
  overflow-y: auto;
}

.pane.tile {
  box-sizing: border-box;
  border: 1px solid var(--border);
}

.pane.tile.focused {
  border-color: var(--accent);
}

.pane.tile.broadcast {
  border-color: var(--warn);
}

/*
  Wirecore's honeycomb pattern, subtly behind the overview: just visible at the
  bottom right, fading towards the top left. A layer of its own that does not
  scroll along.

  The fade is a mask on the lines, not a gradient over the area: that dark, a
  gradient would have ended in visible steps. The tile is shifted by a quarter
  honeycomb so that no edge lies on its border — seams would appear there —,
  and has a whole-number size (166 instead of 166.28 px).
*/
.honeycomb {
  position: absolute;
  inset: 0;
  pointer-events: none;
  background: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 166.28 288' width='166' height='288' preserveAspectRatio='none'%3E%3Cpath d='M124.71 0L41.57 48L-41.57 0M207.85 48L124.71 0M41.57 48V144L-41.57 192M207.85 144L124.71 192L41.57 144M124.71 192V288L41.57 336M207.85 336L124.71 288' fill='none' stroke='white' stroke-opacity='0.04'/%3E%3C/svg%3E")
    0 0 / 166px 288px;
  mask-image: linear-gradient(to bottom right, transparent 25%, black 95%);
}

.placeholder {
  margin-top: 25vh;
}
</style>
