<script setup lang="ts">
import { computed, nextTick, ref } from "vue";
import { invoke } from "@tauri-apps/api/core";
import { useI18n } from "vue-i18n";
import { IconButton, Input, Tabs, TabsList, TabsTrigger } from "@wirecore/wirelayer-vue";
import { Columns2, Plus, Radio, SquareTerminal } from "@lucide/vue";
import ConnectionLeaf from "./ConnectionLeaf.vue";
import { filterBookmarks, filterProjects } from "../search";
import { toggleBookmark } from "../store";
import type { Connection, LocalShell, TabStatus, TabView, Workspace } from "../types";

const props = defineProps<{
  tabs: TabView[];
  activeId: string | null;
  workspace: Workspace | null;
  /** Whether the split view is up, and whether input goes to all of it. */
  split: boolean;
  broadcast: boolean;
}>();

const { t } = useI18n();

/** A tab's state in words, under `TabBar.status.<status>`. */
function statusTitle(status: TabStatus): string {
  return t(`TabBar.status.${status}`);
}

const emit = defineEmits<{
  select: [id: string | null];
  close: [id: string];
  open: [connection: Connection];
  /** A local terminal with this shell. */
  local: [shell: LocalShell];
  split: [];
  broadcast: [];
}>();

/**
 * The overview has no tab id of its own (`null`); the tab list needs a value
 * for it. The panels live in App.vue, `pane-…` is their id there.
 */
const OVERVIEW = "overview";

const selected = computed({
  get: () => props.activeId ?? OVERVIEW,
  set: (value: string | null) => emit("select", value === OVERVIEW ? null : value),
});

const picking = ref(false);
const query = ref("");
const queryInput = ref<InstanceType<typeof Input>>();

const hasConnections = computed(() =>
  (props.workspace?.projects ?? []).some((p) => p.connections.length > 0),
);

/** The tree, searched and alphabetical — the same view the overview draws. */
const branches = computed(() => filterProjects(props.workspace?.projects ?? [], query.value));

/** Pulled out above the tree; a connection appears in both, by design. */
const bookmarks = computed(() => filterBookmarks(props.workspace?.projects ?? [], query.value));

const empty = computed(() => branches.value.length === 0 && bookmarks.value.length === 0);

async function openMenu() {
  picking.value = !picking.value;
  if (!picking.value) return;
  // Reopening starts fresh rather than on the last search.
  query.value = "";
  void loadShells();
  await nextTick();
  queryInput.value?.focus();
}

// ---- Local -----------------------------------------------------------------------
//
// This machine's shells, looked up afresh on every opening — a WSL distribution
// installed a moment ago should show up without a restart. Plus a freely typed
// command; the last one stays.

const LAST_COMMAND_KEY = "wireterm.localCommand";

const shells = ref<LocalShell[]>([]);
const command = ref(readLastCommand());
const commandError = ref("");

function readLastCommand(): string {
  try {
    return localStorage.getItem(LAST_COMMAND_KEY) ?? "";
  } catch {
    return "";
  }
}

async function loadShells() {
  shells.value = await invoke<LocalShell[]>("local_shells").catch(() => []);
}

function pickShell(shell: LocalShell) {
  picking.value = false;
  emit("local", shell);
}

async function runCommand() {
  commandError.value = "";
  try {
    const shell = await invoke<LocalShell>("local_custom_shell", { command: command.value });
    try {
      localStorage.setItem(LAST_COMMAND_KEY, command.value.trim());
    } catch {
      // Without storage the command is simply not there next time.
    }
    pickShell(shell);
  } catch (e) {
    commandError.value = String(e);
  }
}

function pick(connection: Connection) {
  picking.value = false;
  emit("open", connection);
}
</script>

<template>
  <div class="tabbar">
    <!--
      The panels are App.vue's, kept mounted with v-show: `controls` points
      each tab at its pane there. Delete on a focused tab closes it, as the
      × does.
    -->
    <Tabs v-model="selected" :label="t('TabBar.openConnections')" class="tabs">
      <TabsList scrollable>
        <TabsTrigger :value="OVERVIEW" controls="pane-overview">{{ t("TabBar.overview") }}</TabsTrigger>
        <TabsTrigger
          v-for="tab in tabs"
          :key="tab.id"
          :value="tab.id"
          :controls="`pane-${tab.id}`"
          closable
          class="tab"
          :title="`${tab.name} – ${tab.target} (${statusTitle(tab.status)})`"
          @close="emit('close', tab.id)"
        >
          <span class="dot" :class="tab.status"></span>
          <span class="label">
            <span class="name">{{ tab.name }}</span>
            <span class="sep">–</span>
            <span class="target">{{ tab.target }}</span>
          </span>
        </TabsTrigger>
      </TabsList>
    </Tabs>

    <div class="plus-wrap">
      <IconButton
        :icon="Plus"
        :label="t('TabBar.openConnection')"
        :title="t('TabBar.openConnection')"
        variant="text"
        size="sm"
        class="plus"
        :class="{ open: picking }"
        :aria-expanded="picking"
        @click="openMenu"
      />

      <!-- Click-away layer, so the tree closes without a global listener. -->
      <div v-if="picking" class="away" @click="picking = false"></div>

      <div v-if="picking" class="tree" @keydown.esc="picking = false">
        <p class="tree-head">{{ t("TabBar.newConnection") }}</p>

        <Input
          ref="queryInput"
          v-model="query"
          class="tree-search"
          size="sm"
          type="text"
          :placeholder="t('TabBar.search')"
          :aria-label="t('TabBar.searchLabel')"
          @keydown.esc.stop="query ? (query = '') : (picking = false)"
        />

        <div class="branch local">
          <p class="branch-name">{{ t("TabBar.local") }}</p>
          <button
            v-for="shell in shells"
            :key="shell.id"
            type="button"
            class="shell"
            :title="[shell.program, ...shell.args].join(' ')"
            @click="pickShell(shell)"
          >
            <SquareTerminal :size="14" aria-hidden="true" />
            {{ shell.name }}
          </button>
          <form class="command" @submit.prevent="runCommand">
            <Input
              v-model="command"
              size="sm"
              type="text"
              spellcheck="false"
              :placeholder="t('TabBar.commandPlaceholder')"
              :aria-label="t('TabBar.commandLabel')"
              @keydown.esc.stop="picking = false"
            />
          </form>
          <p v-if="commandError" class="command-error">{{ commandError }}</p>
        </div>

        <p v-if="!workspace" class="empty">{{ t("TabBar.noWorkspace") }}</p>
        <p v-else-if="!hasConnections" class="empty">
          {{ t("TabBar.noConnections", { name: workspace.name }) }}
        </p>
        <p v-else-if="empty" class="empty">{{ t("TabBar.noMatches", { query: query.trim() }) }}</p>

        <template v-else>
          <!--
            The shortlist. A bookmarked connection is deliberately here *and*
            in its project below: this is a shortcut, not a move.
          -->
          <div v-if="bookmarks.length" class="branch pinned">
            <p class="branch-name">{{ t("TabBar.bookmarked") }}</p>
            <ConnectionLeaf
              v-for="connection in bookmarks"
              :key="connection.id"
              :connection="connection"
              @pick="pick(connection)"
              @bookmark="toggleBookmark(connection)"
            />
          </div>

          <div v-for="{ project, connections } in branches" :key="project.id" class="branch">
            <p class="branch-name">{{ project.name }}</p>
            <!-- Indented under its project, with a guide line down the side. -->
            <div class="twigs">
              <ConnectionLeaf
                v-for="connection in connections"
                :key="connection.id"
                :connection="connection"
                @pick="pick(connection)"
                @bookmark="toggleBookmark(connection)"
              />
              <p v-if="!connections.length" class="twig-empty">{{ t("TabBar.projectEmpty") }}</p>
            </div>
          </div>
        </template>
      </div>
    </div>

    <!--
      Up to four tabs side by side, starting from the front one. Broadcast sends
      what is typed in one of them to all — meant for the same steps on several
      servers.
    -->
    <div class="view-tools">
      <IconButton
        v-if="split"
        :icon="Radio"
        :label="broadcast ? t('TabBar.broadcastOff') : t('TabBar.broadcastOn')"
        :title="broadcast ? t('TabBar.broadcastOffTitle') : t('TabBar.broadcastOnTitle')"
        variant="text"
        size="sm"
        :class="{ on: broadcast, warn: broadcast }"
        :aria-pressed="broadcast"
        @click="emit('broadcast')"
      />
      <IconButton
        :icon="Columns2"
        :label="split ? t('TabBar.splitOff') : t('TabBar.splitOn')"
        :title="split ? t('TabBar.splitOffTitle') : t('TabBar.splitOnTitle')"
        variant="text"
        size="sm"
        :class="{ on: split }"
        :disabled="!split && tabs.length < 2"
        :aria-pressed="split"
        @click="emit('split')"
      />
    </div>
  </div>
</template>

<style scoped>
.tabbar {
  display: flex;
  align-items: stretch;
  gap: 0.25rem;
  padding: 0.4rem 0.5rem 0;
  background: var(--rail);
  border-bottom: 1px solid var(--border);
  overflow: visible;
}

/* Gives way before the + does: the list scrolls, the button stays. */
.tabs {
  flex: 0 1 auto;
  min-width: 0;
}

.tab {
  max-width: 22rem;
}

.dot {
  flex: 0 0 auto;
  width: 0.5rem;
  height: 0.5rem;
  border-radius: 50%;
  background: var(--muted);
}

.dot.connected {
  background: var(--ok);
}

.dot.connecting {
  background: var(--warn);
  /* Distinguishes "still trying" from a settled state at a glance. */
  animation: pulse 1.2s ease-in-out infinite;
}

.dot.error {
  background: var(--danger);
}

@keyframes pulse {
  50% {
    opacity: 0.3;
  }
}

@media (prefers-reduced-motion: reduce) {
  .dot.connecting {
    animation: none;
  }
}

.label {
  display: flex;
  align-items: baseline;
  gap: 0.35rem;
  min-width: 0;
  overflow: hidden;
  white-space: nowrap;
}

.name {
  overflow: hidden;
  text-overflow: ellipsis;
}

/* The target is the first thing to give way when the tab gets tight. */
.sep,
.target {
  flex: 0 1 auto;
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  font-size: 0.85em;
  opacity: 0.75;
}

.plus-wrap {
  position: relative;
  display: flex;
  align-items: center;
}

.plus.open {
  color: var(--fg);
}

.view-tools {
  margin-left: auto;
  display: flex;
  align-items: center;
  gap: 0.15rem;
}

.view-tools .on {
  color: var(--accent);
}

.view-tools .warn {
  color: var(--warn);
}

.away {
  position: fixed;
  inset: 0;
  z-index: 40;
}

.tree {
  position: absolute;
  top: calc(100% + 0.35rem);
  left: 0;
  z-index: 50;
  width: 24rem;
  max-height: 28rem;
  overflow-y: auto;
  padding: 0.5rem;
  border-radius: 10px;
  background: var(--panel);
  border: 1px solid var(--border);
  box-shadow: 0 12px 32px rgba(0, 0, 0, 0.45);
}

.branch + .branch {
  margin-top: 0.5rem;
}

/* Says what the menu is for, so the project names below it cannot be mistaken
   for one of its commands. */
.tree-head {
  margin: 0 0 0.5rem;
  padding: 0 0.4rem 0.5rem;
  border-bottom: 1px solid var(--border);
  font-size: 0.8rem;
  font-weight: 600;
  color: var(--fg);
}

.tree-search {
  width: 100%;
  margin-bottom: 0.5rem;
}

/* The shortlist reads as its own block, not as another project. */
.branch.pinned {
  padding-bottom: 0.5rem;
  margin-bottom: 0.5rem;
  border-bottom: 1px solid var(--border);
}

.branch.pinned .branch-name {
  color: var(--accent);
}

.branch.local {
  padding-bottom: 0.5rem;
  margin-bottom: 0.5rem;
  border-bottom: 1px solid var(--border);
}

.shell {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  width: 100%;
  padding: 0.35em 0.5em;
  border: 0;
  border-radius: 6px;
  background: none;
  color: var(--fg);
  font: inherit;
  text-align: left;
  cursor: pointer;
}

.shell:hover,
.shell:focus-visible {
  background: var(--color-line);
  outline: none;
}

.command {
  margin-top: 0.35rem;
  padding: 0 0.25rem;
}

.command-error {
  margin: 0.25rem 0 0;
  padding: 0 0.4rem;
  font-size: 0.8rem;
  color: var(--color-danger, #c33);
}

.branch-name {
  margin: 0 0 0.25rem;
  padding: 0 0.4rem;
  font-size: 0.75rem;
  color: var(--muted);
  text-transform: uppercase;
  letter-spacing: 0.06em;
}

/* The indent plus the guide line is what makes this read as a tree rather
   than as a flat list with headings. */
.twigs {
  margin-left: 0.7rem;
  padding-left: 0.5rem;
  border-left: 1px solid var(--border);
}

.twig-empty {
  margin: 0;
  padding: 0.35em 0.5em;
  font-size: 0.8rem;
  font-style: italic;
  color: var(--muted);
  opacity: 0.7;
}

.empty {
  margin: 0;
  padding: 0.5rem;
  color: var(--muted);
  font-size: 0.9rem;
}
</style>
