<script setup lang="ts">
import { computed, onBeforeUnmount, ref } from "vue";
import { Copy, FolderInput, Pin, Plus, RefreshCw, Settings, X } from "@lucide/vue";
import {
  Alert,
  Badge,
  Button,
  Card,
  EmptyState,
  Field,
  IconButton,
  Input,
  NativeSelect,
} from "@wirecore/wirelayer-vue";
import ConnectionDialog from "./ConnectionDialog.vue";
import ConnectionWizard from "./ConnectionWizard.vue";
import EditDialog from "./EditDialog.vue";
import ExportDialog from "./ExportDialog.vue";
import AppPasswordDialog from "./AppPasswordDialog.vue";
import HostKeysDialog from "./HostKeysDialog.vue";
import ProxyDialog from "./ProxyDialog.vue";
import McpDialog from "./McpDialog.vue";
import LanguageDialog from "./LanguageDialog.vue";
import AboutDialog from "./AboutDialog.vue";
import { useI18n } from "vue-i18n";
import SnippetsDialog from "./SnippetsDialog.vue";
import { localVaultStatus, type LocalVaultStatus } from "../local-vault";
import MembersDialog from "./MembersDialog.vue";
import OsIcon from "./OsIcon.vue";
import ProjectDialog from "./ProjectDialog.vue";
import SharesDialog from "./SharesDialog.vue";
import HostImport from "./HostImport.vue";
import WorkspaceDialog from "./WorkspaceDialog.vue";
import { filterProjects } from "../search";
import { accountOf, deleteWorkspace, dismissConflicts, hideWorkspace, unlockWanted } from "../cloud";
import {
  addConnection,
  deleteConnection,
  dropSnippetsOf,
  loadWorkspaces,
  moveConnection,
  persist,
  storageError,
  storagePath,
  syncing,
  syncNow,
  toggleBookmark,
  updateConnection,
  workspaces,
} from "../store";
import {
  credentialLabel,
  defaultConnection,
  newId,
  ROLE_LABELS,
  STORAGE_LABELS,
  targetLabel,
  TYPE_LABELS,
  type Connection,
  type Project,
  type Workspace,
  type WorkspaceValues,
} from "../types";

const props = defineProps<{ workspace: Workspace }>();
const emit = defineEmits<{
  open: [connection: Connection];
  removed: [];
  /** Change this account's master password — the dialog lives in App.vue. */
  changeMaster: [accountId: string];
}>();

const remote = computed(() => props.workspace.remote ?? null);

/**
 * Whether the tree may be edited right now.
 *
 * Not with a locked vault: a new connection with an entered key could not be
 * encrypted, and a form that opens and fails on saving is worse than one that
 * does not open at all.
 */
const editable = computed(() => !remote.value || !remote.value.locked);

/** Owner and admin create projects; members where the workspace allows it. */
const canCreateProjects = computed(() => (remote.value ? remote.value.canCreateProjects : true));

/** Renaming, sharing and deleting: owner and admin, and whoever created the project. */
function canManage(project: Project): boolean {
  if (!remote.value) return true;
  return remote.value.admin || remote.value.ownProjects.includes(project.id);
}

/**
 * The personal workspace of a WireCloud account belongs to its owner alone:
 * WireCloud knows no organization for it, so nobody can be invited and there
 * are no teams to share with. Members and shares are hidden then.
 */
const solo = computed(
  () => remote.value?.kind === "personal" && !!accountOf(remote.value.accountId)?.managedBy,
);

/** The open dialog for a project's shares. */
const removeError = ref("");

/** Asks for the master password. The dialog itself lives in `App.vue`. */
function askUnlock() {
  if (remote.value) unlockWanted.value = remote.value.accountId;
}

/**
 * The open connection dialog. It carries the project it belongs to, because a
 * new connection has nowhere to be looked up yet — it only exists as a draft
 * until "Create".
 */
const connectionDialog = ref<{
  mode: "create" | "edit";
  projectId: string;
  connection: Connection;
} | null>(null);

/** Same idea one level up, for the project row. */
const projectDialog = ref<{ mode: "create" | "edit"; project: Project } | null>(null);

/** And for the workspace header. It only ever edits the one on screen. */
const editingWorkspace = ref(false);

/** Whether this device works with an app password instead of a keyring — then it can be changed. */
const vaultStatus = ref<LocalVaultStatus | null>(null);
const changingAppPassword = ref(false);
const { t } = useI18n();
/** The project whose snippets are open. */
const editingSnippets = ref<Project | null>(null);
localVaultStatus()
  .then((status) => (vaultStatus.value = status))
  .catch(() => {});

/** The conflict messages stay until someone here dismisses them. */
async function acknowledgeConflicts() {
  await dismissConflicts(props.workspace.id).catch(() => {});
  await loadWorkspaces();
}

function startAddProject() {
  projectDialog.value = {
    mode: "create",
    project: { id: newId(), name: t("WorkspaceOverview.newProject"), connections: [] },
  };
}

function startEditProject(project: Project) {
  projectDialog.value = { mode: "edit", project };
}

function saveProject(name: string) {
  const open = projectDialog.value;
  if (!open) return;
  if (open.mode === "create") {
    props.workspace.projects.push({ ...open.project, name });
  } else {
    // Patched in place: the project holds the connections, and nothing else
    // about it is editable.
    const project = props.workspace.projects.find((p) => p.id === open.project.id);
    if (project) project.name = name;
  }
  persist();
  projectDialog.value = null;
}

function removeProject() {
  const open = projectDialog.value;
  if (!open) return;
  const index = props.workspace.projects.findIndex((p) => p.id === open.project.id);
  if (index >= 0) props.workspace.projects.splice(index, 1);
  dropSnippetsOf(props.workspace, { projectId: open.project.id });
  persist();
  projectDialog.value = null;
}

function saveWorkspace(values: WorkspaceValues) {
  props.workspace.name = values.name;
  props.workspace.storage = values.storage;
  props.workspace.onePasswordAccount = values.onePasswordAccount;
  props.workspace.bitwarden = values.bitwarden;
  persist();
  editingWorkspace.value = false;
}

// ---- Reordering and moving ----------------------------------------------------
//
// With pointer events instead of HTML5 drag and drop: the window has only one
// OS drop target, and Tauri holds it for files from the file manager — so the
// WebView never sees an HTML5 drag. The same pattern as in the file view, see
// README, "Drag and drop".

const DRAG_THRESHOLD = 5;

/** The dragged connection, as soon as it really is a drag. */
const dragging = ref<string | null>(null);
/** Where it would land: before the card at `index`, or at the end of the project. */
const dropTarget = ref<{ projectId: string; index: number } | null>(null);
let pressed: { id: string; x: number; y: number } | null = null;
/** A drag that ends on its own card is not a click to open. */
let justDragged = false;

function pressCard(connection: Connection, event: PointerEvent) {
  if (event.button !== 0 || searching.value || !editable.value) return;
  // The buttons in the corner stay buttons.
  if ((event.target as HTMLElement).closest("button")) return;
  pressed = { id: connection.id, x: event.clientX, y: event.clientY };
  window.addEventListener("pointermove", onDragMove);
  window.addEventListener("pointerup", onDragEnd);
  window.addEventListener("pointercancel", cancelDrag);
}

function onDragMove(event: PointerEvent) {
  if (!pressed) return;
  if (
    !dragging.value &&
    Math.abs(event.clientX - pressed.x) < DRAG_THRESHOLD &&
    Math.abs(event.clientY - pressed.y) < DRAG_THRESHOLD
  ) {
    return;
  }
  dragging.value = pressed.id;
  dropTarget.value = dropAt(event.clientX, event.clientY);
}

/** The spot under the pointer: a card means "before it", free space in the project "at the end". */
function dropAt(x: number, y: number): { projectId: string; index: number } | null {
  const element = document.elementFromPoint(x, y) as HTMLElement | null;
  const cards = element?.closest<HTMLElement>("[data-project-id]");
  if (!cards) return null;
  const projectId = cards.dataset.projectId!;
  const card = element?.closest<HTMLElement>("[data-connection-index]");
  const project = props.workspace.projects.find((p) => p.id === projectId);
  if (!project) return null;
  const index = card ? Number(card.dataset.connectionIndex) : project.connections.length;
  return { projectId, index };
}

function onDragEnd() {
  const id = dragging.value;
  const target = dropTarget.value;
  if (id && target) {
    // Counted without the dragged card: whoever drags backwards within the
    // same project moves up by one.
    const project = props.workspace.projects.find((p) => p.id === target.projectId);
    const from = project?.connections.findIndex((c) => c.id === id) ?? -1;
    const index = from >= 0 && from < target.index ? target.index - 1 : target.index;
    if (!(from === index && from >= 0)) moveConnection(id, target.projectId, index);
  }
  justDragged = !!id;
  cancelDrag();
}

function cancelDrag() {
  pressed = null;
  dragging.value = null;
  dropTarget.value = null;
  window.removeEventListener("pointermove", onDragMove);
  window.removeEventListener("pointerup", onDragEnd);
  window.removeEventListener("pointercancel", cancelDrag);
}

onBeforeUnmount(cancelDrag);

function openCard(connection: Connection) {
  if (justDragged) {
    justDragged = false;
    return;
  }
  emit("open", connection);
}

function startAddConnection(project: Project) {
  connectionDialog.value = {
    mode: "create",
    projectId: project.id,
    connection: defaultConnection(t("WorkspaceOverview.newConnection")),
  };
}

function startEditConnection(project: Project, connection: Connection) {
  connectionDialog.value = { mode: "edit", projectId: project.id, connection };
}

/** "Create" or "Save": the first time the draft touches the tree. */
function saveConnection(connection: Connection) {
  const open = connectionDialog.value;
  if (!open) return;
  if (open.mode === "create") addConnection(open.projectId, connection);
  else updateConnection(connection);
  connectionDialog.value = null;
}

function removeConnection() {
  const open = connectionDialog.value;
  if (!open) return;
  deleteConnection(open.connection.id);
  connectionDialog.value = null;
}

/** Imported from the project's settings, into that project. */
function importConnections(connections: Connection[]) {
  const project = projectDialog.value?.project;
  if (!project) return;
  for (const connection of connections) addConnection(project.id, connection);
  projectDialog.value = null;
}

/**
 * The tabs a project's settings have besides name and delete: the shares for
 * whoever manages this project of a shared workspace, the import for whoever
 * may change the tree.
 */
function projectTabsFor(project: Project) {
  return [
    ...(remote.value && canManage(project) && !solo.value
      ? [{ value: "shares", label: t("WorkspaceOverview.shares") }]
      : []),
    ...(editable.value ? [{ value: "import", label: t("WorkspaceOverview.import") }] : []),
  ];
}

/**
 * What used to sit as buttons in the header, now tabs of the settings: the
 * workspace's own, then those of this device.
 */
const workspaceTabs = computed(() => [
  ...(remote.value && !solo.value ? [{ value: "members", label: t("WorkspaceOverview.members") }] : []),
  { value: "hostKeys", label: t("WorkspaceOverview.hostKeys") },
  { value: "export", label: t("WorkspaceOverview.export") },
  { value: "proxy", label: t("WorkspaceOverview.proxy"), device: true },
  { value: "mcp", label: "MCP", device: true },
  { value: "language", label: t("LanguageDialog.button"), device: true },
  { value: "about", label: t("AboutDialog.button"), device: true },
]);

/** The name question before a connection is duplicated into its project. */
const copying = ref<{ projectId: string; connection: Connection; name: string } | null>(null);

function startCopyConnection(project: Project, connection: Connection) {
  copying.value = {
    projectId: project.id,
    connection,
    name: t("WorkspaceOverview.copyName", { name: connection.name }),
  };
}

/**
 * Settings, secrets included, go along; the detected system and the bookmark
 * stay behind — the copy has not logged in anywhere yet and was not pinned.
 */
function copyConnection() {
  const open = copying.value;
  if (!open || !open.name.trim()) return;
  addConnection(open.projectId, {
    id: newId(),
    name: open.name.trim(),
    settings: JSON.parse(JSON.stringify(open.connection.settings)),
  });
  copying.value = null;
}

/**
 * "Move" — the same as dragging, for those who do not use the mouse: project
 * and position in it. `before` is the connection it lands before, empty means
 * at the end.
 */
const moving = ref<{ connection: Connection; to: string; before: string } | null>(null);

function startMoveConnection(project: Project, connection: Connection) {
  moving.value = { connection, to: project.id, before: "" };
}

/** The positions in the target project — without the connection itself, as `moveConnection` counts. */
const moveSpots = computed(() => {
  const open = moving.value;
  const target = props.workspace.projects.find((p) => p.id === open?.to);
  return [
    { value: "", label: t("WorkspaceOverview.atEnd") },
    ...(target?.connections ?? [])
      .filter((c) => c.id !== open?.connection.id)
      .map((c) => ({ value: c.id, label: t("WorkspaceOverview.before", { name: c.name }) })),
  ];
});

function moveToProject() {
  const open = moving.value;
  const target = props.workspace.projects.find((p) => p.id === open?.to);
  if (!open || !target) return;
  const others = target.connections.filter((c) => c.id !== open.connection.id);
  const at = others.findIndex((c) => c.id === open.before);
  moveConnection(open.connection.id, target.id, at >= 0 ? at : others.length);
  moving.value = null;
}

function removeWorkspace() {
  const index = workspaces.findIndex((w) => w.id === props.workspace.id);
  if (index < 0) return;
  workspaces.splice(index, 1);
  persist();
  emit("removed");
}

/**
 * Deletes the organization on the server — or only leaves it.
 *
 * The difference matters a lot for everyone else, which is why the dialog
 * decides it and not this function.
 */
async function removeRemoteWorkspace(leaveOnly: boolean) {
  removeError.value = "";
  try {
    await deleteWorkspace(props.workspace.id, leaveOnly);
    editingWorkspace.value = false;
    await loadWorkspaces();
    emit("removed");
  } catch (e) {
    removeError.value = String(e);
  }
}

/** Removes the workspace from the rail, only here. */
async function hideRemoteWorkspace() {
  removeError.value = "";
  try {
    await hideWorkspace(props.workspace.id);
    editingWorkspace.value = false;
    await loadWorkspaces();
    emit("removed");
  } catch (e) {
    removeError.value = String(e);
  }
}

// ---- Search and order -----------------------------------------------------

const query = ref("");

const searching = computed(() => query.value.trim() !== "");

/** Shared with the tab menu, so both order and match the same way. */
const visibleProjects = computed(() => filterProjects(props.workspace.projects, query.value));

const hitCount = computed(() =>
  visibleProjects.value.reduce((total, p) => total + p.connections.length, 0),
);

/** Short one-liner under the connection name. */
function target(connection: Connection): string {
  return connection.settings.host
    ? targetLabel(connection.settings)
    : t("WorkspaceOverview.notSetUp");
}
</script>

<template>
  <div class="overview">
    <header class="head">
      <div>
        <h1>{{ workspace.name }}</h1>
        <div class="badges-head">
          <Badge variant="outline">{{ STORAGE_LABELS[workspace.storage] }}</Badge>
          <Badge v-if="remote" variant="outline">{{ remote.server }}</Badge>
          <Badge v-if="remote" variant="outline">{{ ROLE_LABELS[remote.role] }}</Badge>
        </div>
      </div>
      <div class="head-actions">
        <IconButton
          v-if="remote"
          class="gear"
          :class="{ spinning: syncing }"
          :icon="RefreshCw"
          :label="syncing ? t('WorkspaceOverview.syncing') : t('WorkspaceOverview.sync')"
          variant="text"
          size="sm"
          :disabled="syncing"
          :title="syncing ? t('WorkspaceOverview.syncing') : t('WorkspaceOverview.sync')"
          @click="syncNow(workspace.id)"
        />
        <IconButton
          class="gear"
          :icon="Settings"
          :label="t('WorkspaceOverview.editWorkspace')"
          variant="text"
          size="sm"
          :title="t('WorkspaceOverview.editWorkspace')"
          @click="editingWorkspace = true"
        />
      </div>
    </header>

    <Alert v-if="storageError" status="danger" size="sm">{{ storageError }}</Alert>
    <Alert v-if="removeError" status="danger" size="sm">{{ removeError }}</Alert>

    <!--
      The banners of a remote workspace. They stand separately instead of in one
      line, because they can occur together: locked *and* something in the
      queue is the state after a restart with pending changes.
    -->
    <template v-if="remote">
      <Alert v-if="remote.locked" status="neutral" size="sm">
        {{ t("WorkspaceOverview.locked") }}
        <template #actions>
          <Button @click="askUnlock">{{ t("WorkspaceOverview.enterMaster") }}</Button>
        </template>
      </Alert>

      <Alert v-else-if="remote.secretsMissing" status="warn" size="sm">
        {{ t("WorkspaceOverview.secretsMissing") }}
      </Alert>

      <Alert v-if="remote.conflicts?.length" status="warn" size="sm">
        <p v-for="(conflict, index) in remote.conflicts" :key="index">{{ conflict }}</p>
        <Button variant="text" size="sm" @click="acknowledgeConflicts">
          {{ t("WorkspaceOverview.gotIt") }}
        </Button>
      </Alert>

      <Alert v-if="remote.error" status="warn" size="sm">{{ remote.error }}</Alert>

      <Alert v-else-if="remote.pending" status="info" size="sm">
        {{ t("WorkspaceOverview.pending", remote.pending) }}
      </Alert>
    </template>

    <div class="search">
      <Input
        v-model="query"
        class="search-field"
        type="text"
        :placeholder="t('WorkspaceOverview.search')"
        :aria-label="t('WorkspaceOverview.search')"
        @keydown.esc="query = ''"
      />
      <span v-if="searching" class="hits">
        {{ t("WorkspaceOverview.hits", hitCount) }}
      </span>
      <IconButton
        v-if="searching"
        :icon="X"
        :label="t('WorkspaceOverview.clearSearch')"
        variant="text"
        size="sm"
        :title="t('WorkspaceOverview.clearSearch')"
        @click="query = ''"
      />
    </div>

    <section v-for="{ project, connections } in visibleProjects" :key="project.id" class="project">
      <header class="project-head">
        <h2 class="project-name">{{ project.name }}</h2>
        <Button
          v-if="!searching"
          variant="text"
          size="sm"
          :title="t('WorkspaceOverview.snippetsTitle')"
          @click="editingSnippets = project"
        >
          {{ t("WorkspaceOverview.snippets") }}
        </Button>
        <IconButton
          v-if="(canManage(project) && editable) || projectTabsFor(project).length"
          class="gear"
          :icon="Settings"
          :label="t('WorkspaceOverview.editProject')"
          variant="text"
          size="sm"
          :title="t('WorkspaceOverview.editProject')"
          @click="startEditProject(project)"
        />
      </header>

      <div
        class="cards"
        :data-project-id="project.id"
        :class="{
          'drop-end':
            dropTarget?.projectId === project.id && dropTarget.index >= project.connections.length,
        }"
      >
        <!--
          The card itself is the "Open" button. Not a <button> element: the
          gear sits inside it, and a button inside a button is not valid HTML.
        -->
        <Card v-for="(connection, index) in connections" :key="connection.id" interactive as-child>
          <article
            class="card connection"
            :class="{
              dragging: dragging === connection.id,
              'drop-before':
                dropTarget?.projectId === project.id && dropTarget.index === index && dragging !== connection.id,
            }"
            role="button"
            tabindex="0"
            :data-connection-index="index"
:title="t('WorkspaceOverview.openCard', { name: connection.name })"
            @pointerdown="pressCard(connection, $event)"
            @click="openCard(connection)"
            @keydown.enter.self.prevent="emit('open', connection)"
            @keydown.space.self.prevent="emit('open', connection)"
          >
            <div class="card-top">
              <h3>{{ connection.name }}</h3>
              <!--
                The resting state of the corner: a set bookmark sits beside the
                type rather than in place of it, so the type is always readable
                and hovering swaps the pair for the buttons without a jump.
              -->
              <span class="badges">
                <Pin
                  v-if="connection.bookmarked"
                  class="pinned"
                  fill="currentColor"
                  aria-hidden="true"
                />
                <Badge variant="outline">{{ TYPE_LABELS[connection.settings.type] }}</Badge>
              </span>
            </div>
            <p class="target">{{ target(connection) }}</p>
            <p class="source">{{ credentialLabel(connection.settings) }}</p>
            <p v-if="connection.system" class="system" :title="connection.system.pretty">
              <OsIcon :id="connection.system.id" />
              {{ connection.system.name }} {{ connection.system.version }}
            </p>
            <p v-else class="system unknown">{{ t("WorkspaceOverview.systemUnknown") }}</p>

            <div class="card-actions">
              <IconButton
                class="gear pin"
                :class="{ on: connection.bookmarked }"
                :icon="Pin"
                :icon-props="{ fill: connection.bookmarked ? 'currentColor' : 'none' }"
                :label="connection.bookmarked ? t('WorkspaceOverview.unpin') : t('WorkspaceOverview.pin')"
                variant="text"
                size="sm"
                :title="connection.bookmarked ? t('WorkspaceOverview.unpin') : t('WorkspaceOverview.pin')"
                @click.stop="toggleBookmark(connection)"
              />
              <IconButton
                v-if="editable"
                class="gear"
                :icon="Copy"
                :label="t('WorkspaceOverview.copyConnection')"
                variant="text"
                size="sm"
                :title="t('WorkspaceOverview.copyConnection')"
                @click.stop="startCopyConnection(project, connection)"
              />
              <IconButton
                v-if="editable"
                class="gear"
                :icon="FolderInput"
                :label="t('WorkspaceOverview.move')"
                variant="text"
                size="sm"
                :title="t('WorkspaceOverview.move')"
                @click.stop="startMoveConnection(project, connection)"
              />
              <IconButton
                v-if="editable"
                class="gear"
                :icon="Settings"
                :label="t('WorkspaceOverview.editConnection')"
                variant="text"
                size="sm"
                :title="t('WorkspaceOverview.editConnection')"
                @click.stop="startEditConnection(project, connection)"
              />
            </div>
          </article>
        </Card>

        <!-- While searching the grid is a result list; adding into it there
             would only be confusing. -->
        <Card v-if="!searching && editable" interactive as-child>
          <button class="card add" @click="startAddConnection(project)">
            <span>+</span>
            {{ t("WorkspaceOverview.addConnection") }}
          </button>
        </Card>
      </div>
    </section>

    <EmptyState
      v-if="searching && !visibleProjects.length"
      size="sm"
      :title="t('WorkspaceOverview.noHits', { query: query.trim() })"
    />

    <Button
      v-if="!searching && canCreateProjects && editable"
      class="add-project"
      variant="outline"
      :leading-icon="Plus"
      @click="startAddProject"
    >
      {{ t("WorkspaceOverview.addProject") }}
    </Button>
    <p v-else-if="!searching && !canCreateProjects" class="path">
      {{ t("WorkspaceOverview.adminOnly") }}
    </p>

    <p v-if="remote" class="path">
      {{
        t("WorkspaceOverview.remoteStorage", {
          server: remote.server,
          email: remote.email,
          revision: remote.revision,
        })
      }}
    </p>
    <p v-else class="path" :title="storagePath">
      {{ t("WorkspaceOverview.localStorage", { path: storagePath }) }}
      <template v-if="vaultStatus?.state === 'ready' && !vaultStatus.keyring">
        · {{ t("WorkspaceOverview.appPassword") }}
        <Button variant="text" size="sm" @click="changingAppPassword = true">
          {{ t("WorkspaceOverview.change") }}
        </Button>
      </template>
    </p>
    <AppPasswordDialog v-if="changingAppPassword" @close="changingAppPassword = false" />

    <!-- Keyed, so reopening on another connection starts with a fresh draft. -->
    <ConnectionWizard
      v-if="connectionDialog?.mode === 'create'"
      :workspace-id="workspace.id"
      :project-id="connectionDialog.projectId"
      @save="saveConnection"
      @cancel="connectionDialog = null"
    />
    <ConnectionDialog
      v-else-if="connectionDialog"
      :key="connectionDialog.connection.id"
      :connection="connectionDialog.connection"
      :workspace-id="workspace.id"
      @save="saveConnection"
      @remove="removeConnection"
      @cancel="connectionDialog = null"
    />

    <SnippetsDialog
      v-if="editingSnippets"
      :workspace="workspace"
      :project="editingSnippets"
      @close="editingSnippets = null"
    />


    <EditDialog
      v-if="copying"
      :title="t('WorkspaceOverview.copyConnection')"
      mode="create"
      :can-save="copying.name.trim().length > 0"
      @save="copyConnection"
      @cancel="copying = null"
    >
      <Field :label="t('WorkspaceOverview.copyNameLabel')">
        <Input v-model="copying.name" data-autoselect />
      </Field>
    </EditDialog>

    <EditDialog
      v-if="moving"
      :title="t('WorkspaceOverview.moveTitle', { name: moving.connection.name })"
      mode="edit"
      :can-delete="false"
      @save="moveToProject"
      @cancel="moving = null"
    >
      <Field :label="t('WorkspaceOverview.toProject')">
        <NativeSelect
          v-model="moving.to"
          :items="workspace.projects.map((p) => ({ value: p.id, label: p.name }))"
          @update:model-value="moving.before = ''"
        />
      </Field>
      <Field :label="t('WorkspaceOverview.position')">
        <NativeSelect v-model="moving.before" :items="moveSpots" />
      </Field>
    </EditDialog>

    <ProjectDialog
      v-if="projectDialog"
      :key="projectDialog.project.id"
      :project="projectDialog.project"
      :mode="projectDialog.mode"
      :extras="projectDialog.mode === 'edit' ? projectTabsFor(projectDialog.project) : []"
      :general="projectDialog.mode === 'create' || (canManage(projectDialog.project) && editable)"
      @save="saveProject"
      @remove="removeProject"
      @cancel="projectDialog = null"
    >
      <!--
        After saving the shares, a sync runs: a share only shows once the
        project keys are distributed, and that is exactly what the sync does.
      -->
      <template #shares>
        <SharesDialog
          :workspace-id="workspace.id"
          :project-id="projectDialog.project.id"
          :project-name="projectDialog.project.name"
          @saved="
            projectDialog = null;
            syncNow(workspace.id);
          "
          @cancel="projectDialog = null"
        />
      </template>
      <template #import>
        <HostImport :project="projectDialog.project" @save="importConnections" @cancel="projectDialog = null" />
      </template>
    </ProjectDialog>

    <WorkspaceDialog
      v-if="editingWorkspace"
      :workspace="workspace"
      mode="edit"
      :extras="workspaceTabs"
      @save="saveWorkspace"
      @remove="removeWorkspace"
      @remove-remote="removeRemoteWorkspace"
      @hide="hideRemoteWorkspace"
      @change-master="
        editingWorkspace = false;
        remote && emit('changeMaster', remote.accountId);
      "
      @cancel="editingWorkspace = false"
    >
      <template #members>
        <MembersDialog
          v-if="remote"
          :workspace-id="workspace.id"
          :workspace-name="workspace.name"
          :remote="remote"
          @close="editingWorkspace = false"
        />
      </template>
      <template #hostKeys>
        <HostKeysDialog :workspace="workspace" @close="editingWorkspace = false" />
      </template>
      <template #export>
        <ExportDialog :initial-id="workspace.id" @close="editingWorkspace = false" />
      </template>
      <template #proxy>
        <ProxyDialog @close="editingWorkspace = false" />
      </template>
      <template #mcp>
        <McpDialog @close="editingWorkspace = false" />
      </template>
      <template #language>
        <LanguageDialog @close="editingWorkspace = false" />
      </template>
      <template #about>
        <AboutDialog @close="editingWorkspace = false" />
      </template>
    </WorkspaceDialog>
  </div>
</template>

<style scoped>
.overview {
  display: flex;
  flex-direction: column;
  gap: 1.5rem;
  padding: 1.5rem 2rem 2rem;
  max-width: 80rem;
  width: 100%;
  margin: 0 auto;
  box-sizing: border-box;
}

.head {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 1rem;
}

h1 {
  margin: 0;
  font-size: 1.4rem;
}

.badges-head {
  display: flex;
  flex-wrap: wrap;
  gap: 0.35rem;
  margin-top: 0.4rem;
}

.head-actions {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  flex: 0 0 auto;
}

.search {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.search-field {
  flex: 1;
  min-width: 0;
}

.hits {
  flex: 0 0 auto;
  font-size: 0.8rem;
  color: var(--muted);
}

.project {
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
}

.project-head {
  display: flex;
  align-items: center;
  gap: 0.25rem;
  border-bottom: 1px solid var(--border);
  padding-bottom: 0.4rem;
}

.project-name {
  flex: 1;
  min-width: 0;
  margin: 0;
  padding: 0.3em 0;
  font-size: 1rem;
  font-weight: 600;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.connection.dragging {
  opacity: 0.4;
}

.connection.drop-before {
  box-shadow: -3px 0 0 0 var(--color-primary);
}

.cards.drop-end {
  outline: 2px dashed color-mix(in srgb, var(--color-primary) 60%, transparent);
  outline-offset: 4px;
  border-radius: 0.5rem;
}

.cards {
  display: grid;
  /* At most three per row — the corner holds three buttons — and fewer once
     the window gets narrow. */
  grid-template-columns: repeat(auto-fill, minmax(max(16rem, calc((100% - 1.5rem) / 3)), 1fr));
  gap: 0.75rem;
}

/* Surface, border and hover come from WireLayer's Card; only the density is
   tighter, since a grid of them sits on one screen. */
.card {
  --wc-card-p: 0.9rem;
  gap: 0.35rem;
  text-align: left;
  /* The card's own translucent white (7 %), laid onto the page colour: the
     honeycomb behind the overview stays behind the cards. */
  background-color: color-mix(in srgb, white 7%, var(--color-bg));
}

.card-top {
  display: flex;
  align-items: baseline;
  justify-content: space-between;
  gap: 0.5rem;
}

.card h3 {
  margin: 0;
  font-size: 0.95rem;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.badges {
  display: flex;
  align-items: center;
  gap: 0.3rem;
  flex: 0 0 auto;
  transition: opacity 120ms ease;
}

.badges .pinned {
  width: 12px;
  height: 12px;
  color: var(--color-primary);
}

.target,
.source,
.system {
  margin: 0;
  font-size: 0.8rem;
  color: var(--muted);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.system {
  display: flex;
  align-items: center;
  gap: 0.4rem;
}

/* Kept in the layout rather than hidden, so every card is the same height and
   it is visible that the target has simply not been reached yet. */
.system.unknown {
  opacity: 0.55;
  font-style: italic;
}

/* The whole card opens the connection; hover and focus ring come from the
   interactive Card. Relative for the buttons in the corner. */
.card.connection {
  position: relative;
}

/* The edit affordance on every row and card: hidden until the row is touched,
   and reachable by keyboard because focus brings it back. */
.gear {
  flex: 0 0 auto;
  opacity: 0;
  transition: opacity 120ms ease;
}

/*
 * In the header and on the project row the gear is always shown: it floats
 * over nothing it could cover there, and whoever looks for it should see it
 * rather than find it. On a connection card it stays reserved for the
 * pointer — there it lies over the corner where the badges otherwise sit.
 */
.head .gear,
.project-head .gear {
  opacity: 1;
}

/* Turns while the sync runs. */
.spinning :deep(svg) {
  animation: spin 1s linear infinite;
}

@keyframes spin {
  to {
    transform: rotate(360deg);
  }
}

/*
 * `:has(:focus-visible)` rather than `:focus-within`: a mouse click leaves the
 * button focused, and `:focus-within` would then keep the buttons on screen
 * after the pointer has left the card. `:focus-visible` ignores pointer focus
 * by design, so keyboard users still see what they are on.
 */
.card.connection:hover .gear,
.card.connection:focus-visible .gear,
.card.connection:has(:focus-visible) .gear,
.gear:focus-visible {
  opacity: 1;
}

/* On a card they float over the corner, swapped in where the type badge sits
   so nothing jumps. */
.card-actions {
  position: absolute;
  top: 0.5rem;
  right: 0.5rem;
  display: flex;
  gap: 0.1rem;
}

/* The corner holds one thing at a time: the badges at rest, the buttons while
   the card is being used. */
.card.connection:hover .badges,
.card.connection:focus-visible .badges,
.card.connection:has(:focus-visible) .badges {
  opacity: 0;
}

/* Set or not, the button only shows on hover — the badge above carries the
   state the rest of the time. Accent so it reads as already set. */
.gear.pin.on,
.gear.pin.on:hover {
  color: var(--color-primary);
}

@media (prefers-reduced-motion: reduce) {
  .gear,
  .badges {
    transition: none;
  }
}

.card.add {
  align-items: center;
  justify-content: center;
  gap: 0.2rem;
  min-height: 7rem;
  background: transparent;
  border-style: dashed;
  color: var(--color-muted);
}

.card.add span {
  font-size: 1.5rem;
  line-height: 1;
}

.add-project {
  align-self: flex-start;
}

.path {
  margin: 0;
  font-size: 0.7rem;
  color: var(--muted);
  overflow: hidden;
  text-overflow: ellipsis;
}
</style>
