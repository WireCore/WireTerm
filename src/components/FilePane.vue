<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, ref, watch } from "vue";
import { useI18n } from "vue-i18n";
import EditDialog from "./EditDialog.vue";
import FileIcon from "./FileIcon.vue";
import FolderIcon from "./FolderIcon.vue";
import {
  Alert,
  Button,
  ContextMenu,
  EmptyState,
  Field,
  IconButton,
  Input,
  NativeSelect,
  Progress,
  type ContextMenuOpenDetails,
  type MenuEntry,
  type TextFieldHandle,
} from "@wirecore/wirelayer-vue";
import { ArrowUp, RefreshCw, Settings } from "@lucide/vue";
import { locale } from "../i18n";
import { formatBytes, formatDate, join } from "../sftp";
import type { Space } from "../remote";
import type { FileEntry, Listing } from "../types";

/**
 * One half of the file browser.
 *
 * Local and remote are described the same way by the backend, so the same
 * component draws either; `side` only decides how a new path is spelled and
 * whether the permission column has anything to say.
 *
 * The selection lives here rather than above: every action this pane offers
 * already carries the entries it applies to, so there is nothing the parent
 * would do with it. Where the pane has *been* is the parent's business, since
 * the back button has to reach whichever pane the pointer is over.
 */
const props = defineProps<{
  title: string;
  side: "local" | "remote";
  listing: Listing | null;
  loading: boolean;
  error: string;
  /** What a running operation is called, e.g. "deleting…" — with a way to stop it. */
  working?: string;
  /** "Download" or "Upload" — the direction is the parent's business. */
  transferLabel: string;
  /** Offered as a picker where the platform has no single root; Windows only. */
  roots?: string[];
  /**
   * Where a drop would land in this pane right now — a directory row, or the
   * open directory itself. null while nothing is being dragged over it.
   *
   * Decided above rather than here: the pane being dragged *from* must not
   * highlight itself, and a drag from the file manager belongs to neither.
   */
  dropPath?: string | null;
  /**
   * Which pane currently holds the selection.
   *
   * Only one may: every action this pane offers — transfer, rename, delete —
   * applies to one side, and two highlighted lists would not say which one was
   * meant. A pane that is not the owner clears itself.
   */
  owner?: "local" | "remote" | null;
  /** Shows the gear that opens the browser's settings. The server side only. */
  settings?: boolean;
  /**
   * Whether the protocol under the server pane has permissions at all.
   *
   * False over S3, where access is decided by policies rather than by modes.
   * The entry is greyed out on a listing without mode bits anyway, but that
   * only answers once a directory has been read, and "Change permissions" that
   * leads nowhere should not be offered at all.
   */
  permissions?: boolean;
  /** Whether one file can be turned into a link anyone can open. S3 only. */
  links?: boolean;
  /** How full the storage is, drawn as a bar where the server says. */
  space?: Space | null;
}>();

const emit = defineEmits<{
  navigate: [path: string];
  refresh: [];
  transfer: [entries: FileEntry[]];
  mkdir: [path: string];
  touch: [path: string];
  rename: [from: string, to: string];
  remove: [entries: FileEntry[]];
  /** The pointer has moved far enough to mean a drag; the parent takes over. */
  dragstart: [entries: FileEntry[], x: number, y: number];
  /** Something is now selected here, so the other pane must let go. */
  select: [];
  /** Remote only: opens the permissions dialog for one entry. */
  chmod: [entry: FileEntry];
  /** Remote only: downloads one file and starts watching it for changes. */
  edit: [entry: FileEntry];
  /** S3 only: makes a link to one file that works without credentials. */
  link: [entry: FileEntry];
  /** The gear was pressed. What it opens is the browser's business. */
  settings: [];
  /** "Cancel" next to `working`. */
  stop: [];
}>();
const { t } = useI18n();

const root = ref<HTMLElement>();
const listEl = ref<HTMLElement>();

const here = computed(() => props.listing?.path ?? "");

// ---- Sorting ---------------------------------------------------------------

type SortKey = "name" | "size" | "modified" | "permissions";

/** `label` is a message key. */
const COLUMNS: { key: SortKey; label: string; remoteOnly?: boolean; right?: boolean }[] = [
  { key: "name", label: "common.name" },
  { key: "size", label: "FilePane.columns.size", right: true },
  { key: "modified", label: "FilePane.columns.modified" },
  { key: "permissions", label: "FilePane.columns.permissions", remoteOnly: true },
];

const columns = computed(() =>
  COLUMNS.filter((column) => !column.remoteOnly || props.side === "remote"),
);

/** Kept across navigation: a chosen order is about the pane, not the folder. */
const sortKey = ref<SortKey>("name");
const ascending = ref(true);

function sortBy(key: SortKey) {
  if (sortKey.value === key) {
    ascending.value = !ascending.value;
    return;
  }
  sortKey.value = key;
  // Names read forwards; sizes and dates are asked about from the other end —
  // "what is biggest" and "what changed last" are the questions being put.
  ascending.value = key === "name" || key === "permissions";
}

function compare(a: FileEntry, b: FileEntry, key: SortKey): number {
  switch (key) {
    case "size":
      return a.size - b.size;
    case "modified":
      return (a.modified ?? 0) - (b.modified ?? 0);
    case "permissions":
      return (a.permissions ?? "").localeCompare(b.permissions ?? "", locale.value);
    default:
      // `numeric` so file2 comes before file10, which is the order anyone
      // reading a list of numbered files expects.
      return a.name.localeCompare(b.name, locale.value, { numeric: true, sensitivity: "base" });
  }
}

/**
 * Directories stay at the top whatever the column, as every file manager does
 * it: they are how the list is moved through, not entries being compared.
 */
const entries = computed(() => {
  const list = [...(props.listing?.entries ?? [])];
  list.sort((a, b) => {
    if (a.isDir !== b.isDir) return a.isDir ? -1 : 1;
    const primary = compare(a, b, sortKey.value);
    if (primary !== 0) return ascending.value ? primary : -primary;
    // Equal on the chosen column, so the order is at least stable and
    // readable rather than whatever the server happened to send.
    return compare(a, b, "name");
  });
  return list;
});

// ---- Path bar --------------------------------------------------------------

/** Typed into, so it is not the listing itself — it follows it until edited. */
const draft = ref("");
watch(here, (path) => (draft.value = path), { immediate: true });

function go() {
  const path = draft.value.trim();
  if (path && path !== here.value) emit("navigate", path);
}

function up() {
  const parent = props.listing?.parent;
  if (parent) emit("navigate", parent);
}

/** Jumps to a drive and puts the picker back to its label. */
function pickRoot(event: Event) {
  const select = event.target as HTMLSelectElement;
  const root = select.value;
  select.value = "";
  if (root) emit("navigate", root);
}

/**
 * Turns while the listing is being read, and always for at least one whole
 * turn: a refresh that comes back in twenty milliseconds would otherwise
 * flicker and look like nothing had happened.
 */
const spinning = ref(false);

function refresh() {
  spinning.value = true;
  emit("refresh");
}

function onTurn() {
  if (!props.loading) spinning.value = false;
}

// ---- Selection -------------------------------------------------------------

/** A Set rather than an array: a directory of ten thousand files is normal. */
const selected = ref(new Set<string>());
/** Where a shift-click measures from. */
const anchor = ref(-1);

/** Every write to the selection goes through here, so none forgets to claim it. */
function choose(paths: Set<string>) {
  selected.value = paths;
  if (paths.size) emit("select");
}

function clear() {
  selected.value = new Set();
  anchor.value = -1;
}

// Another directory is another set of files; keeping paths selected across a
// navigation would mean acting on things no longer on screen.
watch(here, clear);

// The other pane has taken the selection, so this one lets go of its own.
watch(
  () => props.owner,
  (owner) => {
    if (owner && owner !== props.side) clear();
  },
);

const chosen = computed(() => entries.value.filter((entry) => selected.value.has(entry.path)));

/**
 * Which row an event happened on, or -1 for the empty space below them.
 *
 * Handled on the list rather than on the rows and resolved from the DOM
 * afterwards, so one listener serves a directory of any size. `data-path` is
 * what carries the answer — the same attribute a drop reads.
 */
function rowAt(target: EventTarget | null): number {
  const path = (target as Element | null)?.closest<HTMLElement>("[data-path]")?.dataset.path;
  return path === undefined ? -1 : entries.value.findIndex((entry) => entry.path === path);
}

function onClick(event: MouseEvent) {
  const index = rowAt(event.target);
  if (index >= 0) pick(index, event);
}

function onDoubleClick(event: MouseEvent) {
  const index = rowAt(event.target);
  if (index >= 0) activate(entries.value[index]);
}

function pick(index: number, event: MouseEvent) {
  // The click that ends a drag lands on the row the drag started from; acting
  // on it would undo the selection that was just carried across.
  if (dragged) {
    dragged = false;
    return;
  }
  const entry = entries.value[index];
  if (!entry) return;

  if (event.shiftKey && anchor.value >= 0) {
    const [from, to] = anchor.value < index ? [anchor.value, index] : [index, anchor.value];
    const range = event.ctrlKey ? new Set(selected.value) : new Set<string>();
    for (let i = from; i <= to; i += 1) range.add(entries.value[i].path);
    choose(range);
    return;
  }

  if (event.ctrlKey) {
    const toggled = new Set(selected.value);
    if (toggled.has(entry.path)) toggled.delete(entry.path);
    else toggled.add(entry.path);
    choose(toggled);
  } else {
    choose(new Set([entry.path]));
  }
  anchor.value = index;
}

function selectAll() {
  choose(new Set(entries.value.map((entry) => entry.path)));
}

/** A directory opens, a file goes across. Both are what a double-click means. */
function activate(entry: FileEntry) {
  if (entry.isDir) emit("navigate", entry.path);
  else emit("transfer", [entry]);
}

// ---- Drag and drop ---------------------------------------------------------

/*
 * Dragging is done with plain pointer events rather than the HTML5 drag API.
 *
 * Not by preference — the two cannot coexist. A window has one OS-level drop
 * target, and Tauri claims it so that files dragged in from the file manager
 * arrive as real paths (`dragDropEnabled`, on by default). While it holds it,
 * the webview never sees a drag at all and `dragstart`/`drop` never fire.
 * Giving it up would get HTML5 drag back and lose the file manager: a dropped
 * file would reach the page as a `File` with no path, and the transfer queue
 * moves files by path precisely so a multi-gigabyte upload never has to pass
 * through the renderer.
 *
 * So: the file manager keeps the OS mechanism, and dragging between the panes
 * is done here, where nothing is competing for it.
 */

/** How far the pointer moves before it counts as a drag and not a click. */
const DRAG_THRESHOLD = 5;
/** How close to an edge the pointer scrolls the list under it. */
const SCROLL_EDGE = 28;
const SCROLL_STEP = 14;

/** A press that has not yet moved far enough to mean anything. */
let pressed: { x: number; y: number; index: number } | null = null;
/** Set when a drag starts, so the click that ends it does not reselect. */
let dragged = false;

function onPointerDown(event: PointerEvent) {
  dragged = false;
  // Left button only: the right one opens the menu, and the thumb buttons
  // navigate.
  if (event.button !== 0) return;
  // The empty space below the rows has nothing to drag.
  const index = rowAt(event.target);
  if (index < 0) return;
  pressed = { x: event.clientX, y: event.clientY, index };

  // Watched on the window, not on the list.
  //
  // Deliberately *not* `setPointerCapture`: a captured pointer makes the
  // browser retarget the whole click — `click`, `dblclick` and their
  // `event.target` all become the capturing element — so no row could be told
  // apart any more and clicking selected nothing. Window listeners give the
  // same reach without touching what a click means.
  window.addEventListener("pointermove", onPressMove);
  window.addEventListener("pointerup", endPress);
  window.addEventListener("pointercancel", endPress);
}

function onPressMove(event: PointerEvent) {
  if (!pressed) return;
  if (
    Math.abs(event.clientX - pressed.x) < DRAG_THRESHOLD &&
    Math.abs(event.clientY - pressed.y) < DRAG_THRESHOLD
  ) {
    return;
  }

  const { index } = pressed;
  // Handed over: from here the parent follows the pointer on the window.
  endPress();
  const entry = entries.value[index];
  if (!entry) return;

  // Dragging a row that was not selected is a statement about that row, not
  // about whatever happened to be selected before.
  if (!selected.value.has(entry.path)) {
    choose(new Set([entry.path]));
    anchor.value = index;
  }
  dragged = true;
  emit("dragstart", chosen.value, event.clientX, event.clientY);
}

function endPress() {
  pressed = null;
  window.removeEventListener("pointermove", onPressMove);
  window.removeEventListener("pointerup", endPress);
  window.removeEventListener("pointercancel", endPress);
}

onBeforeUnmount(endPress);

/**
 * What a drop at this point would land on, and null if the point is not over
 * this pane at all.
 *
 * Called by the parent on every move of a drag, from anywhere — a pointer drag
 * between the panes as much as a file dragged in from outside, which arrives
 * as window coordinates and nothing else. Nudging the list along near its
 * edges belongs to the same moment, which is why it happens here too: without
 * it there is no way to reach a folder further down while holding something.
 */
function hover(x: number, y: number): string | null {
  if (!props.listing || !root.value) return null;

  const element = document.elementFromPoint(x, y);
  if (!element || !root.value.contains(element)) return null;

  const list = listEl.value;
  if (list) {
    const box = list.getBoundingClientRect();
    if (y > box.top && y < box.top + SCROLL_EDGE) list.scrollTop -= SCROLL_STEP;
    else if (y < box.bottom && y > box.bottom - SCROLL_EDGE) list.scrollTop += SCROLL_STEP;
  }

  // Only directories take a drop of their own; anything else means the folder
  // that is open.
  const row = element.closest<HTMLElement>("[data-dir='1']");
  return row?.dataset.path ?? props.listing.path;
}

defineExpose({ hover });

// ---- Context menu ----------------------------------------------------------

/** Open: the list leaves the keyboard to the menu meanwhile. */
const menuOpen = ref(false);

/**
 * Right-clicking outside the selection moves it, the way every file manager
 * does: the menu is about what was clicked. Opened from the keyboard
 * (Shift+F10, the menu key) it is about the selection as it stands — the list
 * is focused as a whole, so there is no row under anything to go by.
 */
function beforeMenu(target: Element, details: ContextMenuOpenDetails) {
  if (details.source === "keyboard") return;
  const index = rowAt(target);
  if (index < 0) {
    clear();
    return;
  }
  if (!selected.value.has(entries.value[index].path)) {
    choose(new Set([entries.value[index].path]));
    anchor.value = index;
  }
}

const SEPARATOR: MenuEntry = { type: "separator" };

const menuItems = computed<MenuEntry[]>(() => {
  const count = chosen.value.length;
  const single = count === 1 ? chosen.value[0] : null;
  const remote = props.side === "remote";
  const entries: (MenuEntry | null)[] = [
    { value: "transfer", label: props.transferLabel, disabled: count === 0 },
    { value: "open", label: t("FilePane.menu.open"), disabled: !single?.isDir },
    remote
      ? { value: "edit", label: t("common.edit"), disabled: !single || single.isDir }
      : null,
    // Only where the protocol has such a thing at all — which is S3 and
    // nothing else, since neither SFTP nor FTP can hand out a URL that works
    // without a login.
    remote && props.links
      ? { value: "link", label: t("FilePane.menu.link"), disabled: !single || single.isDir }
      : null,
    SEPARATOR,
    { value: "rename", label: t("FilePane.rename"), disabled: count !== 1 },
    // Left out entirely where the protocol has no permissions, and greyed out
    // where this listing carried none — over FTP a server may simply not state
    // them. A dialog that starts at 000 because nothing was known is how
    // someone sets 000 without meaning to.
    remote && props.permissions !== false
      ? {
          value: "chmod",
          label: t("FilePane.menu.chmod"),
          disabled: !single || single.mode === null,
        }
      : null,
    { value: "remove", label: t("common.delete"), disabled: count === 0, danger: true },
    SEPARATOR,
    { value: "mkdir", label: t("FilePane.newFolder") },
    { value: "touch", label: t("FilePane.newFile") },
    { value: "refresh", label: t("FilePane.menu.refresh") },
  ];
  return entries.filter((entry): entry is MenuEntry => entry !== null);
});

function runMenu(id: string) {
  if (id === "transfer") emit("transfer", chosen.value);
  else if (id === "open" && chosen.value[0]) activate(chosen.value[0]);
  else if (id === "edit" && chosen.value[0]) emit("edit", chosen.value[0]);
  else if (id === "link" && chosen.value[0]) emit("link", chosen.value[0]);
  else if (id === "rename") startNaming("rename");
  else if (id === "chmod" && chosen.value[0]) emit("chmod", chosen.value[0]);
  else if (id === "remove") removing.value = true;
  else if (id === "mkdir") startNaming("mkdir");
  else if (id === "touch") startNaming("touch");
  else if (id === "refresh") refresh();
}

// ---- Create, rename, delete ------------------------------------------------

/** "New folder", "New file" and "Rename": one dialog, three verbs. */
type Naming = "mkdir" | "touch" | "rename";

const NAMING = computed<Record<Naming, { title: string; verb: string; preset: string }>>(() => ({
  mkdir: {
    title: t("FilePane.newFolder"),
    verb: t("FilePane.create"),
    preset: t("FilePane.newFolderPreset"),
  },
  touch: {
    title: t("FilePane.newFile"),
    verb: t("FilePane.create"),
    preset: t("FilePane.newFilePreset"),
  },
  rename: { title: t("FilePane.rename"), verb: t("FilePane.rename"), preset: "" },
}));

const naming = ref<{ kind: Naming; entry?: FileEntry } | null>(null);
const name = ref("");
const nameField = ref<TextFieldHandle>();

async function startNaming(kind: Naming) {
  const entry = kind === "rename" ? chosen.value[0] : undefined;
  if (kind === "rename" && !entry) return;
  naming.value = { kind, entry };
  name.value = entry?.name ?? NAMING.value[kind].preset;
  await nextTick();
  nameField.value?.focus();
  // Without the extension, which is the part nobody means to retype.
  const dot = name.value.lastIndexOf(".");
  nameField.value?.setSelectionRange(0, dot > 0 ? dot : name.value.length);
}

const nameOk = computed(() => {
  const value = name.value.trim();
  // A separator would move the entry somewhere else, which neither verb means.
  return value !== "" && !value.includes("/") && !value.includes("\\");
});

function confirmNaming() {
  const open = naming.value;
  if (!open || !nameOk.value) return;
  const value = name.value.trim();
  const path = join(props.side, here.value, value);
  if (open.kind === "mkdir") emit("mkdir", path);
  else if (open.kind === "touch") emit("touch", path);
  else if (open.entry) emit("rename", open.entry.path, path);
  naming.value = null;
}

const removing = ref(false);

function confirmRemove() {
  emit("remove", chosen.value);
  removing.value = false;
}

const removeQuestion = computed(() => {
  const count = chosen.value.length;
  if (count === 1) {
    const only = chosen.value[0];
    return t(only.isDir ? "FilePane.removeDir" : "FilePane.removeFile", { name: only.name });
  }
  return t("FilePane.removeMany", { n: count });
});

function onKeydown(event: KeyboardEvent) {
  // A dialog or a menu in front owns the keyboard. Without this the list
  // answers the same Enter that confirms the dialog it just opened.
  if (naming.value || removing.value || menuOpen.value) return;

  if (event.key === "Delete" && chosen.value.length) {
    removing.value = true;
  } else if (event.key === "F2" && chosen.value.length === 1) {
    startNaming("rename");
  } else if (event.key === "Enter") {
    // Opens a directory and does nothing else. It used to transfer a selected
    // file, which is far too easy to set off by accident — the key is pressed
    // to confirm a selection, not to act on it. Transferring is the double
    // click, the drag, the button and the menu.
    const only = chosen.value.length === 1 ? chosen.value[0] : null;
    if (!only?.isDir) return;
    emit("navigate", only.path);
  } else if (event.key === "a" && event.ctrlKey) {
    selectAll();
  } else if (event.key === "Backspace") {
    up();
  } else {
    return;
  }
  event.preventDefault();
}
</script>

<template>
  <!-- `perms` widens the grid for the permission column, which only the remote
       side fills. -->
  <section ref="root" class="pane" :class="{ perms: side === 'remote' }">
    <header class="bar">
      <span class="side">{{ title }}</span>

      <!-- Windows has no single root, so the pane would otherwise be stuck on
           whichever drive it started on. -->
      <!-- `pickRoot` reads and resets the <select> itself, so no v-model. -->
      <NativeSelect
        v-if="roots && roots.length > 1"
        class="roots"
        size="sm"
        :aria-label="t('FilePane.drive')"
        :placeholder="t('FilePane.drive')"
        :items="roots.map((root) => ({ value: root, label: root }))"
        @change="pickRoot"
      />

      <Input
        v-model="draft"
        class="path"
        size="sm"
        mono
        type="text"
        spellcheck="false"
        :aria-label="t('FilePane.path', { title })"
        @keydown.enter.prevent="go"
        @keydown.esc.prevent="draft = here"
      />

      <Button variant="text" size="sm" :disabled="!chosen.length" @click="emit('transfer', chosen)">
        {{ transferLabel }}
      </Button>

      <IconButton
        :icon="ArrowUp"
        :label="t('FilePane.up')"
        :title="t('FilePane.up')"
        variant="text"
        size="sm"
        :disabled="!listing?.parent"
        @click="up"
      />
      <!-- `animationiteration` bubbles up from the turning icon. -->
      <IconButton
        :icon="RefreshCw"
        :label="t('FilePane.reload')"
        :title="t('FilePane.reload')"
        variant="text"
        size="sm"
        :class="{ spin: spinning }"
        @click="refresh"
        @animationiteration="onTurn"
      />

      <!-- The server pane's own gear. Here rather than in a slot: a slot's
           contents carry the parent's style scope, and every button on this
           bar is styled by this component. -->
      <IconButton
        v-if="settings"
        :icon="Settings"
        :label="t('FilePane.settings')"
        :title="t('FilePane.settings')"
        variant="text"
        size="sm"
        @click="emit('settings')"
      />
    </header>

    <Alert v-if="error" status="danger" variant="simple" size="sm" class="error">{{ error }}</Alert>

    <div class="head">
      <button
        v-for="column in columns"
        :key="column.key"
        class="column"
        :class="{ right: column.right, sorted: sortKey === column.key }"
        type="button"
        @click="sortBy(column.key)"
      >
        {{ t(column.label) }}
        <span class="caret">{{
          sortKey === column.key ? (ascending ? "▴" : "▾") : ""
        }}</span>
      </button>
    </div>

    <!--
      Focusable as a whole rather than per row: the keys below act on the
      selection, not on whatever the tab order last landed on.
    -->
    <!--
      The window moving under the menu, or a scroll that would leave it hanging
      over the wrong row, closes it too. The first entry starts highlighted, so
      Enter takes it, as in a desktop context menu.
    -->
    <ContextMenu
      v-model:open="menuOpen"
      :items="menuItems"
      :label="t('FilePane.actions')"
      close-on-scroll
      close-on-resize
      close-on-blur
      highlight-first
      @before-open="beforeMenu"
      @select="runMenu"
    >
    <div
      ref="listEl"
      class="list"
      :class="{ over: dropPath === here }"
      tabindex="0"
      @keydown="onKeydown"
      @click="onClick"
      @dblclick="onDoubleClick"
      @pointerdown="onPointerDown"
    >
      <!--
        `data-dir` is what a drag reads to find the folder under the pointer:
        the parent hit-tests with `elementFromPoint` and has only the DOM to go
        on. `data-path` carries the answer.
      -->
      <div
        v-for="entry in entries"
        :key="entry.path"
        class="row"
        :class="{ on: selected.has(entry.path), over: dropPath === entry.path }"
        :title="entry.path"
        :data-path="entry.path"
        :data-dir="entry.isDir ? '1' : '0'"
      >
        <span class="name">
          <span class="icon" :class="{ dir: entry.isDir }">
            <FolderIcon v-if="entry.isDir" />
            <FileIcon v-else />
          </span>
          <span class="label" :class="{ link: entry.isSymlink }">{{ entry.name }}</span>
        </span>
        <span class="right size">{{ entry.isDir ? "" : formatBytes(entry.size) }}</span>
        <span class="muted">{{ formatDate(entry.modified) }}</span>
        <span v-if="side === 'remote'" class="muted mono">{{ entry.permissions ?? "–" }}</span>
      </div>

      <EmptyState
        v-if="!entries.length && !loading && !error"
        :title="t('FilePane.empty')"
        size="sm"
      />
    </div>
    </ContextMenu>

    <footer class="status">
      <span v-if="working">
        {{ working }}
        <Button variant="text" size="sm" @click="emit('stop')">{{ t("common.cancel") }}</Button>
      </span>
      <span v-else-if="loading">{{ t("FilePane.loading") }}</span>
      <span v-else-if="chosen.length">{{
        t("FilePane.selected", { n: chosen.length, total: entries.length })
      }}</span>
      <span v-else-if="listing?.truncated" class="cut" :title="t('FilePane.truncatedTitle')">
        {{ t("FilePane.truncated", { n: entries.length }) }}
      </span>
      <span v-else>{{ t("FilePane.entries", entries.length) }}</span>
      <span
        v-if="space"
        class="space"
        :title="t('FilePane.free', { size: formatBytes(space.total - space.used) })"
      >
        <Progress
          class="meter"
          :value="Math.min(space.used, space.total)"
          :max="space.total"
          :label="t('FilePane.space')"
          size="xs"
          hide-label
          :show-value="false"
        />
        {{ t("FilePane.usage", { used: formatBytes(space.used), total: formatBytes(space.total) }) }}
      </span>
    </footer>

    <!-- Its own buttons rather than the dialog's: the default pair offers
         Delete in "edit" mode, and renaming is not a place to delete from. -->
    <EditDialog
      v-if="naming"
      :title="NAMING[naming.kind].title"
      :can-save="nameOk"
      @save="confirmNaming"
      @cancel="naming = null"
    >
      <Field :label="t('common.name')">
        <!-- No Enter handler of its own: the dialog answers the key for every
             field in it, so there is one rule and not one per input. -->
        <Input ref="nameField" v-model="name" type="text" spellcheck="false" data-autofocus />
      </Field>

      <template #actions>
        <span class="spacer"></span>
        <Button variant="outline" @click="naming = null">{{ t("common.cancel") }}</Button>
        <Button :disabled="!nameOk" @click="confirmNaming">
          {{ NAMING[naming.kind].verb }}
        </Button>
      </template>
    </EditDialog>

    <EditDialog
      v-if="removing"
      :title="t('common.delete')"
      @save="confirmRemove"
      @cancel="removing = false"
    >
      <p class="question">{{ removeQuestion }}</p>
      <Alert status="warn" variant="simple" size="sm">{{ t("FilePane.irreversible") }}</Alert>

      <template #actions>
        <span class="spacer"></span>
        <Button variant="outline" @click="removing = false">{{ t("common.cancel") }}</Button>
        <Button variant="danger" @click="confirmRemove">{{ t("common.delete") }}</Button>
      </template>
    </EditDialog>
  </section>
</template>

<style scoped>
.pane {
  display: flex;
  flex-direction: column;
  min-width: 0;
  min-height: 0;
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 8px;
  overflow: hidden;
}

.bar {
  display: flex;
  align-items: center;
  gap: 0.35rem;
  padding: 0.4rem 0.5rem;
  border-bottom: 1px solid var(--border);
}

.side {
  flex: 0 0 auto;
  font-size: 0.8rem;
  font-weight: 600;
  color: var(--muted);
  text-transform: uppercase;
  letter-spacing: 0.04em;
}

.roots {
  flex: 0 0 auto;
}

.path {
  flex: 1;
  min-width: 0;
}

.spin :deep(svg) {
  animation: spin 700ms linear infinite;
}

@keyframes spin {
  to {
    transform: rotate(360deg);
  }
}

/* One slow turn rather than none: the point is to show that the click landed,
   and a glyph that never moves says the opposite. */
@media (prefers-reduced-motion: reduce) {
  .spin :deep(svg) {
    animation-duration: 1.8s;
  }
}

.error {
  padding: 0.45rem 0.6rem;
  word-break: break-word;
  border-bottom: 1px solid var(--border);
}

.head,
.row {
  display: grid;
  grid-template-columns: minmax(0, 1fr) 6.5rem 9.5rem;
  align-items: center;
  gap: 0.5rem;
  padding: 0.22rem 0.6rem;
}

.pane.perms .head,
.pane.perms .row {
  grid-template-columns: minmax(0, 1fr) 6.5rem 9.5rem 6.5rem;
}

.head {
  padding: 0 0.35rem;
  border-bottom: 1px solid var(--border);
  gap: 0.25rem;
}

.column {
  display: flex;
  align-items: center;
  gap: 0.2rem;
  min-width: 0;
  padding: 0.35em 0.25em;
  border-radius: 4px;
  background: transparent;
  border-color: transparent;
  font-size: 0.78rem;
  text-transform: uppercase;
  letter-spacing: 0.04em;
  color: var(--muted);
}

.column.right {
  justify-content: flex-end;
}

.column:hover {
  color: var(--fg);
  background: var(--card);
  border-color: transparent;
}

.column.sorted {
  color: var(--fg);
}

.caret {
  font-size: 0.7em;
}

.list {
  flex: 1;
  min-height: 0;
  overflow: auto;
  outline: none;
  font-size: 0.9rem;
}

.list:focus-visible {
  box-shadow: inset 0 0 0 1px var(--accent-dim);
}

/* The pane as a whole is the target for "into the folder that is open". */
.list.over {
  box-shadow: inset 0 0 0 2px var(--accent);
}

.row {
  cursor: default;
  user-select: none;
  white-space: nowrap;
}

.row:hover {
  background: var(--card);
}

.row.on {
  background: var(--accent-dim);
}

/* A directory under the pointer takes the drop instead of the open folder, so
   it has to be the thing that looks like the target. */
.row.over {
  box-shadow: inset 0 0 0 2px var(--accent);
  background: var(--accent-dim);
}

.name {
  display: flex;
  align-items: center;
  gap: 0.4rem;
  min-width: 0;
}

.icon {
  flex: 0 0 auto;
  display: grid;
  place-items: center;
  color: var(--muted);
}

/* Directories carry the accent, so the eye can pick out the way through a
   long listing without reading it. */
.icon.dir {
  color: var(--accent);
}

.row.on .icon {
  color: var(--fg);
}

.label {
  overflow: hidden;
  text-overflow: ellipsis;
}

/* A symlink is worth seeing as one: it decides what "delete" removes. */
.label.link {
  font-style: italic;
}

.right {
  text-align: right;
}

.size,
.muted {
  color: var(--muted);
  font-variant-numeric: tabular-nums;
  overflow: hidden;
  text-overflow: ellipsis;
}

.row.on .size,
.row.on .muted {
  color: var(--fg);
}

.mono {
  font-family: ui-monospace, "Cascadia Mono", Consolas, monospace;
  font-size: 0.82rem;
}

.status {
  display: flex;
  justify-content: space-between;
  gap: 1rem;
  padding: 0.3rem 0.6rem;
  border-top: 1px solid var(--border);
  font-size: 0.8rem;
  color: var(--muted);
}

.cut {
  color: var(--warning, var(--muted));
}

.space {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  white-space: nowrap;
}

.meter {
  width: 6rem;
}

.question {
  margin: 0 0 0.5rem;
}

.spacer {
  flex: 1;
}
</style>
