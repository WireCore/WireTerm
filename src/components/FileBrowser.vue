<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, reactive, ref, shallowRef, watch } from "vue";
import { useI18n } from "vue-i18n";
import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { getCurrentWebview } from "@tauri-apps/api/webview";
import { openPath } from "@tauri-apps/plugin-opener";
import { Alert, Button, Spinner } from "@wirecore/wirelayer-vue";
import FilePane from "./FilePane.vue";
import LinkDialog from "./LinkDialog.vue";
import OverwriteDialog from "./OverwriteDialog.vue";
import PermissionsDialog from "./PermissionsDialog.vue";
import RemoteEdits from "./RemoteEdits.vue";
import TransferSettingsDialog from "./TransferSettingsDialog.vue";
import TransferQueue from "./TransferQueue.vue";
import { reportVaultProblem } from "../vault";
import {
  cancelTransfer,
  closeEdit as stopEdit,
  editStatusEvent,
  progressEvent,
  remote as remoteApi,
  remoteKind,
  type Space,
} from "../remote";
import { CANCELLED, candidateName, formatDate, join, joinLocal, joinRemote } from "../sftp";
import { transferSettings } from "../transfer-settings";
import {
  newId,
  type ConnectionSettings,
  type EditSession,
  type FileEntry,
  type Listing,
  type OverwriteAnswer,
  type OverwriteConflict,
  type RemoteEdit,
  type RemoteSystem,
  type StaleUploads,
  type TabStatus,
  type Transfer,
  type TransferDirection,
} from "../types";

/**
 * The file browser of a connection, over SFTP, FTP or S3.
 *
 * Two panes — this machine on the left, the target on the right — and a queue
 * underneath. Directories are not handed to the backend as such: they are
 * walked here and become one queued transfer per file, which is what lets the
 * queue say what is actually happening instead of showing one row that sits
 * still for a minute.
 *
 * Which protocol is underneath shows up in exactly one place, the `api` below.
 * Everything after it asks the same questions of either, because from up here
 * they are the same questions — the difference is in what they cost, and that
 * is the backend's business.
 *
 * On an SSH tab this is built on first use and kept afterwards, so switching
 * back to the terminal and out again does not lose where either pane was. On
 * an FTP or S3 tab it is the whole tab and is there from the start.
 */
const props = defineProps<{
  /** The tab's id: names the session the backend keeps for it. */
  sessionId: string;
  settings: ConnectionSettings;
  /**
   * Whether this browser is the one on screen.
   *
   * Every open tab keeps its browser mounted, so all of them hear the window's
   * file-drop events. Only the visible one may answer, or a file dropped on
   * one server would be uploaded to several.
   */
  active: boolean;
}>();

/**
 * Reported so the dot on a tab without a terminal means something: there the
 * browser is the whole connection, and nothing else is in a position to say
 * how it is doing. On an SSH tab the terminal says it instead and this is
 * ignored.
 */
const emit = defineEmits<{
  status: [status: TabStatus];
  /** What an S3 endpoint said it is, for the card; see `s3_connect`. */
  system: [system: RemoteSystem];
}>();
const { t } = useI18n();

/**
 * The backend commands of this connection, bound once.
 *
 * Which protocol they belong to is settled here and nowhere else below — see
 * [`remote`](../remote.ts). Bound once rather than recomputed, because the
 * session in the backend is opened as one protocol and stays that: a
 * connection whose type is edited while its tab is open is remounted by
 * `ConnectionPane` rather than switched underneath.
 */
const api = remoteApi(remoteKind(props.settings), props.sessionId);

const connecting = ref(false);
const connectError = ref("");

const local = ref<Listing | null>(null);
const localLoading = ref(false);
const localError = ref("");
const roots = ref<string[]>([]);

const remote = ref<Listing | null>(null);
const remoteLoading = ref(false);
const remoteError = ref("");
const space = ref<Space | null>(null);

/**
 * Left-behind multipart uploads in a bucket the pane went into. Asked once per
 * bucket and tab: the answer changes only when somebody uploads, and it is a
 * request of its own that a listing should not pay for every time.
 */
const staleUploads = ref<StaleUploads | null>(null);
const staleAsked = new Set<string>();
const staleBusy = ref(false);
const staleError = ref("");

const transfers = ref<Transfer[]>([]);
const unlisten = shallowRef<UnlistenFn>();
const unlistenFiles = shallowRef<UnlistenFn>();
const unlistenSystem = shallowRef<UnlistenFn>();

type Side = "local" | "remote";

// ---- Connecting ------------------------------------------------------------

async function connect() {
  if (connecting.value) return;
  connecting.value = true;
  connectError.value = "";
  emit("status", "connecting");
  try {
    // Over SSH this is free if the terminal in this tab is already logged in:
    // SFTP is another channel on the connection it opened, not a second login.
    // Over FTP it is the login, and over S3 it is one signed request that
    // proves the endpoint is there — in both cases there is nothing else in
    // the tab to have done it already.
    const home = await api.connect(props.settings);
    // `~` is the shell's, not the protocol's, so it is resolved here. A start
    // path that does not (or no longer) exist falls back to home.
    const start =
      props.settings.type === "s3" ? "" : props.settings.startPath?.replace(/^~(?=\/|$)/, home);
    await openRemote(start || home);
    if (start && remoteError.value) await openRemote(home);
    emit("status", "connected");
  } catch (e) {
    connectError.value = String(e);
    emit("status", "error");
    // A vault that has to be sorted out first — a missing account, a locked
    // Bitwarden — raises its own dialog; "Reconnect" is what to press
    // once it has been.
    reportVaultProblem(connectError.value);
  } finally {
    connecting.value = false;
  }
}

// ---- History ---------------------------------------------------------------

/**
 * Where each pane has been, so the mouse's back button has somewhere to go.
 *
 * Resolved paths only — recorded after a listing comes back, because what was
 * typed may have been relative or full of `..` and going "back" to that would
 * land somewhere else than the pane was.
 */
type History = { stack: string[]; index: number };
const history: Record<Side, History> = {
  local: reactive({ stack: [], index: -1 }),
  remote: reactive({ stack: [], index: -1 }),
};

function record(side: Side, path: string) {
  const trail = history[side];
  if (trail.stack[trail.index] === path) return;
  // Everything ahead of here is a branch that was not taken.
  trail.stack.splice(trail.index + 1);
  trail.stack.push(path);
  trail.index = trail.stack.length - 1;
}

function step(side: Side, by: number) {
  const trail = history[side];
  const next = trail.index + by;
  if (next < 0 || next >= trail.stack.length) return;
  trail.index = next;
  // Not recorded: moving through the trail must not rewrite it.
  open(side, trail.stack[next], false);
}

/**
 * Which pane the back button applies to: the one last pointed at.
 *
 * Set on the way down from the panes' own mousedown, so it is already right by
 * the time the button handler on this element sees the same event.
 */
const focused = ref<Side>("remote");

/**
 * Which pane holds the selection. Only one may.
 *
 * Kept apart from `focused` on purpose: pressing a pane's refresh button points
 * at it, but it is no reason to throw away what was marked on the other side.
 */
const owner = ref<Side | null>(null);

function onMouseNav(event: MouseEvent) {
  // 3 and 4 are the thumb buttons, which browsers map to back and forward.
  if (event.button !== 3 && event.button !== 4) return;
  // Both halves of the click: Chromium navigates on the release, and there is
  // nothing in this window's history worth going back to.
  event.preventDefault();
  if (event.type === "mousedown") step(focused.value, event.button === 3 ? -1 : 1);
}

// ---- Directories -----------------------------------------------------------

async function openRemote(path: string, remember = true) {
  remoteLoading.value = true;
  remoteError.value = "";
  try {
    remote.value = await api.list(path);
    if (remember) record("remote", remote.value.path);
    // Beside the listing, not before it: a server slow to answer this must
    // not hold the directory up, and one that cannot answer shows no bar.
    api.space(remote.value.path).then(
      (answer) => (space.value = answer),
      () => (space.value = null),
    );
    askStaleUploads(remote.value.path);
  } catch (e) {
    remoteError.value = String(e);
  } finally {
    remoteLoading.value = false;
  }
}

/**
 * Beside the listing as well. A failure is no news: a key that may read a
 * bucket need not be allowed to list its uploads, and saying so on every
 * bucket would be noise about something nobody asked.
 */
function askStaleUploads(path: string) {
  const bucket = path.split("/")[1];
  if (api.kind !== "s3" || !bucket || staleAsked.has(bucket)) return;
  staleAsked.add(bucket);
  api.staleUploads(path).then(
    (answer) => {
      if (answer) {
        staleUploads.value = answer;
        staleError.value = "";
      }
    },
    () => {},
  );
}

async function abortStaleUploads() {
  if (!staleUploads.value || staleBusy.value) return;
  staleBusy.value = true;
  staleError.value = "";
  try {
    await api.abortStaleUploads(staleUploads.value.bucket);
    staleUploads.value = null;
  } catch (e) {
    staleError.value = String(e);
  } finally {
    staleBusy.value = false;
  }
}

async function openLocal(path: string, remember = true) {
  localLoading.value = true;
  localError.value = "";
  try {
    local.value = await invoke<Listing>("local_list", { path });
    if (remember) record("local", local.value.path);
  } catch (e) {
    localError.value = String(e);
  } finally {
    localLoading.value = false;
  }
}

const open = (side: Side, path: string, remember = true) =>
  side === "remote" ? openRemote(path, remember) : openLocal(path, remember);

// Refreshing is not a move: it must not add a second entry to the trail.
const refreshRemote = () =>
  remote.value ? openRemote(remote.value.path, false) : Promise.resolve();
const refreshLocal = () => (local.value ? openLocal(local.value.path, false) : Promise.resolve());

// ---- Create, rename, delete ------------------------------------------------

async function remoteAction(run: () => Promise<unknown>) {
  try {
    await run();
    remoteError.value = "";
  } catch (e) {
    remoteError.value = String(e);
  }
  await refreshRemote();
}

async function localAction(run: () => Promise<unknown>) {
  try {
    await run();
    localError.value = "";
  } catch (e) {
    localError.value = String(e);
  }
  await refreshLocal();
}

/** Set while S3 deletes, the one protocol where it can be stopped. */
const removing = ref<string | null>(null);

function removeRemote(entries: FileEntry[]) {
  const operation = remoteKind(props.settings) === "s3" ? newId() : undefined;
  removing.value = operation ?? null;
  return remoteAction(async () => {
    try {
      for (const entry of entries) {
        await api.remove(entry.path, entry.isDir, operation);
      }
    } catch (e) {
      if (String(e).includes(CANCELLED)) {
        throw t("FileBrowser.removeCancelled");
      }
      throw e;
    } finally {
      removing.value = null;
    }
  });
}

function removeLocal(entries: FileEntry[]) {
  return localAction(async () => {
    for (const entry of entries) {
      await invoke("local_remove", { path: entry.path, isDir: entry.isDir });
    }
  });
}

// ---- Drag and drop ---------------------------------------------------------
//
// Two mechanisms, because a window has only one OS-level drop target and Tauri
// holds it (`dragDropEnabled`, on by default). That is what makes a file
// dragged in from the file manager arrive as a real path — which the transfer
// queue needs, since it moves files by path and never through the renderer.
// The price is that the webview sees no drag at all, so HTML5 drag and drop
// does not work anywhere in this window.
//
// Dragging between the panes is therefore done with plain pointer events, and
// the file manager keeps the OS mechanism. Both end in the same place: a
// directory to drop into, worked out by asking the pane under the pointer.
//
// A drop inside the pane the drag started in is a move rather than a transfer:
// nothing crosses the connection, and one rename says the whole thing.

const localPane = ref<InstanceType<typeof FilePane>>();
const remotePane = ref<InstanceType<typeof FilePane>>();

/** What is being dragged out of a pane, and where the pointer has got to. */
const drag = ref<{ source: Side; entries: FileEntry[]; x: number; y: number } | null>(null);

/**
 * Where a drop would land right now — which pane, and which directory in it.
 *
 * One piece of state for both mechanisms, so a pane highlights the same way
 * whether the files are coming from the other pane or from the file manager.
 */
const dropping = ref<{ side: Side; path: string } | null>(null);

const localDrop = computed(() =>
  dropping.value?.side === "local" ? dropping.value.path : null,
);
const remoteDrop = computed(() =>
  dropping.value?.side === "remote" ? dropping.value.path : null,
);

/**
 * Whether a drop inside the pane it came from would mean anything.
 *
 * Only a folder row counts: the open directory itself is where the entries
 * already are, and it is the one path `hover` reports that is not a row. Never
 * a folder that is part of what is being dragged either — and since everything
 * in the drag is a sibling of the target, one that is not the target cannot
 * contain it, so there is nothing deeper to rule out.
 */
function movable(side: Side, path: string, dragged: FileEntry[]): boolean {
  const here = (side === "local" ? local.value : remote.value)?.path;
  if (!here || path === here) return false;
  return !dragged.some((entry) => entry.path === path);
}

/**
 * Where a drop at this point would land, or null where it would land nowhere.
 *
 * Both panes are asked rather than only the opposite one, since a drop on a
 * folder of the pane the drag started in is a move. `hover` leaves a pane the
 * pointer is not over untouched, so asking both never scrolls the wrong list.
 */
function targetAt(x: number, y: number, dragged: FileEntry[], source: Side) {
  const sides: Side[] = ["local", "remote"];
  for (const side of sides) {
    const pane = side === "local" ? localPane.value : remotePane.value;
    const path = pane?.hover(x, y) ?? null;
    if (!path) continue;
    if (side === source && !movable(side, path, dragged)) return null;
    return { side, path };
  }
  return null;
}

function beginDrag(source: Side, entries: FileEntry[], x: number, y: number) {
  if (!entries.length) return;
  drag.value = { source, entries, x, y };
  // On the window, not on the panes: the pointer spends most of a drag between
  // them, over the splitter, the queue, or outside the window entirely.
  window.addEventListener("pointermove", moveDrag);
  window.addEventListener("pointerup", finishDrag);
  window.addEventListener("pointercancel", endDrag);
  window.addEventListener("keydown", onDragKey);
  document.body.classList.add("dragging");
  moveDrag({ clientX: x, clientY: y } as PointerEvent);
}

function moveDrag(event: PointerEvent) {
  const current = drag.value;
  if (!current) return;
  current.x = event.clientX;
  current.y = event.clientY;
  dropping.value = targetAt(event.clientX, event.clientY, current.entries, current.source);
}

function finishDrag(event: PointerEvent) {
  const current = drag.value;
  if (!current) return;
  // Asked once more rather than trusting the last move: a pointer can be
  // released somewhere no move event reported.
  const target = targetAt(event.clientX, event.clientY, current.entries, current.source);
  const { source, entries } = current;
  endDrag();
  if (!target) return;
  if (target.side === source) void move(source, entries, target.path);
  else if (source === "local") void upload(entries, target.path);
  else void download(entries, target.path);
}

function onDragKey(event: KeyboardEvent) {
  if (event.key === "Escape") endDrag();
}

function endDrag() {
  drag.value = null;
  dropping.value = null;
  window.removeEventListener("pointermove", moveDrag);
  window.removeEventListener("pointerup", finishDrag);
  window.removeEventListener("pointercancel", endDrag);
  window.removeEventListener("keydown", onDragKey);
  document.body.classList.remove("dragging");
}

// ---- Dropping from the file manager ----------------------------------------

/**
 * Where the file manager says the pointer is, in the page's own coordinates.
 *
 * The event reports physical pixels — what the screen has — while everything
 * in the page is measured in CSS pixels. On a display at anything but 100 %
 * the two differ, and a drop would be tested against the wrong place.
 */
function toPage(position: { x: number; y: number }) {
  const ratio = window.devicePixelRatio || 1;
  return { x: position.x / ratio, y: position.y / ratio };
}

/**
 * Only the server pane takes these.
 *
 * Dropping onto the local pane would be a local copy — a file operation that
 * has nothing to do with this connection, and nothing in the backend to do it
 * with. Not highlighting it is how that is said.
 */
function fileManagerTarget(x: number, y: number): string | null {
  return remotePane.value?.hover(x, y) ?? null;
}

/** Turns the bare paths a drop carries back into entries the queue can take. */
async function uploadPaths(paths: string[], target: string) {
  try {
    const entries = await Promise.all(
      paths.map((path) => invoke<FileEntry>("local_stat", { path })),
    );
    await upload(entries, target);
  } catch (e) {
    localError.value = String(e);
  }
}

// ---- Already exists ---------------------------------------------------------
//
// One row per name that is already taken, each with its own answer, and a
// header that sets them all at once. A handful of names is worth reviewing one
// by one and a dragged folder of a hundred is not; the header is how one
// dialog serves both without having to guess which case it is in.
//
// Two directories of the same name are not a conflict but a merge: what is
// dropped joins what is there. Whatever collides *inside* is a conflict of its
// own, found while the folder is walked and asked about by name — which is why
// a folder with many conflicts can raise the dialog twice, once for the names
// dropped and once for what turned up underneath them.

const conflictDialog = ref<{
  conflicts: OverwriteConflict[];
  nested: boolean;
  merge: boolean;
  resolve: (answer: OverwriteAnswer) => void;
} | null>(null);

function askOverwrite(
  conflicts: OverwriteConflict[],
  { nested = false, merge = true } = {},
): Promise<OverwriteAnswer> {
  return new Promise((resolve) => {
    conflictDialog.value = { conflicts, nested, merge, resolve };
  });
}

function answerOverwrite(answer: OverwriteAnswer) {
  conflictDialog.value?.resolve(answer);
  conflictDialog.value = null;
}

/**
 * What a directory holds, by name.
 *
 * One listing rather than an existence check per name: a dragged folder of two
 * hundred files used to ask two hundred questions, and a listing answers all
 * of them at once. It also says how large and how old each entry is, which is
 * what lets the dialog show what would be replaced by what.
 *
 * A directory that is not there yet reads as empty, which is the truth —
 * nothing in it can collide.
 */
async function index(side: Side, dir: string): Promise<Map<string, FileEntry>> {
  try {
    const listing =
      side === "remote"
        ? await api.list(dir)
        : await invoke<Listing>("local_list", { path: dir });
    return new Map(listing.entries.map((entry) => [entry.name, entry]));
  } catch {
    return new Map();
  }
}

function conflictOf(
  key: string,
  label: string,
  source: FileEntry,
  target: FileEntry,
): OverwriteConflict {
  return {
    key,
    label,
    isDir: source.isDir,
    size: source.size,
    modified: source.modified,
    targetIsDir: target.isDir,
    targetSize: target.size,
    targetModified: target.modified,
  };
}

/**
 * The first name in the `note.txt` → `note (2).txt` series that nothing has
 * claimed, and claiming it — each guess changes what the next one has to
 * avoid, whether the name was taken by the target or by an earlier rename in
 * the same batch.
 */
function freeName(name: string, isDir: boolean, taken: Set<string>): string {
  let attempt = 2;
  let candidate = candidateName(name, isDir, attempt);
  while (taken.has(candidate)) {
    attempt += 1;
    candidate = candidateName(name, isDir, attempt);
  }
  taken.add(candidate);
  return candidate;
}

/**
 * Works out the target name for every entry that was dropped, asking about the
 * ones whose name is already taken.
 *
 * Returns null on "Cancel". Entries left out of the map are the ones to
 * skip. `merge` is off for a move, which has no way to merge two directories:
 * a rename cannot put one inside another, so there the pair is a real conflict
 * and "Replace" means what it says.
 */
async function resolveTargets(
  side: Side,
  dir: string,
  entries: FileEntry[],
  merge = true,
): Promise<{ names: Map<string, string>; present: Map<string, FileEntry> } | null> {
  const present = await index(side, dir);
  const names = new Map(entries.map((entry) => [entry.path, entry.name]));

  const conflicts: OverwriteConflict[] = [];
  for (const entry of entries) {
    const target = present.get(entry.name);
    if (!target) continue;
    if (merge && entry.isDir && target.isDir) continue;
    conflicts.push(conflictOf(entry.path, entry.name, entry, target));
  }
  if (!conflicts.length) return { names, present };

  const answer = await askOverwrite(conflicts, { merge });
  if (!answer) return null;

  // Both what is at the target and what is arriving beside it: a renamed entry
  // must not be given the name of another entry in the same drop.
  const taken = new Set([...present.keys(), ...entries.map((entry) => entry.name)]);
  for (const entry of entries) {
    const action = answer[entry.path];
    if (!action || action === "overwrite") continue;
    if (action === "skip") names.delete(entry.path);
    else names.set(entry.path, freeName(entry.name, entry.isDir, taken));
  }
  return { names, present };
}

// ---- Filling the queue -----------------------------------------------------

function queued(
  direction: TransferDirection,
  name: string,
  localPath: string,
  remotePath: string,
  size: number,
): Transfer {
  return {
    id: newId(),
    direction,
    name,
    local: localPath,
    remote: remotePath,
    size,
    transferred: 0,
    status: "queued",
  };
}

/**
 * What walking a dropped folder produces: the transfers it becomes, the names
 * it would overwrite on the way, and what each directory it touched already
 * held — the last so a rename can be worked out without asking again.
 */
type Plan = {
  transfers: Transfer[];
  conflicts: OverwriteConflict[];
  /** Per target directory, the names in it that are spoken for. */
  taken: Map<string, Set<string>>;
  /** Which directory each conflict is in, by its key. */
  dirOf: Map<string, string>;
};

const emptyPlan = (): Plan => ({
  transfers: [],
  conflicts: [],
  taken: new Map(),
  dirOf: new Map(),
});

/** A path below `base`, which is what says where a nested conflict is. */
function relative(base: string, path: string): string {
  return path.startsWith(base) ? path.slice(base.length).replace(/^[\\/]+/, "") : path;
}

/**
 * Walks a remote directory, creating the local tree as it goes.
 *
 * `seen` holds the directories already visited, by their resolved path. A
 * symlink pointing back up its own tree would otherwise walk forever, and
 * there is no depth at which that stops being possible.
 *
 * `base` is the directory the whole drop landed in, and is only carried along
 * so a conflict deep inside can be labelled by its path below it rather than
 * by a bare file name that says nothing about where it is.
 */
async function walkRemote(
  path: string,
  target: string,
  plan: Plan,
  seen: Set<string>,
  base: string,
) {
  const listing = await api.list(path);
  if (seen.has(listing.path)) return;
  seen.add(listing.path);

  // Created now rather than by the transfer, so an empty directory comes
  // across too.
  await invoke("local_mkdir", { path: target });
  // Read after creating it, so a directory that was not there reads as empty
  // rather than failing: what matters is what was in it beforehand.
  const present = await index("local", target);
  plan.taken.set(
    target,
    new Set([...present.keys(), ...listing.entries.map((entry) => entry.name)]),
  );

  for (const entry of listing.entries) {
    const next = joinLocal(target, entry.name);
    if (entry.isDir) {
      await walkRemote(entry.path, next, plan, seen, base);
      continue;
    }
    const clash = present.get(entry.name);
    if (clash) {
      plan.conflicts.push(conflictOf(next, relative(base, next), entry, clash));
      plan.dirOf.set(next, target);
    }
    plan.transfers.push(queued("download", entry.name, next, entry.path, entry.size));
  }
}

async function walkLocal(
  path: string,
  target: string,
  plan: Plan,
  seen: Set<string>,
  base: string,
) {
  const listing = await invoke<Listing>("local_list", { path });
  if (seen.has(listing.path)) return;
  seen.add(listing.path);

  await api.mkdir(target);
  const present = await index("remote", target);
  plan.taken.set(
    target,
    new Set([...present.keys(), ...listing.entries.map((entry) => entry.name)]),
  );

  for (const entry of listing.entries) {
    const next = joinRemote(target, entry.name);
    if (entry.isDir) {
      await walkLocal(entry.path, next, plan, seen, base);
      continue;
    }
    const clash = present.get(entry.name);
    if (clash) {
      plan.conflicts.push(conflictOf(next, relative(base, next), entry, clash));
      plan.dirOf.set(next, target);
    }
    plan.transfers.push(queued("upload", entry.name, entry.path, next, entry.size));
  }
}

/**
 * Asks about the conflicts the walk found inside merged directories and
 * applies the answer to the transfers.
 *
 * Skipped files leave the batch; renamed ones are given a free name in the
 * directory they were going to land in, worked out from what the walk already
 * read rather than by asking the other side again. "Cancel" drops the whole
 * batch: half a folder is not what anyone meant by cancelling.
 */
async function settle(plan: Plan, side: Side): Promise<Transfer[]> {
  if (!plan.conflicts.length) return plan.transfers;

  const answer = await askOverwrite(plan.conflicts, { nested: true });
  if (!answer) return [];

  const target = (transfer: Transfer) => (side === "local" ? transfer.local : transfer.remote);
  const byTarget = new Map(plan.transfers.map((transfer) => [target(transfer), transfer]));
  const dropped = new Set<string>();

  for (const conflict of plan.conflicts) {
    const action = answer[conflict.key];
    if (!action || action === "overwrite") continue;
    const transfer = byTarget.get(conflict.key);
    if (!transfer) continue;
    if (action === "skip") {
      dropped.add(conflict.key);
      continue;
    }
    const dir = plan.dirOf.get(conflict.key);
    if (dir === undefined) continue;
    const taken = plan.taken.get(dir) ?? new Set<string>();
    const name = freeName(transfer.name, false, taken);
    plan.taken.set(dir, taken);
    transfer.name = name;
    if (side === "local") transfer.local = joinLocal(dir, name);
    else transfer.remote = joinRemote(dir, name);
  }

  return plan.transfers.filter((transfer) => !dropped.has(target(transfer)));
}

/**
 * "Download": from the remote pane into the local one.
 *
 * `target` is given when something was dropped on a directory; otherwise it is
 * whatever the local pane currently shows.
 */
async function download(entries: FileEntry[], target = local.value?.path) {
  if (!target || !entries.length) return;
  const resolved = await resolveTargets("local", target, entries);
  if (!resolved) return; // "Cancel"

  const plan = emptyPlan();
  const seen = new Set<string>();
  try {
    for (const entry of entries) {
      const name = resolved.names.get(entry.path);
      if (name === undefined) continue; // "Skip"
      const into = joinLocal(target, name);
      if (entry.isDir) await walkRemote(entry.path, into, plan, seen, target);
      else plan.transfers.push(queued("download", name, into, entry.path, entry.size));
    }
    remoteError.value = "";
  } catch (e) {
    // Whatever was collected before the failure is still worth transferring;
    // the message says what could not be read.
    remoteError.value = String(e);
  }
  enqueue(await settle(plan, "local"));
}

async function upload(entries: FileEntry[], target = remote.value?.path) {
  if (!target || !entries.length) return;
  const resolved = await resolveTargets("remote", target, entries);
  if (!resolved) return;

  const plan = emptyPlan();
  const seen = new Set<string>();
  try {
    for (const entry of entries) {
      const name = resolved.names.get(entry.path);
      if (name === undefined) continue;
      const into = joinRemote(target, name);
      if (entry.isDir) await walkLocal(entry.path, into, plan, seen, target);
      else plan.transfers.push(queued("upload", name, entry.path, into, entry.size));
    }
    localError.value = "";
  } catch (e) {
    localError.value = String(e);
  }
  enqueue(await settle(plan, "remote"));
}

// ---- Moving within one side -------------------------------------------------

const renameOn = (side: Side, from: string, to: string) =>
  side === "remote"
    ? api.rename(from, to)
    : invoke("local_rename", { from, to });

const removeOn = (side: Side, entry: FileEntry) =>
  side === "remote"
    ? api.remove(entry.path, entry.isDir)
    : invoke("local_remove", { path: entry.path, isDir: entry.isDir });

/**
 * Moves entries into a folder of the pane they came from.
 *
 * A rename on one side, not a transfer: nothing crosses the connection, so
 * there is nothing for the queue to show and no progress to report. The
 * overwrite question is the same one a transfer asks, because the outcome is
 * the same — something at the target stops existing — except that two
 * directories cannot be merged here, which is what `merge: false` says.
 */
async function move(side: Side, entries: FileEntry[], target: string) {
  const resolved = await resolveTargets(side, target, entries, false);
  if (!resolved) return;

  const act = side === "remote" ? remoteAction : localAction;
  await act(async () => {
    for (const entry of entries) {
      const name = resolved.names.get(entry.path);
      if (name === undefined) continue;
      const to = join(side, target, name);
      if (to === entry.path) continue;
      // Neither side's rename replaces an entry that is already there, so what
      // the dialog agreed to overwrite goes first. A name that was changed to
      // a free one finds nothing here.
      const clash = resolved.present.get(name);
      if (clash) await removeOn(side, clash);
      await renameOn(side, entry.path, to);
    }
  });
  // The entries left the directory that is open; the one they went into is not
  // on screen, so this is the only pane that has to be read again.
  owner.value = null;
}

// ---- Working through the queue ---------------------------------------------

/**
 * Successful transfers, which are no longer in the list.
 *
 * Their rows leave the moment they finish, so this is all that is left to say
 * a batch of two hundred files went across. Reset when a new batch starts on
 * an empty queue: that is a new piece of work, not a continuation.
 */
const completed = ref(0);
const completedBytes = ref(0);

function enqueue(batch: Transfer[]) {
  if (!batch.length) return;
  if (!transfers.value.length) {
    completed.value = 0;
    completedBytes.value = 0;
  }
  transfers.value.push(...batch);
  pump();
}

/**
 * Takes a stopped transfer off the list and throws away what it left behind.
 *
 * "Discard" is the one gesture that says the transfer is not wanted after
 * all: "Cancel" only stops it, and its `.wtpart` fragment stays so a later
 * attempt can carry on from it. Here the fragment goes too, which is what
 * keeps abandoned ones from piling up in the directory.
 */
function dismiss(id: string) {
  const transfer = transfers.value.find((entry) => entry.id === id);
  transfers.value = transfers.value.filter((entry) => entry.id !== id);
  if (!transfer) return;

  api
    .discard(transfer.direction, transfer.local, transfer.remote)
    .then(() =>
      // The fragment was visible in one of the panes; which one depends on
      // which way the transfer was going.
      transfer.direction === "download" ? refreshLocal() : refreshRemote(),
    )
    .catch(() => {});
}

/**
 * How many run at once: whatever the settings say, read rather than handed
 * over, so raising the number in the middle of a folder takes effect on that
 * folder — see [`pump`].
 *
 * The limit is about the round trip, not the link: russh-sftp already keeps
 * sixteen requests in flight for one file, so a large transfer fills a fast
 * line on its own. Many small files spend their time waiting for a reply, and
 * several waiting together is what hides it.
 */
let running = 0;

/**
 * Starts transfers until as many are running as the settings allow.
 *
 * Called whenever that could have changed — a batch arriving, a worker
 * finishing, the limit being moved — rather than starting a fixed number of
 * workers once and for all.
 */
function pump() {
  while (
    running < transferSettings.maxParallel &&
    transfers.value.some((transfer) => transfer.status === "queued")
  ) {
    running += 1;
    void worker().finally(() => {
      running -= 1;
      // The last one out turns the lights off: a download may have been
      // started from a pane that has since been navigated elsewhere, and
      // reading what is on screen again is cheap.
      if (running === 0) void Promise.all([refreshLocal(), refreshRemote()]);
    });
  }
}

// Raising the limit while a folder is going across starts further transfers at
// once; lowering it lets the extra ones finish and simply does not replace
// them, since `pump` is what starts a new one.
watch(() => transferSettings.maxParallel, pump);

/**
 * Claims one queued transfer at a time and runs it to the end.
 *
 * `find` and `run`'s own first line — marking the transfer "running" — happen
 * with no `await` between them, so two workers calling this back to back
 * cannot both claim the same one: whichever runs first has already changed
 * its status by the time the other's `find` looks at it.
 */
async function worker() {
  for (;;) {
    const next = transfers.value.find((entry) => entry.status === "queued");
    if (!next) return;
    await run(next);
  }
}

async function run(transfer: Transfer) {
  transfer.status = "running";
  transfer.startedAt = performance.now();
  transfer.transferred = 0;
  transfer.elapsed = undefined;
  transfer.error = undefined;

  try {
    const moved =
      transfer.direction === "download"
        ? await api.download(transfer.id, transfer.remote, transfer.local)
        : await api.upload(transfer.id, transfer.local, transfer.remote);
    transfer.transferred = moved;
    // A server that would not say how big the file was: now we know.
    if (!transfer.size) transfer.size = moved;
    transfer.status = "done";
    // Off the list straight away. It is counted in the header instead, so a
    // long queue shows what is left rather than what is behind it.
    completed.value += 1;
    completedBytes.value += moved;
    const at = transfers.value.indexOf(transfer);
    if (at >= 0) transfers.value.splice(at, 1);
  } catch (e) {
    const message = String(e);
    const stopped = message.includes(CANCELLED);
    transfer.status = stopped ? "cancelled" : "error";
    if (!stopped) transfer.error = message;
  } finally {
    transfer.elapsed = performance.now() - (transfer.startedAt ?? performance.now());
  }
}

function cancel(id: string) {
  const transfer = transfers.value.find((entry) => entry.id === id);
  if (!transfer) return;
  // One that has not started yet never reaches the backend, so there is
  // nothing there to stop.
  if (transfer.status === "queued") transfer.status = "cancelled";
  else if (transfer.status === "running") {
    cancelTransfer(id).catch(() => {});
  }
}

function cancelAll() {
  for (const transfer of transfers.value) {
    if (transfer.status === "queued" || transfer.status === "running") cancel(transfer.id);
  }
}

function retry(id: string) {
  const transfer = transfers.value.find((entry) => entry.id === id);
  if (!transfer) return;
  transfer.status = "queued";
  transfer.transferred = 0;
  transfer.startedAt = undefined;
  transfer.elapsed = undefined;
  transfer.error = undefined;
  pump();
}

// ---- Queue height ----------------------------------------------------------

/**
 * Kept in localStorage rather than in the workspace: it describes this
 * window on this screen, and has no business travelling to another machine
 * along with the connections.
 */
const HEIGHT_KEY = "wireterm.sftpQueueHeight";
const MIN_HEIGHT = 120;
/** What the panes must keep, so the queue can never swallow them. */
const MIN_PANES = 200;

function storedHeight(): number {
  try {
    const value = Number(localStorage.getItem(HEIGHT_KEY));
    if (Number.isFinite(value) && value >= MIN_HEIGHT) return value;
  } catch {
    // Private mode or blocked storage; the default is no loss.
  }
  return 260;
}

const queueHeight = ref(storedHeight());
const collapsed = ref(false);
const resizing = ref(false);
const browser = ref<HTMLElement>();

let grabbedAt = 0;
let grabbedHeight = 0;

function startResize(event: PointerEvent) {
  grabbedAt = event.clientY;
  grabbedHeight = queueHeight.value;
  resizing.value = true;
  // Captured, so the drag survives the pointer leaving the thin handle — which
  // it does immediately, since the handle is what is being moved.
  (event.currentTarget as HTMLElement).setPointerCapture(event.pointerId);
}

function onResize(event: PointerEvent) {
  if (!resizing.value) return;
  const available = (browser.value?.clientHeight ?? window.innerHeight) - MIN_PANES;
  const wanted = grabbedHeight - (event.clientY - grabbedAt);
  queueHeight.value = Math.max(MIN_HEIGHT, Math.min(wanted, Math.max(MIN_HEIGHT, available)));
}

function endResize(event: PointerEvent) {
  if (!resizing.value) return;
  resizing.value = false;
  (event.currentTarget as HTMLElement).releasePointerCapture(event.pointerId);
  try {
    localStorage.setItem(HEIGHT_KEY, String(Math.round(queueHeight.value)));
  } catch {
    // see storedHeight
  }
}

/** Collapsed it is only its header, so the dragged height does not apply. */
const queueStyle = computed(() =>
  collapsed.value ? undefined : { height: `${queueHeight.value}px` },
);

// ---- Settings ---------------------------------------------------------------

/** The gear above the server pane. The settings themselves are app-wide. */
const settingsOpen = ref(false);

// ---- Change permissions -----------------------------------------------------

const chmodTarget = ref<FileEntry | null>(null);
/** The run in progress, which "Cancel" in the dialog stops. */
const chmodOperation = ref<string | null>(null);

/**
 * A recursive run keeps going past what it may not touch, so what it could not
 * do comes back as a count rather than as a failure — and is reported here in
 * the pane's own error line. The dialog stays up while it runs: on a large
 * tree this is thousands of requests, and closing it first would say the work
 * was already done.
 */
async function chmod(mode: number, recursive: boolean) {
  const entry = chmodTarget.value;
  if (!entry) return;
  const operation = newId();
  chmodOperation.value = operation;
  try {
    const result = await api.chmod(entry.path, mode, recursive, operation);
    const total = result.changed + result.failed;
    remoteError.value = result.cancelled
      ? t("FileBrowser.chmodCancelled", { n: total })
      : result.failed
        ? t("FileBrowser.chmodFailed", {
            failed: result.failed,
            total,
            reason: result.error ?? t("FileBrowser.unknownReason"),
          })
        : "";
  } catch (e) {
    remoteError.value = String(e);
  }
  chmodOperation.value = null;
  chmodTarget.value = null;
  await refreshRemote();
}

// ---- Create link ------------------------------------------------------------
//
// S3 only, and the one place where the panes are not the same on both sides:
// there is no such thing over SFTP or FTP, where reading a file means having a
// login. Whether the entry is offered at all is the adapter's answer, not this
// component's — see [`remote`](../remote.ts).

const linkTarget = ref<FileEntry | null>(null);
const linkUrl = ref("");
const linkBusy = ref(false);
const linkError = ref("");

async function createLink(seconds: number) {
  const entry = linkTarget.value;
  if (!entry || linkBusy.value) return;
  linkBusy.value = true;
  linkError.value = "";
  // Cleared first, so a second attempt after a changed validity cannot leave
  // the previous link on screen looking like the answer.
  linkUrl.value = "";
  try {
    linkUrl.value = await api.link(entry.path, seconds);
  } catch (e) {
    linkError.value = String(e);
  } finally {
    linkBusy.value = false;
  }
}

function closeLink() {
  linkTarget.value = null;
  linkUrl.value = "";
  linkError.value = "";
}

// ---- Editing on the server --------------------------------------------------
//
// Watched for as long as this browser stays open. Closing it ends every edit
// on the tab — merely switching to the terminal beside it does not, because
// that leaves this mounted. See `crate::edit` for the watch itself.

const edits = ref<RemoteEdit[]>([]);
const editListeners = new Map<string, UnlistenFn>();

async function openEdit(entry: FileEntry) {
  let started: EditSession | null = null;
  try {
    // The configured editor, or nothing — in which case the backend starts no
    // process and the file goes to the system below.
    const session = await api.editOpen(
      entry.path,
      transferSettings.editorPath.trim()
        ? { path: transferSettings.editorPath.trim(), args: transferSettings.editorArgs }
        : null,
    );
    started = session;
    edits.value.push({ id: session.id, name: session.name, remote: entry.path, state: "synced" });

    editListeners.set(
      session.id,
      await listen<{ state: RemoteEdit["state"]; message: string | null }>(
        editStatusEvent(session.id),
        (event) => {
          // The end of the edit — the editor was closed, or the working copy
          // went away. It arrives after any last upload, so taking the row
          // away here loses nothing.
          if (event.payload.state === "closed") {
            closeEdit(session.id);
            return;
          }
          const edit = edits.value.find((e) => e.id === session.id);
          if (!edit) return;
          edit.state = event.payload.state;
          edit.message = event.payload.message ?? undefined;
        },
      ),
    );

    // Only where the backend started nothing itself: the system's own choice
    // of program, the same as a link in a terminal opens in the system's own
    // browser. The path has to be inside the opener's scope — see
    // the backend's own `working_copy`, which is what puts it there. Nothing
    // waits for a
    // program opened this way, so such an edit ends only by hand.
    if (!session.opened) await openPath(session.localPath);
  } catch (e) {
    remoteError.value = String(e);
    // Nothing is being edited if nothing opened, and a row that stays in the
    // bar would offer to close an edit that never began — while the backend
    // went on polling a file no editor ever had.
    if (started) closeEdit(started.id);
  }
}

function closeEdit(id: string) {
  editListeners.get(id)?.();
  editListeners.delete(id);
  edits.value = edits.value.filter((e) => e.id !== id);
  stopEdit(id).catch(() => {});
}

// ---- Setup and teardown ----------------------------------------------------

onMounted(async () => {
  // Before connecting, so the first bytes of the first transfer are not
  // missed. Named per session: only this tab hears its own transfers.
  unlisten.value = await listen<{ id: string; transferred: number; total: number }>(
    progressEvent(props.sessionId),
    (event) => {
      const transfer = transfers.value.find((entry) => entry.id === event.payload.id);
      if (!transfer) return;
      transfer.transferred = event.payload.transferred;
      if (!transfer.size && event.payload.total) transfer.size = event.payload.total;
    },
  );
  unlistenSystem.value = await listen<RemoteSystem>(`system:${props.sessionId}`, (event) =>
    emit("system", event.payload),
  );

  // Files dragged in from outside. Reported by Tauri rather than by the page,
  // because it holds the window's drop target — see "Drag and drop".
  unlistenFiles.value = await getCurrentWebview().onDragDropEvent((event) => {
    if (!props.active) return;
    const payload = event.payload;

    if (payload.type === "leave") {
      dropping.value = null;
      return;
    }

    const { x, y } = toPage(payload.position);
    const target = fileManagerTarget(x, y);

    if (payload.type === "drop") {
      dropping.value = null;
      if (target) uploadPaths(payload.paths, target);
    } else {
      // "enter" and "over" both only say where the pointer is.
      dropping.value = target ? { side: "remote", path: target } : null;
    }
  });

  // The local side needs no connection, so it fills in while the login runs.
  roots.value = await invoke<string[]>("local_roots").catch(() => []);
  invoke<string>("local_home")
    .then((home) => openLocal(home))
    .catch((e) => (localError.value = String(e)));

  await connect();
});

onBeforeUnmount(() => {
  unlisten.value?.();
  unlistenFiles.value?.();
  unlistenSystem.value?.();
  // A drag interrupted by the tab closing would otherwise leave its listeners
  // and the body class behind.
  endDrag();
  // The watchers themselves are stopped on the backend by the disconnect
  // below; this only lets go of the frontend's own event listeners.
  editListeners.forEach((stop) => stop());
  // Over SSH this closes only the file channel — the terminal beside it keeps
  // the connection. Over FTP and S3 there is nothing beside it, so this is the
  // lot.
  api.disconnect().catch(() => {});
});
</script>

<template>
  <!--
    The thumb buttons are caught here rather than on the window: every open tab
    keeps its browser mounted, and a listener on the window would have all of
    them answering one click.
  -->
  <section
    ref="browser"
    class="browser"
    @mousedown="onMouseNav"
    @mouseup="onMouseNav"
    @contextmenu.self.prevent
  >
    <Alert v-if="connectError" class="ended" status="danger" variant="simple" size="sm">
      {{ t("FileBrowser.noConnection") }}
      <template #actions>
        <Button variant="outline" :disabled="connecting" @click="connect">
          {{ t("FileBrowser.reconnect") }}
        </Button>
      </template>
    </Alert>

    <Alert v-if="staleUploads" class="ended" status="warn" variant="simple" size="sm">
      {{
        t(
          "FileBrowser.staleUploads",
          {
            bucket: staleUploads.bucket,
            n: staleUploads.count,
            date: formatDate(staleUploads.oldest),
          },
          staleUploads.count,
        )
      }}
      <template v-if="staleError"><br />{{ staleError }}</template>
      <template #actions>
        <Button variant="outline" :disabled="staleBusy" @click="abortStaleUploads">
          {{ t("FileBrowser.cleanUp") }}
        </Button>
        <Button variant="text" :disabled="staleBusy" @click="staleUploads = null">
          {{ t("FileBrowser.hide") }}
        </Button>
      </template>
    </Alert>

    <RemoteEdits :edits="edits" @close="closeEdit" />

    <div class="panes">
      <FilePane
        ref="localPane"
        :title="t('FileBrowser.local')"
        side="local"
        :listing="local"
        :loading="localLoading"
        :error="localError"
        :roots="roots"
        :drop-path="localDrop"
        :owner="owner"
        :transfer-label="t('FileBrowser.upload')"
        @mousedown="focused = 'local'"
        @navigate="(path) => openLocal(path)"
        @refresh="refreshLocal"
        @transfer="(entries) => upload(entries)"
        @mkdir="(path) => localAction(() => invoke('local_mkdir', { path }))"
        @touch="(path) => localAction(() => invoke('local_create_file', { path }))"
        @rename="(from, to) => localAction(() => invoke('local_rename', { from, to }))"
        @remove="removeLocal"
        @dragstart="(entries, x, y) => beginDrag('local', entries, x, y)"
        @select="owner = 'local'"
      />

      <FilePane
        ref="remotePane"
        :title="t('FileBrowser.server')"
        side="remote"
        settings
        :permissions="api.permissions"
        :links="api.links"
        :space="space"
        :listing="remote"
        :loading="remoteLoading || connecting"
        :error="connectError || remoteError"
        :working="removing ? t('FileBrowser.deleting') : undefined"
        :drop-path="remoteDrop"
        :owner="owner"
        :transfer-label="t('FileBrowser.download')"
        @mousedown="focused = 'remote'"
        @navigate="(path) => openRemote(path)"
        @refresh="refreshRemote"
        @transfer="(entries) => download(entries)"
        @mkdir="(path) => remoteAction(() => api.mkdir(path))"
        @touch="(path) => remoteAction(() => api.createFile(path))"
        @rename="(from, to) => remoteAction(() => api.rename(from, to))"
        @remove="removeRemote"
        @dragstart="(entries, x, y) => beginDrag('remote', entries, x, y)"
        @select="owner = 'remote'"
        @chmod="chmodTarget = $event"
        @edit="openEdit"
        @link="linkTarget = $event"
        @settings="settingsOpen = true"
        @stop="removing && cancelTransfer(removing)"
      />

      <!--
        Over the remote pane only: the local side is readable straight away and
        blanking it would say otherwise. `pointer-events: none` so it never
        sits between the user and what is underneath.
      -->
      <div v-if="connecting" class="loading">
        <Spinner
          :label="t('FileBrowser.connecting')"
          :classes="{ icon: 'size-9 text-[var(--accent)]' }"
        />
        <span class="loading-note" aria-hidden="true">{{ t("FileBrowser.connecting") }}</span>
      </div>
    </div>

    <div
      v-if="!collapsed"
      class="splitter"
      :class="{ held: resizing }"
      role="separator"
      aria-orientation="horizontal"
      :aria-label="t('FileBrowser.queueHeight')"
      @pointerdown.prevent="startResize"
      @pointermove="onResize"
      @pointerup="endResize"
      @pointercancel="endResize"
    ></div>

    <TransferQueue
      v-model:collapsed="collapsed"
      :transfers="transfers"
      :completed="completed"
      :completed-bytes="completedBytes"
      :style="queueStyle"
      @cancel="cancel"
      @retry="retry"
      @dismiss="dismiss"
      @cancel-all="cancelAll"
    />

    <!--
      What the pointer is carrying. Teleported and fixed, because it follows
      the pointer across both panes and everything between them; without
      pointer-events off it would be what every hit test found.
    -->
    <Teleport to="body">
      <div
        v-if="drag"
        class="drag-ghost"
        :style="{ left: `${drag.x + 14}px`, top: `${drag.y + 14}px` }"
      >
        <span class="count">{{ drag.entries.length }}</span>
        {{ drag.entries.length === 1 ? drag.entries[0].name : t("FileBrowser.entries") }}
      </div>
    </Teleport>

    <PermissionsDialog
      v-if="chmodTarget"
      :name="chmodTarget.name"
      :is-dir="chmodTarget.isDir"
      :mode="chmodTarget.mode"
      @save="chmod"
      @stop="chmodOperation && cancelTransfer(chmodOperation)"
      @cancel="chmodTarget = null"
    />

    <LinkDialog
      v-if="linkTarget"
      :name="linkTarget.name"
      :url="linkUrl"
      :busy="linkBusy"
      :error="linkError"
      @create="createLink"
      @close="closeLink"
    />

    <OverwriteDialog
      v-if="conflictDialog"
      :conflicts="conflictDialog.conflicts"
      :nested="conflictDialog.nested"
      :merge="conflictDialog.merge"
      @answer="answerOverwrite"
    />

    <TransferSettingsDialog v-if="settingsOpen" @close="settingsOpen = false" />
  </section>
</template>

<!--
  Unscoped, because it is the document's own body that has to change: a drag
  runs over everything, and a text cursor or a stray selection halfway through
  one says the wrong thing about what is happening.
-->
<style>
body.dragging {
  cursor: copy;
  user-select: none;
}

/*
  `drag-ghost` and not `ghost`: app-wide, `.ghost` is the quiet button —
  twenty-four of them sit in nine components — and this block is unscoped.
  Together that meant every such button got `position: fixed` and lay in the
  same spot as its neighbours.
*/
.drag-ghost {
  position: fixed;
  z-index: 300;
  display: flex;
  align-items: center;
  gap: 0.4rem;
  max-width: 18rem;
  padding: 0.25rem 0.6rem 0.25rem 0.3rem;
  border-radius: 6px;
  background: var(--panel);
  border: 1px solid var(--accent);
  box-shadow: 0 8px 24px rgba(0, 0, 0, 0.5);
  font-size: 0.82rem;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  pointer-events: none;
}

.drag-ghost .count {
  flex: 0 0 auto;
  min-width: 1.3rem;
  padding: 0.05rem 0.3rem;
  border-radius: 4px;
  background: var(--accent);
  color: var(--color-on-primary);
  font-weight: 600;
  text-align: center;
}
</style>

<style scoped>
.browser {
  display: flex;
  flex-direction: column;
  height: 100%;
  min-height: 0;
  padding: 0.5rem 1rem 1rem;
  box-sizing: border-box;
}

.ended {
  margin-bottom: 0.5rem;
}

.panes {
  position: relative;
  flex: 1;
  min-height: 0;
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 0.5rem;
}

/* Narrow windows cannot hold two file lists side by side; stacked they are
   still usable, and the transfer buttons still say which way things go. */
@media (max-width: 60rem) {
  .panes {
    grid-template-columns: 1fr;
    grid-template-rows: 1fr 1fr;
  }
}

/* Thin, but with room above and below to grab it: a splitter the width of the
   line it draws is a splitter nobody can hit. */
.splitter {
  flex: 0 0 auto;
  height: 0.6rem;
  margin: 0.15rem 0;
  border-radius: 3px;
  cursor: row-resize;
  touch-action: none;
  background: transparent;
}

.splitter::after {
  content: "";
  display: block;
  width: 3rem;
  height: 3px;
  margin: calc((0.6rem - 3px) / 2) auto;
  border-radius: 2px;
  background: var(--border);
}

.splitter:hover::after,
.splitter.held::after {
  background: var(--accent);
}

/* The queue takes the height it was dragged to; collapsed it takes none. */
.browser > :last-child {
  flex: 0 0 auto;
}

.loading {
  position: absolute;
  inset: 0 0 0 50%;
  z-index: 1;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 0.75rem;
  pointer-events: none;
}

@media (max-width: 60rem) {
  .loading {
    inset: 50% 0 0 0;
  }
}

.loading-note {
  font-size: 0.85rem;
  color: var(--muted);
}
</style>
