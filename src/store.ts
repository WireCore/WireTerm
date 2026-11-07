/**
 * The workspace tree and its persistence.
 *
 * The whole tree is written on every change. It is small, single-user data,
 * and this keeps the backend down to load and save instead of a command per
 * entity. Saves are debounced so a burst of keystrokes in a form does not
 * become a burst of disk writes.
 *
 * For a workspace on a backend the same holds as seen from here: the same
 * tree goes out. What becomes of it — a comparison against the local copy and
 * individual calls instead of an overwrite — is in `src-tauri/src/cloud`. The
 * difference this module has to know about is the sync: it runs on its own and
 * brings along changes nobody made here.
 */

import { reactive, ref } from "vue";
import { invoke } from "@tauri-apps/api/core";
import { dialogsOpen } from "./components/EditDialog.vue";
import * as cloud from "./cloud";
import type { Connection, ConnectionSettings, Project, SshSettings, Workspace } from "./types";

export const workspaces = reactive<Workspace[]>([]);
export const loaded = ref(false);
export const storageError = ref("");
export const storagePath = ref("");
/** Is a sync running right now? For the hint in the header. */
export const syncing = ref(false);

let saveTimer: ReturnType<typeof setTimeout> | undefined;

/**
 * Which workspace was open last. Kept in localStorage rather than in
 * workspaces.json: it describes this device's view, not the data, and it must
 * not travel along once workspaces can live on a backend or in the cloud.
 */
const LAST_WORKSPACE_KEY = "wireterm.lastWorkspaceId";

export function rememberWorkspace(id: string | null) {
  try {
    if (id) localStorage.setItem(LAST_WORKSPACE_KEY, id);
    else localStorage.removeItem(LAST_WORKSPACE_KEY);
  } catch {
    // Private mode or blocked storage: losing the last workspace is harmless.
  }
}

const OPEN_TABS_KEY = "wireterm.openTabs";

/** Which connections are open as tabs, and which of them is in front. */
export type OpenTabs = { connectionIds: string[]; active: number | null };

export function rememberTabs(open: OpenTabs) {
  try {
    localStorage.setItem(OPEN_TABS_KEY, JSON.stringify(open));
  } catch {
    // As with the workspace: without storage only the tabs are lost on restart.
  }
}

/** The tabs from last time — only those whose connection still exists. */
export function rememberedTabs(): OpenTabs {
  try {
    const raw = localStorage.getItem(OPEN_TABS_KEY);
    if (!raw) return { connectionIds: [], active: null };
    const open = JSON.parse(raw) as OpenTabs;
    const ids = Array.isArray(open.connectionIds) ? open.connectionIds : [];
    const active = typeof open.active === "number" ? ids[open.active] : undefined;
    const kept = ids.filter((id) => typeof id === "string" && findConnection(id));
    return { connectionIds: kept, active: active ? kept.indexOf(active) : null };
  } catch {
    return { connectionIds: [], active: null };
  }
}

/** The remembered workspace, or the first one if it is gone. */
export function initialWorkspaceId(): string | null {
  let remembered: string | null = null;
  try {
    remembered = localStorage.getItem(LAST_WORKSPACE_KEY);
  } catch {
    // see above
  }
  if (remembered && workspaces.some((w) => w.id === remembered)) return remembered;
  return workspaces[0]?.id ?? null;
}

export async function loadWorkspaces() {
  try {
    const stored = await invoke<Workspace[]>("workspaces_load");
    workspaces.splice(0, workspaces.length, ...stored);
    storagePath.value = await invoke<string>("workspaces_location");
    storageError.value = "";
  } catch (e) {
    storageError.value = String(e);
  } finally {
    loaded.value = true;
  }
}

// ---- Personal workspace ----------------------------------------------------
//
// Whoever has an account has an organization on the backend that belongs only
// to them — it is created at registration. Having to look for it in the dialog
// first turns a state into a task, so the client brings it into the rail on
// its own.

/**
 * Accounts whose personal workspace has been in the rail here before.
 *
 * In localStorage for the same reason as `LAST_WORKSPACE_KEY`: the note
 * describes this rail and not the data. Without it the workspace would come
 * back on the next start after every "Remove from rail".
 */
const ADOPTED_KEY = "wireterm.personalAdopted";

function adopted(): Set<string> {
  try {
    return new Set(JSON.parse(localStorage.getItem(ADOPTED_KEY) ?? "[]") as string[]);
  } catch {
    // Private mode or blocked storage, see `rememberWorkspace`: then the
    // workspace is simply added once more if it is missing.
    return new Set();
  }
}

/**
 * Brings the personal workspace into the rail — once per account.
 *
 * Without an account ID for all signed-in accounts, with one for that one:
 * after a sign-in only that one is meant, at startup each.
 *
 * Errors stay here. No network is no reason to let a sign-in fail — nothing is
 * noted then, and the next start tries again.
 */
export async function adoptPersonalWorkspaces(accountId?: string): Promise<void> {
  const done = adopted();
  const targets = cloud.accounts.filter(
    (account) =>
      account.signedIn && !done.has(account.id) && (!accountId || account.id === accountId),
  );
  if (targets.length === 0) return;

  let added = false;
  for (const account of targets) {
    try {
      const options = await cloud.availableWorkspaces(account.id);
      const personal = options.find((option) => option.kind === "personal");
      if (personal && !personal.added) {
        await cloud.addWorkspace(account.id, personal.id, personal.name);
        added = true;
      }
      done.add(account.id);
    } catch {
      // see above
    }
  }

  try {
    localStorage.setItem(ADOPTED_KEY, JSON.stringify([...done]));
  } catch {
    // see `rememberWorkspace`
  }

  if (added) await loadWorkspaces();
}

// ---- Sync -------------------------------------------------------------------
//
// A workspace on a backend changes even when nobody here does anything: a
// colleague adds a connection, an administrator shares a project. That is why
// the sync runs on its own — at startup, at intervals, and after every save
// (the Rust side takes care of that along the way).

/**
 * How often to sync on its own.
 *
 * One minute: often enough that a colleague's change does not only arrive
 * after lunch, rarely enough that a `since` query per workspace does not
 * matter — it normally returns empty lists.
 */
const SYNC_INTERVAL = 60_000;

let syncTimer: ReturnType<typeof setInterval> | undefined;

/**
 * Syncs and puts the result in place.
 *
 * Not while a dialog is open: the tree is swapped for the server's state, and
 * a form holds a connection from the old one — "Save" would then write into
 * something that no longer exists. The sync still runs; only putting it in
 * place waits for the next round.
 */
export async function syncNow(workspaceId?: string) {
  if (syncing.value) return;
  syncing.value = true;
  try {
    await cloud.sync(workspaceId);
    if (dialogsOpen.value === 0) await loadWorkspaces();
  } catch (e) {
    // No network is not an error the header would have to report: the
    // affected workspace carries it itself, see `Remote.error`.
    console.warn("Sync failed:", e);
  } finally {
    syncing.value = false;
  }
}

export function startSyncing() {
  if (syncTimer) return;
  syncTimer = setInterval(() => {
    if (workspaces.some((workspace) => workspace.remote)) void syncNow();
  }, SYNC_INTERVAL);
}

export function stopSyncing() {
  clearInterval(syncTimer);
  syncTimer = undefined;
}

/** Queues a save. Safe to call on every edit. */
export function persist() {
  clearTimeout(saveTimer);
  saveTimer = setTimeout(saveNow, 300);
}

// ---- Connections -----------------------------------------------------------
//
// A connection can be opened, edited or bookmarked from the overview and from
// the tab menu, and neither of them knows where in the tree it sits. These
// walk it, so that knowledge lives in one place.

/** The project holding a connection, anywhere in any workspace. */
export function projectOf(connectionId: string): Project | null {
  for (const workspace of workspaces) {
    for (const project of workspace.projects) {
      if (project.connections.some((c) => c.id === connectionId)) return project;
    }
  }
  return null;
}

/** The workspace a connection lives in. */
export function workspaceOf(connectionId: string): Workspace | null {
  return (
    workspaces.find((workspace) =>
      workspace.projects.some((project) => project.connections.some((c) => c.id === connectionId)),
    ) ?? null
  );
}

export function findConnection(id: string): Connection | null {
  return projectOf(id)?.connections.find((c) => c.id === id) ?? null;
}

/**
 * SSH settings with the chain of their jump hosts, first hop first — the way
 * the backend needs them to connect. Resolved here because the tree is here;
 * the backend gets the hops ready-made.
 *
 * If a hop is missing or the chain runs in a circle, `via` stays empty, and the
 * backend rejects the connection with a message instead of silently connecting
 * directly.
 */
export function withJumps(settings: ConnectionSettings): ConnectionSettings {
  if (settings.type !== "ssh" || !settings.jump) return settings;
  const via: SshSettings[] = [];
  const seen = new Set<string>();
  let id: string | undefined = settings.jump;
  while (id) {
    const hop = findConnection(id);
    if (seen.has(id) || !hop || hop.settings.type !== "ssh") return { ...settings, via: [] };
    seen.add(id);
    via.unshift({ ...hop.settings, jump: undefined, via: undefined, agentForwarding: false });
    id = hop.settings.jump;
  }
  return { ...settings, via };
}

/** Whether `candidate` ends up at `target` through a chain of jump hosts — then it is no good as its jump host. */
export function jumpsThrough(candidate: Connection, target: string): boolean {
  const seen = new Set<string>();
  let current: Connection | null = candidate;
  while (current && current.settings.type === "ssh" && current.settings.jump) {
    if (current.settings.jump === target || seen.has(current.id)) return true;
    seen.add(current.id);
    current = findConnection(current.settings.jump);
  }
  return false;
}

export function addConnection(projectId: string, connection: Connection) {
  for (const workspace of workspaces) {
    const project = workspace.projects.find((p) => p.id === projectId);
    if (!project) continue;
    project.connections.push(connection);
    persist();
    return;
  }
}

/**
 * Moves a connection to another place — within the same project or into
 * another one of the same workspace. `index` is the position it has afterwards,
 * counted without itself.
 */
export function moveConnection(id: string, projectId: string, index: number) {
  for (const workspace of workspaces) {
    const from = workspace.projects.find((p) => p.connections.some((c) => c.id === id));
    const to = workspace.projects.find((p) => p.id === projectId);
    if (!from || !to) continue;
    const at = from.connections.findIndex((c) => c.id === id);
    const [connection] = from.connections.splice(at, 1);
    to.connections.splice(Math.min(index, to.connections.length), 0, connection);
    persist();
    return;
  }
}

/**
 * Replaces a connection with an edited copy. Replaced rather than patched, and
 * looked up by id, so open tabs reading their connection by id follow along.
 */
export function updateConnection(connection: Connection) {
  const connections = projectOf(connection.id)?.connections;
  if (!connections) return;
  const index = connections.findIndex((c) => c.id === connection.id);
  if (index < 0) return;
  connections[index] = connection;
  persist();
}

export function deleteConnection(id: string) {
  const connections = projectOf(id)?.connections;
  if (!connections) return;
  const index = connections.findIndex((c) => c.id === id);
  if (index < 0) return;
  connections.splice(index, 1);
  persist();
}

export function toggleBookmark(connection: Connection) {
  connection.bookmarked = !connection.bookmarked;
  persist();
}

export async function saveNow() {
  clearTimeout(saveTimer);
  try {
    // Strip Vue's proxies: invoke serializes the argument, and reactive
    // objects carry properties that do not survive the round trip.
    await invoke("workspaces_save", {
      workspaces: JSON.parse(JSON.stringify(workspaces)),
    });
    storageError.value = "";
  } catch (e) {
    storageError.value = String(e);
    return;
  }

  // What goes to a backend is only queued by this. What became of it —
  // uploaded, left in the queue, rejected — is on the workspace afterwards,
  // and only if someone fetches it.
  if (workspaces.some((workspace) => workspace.remote) && dialogsOpen.value === 0) {
    await loadWorkspaces();
  }
}
