/**
 * How the file browser transfers.
 *
 * In localStorage rather than in workspaces.json, for the same reason the
 * terminal settings are: this describes what *this person on this machine*
 * wants of their link, not what a workspace contains. It must not travel along
 * once workspaces can live on a backend, and it applies to every connection in
 * every workspace at once.
 */

import { reactive, watch } from "vue";

export type TransferSettings = {
  /** How many files are transferred at the same time. */
  maxParallel: number;
  /**
   * The program "Edit" hands a working copy to. Empty means whatever
   * the system would open the file with.
   */
  editorPath: string;
  /**
   * Arguments for it, as typed. `%f` stands for the file; without it the file
   * is appended.
   *
   * Worth setting: most editors are single-instance and quit the moment they
   * have passed the file to the window already open, which is why WireTerm
   * cannot tell when they are done. An argument that forces an instance of
   * its own — `-multiInst -nosession` for Notepad++, `--wait` for VS Code —
   * is what makes "the editor is closed" something it can see.
   */
  editorArgs: string;
};

/**
 * Three at once.
 *
 * Not about bandwidth. Over SFTP a single file already keeps sixteen requests
 * in flight and fills a link on its own; over FTP a transfer has a connection
 * to itself. What this buys in both cases is the round trip on many small
 * files, where most of the time is spent waiting for a reply that a second and
 * a third file could be waiting for at the same time.
 */
export const DEFAULT_SETTINGS: TransferSettings = {
  maxParallel: 3,
  editorPath: "",
  editorArgs: "",
};

/**
 * Past this the queue costs more than it gains, in both directions: over SFTP
 * every transfer in flight is another set of requests sharing the one channel,
 * and over FTP it is another login — servers commonly cap how many of those
 * one account may hold and start refusing rather than going faster. The same
 * ceiling FileZilla puts on it.
 */
export const MAX_PARALLEL_LIMIT = 10;

// ---- Storage ---------------------------------------------------------------

const KEY = "wireterm.transferSettings";

/**
 * What the key was called while the file browser only spoke SFTP.
 *
 * Still read, so nobody's parallel count and editor path are quietly reset by
 * a rename that means nothing to them. Written back under the new key on the
 * first change, and never written under the old one again.
 */
const FORMER_KEY = "wireterm.sftpSettings";

function clamp(value: unknown): number {
  const number = Math.round(Number(value));
  if (!Number.isFinite(number)) return DEFAULT_SETTINGS.maxParallel;
  return Math.min(MAX_PARALLEL_LIMIT, Math.max(1, number));
}

function load(): TransferSettings {
  try {
    const raw = localStorage.getItem(KEY) ?? localStorage.getItem(FORMER_KEY);
    if (!raw) return { ...DEFAULT_SETTINGS };
    const stored = JSON.parse(raw);
    return {
      maxParallel: clamp(stored?.maxParallel),
      editorPath: typeof stored?.editorPath === "string" ? stored.editorPath : "",
      editorArgs: typeof stored?.editorArgs === "string" ? stored.editorArgs : "",
    };
  } catch {
    // Private mode, blocked storage or damaged JSON: the defaults are fine.
    return { ...DEFAULT_SETTINGS };
  }
}

export const transferSettings = reactive<TransferSettings>(load());

export function saveTransferSettings() {
  try {
    localStorage.setItem(KEY, JSON.stringify(transferSettings));
  } catch {
    // Losing the preference is survivable; failing the edit is not.
  }
}

export function resetTransferSettings() {
  Object.assign(transferSettings, DEFAULT_SETTINGS);
}

/**
 * Written straight through, as the terminal settings are. The queue reads the
 * number rather than being handed it, so raising it while a folder is going
 * across starts further transfers at once and lowering it lets the extra ones
 * finish and not be replaced.
 */
watch(transferSettings, saveTransferSettings, { deep: true });
