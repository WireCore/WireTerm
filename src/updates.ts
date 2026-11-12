/**
 * Updates from GitHub.
 *
 * Shortly after the start, every hour, and whenever the window gets the focus
 * back (at most every 15 minutes) the app asks the latest release on GitHub —
 * its `latest.json`, see `plugins.updater` in tauri.conf.json — whether there
 * is a newer version. Six hours turned out too long: a release published while
 * WireTerm was running, or while its build was still going, only showed up the
 * next working day. "Check for updates" asks right away.
 *
 * Download, signature check against the update key and installation are done
 * by tauri-plugin-updater; the person decides when, because WireTerm restarts
 * afterwards and open connections end.
 *
 * Offline, or before the first release: the automatic checks say nothing, a
 * check that was asked for says that it failed.
 */

import { reactive, shallowRef } from "vue";
import { check, type Update } from "@tauri-apps/plugin-updater";
import { relaunch } from "@tauri-apps/plugin-process";

const FIRST_CHECK = 10_000;
const EVERY = 60 * 60 * 1000;
/** Getting the focus back checks again, but not on every switch between windows. */
const ON_FOCUS_AFTER = 15 * 60 * 1000;

/**
 * Kept outside `reactive`: an `Update` holds a private resource id that a
 * proxy cannot reach.
 */
export const availableUpdate = shallowRef<Update | null>(null);

export const updateState = reactive({
  /** Hidden with "Later" until the next start or a newer version. */
  dismissed: false,
  /** Percent while downloading; `null` before it starts or without a size. */
  progress: null as number | null,
  installing: false,
  error: null as string | null,
});

/** The last check, for "Check for updates" to report on. */
export const checkState = reactive({
  checking: false,
  /** When the last check ended, successfully or not. */
  at: null as Date | null,
  /** `current`: nothing newer; `available`: see `availableUpdate`. */
  result: null as "current" | "available" | "failed" | null,
  error: null as string | null,
});

async function look(): Promise<void> {
  if (checkState.checking) return;
  checkState.checking = true;
  try {
    const update = await check();
    if (update && update.version !== availableUpdate.value?.version) {
      availableUpdate.value = update;
      updateState.dismissed = false;
      updateState.error = null;
    }
    checkState.result = update ? "available" : "current";
    checkState.error = null;
  } catch (error) {
    console.warn("Update check failed:", error);
    checkState.result = "failed";
    checkState.error = String(error);
  } finally {
    checkState.checking = false;
    checkState.at = new Date();
  }
}

/**
 * Asks right away, because someone clicked. An update hidden with "Later"
 * shows again: whoever asks wants to see the answer.
 */
export async function checkForUpdates(): Promise<void> {
  await look();
  if (availableUpdate.value) updateState.dismissed = false;
}

/** Starts the checks. Not in development, where there is nothing to update. */
export function watchForUpdates() {
  if (import.meta.env.DEV) return;
  setTimeout(() => void look(), FIRST_CHECK);
  setInterval(() => void look(), EVERY);
  window.addEventListener("focus", () => {
    const last = checkState.at?.getTime() ?? 0;
    if (Date.now() - last >= ON_FOCUS_AFTER) void look();
  });
}

export function dismissUpdate() {
  updateState.dismissed = true;
}

/** Downloads, installs and restarts. On Windows the installer ends the app itself. */
export async function installUpdate() {
  const update = availableUpdate.value;
  if (!update || updateState.installing) return;
  updateState.installing = true;
  updateState.error = null;
  updateState.progress = null;
  let total = 0;
  let received = 0;
  try {
    await update.downloadAndInstall((event) => {
      if (event.event === "Started") {
        total = event.data.contentLength ?? 0;
        updateState.progress = total ? 0 : null;
      } else if (event.event === "Progress" && total) {
        received += event.data.chunkLength;
        updateState.progress = Math.min(100, Math.round((received / total) * 100));
      }
    });
    await relaunch();
  } catch (error) {
    updateState.installing = false;
    updateState.error = String(error);
  }
}
