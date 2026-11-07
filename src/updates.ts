/**
 * Updates from GitHub.
 *
 * On start and every six hours the app asks the latest release on GitHub —
 * its `latest.json`, see `plugins.updater` in tauri.conf.json — whether there
 * is a newer version. Download, signature check against the update key and
 * installation are done by tauri-plugin-updater; the person decides when,
 * because WireTerm restarts afterwards and open connections end.
 *
 * Offline, or before the first release: nothing happens, and nothing is said.
 */

import { reactive, shallowRef } from "vue";
import { check, type Update } from "@tauri-apps/plugin-updater";
import { relaunch } from "@tauri-apps/plugin-process";

const FIRST_CHECK = 10_000;
const EVERY = 6 * 60 * 60 * 1000;

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

async function look() {
  try {
    const update = await check();
    if (update && update.version !== availableUpdate.value?.version) {
      availableUpdate.value = update;
      updateState.dismissed = false;
      updateState.error = null;
    }
  } catch (error) {
    console.warn("Update check failed:", error);
  }
}

/** Starts the checks. Not in development, where there is nothing to update. */
export function watchForUpdates() {
  if (import.meta.env.DEV) return;
  setTimeout(() => void look(), FIRST_CHECK);
  setInterval(() => void look(), EVERY);
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
