import { invoke } from "@tauri-apps/api/core";
import type { Workspace } from "./types";

/**
 * The device key with which `workspaces.json` encrypts its secrets — see
 * `src-tauri/src/local_secrets`.
 *
 * - `ready`: open, from the keyring or after the app password.
 * - `locked`: lies under an app password that has not been entered yet.
 * - `setup`: no keyring on this system, and no app password yet.
 * - `unavailable`: the keyring had the key but is not answering right now.
 *   Then **no** new one is created.
 */
export type LocalVaultStatus = {
  state: "ready" | "locked" | "setup" | "unavailable";
  keyring: boolean;
  reason?: string;
};

export function localVaultStatus() {
  return invoke<LocalVaultStatus>("local_vault_status");
}

export function localVaultRetry() {
  return invoke<LocalVaultStatus>("local_vault_retry");
}

export function localVaultUnlock(password: string) {
  return invoke("local_vault_unlock", { password });
}

export function localVaultSetup(password: string) {
  return invoke("local_vault_setup", { password });
}

/** A new app password; the device key stays the same. */
export function localVaultChangePassword(old: string, next: string) {
  return invoke("local_vault_change_password", { old, new: next });
}

/** The workspaces including their secrets into a file, under a password. */
export function exportWorkspaces(path: string, password: string, workspaces: Workspace[]) {
  return invoke("workspaces_export", {
    path,
    password,
    // Without Vue's proxies, as when saving.
    workspaces: JSON.parse(JSON.stringify(workspaces)),
  });
}

/** Reads an export file; the workspaces come back with new IDs. */
export function importWorkspaces(path: string, password: string) {
  return invoke<Workspace[]>("workspaces_import", { path, password });
}
