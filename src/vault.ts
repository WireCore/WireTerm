/**
 * The password-manager accounts a workspace reads its secrets with.
 *
 * Neither provider has a name the app could know in advance: 1Password's
 * desktop-app integration signs every user in with their *own* account, and a
 * Bitwarden vault lives wherever its owner put it. Both therefore belong to
 * the workspace, are handed to the backend whenever one is opened, and are
 * reported back with a marker when something about them is missing or wrong.
 *
 * This module turns those markers into a question instead of a raw error
 * message — and it is one module rather than two, because from here the two
 * providers differ only in which question gets asked.
 */

import { ref } from "vue";
import { invoke } from "@tauri-apps/api/core";

import { t } from "./i18n";
import { defaultBitwardenAccount, type VaultProvider, type Workspace } from "./types";

/** Mirrors the markers in src-tauri/src/op.rs and src-tauri/src/bitwarden/mod.rs. */
const OP_NO_ACCOUNT = "op:no-account";
const OP_UNKNOWN_ACCOUNT = "op:unknown-account";
const BW_NO_ACCOUNT = "bw:no-account";
const BW_TWO_FACTOR = "bw:two-factor";
const BW_LOCKED = "bw:locked";

/**
 * What has to be answered before a vault can be read.
 *
 * "account" is a setting and is saved onto the workspace. "unlock" is a master
 * password, which is answered once and kept nowhere — hence two kinds rather
 * than one dialog that tries to do both.
 */
export type VaultProblem =
  | { kind: "account"; provider: VaultProvider; reason: string }
  | {
      kind: "unlock";
      provider: "bitwarden";
      reason: string;
      /** The second factor the server asked for, or "" when it asked for none. */
      twoFactor: string;
    };

/**
 * The open question, or null while nothing is wrong. A single ref because the
 * answer is a property of the workspace, not of whichever call happened to
 * notice.
 */
export const vaultProblem = ref<VaultProblem | null>(null);

/** Hands both accounts to the backend. Called on every workspace change. */
export async function useVaults(workspace: Workspace | null) {
  try {
    await invoke("vault_configure", {
      config: {
        onePasswordAccount: workspace?.onePasswordAccount ?? "",
        bitwarden: workspace?.bitwarden ?? defaultBitwardenAccount(),
      },
    });
  } catch {
    // Nothing to do and nothing to show: the next call into a vault will
    // report what is missing itself.
  }
}

/**
 * Raises the right question if that is what went wrong, and says whether it
 * did — so callers can leave their own error display alone when it has.
 *
 * Matched with `includes`, because a marker reaches the frontend wrapped in
 * whatever message the layer above added to it.
 */
export function reportVaultProblem(message: string): boolean {
  if (message.includes(OP_NO_ACCOUNT)) {
    vaultProblem.value = {
      kind: "account",
      provider: "onePassword",
      reason: t("vault.onePasswordNoAccount"),
    };
    return true;
  }
  if (message.includes(OP_UNKNOWN_ACCOUNT)) {
    vaultProblem.value = {
      kind: "account",
      provider: "onePassword",
      reason: t("vault.onePasswordUnknownAccount"),
    };
    return true;
  }
  if (message.includes(BW_NO_ACCOUNT)) {
    vaultProblem.value = {
      kind: "account",
      provider: "bitwarden",
      reason: t("vault.bitwardenNoAccount"),
    };
    return true;
  }
  // Before the plain lock, because the marker for a second factor is the more
  // specific of the two and carries what to ask for after its colon.
  const twoFactor = message.indexOf(BW_TWO_FACTOR);
  if (twoFactor >= 0) {
    const method = message.slice(twoFactor + BW_TWO_FACTOR.length + 1).trim();
    vaultProblem.value = {
      kind: "unlock",
      provider: "bitwarden",
      reason: t("vault.bitwardenTwoFactor"),
      twoFactor: method || t("vault.secondFactor"),
    };
    return true;
  }
  if (message.includes(BW_LOCKED)) {
    vaultProblem.value = {
      kind: "unlock",
      provider: "bitwarden",
      reason: t("vault.bitwardenLocked"),
      twoFactor: "",
    };
    return true;
  }
  return false;
}

/**
 * Unlocks the Bitwarden vault. `code` is the second factor where one was
 * asked for; empty otherwise.
 *
 * Neither value is kept here: they go straight to the backend, which derives
 * the keys from them and forgets the password.
 */
export async function unlockBitwarden(password: string, code: string) {
  await invoke("bw_unlock", { password, code });
}

/** Closes the vault again. Everything after it asks for the password anew. */
export async function lockBitwarden() {
  try {
    await invoke("bw_lock");
  } catch {
    // A vault that cannot be locked was not open.
  }
}

export async function bitwardenUnlocked(): Promise<boolean> {
  try {
    return await invoke<boolean>("bw_unlocked");
  } catch {
    return false;
  }
}
