/**
 * The UI side of `src-tauri/src/cloud`.
 *
 * This module does two things and nothing else: it gives the commands a type,
 * and it keeps track of which accounts exist and which of them are unlocked.
 * The tree itself still goes through [`store`](./store.ts) — a remote
 * workspace looks to the rest of the app like any other, just with
 * [`Workspace.remote`] attached.
 *
 * What does **not** appear here: the master password. It is entered in a
 * dialog, travels as an argument into a command and is gone afterwards. It
 * sits in no reactive variable, is cached nowhere and never goes over the
 * wire.
 */

import { reactive, ref } from "vue";
import { invoke } from "@tauri-apps/api/core";
import type { Role, ShareRole, WorkspaceKind } from "./types";

/** An account on a backend, as the UI sees it. */
export type CloudAccount = {
  id: string;
  /** The address without scheme, for lists. */
  server: string;
  /** The address as it belongs in a field. */
  url: string;
  email: string;
  name: string;
  userId: string;
  /** Whether there is a session. Whether it is still valid only the server knows. */
  signedIn: boolean;
  /**
   * The address of WireCloud if the account is signed in through it. Then
   * WireCloud manages members, teams and invitations, not this program: the
   * UI hides that and only displays.
   */
  managedBy: string | null;
  /** Whether the master password has already been entered in this run. */
  unlocked: boolean;
};

/** How far an account is set up. */
export type KeyStatus = {
  /** `false` means: the master password is still pending. */
  hasKeys: boolean;
  unlocked: boolean;
  recovery: { id: string; label: string; usedAt: string | null }[];
};

export type WorkspaceOption = {
  id: string;
  name: string;
  kind: WorkspaceKind;
  role: Role;
  /** Whether this workspace is already in the rail here. */
  added: boolean;
};

export type MemberUser = { name: string; email: string };

export type MemberRow = {
  /** The membership ID — what a role change expects. */
  id: string;
  userId: string;
  role: Role;
  user?: MemberUser | null;
};

export type InvitationRow = {
  id: string;
  email: string;
  role: string | null;
  status: string;
  teamId: string | null;
  expiresAt: string | null;
  organizationId?: string | null;
  organizationName?: string | null;
};

export type TeamRow = { id: string; name: string; organizationId: string };

/** A member's public key — or none. */
export type MemberKey = {
  userId: string;
  name: string;
  email: string;
  role: Role | null;
  /**
   * `null` means: this person has not set up a master password yet. Nothing
   * can be wrapped for them — not a failure, but a state the UI should name.
   */
  key: { algorithm: string; publicKey: string } | null;
  keyIds: string[];
};

export type Members = {
  organization: {
    id: string;
    name: string;
    slug: string;
    members: MemberRow[];
    invitations: InvitationRow[];
    teams: TeamRow[];
  };
  keys: MemberKey[];
  teams: TeamRow[];
  role: Role;
  kind: WorkspaceKind;
  ownUserId: string;
  /** Like [`CloudAccount.managedBy`]: members only for viewing, no teams. */
  managedBy: string | null;
};

/** A share. `teamId: null` means: the whole organization. */
export type Share = {
  id?: string;
  projectId?: string;
  teamId: string | null;
  teamName?: string | null;
  role: ShareRole;
};

export type KnownHost = {
  id: string;
  host: string;
  port: number;
  algorithm: string;
  publicKey: string;
  trustedById: string | null;
};

// ---- State -----------------------------------------------------------------

/** The known accounts. Filled by [`loadAccounts`]. */
export const accounts = reactive<CloudAccount[]>([]);

/**
 * The account whose vault is to be unlocked right now.
 *
 * A variable instead of an event, because the question comes from two
 * directions — when opening a locked workspace and after the quarter of an
 * hour has passed — and both times the same dialog is meant.
 */
export const unlockWanted = ref<string | null>(null);

/**
 * The profile pictures of the accounts signed in through WireCloud (data URL).
 * Without an entry the UI shows initials. The program fetches the picture from
 * WireCloud, not the backend; an error (no network, no picture) leaves the
 * initials, and after a few minutes it asks again.
 */
export const accountImages = reactive<Record<string, string>>({});
const imageCheckedAt = new Map<string, number>();
const IMAGE_RECHECK_MS = 5 * 60 * 1000;

/**
 * The pictures of the WireCloud companies behind remote workspaces, by
 * workspace ID (data URL) — the same way as the profile pictures: from
 * WireCloud, and without one the tile shows initials.
 */
export const workspaceImages = reactive<Record<string, string>>({});
/** Which entries above came with which account, to replace them as a whole. */
const workspaceImagesOf = new Map<string, string[]>();

function setWorkspaceImages(accountId: string, images: Record<string, string>) {
  for (const id of workspaceImagesOf.get(accountId) ?? []) delete workspaceImages[id];
  Object.assign(workspaceImages, images);
  workspaceImagesOf.set(accountId, Object.keys(images));
}

/** Asks right away, not only every few minutes — after adding a workspace. */
export function refreshWorkspaceImages(accountId: string) {
  invoke<Record<string, string>>("cloud_workspace_images", { accountId })
    .then((images) => setWorkspaceImages(accountId, images))
    .catch(() => {});
}

function refreshImages(list: CloudAccount[]) {
  const ids = new Set(list.map((account) => account.id));
  for (const id of Object.keys(accountImages)) if (!ids.has(id)) delete accountImages[id];
  for (const id of [...workspaceImagesOf.keys()]) {
    if (ids.has(id)) continue;
    setWorkspaceImages(id, {});
    workspaceImagesOf.delete(id);
  }
  for (const account of list) {
    if (!account.managedBy || !account.signedIn) {
      delete accountImages[account.id];
      setWorkspaceImages(account.id, {});
      continue;
    }
    const last = imageCheckedAt.get(account.id) ?? 0;
    if (Date.now() - last < IMAGE_RECHECK_MS) continue;
    imageCheckedAt.set(account.id, Date.now());
    refreshWorkspaceImages(account.id);
    invoke<string | null>("cloud_account_image", { accountId: account.id })
      .then((image) => {
        if (image) accountImages[account.id] = image;
        else delete accountImages[account.id];
      })
      .catch(() => imageCheckedAt.delete(account.id));
  }
}

function replace(list: CloudAccount[]) {
  accounts.splice(0, accounts.length, ...list);
  refreshImages(list);
}

export async function loadAccounts(): Promise<CloudAccount[]> {
  const list = await invoke<CloudAccount[]>("cloud_accounts");
  replace(list);
  return list;
}

/**
 * Checks at startup whether the stored sessions are still valid.
 *
 * A session the server no longer knows would otherwise only be noticed at the
 * first sync — and then as an error banner above a workspace instead of as a
 * prompt to sign in.
 */
export async function checkSessions(): Promise<CloudAccount[]> {
  const list = await invoke<CloudAccount[]>("cloud_check_sessions");
  replace(list);
  return list;
}

export function accountOf(id: string | null | undefined): CloudAccount | null {
  return accounts.find((account) => account.id === id) ?? null;
}

// ---- Signing in ------------------------------------------------------------

export type SignInValues = {
  server: string;
  acceptInvalidCert: boolean;
  email: string;
  password: string;
};

/** The fixed address of the cloud, from `CLOUD_URL` in `cloud/http.rs`. */
export function cloudUrl() {
  return invoke<string>("cloud_url");
}

export async function signIn(values: SignInValues): Promise<CloudAccount> {
  const account = await invoke<CloudAccount>("cloud_sign_in", { ...values });
  await loadAccounts();
  return account;
}

// ---- Signing in through WireCloud ------------------------------------------

/** What a backend in WireCloud mode says about itself. */
export type WireCloudInfo = {
  /** Where WireCloud is reachable for clients. */
  wirecloudUrl: string;
  audience: string;
};

/** How a sign-in through WireCloud ends. */
export type WireCloudSignIn =
  | { status: "signedIn"; account: CloudAccount }
  /**
   * There is already an account here for this address from the time before
   * WireCloud. It is linked once the person enters its previous sign-in
   * password.
   */
  | { status: "needsLink"; pendingId: string; email: string; message: string | null };

/**
 * Asks a backend whether it runs in WireCloud mode. `null` means: no, or it
 * does not answer — then the path with email and sign-in password applies.
 */
export function detectWireCloud(
  server: string,
  acceptInvalidCert: boolean,
): Promise<WireCloudInfo | null> {
  return invoke<WireCloudInfo | null>("cloud_wirecloud_detect", { server, acceptInvalidCert });
}

/**
 * Signs in at WireCloud through the system browser. Waits until the person is
 * done in the browser (or cancels); no password passes through this program.
 */
export async function signInWireCloud(
  server: string,
  acceptInvalidCert: boolean,
): Promise<WireCloudSignIn> {
  const result = await invoke<WireCloudSignIn>("cloud_wirecloud_sign_in", {
    server,
    acceptInvalidCert,
  });
  if (result.status === "signedIn") await loadAccounts();
  return result;
}

/** Links the previous account after its sign-in password was entered. */
export async function linkWireCloud(pendingId: string, password: string): Promise<WireCloudSignIn> {
  const result = await invoke<WireCloudSignIn>("cloud_wirecloud_link", { pendingId, password });
  if (result.status === "signedIn") await loadAccounts();
  return result;
}

/** Cancels waiting for the browser or the pending link. */
export function cancelWireCloud(pendingId?: string) {
  return invoke("cloud_wirecloud_cancel", { pendingId: pendingId ?? null });
}

export async function signUp(values: SignInValues & { name: string }): Promise<CloudAccount> {
  const account = await invoke<CloudAccount>("cloud_sign_up", { ...values });
  await loadAccounts();
  return account;
}

export async function signOut(accountId: string) {
  await invoke("cloud_sign_out", { accountId });
  await loadAccounts();
}

/** Forgets the account along with all workspaces that belong to it. */
export async function forgetAccount(accountId: string) {
  await invoke("cloud_forget_account", { accountId });
  await loadAccounts();
}

/**
 * Sends the mail for resetting the **sign-in password**.
 *
 * Not the master password — that does not come back this way, the recovery
 * codes are for that. The dialog says so once more at that point.
 */
export function requestPasswordReset(server: string, acceptInvalidCert: boolean, email: string) {
  return invoke("cloud_request_password_reset", { server, acceptInvalidCert, email });
}

// ---- Master password -------------------------------------------------------

export function keyStatus(accountId: string) {
  return invoke<KeyStatus>("cloud_key_status", { accountId });
}

/**
 * Sets up the master password and returns the recovery codes.
 *
 * They are shown **once**. The server does not know them, not even as a hash —
 * a hash would be a point of attack for exactly the database that is not
 * supposed to be able to read anything.
 */
export async function setupMaster(accountId: string, masterPassword: string): Promise<string[]> {
  const codes = await invoke<string[]>("cloud_setup_master", { accountId, masterPassword });
  await loadAccounts();
  return codes;
}

/**
 * Unlocks the vault.
 *
 * Does **not** touch [`unlockWanted`], although it would be obvious: whoever
 * closes the dialog is whoever opened it. If this did it, the component would
 * vanish while still submitting — and the `done` with which it then has the
 * tree reloaded would go nowhere. That is exactly how the banner "The vault is
 * locked" stayed up long after it was unlocked.
 */
export async function unlock(accountId: string, masterPassword: string) {
  await invoke("cloud_unlock", { accountId, masterPassword });
  await loadAccounts();
}

/**
 * Redeems a recovery code and sets a new master password along the way.
 *
 * The old set of codes is replaced: every one of them opened the same door.
 *
 * Does not touch [`unlockWanted`] for the same reason as [`unlock`] — here it
 * would weigh even more: the dialog would vanish before it can show the
 * **new** set of codes, and there is no second chance for those.
 */
export async function recoverMaster(accountId: string, code: string, masterPassword: string) {
  const codes = await invoke<string[]>("cloud_recover_master", {
    accountId,
    code,
    masterPassword,
  });
  await loadAccounts();
  return codes;
}

/** The same, except that the key comes from the old master password. */
export async function changeMaster(
  accountId: string,
  oldPassword: string,
  masterPassword: string,
) {
  const codes = await invoke<string[]>("cloud_change_master", {
    accountId,
    oldPassword,
    masterPassword,
  });
  await loadAccounts();
  return codes;
}

export async function lock(accountId: string) {
  await invoke("cloud_lock", { accountId });
  await loadAccounts();
}

export function isUnlocked(accountId: string) {
  return invoke<boolean>("cloud_unlocked", { accountId });
}

// ---- Workspaces ------------------------------------------------------------

export function availableWorkspaces(accountId: string) {
  return invoke<WorkspaceOption[]>("cloud_available_workspaces", { accountId });
}

export function addWorkspace(accountId: string, organizationId: string, name: string) {
  return invoke<string>("cloud_add_workspace", { accountId, organizationId, name });
}

export function createWorkspace(accountId: string, name: string) {
  return invoke<string>("cloud_create_workspace", { accountId, name });
}

/**
 * Deletes the organization on the server — or only leaves it if it is not
 * one's own.
 */
export function deleteWorkspace(workspaceId: string, leaveOnly: boolean) {
  return invoke("cloud_delete_workspace", { workspaceId, leaveOnly });
}

/** Removes a workspace from the rail, only here. */
export function hideWorkspace(workspaceId: string) {
  return invoke("cloud_hide_workspace", { workspaceId });
}

export function sync(workspaceId?: string) {
  return invoke("cloud_sync", { workspaceId: workspaceId ?? null });
}

// ---- Members and teams -----------------------------------------------------

export function members(workspaceId: string) {
  return invoke<Members>("cloud_members", { workspaceId });
}

export function invite(workspaceId: string, email: string, role: Role, teamId: string | null) {
  return invoke<InvitationRow>("cloud_invite", { workspaceId, email, role, teamId });
}

export function cancelInvitation(workspaceId: string, invitationId: string) {
  return invoke("cloud_cancel_invitation", { workspaceId, invitationId });
}

export function removeMember(workspaceId: string, member: string) {
  return invoke("cloud_remove_member", { workspaceId, member });
}

export function setMemberRole(workspaceId: string, memberId: string, role: Role) {
  return invoke("cloud_set_member_role", { workspaceId, memberId, role });
}

export function createTeam(workspaceId: string, name: string) {
  return invoke<TeamRow>("cloud_create_team", { workspaceId, name });
}

export function renameTeam(workspaceId: string, teamId: string, name: string) {
  return invoke("cloud_rename_team", { workspaceId, teamId, name });
}

export function removeTeam(workspaceId: string, teamId: string) {
  return invoke("cloud_remove_team", { workspaceId, teamId });
}

export function teamMembers(workspaceId: string, teamId: string) {
  return invoke<MemberRow[]>("cloud_team_members", { workspaceId, teamId });
}

export function addTeamMember(workspaceId: string, teamId: string, userId: string) {
  return invoke("cloud_add_team_member", { workspaceId, teamId, userId });
}

export function removeTeamMember(workspaceId: string, teamId: string, userId: string) {
  return invoke("cloud_remove_team_member", { workspaceId, teamId, userId });
}

// ---- Shares ----------------------------------------------------------------

export function shares(workspaceId: string, projectId: string) {
  return invoke<Share[]>("cloud_shares", { workspaceId, projectId });
}

/**
 * Replaces the whole set. Whoever is no longer in the list loses access — and
 * the server deletes their wrapped copy of the project key along the way.
 */
export function setShares(
  workspaceId: string,
  projectId: string,
  list: { teamId: string | null; role: ShareRole }[],
) {
  return invoke("cloud_set_shares", { workspaceId, projectId, shares: list });
}

/** Whether members may create projects in this workspace. Owner and admin only. */
export function setMemberProjects(workspaceId: string, enabled: boolean) {
  return invoke("cloud_set_member_projects", { workspaceId, enabled });
}

export function revokeKey(workspaceId: string, projectId: string, userId: string) {
  return invoke("cloud_revoke_key", { workspaceId, projectId, userId });
}

/** The projects whose keys need renewing after removing `userId`. */
export function staleKeys(workspaceId: string, userId: string) {
  return invoke<string[]>("cloud_stale_keys", { workspaceId, userId });
}

/** What a rotation achieved — mirror of `cloud::rotate::Rotated`. */
export type Rotated = {
  keyId: string;
  /** Secrets that now sit under the new version. */
  secrets: number;
  /** Secrets that could not be opened here and stay under the old one. */
  skipped: number;
  /** For how many the new version was wrapped. */
  granted: number;
  /** Entitled members without a master password — they get it later on their own. */
  waiting: number;
};

/**
 * A new version of the project key, and all secrets below it re-encrypted.
 * Only then is a revocation tight: what someone read before is of no use to
 * them for the new ciphertexts.
 */
export function rotateProjectKey(workspaceId: string, projectId: string) {
  return invoke<Rotated>("cloud_rotate_project_key", { workspaceId, projectId });
}

// ---- Host keys -------------------------------------------------------------

/**
 * Records a confirmed host key in the workspace, so that not every team member
 * answers the same question on their own.
 *
 * Errors are swallowed: on this device the key is already noted, and an error
 * message in the middle of connecting would help no one.
 */
export function trustHost(
  workspaceId: string,
  host: string,
  port: number,
  algorithm: string,
  publicKey: string,
) {
  return invoke("cloud_trust_host", { workspaceId, host, port, algorithm, publicKey }).catch(
    () => {},
  );
}

export function knownHosts(workspaceId: string) {
  return invoke<KnownHost[]>("cloud_known_hosts", { workspaceId });
}

export function forgetHost(workspaceId: string, id: string) {
  return invoke("cloud_forget_host", { workspaceId, id });
}

/** "Got it" below a workspace's conflict messages. */
export function dismissConflicts(workspaceId: string) {
  return invoke("cloud_dismiss_conflicts", { workspaceId });
}

// ---- Invitations to oneself ------------------------------------------------

/**
 * The open invitations to this account.
 *
 * The backend only hands them out once the email address is verified — an
 * unconditional check in `list-user-invitations`. Until then `emailVerified`
 * is `false` and the list empty, because unknown. **Accepting** works without
 * it, which is why the path through [`invitationIdFrom`] remains.
 */
export function myInvitations(accountId: string) {
  return invoke<{ invitations: InvitationRow[]; emailVerified: boolean }>(
    "cloud_my_invitations",
    { accountId },
  );
}

/** Sends the link for verifying the email address once more. */
export function sendVerificationEmail(accountId: string) {
  return invoke("cloud_send_verification_email", { accountId });
}

/**
 * The ID from whatever someone copied from the invitation mail.
 *
 * That is either the whole link — `…/organization/acceptinvite/<id>` — or the
 * ID alone. Both land in the same field, because nobody knows beforehand which
 * of the two is in their clipboard.
 */
export function invitationIdFrom(input: string): string {
  const text = input.trim();
  if (!text) return "";
  // Trailing bits that come along when copying from a mail.
  const withoutQuery = text.split(/[?#]/)[0].replace(/\/+$/, "");
  const last = withoutQuery.split("/").pop() ?? "";
  return last.trim();
}

export function acceptInvitation(accountId: string, invitationId: string) {
  return invoke("cloud_accept_invitation", { accountId, invitationId });
}

export function rejectInvitation(accountId: string, invitationId: string) {
  return invoke("cloud_reject_invitation", { accountId, invitationId });
}
