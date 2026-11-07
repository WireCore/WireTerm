/**
 * The file browser's side of the connection, whichever protocol it is.
 *
 * SFTP, FTP and S3 answer the same questions — read this directory, send this
 * file, change these permissions — and the backend implements them three times
 * under three sets of command names. This is where that ends: the browser
 * above it asks for `list` and `upload`, and which command that becomes is
 * decided in one place instead of at twenty call sites.
 *
 * Only the *questions* are shared. What it costs to answer them is not: over
 * SFTP several transfers ride one channel, over FTP each one holds a
 * connection of its own, and over S3 every single request is signed and stands
 * alone. That difference lives in the backend, where it belongs, and none of
 * it needs saying here.
 *
 * What is *not* shared is said out loud rather than faked: [`chmod`] fails
 * over S3, which has no permissions, and [`link`] exists only there. Both are
 * asked about with the flags below, so the pane draws what a protocol can
 * actually do rather than offering a menu entry that will fail.
 *
 * Progress and edit events are not named per protocol either — a queue row
 * looks the same whatever carried it — so the names below carry no prefix.
 */

import { invoke } from "@tauri-apps/api/core";
import type {
  ChmodResult,
  ConnectionProbe,
  ConnectionSettings,
  EditSession,
  Listing,
  StaleUploads,
  TransferDirection,
} from "./types";

/** Which of the three the backend should be asked. */
export type RemoteKind = "sftp" | "ftp" | "s3";

export function remoteKind(settings: ConnectionSettings): RemoteKind {
  if (settings.type === "ftp") return "ftp";
  if (settings.type === "s3") return "s3";
  return "sftp";
}

/** Used and total bytes of the storage under the server pane. */
export type Space = { used: number; total: number };

/** What "Edit" hands the working copy to. */
export type EditorCommand = { path: string; args: string };

/**
 * Where a transfer reports its progress. One event carries the whole state of
 * one transfer, so a dropped one costs nothing — the next is complete again.
 */
export const progressEvent = (sessionId: string) => `transfer:progress:${sessionId}`;

/** Where one open edit reports what its last sync attempt did. */
export const editStatusEvent = (editId: string) => `edit:status:${editId}`;

/**
 * Where the backend asks for a secret it has nowhere to read: an FTP password
 * or an S3 secret access key. One event for both, because the question, the
 * dialog and what happens to the answer are the same.
 */
export const SECRET_EVENT = "secret:ask";

/**
 * Strips Vue's proxies: `invoke` serializes its argument, and a reactive
 * object does not survive that on its own.
 */
const plain = <T>(value: T): T => JSON.parse(JSON.stringify(value));

/**
 * The commands of one open file browser.
 *
 * Bound to a session and a protocol once, so nothing downstream has to carry
 * either around.
 */
export function remote(kind: RemoteKind, sessionId: string) {
  const command = (verb: string) => `${kind}_${verb}`;

  return {
    kind,

    /**
     * Whether "Change permissions" leads anywhere. False over S3, which decides
     * access with policies rather than with modes — the pane greys the entry
     * out on the listing's missing mode bits anyway, and this is the same
     * answer given before a single directory has been read.
     */
    permissions: kind !== "s3",

    /** Whether one file can be turned into a link anyone can open. S3 only. */
    links: kind === "s3",

    /** Opens the browser and reports the directory it starts in. */
    connect: (settings: ConnectionSettings) =>
      invoke<string>(command("connect"), { sessionId, settings: plain(settings) }),

    disconnect: () => invoke(command("disconnect"), { sessionId }),

    list: (path: string) => invoke<Listing>(command("list"), { sessionId, path }),

    mkdir: (path: string) => invoke(command("mkdir"), { sessionId, path }),

    createFile: (path: string) => invoke(command("create_file"), { sessionId, path }),

    exists: (path: string) => invoke<boolean>(command("exists"), { sessionId, path }),

    /** How full the storage is, where the server says. SFTP only. */
    space: (path: string) =>
      kind === "sftp"
        ? invoke<Space | null>(command("space"), { sessionId, path })
        : Promise.resolve(null),

    /**
     * Unfinished multipart uploads older than a day in the bucket `path` is
     * in. S3 only — nothing else leaves invisible, billed remains behind.
     */
    staleUploads: (path: string) =>
      kind === "s3"
        ? invoke<StaleUploads | null>(command("stale_uploads"), { sessionId, path })
        : Promise.resolve(null),

    /** Aborts them and says how many went. Only called where the above found some. */
    abortStaleUploads: (bucket: string) =>
      invoke<number>(command("abort_stale_uploads"), { sessionId, bucket }),

    rename: (from: string, to: string) => invoke(command("rename"), { sessionId, from, to }),

    /**
     * `operationId` names the run so [`cancelTransfer`] can stop it — only S3
     * looks at it, where a prefix can hold tens of thousands of objects.
     */
    remove: (path: string, isDir: boolean, operationId?: string) =>
      invoke(command("remove"), { sessionId, path, isDir, operationId }),

    /** `operationId` is what a recursive run can be stopped by. */
    chmod: (path: string, mode: number, recursive: boolean, operationId?: string) =>
      invoke<ChmodResult>(command("chmod"), { sessionId, path, mode, recursive, operationId }),

    download: (transferId: string, remotePath: string, localPath: string) =>
      invoke<number>(command("download"), {
        sessionId,
        transferId,
        remote: remotePath,
        local: localPath,
      }),

    upload: (transferId: string, localPath: string, remotePath: string) =>
      invoke<number>(command("upload"), {
        sessionId,
        transferId,
        local: localPath,
        remote: remotePath,
      }),

    /** Throws away what a stopped transfer left behind. */
    discard: (direction: TransferDirection, localPath: string, remotePath: string) =>
      invoke(command("discard"), {
        sessionId,
        direction,
        local: localPath,
        remote: remotePath,
      }),

    editOpen: (remotePath: string, editor: EditorCommand | null) =>
      invoke<EditSession>(command("edit_open"), { sessionId, remote: remotePath, editor }),

    /**
     * A link to one file that works without any credentials, valid for
     * `seconds`. Only ever called where `links` says it leads somewhere.
     */
    link: (remotePath: string, seconds: number) =>
      invoke<string>(command("link"), { sessionId, path: remotePath, seconds }),
  };
}

export type Remote = ReturnType<typeof remote>;

/**
 * Asks a running transfer to stop. Not part of [`remote`]: a transfer is
 * identified by its own id and the backend keeps one list of them for both
 * protocols, so there is nothing here that depends on the session.
 */
export const cancelTransfer = (transferId: string) =>
  invoke("transfer_cancel", { transferId });

/** Stops watching an open edit. Shared for the same reason. */
export const closeEdit = (editId: string) => invoke("edit_close", { editId });

/**
 * "Test connection", against settings that may not be saved yet.
 *
 * Named after the connection type rather than after [`RemoteKind`]: a test
 * logs in, and over SSH that is the connection itself and not the file
 * browser's channel on it.
 */
export const probe = (settings: ConnectionSettings) =>
  invoke<ConnectionProbe>(`${settings.type}_probe`, { settings: plain(settings) });

/** The answer to a secret question. `null` is "Cancel". */
export const answerSecret = (id: string, secret: string | null) =>
  invoke("secret_answer", { id, secret });
