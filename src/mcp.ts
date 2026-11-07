import { ref } from "vue";
import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { findConnection, projectOf, withJumps, workspaceOf, workspaces } from "./store";
import { openTerminals, readTerminal, send } from "./terminals";
import { remote, remoteKind } from "./remote";
import { t } from "./i18n";
import { newId, targetLabel, type Connection, type Listing } from "./types";

/**
 * The MCP server, from this side.
 *
 * The backend speaks the protocol (`mcp.rs`); a call only comes here when it
 * is to be carried out — as `mcp:call`, answered with `mcp_answer`. Reading
 * runs without asking. Whatever does something on a server waits for a
 * confirmation in [`confirmations`], and does so every time.
 *
 * The answers are in English: they go to an agent, not to someone who reads
 * them.
 */

export type McpStatus = {
  enabled: boolean;
  running: boolean;
  port: number;
  url: string;
  error: string | null;
};

export const mcpStatus = () => invoke<McpStatus>("mcp_status");
export const configureMcp = (enabled: boolean, port: number) =>
  invoke<McpStatus>("mcp_configure", { enabled, port });
export const mcpToken = () => invoke<string>("mcp_token");
export const renewMcpToken = () => invoke<string>("mcp_renew_token");

type McpCall = {
  id: string;
  tool: string;
  arguments: Record<string, unknown>;
  client: string;
};

type Outcome = { text: string; isError?: boolean };

/** A question in the confirmation dialog. */
export type Confirmation = {
  id: number;
  client: string;
  /** What is to be done, as a heading. */
  action: string;
  /** Where: connection or terminal. */
  target: string;
  /** The exact command or text. */
  detail: string;
  answer: (allowed: boolean) => void;
};

/** Open questions, oldest first — several calls can be waiting at once. */
export const confirmations = ref<Confirmation[]>([]);

let asked = 0;

function confirm(question: Omit<Confirmation, "answer" | "id">): Promise<boolean> {
  return new Promise((resolve) => {
    confirmations.value.push({ ...question, id: ++asked, answer: resolve });
  });
}

/** Answers the frontmost question. */
export function answerConfirmation(allowed: boolean) {
  const question = confirmations.value.shift();
  question?.answer(allowed);
}

const DECLINED: Outcome = { text: "The user declined this request in WireTerm.", isError: true };

const json = (value: unknown): Outcome => ({ text: JSON.stringify(value, null, 2) });

function text(args: Record<string, unknown>, name: string): string {
  const value = args[name];
  if (typeof value !== "string" || !value) throw new Error(`Missing argument: ${name}`);
  return value;
}

function connection(args: Record<string, unknown>): Connection {
  const id = text(args, "connectionId");
  const found = findConnection(id);
  if (!found) throw new Error(`No connection with id ${id}. Use list_connections.`);
  return found;
}

/** Where a connection is, as the dialog names it. */
function place(found: Connection): string {
  const workspace = workspaceOf(found.id)?.name ?? "";
  const project = projectOf(found.id)?.name ?? "";
  return `${workspace} / ${project} / ${found.name} (${targetLabel(found.settings)})`;
}

/** A vault reference is not a user name and does not go out. */
const userOf = (user: string) => (user.includes("://") ? undefined : user);

function listConnections(): Outcome {
  return json(
    workspaces.flatMap((workspace) =>
      workspace.projects.flatMap((project) =>
        project.connections.map((c) => {
          const s = c.settings;
          return {
            id: c.id,
            name: c.name,
            type: s.type,
            workspace: workspace.name,
            project: project.name,
            host: s.host,
            port: s.port,
            ...(s.type === "s3"
              ? { bucket: s.bucket || undefined, region: s.region }
              : { user: userOf(s.user) }),
          };
        }),
      ),
    ),
  );
}

function listSnippets(): Outcome {
  return json(
    workspaces.flatMap((workspace) =>
      (workspace.snippets ?? []).map((snippet) => ({
        id: snippet.id,
        workspace: workspace.name,
        folder: snippet.folder,
        name: snippet.name,
        command: snippet.command,
      })),
    ),
  );
}

function terminalName(sessionId: string): string {
  const open = openTerminals().find((t) => t.sessionId === sessionId);
  if (!open) throw new Error(`No open terminal ${sessionId}. Use list_terminals.`);
  if (open.local !== undefined) return `${open.local} (${t("common.local")})`;
  const found = findConnection(open.connectionId);
  return found ? place(found) : sessionId;
}

function listTerminals(): Outcome {
  return json(
    openTerminals().map((t) => {
      const found = t.local === undefined ? findConnection(t.connectionId) : null;
      return {
        sessionId: t.sessionId,
        kind: t.local === undefined ? "ssh" : "local",
        name: t.local ?? found?.name ?? "",
        connectionId: t.connectionId || undefined,
      };
    }),
  );
}

function read(args: Record<string, unknown>): Outcome {
  const sessionId = text(args, "sessionId");
  const lines = Math.min(2000, Math.max(1, Number(args.lines ?? 100) || 100));
  terminalName(sessionId);
  return { text: readTerminal(sessionId, lines) ?? "" };
}

async function listFiles(args: Record<string, unknown>): Promise<Outcome> {
  const found = connection(args);
  const settings = withJumps(found.settings);
  const kind = remoteKind(settings);
  // A session of its own that closes again afterwards — no open tab is used
  // for it, so its directory stays where it is.
  const sessionId = newId();
  const api = remote(kind, sessionId);
  try {
    const start = await api.connect(settings);
    const path = typeof args.path === "string" && args.path ? args.path : start;
    const listing: Listing = await api.list(path);
    const rows = listing.entries.map((e) => ({
      name: e.name + (e.isDir ? "/" : ""),
      size: e.isDir ? undefined : e.size,
      modified: e.modified ? new Date(e.modified * 1000).toISOString() : undefined,
      permissions: e.permissions ?? undefined,
    }));
    return json({ path: listing.path, truncated: listing.truncated || undefined, entries: rows });
  } finally {
    await api.disconnect().catch(() => {});
    if (kind === "sftp") await invoke("session_close", { sessionId }).catch(() => {});
  }
}

type ExecResult = {
  stdout: string;
  stderr: string;
  exitCode: number | null;
  timedOut: boolean;
  truncated: boolean;
};

async function runCommand(call: McpCall): Promise<Outcome> {
  const found = connection(call.arguments);
  if (found.settings.type !== "ssh") throw new Error("run_command needs an SSH connection.");
  const command = text(call.arguments, "command");
  const timeoutSeconds = Math.min(3600, Math.max(1, Number(call.arguments.timeoutSeconds ?? 60) || 60));

  const allowed = await confirm({
    client: call.client,
    action: t("mcp.runCommand"),
    target: place(found),
    detail: command,
  });
  if (!allowed) return DECLINED;

  const result = await invoke<ExecResult>("ssh_exec", {
    settings: JSON.parse(JSON.stringify(withJumps(found.settings))),
    command,
    timeoutSeconds,
  });
  const notes = [
    result.timedOut ? `timed out after ${timeoutSeconds} s` : `exit code ${result.exitCode ?? "unknown"}`,
    result.truncated ? "output truncated at 1 MiB" : "",
  ].filter(Boolean);
  return {
    text: `${notes.join(", ")}\n--- stdout ---\n${result.stdout}\n--- stderr ---\n${result.stderr}`,
    isError: result.timedOut || (result.exitCode !== null && result.exitCode !== 0),
  };
}

async function sendToTerminal(call: McpCall): Promise<Outcome> {
  const sessionId = text(call.arguments, "sessionId");
  const typed = call.arguments.text;
  if (typeof typed !== "string") throw new Error("Missing argument: text");
  const enter = call.arguments.pressEnter !== false;

  const allowed = await confirm({
    client: call.client,
    action: enter ? t("mcp.typeAndEnter") : t("mcp.type"),
    target: terminalName(sessionId),
    detail: typed,
  });
  if (!allowed) return DECLINED;

  const data = typed.replace(/\r?\n/g, "\r");
  await send(sessionId, enter && !data.endsWith("\r") ? `${data}\r` : data);
  return { text: "Sent. Use read_terminal to see the output." };
}

async function handle(call: McpCall): Promise<Outcome> {
  switch (call.tool) {
    case "list_connections":
      return listConnections();
    case "list_snippets":
      return listSnippets();
    case "list_terminals":
      return listTerminals();
    case "read_terminal":
      return read(call.arguments);
    case "list_files":
      return listFiles(call.arguments);
    case "run_command":
      return runCommand(call);
    case "send_to_terminal":
      return sendToTerminal(call);
    default:
      return { text: `Unknown tool ${call.tool}`, isError: true };
  }
}

/** Listens for calls as long as the window is open. */
export function listenForMcp(): Promise<UnlistenFn> {
  return listen<McpCall>("mcp:call", async (event) => {
    const call = event.payload;
    const result = await handle({ ...call, arguments: call.arguments ?? {} }).catch(
      (e): Outcome => ({ text: e instanceof Error ? e.message : String(e), isError: true }),
    );
    await invoke("mcp_answer", { id: call.id, result }).catch(() => {});
  });
}
