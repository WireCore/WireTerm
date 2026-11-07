import { reactive } from "vue";
import { invoke } from "@tauri-apps/api/core";
import { findConnection } from "./store";
import type { Connection, Snippet } from "./types";

/**
 * What the open terminals need to know about each other: which one belongs to
 * which connection, and whether input goes to several at once.
 *
 * **Broadcast** applies to the terminals of the split view. What is typed in
 * one of them goes to all — and so does a snippet, then with the placeholders
 * of each terminal's own connection.
 */
export const terminals = reactive({
  /** Session → connection, as long as the terminal is up. */
  connections: {} as Record<string, string>,
  broadcast: false,
  /** The sessions of the split view. */
  group: [] as string[],
});

/** What the MCP server needs to know about a terminal — outside `terminals`, because it is not reactive. */
type Entry = {
  /** Set for a local terminal: the name of the shell. Those take input through a different command. */
  local?: string;
  /** The last `lines` lines of screen and scrollback, as text. */
  read?: (lines: number) => string;
};
const entries = new Map<string, Entry>();

export function registerTerminal(sessionId: string, connectionId: string, entry: Entry = {}) {
  terminals.connections[sessionId] = connectionId;
  entries.set(sessionId, entry);
}

export function unregisterTerminal(sessionId: string) {
  delete terminals.connections[sessionId];
  entries.delete(sessionId);
}

/** The open terminals: session, connection (empty for local) and shell. */
export function openTerminals(): { sessionId: string; connectionId: string; local?: string }[] {
  return Object.entries(terminals.connections).map(([sessionId, connectionId]) => ({
    sessionId,
    connectionId,
    local: entries.get(sessionId)?.local,
  }));
}

export function readTerminal(sessionId: string, lines: number): string | null {
  return entries.get(sessionId)?.read?.(lines) ?? null;
}

/** To exactly this one terminal, without broadcast. */
export function send(sessionId: string, data: string): Promise<unknown> {
  const local = entries.get(sessionId)?.local !== undefined;
  return invoke(local ? "local_send" : "ssh_send", { sessionId, data });
}

/** Whether this terminal's input currently goes to the whole group. */
export function broadcasting(sessionId: string): boolean {
  return terminals.broadcast && terminals.group.length > 1 && terminals.group.includes(sessionId);
}

/** Where input from `sessionId` goes — only to terminals that are up. */
function targets(sessionId: string): string[] {
  if (!broadcasting(sessionId)) return [sessionId];
  return terminals.group.filter((id) => id in terminals.connections);
}

/** Sends keyboard input — to the one terminal or to the group. */
export function sendInput(sessionId: string, data: string): Promise<unknown> {
  return Promise.all(targets(sessionId).map((id) => send(id, data)));
}

/** Fills in the placeholders. Unknown ones are left as they are. */
export function fillIn(command: string, connection: Connection | null): string {
  if (!connection || connection.settings.type !== "ssh") return command;
  const values: Record<string, string> = {
    host: connection.settings.host,
    port: String(connection.settings.port),
    user: connection.settings.user,
    name: connection.name,
  };
  return command.replace(/\{\{\s*connection\.(\w+)\s*\}\}/g, (all, key: string) => values[key] ?? all);
}

/**
 * Sends a snippet, line by line with Enter — from the point of view of
 * `sessionId`, so to the group if broadcast is on there.
 */
export function runSnippet(sessionId: string, snippet: Snippet, only = false): Promise<unknown> {
  const ids = only ? [sessionId] : targets(sessionId);
  return Promise.all(
    ids.map((id) => {
      const connection = findConnection(terminals.connections[id] ?? "");
      const text = fillIn(snippet.command, connection).replace(/\r?\n/g, "\r");
      return send(id, text.endsWith("\r") ? text : `${text}\r`);
    }),
  );
}
