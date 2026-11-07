<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, ref, shallowRef, watch } from "vue";
import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { openUrl } from "@tauri-apps/plugin-opener";
import { useI18n } from "vue-i18n";
import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import {
  ClipboardAddon,
  type ClipboardSelectionType,
  type IClipboardProvider,
} from "@xterm/addon-clipboard";
import { SearchAddon } from "@xterm/addon-search";
import { SerializeAddon } from "@xterm/addon-serialize";
import { Unicode11Addon } from "@xterm/addon-unicode11";
import { WebLinksAddon } from "@xterm/addon-web-links";
import { WebglAddon } from "@xterm/addon-webgl";
import "@xterm/xterm/css/xterm.css";
import { Alert, Button, IconButton, Input, Spinner } from "@wirecore/wirelayer-vue";
import { ChevronDown, ChevronUp, Copy, ScrollText, Search, Settings, X } from "@lucide/vue";
import TerminalSettingsDialog from "./TerminalSettingsDialog.vue";
import SnippetMenu from "./SnippetMenu.vue";
import { reportVaultProblem } from "../vault";
import { findTheme, terminalSettings } from "../terminal-settings";
import { workspaceOf } from "../store";
import {
  broadcasting,
  registerTerminal,
  runSnippet,
  sendInput,
  unregisterTerminal,
} from "../terminals";
import type { LocalShell, RemoteSystem, Snippet, SshSettings, TabStatus } from "../types";

/**
 * A terminal — over SSH or, with `local`, a shell on this machine. Both look
 * the same from here; only the commands and events behind them differ
 * (`ssh_…` and `local_…`).
 */
const props = defineProps<{
  /** Identifies the session in the backend; stable for this tab's lifetime. */
  sessionId: string;
  /** For the workspace's snippets and their placeholders. Empty for `local`. */
  connectionId: string;
  settings?: SshSettings;
  /** Instead of SSH: this shell on this machine. */
  local?: LocalShell;
  /** Hidden tabs stay mounted, so the session survives a tab switch. */
  active: boolean;
}>();

// The tab shows the state, so it has to travel up. So does what the target
// turned out to be: the overview stores it on the connection.
const emit = defineEmits<{
  status: [status: TabStatus];
  system: [system: RemoteSystem];
}>();
const { t } = useI18n();

/** The name under which the backend keeps the commands and events. */
const channel = props.local ? "local" : "ssh";

const host = ref<HTMLDivElement>();
const connected = ref(false);
const connecting = ref(false);
const error = ref("");

function report(status: TabStatus) {
  emit("status", status);
}

// ---- Suche im Verlauf ------------------------------------------------------

const searching = ref(false);
const needle = ref("");
const needleInput = ref<InstanceType<typeof Input>>();
const hits = ref({ index: -1, count: 0 });

/** Matched in the accent colours, so hits read the same as anything else. */
const DECORATIONS = {
  matchBackground: "#2f5a94",
  matchOverviewRuler: "#4c9aff",
  activeMatchBackground: "#4c9aff",
  activeMatchBorder: "#e6e8ea",
  activeMatchColorOverviewRuler: "#e6e8ea",
};

async function openSearch() {
  searching.value = true;
  await nextTick();
  needleInput.value?.focus();
  needleInput.value?.select();
}

function closeSearch() {
  searching.value = false;
  search.value?.clearDecorations();
  hits.value = { index: -1, count: 0 };
  term.value?.focus();
}

/** `incremental` keeps the current hit while the term is still being typed. */
function findNext(incremental = false) {
  if (!needle.value) {
    search.value?.clearDecorations();
    hits.value = { index: -1, count: 0 };
    return;
  }
  search.value?.findNext(needle.value, { decorations: DECORATIONS, incremental });
}

function findPrevious() {
  if (!needle.value) return;
  search.value?.findPrevious(needle.value, { decorations: DECORATIONS });
}

const settingsOpen = ref(false);

// ---- Snippets ------------------------------------------------------------------

const snippetsOpen = ref(false);
const snippets = computed(() => workspaceOf(props.connectionId)?.snippets ?? []);
const broadcast = computed(() => broadcasting(props.sessionId));

function run(snippet: Snippet, only: boolean) {
  runSnippet(props.sessionId, snippet, only).catch((e) => (error.value = String(e)));
  term.value?.focus();
}

/** The connection's startup command, only in this terminal. */
function runStartup() {
  const snippet = snippets.value.find((s) => s.id === props.settings?.startupSnippet);
  if (snippet) run(snippet, true);
}

/** The padding around the screen has to match, or the theme stops at its edge. */
const screenBackground = computed(() => findTheme(terminalSettings.theme).theme.background);

// ---- Sitzung kopieren ------------------------------------------------------

/** Cleared by a timer, so the button says what happened without a dialog. */
const copyNote = ref("");
let copyTimer: ReturnType<typeof setTimeout> | undefined;

/**
 * What `serialize()` returns carries the colour escapes needed to replay the
 * buffer in another terminal. This copy is for pasting into a ticket or a
 * chat, so they come back out again.
 *
 * Everything the addon emits is CSI; the other three branches cost nothing and
 * cover anything that reaches here by another route — OSC with either
 * terminator, a charset designation, and the single-character escapes.
 */
const ANSI =
  /\x1b\[[0-9;:?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[ -/]+[0-~]|\x1b[@-Z\\-_]/g;

async function copySession() {
  const text = serializer.value?.serialize({ excludeModes: true, excludeAltBuffer: true });
  if (text === undefined) return;
  const ok = await copyToClipboard(text.replace(ANSI, "").replace(/[ \t]+$/gm, ""));
  copyNote.value = ok ? t("SshTerminal.copied") : t("SshTerminal.copyFailed");
  clearTimeout(copyTimer);
  copyTimer = setTimeout(() => (copyNote.value = ""), 2000);
}

/**
 * The last lines as text — for the MCP server. Wrapped lines become one again,
 * as they were written.
 */
function readLines(count: number): string {
  const buffer = term.value?.buffer.active;
  if (!buffer) return "";
  const lines: string[] = [];
  for (let y = 0; y < buffer.length; y++) {
    const line = buffer.getLine(y);
    if (!line) continue;
    const text = line.translateToString(true);
    if (line.isWrapped && lines.length) lines[lines.length - 1] += text;
    else lines.push(text);
  }
  while (lines.length && !lines[lines.length - 1].trim()) lines.pop();
  return lines.slice(-count).join("\n");
}

// shallowRef: these are large mutable objects that must not be made reactive.
const term = shallowRef<Terminal>();
const fit = shallowRef<FitAddon>();
const search = shallowRef<SearchAddon>();
const serializer = shallowRef<SerializeAddon>();
const unlisten = shallowRef<UnlistenFn[]>([]);
const observer = shallowRef<ResizeObserver>();
let refitTimer: ReturnType<typeof setTimeout> | undefined;

/**
 * OSC 52, write only.
 *
 * The sequence lets the far side put text into the local clipboard, which is
 * what makes a tmux or neovim yank over SSH work. It can also *read* the
 * clipboard, and that is the part we refuse: a server one happens to be logged
 * into should not be able to ask for whatever was copied last, which on this
 * machine may well have come out of a password manager.
 */
class WriteOnlyClipboard implements IClipboardProvider {
  readText(): string {
    return "";
  }

  async writeText(_selection: ClipboardSelectionType, text: string): Promise<void> {
    await copyToClipboard(text);
  }
}

async function copyToClipboard(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    // Blocked or unavailable. A failed copy must not take the session down.
    return false;
  }
}

/**
 * Each addon on its own, because every one of them is decoration: a terminal
 * that cannot search is a nuisance, a connection that never opens because an
 * addon threw is a fault. The name makes a broken one findable in the console
 * instead of it failing silently.
 */
function attempt(name: string, load: () => void) {
  try {
    load();
  } catch (e) {
    console.warn(`Terminal addon "${name}" not loaded:`, e);
  }
}

/**
 * The settings live outside any workspace and every terminal reads the same
 * object, so one change reaches all open sessions at once. Everything here can
 * be set on a running terminal, which is what lets the dialog preview a theme
 * on the session behind it.
 */
function applySettings(terminal: Terminal) {
  const s = terminalSettings;
  terminal.options.theme = findTheme(s.theme).theme;
  terminal.options.fontFamily = s.fontFamily;
  terminal.options.fontSize = s.fontSize;
  terminal.options.lineHeight = s.lineHeight;
  terminal.options.cursorStyle = s.cursorStyle;
  terminal.options.cursorBlink = s.cursorBlink;
  terminal.options.scrollback = s.scrollback;
  terminal.options.minimumContrastRatio = s.minimumContrastRatio;
  terminal.options.drawBoldTextInBrightColors = s.drawBoldTextInBrightColors;
}

function loadAddons(terminal: Terminal) {
  // Emoji and CJK are two cells wide; without this xterm assumes one and the
  // cursor ends up beside the text on any prompt with an icon in it.
  attempt("unicode11", () => {
    terminal.loadAddon(new Unicode11Addon());
    terminal.unicode.activeVersion = "11";
  });

  // Into the system browser, not this window: the default would navigate the
  // app itself away and there is no way back from that.
  attempt("web-links", () => {
    terminal.loadAddon(
      new WebLinksAddon((event, uri) => {
        event.preventDefault();
        openUrl(uri).catch(() => {});
      }),
    );
  });

  attempt("clipboard", () => {
    terminal.loadAddon(new ClipboardAddon(undefined, new WriteOnlyClipboard()));
  });

  attempt("search", () => {
    const addon = new SearchAddon();
    terminal.loadAddon(addon);
    addon.onDidChangeResults(({ resultIndex, resultCount }) => {
      hits.value = { index: resultIndex, count: resultCount };
    });
    search.value = addon;
  });

  attempt("serialize", () => {
    const addon = new SerializeAddon();
    terminal.loadAddon(addon);
    serializer.value = addon;
  });

  // The GPU renderer, which is what keeps a chatty `tail -f` readable. It can
  // fail to start (no WebGL2 at all) and it can lose a live context later —
  // not exotic here, since every open tab keeps its terminal mounted and holds
  // its own context while the browser caps how many it hands out. Either way
  // the DOM renderer takes over: slower, still correct.
  attempt("webgl", () => {
    const webgl = new WebglAddon();
    webgl.onContextLoss(() => webgl.dispose());
    terminal.loadAddon(webgl);
  });
}

function refit() {
  try {
    fit.value?.fit();
  } catch {
    // fit() throws while the element is hidden or has no size yet.
  }
}

async function connect() {
  if (connected.value || connecting.value) return;
  connecting.value = true;
  error.value = "";
  report("connecting");

  // Everything, not just the invoke: anything thrown while building the
  // terminal used to leave `connecting` stuck at true, which hid the error bar
  // and looked exactly like a connection waiting on something.
  try {
    await open();
    connected.value = true;
    report("connected");
    if (props.active) term.value?.focus();
    runStartup();
  } catch (e) {
    error.value = String(e);
    // A vault that has to be sorted out first raises its own dialog. The bar
    // below still says what happened and still offers "Reconnect",
    // which is what to do once it has been.
    reportVaultProblem(error.value);
    await teardown();
    report("error");
  } finally {
    connecting.value = false;
  }
}

/** Builds the terminal, wires it up and opens the session. */
async function open() {
  const terminal = new Terminal({
    // Two of the addons below throw without it: unicode11 sets a Unicode
    // version, and the search addon draws its hits with decorations. Both of
    // those APIs are marked proposed and may change between xterm minor
    // releases, which is why xterm is pinned to an exact version.
    allowProposedApi: true,
    // Draws the search hits beside the scrollbar, so a match far up the buffer
    // is findable rather than merely found.
    overviewRuler: { width: 10 },
  });
  applySettings(terminal);
  const fitAddon = new FitAddon();
  terminal.loadAddon(fitAddon);
  terminal.open(host.value!);
  term.value = terminal;
  fit.value = fitAddon;
  loadAddons(terminal);
  refit();

  // Ctrl+Shift+F, as in most terminal emulators. Plain Ctrl+F is left to the
  // remote side, where it is forward-char in readline and page-down in vim.
  terminal.attachCustomKeyEventHandler((event) => {
    if (event.type === "keydown" && event.ctrlKey && event.shiftKey && event.code === "KeyF") {
      openSearch();
      return false;
    }
    return true;
  });

  // Subscribe before connecting so the shell's banner and first prompt are
  // not missed. The event names carry the session id, so this terminal only
  // hears its own output.
  unlisten.value = [
    await listen<number[]>(`${channel}:data:${props.sessionId}`, (event) => {
      terminal.write(new Uint8Array(event.payload));
    }),
    await listen(`${channel}:closed:${props.sessionId}`, () => {
      terminal.writeln(
        `\r\n\x1b[90m-- ${props.local ? t("SshTerminal.shellClosed") : t("SshTerminal.connectionClosed")} --\x1b[0m`,
      );
      connected.value = false;
      report("closed");
    }),
    // Arrives a moment after the shell, once the backend has asked the target
    // what it is. Never arrives if the target does not say.
    await listen<RemoteSystem>(`ssh:system:${props.sessionId}`, (event) => {
      emit("system", event.payload);
    }),
  ];

  // With broadcast, to all terminals of the split view.
  terminal.onData((data) => {
    sendInput(props.sessionId, data).catch((e) => (error.value = String(e)));
  });

  // fit() changes the terminal's cols/rows, which fires onResize; that is the
  // single place the remote pty is told about a new size.
  terminal.onResize(({ cols, rows }) => {
    invoke(`${channel}_resize`, { sessionId: props.sessionId, cols, rows }).catch(() => {});
  });

  // Debounced, because dragging a window edge produces a burst of events and
  // each one would otherwise become a round trip to the server.
  observer.value = new ResizeObserver(() => {
    clearTimeout(refitTimer);
    refitTimer = setTimeout(refit, 80);
  });
  observer.value.observe(host.value!);

  if (props.local) {
    await invoke("local_open", {
      sessionId: props.sessionId,
      shell: JSON.parse(JSON.stringify(props.local)),
      cols: terminal.cols,
      rows: terminal.rows,
    });
    return;
  }
  await invoke("ssh_connect", {
    sessionId: props.sessionId,
    settings: JSON.parse(JSON.stringify(props.settings)),
    cols: terminal.cols,
    rows: terminal.rows,
  });
}

async function teardown() {
  clearTimeout(refitTimer);
  clearTimeout(copyTimer);
  observer.value?.disconnect();
  observer.value = undefined;
  unlisten.value.forEach((fn) => fn());
  unlisten.value = [];
  // Disposing the terminal disposes the addons loaded into it.
  term.value?.dispose();
  term.value = undefined;
  fit.value = undefined;
  search.value = undefined;
  serializer.value = undefined;
  searching.value = false;
  connected.value = false;
}

async function disconnect() {
  await invoke(props.local ? "local_close" : "ssh_disconnect", { sessionId: props.sessionId }).catch(
    () => {},
  );
  await teardown();
}

// A hidden terminal has no size, so xterm cannot lay out while it is away.
// Re-measure once it is visible again.
watch(
  () => props.active,
  async (active) => {
    if (!active) return;
    await nextTick();
    refit();
    term.value?.focus();
  },
);

// Font size and line height change how many rows fit, so the remote pty has to
// be told — refit() does that through onResize.
watch(
  terminalSettings,
  () => {
    if (!term.value) return;
    applySettings(term.value);
    refit();
  },
  { deep: true },
);

onMounted(() => {
  registerTerminal(props.sessionId, props.connectionId, {
    local: props.local?.name,
    read: readLines,
  });
  void connect();
});
onBeforeUnmount(() => {
  unregisterTerminal(props.sessionId);
  void disconnect();
});
</script>

<template>
  <section class="terminal-pane">
    <!--
      No header while things are fine: the tab carries the name, the target and
      the state. This bar only appears once the session is gone, because
      otherwise there would be no way back without closing the tab.
    -->
    <div v-if="!connected && !connecting" class="ended">
      <Alert v-if="error" class="error" status="danger" variant="simple" size="sm">{{ error }}</Alert>
      <span v-else class="note">{{ local ? t("SshTerminal.shellEnded") : t("SshTerminal.disconnected") }}</span>
      <Button variant="outline" size="sm" @click="connect">
        {{ local ? t("SshTerminal.restart") : t("SshTerminal.reconnect") }}
      </Button>
    </div>

    <div class="screen-wrap">
      <div ref="host" class="screen" :style="{ background: screenBackground }"></div>

      <!--
        The tab dot already says "connecting", but the pane it opens into is
        blank, and the wait can be seconds long while a password manager is
        asked for the key. `pointer-events: none` so it never sits between the user and
        the terminal underneath.
      -->
      <div v-if="connecting" class="loading">
        <!-- The Spinner is the live region; the note is only for the eye. -->
        <Spinner size="lg" :label="local ? t('SshTerminal.starting') : t('SshTerminal.connecting')" />
        <span class="loading-note" aria-hidden="true">{{
          local ? t("SshTerminal.starting") : t("SshTerminal.connecting")
        }}</span>
      </div>

      <!-- Over the terminal and out of the way until wanted, like the cards. -->
      <div class="tools" :class="{ shown: searching || copyNote || snippetsOpen }">
        <template v-if="searching">
          <Input
            ref="needleInput"
            v-model="needle"
            class="needle"
            size="sm"
            type="text"
            :placeholder="t('SshTerminal.search')"
            :aria-label="t('SshTerminal.search')"
            @input="findNext(true)"
            @keydown.enter.exact.prevent="findNext()"
            @keydown.enter.shift.prevent="findPrevious"
            @keydown.esc.prevent="closeSearch"
          />
          <span class="count">
            {{ needle ? (hits.count ? `${hits.index + 1}/${hits.count}` : "0") : "" }}
          </span>
          <IconButton
            :icon="ChevronUp"
            :label="t('SshTerminal.previous')"
            :title="t('SshTerminal.previousTitle')"
            variant="text"
            size="xs"
            @click="findPrevious"
          />
          <IconButton
            :icon="ChevronDown"
            :label="t('SshTerminal.next')"
            :title="t('SshTerminal.nextTitle')"
            variant="text"
            size="xs"
            @click="findNext()"
          />
          <IconButton
            :icon="X"
            :label="t('SshTerminal.closeSearch')"
            :title="t('SshTerminal.closeSearchTitle')"
            variant="text"
            size="xs"
            @click="closeSearch"
          />
        </template>

        <template v-else>
          <span v-if="copyNote" class="count">{{ copyNote }}</span>
          <IconButton
            :icon="Search"
            :label="t('SshTerminal.search')"
            :title="t('SshTerminal.searchTitle')"
            variant="text"
            size="xs"
            @click="openSearch"
          />
          <IconButton
            v-if="connectionId"
            :icon="ScrollText"
            label="Snippets"
            :title="broadcast ? t('SshTerminal.snippetBroadcast') : t('SshTerminal.snippet')"
            variant="text"
            size="xs"
            @click="snippetsOpen = !snippetsOpen"
          />
          <SnippetMenu
            v-if="snippetsOpen"
            :snippets="snippets"
            :broadcast="broadcast"
            @run="run"
            @close="snippetsOpen = false"
          />
          <IconButton
            :icon="Copy"
            :label="t('SshTerminal.copySession')"
            :title="t('SshTerminal.copySessionTitle')"
            variant="text"
            size="xs"
            @click="copySession"
          />
          <IconButton
            :icon="Settings"
            :label="t('SshTerminal.settings')"
            :title="t('SshTerminal.settings')"
            variant="text"
            size="xs"
            @click="settingsOpen = true"
          />
        </template>
      </div>

      <!--
        Edits the shared settings, so it changes this terminal and every other
        open one while it is on screen.
      -->
      <TerminalSettingsDialog v-if="settingsOpen" @close="settingsOpen = false" />
    </div>
  </section>
</template>

<style scoped>
.terminal-pane {
  display: flex;
  flex-direction: column;
  height: 100%;
  min-height: 0;
  padding: 0.75rem 1rem 1rem;
  box-sizing: border-box;
}

.ended {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  flex-wrap: wrap;
  padding: 0 0 0.6rem;
}

.note {
  color: var(--muted);
  font-size: 0.85rem;
}

.error {
  word-break: break-word;
}

/* Only here to anchor the tools; the screen keeps sizing itself the way it
   did before, as a flex item. Giving it `height: 100%` instead let its padding
   push it past the pane and put a scrollbar on the page. */
.screen-wrap {
  position: relative;
  display: flex;
  flex-direction: column;
  flex: 1;
  min-height: 0;
}

.loading {
  position: absolute;
  inset: 0;
  z-index: 1;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 0.75rem;
  pointer-events: none;
}

.loading-note {
  font-size: 0.8rem;
  color: var(--muted);
}

.tools {
  position: absolute;
  top: 0.5rem;
  /* Clear of xterm's own scrollbar and the overview ruler beside it. */
  right: 1.5rem;
  z-index: 2;
  display: flex;
  align-items: center;
  gap: 0.25rem;
  padding: 0.25rem;
  border-radius: 8px;
  background: var(--panel);
  border: 1px solid var(--border);
  box-shadow: 0 4px 14px rgba(0, 0, 0, 0.45);
  opacity: 0;
  pointer-events: none;
  transition: opacity 120ms ease;
}

/* `.shown` already covers the open search bar, so focus only has to keep the
   bar up for keyboard users — `:focus-within` would also hold it there after a
   click on the copy button, long after the pointer had left. */
.screen-wrap:hover .tools,
.tools:has(:focus-visible),
.tools.shown {
  opacity: 1;
  pointer-events: auto;
}

.needle {
  width: 12rem;
}

.count {
  flex: 0 0 auto;
  min-width: 2.5rem;
  text-align: center;
  font-size: 0.75rem;
  color: var(--muted);
  font-variant-numeric: tabular-nums;
}

@media (prefers-reduced-motion: reduce) {
  .tools {
    transition: none;
  }
}

.screen {
  flex: 1;
  min-height: 0;
  box-sizing: border-box;
  border-radius: 8px;
  overflow: hidden;
  padding: 0.5rem;
}
</style>
