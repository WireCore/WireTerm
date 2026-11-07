/**
 * How every terminal looks and behaves.
 *
 * Kept in localStorage rather than in workspaces.json, for the same reason the
 * last-opened workspace is: this describes how *this person on this machine*
 * wants to read a terminal, not what a workspace contains. It must not travel
 * along once workspaces can live on a backend, and it deliberately applies to
 * every connection in every workspace at once.
 */

import { reactive, watch } from "vue";
import type { ITheme } from "@xterm/xterm";
import { t } from "./i18n";

export type CursorStyle = "block" | "underline" | "bar";

export type TerminalSettings = {
  /** Id of one of [`TERMINAL_THEMES`]; an unknown one falls back to the first. */
  theme: string;
  fontFamily: string;
  fontSize: number;
  lineHeight: number;
  cursorStyle: CursorStyle;
  cursorBlink: boolean;
  /** Lines kept above the screen. Only cost is memory. */
  scrollback: number;
  /**
   * Lifts foreground colours until they reach this contrast against their
   * background. 1 disables it. It is the cure for programs that write dark
   * blue on black.
   */
  minimumContrastRatio: number;
  /** Off reads calmer: bold stays bold instead of also changing colour. */
  drawBoldTextInBrightColors: boolean;
};

export const DEFAULT_SETTINGS: TerminalSettings = {
  theme: "wireterm",
  fontFamily: "Consolas, Menlo, monospace",
  fontSize: 13,
  lineHeight: 1.2,
  cursorStyle: "block",
  cursorBlink: true,
  scrollback: 10000,
  minimumContrastRatio: 1,
  drawBoldTextInBrightColors: true,
};

// Labels that need translating are getters, so they follow the language at
// render time instead of freezing it at import.

export const FONT_FAMILIES: { value: string; label: string }[] = [
  { value: "Consolas, Menlo, monospace", label: "Consolas" },
  { value: "'Cascadia Mono', Consolas, monospace", label: "Cascadia Mono" },
  { value: "'JetBrains Mono', Consolas, monospace", label: "JetBrains Mono" },
  { value: "'Fira Code', Consolas, monospace", label: "Fira Code" },
  { value: "'Source Code Pro', Consolas, monospace", label: "Source Code Pro" },
  {
    value: "monospace",
    get label() {
      return t("terminal-settings.font.system");
    },
  },
];

export const CURSOR_STYLES: { value: CursorStyle; label: string }[] = [
  {
    value: "block",
    get label() {
      return t("terminal-settings.cursor.block");
    },
  },
  {
    value: "underline",
    get label() {
      return t("terminal-settings.cursor.underline");
    },
  },
  {
    value: "bar",
    get label() {
      return t("terminal-settings.cursor.bar");
    },
  },
];

export const CONTRAST_LEVELS: { value: number; label: string }[] = [
  {
    value: 1,
    get label() {
      return t("terminal-settings.contrast.off");
    },
  },
  {
    value: 3,
    get label() {
      return t("terminal-settings.contrast.light");
    },
  },
  {
    value: 4.5,
    get label() {
      return t("terminal-settings.contrast.readable");
    },
  },
  {
    value: 7,
    get label() {
      return t("terminal-settings.contrast.strong");
    },
  },
];

// ---- Themes ----------------------------------------------------------------
//
// The published palettes, transcribed. Each carries the full 16 ANSI colours,
// because a terminal that only themes the background still shows whatever the
// remote `ls` and prompt decide to colour things.

export type TerminalTheme = {
  id: string;
  label: string;
  /** Groups the picker and tells the app which way round the pane should go. */
  dark: boolean;
  theme: ITheme;
};

export const TERMINAL_THEMES: TerminalTheme[] = [
  {
    id: "wireterm",
    label: "WireTerm",
    dark: true,
    // The app's own palette, so the terminal sits in the window rather than on
    // top of it. Colours follow the --accent/--ok/--warn/--danger variables.
    theme: {
      background: "#14161a",
      foreground: "#e6e8ea",
      cursor: "#4c9aff",
      cursorAccent: "#14161a",
      selectionBackground: "#2f5a94",
      black: "#1b1d21",
      red: "#e56a5a",
      green: "#4fbf72",
      yellow: "#e0a33a",
      blue: "#4c9aff",
      magenta: "#b48ead",
      cyan: "#5ec8d8",
      white: "#c8ccd2",
      brightBlack: "#5a616b",
      brightRed: "#ff8574",
      brightGreen: "#6fdc90",
      brightYellow: "#f5bd5c",
      brightBlue: "#79b4ff",
      brightMagenta: "#cfa8c8",
      brightCyan: "#7fe0ee",
      brightWhite: "#f2f4f6",
    },
  },
  {
    id: "campbell",
    label: "Campbell",
    dark: true,
    // What Windows Terminal ships as its default.
    theme: {
      background: "#0c0c0c",
      foreground: "#cccccc",
      cursor: "#ffffff",
      cursorAccent: "#0c0c0c",
      selectionBackground: "#3a3d41",
      black: "#0c0c0c",
      red: "#c50f1f",
      green: "#13a10e",
      yellow: "#c19c00",
      blue: "#0037da",
      magenta: "#881798",
      cyan: "#3a96dd",
      white: "#cccccc",
      brightBlack: "#767676",
      brightRed: "#e74856",
      brightGreen: "#16c60c",
      brightYellow: "#f9f1a5",
      brightBlue: "#3b78ff",
      brightMagenta: "#b4009e",
      brightCyan: "#61d6d6",
      brightWhite: "#f2f2f2",
    },
  },
  {
    id: "one-half-dark",
    label: "One Half Dark",
    dark: true,
    theme: {
      background: "#282c34",
      foreground: "#dcdfe4",
      cursor: "#dcdfe4",
      cursorAccent: "#282c34",
      selectionBackground: "#474e5d",
      black: "#282c34",
      red: "#e06c75",
      green: "#98c379",
      yellow: "#e5c07b",
      blue: "#61afef",
      magenta: "#c678dd",
      cyan: "#56b6c2",
      white: "#dcdfe4",
      brightBlack: "#5a6374",
      brightRed: "#e06c75",
      brightGreen: "#98c379",
      brightYellow: "#e5c07b",
      brightBlue: "#61afef",
      brightMagenta: "#c678dd",
      brightCyan: "#56b6c2",
      brightWhite: "#dcdfe4",
    },
  },
  {
    id: "dracula",
    label: "Dracula",
    dark: true,
    theme: {
      background: "#282a36",
      foreground: "#f8f8f2",
      cursor: "#f8f8f2",
      cursorAccent: "#282a36",
      selectionBackground: "#44475a",
      black: "#21222c",
      red: "#ff5555",
      green: "#50fa7b",
      yellow: "#f1fa8c",
      blue: "#bd93f9",
      magenta: "#ff79c6",
      cyan: "#8be9fd",
      white: "#f8f8f2",
      brightBlack: "#6272a4",
      brightRed: "#ff6e6e",
      brightGreen: "#69ff94",
      brightYellow: "#ffffa5",
      brightBlue: "#d6acff",
      brightMagenta: "#ff92df",
      brightCyan: "#a4ffff",
      brightWhite: "#ffffff",
    },
  },
  {
    id: "nord",
    label: "Nord",
    dark: true,
    theme: {
      background: "#2e3440",
      foreground: "#d8dee9",
      cursor: "#d8dee9",
      cursorAccent: "#2e3440",
      selectionBackground: "#434c5e",
      black: "#3b4252",
      red: "#bf616a",
      green: "#a3be8c",
      yellow: "#ebcb8b",
      blue: "#81a1c1",
      magenta: "#b48ead",
      cyan: "#88c0d0",
      white: "#e5e9f0",
      brightBlack: "#4c566a",
      brightRed: "#bf616a",
      brightGreen: "#a3be8c",
      brightYellow: "#ebcb8b",
      brightBlue: "#81a1c1",
      brightMagenta: "#b48ead",
      brightCyan: "#8fbcbb",
      brightWhite: "#eceff4",
    },
  },
  {
    id: "gruvbox-dark",
    label: "Gruvbox Dark",
    dark: true,
    theme: {
      background: "#282828",
      foreground: "#ebdbb2",
      cursor: "#ebdbb2",
      cursorAccent: "#282828",
      selectionBackground: "#504945",
      black: "#282828",
      red: "#cc241d",
      green: "#98971a",
      yellow: "#d79921",
      blue: "#458588",
      magenta: "#b16286",
      cyan: "#689d6a",
      white: "#a89984",
      brightBlack: "#928374",
      brightRed: "#fb4934",
      brightGreen: "#b8bb26",
      brightYellow: "#fabd2f",
      brightBlue: "#83a598",
      brightMagenta: "#d3869b",
      brightCyan: "#8ec07c",
      brightWhite: "#ebdbb2",
    },
  },
  {
    id: "solarized-dark",
    label: "Solarized Dark",
    dark: true,
    theme: {
      background: "#002b36",
      foreground: "#839496",
      cursor: "#93a1a1",
      cursorAccent: "#002b36",
      selectionBackground: "#073642",
      black: "#073642",
      red: "#dc322f",
      green: "#859900",
      yellow: "#b58900",
      blue: "#268bd2",
      magenta: "#d33682",
      cyan: "#2aa198",
      white: "#eee8d5",
      brightBlack: "#002b36",
      brightRed: "#cb4b16",
      brightGreen: "#586e75",
      brightYellow: "#657b83",
      brightBlue: "#839496",
      brightMagenta: "#6c71c4",
      brightCyan: "#93a1a1",
      brightWhite: "#fdf6e3",
    },
  },
  {
    id: "solarized-light",
    label: "Solarized Light",
    dark: false,
    theme: {
      background: "#fdf6e3",
      foreground: "#657b83",
      cursor: "#586e75",
      cursorAccent: "#fdf6e3",
      selectionBackground: "#eee8d5",
      black: "#073642",
      red: "#dc322f",
      green: "#859900",
      yellow: "#b58900",
      blue: "#268bd2",
      magenta: "#d33682",
      cyan: "#2aa198",
      white: "#eee8d5",
      brightBlack: "#002b36",
      brightRed: "#cb4b16",
      brightGreen: "#586e75",
      brightYellow: "#657b83",
      brightBlue: "#839496",
      brightMagenta: "#6c71c4",
      brightCyan: "#93a1a1",
      brightWhite: "#fdf6e3",
    },
  },
  {
    id: "one-half-light",
    label: "One Half Light",
    dark: false,
    theme: {
      background: "#fafafa",
      foreground: "#383a42",
      cursor: "#383a42",
      cursorAccent: "#fafafa",
      selectionBackground: "#bfceff",
      black: "#383a42",
      red: "#e45649",
      green: "#50a14f",
      yellow: "#c18401",
      blue: "#0184bc",
      magenta: "#a626a4",
      cyan: "#0997b3",
      white: "#fafafa",
      brightBlack: "#4f525d",
      brightRed: "#e45649",
      brightGreen: "#50a14f",
      brightYellow: "#c18401",
      brightBlue: "#0184bc",
      brightMagenta: "#a626a4",
      brightCyan: "#0997b3",
      brightWhite: "#ffffff",
    },
  },
];

export function findTheme(id: string): TerminalTheme {
  return TERMINAL_THEMES.find((t) => t.id === id) ?? TERMINAL_THEMES[0];
}

// ---- Storage ---------------------------------------------------------------

const KEY = "wireterm.terminalSettings";

function load(): TerminalSettings {
  try {
    const raw = localStorage.getItem(KEY);
    if (!raw) return { ...DEFAULT_SETTINGS };
    // Merged over the defaults, so a settings file written by an older build
    // gains new keys instead of leaving them undefined.
    return { ...DEFAULT_SETTINGS, ...JSON.parse(raw) };
  } catch {
    // Private mode, blocked storage or damaged JSON: the defaults are fine.
    return { ...DEFAULT_SETTINGS };
  }
}

export const terminalSettings = reactive<TerminalSettings>(load());

export function saveTerminalSettings() {
  try {
    localStorage.setItem(KEY, JSON.stringify(terminalSettings));
  } catch {
    // Losing the preference is survivable; failing the edit is not.
  }
}

export function resetTerminalSettings() {
  Object.assign(terminalSettings, DEFAULT_SETTINGS);
}

/**
 * Written straight through rather than on a save button: the dialog applies
 * changes to the open terminals as they are made, so there is no draft to
 * confirm. The object is a dozen fields — debouncing would only add a way to
 * lose the last one.
 */
watch(terminalSettings, saveTerminalSettings, { deep: true });
