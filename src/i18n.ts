/**
 * The UI language.
 *
 * Starts with the system language (German if the system says German, English
 * otherwise) unless the user picked one; the choice lives in localStorage, like
 * the terminal settings, because it belongs to this person on this machine.
 *
 * Texts live in `locales/<area>/<locale>.json`, one area per component or
 * module, and are addressed as `t("<area>.<key>")`. Areas keep translators and
 * parallel changes out of each other's way; `common` holds what many share.
 * The Rust side has its own files (`src-tauri/locales`) and learns the locale
 * through `set_locale`.
 */

import { computed, ref } from "vue";
import { createI18n } from "vue-i18n";
import { invoke } from "@tauri-apps/api/core";

export type Locale = "en" | "de";
/** What the user picked; `system` follows the operating system. */
export type LocaleChoice = Locale | "system";

export const LOCALES: Locale[] = ["en", "de"];
/** Each in its own language, so a reader who cannot read the current one still finds theirs. */
export const LOCALE_NAMES: Record<Locale, string> = { en: "English", de: "Deutsch" };

const STORAGE_KEY = "wireterm.locale";

// eslint-disable-next-line @typescript-eslint/no-explicit-any -- nested JSON of any depth
type Messages = Record<string, any>;
const files = import.meta.glob<{ default: Messages }>("./locales/*/*.json", { eager: true });
const messages: Record<Locale, Messages> = { en: {}, de: {} };
for (const [path, module] of Object.entries(files)) {
  const match = /\/locales\/([^/]+)\/(en|de)\.json$/.exec(path);
  if (match) messages[match[2] as Locale][match[1]] = module.default;
}

function systemLocale(): Locale {
  return navigator.language.toLowerCase().startsWith("de") ? "de" : "en";
}

function storedChoice(): LocaleChoice {
  try {
    const value = localStorage.getItem(STORAGE_KEY);
    if (value === "en" || value === "de") return value;
  } catch {
    // No storage: follow the system.
  }
  return "system";
}

const choice = ref<LocaleChoice>(storedChoice());

function resolve(value: LocaleChoice): Locale {
  return value === "system" ? systemLocale() : value;
}

export const i18n = createI18n({
  legacy: false as const,
  locale: resolve(choice.value),
  fallbackLocale: "en",
  messages,
});

/**
 * The global composer, typed narrowly: vue-i18n infers its types from the
 * message tree, and with JSON of any depth that inference does not terminate.
 */
const composer = i18n.global as unknown as {
  locale: { value: Locale };
  t: (key: string, values: Record<string, unknown>) => string;
};

/** The language in effect right now. */
export const locale = computed(() => composer.locale.value);
/** What the user picked, including `system`. */
export const localeChoice = computed(() => choice.value);
/** For WireLayer's LocaleProvider and number/date formatting. */
export const intlLocale = computed(() => (locale.value === "de" ? "de-DE" : "en-US"));

/** Shorthand for code outside components (stores, helpers). */
export function t(key: string, values: Record<string, unknown> = {}): string {
  return composer.t(key, values);
}

function apply(value: Locale) {
  composer.locale.value = value;
  document.documentElement.lang = value;
  // The Rust side builds its own messages; it needs to know as well.
  return invoke("set_locale", { locale: value });
}

/** Called once at startup, before anything asks the Rust side for a message. */
export function initLocale() {
  return apply(locale.value);
}

/** Changes the language and tells every signed-in backend account about it. */
export async function setLocale(value: LocaleChoice) {
  choice.value = value;
  try {
    if (value === "system") localStorage.removeItem(STORAGE_KEY);
    else localStorage.setItem(STORAGE_KEY, value);
  } catch {
    // Not stored: the choice holds until the app closes.
  }
  await apply(resolve(value));
  // Mails from a backend (password reset, invitations) use the account's language.
  await invoke("cloud_push_locale").catch(() => undefined);
}
