/**
 * Formatting and path arithmetic for the file browser.
 *
 * The two sides do not spell paths the same way: the remote one is always
 * POSIX, the local one is whatever this machine uses. Every local path the
 * browser holds came from the backend, which spells it the platform's way, so
 * the separator is read back off the path rather than configured anywhere.
 */

import { intlLocale } from "./i18n";

/** What a download or upload rejects with when it was stopped. */
export const CANCELLED = "transfer:cancelled";

/**
 * Binary multiples, labelled as such. A file manager that says "MB" and means
 * 1 048 576 bytes disagrees with the size the operating system shows for the
 * same file, and the difference is large enough to notice.
 */
const UNITS = ["B", "KiB", "MiB", "GiB", "TiB"];

/** In the UI language, built once per language. */
const formats: Record<string, { decimal: Intl.NumberFormat; timestamp: Intl.DateTimeFormat }> = {};

function format() {
  return (formats[intlLocale.value] ??= {
    decimal: new Intl.NumberFormat(intlLocale.value, { maximumFractionDigits: 1 }),
    timestamp: new Intl.DateTimeFormat(intlLocale.value, { dateStyle: "short", timeStyle: "short" }),
  });
}

export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 0) return "–";
  if (bytes < 1024) return `${bytes} B`;
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < UNITS.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${format().decimal.format(value)} ${UNITS[unit]}`;
}

export function formatSpeed(bytesPerSecond: number): string {
  if (!Number.isFinite(bytesPerSecond) || bytesPerSecond <= 0) return "–";
  return `${formatBytes(bytesPerSecond)}/s`;
}

/** `m:ss`, or `h:mm:ss` once it runs that long. */
export function formatDuration(millis: number): string {
  if (!Number.isFinite(millis) || millis < 0) return "–";
  const total = Math.round(millis / 1000);
  const hours = Math.floor(total / 3600);
  const minutes = Math.floor((total % 3600) / 60);
  const seconds = total % 60;
  const pad = (n: number) => String(n).padStart(2, "0");
  return hours > 0 ? `${hours}:${pad(minutes)}:${pad(seconds)}` : `${minutes}:${pad(seconds)}`;
}

export function formatDate(unixSeconds: number | null): string {
  if (!unixSeconds) return "–";
  return format().timestamp.format(new Date(unixSeconds * 1000));
}

export function joinRemote(dir: string, name: string): string {
  return dir.endsWith("/") ? `${dir}${name}` : `${dir}/${name}`;
}

export function joinLocal(dir: string, name: string): string {
  const separator = dir.includes("\\") ? "\\" : "/";
  return dir.endsWith(separator) ? `${dir}${name}` : `${dir}${separator}${name}`;
}

/** Joins on whichever side the directory belongs to. */
export function join(side: "local" | "remote", dir: string, name: string): string {
  return side === "remote" ? joinRemote(dir, name) : joinLocal(dir, name);
}

/**
 * The name a conflicting entry gets when "Rename" is chosen, on the
 * `attempt`-th try: `note.txt` → `note (2).txt` → `note (3).txt`, or
 * `backup` → `backup (2)` for a directory, which has no extension to keep out
 * of the way of the counter.
 */
export function candidateName(name: string, isDir: boolean, attempt: number): string {
  if (isDir) return `${name} (${attempt})`;
  const dot = name.lastIndexOf(".");
  // A dot at the very start (`.gitignore`) is not an extension — nothing
  // meaningful would be left of it to keep.
  if (dot <= 0) return `${name} (${attempt})`;
  return `${name.slice(0, dot)} (${attempt})${name.slice(dot)}`;
}
