/**
 * Searching and ordering the workspace tree.
 *
 * Shared by the overview and the tab menu, so a search means the same thing in
 * both and a connection sits in the same place in both lists.
 */

import { locale, type Locale } from "./i18n";
import type { Connection, Project } from "./types";

/**
 * `sensitivity: "base"` ignores case and accents, so `Ärger` sorts at `A`
 * rather than after `Z`. `numeric` puts `web-2` before `web-10` instead of
 * after it, which is the difference between useful and annoying once hosts are
 * numbered.
 */
const collators: Partial<Record<Locale, Intl.Collator>> = {};

/** In the UI language, built once per language. */
function collator(): Intl.Collator {
  return (collators[locale.value] ??= new Intl.Collator(locale.value, {
    sensitivity: "base",
    numeric: true,
  }));
}

export function byName(a: { name: string }, b: { name: string }): number {
  return collator().compare(a.name, b.name);
}

/** Plain case-insensitive substring; `needle` is expected already lowercased. */
export function matches(text: string, needle: string): boolean {
  return text.toLocaleLowerCase(locale.value).includes(needle);
}

export function normalize(query: string): string {
  return query.trim().toLocaleLowerCase(locale.value);
}

/** One project as it is drawn, with its connections already filtered. */
export type ProjectView = { project: Project; connections: Connection[] };

/**
 * The tree after a search, connections in alphabetical order.
 *
 * A project whose own name matches brings all of its connections along —
 * searching for a project means wanting to see that project. One whose name
 * does not match keeps only the connections that match themselves, and drops
 * out entirely when none do.
 *
 * The result is a view: the stored order is never touched.
 */
export function filterProjects(projects: Project[], query: string): ProjectView[] {
  const needle = normalize(query);
  return projects.flatMap((project) => {
    const sorted = [...project.connections].sort(byName);
    if (!needle || matches(project.name, needle)) return [{ project, connections: sorted }];
    const hits = sorted.filter((c) => matches(c.name, needle));
    return hits.length ? [{ project, connections: hits }] : [];
  });
}

/** The bookmarked connections of a workspace, searched and sorted alike. */
export function filterBookmarks(projects: Project[], query: string): Connection[] {
  const needle = normalize(query);
  return projects
    .flatMap((project) => project.connections)
    .filter((c) => c.bookmarked && (!needle || matches(c.name, needle)))
    .sort(byName);
}
