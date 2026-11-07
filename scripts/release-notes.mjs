// Writes the body of a GitHub release: a table of the installers, the way
// RustDesk shows its downloads, followed by GitHub's generated notes.
//
//   node scripts/release-notes.mjs <release.json> <owner/repo> <tag> [generated-notes.md] > body.md
//
// <release.json> is the release from the API (`gh api repos/<owner/repo>/releases/<id>`);
// only the names in its `assets` are read. The table is built from
// the files that were actually uploaded, so it never links to one a build job
// did not produce. The links are built from tag and file name: while the
// release is a draft, GitHub serves its files under a provisional path that
// changes when it is published.

import { readFileSync } from "node:fs";

const [releaseFile, repo, tag, notesFile] = process.argv.slice(2);
if (!releaseFile || !repo || !tag) {
  console.error("usage: release-notes.mjs <release.json> <owner/repo> <tag> [generated-notes.md]");
  process.exit(1);
}
const download = (name) =>
  `https://github.com/${repo}/releases/download/${encodeURIComponent(tag)}/${encodeURIComponent(name)}`;

const { assets } = JSON.parse(readFileSync(releaseFile, "utf8"));
const notes = notesFile ? readFileSync(notesFile, "utf8").trim() : "";

// The file name endings Tauri's bundlers produce, by column and row.
const ARCHS = [
  { label: "x86-64 (64-bit)", win: "x64", mac: "x64", deb: "amd64", rpm: "x86_64", appimage: "amd64" },
  { label: "AArch64 (ARM64)", win: "arm64", mac: "aarch64", deb: "arm64", rpm: "aarch64", appimage: "aarch64" },
];
const COLUMNS = [
  { title: "Windows", files: (a) => [[`_${a.win}-setup.exe`, "EXE"], [new RegExp(`_${a.win}_[A-Za-z-]+\\.msi$`), "MSI"]] },
  { title: "macOS", files: (a) => [[`_${a.mac}.dmg`, "DMG"]] },
  { title: "Debian / Ubuntu", files: (a) => [[`_${a.deb}.deb`, "DEB"]] },
  { title: "Fedora / openSUSE", files: (a) => [[`.${a.rpm}.rpm`, "RPM"]] },
  { title: "Other Linux", files: (a) => [[`_${a.appimage}.AppImage`, "AppImage"]] },
];

const find = (ending) =>
  assets.find((asset) =>
    typeof ending === "string" ? asset.name.endsWith(ending) : ending.test(asset.name),
  );

const cell = (column, arch) =>
  column
    .files(arch)
    .map(([ending, label]) => find(ending))
    .map((asset, i) => (asset ? `[${column.files(arch)[i][1]}](${download(asset.name)})` : null))
    .filter(Boolean)
    .join(" · ") || "–";

const rows = ARCHS.map((arch) => `| ${arch.label} | ${COLUMNS.map((c) => cell(c, arch)).join(" | ")} |`);

const body = [
  `| Architecture | ${COLUMNS.map((c) => c.title).join(" | ")} |`,
  `|---|${COLUMNS.map(() => ":---:").join("|")}|`,
  ...rows,
  "",
  "Not sure which one? Windows: the EXE. Mac: Apple Silicon (M1 and later) is AArch64, an Intel Mac x86-64. Linux: the package of your distribution, otherwise the AppImage.",
  "",
  "> [!NOTE]",
  "> The installers are not signed yet. Windows SmartScreen warns before the first start; on macOS the app opens only after allowing it under **System Settings → Privacy & Security**.",
  "",
  "Sign in with [WireCloud](https://cloud.wirecore.net) to sync your workspaces — see [Getting started](https://github.com/WireCore/wireterm#getting-started).",
  ...(notes ? ["", notes] : []),
  "",
].join("\n");

process.stdout.write(body);
