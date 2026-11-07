# CLAUDE.md

## Prod build

Before every prod build (`npm run tauri build`), propose a new version and enter it only after
confirmation — always in all three files at once: `src-tauri/tauri.conf.json` (authoritative for
the installers), `package.json` and `src-tauri/Cargo.toml`. An installer with the same version
number does not replace the installed one. The MSI format only allows `Major.Minor.Patch` made of
numbers, so no `-beta`.

## WireLayer

The UI is built on `@wirecore/wirelayer-vue`. If something comes up that the library does not
cover and that would ideally be solved there (not project-specific, as an extension without a
change in behavior), it goes into `WIRELAYER-GAPS.md` together with where the workaround lives.
Remove resolved items there as soon as a new WireLayer version covers them and the workaround is
gone.

## Texts

Every user-visible text goes through vue-i18n (`src/locales/<Area>/{en,de}.json`) or rust-i18n
(`src-tauri/locales/*.yml`), always in both languages, with English as the source.

## Formatting

The Rust code in `src-tauri` is rustfmt-clean and should stay that way: run `cargo fmt --check`
(in `src-tauri`) before every commit.
