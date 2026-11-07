# Contributing

Thank you for helping with WireTerm. Bug reports, ideas and pull requests are
welcome.

## Before you start

- For anything bigger than a small fix, open an issue first so we can agree on
  the approach before you spend time on it. [TODO.md](TODO.md) lists what is
  known to be missing.
- Security problems go through the private channel in [SECURITY.md](SECURITY.md),
  not through issues.

## Development

The client builds on **Windows, macOS and Linux** (Node.js, Rust, Go for the 1Password
sidecar); see [README.md](README.md) for the setup.

```bash
npm install
npm run build:sidecar
npm run tauri dev
```

Before a pull request:

```bash
npm run build                      # vue-tsc and Vite
cd src-tauri && cargo fmt --check && cargo test --lib
```

The CI runs the same. Add or adjust tests for what you change; the live tests
(`#[ignore]`) need servers and are described in the README.

## Guidelines

- Code, comments and commit messages are in English.
- Every text a user sees exists in English and German: in
  `src/locales/<Area>/{en,de}.json` (vue-i18n) for the UI and in
  `src-tauri/locales/*.yml` (rust-i18n) for messages from the Rust side.
  English is the source; never call `t()` at module load.
- Nothing persisted or sent over the wire changes its shape without a
  migration path: `workspaces.json`, export files, serde names, error codes.
- Rust code stays rustfmt-clean.

## License

By contributing you agree that your contribution is licensed under the
[GNU AGPL v3](LICENSE), like the rest of the project.
