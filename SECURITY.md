# Security policy

WireTerm holds the keys to other people's servers: SSH keys, passwords, S3
credentials, access to password managers. We take reports about its security
seriously and are grateful for them.

## Reporting a vulnerability

Please **do not open a public issue**. Report it privately through GitHub:
**Security → Report a vulnerability** in this repository. Include what is
affected, how to reproduce it and what an attacker gains.

We confirm receipt within a few working days, keep you informed while we work
on a fix and credit you in the release notes unless you prefer otherwise.

## Scope

In scope is this repository: the desktop client, including the encryption of
secrets on the device and before they reach a backend, the host key and
certificate checks, the vault integrations (1Password, Bitwarden/Vaultwarden)
and the local MCP server. The sync server lives in `wirecore/wireterm-server`;
a report here reaches the same people either way.

Known and accepted: see the open points in [TODO.md](TODO.md) (for example
RUSTSEC-2023-0071 in `rsa`, with the reasoning in `src-tauri/.cargo/audit.toml`).

## Supported versions

Security fixes go into the latest release. Please update before reporting.
