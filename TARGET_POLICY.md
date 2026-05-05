# OSS Security Scout — Target Policy

## Eligible targets

1. **Primary**: This control repository (`github-pages-deploy-action` / workspace root) — TypeScript action sources, `action.yml`, GitHub workflows under `.github/workflows`, and documented inputs/outputs.
2. **Secondary** (future cycles): Upstream dependencies declared in `package.json` / lockfile, **scanned read-only** via public metadata (advisories, release notes) without cloning outside this workspace unless explicitly added as a git submodule here.

## Selection rules

- Each cycle selects **one** target.
- **Skip** any repository or path already listed under “Covered targets” in `memory/security-scout-memory.md` for the same run type, unless the mission is a `follow-up` or `delta` explicitly targeting that entry.
- Prefer targets with security-sensitive behavior: authentication, subprocess invocation, file I/O, network/git operations, workflow `permissions`, and secret handling.

## Initial cycle default

For `run_type: initial`, if memory is empty or contains no prior coverage of the control repo, the default target is **this repository** at its canonical remote:

`https://github.com/JamesIves/github-pages-deploy-action`

## Constraints

- Do not store secrets, tokens, or private keys in reports or memory.
- Cite only **public** repository layout and behavior observable from this workspace.
