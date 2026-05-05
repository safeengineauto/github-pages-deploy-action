# Target Selection Policy

## Eligible Targets

Targets must be **public OSS projects** that meet at least one of these criteria:

1. **Direct dependency** of this repository (listed in `package.json`).
2. **Transitive dependency** reachable via `yarn.lock` / `package-lock.json`.
3. **Peer GitHub Action** commonly composed with this action in workflows (e.g. `actions/checkout`, `actions/upload-artifact`).
4. **Ecosystem peer** — a GitHub Action or deployment tool in the same problem space.

## Selection Priority

Prefer targets that:

- Have high downstream usage (npm weekly downloads, GitHub Action marketplace installs).
- Handle secrets, tokens, SSH keys, or filesystem operations.
- Have not been audited recently by this scout (check `memory/security-scout-memory.md`).
- Have had recent code changes in security-sensitive areas.

## Exclusions

- Targets already listed in `memory/security-scout-memory.md` (unless the run type is `follow-up` or `cross-check`).
- Private or archived repositories.
- Projects with fewer than 100 GitHub stars (too niche for broad-impact scouting).

## Scope per Audit

Each audit should examine:

1. **Input handling** — Action inputs, environment variables, event payloads.
2. **Command injection** — Shell commands built from untrusted strings.
3. **Path traversal** — File operations on user-controlled paths.
4. **Secret exposure** — Tokens or keys leaked via logs, outputs, or artifacts.
5. **Dependency hygiene** — Known CVEs, pinning practices, lockfile integrity.
6. **CI/CD configuration** — Workflow permissions, `pull_request_target` usage, artifact trust.
