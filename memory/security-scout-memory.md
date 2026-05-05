# OSS Security Scout — Memory

Append-only style log of **completed scout targets** for this control repository. Cycles should skip targets already listed here unless a **follow-up** run is explicitly requested.

## Completed targets

| Date (UTC) | Run type | Target | Scope / notes |
|------------|----------|--------|----------------|
| 2026-05-05 | initial | **Control repo:** `JamesIves/github-pages-deploy-action` | First-party `src/*`, `action.yml`; shell-built `git`/`rsync`; token-in-URL remote |
| 2026-05-05 | initial | **OSS dependency:** `@actions/github@9.0.0` | Declared in `package.json`; supply-chain / advisory posture (no local audit run) |

## Avoid duplicating (next initial / broad passes)

- Deep-dive on `@actions/github@9.0.0` **again** unless version changes or a new advisory names this release line — prefer bump + lockfile audit first.
- Re-review **entire** first-party `src/` tree from scratch only after significant refactors or new deployment surfaces.

## Candidate queue (not yet scouted as primary targets)

- Transitive dependency tree under `@actions/github` (requires install + audit/OSV).
- Remaining `.github/workflows/*.yml` (deploy, production, sponsors, version, label) for least-privilege and secret handling.
- `@actions/core`, `@actions/exec`, `@actions/io` pinned versions vs known GHSA history.
