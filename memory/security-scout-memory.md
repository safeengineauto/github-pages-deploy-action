# Security Scout Memory

This file tracks all targets that have already been scanned. Future run cycles **must not** re-scan targets listed here unless the run type is `followup` or `advisory`.

## Scanned Targets

| Slug | Full target | Scan date | Run type | Version / Commit | One-line summary |
|---|---|---|---|---|---|
| `github-pages-deploy-action` | `JamesIves/github-pages-deploy-action` | 2026-05-05 | initial | 4.8.0 / `8072b9c` | 2 medium-severity argument-injection surfaces (commit-message, tag inputs), 2 low-severity git config injections, weak randomness in temp branch name, all 4 March-2026 undici CVEs already patched in resolved lockfile version (6.24.1). |

## Notes

- Reports are stored under `reports/`.
- Each entry's slug must match the filename prefix in `reports/` for easy cross-referencing.
