# Security Scout Memory

This file is maintained automatically by the OSS Security Scout agent.
It records every completed scan cycle so the agent never revisits the same target.

---

## Completed Scans

| # | Repository | Scan Date | Run Type | Findings (C/H/M/L/I) | Report File |
|---|-----------|-----------|----------|----------------------|-------------|
| 1 | JamesIves/github-pages-deploy-action | 2026-05-05 | initial | 0C / 2H / 3M / 2L / 1I | `reports/2026-05-05-JamesIves-github-pages-deploy-action.md` |

---

## Finding Index

Quick-reference index of all findings across all cycles.

| Cycle | Repo | Finding | Severity |
|-------|------|---------|---------|
| 1 | JamesIves/github-pages-deploy-action | Race condition in shared `execute.ts` output buffer | HIGH |
| 1 | JamesIves/github-pages-deploy-action | Token embedded in plaintext HTTPS remote URL (visible in `git remote -v`) | HIGH |
| 1 | JamesIves/github-pages-deploy-action | Unpinned major-version ranges for security-sensitive `@actions/*` runtime deps | MEDIUM |
| 1 | JamesIves/github-pages-deploy-action | User-controlled commit message interpolated directly into shell command string | MEDIUM |
| 1 | JamesIves/github-pages-deploy-action | User-controlled `folder` path allows traversal outside workspace | MEDIUM |
| 1 | JamesIves/github-pages-deploy-action | SSH known-hosts seeded with deprecated DSS key type | LOW |
| 1 | JamesIves/github-pages-deploy-action | `getRsyncVersion` silently falls back to empty string, allowing version-check bypass | LOW |
| 1 | JamesIves/github-pages-deploy-action | `singleCommit` wipes full branch history without confirmation gate | INFO |

---

## Notes

- Initial run bootstrapped all scaffold files (AGENTS.md, TARGET_POLICY.md, REPORT_TEMPLATE.md, memory/).
- Next standard cycle should target a different P0-tier GitHub Action (e.g. `actions/cache` or `peaceiris/actions-gh-pages`).
