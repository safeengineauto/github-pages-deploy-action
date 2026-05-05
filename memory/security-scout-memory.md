# Security Scout Memory

This file tracks previously audited targets to avoid redundant work across cycles.

## Audited Targets

| Date | Target | Run Type | Report | Summary |
|------|--------|----------|--------|---------|
| 2025-05-05 | `JamesIves/github-pages-deploy-action` (v4.8.0, `dev` branch) | initial | `reports/2025-05-05-github-pages-deploy-action.md` | 10 findings (1 High, 3 Medium, 4 Low, 2 Info). Key issues: shell command injection via unescaped inputs in git.ts, token embedded in CLI arguments, debug-mode secret suppression bypass, outdated SSH host keys. |
