# Security Scout Memory

## Purpose
Tracks targets already analysed so future cycles avoid repetition.

---

## Analysed Targets

### 2026-05-05 — JamesIves/github-pages-deploy-action (this repository)
- **Run type:** initial
- **Cycle:** 1
- **Report file:** `reports/2026-05-05-github-pages-deploy-action.md`
- **Findings summary:**
  - SCOUT-001: Command injection via user-controlled git config inputs (HIGH)
  - SCOUT-002: Command injection via commit-message / tag / branch in shell strings (HIGH)
  - SCOUT-003: Revoked GitHub RSA SSH host key pinned in code (HIGH)
  - SCOUT-004: Token not masked with `core.setSecret()` — relies solely on manual suppression (MEDIUM)
  - SCOUT-005: `async` callbacks in `Array.prototype.map()` for SSH key loading — promise errors silently dropped (MEDIUM)
  - SCOUT-006: `Math.random()` used for temporary deployment branch name (LOW)
  - SCOUT-007: `git commit --no-verify` silently bypasses repo-configured commit hooks (INFORMATIONAL)

---
