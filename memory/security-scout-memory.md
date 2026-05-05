# Security Scout Memory

This file tracks all targets that have been audited by the OSS Security Scout.
Consult this before selecting a new target to avoid duplicate work.

## Audited Targets

| Date | Target | Run Type | Report | Summary |
|------|--------|----------|--------|---------|
| 2026-05-05 | `release-drafter/release-drafter` | cross-check | `reports/2026-05-05-release-drafter-crosscheck.md` | Path traversal in `normalizeFilepath`/`getConfigFileFromFs` confirmed real but downgraded from P1 to P3 — no untrusted-input reachability in idiomatic usage. |
| 2026-05-05 | `actions/toolkit` (`@actions/exec`, `@actions/io`) | initial | `reports/2026-05-05-actions-exec.md` | No critical vulns. P3 findings: `argStringToArray` argument-injection risk when callers interpolate user input into commandLine strings; Windows `%`-expansion not escaped in cmd.exe quoting; `io.cp` follows symlinks without containment checks. Bonus finding: consumer repo ships compromised pre-2023-03-24 GitHub RSA SSH host key. |
