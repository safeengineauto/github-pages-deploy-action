# OSS Security Scout Memory

This file tracks targets already covered by OSS Security Scout cycles so future
runs can skip them. Each row is a single completed cycle. Future scouts should
treat every target listed here as off-limits unless `TARGET_POLICY.md`
explicitly authorizes a revisit.

## Targets already covered

| Date | Run type | Target | Commit / reference | Report | Outcome |
| --- | --- | --- | --- | --- | --- |
| 2026-05-05 | cross-check | `release-drafter/release-drafter` | `0c28acd0bcb335f1f86b350a4283045eb03025b9` | `reports/2026-05-05-release-drafter-crosscheck.md` (visible on remote branch `origin/cursor/release-drafter-p1-crosscheck-de06`) | Confirmed hardening bug (workspace path traversal in `getConfigFileFromFs`); severity narrowed from P1 to P3. |
| 2026-05-05 | initial | `JamesIves/github-pages-deploy-action` | `8072b9c7e8f9bd5cda32539dde262854f2073722` | `reports/2026-05-05-github-pages-deploy-action-argument-injection.md` (visible on remote branch `origin/cursor/security-scout-initial-e961`) and `reports/2026-05-05-github-pages-deploy-action-initial.md` (visible on remote branch `origin/cursor/security-scout-initial-gh-pages-action-bd3f`) | No reportable cross-boundary vulnerability; recommended hardening for command-string construction in `src/git.ts` / `src/worktree.ts`. |
| 2026-05-05 | initial | `peaceiris/actions-gh-pages` | `4b09552702d0b65573696410d4707c765da2630b` | `reports/2026-05-05-actions-gh-pages-symlink-leak.md` | Confirmed symlink-dereference leak via `shelljs.cp('-RfL', …)` in `copyAssets`; reachable in PR-preview / external-repo deploy patterns. Severity P3 (footgun). Two secondary observations: unvalidated `tag_name` shape; fixed `SSH_AUTH_SOCK=/tmp/ssh-auth.sock`. |

## Notes

- The control files `AGENTS.md`, `TARGET_POLICY.md`, and `REPORT_TEMPLATE.md`
  were **not present** in the `dev` branch checkout at any of the cycles
  recorded above. Each cycle therefore used the standard scout report
  sections (target, evidence, reachability, severity, recommendation,
  disclosure status). When those files appear in the control repo, future
  scouts should switch to the canonical template and re-read this memory
  for the avoid list.
- This memory file was assembled by unioning the two earlier scout-cycle
  snapshots (on remote branches `origin/cursor/security-scout-initial-e961`
  and `origin/cursor/security-scout-initial-gh-pages-action-bd3f`) with
  the current cycle, so no previously recorded entry was dropped.
- Future scout cycles should avoid all targets above unless an updated
  `TARGET_POLICY.md` authorizes a revisit (e.g. for re-auditing a fix
  landed by upstream).
