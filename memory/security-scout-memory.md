# OSS Security Scout Memory

This file tracks targets already covered by OSS Security Scout cycles so future runs can avoid repeating them.

## Targets already covered

| Date | Run type | Target | Commit / reference | Report | Outcome |
| --- | --- | --- | --- | --- | --- |
| 2026-05-05 | cross-check | `release-drafter/release-drafter` | `0c28acd0bcb335f1f86b350a4283045eb03025b9` | `reports/2026-05-05-release-drafter-crosscheck.md` (visible on remote branch `origin/cursor/release-drafter-p1-crosscheck-de06`) | Confirmed hardening bug, severity narrowed to P3/low-info. |
| 2026-05-05 | initial | `JamesIves/github-pages-deploy-action` | `8072b9c7e8f9bd5cda32539dde262854f2073722` | `reports/2026-05-05-github-pages-deploy-action-initial.md` | No confirmed reportable vulnerability. |

## Notes

- At the start of the 2026-05-05 initial run, `AGENTS.md`, `TARGET_POLICY.md`, `REPORT_TEMPLATE.md`, and this memory file were absent from the checked-out `dev` tree. The prior `release-drafter/release-drafter` target was inferred from the existing remote scout report branch and included here to preserve the avoid list.
