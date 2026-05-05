# OSS Security Scout Memory

This file tracks targets already covered by OSS Security Scout cycles so
future runs can avoid repeating them.

## Targets already covered

| Date | Run type | Target | Commit / reference | Report | Outcome |
| --- | --- | --- | --- | --- | --- |
| 2026-05-05 | cross-check | `release-drafter/release-drafter` | `0c28acd0bcb335f1f86b350a4283045eb03025b9` | `reports/2026-05-05-release-drafter-crosscheck.md` (visible on remote branch `origin/cursor/release-drafter-p1-crosscheck-de06`) | Confirmed hardening bug (path traversal in `getConfigFileFromFs`); severity narrowed from P1 to P3/low-info because no untrusted-input path crosses the trust boundary. |
| 2026-05-05 | initial | `JamesIves/github-pages-deploy-action` | `8072b9c7e8f9bd5cda32539dde262854f2073722` | `reports/2026-05-05-github-pages-deploy-action-initial.md` (visible on remote branch `origin/cursor/security-scout-initial-gh-pages-action-bd3f`) and `reports/2026-05-05-github-pages-deploy-action-argument-injection.md` (visible on remote branch `origin/cursor/security-scout-initial-e961`) | Argument injection through interpolated `git` / `rsync` / `chmod` command strings is reachable from workflow-author-controlled inputs; no untrusted-input crossing identified, so no confirmed reportable vulnerability. Hardening recommended. |
| 2026-05-05 | initial | `softprops/action-gh-release` | `2bc819c87a4e63a4ac4e581a02085318bd49975a` | `reports/2026-05-05-action-gh-release-initial.md` (this branch) | `body_path` → `readFileSync` and `files` → `glob.sync` accept absolute / `..` / `~` paths and read or upload arbitrary runner files into a public release. Reachable only from workflow-author-controlled inputs in idiomatic usage, so no confirmed reportable vulnerability. Hardening recommended (containment check vs. `working_directory`/`GITHUB_WORKSPACE`, README warning against plumbing untrusted event data into these inputs). |

## Avoid list (do not re-target without policy update)

- `release-drafter/release-drafter`
- `JamesIves/github-pages-deploy-action`
- `softprops/action-gh-release`

## Notes

- At the start of every 2026-05-05 cycle so far, `AGENTS.md`,
  `TARGET_POLICY.md`, `REPORT_TEMPLATE.md`, and this memory file have been
  absent from the checked-out `dev` tree of the control repository. Each
  cycle has bootstrapped the memory file on its own branch. This file is
  the third such bootstrap and aggregates all three known prior runs so
  the avoid list is preserved across branches even though the missing
  control files have not yet been merged into `dev`.
- Future scout cycles should:
  - Re-read this memory file from the most recent `cursor/security-scout-*`
    branch on `origin` if `dev` still lacks one.
  - Pick a target *not* in the avoid list above.
  - Continue using the report shape established in
    `reports/2026-05-05-release-drafter-crosscheck.md` and
    `reports/2026-05-05-github-pages-deploy-action-initial.md` until a
    real `REPORT_TEMPLATE.md` lands.
- Only files inside this control repository were written during the
  2026-05-05 `softprops/action-gh-release` cycle. The target repository was
  cloned read-only outside the workspace for inspection.
