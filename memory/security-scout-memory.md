# OSS Security Scout — durable memory

This file is the canonical list of targets the OSS Security Scout has touched.
For `initial` runs the agent **must** avoid every entry below (regardless of
status). `followup` and `crosscheck` runs may revisit.

## Schema

Each entry:

```
### <YYYY-MM-DD> — <owner>/<repo>
- **Run type:** initial | crosscheck | followup
- **Audited SHA:** <full SHA or "n/a (referenced only)">
- **Report:** reports/<file>.md (or "n/a" if not stored here)
- **Top finding:** <one line> (severity)
- **Status:** open | fix-suggested | confirmed-noissue | deferred
- **Notes:** <one or two lines, optional>
```

Append new entries to the bottom. Do not rewrite history; if a target needs
revisiting, add a new entry with `Run type: followup`.

---

## Targets

### 2026-05-05 — release-drafter/release-drafter
- **Run type:** crosscheck
- **Audited SHA:** 0c28acd0bcb335f1f86b350a4283045eb03025b9
- **Report:** n/a (cross-check report lives on a separate branch
  `cursor/release-drafter-p1-crosscheck-de06`,
  `reports/2026-05-05-release-drafter-crosscheck.md`)
- **Top finding:** workspace-escape via `normalizeFilepath` →
  `getConfigFileFromFs` (P3, narrowed from a P1 candidate)
- **Status:** fix-suggested
- **Notes:** Original `initial` report (`reports/2026-05-05-release-drafter.md`)
  is referenced in the cross-check but not stored on this branch. Treat the
  target as already covered for `initial` runs.

### 2026-05-05 — webfactory/ssh-agent
- **Run type:** initial
- **Audited SHA:** e83874834305fe9a4a2997156cb26c5de65a8555 (tag `v0.10.0`)
- **Report:** reports/2026-05-05-webfactory-ssh-agent.md
- **Top finding:** `git-cmd` input is interpolated into `child_process.execSync`
  in `index.js:63-65` (P3 defense-in-depth; no trust boundary crossed in
  realistic usage). Two Info notes on `ssh-auth-sock` and the public-key
  comment regex.
- **Status:** fix-suggested
- **Notes:** Selected as an `initial` target because it is a direct
  dependency of this control repo's host project
  (`JamesIves/github-pages-deploy-action` integration workflow) and ships
  ≈85 LOC of first-party JS — fully reviewable in one cycle. `dist/` was
  not reviewed; future `followup` should diff `dist/index.js` against a
  from-source rebuild.
