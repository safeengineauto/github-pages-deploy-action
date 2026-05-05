# OSS Security Scout — Memory

Avoid repeating the same primary targets in future cycles unless doing an explicit follow-up.

## Scoped targets (completed)

| Date (UTC) | Run type | Target identifier | Notes |
| --- | --- | --- | --- |
| 2026-05-05 | initial | `JamesIves/github-pages-deploy-action` (control workspace) | First cycle; report `reports/oss-security-scout-2026-05-05-initial.md` |

## Deferred / suggested (not yet scouted as primary)

- Full transitive dependency audit (`yarn.lock` + advisory DB).
- Remaining CI workflows under `.github/workflows/` (beyond `deploy.yml` spot-check).
