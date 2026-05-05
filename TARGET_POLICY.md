# OSS Security Scout — Target Selection Policy

## Eligibility Criteria

A repository is eligible as a scan target if ALL of the following are true:

1. **Open source** — Source code is publicly available under an OSI-approved licence.
2. **Active** — At least one commit in the past 18 months.
3. **Meaningful attack surface** — The project handles secrets, tokens, file-system operations, network I/O, CI/CD pipelines, or cryptography.
4. **Not already in memory** — The repository slug (`owner/repo`) must not appear in `memory/security-scout-memory.md`.
5. **Not a mirror or fork** — Target should be the canonical upstream repository.

## Priority Tiers

| Tier | Description | Examples |
|------|-------------|---------|
| P0 | GitHub Actions used by millions of repos; compromise = supply-chain attack | `actions/checkout`, deployment actions, cache actions |
| P1 | Popular developer tools with direct CI/CD or secrets access | CLI tools, build systems, package managers |
| P2 | Widely-used libraries that process untrusted input | Parsers, serializers, HTTP clients |
| P3 | Supporting infrastructure tools | Static-site generators, scaffolding tools |

## Selection Algorithm

1. On an **initial** run, the host repository itself is always the first target (it is the most convenient and avoids network access).
2. On **standard** runs, prefer the highest-priority tier not yet covered in memory.
3. Within a tier, prefer repositories with the largest number of dependents (GitHub "Used by" count) or GitHub Actions Marketplace download rank.
4. Never select a repository whose owner has filed a responsible-disclosure request asking not to be scanned.

## Exclusion List

The following repository slugs are permanently excluded (e.g. due to scope or prior coordinated disclosure agreements):

*(empty — none excluded at this time)*

## Scope Boundaries

- Analysis is **read-only**: clone, read, analyse, report. Do not submit issues, PRs, or comments to the target repository.
- Do not exfiltrate credentials found during analysis; redact them in reports.
- Findings are for informational and educational purposes; the agent is not a penetration tester operating under a bug-bounty agreement.
