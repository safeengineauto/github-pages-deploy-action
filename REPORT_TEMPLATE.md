# OSS Security Scout — Report Template

Use this structure for each scout cycle. Replace placeholder text; remove instructional lines before publishing if desired.

## Metadata

- **Run type:** `initial` | `follow-up`
- **Date (UTC):** YYYY-MM-DD
- **Control repository:** (name / path)
- **Scout scope:** (e.g. first-party code paths, named OSS dependency, CI config)

## Target

- **Target name / version:** 
- **Source:** (e.g. path in repo, lockfile coordinate, URL)
- **Why this target:** (one sentence)

## Executive summary

2–5 sentences: overall risk posture, whether blockers exist, and top themes (e.g. shell usage, secrets, supply chain).

## Scope and limits

- What was reviewed (files, packages, workflows).
- What was out of scope or could not be verified (e.g. no `yarn audit` in environment).
- Assumptions and trust boundaries (e.g. GitHub Actions workflow inputs).

## Findings

For each finding, use a consistent ID (e.g. F-001). Order by severity.

| ID | Severity | Category | Title | Status |
|----|----------|----------|-------|--------|
| F-001 | Critical / High / Medium / Low / Informational | e.g. injection, secrets, auth | Short title | Open / Accepted risk / Fixed |

### F-001 — Title

- **Description:** What is wrong and where (paths, functions).
- **Impact:** Who can abuse it and what they gain.
- **Likelihood:** Preconditions (attacker control, config mistakes).
- **Evidence:** Code references or config snippets (redact secrets).
- **Remediation:** Concrete fix or mitigation.
- **References:** CVE/GHSA/advisory links if applicable.

## Recommendations (prioritized)

1. …
2. …

## Memory / follow-ups

- Targets or areas to **avoid** duplicating next cycle (see `memory/security-scout-memory.md`).
- Suggested next targets or verification steps.
