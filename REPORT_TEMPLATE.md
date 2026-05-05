# OSS Security Scout — Report

## Metadata

| Field | Value |
| --- | --- |
| Run type | `initial` \| `follow-up` |
| Cycle date | YYYY-MM-DD (UTC) |
| Target | Repository or component identifier |
| Scope | What was reviewed (paths, workflows, release surface) |
| Protocol notes | Reference to AGENTS.md / TARGET_POLICY.md sections applied |

## Executive summary

2–4 sentences: overall risk posture, whether blocking issues exist, and recommended next steps.

## Target selection

- Why this target was chosen for this cycle.
- Alignment with TARGET_POLICY.md (eligibility, exclusions, depth).

## Methodology

- Static review steps performed.
- Tools or heuristics used (if any).
- Limits of the review (what was out of scope).

## Findings

For each finding, use one subsection:

### [SEVERITY] Short title

- **Category:** (e.g. secret handling, injection, supply chain, permissions)
- **Location:** file path and symbol or workflow job/step
- **Description:** what is wrong or fragile
- **Prerequisites:** who can trigger / what configuration is required
- **Recommendation:** concrete mitigation or verification step
- **Status:** new / acknowledged / tracked externally

## Positive observations

Security-relevant defenses or good practices worth preserving.

## Recommended targets for next cycle

Candidates that fit TARGET_POLICY.md and are not already listed in `memory/security-scout-memory.md`.

## Appendix

Optional: references, snippets, or command transcripts (avoid secrets).
