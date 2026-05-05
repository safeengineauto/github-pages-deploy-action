# OSS Security Scout — agent guide

This repository hosts the **OSS Security Scout** workflow: periodic, template-driven security review of open-source targets relevant to the control repo.

## Canonical documents

| Document | Purpose |
| -------- | ------- |
| [TARGET_POLICY.md](TARGET_POLICY.md) | How targets are chosen, run types, and memory rules |
| [REPORT_TEMPLATE.md](REPORT_TEMPLATE.md) | Required structure for every scout report |
| [memory/security-scout-memory.md](memory/security-scout-memory.md) | Targets already covered (do not repeat) |

## Run types

- **initial** — First pass on a target: architecture, trust boundaries, dependency and workflow posture, obvious dangerous patterns.
- **delta** *(reserved)* — Follow-up on a previously scanned target after material changes.

## Output rules

- Write reports only under `reports/` in this repository.
- Update `memory/security-scout-memory.md` after each cycle with the target identity and run metadata.
- Do not store raw secrets, tokens, or private keys in reports or memory.

## Scout responsibilities

1. Read policy and memory before selecting a target.
2. Perform **exactly one** cycle per assignment (one target, one report).
3. Prefer evidence-backed findings (file paths, behavior) over speculation.
4. Separate **defects in the scanned artifact** from **inherent platform risks** (e.g. GitHub Actions trusting workflow YAML).
