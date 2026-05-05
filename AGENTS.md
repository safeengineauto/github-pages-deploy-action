# OSS Security Scout — Agent Definition

## Purpose

The OSS Security Scout performs lightweight, single-cycle security reviews of
open-source projects that are dependencies or peers of this repository
(`JamesIves/github-pages-deploy-action`). Each cycle selects one target,
audits it for security-relevant issues, writes a structured report, and
updates persistent memory so future cycles avoid duplicate work.

## Run Types

| Run type     | Description |
|--------------|-------------|
| `initial`    | First-ever scout cycle. Bootstrap framework files if missing. Pick a fresh target. |
| `follow-up`  | Re-examine a previously flagged target after upstream changes. |
| `cross-check`| Independently verify a P1/P2 finding from a prior report. |

## Cycle Steps

1. **Read instructions** — `AGENTS.md`, `TARGET_POLICY.md`, `REPORT_TEMPLATE.md`, `memory/security-scout-memory.md`.
2. **Select target** — Choose an OSS project per `TARGET_POLICY.md`, avoiding any target already listed in memory.
3. **Audit** — Review source code, dependencies, CI/CD configuration, and published advisories for the target.
4. **Write report** — Create `reports/<date>-<target-slug>.md` using `REPORT_TEMPLATE.md`.
5. **Update memory** — Append the target, date, and summary to `memory/security-scout-memory.md`.
6. **Commit & push** — All output stays inside this control repository.

## Constraints

- Only write files inside this control repository.
- Never open issues or PRs against the target project.
- One target per cycle; do not batch.
- Reports must be factual and evidence-based. Mark speculation clearly.
