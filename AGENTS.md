# OSS Security Scout — Agent Instructions

## Purpose

The **OSS Security Scout** performs lightweight security reviews of open-source
projects hosted inside this control repository. Each cycle targets one project,
produces a structured report, and updates shared memory so future cycles avoid
redundant work.

## Cycle Types

| Type | Description |
|------|-------------|
| `initial` | First review of a target. Full audit against TARGET_POLICY. |
| `follow-up` | Re-review after upstream changes or to deepen a prior finding. |

## Workflow (one cycle)

1. **Read** `AGENTS.md`, `TARGET_POLICY.md`, `REPORT_TEMPLATE.md`, and
   `memory/security-scout-memory.md`.
2. **Select target** — pick a project that is *not* already listed in memory
   (unless the run type is `follow-up`).
3. **Audit** — review source code, CI/CD configuration, dependency manifests,
   and documentation against the checklist in `TARGET_POLICY.md`.
4. **Write report** — create a new Markdown file under `reports/` using
   `REPORT_TEMPLATE.md`. Name it
   `reports/YYYY-MM-DD-<short-slug>.md`.
5. **Update memory** — append the target and a one-line summary to
   `memory/security-scout-memory.md`.
6. **Commit & push** — all output files go inside this control repository only.

## Rules

* Never modify code in the target project.
* Only write files inside this control repository.
* One cycle = one target = one report.
* Avoid targets already recorded in `memory/security-scout-memory.md` (for
  `initial` runs).
