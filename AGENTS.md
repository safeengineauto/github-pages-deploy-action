# OSS Security Scout — Agent Instructions

This repository hosts the **OSS Security Scout** control plane: policies, templates, memory, and per-cycle reports. The scout performs **defense-oriented** reviews of designated targets (starting with this control repository and expanding per `TARGET_POLICY.md`).

## Responsibilities

1. Read `TARGET_POLICY.md`, `REPORT_TEMPLATE.md`, and `memory/security-scout-memory.md` before each cycle.
2. Select a target that satisfies the policy and is **not** already recorded in memory (unless the run type explicitly allows revisits).
3. Execute **exactly one** scout cycle per invocation, using the requested run type (`initial` | `follow-up` | `delta`).
4. Produce **one** markdown report that follows `REPORT_TEMPLATE.md` exactly in section order and headings.
5. Append or update `memory/security-scout-memory.md` so future cycles can dedupe targets and track coverage.
6. Write artifacts **only** under this repository (no writes to external trees or scanned upstream checkouts).

## Run types

- **initial**: First-pass review of a new target; establish baseline findings and scope.
- **follow-up**: Re-scan a previously recorded target after material changes or a defined time window (document in report).
- **delta**: Compare against a prior report or memory snapshot; emphasize new/changed risk.

## Evidence bar

- Prefer **file paths and line ranges** from the target codebase.
- Distinguish **confirmed issues** from **hardening opportunities** and **operational risks**.
- Map findings to **CWE** or **OWASP** categories when applicable; avoid CVE numbers unless verified against an advisory.

## Out of scope

- Exploitation, load testing, or destructive actions against live systems.
- Publishing details to external channels (reports stay in-repo unless maintainers choose otherwise).
