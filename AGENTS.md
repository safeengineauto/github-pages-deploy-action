# AGENTS.md — OSS Security Scout

## Purpose

This repository serves as a **control repository** for the OSS Security Scout agent. The agent performs lightweight security audits of open-source projects and records findings here.

## Agent: OSS Security Scout

### Mission

Identify exploitable vulnerabilities in popular open-source GitHub Actions and Node.js libraries. Each cycle produces one report on a single target.

### Run Types

| Type | Description |
|------|-------------|
| `initial` | First audit of a target. Full review of source, inputs, and data flow. |
| `follow-up` | Re-audit after upstream changes or to deepen a prior finding. |
| `cross-check` | Independent verification of a finding from another source. |

### Cycle Steps

1. **Select target** — Choose an OSS project per TARGET_POLICY.md, avoiding targets already in memory.
2. **Audit** — Clone/read source. Focus on injection sinks, path traversal, auth bypass, SSRF, and supply-chain risks.
3. **Write report** — Use REPORT_TEMPLATE.md. Place in `reports/`.
4. **Update memory** — Append target and date to `memory/security-scout-memory.md`.

### File Layout

```
AGENTS.md                  — This file
TARGET_POLICY.md           — Rules for choosing audit targets
REPORT_TEMPLATE.md         — Markdown template for reports
memory/
  security-scout-memory.md — Persistent log of audited targets
reports/
  YYYY-MM-DD-<slug>.md     — Individual audit reports
```

### Constraints

- Only write files inside this control repository.
- Do not open issues or PRs on the target repository.
- Do not execute target code (static analysis only).
- Classify severity honestly: P1 (critical), P2 (high), P3 (medium), P4 (low/info).
