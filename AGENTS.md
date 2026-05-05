# Security Scout Agent Instructions

This repository is being used as an OSS Security Scout control repository.

## Operating Rules
- Run exactly one scout cycle per request unless told otherwise.
- Honor run types (for example: initial).
- Avoid scanning targets already listed in `memory/security-scout-memory.md`.
- Keep all outputs inside this repository.

## Required Artifacts
- `REPORT_TEMPLATE.md` defines report structure.
- `memory/security-scout-memory.md` tracks scanned targets and findings.
- `reports/` stores generated cycle reports.
