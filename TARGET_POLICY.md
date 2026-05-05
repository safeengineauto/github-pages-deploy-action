# OSS Security Scout — target policy

## Eligible targets

- **Primary**: Open-source software that this control repository ships, vendors, or documents as a first-class dependency (including the repository itself when it is the product under review).
- **Secondary** *(optional future)*: Upstream libraries explicitly named as critical in maintenance docs, scoped to one org/repo per cycle.

## Exclusions

- Targets already listed in [memory/security-scout-memory.md](memory/security-scout-memory.md) for the same **run type** and major **scope** (e.g. same repository + same high-level component), unless `TARGET_POLICY.md` is amended to allow a re-scan.
- Private or non-public codebases (no URL, no clone access).

## Run type: `initial`

Must include:

1. **Scope statement** — What was reviewed (paths, workflows, packages) and what was out of scope.
2. **Supply chain** — Package manager manifests, pinned vs floating versions, and notable transitive risk surface.
3. **Trust boundaries** — Where secrets and tokens flow; what an attacker who can edit workflow YAML or open a PR can do.
4. **Findings** — Ranked issues and positive controls.

## Target selection (single cycle)

1. Read memory; discard candidates that are “already listed” for the intended run.
2. Prefer the **smallest coherent unit** (one repo or one monorepo component) that fits the assignment.
3. Record the chosen target in memory after the report is written.

## Severity rubric (informative)

| Level | Meaning |
| ----- | ------- |
| Critical | Immediate likely compromise of repo, secrets, or production users |
| High | Exploitable with common CI/repo assumptions |
| Medium | Meaningful hardening gap or defense-in-depth miss |
| Low | Theoretical, niche, or cosmetic security issues |
| Informational | No vulnerability; note for auditors or future work |
