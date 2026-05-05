# OSS Security Scout Report Template

Copy this structure into `reports/<slug>.md` and replace every `{{placeholder}}`.

## Report metadata

| Field | Value |
| ----- | ----- |
| **Run type** | {{initial \| delta}} |
| **Target** | {{name and primary URL}} |
| **Scope** | {{what was reviewed}} |
| **Out of scope** | {{explicit exclusions}} |
| **Cycle date** | {{ISO-8601 date}} |
| **Analyst** | {{tool or human identifier}} |
| **Commit / version** | {{git SHA, tag, or release}} |

## Executive summary

{{2–4 sentences: overall risk posture and top themes}}

## Methodology

{{How the cycle was performed: static review areas, files, dependency lists, threat model assumptions}}

## Supply chain and dependencies

{{Key direct dependencies, pinning strategy, update surface, notable transitive concerns}}

## Trust boundaries and assumptions

{{Who is trusted: maintainers, workflow authors, GitHub, npm registry, etc.}}

## Findings

For each finding, use:

### {{Finding ID}} — {{Short title}}

| Attribute | Value |
| --------- | ----- |
| **Severity** | {{Critical \| High \| Medium \| Low \| Informational}} |
| **Category** | {{e.g. injection, secret handling, authz, denial of service}} |
| **Location** | {{file path or workflow}} |
| **Description** | {{what is wrong}} |
| **Prerequisites** | {{who can trigger / what access is needed}} |
| **Recommendation** | {{concrete fix or mitigation}} |

*(Add or remove finding subsections as needed.)*

## Positive observations

{{Security-positive patterns worth preserving}}

## Recommendations summary

{{Prioritized list of next actions}}

## Appendix

### Files and areas reviewed

{{Bullet list}}

### References

{{Links to docs, advisories, or standards cited}}
