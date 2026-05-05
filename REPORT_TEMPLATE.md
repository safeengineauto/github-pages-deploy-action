# Security Scout Report — `<owner>/<repo>`

| Field | Value |
|-------|-------|
| **Target** | `<owner>/<repo>` |
| **Repository URL** | https://github.com/<owner>/<repo> |
| **Scan Date** | YYYY-MM-DD |
| **Run Type** | initial / standard / follow-up |
| **Analyst** | OSS Security Scout (automated) |
| **Commit / Version Analysed** | `<git SHA or version tag>` |

---

## Executive Summary

*2–4 sentences describing what the project does, its threat model, and the overall security posture observed.*

---

## Findings

> Each finding follows this structure. Repeat the block for every finding. Remove this instruction line in the final report.

---

### Finding N — \<Short Title\>

| Attribute | Value |
|-----------|-------|
| **Severity** | CRITICAL / HIGH / MEDIUM / LOW / INFO |
| **Category** | (e.g. Secrets Handling, Command Injection, Supply-Chain, …) |
| **File(s)** | `path/to/file.ts` line(s) NN |
| **CWE** | CWE-NNNN — \<name\> (if applicable) |

#### Description

*Detailed explanation of the vulnerability or weakness: what it is, where it lives, and why it matters.*

#### Evidence

```
Paste the relevant code snippet or configuration excerpt here.
```

#### Attack Scenario

*Step-by-step description of how an attacker could exploit this finding. Be concrete.*

#### Recommended Fix

*Actionable remediation advice. Include example code where helpful.*

---

## Summary Table

| # | Title | Severity | Category | File |
|---|-------|----------|----------|------|
| 1 | Finding title | SEVERITY | Category | `file:line` |

---

## Methodology

*Brief description of analysis techniques used (static analysis, dependency audit, workflow review, etc.).*

---

## Out of Scope / Not Analysed

*Items intentionally not covered in this cycle (e.g. dynamic analysis, fuzzing, binary review).*

---

## References

- Link or citation 1
- Link or citation 2
