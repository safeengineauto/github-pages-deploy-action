# Security Scout Report

<!-- Copy this template to reports/<YYYY-MM-DD>-<slug>.md and fill in each section. -->

## Metadata

| Field | Value |
|---|---|
| **Target** | `<owner/repo>` |
| **Version / Commit** | `<version or commit SHA>` |
| **Scan date** | `<YYYY-MM-DD>` |
| **Run type** | `initial` / `followup` / `advisory` |
| **Analyst** | OSS Security Scout (automated) |

---

## Executive Summary

<!-- 3–5 sentences. What is the project, why is it interesting from a security standpoint,
     and what is the headline finding (or "no critical findings")? -->

---

## Scope

<!-- What was examined? e.g. "Full source tree at HEAD, package.json + yarn.lock, public advisories." -->

---

## Findings

### Finding 1 — \<Short title\>

| Field | Value |
|---|---|
| **Severity** | Critical / High / Medium / Low / Informational |
| **CWE** | CWE-\<number\>: \<name\> |
| **CVE** | CVE-XXXX-XXXXX (if applicable) |
| **File / Line** | `src/foo.ts:42` |
| **Status** | Open / Fixed in \<version\> / Won't Fix |

**Description**

<!-- Explain what the vulnerability is and why it is exploitable. -->

**Evidence**

```
<!-- Paste the relevant code snippet or log output. -->
```

**Impact**

<!-- What can an attacker achieve? Describe the worst-case scenario. -->

**Recommendation**

<!-- Concrete mitigation: code change, configuration change, version upgrade, etc. -->

---

<!-- Repeat the Finding block for each additional finding. -->

---

## Dependency Audit

| Package | Current version | Vulnerable versions | CVE | Severity | Fix version |
|---|---|---|---|---|---|
| `example-pkg` | `1.2.3` | `< 1.2.4` | CVE-XXXX-XXXXX | High | `1.2.4` |

*If no vulnerable dependencies were found, write: "No vulnerable dependencies identified."*

---

## Positive Observations

<!-- Note any security controls that are working well (secret masking, sandboxing, input validation, etc.). -->

---

## References

<!-- Links to CVE entries, advisories, relevant code, documentation. -->
