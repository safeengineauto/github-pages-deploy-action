# REPORT_TEMPLATE.md

Use this template for all security scout reports. Copy it to `reports/YYYY-MM-DD-<slug>.md` and fill in each section.

---

```markdown
# Security Report — <target_name>

| Field | Value |
|-------|-------|
| **Target** | `<owner>/<repo>` |
| **Commit audited** | `<sha>` |
| **Date** | YYYY-MM-DD |
| **Run type** | initial / follow-up / cross-check |
| **Severity** | P1 / P2 / P3 / P4 |
| **Status** | confirmed / probable / false-positive / informational |

## Summary

One-paragraph description of the finding.

## Vulnerability Details

### Attack Surface

Describe the entry points and how attacker-controlled data reaches the vulnerable code.

### Root Cause

Explain the underlying flaw (e.g., unsanitized interpolation into shell command).

### Proof of Concept

Show a minimal reproducer or describe the exploitation steps.

### Impact

What can an attacker achieve? (RCE, secret exfiltration, repository compromise, etc.)

## Affected Code

Reference specific files and line numbers. Use code blocks.

## Suggested Fix

Describe or sketch the remediation.

## Notes

Any caveats, mitigating factors, or areas for follow-up.
```
