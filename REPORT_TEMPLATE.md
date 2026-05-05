# Security Scout Report — {{TARGET}}

- **Target repo:** `{{OWNER}}/{{REPO}}`
- **Version / commit audited:** `{{COMMIT_OR_VERSION}}`
- **Date:** {{DATE}}
- **Run type:** {{RUN_TYPE}}
- **Scout:** OSS Security Scout (automated)

---

## 1. Target Overview

{{Brief description of what the project does, its popularity metrics, and why it was selected.}}

## 2. Audit Scope

{{What was examined: source files, CI config, dependency tree, published advisories, etc.}}

## 3. Findings

### 3.1 {{Finding title}}

- **Severity:** {{P1 | P2 | P3 | P4 | Info}}
- **Category:** {{command-injection | path-traversal | secret-exposure | dependency-vuln | ci-misconfiguration | other}}
- **File(s):** `{{path/to/file}}`
- **Evidence:**

{{Code snippets, reproduction steps, or reasoning that supports the finding.}}

- **Exploitability:**

{{Who can trigger this? What trust boundary is crossed? What is the realistic impact?}}

- **Suggested fix:**

{{Concrete remediation sketch or reference to an upstream fix.}}

---

*(Repeat §3.x for each finding. If no findings, state "No actionable findings identified." and explain what was checked.)*

## 4. Dependency Snapshot

| Package | Version | Known CVEs | Notes |
|---------|---------|------------|-------|
| {{pkg}} | {{ver}} | {{cve}}    | {{notes}} |

## 5. Summary & Recommendations

{{One-paragraph overall assessment. List any recommended follow-up actions.}}

## 6. Limitations

{{What was NOT examined and why (e.g., no runtime testing, no fuzzing, limited to static analysis of public source).}}
