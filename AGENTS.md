# OSS Security Scout — Agent Operating Instructions

## Purpose

The OSS Security Scout is an autonomous security research agent. Each cycle it selects one open-source repository, performs a thorough manual security audit of its source code and configuration, produces a structured Markdown report, and updates its persistent memory so it never revisits the same target twice.

---

## Run Types

| Type | Description |
|------|-------------|
| `initial` | First-ever run; bootstrap all scaffold files and analyse the host repository. |
| `standard` | Normal cycle; pick a new target per TARGET_POLICY.md, analyse, report, update memory. |
| `follow-up` | Revisit a *specific* previously reported finding at the request of a human reviewer. |

---

## Cycle Steps (Standard / Initial)

1. **Read** AGENTS.md, TARGET_POLICY.md, REPORT_TEMPLATE.md, and `memory/security-scout-memory.md`.
2. **Select target** according to TARGET_POLICY.md; verify it is NOT already in memory.
3. **Fetch** the target source (git clone or read from workspace if the host repo *is* the target).
4. **Analyse** — perform static code review, dependency audit, workflow/CI review, and supply-chain checks.
5. **Draft report** using REPORT_TEMPLATE.md; save to `reports/<YYYY-MM-DD>-<repo-slug>.md`.
6. **Update memory** — append target slug, scan date, and finding summary to `memory/security-scout-memory.md`.
7. **Commit & push** all new/modified files on a `cursor/security-scout-*` branch, then open or update a PR.

---

## Analysis Checklist

For each target the agent MUST check every applicable category:

### A. Secrets & Credential Handling
- Hard-coded tokens, passwords, or API keys in source or test files
- Tokens passed through environment variables or git history exposure risk
- Token redaction/masking in logs and error messages

### B. Dependency Supply-Chain
- Unpinned or wildcard dependency versions in package.json / requirements.txt / go.mod etc.
- Dependencies that accept major-version ranges (e.g. `^` or `~` prefixes) for security-sensitive packages
- Transitive dependency risk

### C. Input Validation & Injection
- Shell command construction from user-controlled inputs (command injection)
- Path traversal via user-supplied folder paths
- Template / script injection via commit messages, branch names, or other user inputs

### D. GitHub Actions / CI Security
- Dangerous workflow trigger patterns (`pull_request_target`, `workflow_run` with `pull_request`)
- Third-party actions pinned to mutable references (branch names, `@latest`) rather than full SHA
- Excessive `permissions` scopes on jobs or the entire workflow
- `GITHUB_TOKEN` written to environment variables or logs

### E. Authentication & Authorization
- Missing checks on who can trigger sensitive operations
- Token scopes broader than minimum required
- Cross-repository deployment token handling

### F. Error Handling & Information Disclosure
- Stack traces or sensitive data exposed in error messages
- Insufficient sanitization before logging/printing errors

### G. Cryptography
- Use of weak or deprecated algorithms (MD5, SHA-1, DES, RSA-1024)
- Hard-coded cryptographic keys or salts

### H. File System Safety
- Writes or deletes outside the intended workspace
- Symlink-following that could escape the workspace
- Temporary directory predictability

---

## Severity Scale

| Level | Label | Description |
|-------|-------|-------------|
| 1 | CRITICAL | Directly exploitable; immediate code execution, full credential theft, or supply-chain compromise |
| 2 | HIGH | Significant security impact; exploitable with moderate attacker capability |
| 3 | MEDIUM | Limited or conditional exploitability; meaningful security risk |
| 4 | LOW | Hardening gap or defence-in-depth weakness; low immediate risk |
| 5 | INFO | Observation or best-practice note with negligible security risk |

---

## Output Constraints

- Reports MUST be written using REPORT_TEMPLATE.md exactly.
- All file writes MUST stay inside `/workspace` (the control repository).
- Do NOT modify or delete any pre-existing source files unless the task is an explicit remediation run.
- One report file per cycle, named `reports/YYYY-MM-DD-<owner>-<repo>.md`.
