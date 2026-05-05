# TARGET_POLICY.md — Target Selection Rules

## Eligible Targets

1. **GitHub Actions** — Popular actions (>1 000 stars) that handle tokens, deployments, or user-supplied inputs.
2. **Node.js libraries** — Widely depended-upon packages where a vulnerability has high blast radius.
3. **CI/CD tooling** — Build tools, deployment scripts, and workflow utilities.

## Selection Criteria

- Must be open-source with a public repository on GitHub.
- Prefer projects with recent activity (commit in last 12 months).
- Prefer projects where input handling is non-trivial (file paths, branch names, commit messages, etc.).
- Avoid targets already listed in `memory/security-scout-memory.md`.

## Exclusions

- Projects with active, well-funded security teams and formal bug-bounty programs (e.g., actions/checkout itself is out of scope unless a specific lead exists).
- Archived or unmaintained repositories (no commits in 24+ months).
- Targets already audited in a prior cycle (check memory).

## Priority Signals

- User-controlled inputs that flow into shell commands (`exec`, `execSync`, template strings in commands).
- Path manipulation without normalization or containment checks.
- Token/secret handling that may leak into logs or error messages.
- Missing input validation on action inputs (action.yml inputs used raw).
