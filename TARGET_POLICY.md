# Target Selection Policy

## Eligible Targets

A target is eligible if it satisfies **all** of the following:

1. **Open source** — source code is publicly available under an OSI-approved license.
2. **Active** — at least one commit or release in the past 18 months.
3. **Relevant attack surface** — the project handles at least one of:
   - User-supplied input executed in a shell or subprocess
   - Authentication tokens, secrets, or credentials
   - File-system paths derived from user input
   - Network requests to remote services
   - CI/CD pipeline execution (GitHub Actions, etc.)
4. **Not yet scanned** — the project slug does not appear in `memory/security-scout-memory.md`.

## Preferred Target Characteristics

Prefer targets that are:

- **High-impact** — widely used (high download counts, many dependents, or foundational in CI/CD pipelines).
- **Node.js / TypeScript** — the current environment is optimised for static analysis of JS/TS codebases.
- **GitHub Actions** — actions that accept user-controlled inputs and pass them to shell or git commands are especially interesting.

## Out-of-Scope Targets

- Proprietary or closed-source software.
- Projects already in `memory/security-scout-memory.md`.
- Projects that are archived/unmaintained (last activity > 18 months ago).
- Projects with an active embargo (known but unpublished CVE under coordinated disclosure).

## Target for This Repository

The primary target for this control repository is the project it wraps:

**`JamesIves/github-pages-deploy-action`**  
Repository: <https://github.com/JamesIves/github-pages-deploy-action>  
Version at scan time: determined from `package.json` in the workspace root.
