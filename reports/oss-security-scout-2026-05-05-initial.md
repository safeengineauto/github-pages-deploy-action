# OSS Security Scout Report

## Run metadata

| Field | Value |
| ----- | ----- |
| **Run type** | initial |
| **Date (UTC)** | 2026-05-05 |
| **Target** | https://github.com/JamesIves/github-pages-deploy-action (control repository / workspace `dev`) |
| **Analyst** | OSS Security Scout (static review) |
| **Scope** | TypeScript sources under `src/`, root `action.yml`, `SECURITY.md`; dependency audit not executed (Node.js tooling unavailable in review environment) |
| **Out of scope** | Live workflow execution, GitHub-hosted runtime secrets, third-party repository clones, penetration testing |

## Executive summary

This **initial** cycle reviewed the GitHub Pages deploy action as the sole in-scope target. The codebase follows sensible patterns for masking tokens in error paths and excludes sensitive directories from rsync deployments. The highest-risk area is **shell command construction**: several workflow-controlled strings are interpolated into commands passed to `@actions/exec` without escaping, which can become **argument or command injection** (CWE-78) when those inputs are fed from workflow expressions that include partially untrusted data (for example commit messages or tags copied from repository events). No remote code execution was demonstrated; findings below are static and assume a threat model where an actor can influence action inputs without already owning the repository at the same privilege level as the token used for push. Operational note: enabling GitHub Actions step debug disables redaction of secrets in `suppressSensitiveInformation`, which is expected but worth documenting for incident responders.

## Methodology

- Manual read of `src/lib.ts`, `src/git.ts`, `src/execute.ts`, `src/util.ts`, `src/ssh.ts`, `src/constants.ts`, and `action.yml`.
- Grep for token handling, subprocess use, and user-controlled inputs.
- **Dependency audit**: `npm audit` / `yarn npm audit` was **not** run because the Node.js runtime was not available in the execution environment; supply-chain posture is therefore **not** fully validated this cycle.

## Findings

### Finding 1 — Potential shell injection via `commit-message` and other interpolated inputs

- **Severity**: Medium
- **Location**: `src/git.ts` (e.g. commit at lines 244–257); `src/git.ts` (git config in `init`, lines 40–50); `src/git.ts` (`cleanExclude` / `rsync`, lines 156–202); `src/git.ts` (`git tag`, lines 335–346)
- **Description**: The `execute` helper passes full command strings to `@actions/exec`. Values such as `commitMessage`, `action.name`, `action.email`, `cleanExclude` entries, and `action.tag` are embedded in double-quoted shell segments (for example `git commit -m "${commitMessage}"`). A value containing double quotes, backticks, command substitutions, or newlines can break out of the intended argument and alter the interpreted command when the workflow author binds these inputs to event-derived strings.
- **Preconditions / attacker model**: Requires a workflow that supplies attacker-influenced content to `with: commit-message`, `git-config-name`, `git-config-email`, `clean-exclude`, or `tag` (for example echoing `github.event.head_commit.message` or similar). The practical impact depends on the token permissions available to that job.
- **Recommendation**: Avoid interpolating raw user/workflow strings into shell one-liners. Prefer `exec` with argument arrays (if supported by the toolkit), or validate/sanitize inputs (strict allowlist for `tag`, newline rejection, escape for POSIX shells), or use dedicated APIs (for example `git commit` via libgit2 or minimal argv-split invocations) so metacharacters cannot change command boundaries.

### Finding 2 — `clean-exclude` values passed unquoted into `rsync`

- **Severity**: Low
- **Location**: `src/git.ts` lines 156–160, 172–199
- **Description**: Each `cleanExclude` line becomes `--exclude ${item}` in a larger shell command without quoting. Spaces or rsync-specific tokens inside `item` may parse unexpectedly or broaden exclusion semantics.
- **Preconditions / attacker model**: Workflow author supplies multiline `clean-exclude`; accidental misconfiguration is the primary risk; malicious use requires ability to set workflow inputs.
- **Recommendation**: Quote each exclude pattern for the shell (`--exclude '${escaped}'`) and reject patterns containing `'` or other disallowed characters if feasible.

### Finding 3 — SSH client enables legacy `ssh-dss` host key material

- **Severity**: Low (Informational for GitHub.com; higher if operators assume modern-only crypto on all hosts)
- **Location**: `src/ssh.ts` lines 17–19, 25–26
- **Description**: Known-host entries include `ssh-dss`, which is deprecated and disabled by default in modern OpenSSH clients. This may cause compatibility friction or encourage weaker trust material on hardened runners.
- **Preconditions / attacker model**: Hostile network position benefits are limited while RSA/ed25519 pins exist; mainly a **configuration hygiene** concern.
- **Recommendation**: Align with current GitHub SSH host key guidance (Ed25519 where available); drop DSS once minimum client versions are acceptable for your support matrix.

### Finding 4 — Debug mode surfaces redacted material in error helper

- **Severity**: Informational
- **Location**: `src/util.ts` lines 107–116
- **Description**: `suppressSensitiveInformation` returns unmodified strings when `isDebug()` is true, which is appropriate for debugging but increases leak risk if `ACTIONS_STEP_DEBUG` is left on in shared runners or exported logs.
- **Preconditions / attacker model**: Maintainer enables debug on a workflow that surfaces git errors containing URLs or paths that still embed credentials.
- **Recommendation**: Document in operator runbooks that debug runs may log sensitive material; consider scoping redaction relaxations more narrowly if GitHub Actions adds finer-grained controls in the future.

## Dependency and supply chain notes

- Production dependencies are pinned in `package.json` with exact versions for core `@actions/*` packages; full **lockfile advisory** review was **not** performed (no `npm audit` this cycle). A follow-up cycle should run `yarn install` / `npm ci` and `npm audit` or OSV-Scanner in CI.

## Positive observations

- Deployment staging uses `rsync` with explicit `--exclude` for `.ssh`, `.git`, and `.github`, reducing accidental publication of VCS metadata and SSH material (`src/git.ts` around lines 193–198).
- Errors passed through `suppressSensitiveInformation` reduce accidental token leakage in normal (non-debug) runs (`src/util.ts`).
- `action.yml` defaults `token` to `${{ github.token }}` and documents least-privilege PAT guidance.

## Recommended next steps

1. Refactor high-risk `execute(\`...\`)` call sites to structured invocation or strict input validation, starting with `commit-message` and `tag`.
2. Run an automated dependency audit on `yarn.lock` in a follow-up scout cycle or in CI (SARIF upload optional).
3. Review `.github/workflows` in a subsequent cycle for `permissions:` minimization and pinned third-party action versions.

## Appendix

### Files reviewed

- `src/lib.ts`
- `src/git.ts`
- `src/execute.ts`
- `src/util.ts`
- `src/ssh.ts`
- `src/constants.ts`
- `action.yml`
- `SECURITY.md`

### References

- [CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')](https://cwe.mitre.org/data/definitions/78.html)
- [GitHub Actions: Workflow syntax — `ACTIONS_STEP_DEBUG`](https://docs.github.com/en/actions/monitoring-and-troubleshooting-workflows/enabling-debug-logging)
