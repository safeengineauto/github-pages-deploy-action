# OSS Security Scout — Report

## Metadata

| Field | Value |
| --- | --- |
| Run type | `initial` |
| Cycle date | 2026-05-05 (UTC) |
| Target | **Control repository:** `JamesIves/github-pages-deploy-action` (GitHub Pages Deploy Action — workspace at `/workspace`, TypeScript action `lib/main.js`, Node 24) |
| Scope | `src/**/*.ts`, `action.yml`, representative workflow `.github/workflows/deploy.yml`; dependency declarations in `package.json` (not full transitive audit) |
| Protocol notes | Requested reads of `AGENTS.md`, `TARGET_POLICY.md`, `REPORT_TEMPLATE.md`, and `memory/security-scout-memory.md` were attempted; **only `REPORT_TEMPLATE.md` exists in-repo after this change** — this cycle applied common OSS security-review practice and the structure defined in `REPORT_TEMPLATE.md`. |

## Executive summary

This action runs with repository credentials (default `github.token` or user-supplied PAT) and pushes content to a configurable branch, so **workflow trust** and **input handling into shell commands** are the main concerns. Several user-controlled strings are interpolated into `git` and `rsync` invocations built as single command strings passed to `@actions/exec`, which typically executes through a shell on Linux runners—**command injection is plausible if a workflow feeds untrusted or attacker-controlled inputs** into `commit-message`, `clean-exclude`, `tag`, `branch`, `target-folder`, or related fields without validation. No separate remote dependency execution surface was identified in the reviewed TypeScript beyond GitHub-hosted Actions dependencies. **Next steps:** validate or parameterize shell commands (argument arrays), document which inputs must be trusted, and consider follow-up on tag-push using `origin` vs the same authenticated remote URL pattern.

## Target selection

- **Initial cycle:** the only codebase present in this control workspace is the deploy action itself; it is a high-impact GitHub Action (writes to git remotes, handles tokens and optional SSH keys).
- **TARGET_POLICY:** file not present in repository; selection defaulted to **this repo** as the scoped target for the initial run.

## Methodology

- Manual read-through of action inputs (`action.yml`), configuration assembly (`constants.ts`, `util.ts`), deployment and git operations (`git.ts`, `worktree.ts`), SSH setup (`ssh.ts`), and the action entrypoint (`lib.ts`).
- Grep for `execute(`, `execSync`, and `execFileSync` to locate shell boundaries.
- **Out of scope:** full `yarn.lock` transitive vulnerability database scan, GitHub-hosted runner hardening, consumer workflow audits outside this repo, and dynamic/fuzz testing.

## Findings

### [High] Shell command construction from workflow inputs

- **Category:** command injection / unsafe shell invocation
- **Location:** `src/git.ts` (`deploy`, `init`); `src/worktree.ts` (`generateWorktree`); `@actions/exec` usage in `src/execute.ts`
- **Description:** `execute(cmd, …)` passes a **single string** as the command to `@actions/exec` with an empty argument array. On Linux, this commonly runs under `/bin/sh -c`. Values such as `commitMessage` (embedded in `git commit -m "…"`), `cleanExclude` lines (concatenated into `rsync … --exclude ${item}`), `temporaryDeploymentBranch` (from random alphanumeric but branch name patterns matter for git), `action.branch`, `action.targetFolder`, and `action.tag` are interpolated into these strings. A malicious or compromised workflow (or a workflow that concatenates untrusted data into these inputs) could break out of quoting or inject additional commands.
- **Prerequisites:** Ability to set action inputs in a workflow that runs this action (normally repo maintainers; supply-chain compromise of workflow YAML escalates impact).
- **Recommendation:** Prefer `exec`/`execFile` style APIs with **argv arrays** and no shell for `git`/`rsync`, or use `@actions/exec` with `commandLine`/`arguments` patterns that avoid shell interpretation; strictly validate inputs (e.g. allowlist branch/tag/folder names, escape or reject characters meaningful to sh).
- **Status:** new

### [Medium] Error paths may leak credentials when Actions debug logging is enabled

- **Category:** secret handling / observability
- **Location:** `src/util.ts` — `suppressSensitiveInformation`
- **Description:** When `@actions/core` debug mode is active (`isDebug()` true), suppression is **skipped** and error strings may contain the full `repositoryPath` (including embedded token for HTTPS remotes).
- **Prerequisites:** Maintainer enables debug logging on a workflow run that fails in a way that surfaces repository path in errors.
- **Recommendation:** Document clearly; consider always redacting token substrings even in debug, or redacting with an explicit opt-in to full verbosity.
- **Status:** new

### [Medium] Tag push uses `origin` remote while deploy uses constructed remote URL

- **Category:** consistency / authentication edge case
- **Location:** `src/git.ts` — `git push origin ${action.tag}` vs earlier `git push … ${action.repositoryPath}`
- **Description:** Deployment pushes use `action.repositoryPath` (HTTPS with token or SSH form). Tag push uses **`origin`**, which was re-added to point at `repositoryPath` in `init`, so behavior is likely consistent; if a future refactor changed `origin`, tags could push to an unexpected remote or fail opaquely.
- **Recommendation:** Use the same remote specifier for all pushes (e.g. always `origin` after `git remote add origin`, or always `repositoryPath`) to reduce mismatch risk.
- **Status:** new (defensive / maintainability)

### [Low] SSH host key material uses legacy RSA/DSS GitHub entries

- **Category:** cryptographic hygiene / TOFU
- **Location:** `src/ssh.ts` — `sshGitHubKnownHostRsa`, `sshGitHubKnownHostDss`
- **Description:** Known-hosts bootstrapping follows GitHub’s published fingerprints; algorithm set may be narrower than modern best practice (e.g. Ed25519-first deployments). DSS is deprecated in many OpenSSH configurations.
- **Prerequisites:** SSH-based deploy path in use.
- **Recommendation:** Align with current GitHub documentation for host keys and prefer modern algorithms where supported.
- **Status:** new

## Positive observations

- **Redaction helper:** `suppressSensitiveInformation` attempts to strip `token` and `repositoryPath` from surfaced errors under normal (non-debug) operation.
- **Rsync excludes:** `.ssh`, `.git`, and `.github` are excluded from deployment copies by default, reducing accidental publication of VCS metadata.
- **Documentation:** `action.yml` and README stress storing PATs/SSH keys as GitHub secrets and least-privilege PATs.

## Recommended targets for next cycle

- **Upstream ecosystem:** `@actions/core`, `@actions/exec`, `@actions/github`, `@actions/io` (version pinning policy and Dependabot noise vs security updates).
- **Workflow set:** other `.github/workflows/*.yml` not deeply reviewed in this cycle (build, integration, production, sponsors).
- **Integration fixture:** `integration/` static site used in docs or tests — lower risk but confirms no accidental secret patterns.

## Appendix

- Protocol files `AGENTS.md` and `TARGET_POLICY.md` were **not** in the workspace at cycle start; this report follows `REPORT_TEMPLATE.md` as added/filled in the same change set.
