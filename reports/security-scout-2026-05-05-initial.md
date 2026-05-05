# OSS Security Scout — Report

## Metadata

- **Run type:** initial
- **Date (UTC):** 2026-05-05
- **Control repository:** `JamesIves/github-pages-deploy-action` (workspace `/workspace`)
- **Scout scope:** First-party TypeScript action sources (`src/`), `action.yml`, and declared runtime dependency `@actions/github@9.0.0` (from `package.json`; lockfile present, `yarn audit` not executed — Node/yarn unavailable in scout environment)

## Target

- **Target name / version:** `JamesIves/github-pages-deploy-action` (control repo) + dependency **`@actions/github` `9.0.0`**
- **Source:** `package.json` (`dependencies`); implementation in `src/git.ts`, `src/util.ts`, `src/ssh.ts`, `src/worktree.ts`, `src/execute.ts`, `src/constants.ts`
- **Why this target:** Initial cycle on the control repository; memory listed no prior targets — dependency `@actions/github` is the highest-impact external OSS surface for API/auth behavior and transitive advisories.

## Executive summary

The action’s core risk is **shelling out to `git` and `rsync` with string-built commands** while several inputs (`commit-message`, `clean-exclude` lines, `tag`, branch and path-derived segments) can originate from workflow configuration. Under normal use the workflow author is trusted, but **defense in depth is weak** where values are embedded unquoted in shell strings. **Credential handling** embeds the token in an HTTPS remote URL (`generateRepositoryPath`); errors are masked unless Actions debug logging is enabled (`suppressSensitiveInformation`). **SSH path** pins RSA and DSS host keys for `action.hostname` (appropriate for github.com; GHES operators should confirm host key policy). The pinned **`@actions/github@9.0.0`** aligns with current toolkit releases; public advisory databases indicate recent GHAs affected older Octokit lines — **stay on current minors and run `yarn npm audit` / dependabot** in CI. No Critical remote-code-execution issue was identified in static review without running the action.

## Scope and limits

**In scope:** `src/*.ts`, `action.yml`, `SECURITY.md`, `.github/workflows/build.yml` (spot-check for secret exposure patterns).

**Out of scope / not verified:** Full transitive dependency graph audit (no local `node_modules` — Node not installed), runtime behavior on Windows/macOS (code warns unsupported), GitHub Enterprise Server-specific SSH host key rotation, third-party consumer workflows.

**Trust boundary:** Assumes repository workflows and `with:` inputs are controlled by repository maintainers; findings focus on misuse, forked workflow confusion, and robustness against accidental metacharacters in inputs.

## Findings

| ID | Severity | Category | Title | Status |
|----|----------|----------|-------|--------|
| F-001 | Medium | Command injection (defense in depth) | User-controlled strings passed unquoted to `git` / `rsync` via `execute()` | Open |
| F-002 | Low | Secrets in URLs / logs | Token embedded in `repositoryPath`; masking skipped when Actions debug is on | Open |
| F-003 | Informational | Cryptography / SSH | DSS host key still appended for GitHub SSH alongside RSA | Open |
| F-004 | Informational | Supply chain | Keep `@actions/*` and Octokit transitive deps updated; run lockfile audits in CI | Open |

### F-001 — User-controlled strings passed unquoted to `git` / `rsync` via `execute()`

- **Description:** `execute()` runs commands through the shell with a single string (`exec(cmd, [], …)` in `@actions/exec`). Several interpolations are not shell-escaped, including `commitMessage` in `git commit -m "${commitMessage}"`, `cleanExclude` entries as `--exclude ${item}`, `action.tag` in `git tag ${action.tag}`, and large segments of the `rsync` line (e.g. `folderPath`).
- **Impact:** A maintainer who interpolates untrusted data into `commit-message`, `clean-exclude`, or `tag` could enable shell metacharacter injection in the runner. Even with static YAML, accidental quotes or backticks in messages could break or subvert the command.
- **Likelihood:** Low for typical static workflows; higher if inputs are built from PR titles, labels, or other untrusted context without sanitization.
- **Evidence:** Commit uses interpolated message:

```249:257:src/git.ts
    await execute(
      `git commit -m "${commitMessage}" --quiet --no-verify`,
      `${action.workspace}/${temporaryDeploymentDirectory}`,
      action.silent
    )
```

`clean-exclude` concatenation:

```156:161:src/git.ts
    if (action.clean && action.cleanExclude) {
      for (const item of action.cleanExclude) {
        excludes += `--exclude ${item} `
      }
    }
```

- **Remediation:** Prefer `execFile` with argument arrays for `git`/`rsync`, or use `git commit -m` with `-F` and a file containing the message; validate/shell-escape `tag`, `branch`, and exclude patterns against a strict allowlist.
- **References:** GitHub Actions `exec` API (shell vs non-shell behavior).

### F-002 — Token embedded in `repositoryPath`; masking skipped when Actions debug is on

- **Description:** HTTPS remotes include `x-access-token:${action.token}` in the URL (`generateRepositoryPath`). `suppressSensitiveInformation` replaces token and full `repositoryPath` in errors but **returns unmasked strings when `isDebug()` is true** (`ACTIONS_STEP_DEBUG` / core debug).
- **Impact:** Misconfiguration or support sessions with debug enabled may leak token material in logs; URL form also increases exposure in process listings compared to header-only auth (git credential helper pattern).
- **Likelihood:** Low; requires enabling debug or leaking error paths outside Actions log redaction.
- **Evidence:**

```36:41:src/util.ts
export const generateRepositoryPath = (action: ActionInterface): string =>
  action.sshKey
    ? `git@${action.hostname}:${action.repositoryName}`
    : `https://${`x-access-token:${action.token}`}@${action.hostname}/${
        action.repositoryName
      }.git`
```

```107:116:src/util.ts
  if (isDebug()) {
    // Data is unmasked in debug mode.
    return value
  }
```

- **Remediation:** Document that debug must not be used on production secrets; consider `GIT_ASKPASS` / credential helper instead of token-in-URL where feasible; ensure error paths always redact in fork PR scenarios.
- **References:** GitHub Actions documentation on step debug logging.

### F-003 — DSS host key still appended for GitHub SSH alongside RSA

- **Description:** `configureSSH` appends both RSA and **ssh-dss** known-host lines for `action.hostname`.
- **Impact:** DSS is deprecated and disabled in many OpenSSH clients; duplicate or legacy keys can confuse operators or trigger policy warnings. Low direct security impact if client ignores DSS.
- **Likelihood:** Informational for hardening and GHES key rotation hygiene.
- **Evidence:** `src/ssh.ts` — `sshGitHubKnownHostDss` constant and `appendFileSync` calls.
- **Remediation:** Prefer modern key types (e.g. ed25519) per current GitHub docs; drop DSS if no longer required for supported platforms.
- **References:** [GitHub SSH key fingerprints](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/githubs-ssh-key-fingerprints) (verify current recommended keys).

### F-004 — Keep `@actions/*` and Octokit transitive deps updated

- **Description:** This action depends on `@actions/github@9.0.0`. Historical GHSA reports affected older `@actions/github` / Octokit versions (ReDoS class issues in request/pagination plugins). Current line appears maintained; **transitives were not audited** in this environment.
- **Impact:** Latent vulnerabilities in dependencies could affect action consumers until upgraded.
- **Likelihood:** Informational ongoing risk.
- **Evidence:** `package.json` dependency block; `yarn.lock` present.
- **Remediation:** Run `yarn install` and `yarn npm audit` (or `npm audit`) in CI; enable Dependabot (already present under `.github/dependabot.yml`); bump `@actions/github` when toolkit releases security fixes.
- **References:** GitHub `actions/toolkit` advisories and release notes for `@actions/github`.

## Recommendations (prioritized)

1. **Harden command construction:** migrate high-risk invocations (`git commit`, `rsync`, `git tag`) away from string-shell composition toward argument arrays or file-backed `-F` / `--files-from` patterns.
2. **Document debug and token exposure:** explicitly warn maintainers not to enable Actions step debug when testing with PATs; prefer minimal-scope tokens.
3. **SSH known_hosts:** refresh host key set per current GitHub documentation; remove legacy algorithms if safe for supported consumers.
4. **CI assurance:** add a non-interactive `yarn audit` / OSV-scanner step on `push`/`pull_request` so dependency regressions are caught automatically.

## Memory / follow-ups

- Record completed targets in `memory/security-scout-memory.md` to avoid duplicate deep-dives.
- **Suggested next targets (not run this cycle):** transitive packages under `@actions/github` once `node_modules` is available; `.github/workflows/deploy.yml` / `production.yml` for OIDC vs token patterns; integration test mocks vs production paths.
