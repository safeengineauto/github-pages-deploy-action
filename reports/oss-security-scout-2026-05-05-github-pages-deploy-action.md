# OSS Security Scout Report

## Report metadata

| Field | Value |
| ----- | ----- |
| **Run type** | initial |
| **Target** | JamesIves / github-pages-deploy-action — https://github.com/JamesIves/github-pages-deploy-action |
| **Scope** | TypeScript action source under `src/` (`lib.ts`, `git.ts`, `ssh.ts`, `util.ts`, `worktree.ts`, `execute.ts`, `constants.ts`), root `action.yml`, and `package.json` dependency declarations (no full transitive graph audit). |
| **Out of scope** | Compiled `lib/` output, exhaustive third-party vulnerability database pass, GitHub-hosted runner isolation guarantees, consumer repository configurations except as referenced in README. |
| **Cycle date** | 2026-05-05 |
| **Analyst** | Cursor OSS Security Scout (automated static review) |
| **Commit / version** | Workspace aligned with package version **4.8.0** (`package.json`); exact git SHA not pinned in this environment. |

## Executive summary

This action intentionally runs **git**, **rsync**, and optional **ssh** with credentials derived from workflow inputs, which is appropriate for its purpose but concentrates risk in **shell-assembled commands** and **secret-bearing remote URLs**. No critical remote-code-execution flaw was identified in the reviewed paths under typical GitHub Actions trust assumptions (only trusted actors edit workflow YAML). The highest practical risks are **command-line metacharacter handling** for user-controlled strings passed into `git commit` and `rsync`, and **operational leakage** when debug logging is enabled.

## Methodology

- Read policy (`TARGET_POLICY.md`), agent guide (`AGENTS.md`), and memory (empty prior to this cycle).
- Performed static review of deployment and authentication logic: subprocess invocation patterns, URL construction, SSH setup, and rsync/git command assembly.
- Cross-checked `action.yml` inputs against `constants.ts` consumption.
- Did not run dynamic fuzzing or integration tests.

## Supply chain and dependencies

- **Runtime (production)**: `@actions/core` 3.0.0, `@actions/exec` 3.0.0, `@actions/github` 9.0.0, `@actions/io` 3.0.2, plus `typescript-eslint` / `@eslint/js` as dependencies (unusual for a published action; increases install surface and supply-chain exposure for consumers who install the package, though the published action bundle may tree-shake differently in practice).
- **Dev tooling**: Jest, ESLint, Prettier, TypeScript — not executed by the action runtime on GitHub-hosted runners when using `action.yml` with `runs: node24`.
- **Pinning**: Exact versions on core `@actions/*` packages reduces drift; consumers still reference moving tags like `@v4` per README examples (ecosystem norm, not specific to this repo).

## Trust boundaries and assumptions

- **Trusted**: Authors of workflows that invoke the action; GitHub’s provision of `GITHUB_TOKEN` and event payload; maintainers of this repository and its release artifacts.
- **Untrusted relative to the repo**: Fork PRs from strangers (mitigated if secrets are not exposed to those workflows), compromised dependencies during `npm ci` / packaging, malicious `repository-name` / `commit-message` values if they are fed from untrusted workflow expressions without sanitization.

## Findings

### FIND-01 — Shell metacharacters in `commit-message` reach unescaped double quotes

| Attribute | Value |
| --------- | ----- |
| **Severity** | Medium |
| **Category** | Command injection / argument injection |
| **Location** | `src/git.ts` (`git commit -m "${commitMessage}"`) |
| **Description** | The commit message is interpolated into a double-quoted shell string for `git commit`. Characters such as `"`, `` ` ``, `$`, and command substitution forms can alter command interpretation if `commit-message` is populated from untrusted or partially trusted workflow data. |
| **Prerequisites** | Ability to influence the `commit-message` input seen by the action (typically workflow author; higher risk if workflows compose this input from `github.event` or other attacker-controlled fields). |
| **Recommendation** | Avoid shell-quoting pitfalls by using `git commit` without a shell-assembled `-m` string (e.g. pass `-m` via argv with separate arguments, or use environment variable `GIT_COMMITTER_*` patterns supported by git). At minimum document that `commit-message` must be static or strictly sanitized. |

### FIND-02 — `clean-exclude` entries are concatenated into an rsync shell line without escaping

| Attribute | Value |
| --------- | ----- |
| **Severity** | Low |
| **Category** | Shell / argument injection |
| **Location** | `src/git.ts` (construction of `excludes` for `rsync` `--delete` block) |
| **Description** | Each `cleanExclude` line becomes `--exclude ${item}` in a string executed by the shell. Spaces, glob characters, or subsyntax could change rsync behavior compared to operator intent. |
| **Prerequisites** | Control over `clean-exclude` multiline input in the workflow. |
| **Recommendation** | Pass excludes using rsync’s repeated `--exclude` with proper argv separation (no intermediate shell string), or validate against a strict allow pattern. |

### FIND-03 — Sensitive strings may appear unmasked when Actions debug is enabled

| Attribute | Value |
| --------- | ----- |
| **Severity** | Informational |
| **Category** | Information disclosure |
| **Location** | `src/util.ts` (`suppressSensitiveInformation` early return when `isDebug()` is true) |
| **Description** | When `ACTIONS_STEP_DEBUG` / debug mode is on, masking of tokens and repository URLs in error paths is disabled by design. |
| **Prerequisites** | Maintainer enables debug on a workflow run that fails in a way surfacing remote URLs or tokens in error text. |
| **Recommendation** | Document clearly for operators; consider masking high-risk substrings even in debug, or gate full dumps behind an additional explicit flag. |

## Positive observations

- **Default exclusions** for rsync omit `.git`, `.github`, and `.ssh` from published artifacts, reducing accidental secret publication from the deployment folder.
- **HTTPS remote URLs** embed the token in a conventional `x-access-token` form; errors go through `suppressSensitiveInformation` under normal (non-debug) operation.
- **SSH known hosts** for GitHub are pinned when configuring deploy keys, improving resistance to naive MITM against first-connect scenarios.
- **README** calls out `permissions: contents: write` and `persist-credentials: false` when using PATs for cross-repo pushes—good alignment with least privilege.

## Recommendations summary

1. Harden `commit-message` handling so it cannot break shell quoting (highest user-facing hardening value).
2. Treat `clean-exclude` and similar inputs as structured data, not raw shell fragments.
3. Keep documenting PAT scope minimization and fork PR secret exposure for workflow authors.

## Appendix

### Files and areas reviewed

- `src/lib.ts`, `src/git.ts`, `src/ssh.ts`, `src/util.ts`, `src/worktree.ts`, `src/execute.ts`, `src/constants.ts`, `src/main.ts`
- `action.yml`, `package.json`, `SECURITY.md` (policy text only)

### References

- GitHub Actions: [Encrypted secrets](https://docs.github.com/en/actions/security-guides/using-secrets-in-github-actions)
- GitHub SSH key fingerprints (referenced in-code): https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/githubs-ssh-key-fingerprints
