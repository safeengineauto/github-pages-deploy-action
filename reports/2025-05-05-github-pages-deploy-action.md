# Security Scout Report

| Field | Value |
|-------|-------|
| **Target** | `JamesIves/github-pages-deploy-action` |
| **Version / Ref** | `dev` branch, v4.8.0 |
| **Run type** | `initial` |
| **Date** | 2025-05-05 |
| **Scout** | OSS Security Scout (automated) |

---

## Executive Summary

`github-pages-deploy-action` is a widely-used GitHub Action for deploying static
sites to GitHub Pages. The project demonstrates several good security practices
including secret suppression in error messages and use of `persist-credentials: false`
in CI workflows. However, the audit identified multiple command-injection vectors
where user-controlled action inputs are interpolated into shell commands without
escaping, outdated/deprecated SSH host key fingerprints, a debug-mode bypass of
secret suppression, and several CI/CD hardening gaps.

---

## Findings

### F-1: Shell Command Injection via Unescaped Action Inputs

| Attribute | Value |
|-----------|-------|
| **Severity** | High |
| **Category** | Input Validation & Injection |
| **File(s)** | `src/git.ts` |
| **Line(s)** | L32, L41, L46, L64, L89–93, L135, L147, L173–201, L255, L270, L294–303, L309, L337–346 |

**Description**

Multiple action inputs (`action.name`, `action.email`, `action.workspace`,
`action.hostname`, `action.branch`, `action.commitMessage`, `action.tag`,
`action.repositoryPath`, `action.folderPath`, `action.targetFolder`) are
interpolated directly into command strings passed to the `execute()` wrapper
(which calls `@actions/exec`). While `@actions/exec` with a single string
argument typically delegates to the shell, a malicious or malformed input
containing shell metacharacters (e.g., `"; rm -rf /; "`) could alter command
semantics.

The `git-config-name`, `git-config-email`, `commit-message`, `branch`, `tag`,
`target-folder`, and `folder` inputs are all user-supplied from workflow YAML and
are not sanitised before interpolation.

**Evidence**

```typescript
// src/git.ts L41-46
await execute(
  `git config user.name "${action.name}"`,
  action.workspace,
  action.silent
)

await execute(
  `git config user.email "${action.email}"`,
  action.workspace,
  action.silent
)
```

```typescript
// src/git.ts L255
`git commit -m "${commitMessage}" --quiet --no-verify`,
```

```typescript
// src/git.ts L337
`git tag ${action.tag}`,
```

**Recommendation**

Use the array-argument form of `@actions/exec` (passing `[arg1, arg2, ...]`
instead of a single command string) to avoid shell interpretation of
metacharacters. Alternatively, validate and sanitise all inputs against an
allowlist of safe characters before interpolation.

---

### F-2: Token Embedded in Repository URL (Credential in Command Argument)

| Attribute | Value |
|-----------|-------|
| **Severity** | Medium |
| **Category** | Credential & Secret Handling |
| **File(s)** | `src/util.ts` |
| **Line(s)** | L36–L41 |

**Description**

When SSH is not in use, the PAT/token is embedded directly in the HTTPS
repository URL (`https://x-access-token:<TOKEN>@github.com/...`). This URL is
then passed as an argument to `git remote add origin`, `git push`, `git fetch`,
and `git ls-remote`. Although `@actions/exec` can mask secrets, the token appears
as a process argument visible in `/proc/<pid>/cmdline` on the runner and could
leak through runner diagnostic logs.

**Evidence**

```typescript
// src/util.ts L36-41
export const generateRepositoryPath = (action: ActionInterface): string =>
  action.sshKey
    ? `git@${action.hostname}:${action.repositoryName}`
    : `https://${`x-access-token:${action.token}`}@${action.hostname}/${
        action.repositoryName
      }.git`
```

**Recommendation**

Instead of embedding the token in the URL, configure `git` to use an
`extraheader` for authentication:

```bash
git config http.https://github.com/.extraheader "AUTHORIZATION: basic $(echo -n x-access-token:<TOKEN> | base64)"
```

This keeps the token out of command-line arguments and process listings.

---

### F-3: Debug Mode Disables Secret Suppression

| Attribute | Value |
|-----------|-------|
| **Severity** | Medium |
| **Category** | Credential & Secret Handling |
| **File(s)** | `src/util.ts` |
| **Line(s)** | L107–L127 |

**Description**

The `suppressSensitiveInformation()` function returns the unmasked string when
`isDebug()` is true. GitHub Actions debug mode can be enabled by anyone with
write access to the repository (by setting the `ACTIONS_STEP_DEBUG` secret to
`true`). This means that enabling debug logging could cause tokens and
repository paths to appear unmasked in workflow run logs.

**Evidence**

```typescript
// src/util.ts L107-127
export const suppressSensitiveInformation = (
  str: string,
  action: ActionInterface
): string => {
  let value = str

  if (isDebug()) {
    // Data is unmasked in debug mode.
    return value
  }
  // ... masking logic ...
}
```

**Recommendation**

Always mask sensitive information regardless of debug mode. The `@actions/core`
`setSecret()` API already handles debug-safe masking at the runner level. Remove
the early-return on `isDebug()` or, at minimum, ensure the token value is
registered via `setSecret()` at action startup.

---

### F-4: Outdated and Deprecated SSH Host Key Fingerprints

| Attribute | Value |
|-----------|-------|
| **Severity** | Medium |
| **Category** | Cryptographic & Transport Security |
| **File(s)** | `src/ssh.ts` |
| **Line(s)** | L18–L19 |

**Description**

The action hardcodes SSH known-host entries for GitHub using RSA and DSS key
types. GitHub deprecated the DSS host key in 2021 and rotated the RSA host key
in March 2023. The RSA fingerprint in `ssh.ts` corresponds to the **pre-rotation**
key (which GitHub has since revoked). Additionally, the Ed25519 and ECDSA host
keys, which GitHub recommends as primary, are not included.

Using revoked/outdated host keys means the SSH known_hosts file may not match
GitHub's actual server key, potentially causing connection failures or reducing
TOFU (trust-on-first-use) guarantees.

**Evidence**

```typescript
// src/ssh.ts L18-19 — RSA key matches the old (revoked) GitHub host key
const sshGitHubKnownHostRsa = `\n${action.hostname} ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAq2A7hRGmd...`
const sshGitHubKnownHostDss = `\n${action.hostname} ssh-dss AAAAB3NzaC1kc3MAAACBANGFW2P9xlGU3zW...`
```

**Recommendation**

1. Remove the DSS key entirely (deprecated by GitHub).
2. Replace the RSA key with GitHub's current RSA key (post-March 2023 rotation).
3. Add Ed25519 and ECDSA host keys per [GitHub's documentation](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/githubs-ssh-key-fingerprints).
4. Consider fetching host keys dynamically via the GitHub API meta endpoint
   (`https://api.github.com/meta`) for self-updating known_hosts.

---

### F-5: CI Workflows Missing Explicit Permissions Block

| Attribute | Value |
|-----------|-------|
| **Severity** | Low |
| **Category** | CI/CD & Workflow Security |
| **File(s)** | `.github/workflows/integration.yml`, `.github/workflows/build.yml` |
| **Line(s)** | (top-level) |

**Description**

Neither `integration.yml` nor `build.yml` defines a top-level `permissions`
block. Without explicit permissions, the `GITHUB_TOKEN` inherits the repository's
default permissions (which may be read-write for all scopes). While `build.yml`
does not perform security-sensitive operations, `integration.yml` performs
cross-repository pushes and branch deletion using separate PATs, and the
implicit `GITHUB_TOKEN` permissions are broader than necessary.

**Evidence**

```yaml
# .github/workflows/build.yml — no top-level permissions key
name: Unit Tests 🧪
on:
  pull_request: ...
  push: ...
jobs: ...
```

**Recommendation**

Add a top-level `permissions` block with the minimum required scopes to all
workflow files. For example:

```yaml
permissions:
  contents: read
```

Elevate permissions only at the job level where needed.

---

### F-6: CI Action References Not Pinned to Commit SHAs

| Attribute | Value |
|-----------|-------|
| **Severity** | Low |
| **Category** | Dependency & Supply-Chain Risk |
| **File(s)** | `.github/workflows/integration.yml`, `.github/workflows/build.yml` |
| **Line(s)** | Various |

**Description**

Third-party actions used in CI workflows are referenced by version tags (e.g.,
`actions/checkout@v6.0.2`, `dawidd6/action-delete-branch@v3.1.0`,
`webfactory/ssh-agent@v0.10.0`) rather than pinned commit SHAs. A compromised
or re-tagged upstream action could execute arbitrary code in the CI environment.

**Evidence**

```yaml
- uses: actions/checkout@v6.0.2
- uses: dawidd6/action-delete-branch@v3.1.0
- uses: webfactory/ssh-agent@v0.10.0
- uses: codecov/codecov-action@v6.0.0
```

**Recommendation**

Pin all third-party action references to full commit SHAs. Add a comment with
the version tag for readability:

```yaml
- uses: actions/checkout@<full-sha> # v6.0.2
```

Consider using tools like Dependabot or StepSecurity's `harden-runner` to
automate SHA pinning.

---

### F-7: `rsync` Clean Exclude Items Not Quoted

| Attribute | Value |
|-----------|-------|
| **Severity** | Low |
| **Category** | Input Validation & Injection |
| **File(s)** | `src/git.ts` |
| **Line(s)** | L157–L160 |

**Description**

The `clean-exclude` input is split by newlines and each item is appended to the
rsync command as `--exclude <item>` without quoting. If a user provides an
exclude pattern containing spaces or shell metacharacters, the rsync command will
break or potentially interpret the value incorrectly.

**Evidence**

```typescript
// src/git.ts L157-160
for (const item of action.cleanExclude) {
  excludes += `--exclude ${item} `
}
```

**Recommendation**

Quote exclude values:

```typescript
excludes += `--exclude "${item}" `
```

Or, preferably, pass rsync arguments as an array to avoid shell interpretation.

---

### F-8: Shared Mutable Output Buffer in `execute.ts`

| Attribute | Value |
|-----------|-------|
| **Severity** | Low |
| **Category** | Code Quality & Error Handling |
| **File(s)** | `src/execute.ts` |
| **Line(s)** | L18, L35–L36 |

**Description**

The `execute()` function uses a module-level shared `output` object that is
reset at the start of each call. If `execute()` were ever called concurrently
(e.g., in a future refactor or when used as an imported library), output from
one command could bleed into another, potentially leaking sensitive information
between invocations.

**Evidence**

```typescript
// src/execute.ts L18
const output: ExecuteOutput = {stdout: '', stderr: ''}

// src/execute.ts L35-36
output.stdout = ''
output.stderr = ''
```

**Recommendation**

Create a new `output` object inside each `execute()` call rather than reusing a
module-level variable:

```typescript
export async function execute(...) {
  const output: ExecuteOutput = {stdout: '', stderr: ''}
  // ...
}
```

---

### F-9: `--no-verify` Flag on Git Commit

| Attribute | Value |
|-----------|-------|
| **Severity** | Info |
| **Category** | Code Quality & Error Handling |
| **File(s)** | `src/git.ts` |
| **Line(s)** | L255 |

**Description**

The `git commit` invocation includes `--no-verify`, which skips any pre-commit
and commit-msg hooks. While this is intentional in a CI deployment context (to
avoid interference from user hooks), it also means that any security-related
hooks in the deployment branch are bypassed.

**Evidence**

```typescript
`git commit -m "${commitMessage}" --quiet --no-verify`,
```

**Recommendation**

This is acceptable for a deployment automation tool. Document in the README
that pre-commit hooks are intentionally bypassed during deployment pushes, so
users relying on hooks for enforcement are aware.

---

### F-10: Security Policy Encourages Public Bug Reports for Vulnerabilities

| Attribute | Value |
|-----------|-------|
| **Severity** | Info |
| **Category** | Code Quality & Error Handling |
| **File(s)** | `SECURITY.md` |
| **Line(s)** | L14 |

**Description**

The `SECURITY.md` file suggests reporting vulnerabilities "through the issues
interface (as a bug)." Public issue reports for security vulnerabilities could
expose zero-day information before a fix is available.

**Evidence**

```markdown
Please disclose any security vulnerabilities either through the issues interface
(as a bug) or by emailing the project maintainer.
```

**Recommendation**

Enable GitHub's private vulnerability reporting (Security Advisories) and update
`SECURITY.md` to direct reporters to use that mechanism first, with email as a
fallback. Remove the suggestion to file public issues for vulnerabilities.

---

## Positive Observations

1. **Secret suppression in error messages** — The `suppressSensitiveInformation()`
   function in `util.ts` replaces tokens and repository paths in error messages
   with `***`, reducing the risk of accidental credential exposure (aside from
   the debug-mode bypass noted in F-3).

2. **`persist-credentials: false` in CI** — Integration test workflows correctly
   use `persist-credentials: false` on checkout steps, preventing the default
   token from persisting in the git credential store during cross-repo operations.

3. **Locked dependency manifest** — A `yarn.lock` file is present and committed,
   ensuring reproducible builds and reducing supply-chain risk from floating
   dependency resolutions.

4. **Dry-run support** — The action provides a `dry-run` mode that skips the
   actual push, enabling safe testing of deployment configurations.

5. **Default branch protection** — The action defaults to deploying to `gh-pages`
   rather than the source branch, reducing the risk of accidentally overwriting
   source code.

6. **Input parameter validation** — The `checkParameters()` function validates
   that required inputs (token/SSH key, branch, folder) are present before
   proceeding with deployment.

---

## Summary Table

| ID | Title | Severity | Category |
|----|-------|----------|----------|
| F-1 | Shell Command Injection via Unescaped Action Inputs | High | Input Validation & Injection |
| F-2 | Token Embedded in Repository URL | Medium | Credential & Secret Handling |
| F-3 | Debug Mode Disables Secret Suppression | Medium | Credential & Secret Handling |
| F-4 | Outdated and Deprecated SSH Host Key Fingerprints | Medium | Cryptographic & Transport Security |
| F-5 | CI Workflows Missing Explicit Permissions Block | Low | CI/CD & Workflow Security |
| F-6 | CI Action References Not Pinned to Commit SHAs | Low | Dependency & Supply-Chain Risk |
| F-7 | `rsync` Clean Exclude Items Not Quoted | Low | Input Validation & Injection |
| F-8 | Shared Mutable Output Buffer in `execute.ts` | Low | Code Quality & Error Handling |
| F-9 | `--no-verify` Flag on Git Commit | Info | Code Quality & Error Handling |
| F-10 | Security Policy Encourages Public Bug Reports | Info | Code Quality & Error Handling |

---

*Report generated by OSS Security Scout.*
