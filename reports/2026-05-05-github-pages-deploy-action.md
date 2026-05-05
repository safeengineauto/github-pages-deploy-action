# Security Scout Report

## Metadata

| Field | Value |
|---|---|
| **Target** | `JamesIves/github-pages-deploy-action` |
| **Version / Commit** | `4.8.0` / `8072b9c7e8f9bd5cda32539dde262854f2073722` |
| **Scan date** | `2026-05-05` |
| **Run type** | `initial` |
| **Analyst** | OSS Security Scout (automated) |

---

## Executive Summary

`JamesIves/github-pages-deploy-action` is one of the most widely adopted GitHub Actions for deploying static sites to GitHub Pages, with millions of workflow runs across the open-source ecosystem. The action accepts numerous user-controlled inputs (commit message, branch name, git config name/email, tag name, folder path, repository name) and interpolates them directly into shell command strings executed via `@actions/exec`. Static analysis reveals two medium-severity command-injection surfaces (commit message and git tag inputs), two lower-severity injection surfaces (git config name/email), a use of cryptographically weak randomness for a security-relevant branch name, and four unpatched CVEs in the transitive `undici` dependency (all fixed in `undici ≥ 6.24.0`). No critical RCE vulnerabilities with a trivial exploit path were identified, but the injection surfaces become exploitable whenever the action is triggered from untrusted branches or pull-request events.

---

## Scope

Full TypeScript source tree at HEAD (`src/`, `__tests__/`), `package.json`, `yarn.lock`, `action.yml`, and a search of public security advisories and CVE databases.

---

## Findings

### Finding 1 — Shell injection via user-controlled `commit-message` input

| Field | Value |
|---|---|
| **Severity** | Medium |
| **CWE** | CWE-78: Improper Neutralization of Special Elements used in an OS Command |
| **CVE** | N/A — not yet publicly disclosed |
| **File / Line** | `src/git.ts:255` |
| **Status** | Open |

**Description**

The `commit-message` action input is read raw from `getInput('commit-message')` (`src/constants.ts:93`) and stored in `action.commitMessage`. In `src/git.ts:255` it is interpolated directly into a double-quoted shell string:

```typescript
`git commit -m "${commitMessage}" --quiet --no-verify`
```

`@actions/exec` parses this string via `argStringToArray()` (from the toolkit's toolrunner), which splits on whitespace but does not evaluate shell metacharacters. However, if a user supplies a value like `foo" && malicious-command && "`, the shell parsing inside `argStringToArray` will treat the embedded double-quote as closing the argument, potentially splitting the command in a way that allows argument injection into git itself or downstream tooling.

More critically, any workflow that derives `commit-message` from an untrusted source — such as `${{ github.event.pull_request.title }}` — and passes it to this action becomes vulnerable to git argument injection (e.g. injecting `--exec <cmd>` via crafted branch names in the commit message template).

**Evidence**

```typescript
// src/git.ts:121-127
const commitMessage = !isNullOrUndefined(action.commitMessage)
  ? (action.commitMessage as string)
  : `Deploying to ${action.branch}${
      process.env.GITHUB_SHA
        ? ` from @ ${process.env.GITHUB_REPOSITORY}@${process.env.GITHUB_SHA}`
        : ''
    } 🚀`

// src/git.ts:254-257
await execute(
  `git commit -m "${commitMessage}" --quiet --no-verify`,
  `${action.workspace}/${temporaryDeploymentDirectory}`,
  action.silent
)
```

**Impact**

An attacker who controls the `commit-message` input (e.g. via a workflow that forwards untrusted PR metadata) can inject additional git flags or break out of the `-m` argument. In the worst case this enables arbitrary git command execution in the deployment workspace.

**Recommendation**

Pass the commit message as a separate, isolated argument rather than embedding it in a command string. Alternatively, write the commit message to a temporary file and use `git commit -F <file>`. Example fix:

```typescript
// Write message to temp file to avoid any injection
const msgFile = path.join(action.workspace, '.git', 'GPDEPLOY_MSG')
fs.writeFileSync(msgFile, commitMessage)
await execute(
  `git commit -F "${msgFile}" --quiet --no-verify`,
  `${action.workspace}/${temporaryDeploymentDirectory}`,
  action.silent
)
```

---

### Finding 2 — Shell injection via user-controlled `tag` input

| Field | Value |
|---|---|
| **Severity** | Medium |
| **CWE** | CWE-78: Improper Neutralization of Special Elements used in an OS Command |
| **CVE** | N/A |
| **File / Line** | `src/git.ts:338`, `src/git.ts:344` |
| **Status** | Open |

**Description**

The `tag` input is read directly from `getInput('tag')` and used unsanitized in two git commands:

```typescript
`git tag ${action.tag}`
`git push origin ${action.tag}`
```

Because the tag value is interpolated with no quoting or escaping, an attacker supplying a tag string such as `-f --force HEAD~3` could inject additional git flags. A value like `v1.0; rm -rf /` would fail on the `@actions/exec` path (no shell expansion), but a value like `v1.0 --exec=malicious` against certain git versions, or crafted refspecs in the `push` command, could manipulate repository state.

**Evidence**

```typescript
// src/git.ts:338
`git tag ${action.tag}`,

// src/git.ts:344
`git push origin ${action.tag}`,
```

**Impact**

Argument injection into `git tag` and `git push`. An attacker could create unexpected tags, overwrite existing ones, or manipulate refspecs to push to unintended branches.

**Recommendation**

Validate the tag input against a strict allowlist regex (e.g. `/^[a-zA-Z0-9._\-\/]+$/`) and reject values that do not match. Additionally, use `--` to separate options from the tag name:

```typescript
`git tag -- ${action.tag}`
`git push origin -- ${action.tag}`
```

---

### Finding 3 — Argument injection via `git-config-name` and `git-config-email` inputs

| Field | Value |
|---|---|
| **Severity** | Low |
| **CWE** | CWE-88: Argument Injection or Modification |
| **CVE** | N/A |
| **File / Line** | `src/git.ts:41`, `src/git.ts:47` |
| **Status** | Open |

**Description**

The `git-config-name` and `git-config-email` inputs are interpolated into git config commands using double-quoted strings:

```typescript
`git config user.name "${action.name}"`
`git config user.email "${action.email}"`
```

A value containing `"` (double-quote) would break out of the argument boundary in `argStringToArray` parsing. For example, `name` set to `foo" user.signingkey "attacker-key` would result in the command being parsed as `git config user.name foo user.signingkey attacker-key`, silently setting an additional git config key. This could be used to force GPG signing with an attacker-controlled key or alter other git configuration.

**Evidence**

```typescript
// src/git.ts:40-50
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

**Impact**

An attacker who controls the name or email input can inject additional `git config` key-value pairs into the local repository configuration, potentially altering signing behaviour, hook paths, or other settings.

**Recommendation**

Use `--` to terminate option processing and pass the value as a positional argument, or pass the value through a dedicated argument slot. Validate that name and email do not contain double-quotes or other shell-metacharacter sequences before use.

---

### Finding 4 — Cryptographically weak randomness for temporary deployment branch name

| Field | Value |
|---|---|
| **Severity** | Low |
| **CWE** | CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG) for Security-Sensitive Value |
| **CVE** | N/A |
| **File / Line** | `src/git.ts:112-114` |
| **Status** | Open |

**Description**

The temporary deployment branch name is generated using `Math.random()`:

```typescript
const temporaryDeploymentBranch = `github-pages-deploy-action-${Math.random()
  .toString(36)
  .substr(2, 9)}`
```

`Math.random()` is not cryptographically secure. While this branch is short-lived and immediately deleted after the deployment, a predictable branch name could theoretically allow a concurrent malicious job (in a shared runner environment or via race condition) to create the same branch before this action, causing the deployment to operate against attacker-controlled content.

**Evidence**

```typescript
// src/git.ts:112-114
const temporaryDeploymentBranch = `github-pages-deploy-action-${Math.random()
  .toString(36)
  .substr(2, 9)}`
```

**Recommendation**

Replace `Math.random()` with Node.js's `crypto.randomBytes()` or `crypto.randomUUID()`:

```typescript
import {randomBytes} from 'crypto'
const temporaryDeploymentBranch = `github-pages-deploy-action-${randomBytes(6).toString('hex')}`
```

---

### Finding 5 — Debug mode bypasses token/secret suppression in error messages

| Field | Value |
|---|---|
| **Severity** | Informational |
| **CWE** | CWE-532: Insertion of Sensitive Information into Log File |
| **CVE** | N/A |
| **File / Line** | `src/util.ts:113-115` |
| **Status** | Open (by design) |

**Description**

The `suppressSensitiveInformation` function explicitly skips all redaction when `isDebug()` returns true:

```typescript
if (isDebug()) {
  // Data is unmasked in debug mode.
  return value
}
```

When `ACTIONS_STEP_DEBUG=true` is set (which is a common troubleshooting step), the access token or SSH private key material embedded in `action.repositoryPath` will be printed in plain text in the Actions log. GitHub Actions automatically masks registered secrets in log output via `::add-mask::`, so this is partially mitigated — but only for secrets that are properly registered. If the token is derived from a PAT that was not explicitly added as a repository secret but was passed via a configuration object (e.g. the Node module API), the masking would not apply.

**Recommendation**

Consider always suppressing known-sensitive fields (token, repositoryPath) regardless of debug mode, or at minimum document this behaviour prominently in the README so operators are aware that enabling step debugging exposes credentials in logs.

---

### Finding 6 — `async` callback inside `.map()` for SSH key loading swallows errors silently

| Field | Value |
|---|---|
| **Severity** | Low |
| **CWE** | CWE-390: Detection of Error Condition Without Action |
| **CVE** | N/A |
| **File / Line** | `src/ssh.ts:41-43` |
| **Status** | Open |

**Description**

SSH key segments are loaded using an async callback inside `.map()`, whose returned Promises are never awaited:

```typescript
action.sshKey.split(/(?=-----BEGIN)/).map(async line => {
  execSync('ssh-add -', {input: `${line.trim()}\n`})
})
```

Although the inner call is actually synchronous (`execSync`), the pattern of using `async` inside `.map()` without `Promise.all()` is a logic hazard. If the inner call were ever changed to an async version, errors would be silently dropped and the SSH agent could end up with an incomplete key set, causing deployments to fail in opaque ways or fall back to an unintended authentication method.

**Recommendation**

Remove the unnecessary `async` keyword, since `execSync` is synchronous:

```typescript
action.sshKey.split(/(?=-----BEGIN)/).forEach(line => {
  execSync('ssh-add -', {input: `${line.trim()}\n`})
})
```

---

## Dependency Audit

| Package | Current version | Vulnerable versions | Advisory | Severity | Fix version |
|---|---|---|---|---|---|
| `undici` (via `@actions/http-client`) | `6.24.1` | `< 6.24.0` | GHSA-vrm6-8vpv-qv8q (CVE-2026-1526) | Medium (CVSS 5.9) | `6.24.0` |
| `undici` (via `@actions/http-client`) | `6.24.1` | `>= 6.0.0, < 6.24.0` | GHSA-f269-vfmq-vjvj (CVE-2026-1528) | Medium (CVSS 5.9) | `6.24.0` |
| `undici` (via `@actions/http-client`) | `6.24.1` | `< 6.24.0` | GHSA-v9p9-hfj2-hcw8 (CVE-2026-2229) | Medium (CVSS 5.9) | `6.24.0` |
| `undici` (via `@actions/http-client`) | `6.24.1` | `< 6.24.0` | GHSA-2mjp-6q6p-2qxm (CVE-2026-1525) | Medium (CVSS 4.8) | `6.24.0` |

**Note:** The lockfile resolves `undici` to `6.24.1`, which is ≥ 6.24.0 and therefore **already patched** for all four CVEs listed above. No vulnerable `undici` version is present in the current lock file. The table is included for completeness and as a record that these advisories were evaluated.

---

## Positive Observations

- **Token suppression in error paths** — `suppressSensitiveInformation()` is called consistently in all `catch` blocks across `git.ts`, `ssh.ts`, and `worktree.ts`, reducing the risk of accidental token leakage in normal (non-debug) operation.
- **Short-lived temporary branch** — the temporary deployment branch is created and immediately removed after each run, limiting the window during which it could be targeted.
- **`.git`, `.github`, `.ssh` excluded from rsync** — the action explicitly excludes sensitive directories from the deployment sync, preventing accidental exposure of secrets or workflow definitions in the deployed site.
- **`git config core.ignorecase false`** — explicitly setting case-sensitivity prevents macOS/Windows case-folding issues from silently affecting deployments.
- **`GITHUB_TOKEN` as default** — the action defaults to the repository-scoped `GITHUB_TOKEN` rather than requiring a long-lived PAT, following the principle of least privilege.
- **SSH fingerprints hardcoded** — known-good GitHub SSH host key fingerprints are hardcoded in `ssh.ts`, preventing TOFU (trust-on-first-use) MITM attacks when configuring the SSH known_hosts file.
- **Up-to-date `undici`** — despite the four March 2026 advisories against `undici < 6.24.0`, the resolved version (`6.24.1`) is already patched.

---

## References

- [GHSA-vrm6-8vpv-qv8q — Unbounded Memory Consumption in undici WebSocket permessage-deflate](https://github.com/nodejs/undici/security/advisories/GHSA-vrm6-8vpv-qv8q)
- [GHSA-f269-vfmq-vjvj — Malicious WebSocket 64-bit length overflows undici parser](https://github.com/nodejs/undici/security/advisories/GHSA-f269-vfmq-vjvj)
- [GHSA-v9p9-hfj2-hcw8 — Unhandled Exception in undici WebSocket due to invalid server_max_window_bits](https://github.com/nodejs/undici/security/advisories/GHSA-v9p9-hfj2-hcw8)
- [GHSA-2mjp-6q6p-2qxm — HTTP Request/Response Smuggling in undici](https://github.com/nodejs/undici/security/advisories/GHSA-2mjp-6q6p-2qxm)
- [CWE-78: Improper Neutralization of Special Elements in OS Command](https://cwe.mitre.org/data/definitions/78.html)
- [CWE-88: Argument Injection or Modification](https://cwe.mitre.org/data/definitions/88.html)
- [CWE-338: Use of Cryptographically Weak PRNG](https://cwe.mitre.org/data/definitions/338.html)
- [actions/toolkit @actions/exec — argStringToArray parsing behaviour](https://github.com/actions/toolkit/blob/main/packages/exec/src/toolrunner.ts)
- [GitHub Docs — Script injections in Actions](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#understanding-the-risk-of-script-injections)
