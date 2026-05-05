# OSS Security Scout Report

## Cycle Metadata
- Run type: initial
- Date: 2026-05-05
- Analyst: Cursor Cloud Agent
- Target: JamesIves/github-pages-deploy-action
- Repository: https://github.com/JamesIves/github-pages-deploy-action
- Commit reviewed: 8072b9c7

## Control-Repo Notes
- The requested control files `AGENTS.md`, `TARGET_POLICY.md`, `REPORT_TEMPLATE.md`, and `memory/security-scout-memory.md` were not present anywhere in this checkout or other visible refs.
- This report therefore uses a minimal fallback structure while staying within this repository, per instruction.

## Target Selection
- Selected target: this repository (`JamesIves/github-pages-deploy-action`)
- Reason selected: it is the only repository available in the current workspace, and no prior security scout memory existed in this checkout.

## Scope
- Reviewed action metadata and deployment code paths in:
  - `action.yml`
  - `src/lib.ts`
  - `src/git.ts`
  - `src/worktree.ts`
  - `src/util.ts`
  - `src/ssh.ts`
- Focus areas:
  - untrusted action inputs flowing into filesystem operations
  - untrusted action inputs flowing into git/rsync command construction
  - potential credential or SSH handling weaknesses

## Finding Summary
- Severity: High
- Title: `target-folder` path traversal can escape the deployment worktree and write into unintended repository paths

## Technical Details
The action accepts a user-controlled `target-folder` input and uses it directly in both filesystem and sync destinations without normalization or containment checks:

- `src/git.ts:163-166`
  - `mkdirP(`${temporaryDeploymentDirectory}/${action.targetFolder}`)`
- `src/git.ts:173-177`
  - rsync destination becomes `${temporaryDeploymentDirectory}/${action.targetFolder}`

Because `target-folder` is not validated, values containing traversal segments such as `../../.git/hooks` are accepted. Path joining and mkdir semantics will resolve these segments, allowing the deployment copy destination to leave the temporary deployment worktree.

This matters because the action later runs git commands from the worktree and from the workspace:

- `git add --all .`
- `git checkout -b ...`
- `git commit ...`
- `git push ...`

If attacker-controlled deployment content is copied into sensitive adjacent paths, especially repository metadata paths such as `.git/`, the subsequent git operations can be influenced or disrupted. In the worst case, this can become a code-execution or credential-impacting primitive depending on runner state and what files are overwritten.

## Evidence
- `src/constants.ts:149` reads `target-folder` directly from action input.
- `src/git.ts:163-166` creates the target path using raw string concatenation.
- `src/git.ts:173-177` passes the same unvalidated path to rsync as the destination.
- Existing tests only cover a benign target folder (`new_folder`) and do not exercise traversal cases:
  - `__tests__/git.test.ts:350-369`

Example dangerous input:

```yaml
with:
  folder: build
  target-folder: ../../.git/hooks
```

Resulting destination pattern in current code:

```text
github-pages-deploy-action-temp-deployment-folder/../../.git/hooks
```

That path is outside the intended deployment worktree.

## Impact
- Writes can escape the intended deployment directory.
- A malicious workflow author, compromised workflow file, or unsafe caller using this action as a library can direct copied content into unintended repository paths.
- Overwriting repository metadata or hook/config locations can affect subsequent git behavior in the same job.

## Recommended Remediation
1. Normalize `target-folder` before use.
2. Reject absolute paths.
3. Reject empty path segments that resolve outside the worktree (`..` traversal).
4. Enforce that the resolved destination stays within the temporary deployment directory.
5. Add regression tests covering:
   - `../foo`
   - `../../.git/hooks`
   - absolute paths
   - mixed traversal like `safe/../../evil`

## Suggested Fix Shape
- Resolve the candidate destination with `path.resolve`.
- Compare it against the resolved temporary deployment directory prefix.
- Fail closed if the resolved destination is not contained within the deployment worktree.

## Confidence
- Medium-high
- The unsafe data flow is direct and observable in code.
- I did not execute a full end-to-end exploit in GitHub Actions, but the traversal primitive is evident from the path handling and command construction.

## Follow-up
- Add validation for other path-like and ref-like inputs that are interpolated into git/rsync command strings, especially:
  - `branch`
  - `repository-name`
  - `clean-exclude`
  - `tag`
