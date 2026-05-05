# OSS Security Scout Report

## Run metadata

- Run type: initial
- Date: 2026-05-05
- Target: JamesIves/github-pages-deploy-action
- Repository reviewed: https://github.com/safeengineauto/github-pages-deploy-action
- Commit reviewed: 8072b9c7e8f9bd5cda32539dde262854f2073722
- Scout cycle: 1

## Finding summary

The action builds Git and Rsync invocations by interpolating workflow inputs into a
single command-line string before passing it to `@actions/exec`. Because
`@actions/exec` tokenizes that string into the executable and argument vector,
inputs containing quoting or whitespace can become additional arguments to the
underlying tools. Workflows that forward untrusted event or dispatch values into
inputs such as `commit-message`, `target-folder`, `clean-exclude`,
`repository-name`, `git-config-name`, `git-config-email`, `tag`, or `branch`
can therefore let an attacker alter the Git/Rsync operation performed by the
runner.

Severity is workflow-dependent. Static workflow configurations are not directly
exploitable, but reusable workflows or `workflow_dispatch`/event-driven
workflows that pass user-controlled values into these inputs can expose
integrity impact on the deployment branch, tags, or files staged for deployment.

## Affected code

- `src/git.ts` constructs command strings with interpolated inputs:
  - `git config user.name "${action.name}"`
  - `git config user.email "${action.email}"`
  - `git ls-remote --heads ${action.repositoryPath} refs/heads/${action.branch}`
  - `chmod -R +rw ${action.folderPath}`
  - `rsync ... ${action.folderPath}/. ${temporaryDeploymentDirectory}/${action.targetFolder} ... ${excludes}`
  - `git commit -m "${commitMessage}" --quiet --no-verify`
  - `git push ... ${temporaryDeploymentBranch}:${action.branch}`
  - `git fetch ${action.repositoryPath} ${action.branch}:${action.branch}`
  - `git tag ${action.tag}`
- `src/worktree.ts` interpolates `action.branch` into `git fetch`,
  `git checkout`, and fallback checkout commands.
- `src/execute.ts` accepts only a single `cmd` string and passes it to
  `exec(cmd, [], ...)`, so callers cannot keep untrusted input separated from
  the command parser.

## Attack scenario

1. A repository exposes a reusable deployment workflow or a `workflow_dispatch`
   workflow and forwards an untrusted input into this action, for example:

   ```yaml
   - uses: JamesIves/github-pages-deploy-action@v4
     with:
       folder: dist
       target-folder: ${{ inputs.target_folder }}
       commit-message: ${{ inputs.commit_message }}
       clean-exclude: ${{ inputs.clean_exclude }}
   ```

2. An attacker supplies input containing whitespace and option-like tokens.
3. The action embeds the value in the command string. When `@actions/exec`
   tokenizes the string, the payload is interpreted as additional Git or Rsync
   arguments rather than as one literal input value.
4. Depending on which input is attacker-controlled, the attacker can alter what
   files Rsync copies/deletes, modify commit/tag behavior, or influence Git
   fetch/push operations performed with the workflow's deployment credentials.

This issue does not require shell metacharacter execution; the risk is argument
injection into trusted tools that are already executed by the action.

## Impact

- Deployment branch integrity can be affected if attacker-controlled branch,
  target folder, clean exclusion, or repository inputs reach the action.
- Tags or commit metadata can be manipulated if attacker-controlled tag,
  commit-message, git-config-name, or git-config-email inputs reach the action.
- The blast radius is the permissions of the token or SSH key supplied to the
  workflow.

## Recommendation

- Refactor `execute` to accept an executable plus an explicit argument array,
  and update all callers to pass user-controlled values as single arguments.
- Insert `--` before path/ref-like operands where supported.
- Validate Git refs, repository names, tag names, and target folders against
  expected allowlists before invoking Git/Rsync.
- Quote or escape Rsync exclude patterns using an argument array rather than
  concatenating them into a string.
- Document that untrusted workflow inputs must not be forwarded to deployment
  inputs until the command construction is hardened.

## Disclosure status

No upstream disclosure was made during this scout cycle.

## Scout notes

The requested control files (`AGENTS.md`, `TARGET_POLICY.md`,
`REPORT_TEMPLATE.md`, and `memory/security-scout-memory.md`) were not present in
the checkout, so this report uses the standard scout sections needed to capture
the target, evidence, impact, and recommendation while keeping writes inside the
repository.
