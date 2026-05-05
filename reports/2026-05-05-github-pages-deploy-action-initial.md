# OSS Security Scout Report

## Metadata

- **Run type:** initial
- **Target repo:** `JamesIves/github-pages-deploy-action`
- **Control repo commit audited:** `8072b9c7e8f9bd5cda32539dde262854f2073722`
- **Commit title:** `build(deps): bump lodash from 4.17.23 to 4.18.1 (#1966)`
- **Scout cycle date:** 2026-05-05
- **Memory status before cycle:** `memory/security-scout-memory.md` was absent in this checkout. I treated the avoid list as empty, except for the already-visible remote report target `release-drafter/release-drafter`.

## Executive summary

I ran one initial OSS Security Scout cycle against the checked-out GitHub Pages deploy action. The most interesting attack surface is the action's construction of `git`, `rsync`, and `chmod` command lines from action inputs and GitHub event metadata.

No confirmed reportable vulnerability was found in this cycle. The risky-looking command construction is reachable from workflow-author-controlled inputs such as `branch`, `folder`, `target-folder`, `commit-message`, `clean-exclude`, `repository-name`, `tag`, and optional git identity fields. I did not find a path where a less-trusted party, such as a pull request author, comment author, or fork contributor, can influence these sinks without the workflow first explicitly wiring untrusted event data into the action's `with:` block.

## Scope reviewed

- `action.yml` input surface:
  - `folder`, `target-folder`, `commit-message`, `clean-exclude`, `repository-name`, `branch`, `tag`, `token`, `ssh-key`, and git identity inputs.
- Runtime configuration and defaults:
  - `src/constants.ts`
  - `src/util.ts`
  - `src/lib.ts`
- Command execution and deployment flow:
  - `src/execute.ts`
  - `src/git.ts`
  - `src/worktree.ts`
  - `src/ssh.ts`
- Documentation examples in `README.md`, especially the documented `push` trigger and `contents: write` permission.

## Candidate investigated: command/argument injection through action inputs

### Why this looked interesting

The deployment flow interpolates action-controlled strings into command lines before passing them to the shared `execute` helper:

```ts
await execute(
  `git ls-remote --heads ${action.repositoryPath} refs/heads/${action.branch}`,
  action.workspace,
  action.silent
)
```

```ts
await execute(
  `rsync -q -av --checksum --progress ${isMkpathSupported && action.targetFolder ? '--mkpath' : ''} ${action.folderPath}/. ${
    action.targetFolder
      ? `${temporaryDeploymentDirectory}/${action.targetFolder}`
      : temporaryDeploymentDirectory
  } ${action.clean ? `--delete ${excludes} ...` : ''} ...`,
  action.workspace,
  action.silent
)
```

```ts
await execute(
  `git commit -m "${commitMessage}" --quiet --no-verify`,
  `${action.workspace}/${temporaryDeploymentDirectory}`,
  action.silent
)
```

Other similar sinks include `git fetch`, `git push`, `git tag`, `git checkout`, `git config user.name`, and `git config user.email`.

### Reachability analysis

The relevant fields are sourced from `getInput(...)` in `src/constants.ts`, from process environment values set by GitHub Actions, or from GitHub's event payload:

- Workflow-author-controlled inputs:
  - `branch`
  - `folder`
  - `target-folder`
  - `commit-message`
  - `clean-exclude`
  - `repository-name`
  - `tag`
  - `git-config-name`
  - `git-config-email`
  - `token`
  - `ssh-key`
- GitHub-provided or repository-scoped metadata:
  - `GITHUB_WORKSPACE`
  - `GITHUB_REPOSITORY`
  - `GITHUB_SHA`
  - `GITHUB_SERVER_URL`
  - `github.context.payload.repository.full_name`
  - `github.context.payload.pusher.name`
  - `github.context.payload.pusher.email`

The README's primary documented workflow runs on `push` with `contents: write`. That is the expected deployment model: a workflow author grants the action write access and statically configures the inputs.

I did not identify a default path where a fork pull request author, issue/comment author, or other lower-privileged actor can supply any of the command-interpolated fields. A vulnerable workflow could choose to pass untrusted data into these fields, for example by setting `commit-message` or `target-folder` from an event field, but that would be a workflow-specific unsafe composition rather than a vulnerability in the action's default behavior.

### Boundary assessment

The command construction should still be hardened because it is brittle:

- `clean-exclude` values are appended as `--exclude ${item}` and will be parsed as multiple arguments if a pattern contains whitespace.
- `commit-message` is embedded inside quotes in the command string and can affect argument parsing if it contains quote characters.
- `branch`, `tag`, and `target-folder` are not validated against expected Git ref/path shapes before command construction.

However, these are all controlled by the workflow author in the normal trust model. A workflow author with the ability to edit the workflow can already run arbitrary commands in adjacent `run:` steps using the same token and secrets. Therefore the behavior does not cross a meaningful privilege boundary by itself.

## Non-finding: deployment folder path traversal

`generateFolderPath` allows absolute paths and `~` expansion:

```ts
export const generateFolderPath = (action: ActionInterface): string => {
  const folderName = action['folder']
  return path.isAbsolute(folderName)
    ? folderName
    : folderName.startsWith('~')
      ? folderName.replace('~', process.env.HOME as string)
      : path.join(action.workspace, folderName)
}
```

That can cause the action to deploy files outside `GITHUB_WORKSPACE` if the workflow author sets `folder` that way. I did not classify this as a vulnerability because the README documents absolute/`~` paths as supported behavior, and the workflow author controls which local build output gets published.

## Non-finding: SSH known_hosts behavior on custom hosts

`configureSSH` writes GitHub.com public host keys under `action.hostname`, which is derived from `GITHUB_SERVER_URL`:

```ts
const sshGitHubKnownHostRsa = `\n${action.hostname} ssh-rsa ...\n`
const sshGitHubKnownHostDss = `\n${action.hostname} ssh-dss ...\n`
```

For GitHub Enterprise Server, this is more likely to cause SSH host-key validation failures than to create a useful attacker primitive. I did not find a way for a less-trusted actor to exploit it without already controlling the runner environment or workflow.

## Verdict

- **Confirmed vulnerability:** none in this cycle.
- **Security impact:** no reportable cross-boundary issue identified.
- **Hardening recommendation:** refactor `execute` callers to pass argument arrays instead of constructing command strings, and validate structured inputs such as branch names, tags, paths, and rsync exclude patterns before invoking tools.

## Suggested follow-up

If this target is revisited, focus on workflow-composition hazards:

1. Workflows that use this action under `pull_request_target`.
2. Workflows that map untrusted event fields into `commit-message`, `target-folder`, `clean-exclude`, `branch`, or `tag`.
3. Whether `@actions/exec` command-line parsing produces surprising argument boundaries for quoted values containing embedded quotes.
