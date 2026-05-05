# Security Scout report - JamesIves/github-pages-deploy-action

- **Run type:** initial
- **Target repo:** `JamesIves/github-pages-deploy-action` (checked out here as `safeengineauto/github-pages-deploy-action`)
- **Commit audited:** `8072b9c7e8f9bd5cda32539dde262854f2073722`
  (`build(deps): bump lodash from 4.17.23 to 4.18.1 (#1966)`)
- **Reviewer:** OSS Security Scout
- **Control-file note:** `AGENTS.md`, `TARGET_POLICY.md`, `REPORT_TEMPLATE.md`, and
  `memory/security-scout-memory.md` were requested but were not present in the
  checkout or elsewhere on the filesystem. This report follows the structured
  markdown style used by the existing scout report branch.

## Scope

This cycle reviewed the action implementation paths that handle attacker- or
workflow-controlled data:

- action input parsing in `src/constants.ts`
- path and repository helpers in `src/util.ts`
- git, worktree, rsync, and tag operations in `src/git.ts` and `src/worktree.ts`
- process execution in `src/execute.ts`
- SSH setup in `src/ssh.ts`
- user-facing input contract in `action.yml` and `README.md`

## Verdict

I did not confirm a P1/P2 vulnerability with a clear lower-trust attacker path.

The main security weakness is broad command-line argument construction from
action inputs. The implementation passes a single composed command string to
`@actions/exec`; on Linux this is parsed into argv by the toolkit rather than
executed through a shell, so shell metacharacters such as `;` or `$()` are not a
direct command-execution primitive. However, embedded quotes and whitespace can
still break values into additional argv entries for `git` and `rsync`.

That is a real hardening issue for a widely used deploy action, especially if a
consumer workflow interpolates less-trusted event fields into inputs such as
`commit-message`, `branch`, `tag`, `target-folder`, or `clean-exclude`. In the
default documented usage, those inputs are workflow-author-controlled, so the
same actor already controls the job and its token permissions.

## Finding candidates

### 1. Argument injection through composed `git`/`rsync` command strings

**Severity:** P3/P4 hardening, context-dependent  
**Status:** Real weakness, not confirmed as a high-impact vulnerability in the
documented trust model

The wrapper accepts a complete command line:

```ts
// src/execute.ts:29-44
export async function execute(
  cmd: string,
  cwd: string,
  silent: boolean,
  ignoreReturnCode: boolean = false
): Promise<ExecuteOutput> {
  output.stdout = ''
  output.stderr = ''

  await exec(cmd, [], {
    silent,
    cwd,
    listeners: {stdout, stderr},
    ignoreReturnCode
  })
}
```

Callers interpolate action inputs directly into that string, for example:

```ts
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

```ts
// src/git.ts:172-202
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
// src/git.ts:254-258
await execute(
  `git commit -m "${commitMessage}" --quiet --no-verify`,
  `${action.workspace}/${temporaryDeploymentDirectory}`,
  action.silent
)
```

```ts
// src/git.ts:337-346
await execute(
  `git tag ${action.tag}`,
  `${action.workspace}/${temporaryDeploymentDirectory}`,
  action.silent
)
await execute(
  `git push origin ${action.tag}`,
  `${action.workspace}/${temporaryDeploymentDirectory}`,
  action.silent
)
```

The toolkit command parser treats quote characters as syntax. If an input value
contains a double quote, the value can escape the intended argument and add
extra argv entries to the underlying tool. This affects several inputs:

- `git-config-name` / `git-config-email`
- `branch`
- `repository-name` and the derived `repositoryPath`
- `folder` / derived `folderPath`
- `target-folder`
- `commit-message`
- `clean-exclude`
- `tag`

This is not equivalent to `/bin/sh -c` command execution on Linux, but it can
alter `git` or `rsync` behavior in ways the workflow author did not intend if
untrusted event text is forwarded into these inputs.

**Impact examples:**

- A dynamic `commit-message` can be split into extra `git commit` options.
- `clean-exclude` entries can become extra `rsync` arguments instead of literal
  exclude patterns.
- `tag` and `branch` values can become malformed ref arguments or additional
  options to git subcommands.

**Trust boundary assessment:**

The README shows these values as static `with:` configuration in the workflow.
Under that model, the actor who controls the values also controls arbitrary
workflow steps and the deployment token configuration, so there is no new
privilege boundary.

The risk becomes security-relevant when a consumer workflow maps lower-trust
event fields into these inputs, for example PR titles, issue text, dispatch
payloads, or branch names from less-trusted contributors. In those workflows,
the action treats event strings as argv syntax rather than data.

**Suggested fix:**

Refactor `execute` call sites to pass tools and arguments separately, e.g.
`exec('git', ['commit', '-m', commitMessage, '--quiet', '--no-verify'], ...)`.
For fields that are git refs, repository names, or tag names, add explicit
validation before execution.

### 2. `clean-exclude` is documented as patterns but parsed as raw CLI tokens

**Severity:** P4 hardening  
**Status:** Confirmed behavior, context-dependent impact

`clean-exclude` is split into lines in `src/constants.ts`:

```ts
// src/constants.ts:106-108
cleanExclude: (getInput('clean-exclude') || '')
  .split('\n')
  .filter(l => l !== ''),
```

Each line is then appended as unquoted command text:

```ts
// src/git.ts:156-161
let excludes = ''
if (action.clean && action.cleanExclude) {
  for (const item of action.cleanExclude) {
    excludes += `--exclude ${item} `
  }
}
```

The README describes `clean-exclude` as file or folder patterns:

```md
README.md:111
| `clean-exclude` | If you need to use `clean` but you'd like to preserve certain files or folders you can use this option. This should contain each pattern as a single line in a multiline string. |
```

Patterns containing spaces or leading option-looking strings are not passed as a
single literal pattern. They are parsed as additional argv tokens by
`@actions/exec`, changing rsync semantics.

**Suggested fix:**

Build the rsync invocation as argv. Add each pattern as a separate
`--exclude`, `<pattern>` pair.

### 3. `folder` accepts absolute and home-relative paths despite action metadata

**Severity:** P4 hardening / documentation mismatch  
**Status:** Confirmed behavior

The action metadata states:

```yaml
# action.yml:39-41
folder:
  description: '... Folder paths cannot have a leading / or ./. If you wish to deploy the root directory you can place a . here.'
```

The implementation accepts absolute paths and expands `~`:

```ts
// src/util.ts:46-53
export const generateFolderPath = (action: ActionInterface): string => {
  const folderName = action['folder']
  return path.isAbsolute(folderName)
    ? folderName
    : folderName.startsWith('~')
      ? folderName.replace('~', process.env.HOME as string)
      : path.join(action.workspace, folderName)
}
```

The README also says absolute paths via `~` are supported:

```md
README.md:91
You can also utilize absolute file paths by prepending `~` to your folder path.
```

The selected path is later made writable and copied to the deployment branch:

```ts
// src/git.ts:146-150
await execute(
  `chmod -R +rw ${action.folderPath}`,
  action.workspace,
  true
)
```

```ts
// src/git.ts:172-202
rsync ... ${action.folderPath}/. ...
```

This can publish or mutate files outside `GITHUB_WORKSPACE` if a workflow
author configures such a path. That is mostly an expected consequence of
allowing absolute paths, but the metadata and README disagree and the behavior
is risky on self-hosted runners.

**Suggested fix:**

Choose one contract and enforce it. The safer default is to require `folder` to
resolve inside `GITHUB_WORKSPACE`, with an explicit opt-in if absolute paths are
intentionally supported.

## Non-findings

### Shell metacharacter command execution

I did not confirm direct shell command injection. The current
`@actions/exec` implementation parses the command line and spawns the selected
tool without `/bin/sh` on Linux. The risk is argv injection into `git`/`rsync`,
not arbitrary shell syntax execution.

### SSH key setup

`src/ssh.ts` feeds private keys to `ssh-add` over stdin and invokes
`ssh-agent`/`ssh-add` as fixed commands. I did not find a separate injection or
secret disclosure path in this cycle.

### Token masking

`generateRepositoryPath` embeds the token in the remote URL, but error handling
masks the token and full repository path unless debug mode is enabled:

```ts
// src/util.ts:107-126
export const suppressSensitiveInformation = (
  str: string,
  action: ActionInterface
): string => {
  let value = str

  if (isDebug()) {
    return value
  }
  ...
}
```

Debug-mode unmasking is operationally risky but expected behavior for GitHub
Actions debugging and not a standalone vulnerability without a concrete leak
path.

## Recommendations

1. Replace composed command strings with tool-plus-argv execution throughout
   `src/git.ts` and `src/worktree.ts`.
2. Validate git ref-like fields (`branch`, `tag`) with git's own ref validation
   or a strict allowlist before use.
3. Treat `clean-exclude` lines as literal rsync pattern arguments.
4. Reconcile and enforce the `folder` path contract.
5. Add tests with quotes, spaces, leading dashes, and multiline values for all
   command-bound inputs.
