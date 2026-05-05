# OSS Security Scout Report

## Run metadata

- **Run type:** initial
- **Date:** 2026-05-05
- **Scout cycle:** 1 (single cycle as instructed)
- **Control repo:** `safeengineauto/github-pages-deploy-action`
- **Control repo branch / commit when starting cycle:** `dev` @ `8072b9c7e8f9bd5cda32539dde262854f2073722`
- **Target repo audited:** [`peaceiris/actions-gh-pages`](https://github.com/peaceiris/actions-gh-pages)
- **Target commit audited:** `4b09552702d0b65573696410d4707c765da2630b`
  ("ci: change automerge to false", current tip of `main` at the time of this cycle)
- **Disclosure:** none performed during this scout cycle.

## Control-files note

The four requested control files (`AGENTS.md`, `TARGET_POLICY.md`,
`REPORT_TEMPLATE.md`, `memory/security-scout-memory.md`) were **not present** in
this checkout of the control repo. Two earlier scout-cycle remote branches
(`origin/cursor/security-scout-initial-e961`,
`origin/cursor/security-scout-initial-gh-pages-action-bd3f`) had already
bootstrapped a `memory/security-scout-memory.md` independently. Following the
"only write inside this control repository" and "avoid targets already in
memory" rules, I:

- Read both prior memory snapshots and unioned their avoid lists.
- Treated previously covered targets as off-limits for this cycle:
  `release-drafter/release-drafter` (cross-check, 2026-05-05) and
  `JamesIves/github-pages-deploy-action` (initial, 2026-05-05).
- Picked a fresh target in the same problem domain (GitHub Pages
  deployer action) that was *not* already on the avoid list:
  `peaceiris/actions-gh-pages`.
- This run's report uses the standard scout sections (target, evidence,
  reachability, severity, recommendation) since no `REPORT_TEMPLATE.md` was
  available to mirror.

## Executive summary

`peaceiris/actions-gh-pages` builds a publishing branch by copying the contents
of the workflow-author-supplied `publish_dir` into a workdir under `$HOME` and
then `git push`ing that workdir to a GitHub Pages branch using the supplied
`github_token` / `personal_token` / `deploy_key`. The copy step uses
`shelljs.cp('-RfL', …)`, which follows symlinks. Symlinks present inside the
publish directory are therefore *resolved and committed as their target file's
contents* into the deployment branch.

In a deployment that is otherwise a normal author-controlled `push` flow this
is benign — the workflow author already controls the publish directory.
However, the action explicitly supports several workflow patterns where the
publish directory is built from less-trusted content while the runner still
holds a privileged token (typical "build static docs from PR / external repo"
configurations documented in the README and in CI examples in the wild). In
those workflows, an attacker who can plant a symlink in the build output can
cause the action to commit and push an arbitrary file from the runner
filesystem (any path readable as the runner user) into the deployment branch
or external repository.

I treat this as a confirmed integrity / disclosure bug with conditional
reachability. **Severity: P3 (defense-in-depth / footgun).** Fixing it is
small (`cp -Rf` instead of `cp -RfL`, or a pre-copy walk that drops symlinks)
and removes a footgun that several documented workflow patterns step on.

I also flag two lower-severity items found during the same review:

1. `pushTag` lets `tag_name` flow into the working tree's tag/refspec without
   any validation, so values like `--force` or refspecs in `tag_name` are
   passed through `@actions/exec` as separate `git tag` arguments. Because
   `@actions/exec` *does* tokenise its `args` array element-wise (no shell),
   this is **not** an argv injection — but the input also is not validated as
   a tag-name shape.
2. `setSSHKey` writes the deploy key and SSH config to `~/.ssh/...` and uses
   a fixed `SSH_AUTH_SOCK=/tmp/ssh-auth.sock` regardless of any pre-existing
   socket. On a self-hosted runner shared between jobs, that is a known foot
   gun but consistent with the `actions/runner` model.

The full reachability / impact / fix discussion below applies to the primary
finding (symlink dereference in `copyAssets`).

## Scope reviewed

| Area                                     | File                                  |
|------------------------------------------|---------------------------------------|
| Action input surface                     | `action.yml`, `src/get-inputs.ts`     |
| Auth setup (token, PAT, SSH deploy key)  | `src/set-tokens.ts`                   |
| Repo init / clone / orphan-branch logic  | `src/git-utils.ts`                    |
| Asset copy + exclude glob                | `src/git-utils.ts` (`copyAssets`,     |
|                                          | `deleteExcludedAssets`)               |
| Commit / push / tag flow                 | `src/git-utils.ts`, `src/main.ts`     |
| Workdir / CNAME / .nojekyll handling     | `src/utils.ts`, `src/main.ts`         |
| Documented workflow examples             | `README.md`                           |

I did **not** inspect:

- The shipped `lib/index.js` bundle (assumed to be a build of `src/`).
- Transitive dependency CVEs (would require dependency triage out of scope).
- Tag/version-pinning behavior on consumer repos.

## Primary finding — symlink dereference in `copyAssets` ⇒ workspace-escape file leak into the publish branch

### Sink

`src/git-utils.ts` lines 41–65:

```typescript
export async function copyAssets(
  publishDir: string,
  destDir: string,
  excludeAssets: string
): Promise<void> {
  core.info(`[INFO] prepare publishing assets`);

  if (!fs.existsSync(destDir)) {
    core.info(`[INFO] create ${destDir}`);
    await createDir(destDir);
  }

  const dotGitPath = path.join(publishDir, '.git');
  if (fs.existsSync(dotGitPath)) {
    core.info(`[INFO] delete ${dotGitPath}`);
    rm('-rf', dotGitPath);
  }

  core.info(`[INFO] copy ${publishDir} to ${destDir}`);
  cp('-RfL', [`${publishDir}/*`, `${publishDir}/.*`], destDir);

  await deleteExcludedAssets(destDir, excludeAssets);

  return;
}
```

Two things matter:

1. **`-L` follows symlinks**, dereferencing them. `shelljs`'s `-L` flag
   matches POSIX `cp -L`: when a symlink is encountered, the target's contents
   are copied, not the link itself.
2. **Glob expansion is `${publishDir}/*` and `${publishDir}/.*`** — both
   visible regular files *and dotfiles* (e.g. `.env`, `.npmrc`) inside the
   publish directory get walked.

After `copyAssets`, `setRepo` ➜ `git add --all` ➜ `commit` ➜ `push origin <publish_branch>`
publishes the resulting tree.

I confirmed the dereference behavior at the OS level on this runner:

```
$ mkdir -p /tmp/symlink-test/{src,dst}
$ echo "TOKEN=secret-data-here" > /tmp/symlink-test/secret.txt
$ ln -sf /tmp/symlink-test/secret.txt /tmp/symlink-test/src/leak
$ cp -RfL /tmp/symlink-test/src/. /tmp/symlink-test/dst/
$ cat /tmp/symlink-test/dst/leak
TOKEN=secret-data-here
```

`shelljs.cp('-RfL', ...)` invokes the same `cp(1)` semantics; the `-L`
("dereference") option is implemented by reading through the link in
`shelljs/src/cp.js`.

### Resulting primitive

For any file `F` on the runner that the action's UID can read, an attacker
who controls the contents of `publish_dir` can:

- Place `ln -s F some_name` inside `publish_dir`.
- Cause the action to `cp -RfL` the symlink, embedding `F`'s contents at
  `<destDir>/some_name`.
- The downstream `git add --all` + `git commit` + `git push` writes that
  content to the publish branch (or the external repo if `external_repository`
  is configured), under the token in use.

`destDir` is `workDir` (`$HOME/actions_github_pages_<unixTime>`) for the
default deploy, and `path.join(workDir, inps.DestinationDir)` when
`destination_dir` is set. Either way the file lands inside the to-be-pushed
git tree.

### Files of interest readable by the runner UID

This is environment-dependent, but all of the following are commonly
readable by the same UID running the deploy step on a hosted GitHub
runner and are interesting to leak:

- `$HOME/.netrc`, `$HOME/.git-credentials` (token material set up by
  `actions/checkout` or other steps). On a hosted runner, by default,
  `~/.git-credentials` is **not** persisted by `actions/checkout`, but
  workflows that explicitly `git config --global credential.helper store`
  do create one.
- `$HOME/.ssh/id_*` if the workflow earlier ran a custom step that wrote a
  key.
- The job-temporary directory `$RUNNER_TEMP` and earlier action workdirs (
  e.g. caches with private content).
- On self-hosted runners: `/etc/passwd`, the runner's `.runner` config, the
  service-account `$HOME/.aws/credentials`, etc.

The primitive is therefore "**arbitrary file read on the runner UID, exfil
via git push of attacker-controlled symlinks**". Importantly, the published
git push is performed with the token the workflow author granted to the
action, so the attacker doesn't need to recover a token — the action does
the publishing under the workflow's own credentials.

### Reachability — when does `publish_dir` carry attacker-controlled content?

The action's *intended* model is "workflow author builds static site, action
deploys it". In that model the workflow author already trusts every byte
under `publish_dir`. Symlink dereference is benign there.

The realistic problematic configurations I identified, all of which are
explicitly demonstrated in the README or are common in third-party CI
examples:

| Pattern                                                                                  | Trust level of `publish_dir` contents                              | Vulnerable? |
|------------------------------------------------------------------------------------------|--------------------------------------------------------------------|-------------|
| `on: push` to default branch, build then deploy                                          | repo writers only                                                  | No (no new boundary). |
| `on: pull_request_target` + checkout PR head + build + deploy preview to gh-pages        | PR author (untrusted) builds bytes that end up in `publish_dir`    | **Yes.** PR author can drop a symlink into the build artefact directory; deploy step runs with the privileged `pull_request_target` token. |
| `on: pull_request` from a fork without `pull_request_target`, deploying to *external* repo via `personal_token` / `deploy_key` | PR author (untrusted)                                              | **Yes**, when the workflow author wires it that way (uncommon, but the README shows the `external_repository` + `personal_token` / `deploy_key` shape needed). |
| Workflow that downloads an artifact built by an earlier `pull_request` job, then deploys (via `actions/download-artifact` with explicit `run_id`) | Author of the earlier-job source (PR author)                       | **Yes** — same vector. |
| `on: workflow_run` triggered by a fork's CI job, then promoting that artifact to gh-pages | PR author                                                          | **Yes** — the action *cannot* tell the publish dir came from an untrusted CI build. |

So the primitive is reachable in the (well-documented and recommended)
"deploy preview from PR" patterns. The action's defaults *almost* mitigate
this — `skipOnFork()` (`src/utils.ts:57-70`) refuses to deploy on a forked
repo when no token/key is set — but `skipOnFork` is bypassed whenever any
auth input is present. Any workflow that wires preview deploys with a token
sets a token, so `skipOnFork` provides no protection in the very pattern that
matters.

### Why `git add --all` doesn't save us

It is tempting to think that `git add` would commit the symlink as a symlink
(`120000` mode) rather than its target. That is true if the **filesystem**
still contains a symlink. But by the time `git add --all` runs, `cp -RfL`
has already replaced the symlink with a *copy of the target file's bytes*
in `destDir`. So `git add` is adding a regular blob containing the leaked
content, not a symlink object.

### Why `excludeAssets` doesn't save us

`exclude_assets` defaults to `.github` and uses `@actions/glob`. An attacker
controls names freely (anything not literally inside `.github` or whatever
the workflow author configured). And the dereferenced copy already happens
before `deleteExcludedAssets` runs — so even if a name matched the exclude
pattern, the *content* has already been written to disk and could be
recovered by a parallel attacker step in another job (less relevant; the
push happens after).

### Severity rationale

| Factor                                                                                  | Outcome |
|------------------------------------------------------------------------------------------|---------|
| Crosses a privilege boundary (untrusted PR author ⇒ runner / token contents)?           | **Yes**, in PR-preview deploy patterns documented as supported. |
| Default workflow exploitable?                                                            | No. Default `on: push` flow is intra-trust. |
| Requires workflow-author cooperation in unsafe shape?                                    | Yes — the workflow author has to wire PR/forked content into `publish_dir`. But the README *recommends* exactly this for previews. |
| Mitigations available without code change?                                               | Workflow authors can sanitize `publish_dir` before invocation, e.g. `find . -type l -delete`. None of the action's docs warn about this. |
| Fix size                                                                                  | Small: drop `-L`, or pre-walk to drop symlinks, plus a docs note. |

I am calling this **P3 (defense-in-depth / footgun)** rather than P2/P1 because:

- It requires the workflow author to opt into a workflow shape that mixes
  untrusted content with privileged tokens. Several action features (`external_repository`,
  `personal_token`, `deploy_key`) exist *only* to enable that shape, and the
  README documents it, but the most-common usage (`on: push` build &
  deploy) is unaffected.
- The post-condition the action should plausibly guarantee — "I publish
  what was in `publish_dir` and nothing else" — is silently violated even
  in single-trust workflows, which is the contract-violation reason the
  fix is worth landing.

If a future revision adds a "trusted PR preview" feature (or any feature
that pipes fork-content into `publish_dir` automatically), this becomes a
real cross-boundary leak and should be re-rated up.

## Secondary finding — `tag_name` and `tag_message` flow into `git tag` without validation

`src/git-utils.ts:226-240`:

```typescript
export async function pushTag(tagName: string, tagMessage: string): Promise<void> {
  if (tagName === '') {
    return;
  }

  let msg = '';
  if (tagMessage) {
    msg = tagMessage;
  } else {
    msg = `Deployment ${tagName}`;
  }

  await exec.exec('git', ['tag', '-a', `${tagName}`, '-m', `${msg}`]);
  await exec.exec('git', ['push', 'origin', `${tagName}`]);
}
```

`@actions/exec` passes `args` to `child_process.spawn` *without* a shell, so
each element is a separate argv slot — there is no argv injection: a
`tagName` of `--force` becomes a single literal `tag` argument to `git tag`,
which `git` itself rejects (`fatal: '--force' is not a valid tag name`).

**This is therefore not exploitable as command injection.** The
worth-mentioning sub-issue is that `tag_name` is also used as the `refspec`
in `git push origin ${tagName}`. If `tagName` is `:refs/heads/main`, the
push refspec means "delete the remote `main` branch". But `git tag`
already failed first (an invalid tag name), so the push step never runs in
practice. I tried to find an input that passes `git tag`'s validator but
behaves badly as a `git push` refspec; I could not (the Git tag-name
ruleset, RFC-style "no `:` allowed", is strict enough to forbid the cases
that would matter here).

So this is **not a finding**; I'm flagging it because the *contract* "tag
name has the shape of a Git ref" is enforced only by Git's own validator
downstream, and a future refactor that, say, builds the refspec
differently could turn it back into a real bug. A whitelist regex (e.g.
`^[A-Za-z0-9_./-]+$`) at the input layer would future-proof it.

## Secondary finding — fixed `SSH_AUTH_SOCK=/tmp/ssh-auth.sock`

`src/set-tokens.ts:62-63`:

```typescript
await cpexec('ssh-agent', ['-a', '/tmp/ssh-auth.sock']);
core.exportVariable('SSH_AUTH_SOCK', '/tmp/ssh-auth.sock');
```

A predictable `/tmp` path for the SSH agent socket on a multi-tenant or
self-hosted runner could let another local user attach to or hijack the
agent. On hosted GitHub-managed runners this is single-tenant per job, so
the risk is low. Worth changing to a per-job temporary path under
`$RUNNER_TEMP` for self-hosted users; not a stand-alone vuln.

## Non-finding — `getServerUrl().host` interpolation in remote URL strings

`set-tokens.ts:100`:

```typescript
return `https://x-access-token:${githubToken}@${getServerUrl().host}/${publishRepo}.git`;
```

`getServerUrl()` is `new URL(process.env.GITHUB_SERVER_URL || 'https://github.com')`.
`URL.host` is structured (no path / query injection), so even if
`GITHUB_SERVER_URL` is attacker-supplied (it is set by GitHub itself, so it
is not), the result remains a syntactically valid URL host. The
`.git`/`/${publishRepo}` suffix is appended after host, which is the
intended shape. No injection here.

## Non-finding — `GITHUB_ACTOR` interpolation into `git config user.{name,email}`

`getUserName` / `getUserEmail` fall back to `${process.env.GITHUB_ACTOR}` and
`${process.env.GITHUB_ACTOR}@users.noreply.github.com`. `GITHUB_ACTOR` is
set by GitHub Actions itself; it is not under attacker control in any
known event payload. `git config` invocations use `exec.exec('git', […])`
with separate argv elements, so even an exotic actor name with embedded
spaces would be passed as a single argv slot.

## Recommended fixes

### 5.1 Drop `-L` in `copyAssets` (primary fix)

```typescript
cp('-Rf', [`${publishDir}/*`, `${publishDir}/.*`], destDir);
```

This commits symlinks as symlinks (Git stores them as 120000-mode entries).
That preserves the action's intended "publish what's in the directory"
contract, eliminates the leak primitive, and matches the way `actions/checkout`
itself treats symlinks (it preserves them). Workflow authors who *want*
target dereference can `find publish/ -type l -exec sh -c 'cp -L "$1" "$1.tmp" && mv "$1.tmp" "$1"' _ {} \;`
themselves before the action.

### 5.2 Or: pre-copy symlink-walk that errors out

If the maintainers prefer keeping `-L` for backward compatibility, perform an
explicit pre-walk:

```typescript
const findSymlinks = (root: string) => /* walk & collect symlinks */ ;
const links = findSymlinks(publishDir);
if (links.length) {
  throw new Error(
    `publish_dir contains symlinks (${links[0]}, …); refusing to dereference. ` +
    `Either replace them with regular files or set publish_dir to a directory without symlinks.`
  );
}
```

Either change blocks the leak primitive completely.

### 5.3 Validate `tag_name` shape

Add an input-layer regex check in `getInputs()`:

```typescript
const tagName = core.getInput('tag_name');
if (tagName && !/^[A-Za-z0-9_./-]+$/.test(tagName)) {
  throw new Error(`tag_name has invalid shape: ${tagName}`);
}
```

### 5.4 Use a per-job SSH agent socket

```typescript
const sock = path.join(process.env.RUNNER_TEMP || '/tmp', `ssh-auth-${process.pid}.sock`);
await cpexec('ssh-agent', ['-a', sock]);
core.exportVariable('SSH_AUTH_SOCK', sock);
```

## Summary table

| Question                                                                                  | Answer |
|--------------------------------------------------------------------------------------------|--------|
| Does `copyAssets` follow symlinks during publish?                                          | **Yes** (`cp -RfL`). |
| Does the dereferenced content end up in the pushed deploy branch?                          | **Yes** — `git add --all` ➜ `git commit` ➜ `git push origin <publish_branch>`. |
| Can an unprivileged actor (PR author, fork) reach `publish_dir` in idiomatic deploy flows? | **Yes**, in PR-preview / external-repo deploy patterns the README documents. |
| Is the default `on: push` deploy flow exploitable?                                         | **No**, no boundary crossing. |
| Argv injection through `git tag`/`git push`?                                                | **No**, `@actions/exec` argv-tokenises. |
| Is `tag_name` validated as a tag-name shape?                                                | **No**, only Git's downstream validator catches it. |
| Should the symlink behavior be fixed?                                                       | **Yes** — small change (drop `-L` or pre-walk). |
| Severity                                                                                    | **P3** (defense-in-depth / footgun). |

## Disclosure status

No upstream disclosure was made during this scout cycle. The maintainers'
security policy in `SECURITY.md` of `peaceiris/actions-gh-pages` should be
followed if a follow-up cycle promotes this finding for disclosure.

## Suggested follow-up cycles

1. Audit `peaceiris/actions-gh-pages` workflows that integrate the action with
   `pull_request_target`, `workflow_run`, or `external_repository` and confirm
   real exploitability of the symlink primitive against a token-holding deploy.
2. Audit other GitHub Pages deployer actions (`crazy-max/ghaction-github-pages`,
   `actions/deploy-pages`) for the same `cp -L` pattern.
3. Build a regression test fixture that asserts symlinks in `publish_dir` are
   either preserved (post-fix) or refused (post-fix-with-error).
