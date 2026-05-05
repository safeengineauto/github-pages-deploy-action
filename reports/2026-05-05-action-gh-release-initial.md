# OSS Security Scout Report

## Metadata

- **Run type:** initial
- **Target repo:** `softprops/action-gh-release`
- **Target commit reviewed:** `2bc819c87a4e63a4ac4e581a02085318bd49975a`
  ("chore(deps): bump postcss from 8.5.9 to 8.5.10 (#789)")
- **Default branch reviewed:** `master`
- **Control repo commit at cycle start:** `8072b9c7e8f9bd5cda32539dde262854f2073722`
- **Scout cycle date:** 2026-05-05
- **Memory status before cycle:** `memory/security-scout-memory.md`,
  `AGENTS.md`, `TARGET_POLICY.md`, and `REPORT_TEMPLATE.md` were all absent on
  the checked-out `dev` branch. The avoid list was reconstructed from the two
  pre-existing remote scout branches
  (`origin/cursor/release-drafter-p1-crosscheck-de06`,
  `origin/cursor/security-scout-initial-e961`) and the implied target list
  inside their reports/memory. Targets covered before this cycle:
  - `release-drafter/release-drafter` (cross-check)
  - `JamesIves/github-pages-deploy-action` (initial)

  This cycle deliberately picked a different popular GitHub Action target.

## Executive summary

I ran one initial OSS Security Scout cycle against `softprops/action-gh-release`
at the commit above. The most interesting attack surface is the action's
filesystem reads driven by workflow inputs:

- `body_path` is fed straight into `readFileSync` and the contents become the
  public release body.
- `files` patterns are passed to `glob.sync` with `cwd = working_directory`
  but **without** any "stay under `cwd`" containment, so absolute paths,
  `~/...` home-directory expansion, and `../` traversal can pull files from
  anywhere on the runner into a public release as assets.

Both behaviors are reachable from workflow-author-controlled inputs. I did
**not** find a path where a strictly less-trusted party (PR author, fork
contributor, comment author, untrusted `workflow_dispatch` caller) reaches
these sinks without the consuming workflow first explicitly wiring untrusted
event data into the action's `with:` block. The default GitHub Actions trust
boundary therefore is not crossed.

**No confirmed reportable vulnerability** for this scout cycle. The findings
below are documented as defense-in-depth/hardening opportunities and as a
warning to consumers who plumb untrusted event data into `body_path` /
`files` / `working_directory`.

## Scope reviewed

- `action.yml` input surface and defaults.
- TypeScript source under `src/`:
  - `src/main.ts` (orchestration)
  - `src/github.ts` (GitHub REST surface, asset upload, race handling)
  - `src/util.ts` (input parsing, glob/path normalization, body loading)
- Tests under `__tests__/util.test.ts` and `__tests__/github.test.ts` for
  intended semantics around `body_path`, `files`, and `working_directory`.
- `README.md` for the documented threat model and idiomatic invocation.
- `package.json` to confirm dependency surface (`@actions/core@^3`,
  `@actions/github@^9.1`, `glob@^13`, `mime-types@^3`).

I did not review:

- Bundled `dist/index.js` (treated as a build artifact of the reviewed `src/`).
- Vendor packages beyond their package names and major versions.
- The companion `action-gh-release-test` consumer harness.

## Candidate 1 — Arbitrary file read via `body_path`

### Sink

```40:51:src/util.ts
export const releaseBody = (config: Config): string | undefined => {
  if (config.input_body_path) {
    try {
      const contents = readFileSync(config.input_body_path, 'utf8');
      return contents;
    } catch (err: any) {
      console.warn(
        `⚠️ Failed to read body_path "${config.input_body_path}" (${err?.code ?? 'ERR'}). Falling back to 'body' input.`,
      );
    }
  }
  return config.input_body;
};
```

The result of `releaseBody(config)` is passed unchanged into
`createRelease` / `updateRelease` / `prepareReleaseMutation`, which forwards
it as the GitHub release body
(`src/github.ts:155-158`, `src/github.ts:560-588`, `src/github.ts:899`).

### Reachability

`config.input_body_path` is sourced from `env.INPUT_BODY_PATH`, i.e. the
`body_path:` workflow input. There is no normalization, no allowlist, and no
containment check against the workspace.

Concretely, a workflow such as

```yaml
- uses: softprops/action-gh-release@v3
  with:
    body_path: ${{ inputs.changelog_path }}
```

with `inputs.changelog_path` set to `/etc/hostname`, `/home/runner/.docker/config.json`,
`/proc/self/environ`, or any other readable path on the runner would read
that file and place its contents in the **public release body**. On default
GitHub-hosted runners the action's user has read access to `~runner`, the
checkout, the Actions agent's working tree, and (via `/proc/self/environ`)
its own environment, including any secrets passed as env vars to the step.

### Trust boundary analysis

The candidate only crosses a privilege boundary if a *less-trusted* party can
control `body_path`. In idiomatic usage:

| Caller pattern                                                         | Source of `body_path`                | Trust vs. workflow author                  |
|------------------------------------------------------------------------|--------------------------------------|--------------------------------------------|
| `body_path: ${{ github.workspace }}-CHANGELOG.txt` (README example)    | static repo content                  | Same as workflow author. No new boundary.  |
| `body_path: ${{ inputs.path }}` from `workflow_dispatch`               | UI dispatcher with `actions:write`   | Same as repo write. No new boundary.       |
| Reusable workflow / `workflow_call`                                    | calling workflow                     | Same trust as the callee's workflow author.|
| `body_path: ${{ github.event.* }}` from `pull_request_target`/`issue_comment` | **PR author / commenter (untrusted)** | Would be a privilege escalation, but no idiomatic example wires this. |

`pull_request_target` is the only realistic GitHub event in which an untrusted
attacker can both supply input strings and have those strings reach an action
running with elevated `GITHUB_TOKEN` permissions. I did not find any
documentation or example in this repo that wires `pull_request_target` event
data into `body_path`, and the README's only `body_path` example is a static
file path. So the misuse is the workflow author's, not the action's, on the
current corpus of guidance.

### Severity

- Workflow-author-controlled `body_path`: P5 (intended behavior).
- `pull_request_target`-fed `body_path`: P1 *if it ever ships*, but no
  current consumer or documented example does this, so unconfirmed in the
  field.
- Defense-in-depth fix: validate that the resolved `body_path` is inside
  `process.cwd()` / `INPUT_WORKING_DIRECTORY` / `GITHUB_WORKSPACE`, or at
  least warn if it points outside.

## Candidate 2 — `files` glob escaping `working_directory` and home expansion

### Sink

```141:173:src/util.ts
export const expandHomePattern = (pattern: string, homeDirectory: string = homedir()): string => {
  if (pattern === '~') {
    return homeDirectory;
  }
  if (pattern.startsWith('~/') || pattern.startsWith('~\\')) {
    return pathLib.join(homeDirectory, pattern.slice(2));
  }
  return pattern;
};

export const normalizeFilePattern = (
  pattern: string,
  platform: NodeJS.Platform = process.platform,
  homeDirectory: string = homedir(),
): string => {
  return normalizeGlobPattern(expandHomePattern(pattern, homeDirectory), platform);
};

export const paths = (patterns: string[], cwd?: string): string[] => {
  return patterns.reduce((acc: string[], pattern: string): string[] => {
    const matches = glob.sync(normalizeFilePattern(pattern), { cwd, dot: true, absolute: false });
    const resolved = matches
      .map((p) => (cwd && !pathLib.isAbsolute(p) ? pathLib.join(cwd, p) : p))
      .filter((p) => {
        try {
          return statSync(p).isFile();
        } catch {
          return false;
        }
      });
    return acc.concat(resolved);
  }, []);
};
```

The list is then passed to `upload(...)` for each path
(`src/main.ts:67-74`), which `open()`s the file and uploads it as a public
release asset.

### Behaviors

- `glob.sync(pattern, { cwd })` honors absolute patterns and patterns with
  `..` segments. There is no `relative(cwd, match).startsWith('..')` check
  before `open()`/`statSync`. `dot: true` also lets it match dotfiles such
  as `.npmrc`, `.git/config`, etc.
- `~` and `~/...` are expanded to the action user's home directory
  *regardless* of `working_directory`. The action explicitly documents this
  in `action.yml` and `README.md`, so it is intended.
- The default `working_directory` is the workspace root, but a workflow
  using `working_directory: dist` plus `files: ../**/*` would still happily
  upload files from outside `dist` (and outside the workspace, given enough
  `..` segments).

### Reachability

Same workflow-author-controlled trust boundary as Candidate 1. A workflow
that does

```yaml
- uses: softprops/action-gh-release@v3
  with:
    files: ${{ inputs.files }}
```

with `inputs.files` set to e.g.

```
/home/runner/work/_temp/_github_workflow/event.json
~/.docker/config.json
/proc/self/environ
```

uploads those files as **public release assets** signed under the workflow's
identity. On a public repo this is a straight exfiltration primitive for
runner-resident secrets.

### Trust boundary analysis

Identical to Candidate 1. The README does not show any pattern that wires
event-derived strings into `files`, `working_directory`, or `body_path`. To
get a real privilege escalation:

1. The consuming workflow would need to run on a trigger that gives an
   untrusted party string control (e.g., `pull_request_target`, `issue_comment`,
   `repository_dispatch` with relaxed payload validation), and
2. Plumb that untrusted string into `files` / `working_directory` /
   `body_path`.

Both are explicitly anti-patterns in GitHub's docs and are the workflow
author's responsibility, not this action's.

### Severity

- Default usage: P5 (intended behavior).
- Misused with untrusted input: would be P1 (arbitrary file read on the
  runner exfiltrated as a public release asset). Not confirmed in the field.
- Defense-in-depth fix: refuse `files` patterns that resolve outside
  `working_directory ?? GITHUB_WORKSPACE`, with an opt-in flag (e.g.
  `allow-outside-workspace: true`) for users who actually do want to upload
  e.g. `~/.cache/...` artifacts.

## Candidate 3 — Cross-repo writes via `repository` + non-default `token`

### Sink

```508:512:src/github.ts
const [owner, repo] = config.github_repository.split('/');
const tag =
  normalizeTagName(config.input_tag_name) ||
  (isTag(config.github_ref) ? config.github_ref.replace('refs/tags/', '') : '');
```

`github_repository` is `INPUT_REPOSITORY || GITHUB_REPOSITORY`
(`src/util.ts:101`). When `INPUT_REPOSITORY` is set, the action creates the
release in *that* repo using the supplied `token` instead of the calling
repo's `GITHUB_TOKEN`.

### Reachability

Workflow-author-controlled. Misuse pattern is the same as Candidate 1: only
exploitable if the workflow author lets an untrusted party set
`repository:` and the supplied token has cross-repo write access. The
README's example explicitly tells users that cross-repo deployments require a
PAT, i.e. it is an opt-in elevated configuration.

### Severity

- Default usage: P5.
- With cross-repo PAT and untrusted-input plumbing: same misuse class as
  Candidates 1 and 2; not a defect in the action.

## Other items checked and dropped

- **Octokit URL handling in `upload()`** (`src/github.ts:334-335`): `url`
  comes from the GitHub API response (`rel.upload_url`), not from user input.
  No injection here.
- **`uploadUrl` truncation at `{`** (`src/util.ts:31-37`): purely strips the
  RFC 6570 template marker; `release.upload_url` originates server-side.
- **`generate_release_notes` body concatenation** (`src/github.ts:140-153`):
  combines server-generated notes with user `body`. No path or HTML
  injection beyond what GitHub already renders for release bodies.
- **`make_latest` validation** (`src/github.ts:134-139`): only allows
  `'true' | 'false' | 'legacy'`; safe.
- **Asset name handling** (`src/github.ts:269-272`,
  `src/util.ts:201-203`): asset names go through
  `endpoint.searchParams.append('name', name)` (URL-encoded by `URL`) and
  through GitHub's own name normalization. Not a vulnerability here.
- **Token logging**: `config.github_token` is sent in
  `authorization: token ${params.token}`. Octokit / `@actions/github` does
  not log auth headers; the token is also not echoed in any of the
  `console.log` paths I found. No credential leak observed.
- **Race-handling cleanup** (`src/github.ts:800-883`): operates on releases
  with the same `tag_name` and `draft && assets.length === 0`, then deletes.
  This is a denial-of-service-shaped *bug* under heavy concurrency rather
  than a security primitive — an attacker would already need release-write
  on the target repo to plant fake drafts.

## Disclosure status

No upstream disclosure was made during this scout cycle.

## Outcome

**No confirmed reportable vulnerability.** The two interesting sinks
(`body_path` → arbitrary file read; `files` → arbitrary file upload as a
public release asset) are both reachable only from workflow-author-controlled
inputs in the realistic GitHub Actions trust model. Recommended hardening:

1. Add a containment check in `releaseBody` and `paths` so that paths
   resolving outside `working_directory ?? GITHUB_WORKSPACE` are refused by
   default, with an explicit opt-in for the legitimate `~/...` and
   `${{ github.workspace }}-CHANGELOG.txt` use cases that the README
   currently shows.
2. Document, in `README.md` and `action.yml`, that `body_path`, `files`,
   `working_directory`, and `repository` must not be sourced from untrusted
   event data such as `pull_request_target` payloads, comment bodies, or
   `repository_dispatch.client_payload` strings.

These are non-blocking improvements; nothing here warrants a CVE or
coordinated disclosure as of the reviewed commit.

## Scout notes

- The control repository (`safeengineauto/github-pages-deploy-action`) does
  not currently carry `AGENTS.md`, `TARGET_POLICY.md`, `REPORT_TEMPLATE.md`,
  or `memory/security-scout-memory.md` on its `dev` branch. The two earlier
  remote scout branches each independently noted this and bootstrapped the
  memory file inside their own branches; this cycle continues that
  convention by adding a fresh `memory/security-scout-memory.md` on this
  branch that aggregates all three known prior runs (`release-drafter`,
  `JamesIves/github-pages-deploy-action`, and this `softprops/action-gh-release`
  cycle).
- Picked target is **distinct** from those already listed in memory.
- Only files inside this control repository (`reports/...`, `memory/...`)
  were written. The target repository (`softprops/action-gh-release`) was
  cloned read-only into `/tmp` for analysis.
