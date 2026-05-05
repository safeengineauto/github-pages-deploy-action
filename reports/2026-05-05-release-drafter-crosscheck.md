# Cross-check report — release-drafter/release-drafter

- **Target repo:** `release-drafter/release-drafter`
- **Commit audited:** `0c28acd0bcb335f1f86b350a4283045eb03025b9`
  ("feat: recover recently merged PRs missed by associated PRs lag (#1604)")
- **Drift vs current `origin/master`:** none. `0c28acd…` is the current tip of `master`,
  and `git log ^0c28acd master -- src/common/config src/actions/drafter/config action.yml`
  is empty. The findings below apply to current `main`/`master` as well.
- **Reviewer (this report):** OSS Security Scout cross-check
- **Original P1 candidate (from `reports/2026-05-05-release-drafter.md`):**
  > When `config-name` resolves to a local config (`file:` scheme or equivalent
  > local load), `normalizeFilepath` can produce a relative path that, when
  > combined with `GITHUB_WORKSPACE` in `getConfigFileFromFs`, escapes the
  > workspace (enough `../` segments after `.github/` is prepended, etc.).
  > That would be arbitrary file read on the Actions runner if `config-name`
  > (or values that feed it) can be attacker- or workflow-controlled.

## Verdict

**Confirmed as a real bug — workspace escape via path traversal in `getConfigFileFromFs`.**
**Severity: narrowed from P1 to P3 (low/info).** The traversal is reachable from
inputs that are *workflow-author-controlled*, but in the realistic attacker
model for a GitHub Action it does **not** cross a trust boundary: the same
workflow author who can set `config-name` already runs arbitrary code on the
runner via `run:` steps. There is no path I could find where a less-trusted
party (PR author, comment author, fork, reusable-workflow caller passing
untrusted strings, etc.) reaches this sink without the workflow having an
existing, larger problem.

I.e.: the *escape itself* is real and the test suite even encodes it as
"intended" output (see `expected: '../file.yml'` in
`src/tests/drafter/normalize-filepath.test.ts:96`). The *security impact* is
defensive-in-depth, not a privilege boundary crossing.

A safe fix is small and worth landing on hardening grounds.

---

## 1. Evidence — the escape is real

### 1.1 `normalizeFilepath` happily emits paths starting with `../`

```24:55:src/common/config/normalize-filepath.ts
export const normalizeFilepath = (
  config: Pick<ConfigTarget, 'ref' | 'repo' | 'filepath'>,
  parentConfig?: Pick<ConfigTarget, 'ref' | 'repo' | 'filepath'>,
): string => {
  const _filepath = normalize(config.filepath)

  if (isAbsolute(_filepath)) {
    if (_filepath.startsWith('/')) {
      // Remove leading slash to make it relative to repo root
      return _filepath.slice(1)
    } else {
      throw new Error(`Encountered malformed absolute path ${_filepath}`)
    }
  } else {
    if (
      parentConfig &&
      parentConfig.repo.owner === config.repo.owner &&
      parentConfig.repo.repo === config.repo.repo &&
      config.ref === parentConfig.ref
    ) {
      return normalize(join(dirname(parentConfig.filepath), _filepath))
    } else {
      if (_filepath.startsWith('.github/')) {
        return _filepath
      }
      return join('.github', _filepath)
    }
  }
}
```

Notes:

- The "absolute path" branch *strips the leading `/`*. So `/etc/passwd.yml`
  becomes `etc/passwd.yml`, which does **not** escape `GITHUB_WORKSPACE`. So
  the absolute-path lever isn't exploitable. (The `/etc/passwd.yml` example in
  the original write-up overstates the issue on this branch.)
- The "relative path" branch joins onto either the parent config's `dirname`
  (for an `_extends` from the same repo+ref) or onto `.github/`. In both
  cases, `node:path.normalize`/`join` collapse `..` segments **including past
  the prefix**, so the result can start with `../` and escape the prefix.

### 1.2 `getConfigFileFromFs` blindly trusts the normalized output

```6:40:src/common/config/get-config-file-from-fs.ts
export const getConfigFileFromFs = (normalizedFilepath: string) => {
  if (isAbsolute(normalizedFilepath)) {
    throw new Error(
      `Absolute paths are not supported for config file path: ${normalizedFilepath}`,
    )
  }

  if (!process.env.GITHUB_WORKSPACE) {
    throw new Error(
      `env GITHUB_WORKSPACE is not set. Cannot resolve local repo path.`,
    )
  }

  const repoRoot = process.env.GITHUB_WORKSPACE
  const configPath = path.join(repoRoot, normalizedFilepath)

  core.info(`Looking for config locally at ${configPath}...`)

  if (!existsSync(repoRoot)) {
    throw new Error(`Root repo path does not exist: ${repoRoot}`)
  }

  if (!existsSync(configPath)) {
    throw new Error(
      `Config file not found: ${configPath}. Did you clone your sources ? (ex: using @actions/checkout)`,
    )
  }

  core.info(`Loading from file: ${configPath}`)

  return readFileSync(configPath, 'utf8')
}
```

The only sanitisation is `isAbsolute(normalizedFilepath)`. A relative path
like `../../etc/cloud-init/cloud.cfg.yml` passes that check, then `path.join`
resolves the `..` segments and escapes `GITHUB_WORKSPACE`.

### 1.3 The escape is actually reproducible

Implementing the exact `normalizeFilepath` algorithm in Node:

| input `filepath` (config-name)            | `normalizeFilepath` output                | joined under `/home/runner/work/myrepo/myrepo` | escapes? |
|-------------------------------------------|-------------------------------------------|-------------------------------------------------|----------|
| `release-drafter.yml` (default)           | `.github/release-drafter.yml`             | `…/myrepo/.github/release-drafter.yml`          | no       |
| `../foo.yml`                              | `foo.yml`                                 | `…/myrepo/foo.yml`                              | no (still inside repo, but skips `.github/` prefix) |
| `./../../foo.yml`                         | `../foo.yml`                              | `…/work/myrepo/foo.yml`                         | **yes** (sibling repo dir) |
| `../../etc/passwd.yml`                    | `../etc/passwd.yml`                       | `…/work/myrepo/etc/passwd.yml`                  | **yes** |
| `../../../etc/cloud-init/cloud.cfg.yml`   | `../../etc/cloud-init/cloud.cfg.yml`      | `/home/runner/work/etc/cloud-init/cloud.cfg.yml`| **yes** |
| `../../../../../../etc/passwd.yml`        | `../../../../../etc/passwd.yml`           | `/etc/passwd.yml`                               | **yes** (full FS root) |
| `/etc/passwd.yml`                         | `etc/passwd.yml`                          | `…/myrepo/etc/passwd.yml`                       | no       |
| `/../../etc/passwd.yml`                   | `etc/passwd.yml`                          | `…/myrepo/etc/passwd.yml`                       | no       |

(Reproduced live on Node v22, using the function copied verbatim.)

So for sufficiently many `../` segments, the resulting `configPath` lands
anywhere on the runner filesystem.

### 1.4 The behaviour is *intentional* per the unit tests

The intended semantics — including parent escape — are encoded in the test
fixtures:

```86:97:src/tests/drafter/normalize-filepath.test.ts
{
  input: [
    {
      filepath: '../very_long_relative/../../../file.yml',
      ref: 'main',
      repo: { owner: 'cchanche', repo: 'proj' },
    },
    {
      filepath: 'with/a/parent.yaml',
      ref: 'main',
      repo: { owner: 'cchanche', repo: 'proj' },
    },
  ],
  expected: '../file.yml',
},
```

So the maintainers' design explicitly allows `_extends` to walk above the
parent config's directory — fine for "find a config in the repo", but the
*post-condition that the result is still inside the repo root* is nowhere
asserted. Nothing in the tests, in `getConfigFileFromFs`, or in
`normalizeFilepath` enforces "stay inside `GITHUB_WORKSPACE`".

### 1.5 The leak vector

`getConfigFile` calls `yaml.parse(configRaw)` (or `JSON.parse`). The parsed
object is later validated by `configSchema.parse(config)` in
`src/actions/drafter/config/get-config.ts:17`. So *non-YAML/JSON files won't
silently exfiltrate*; they'll throw. But:

- The error message in `getConfigFile` includes the file's contents indirectly
  only via the parser exception, so direct exfil through error messages is
  minimal but possible (e.g. "unexpected token at line N column M").
- More importantly, `existsSync(configPath)` answers a yes/no oracle on
  arbitrary runner paths — useful for fingerprinting installed files.
- A target file that *happens* to be valid YAML/JSON of the right shape would
  be parsed and used as config; the action then writes a draft GitHub release
  whose body is largely derived from PRs, not from the config, so direct
  reflection of secret YAML contents into release notes is limited (header /
  footer / template strings could be reflected back if read from a malicious
  YAML target, but that's not "arbitrary file read", that's the attacker
  having already supplied content).

The most realistic primitive is therefore **arbitrary read of YAML/JSON files
on the runner** plus an **`existsSync` oracle** for arbitrary paths, where
the read content is interpreted as release-drafter config (so it can shift
release behaviour and, via `header`/`footer`/`name-template`, surface into the
release body).

---

## 2. Reachability — who controls `config-name`?

`config-name` is the only string fed into `composeConfigGet` from the
drafter action (`src/actions/drafter/config/get-action-inputs.ts:17`,
`src/actions/drafter/config/get-config.ts:6-7`). The default is
`release-drafter.yml` (`action.yml:14-19`). For escape, that input must
contain `../` (or `_extends:` in a config the maintainers control must do so).

GitHub Actions' `inputs:` for an action are populated in the *workflow file*
of the *consumer repo*. That means:

| caller pattern                                                                                   | `config-name` source                  | trust level vs runner                            |
|--------------------------------------------------------------------------------------------------|----------------------------------------|--------------------------------------------------|
| `with: config-name: my-drafter.yml` — repo constant                                              | committed in `.github/workflows/*`     | Same as workflow author. No new boundary.        |
| `with: config-name: ${{ inputs.config-name }}` from `workflow_dispatch`                          | manual UI dispatcher with `actions:write` | Same as repo write. No new boundary.          |
| `with: config-name: ${{ inputs.config-name }}` from a **reusable workflow** (`workflow_call`)    | calling workflow's author              | Reusable callers already execute code in the callee's runner — same trust as a normal workflow author. |
| `with: config-name: ${{ github.event.inputs.X }}` from `repository_dispatch`                     | needs a `repo`-scoped PAT to fire      | Same as repo write. No new boundary.             |
| `with: config-name: ${{ github.event.* }}` from `pull_request`/`issue_comment`                   | **PR author / commenter (untrusted)**  | release-drafter is normally `pull_request` `closed`+`merged` only; even there, plumbing PR-controlled fields into `config-name` is not idiomatic and would have to be done explicitly by the workflow author. |
| Org-level "caller" data (org variables / `vars`)                                                 | org admins                             | Org admins already have privileged access.       |

I searched release-drafter's own examples (README, `action.yml`, integration
tests) for any guidance that wires `config-name` to event-derived data and
found none. The README only shows it as a static string.

So in **realistic** workflows, `config-name` is a **repo constant** committed
by the workflow author — not a less-trusted source. To get untrusted control
of `config-name`, a workflow author would have to do something obviously
unsafe such as:

```yaml
on: issue_comment
…
- uses: release-drafter/release-drafter@v…
  with:
    config-name: ${{ github.event.comment.body }}   # nobody writes this
```

That kind of plumbing is the *workflow author's* mistake, not a flaw in
release-drafter.

There is also a secondary reachability path: the `_extends` chain in a config
file. A malicious `.github/release-drafter.yml` with a same-repo,
same-`file:`-scheme `_extends: file:../../../etc/foo.yml` would also reach
the same sink (via `getConfigFiles` -> `parseConfigTarget` -> same
`normalizeFilepath`). But anyone able to commit to `.github/release-drafter.yml`
is already a repo collaborator with write access — same trust boundary.

Note: `parseConfigTarget` *does not* permit a `github:` parent to extend into
a `file:` child (`src/common/config/get-config-file.ts:24-30` rejects
`github → file` transitions). So a public org-`/.github` config cannot pivot
a downstream repo into reading local files — that scheme transition is
correctly blocked. This rules out a cross-repo escalation path.

### Reachability summary

- **No untrusted user-supplied path I can identify reaches `config-name`**
  in idiomatic usage.
- All realistic attackers who control `config-name` (or the parent config
  contents) already have repo-write or workflow-edit rights on the consuming
  repo.
- The `github → file` scheme transition is properly forbidden.

---

## 3. False-positive analysis

I went through the things that could invalidate the finding:

### 3.1 Does `parseConfigTarget` strip `..`?

No. Read `parse-config-target.ts:14-124`. It splits on `:` and `@`, validates
scheme/repo/ref shape, and returns `filepath` as-is. There is no path
sanitization. So `with: config-name: ../../../etc/passwd.yml` flows through
to `normalizeFilepath` unchanged. *Confirms the finding.*

### 3.2 Does `getConfigFileFromFs` re-validate that the joined path is inside `GITHUB_WORKSPACE`?

No (see §1.2). Only `isAbsolute(normalizedFilepath)` is checked, which is
defeated by any relative `../`. *Confirms the finding.*

### 3.3 Does the `file:` vs `github:` distinction matter for reachability?

Yes, it narrows but does not eliminate the issue:

- `parseConfigTarget` defaults to `scheme: 'github'` unless the input starts
  with `file:` (`parse-config-target.ts:30`).
- Default `config-name: release-drafter.yml` (no scheme prefix) becomes
  `scheme: github`, *not* `file`. So `getConfigFile` calls
  `getConfigFileFromRepo` (Octokit `repos.getContent`), not
  `getConfigFileFromFs`. There is no local read by default.
- For local read we need either:
  1. The user explicitly passes `config-name: file:…` (rare; intentional opt-in).
  2. The `_extends` directive of a fetched config uses `file:` scheme.

But: the `composeConfigGet` flow always works on the same `normalizeFilepath`
result, and `getConfigFileFromFs` is *the only* place the normalized path is
joined to a filesystem root. So the *escape* happens only on the `file:`
local-load path; the GitHub-API path is constrained by the GitHub side
("path" parameter in `getContent` rejects `..` and unknown files come back
404).

So the finding is **correctly restricted to `file:` scheme local loads**, as
the candidate report states. The finding is *not* applicable to the default
workflow that uses `github:` scheme to fetch from `repos.getContent`. This
narrows reachability further: it requires either an explicit `file:` prefix
in `config-name`, or a fetched config whose `_extends` uses `file:`.

### 3.4 Does `existsSync` make this just a directory probe rather than a read?

The two `existsSync` checks short-circuit to a more specific error, but the
final `readFileSync(configPath, 'utf8')` on line 39 *does* read the file. So
when the target exists and is parseable as YAML/JSON, this is a real read,
not just a probe.

### 3.5 Does the `parent-relative _extends` chain change anything?

Yes — it weakens the issue further. When `_extends` references the same repo
& ref as the parent, the new path is joined onto the *parent's* `dirname`,
not `.github/`. Since the parent was itself loaded from a normalized,
inside-repo location for valid configs, walking `..` from there can still
escape but the attacker also already controls a committed config. So
`_extends` traversal does not give a *new* attacker primitive — it requires
having committed a malicious parent config first, i.e. repo write access.

### 3.6 Is the `'.github/'` prefix skipped check exploitable?

```49:51:src/common/config/normalize-filepath.ts
if (_filepath.startsWith('.github/')) {
  return _filepath
}
```

If `config.filepath` already starts with `.github/`, no `.github/` prefix is
added. If you pass `config-name: .github/../../etc/passwd.yml`, `normalize()`
on line 28 collapses it to `../etc/passwd.yml` *before* the
`startsWith('.github/')` check, so the check is bypassed and the attacker
goes through the "join `.github` prefix" branch — net result is the same as
the plain `../../etc/passwd.yml` case. No new exploit surface beyond what
§1.3 already shows.

### 3.7 Is the absolute-path branch exploitable?

No. It strips the leading `/` and so the joined path is rooted under
`GITHUB_WORKSPACE` (e.g. `/etc/passwd.yml` → `<workspace>/etc/passwd.yml`).
The original report mentions "absolute paths" as an example; this part is a
**false positive**.

---

## 4. Severity

The original P1 rating depends on a malicious or low-trust party being able
to set `config-name`. In the realistic attacker model for this Action:

- **Workflow author / repo collaborator with write access**: already runs
  arbitrary `bash` on the runner via `run:` steps and can read any file
  under `GITHUB_WORKSPACE`, the home dir, secrets in env, etc. The escape
  here is **not a privilege escalation** for them.
- **PR author / fork PR**: release-drafter is typically run on
  `push`/`pull_request: types: [closed]` with `if: github.event.pull_request.merged`,
  i.e. *after merge*. Even when run earlier, fork PRs don't get write tokens
  and don't get to set workflow inputs.
- **`workflow_dispatch` / reusable-workflow caller**: same trust as repo write.
- **Cross-repo (`github:` scheme)**: blocked by the `github → file` transition
  guard in `get-config-file.ts:25-29`.

There is no plausible path where a user with strictly less authority than the
workflow author gains arbitrary-file-read on the runner via this bug.

**Recommended classification: P3 (defense-in-depth / low-impact bug).**
- *Not P1*: no untrusted-input → arbitrary-read crossing.
- *Not P2*: no realistic exploitable workflow pattern even with reusable workflows
  or org-level callers, because such callers are themselves trusted.
- *Worth fixing as P3*: the *contract* is clearly violated (a config name
  should resolve inside the repo), the test suite encodes the violation as
  intended, the fix is a few lines, and a future feature change (e.g. taking
  config-name from `repository_dispatch.client_payload`) could promote this
  to a real vulnerability.

If the maintainers later add a feature that pipes event data into
`config-name` (or otherwise lets a less-trusted caller influence it), this
becomes P1 immediately. The fix below removes that latent footgun.

---

## 5. Safe fix sketch

Two complementary changes; either one alone removes the workspace-escape
read primitive, but applying both is cheap and gives a clearer error.

### 5.1 Reject `..` traversal at the config-name boundary

In `parseConfigTarget` (or directly in `normalizeFilepath`'s public
"top-level" branch where `parentConfig === undefined`), reject any
`config-name` whose normalized form contains a leading `..` segment.

This catches the user-supplied input at the trust boundary and gives a clear
error before any FS work happens.

### 5.2 Enforce the post-condition in `getConfigFileFromFs`

Make the only filesystem-reaching function actually *prove* the path is
inside `GITHUB_WORKSPACE`:

```typescript
import { existsSync, readFileSync, realpathSync } from 'node:fs'
import path, { isAbsolute, relative, resolve, sep } from 'node:path'
import process from 'node:process'
import * as core from '@actions/core'

export const getConfigFileFromFs = (normalizedFilepath: string) => {
  if (isAbsolute(normalizedFilepath)) {
    throw new Error(
      `Absolute paths are not supported for config file path: ${normalizedFilepath}`,
    )
  }
  if (!process.env.GITHUB_WORKSPACE) {
    throw new Error(`env GITHUB_WORKSPACE is not set. Cannot resolve local repo path.`)
  }

  const repoRoot = resolve(process.env.GITHUB_WORKSPACE)
  const configPath = resolve(repoRoot, normalizedFilepath)

  // Lexical containment check. Use `relative` rather than startsWith to avoid
  // prefix collisions between e.g. `/foo` and `/foobar`.
  const rel = relative(repoRoot, configPath)
  if (rel.startsWith('..') || isAbsolute(rel)) {
    throw new Error(
      `Refusing to load config outside GITHUB_WORKSPACE: ${configPath}`,
    )
  }

  if (!existsSync(repoRoot)) {
    throw new Error(`Root repo path does not exist: ${repoRoot}`)
  }
  if (!existsSync(configPath)) {
    throw new Error(
      `Config file not found: ${configPath}. Did you clone your sources ? (ex: using @actions/checkout)`,
    )
  }

  // Defense-in-depth against a symlink inside the repo pointing outside.
  // This is optional; on hosted runners the workspace is checked-out user
  // content, so a malicious symlink can only be planted by a repo writer
  // (same trust level), but it costs little to also check the realpath.
  try {
    const realConfig = realpathSync(configPath)
    const realRoot = realpathSync(repoRoot)
    const realRel = relative(realRoot, realConfig)
    if (realRel.startsWith('..') || isAbsolute(realRel)) {
      throw new Error(
        `Refusing to load config outside GITHUB_WORKSPACE (via symlink): ${realConfig}`,
      )
    }
  } catch (err) {
    // Re-throw the containment error; tolerate ENOENT / EACCES on root
    if ((err as NodeJS.ErrnoException).code !== 'ENOENT' &&
        (err as NodeJS.ErrnoException).code !== 'EACCES') {
      throw err
    }
  }

  core.info(`Loading from file: ${configPath}`)
  return readFileSync(configPath, 'utf8')
}
```

Notes on the fix:

- Use `path.resolve` rather than `path.join` so any future "leading slash"
  edge case still resolves to an absolute path that we *then* check.
- Use `path.relative(...).startsWith('..')` (plus `isAbsolute(rel)` guard for
  Windows drive letters, although Actions runners are Linux/macOS in
  practice) — this is the canonical idiom and avoids the `prefix` pitfall
  (`/work/myrepoX` vs `/work/myrepo`).
- The `realpathSync` step is optional defense-in-depth; the lexical check is
  sufficient for the *current* untrusted-input model. If the maintainers
  later support running on a checkout that may contain attacker-controlled
  symlinks (e.g. a `pull_request_target` style use), the realpath check
  becomes load-bearing.
- The corresponding **unit-test fix** is also required: the test case
  `expected: '../file.yml'` in `normalize-filepath.test.ts:96` should be
  updated to expect a thrown error (or the function should still emit
  `'../file.yml'` and `getConfigFileFromFs` should reject it — pick one
  layer; rejecting at the top boundary in `parseConfigTarget` plus the FS
  layer is cleanest).

### 5.3 Optional: warn/reject `file:` scheme by default

`config-name: file:…` is rare in real workflows. Maintainers could
optionally gate it behind an explicit opt-in input (e.g.
`allow-local-config: true`) to drastically reduce the API surface that ever
reaches the filesystem. This is a product/UX call rather than a security
necessity.

---

## 6. Summary

| Question                                                                                  | Answer |
|--------------------------------------------------------------------------------------------|--------|
| Does `normalizeFilepath` produce a relative path that escapes the repo root via `..`?      | **Yes**, confirmed by code reading and reproduction (§1.3). |
| Does `getConfigFileFromFs` then read that path?                                            | **Yes**, only an `isAbsolute` guard blocks it; relative `..` traversals pass. |
| Is the absolute-path lever (`/etc/passwd.yml`) exploitable?                                | **No**, the leading `/` is stripped (§3.7). The original write-up is wrong on this specific example. |
| Can a less-trusted party (PR author, fork, comment author, org caller) set `config-name`? | **No realistic path identified.** Idiomatic workflows treat it as a repo constant. |
| Does `_extends` from a public org-`/.github` config let a remote attacker pivot to `file:`? | **No**, `github → file` scheme transitions are explicitly blocked. |
| Should this be P1?                                                                         | **No**, downgrade to P3 (defense-in-depth). |
| Should it be fixed?                                                                        | **Yes**, the contract is violated and the fix is small. |
| Drift vs `main`/`master`?                                                                  | **None.** `0c28acd…` is the current tip of `master` for the relevant files. |

### TL;DR for triage

Real bug, wrong threat model. Ship the lexical containment check in
`getConfigFileFromFs` and either reject `..` in `parseConfigTarget` or update
the `normalizeFilepath` tests. P3, not P1.
