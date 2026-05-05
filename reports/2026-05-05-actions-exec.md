# Security Scout Report — @actions/exec

- **Target repo:** `actions/toolkit` (monorepo; focus on `packages/exec` and `packages/io`)
- **Version / commit audited:** `@actions/exec@3.0.0` / commit `cf80afb3922317b98dd74d27cba7cf1032c1fe50`
- **Date:** 2026-05-05
- **Run type:** initial
- **Scout:** OSS Security Scout (automated)

---

## 1. Target Overview

`@actions/exec` is the official command-execution library in the GitHub
Actions toolkit (`actions/toolkit`). It wraps `child_process.spawn()` with
argument parsing, quoting, streaming I/O, and timeout management. It is a
direct dependency of `JamesIves/github-pages-deploy-action` (pinned at
`3.0.0` in `package.json`) and is used by virtually every non-trivial GitHub
Action that runs shell commands.

- **GitHub stars (toolkit):** ~5,700
- **npm weekly downloads (@actions/exec):** millions (foundational Actions package)
- **Why selected:** This is the shell execution layer used by the host
  action (`github-pages-deploy-action`). A vulnerability here would affect
  every downstream action that calls `exec()` or `getExecOutput()`. It also
  handles argument quoting and escaping, which is a historically rich attack
  surface.

The audit also covers `@actions/io` (`packages/io`), since `@actions/exec`
depends on it for `which()` and `isRooted()`, and `github-pages-deploy-action`
uses `@actions/io` directly for `mkdirP` and `rmRF`.

---

## 2. Audit Scope

| Area | What was examined |
|------|-------------------|
| Source code | `packages/exec/src/{exec,toolrunner,interfaces}.ts`, `packages/io/src/{io,io-util}.ts` |
| Argument parsing | `argStringToArray()` — custom shell-like tokeniser |
| Process spawning | `ToolRunner.exec()` — `child_process.spawn()` usage |
| Quoting/escaping | `_windowsQuoteCmdArg()`, `_uvQuoteCmdArg()` — Windows cmd.exe quoting |
| Consumer code | `github-pages-deploy-action` `src/git.ts`, `src/ssh.ts`, `src/util.ts`, `src/worktree.ts` — how inputs flow into `execute()` calls |
| Dependencies | `@actions/io@3.0.2` (sole dep of `@actions/exec`) |
| Published advisories | GitHub Security Advisories for `actions/toolkit`, Snyk, NVD |
| CI/CD configuration | `.github/workflows/build.yml`, `integration.yml` in the consumer repo |

---

## 3. Findings

### 3.1 `argStringToArray` does not prevent argument injection on Linux/macOS

- **Severity:** P3 (Info / defense-in-depth)
- **Category:** command-injection (argument injection)
- **File(s):** `packages/exec/src/toolrunner.ts:554-609`
- **Evidence:**

The `exec(commandLine, args)` API splits `commandLine` via `argStringToArray`,
then passes the resulting array to `child_process.spawn()`. On Linux/macOS,
`spawn()` invokes `execvp()` directly (no shell), so classic `$(...)` or
`; cmd` shell injection is **not** possible through this path.

However, the API documentation says:

> `commandLine` — command to execute (can include additional args). **Must be
> correctly escaped.**

This places the escaping burden on the caller. The `argStringToArray` parser
handles double-quoted strings and backslash-escaped quotes, but does **not**
reject or escape:

- Git argument injection payloads like `--upload-pack=...` or `--exec=...`
- Arguments starting with `-` that could be interpreted as flags by the
  spawned tool

When a caller constructs a command string by interpolating user-controlled
data (as `github-pages-deploy-action` does for `action.name`, `action.email`,
`action.branch`, `action.tag`, `action.commitMessage`, etc.), a malicious
value containing spaces or flags can inject additional arguments.

For example, in `github-pages-deploy-action` `src/git.ts:41`:

```
`git config user.name "${action.name}"`
```

If `action.name` were `foo" --global alias.co "!malicious`, `argStringToArray`
would parse this into tokens that inject `--global`, `alias.co`, and a
command alias into git config.

- **Exploitability:**

Low in practice for this consumer. All `action.*` values come from workflow
`inputs:` (set by the workflow author, not by PR authors) or from
`github.context.payload.pusher` (which requires write access to the repo to
trigger a `push` event). There is no path where a fork PR author or external
commenter controls these values.

The issue is a **design limitation** in `@actions/exec` rather than a direct
vulnerability: the library deliberately does not sanitize arguments, expecting
callers to do so. This is documented but easily overlooked by action authors.

- **Suggested fix:**

Action authors (including `github-pages-deploy-action`) should pass arguments
via the `args` array parameter rather than interpolating into `commandLine`:

```typescript
await exec('git', ['config', 'user.name', action.name], { cwd: action.workspace })
```

This eliminates parsing ambiguity entirely.

---

### 3.2 Windows `cmd.exe` quoting does not escape `%` (environment variable expansion)

- **Severity:** P3 (Info / defense-in-depth)
- **Category:** command-injection
- **File(s):** `packages/exec/src/toolrunner.ts:151-271`
- **Evidence:**

The `_windowsQuoteCmdArg` method contains an explicit comment (lines 240-251):

> a weakness of the quoting rules chosen here, is that % is not escaped. in
> fact, % cannot be escaped when used on the command line directly

On Windows, if a `.cmd` or `.bat` file is invoked, `cmd.exe` interprets
`%VAR%` in arguments. An attacker who controls an argument value could
inject `%PATH%` or `%USERPROFILE%` to leak environment variable contents
into command output, or use `%CD%` to influence path resolution.

- **Exploitability:**

`github-pages-deploy-action` only supports Linux runners
(`SupportedOperatingSystems = [OperatingSystems.LINUX]`), so this Windows
code path is unreachable for this specific consumer. However, other actions
using `@actions/exec` on Windows runners with `.cmd` tools and user-controlled
arguments could be affected.

The toolkit maintainers are aware of this limitation (it's documented in
comments) and consider it an inherent constraint of `cmd.exe` argument
processing.

- **Suggested fix:**

For actions running on Windows with user-controlled inputs, avoid invoking
`.cmd`/`.bat` files with untrusted arguments. Use the `args` array with
non-cmd executables instead.

---

### 3.3 `@actions/io` `cp` follows and copies symlinks without containment checks

- **Severity:** P3 (defense-in-depth)
- **Category:** path-traversal
- **File(s):** `packages/io/src/io.ts:297-327`
- **Evidence:**

The `copyFile` function in `io.ts` handles symlinks by reading the link
target and recreating the symlink at the destination:

```typescript
const symlinkFull: string = await ioUtil.readlink(srcFile)
await ioUtil.symlink(symlinkFull, destFile, ...)
```

There is no check that the symlink target remains within the source tree.
A malicious symlink pointing to `/etc/passwd` or `$HOME/.ssh/id_rsa` would
be faithfully reproduced at the destination. If the copied output is later
published (e.g., deployed to gh-pages), the symlink target's contents could
be exposed.

The recursive copy in `cpDirRecursive` also follows symlinks via
`ioUtil.lstat` → `isDirectory()`, but the actual file copy uses `lstat`
(not `stat`), so directory symlinks are followed for recursion while file
symlinks are handled by the symlink copy path. This is inconsistent but
does not create a worse-than-expected outcome.

- **Exploitability:**

For `github-pages-deploy-action`, this is not directly exploitable because
the action uses `rsync` (not `@actions/io.cp`) for the deployment copy, and
rsync has its own symlink handling (`-a` preserves symlinks by default but
does not dereference them). However, other actions using `io.cp` to process
untrusted directory trees (e.g., user-uploaded artifacts) could be affected.

- **Suggested fix:**

Add an optional `followSymlinks: false` option to `CopyOptions` and default
to not following symlinks outside the source tree. At minimum, add a
containment check in `copyFile` that verifies the resolved symlink target
is within the source directory.

---

### 3.4 No actionable findings in `@actions/exec` core spawn path

The core `ToolRunner.exec()` method correctly:

- Uses `child_process.spawn()` (not `exec()` or `execSync()`), avoiding
  shell interpretation on Linux/macOS.
- Resolves the tool path via `io.which()` with `check=true`, ensuring only
  existing executables on `PATH` are invoked.
- Sets `windowsVerbatimArguments` only when running `.cmd`/`.bat` files.
- Handles STDIO cleanup with a configurable timeout (default 10s).
- Does not leak environment variables or secrets in its own code.

These are positive security properties.

---

## 4. Dependency Snapshot

| Package | Version | Known CVEs | Notes |
|---------|---------|------------|-------|
| `@actions/exec` | 3.0.0 | None | No published advisories (Snyk, NVD) |
| `@actions/io` | 3.0.2 | None | Sole dependency of `@actions/exec` |
| `@actions/core` | 3.0.0 | CVE-2022-35954 (fixed in 1.9.1) | Consumer's version is well past the fix |
| `@actions/github` | 9.0.0 | None | Consumer dependency; uses `undici` internally |

---

## 5. Summary & Recommendations

**Overall assessment:** `@actions/exec` is a well-designed library that
correctly avoids shell interpretation on Linux by using `spawn()` with
argument arrays. The primary risk is not in the library itself but in how
callers use its string-based `commandLine` parameter — constructing command
strings via template literal interpolation is the dominant pattern across
the Actions ecosystem, and it creates argument-injection risk when inputs
are not sanitized.

**Recommendations:**

1. **For `github-pages-deploy-action`:** Refactor `execute()` to accept
   tool and args separately, passing them to `@actions/exec.exec(tool, args)`
   rather than building a single command string. This eliminates the
   argument-parsing ambiguity for all 30+ `execute()` call sites. Priority:
   low (current inputs are workflow-author-controlled, not attacker-controlled).

2. **For `@actions/exec` maintainers:** Consider adding a lint rule or
   runtime warning when `commandLine` contains patterns that look like
   interpolated user input (e.g., GitHub context expressions). Alternatively,
   provide a builder API that enforces safe argument construction.

3. **For `@actions/io` maintainers:** Add symlink containment checks to
   `cp()` when copying from untrusted sources.

4. **Unrelated finding in the consumer repo:** The `dev` branch of
   `github-pages-deploy-action` still ships the **old, compromised GitHub
   RSA SSH host key** (rotated by GitHub on 2023-03-24 after the private key
   was accidentally exposed) and an obsolete DSS host key. The branch
   `update-github-ssh-known-hosts` has the fix but has not been merged.
   This means SSH deployments that rely on this action's known-hosts setup
   could be vulnerable to MitM if an attacker possesses the leaked private
   key. **This is the most impactful finding from this audit cycle** and
   should be addressed by merging that branch.

---

## 6. Limitations

- **No runtime testing or fuzzing.** All analysis was static, based on
  source code reading and manual argument-parsing simulation.
- **No Windows testing.** The Windows quoting analysis is based on code
  review only; no `.cmd` files were executed.
- **Monorepo scope limited.** Only `packages/exec` and `packages/io` were
  reviewed from `actions/toolkit`. Other packages (`cache`, `artifact`,
  `tool-cache`, `http-client`, `attest`, `glob`) were not examined.
- **npm audit not run.** The toolkit's own `npm audit` was not executed
  due to environment constraints; the dependency assessment relies on
  published advisory databases.
- **Consumer analysis focused on `github-pages-deploy-action` only.** The
  argument-injection patterns described in §3.1 may be more exploitable in
  other actions that use `@actions/exec` with attacker-controlled inputs
  (e.g., actions triggered by `pull_request_target` or `issue_comment`
  events).
